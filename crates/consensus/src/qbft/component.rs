//! QBFT consensus component state.

use std::{
    collections::HashMap,
    error::Error as StdError,
    sync::{Arc, Mutex, PoisonError},
};

use futures::future::BoxFuture;
use k256::{PublicKey, SecretKey};
use prost::{Message, Name};
use prost_types::Any;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    instance::InstanceIo,
    protocols::QBFT_V2_PROTOCOL_ID,
    timer::{RoundTimer, RoundTimerFunc},
};
use pluto_core::{
    corepb::v1::{consensus as pbconsensus, core as pbcore, priority as pbpriority},
    deadline::{AddOutcome, DeadlinerHandle},
    qbft,
    types::{Duty, DutyType},
};

use super::{
    msg::{self, ValueMap},
    runner,
};

/// Result returned by outbound QBFT broadcasting.
pub type BroadcastResult = std::result::Result<(), Box<dyn StdError + Send + Sync + 'static>>;

/// External consensus-message broadcaster seam.
pub type Broadcaster = Arc<
    dyn Fn(CancellationToken, pbconsensus::QbftConsensusMsg) -> BoxFuture<'static, BroadcastResult>
        + Send
        + Sync
        + 'static,
>;

/// Duty admission gate.
pub type DutyGater = Arc<dyn Fn(&Duty) -> bool + Send + Sync + 'static>;

/// Sink for completed sniffer instances.
pub type SnifferSink = Arc<dyn Fn(pbconsensus::SniffedConsensusInstance) + Send + Sync + 'static>;

/// Subscriber callback result.
pub type SubscriberResult = std::result::Result<(), Box<dyn StdError + Send + Sync + 'static>>;

type UnsignedSubscriber =
    Box<dyn Fn(Duty, pbcore::UnsignedDataSet) -> SubscriberResult + Send + Sync + 'static>;
type PrioritySubscriber =
    Box<dyn Fn(Duty, pbpriority::PriorityResult) -> SubscriberResult + Send + Sync + 'static>;

/// Peer metadata needed by consensus QBFT.
#[derive(Clone, Debug)]
pub struct Peer {
    /// External peer index, used only for labels.
    pub index: i64,
    /// Human-readable peer name.
    pub name: String,
    /// Peer secp256k1 public key.
    pub public_key: PublicKey,
}

/// QBFT consensus constructor config.
pub struct Config {
    /// Consensus peers in process-index order.
    pub peers: Vec<Peer>,
    /// Local zero-based process index.
    pub local_peer_idx: i64,
    /// Local secp256k1 private key.
    pub privkey: SecretKey,
    /// Duty deadline scheduler.
    pub deadliner: DeadlinerHandle,
    /// Duty admission gate.
    pub duty_gater: DutyGater,
    /// External message broadcaster.
    pub broadcaster: Broadcaster,
    /// Completed sniffer sink.
    pub sniffer: SnifferSink,
    /// Enables attestation value comparison.
    pub compare_attestations: bool,
    /// Round timer factory.
    pub timer_func: RoundTimerFunc,
}

/// Decoded consensus value supported by this component.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DecodedValue {
    /// Unsigned duty data set.
    UnsignedDataSet(pbcore::UnsignedDataSet),
    /// Priority protocol result.
    PriorityResult(pbpriority::PriorityResult),
}

/// Component result.
pub type Result<T> = std::result::Result<T, Error>;

/// Component construction and inbound admission errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Peer order did not fit the wire index type.
    #[error("peer index overflow: {index}")]
    PeerIndexOverflow {
        /// Peer order index.
        index: usize,
    },

    /// Local peer index is not present in the peer list.
    #[error("invalid local peer index: {peer_idx}")]
    InvalidLocalPeerIndex {
        /// Local peer index.
        peer_idx: i64,
    },

    /// Outer consensus message was absent or wrong.
    #[error("invalid consensus message")]
    InvalidConsensusMessage,

    /// Inner message type was invalid.
    #[error("invalid consensus message type")]
    InvalidConsensusMessageType,

    /// Inner duty type was invalid.
    #[error("invalid consensus message duty type")]
    InvalidConsensusMessageDutyType,

    /// Inner round was invalid.
    #[error("invalid consensus message round")]
    InvalidConsensusMessageRound,

    /// Inner prepared round was invalid.
    #[error("invalid consensus message prepared round")]
    InvalidConsensusMessagePreparedRound,

    /// Message peer index was not in the peer map.
    #[error("invalid peer index")]
    InvalidPeerIndex,

    /// Signature verification failed before comparison.
    #[error("verify consensus message signature: {0}")]
    VerifyConsensusMessageSignature(#[source] msg::Error),

    /// Signature recovered to a different peer key.
    #[error("invalid consensus message signature")]
    InvalidConsensusMessageSignature,

    /// Duty gate rejected the message.
    #[error("invalid duty")]
    InvalidDuty,

    /// Justification failed validation.
    #[error("invalid justification: {0}")]
    InvalidJustification(#[source] Box<Error>),

    /// Justification duty differed from the outer message duty.
    #[error("qbft justification duty differs from message duty")]
    JustificationDutyDiffers,

    /// Inbound Any could not be decoded.
    #[error("unmarshal any")]
    UnmarshalAny,

    /// Message wrapper rejected the value map.
    #[error("{0}")]
    Msg(#[from] msg::Error),

    /// Duty deadline rejected the message.
    #[error("duty expired")]
    DutyExpired,

    /// Receive buffer could not accept the message.
    #[error("timeout enqueuing receive buffer")]
    TimeoutEnqueuingReceiveBuffer,

    /// Context was cancelled after expensive verification.
    #[error("receive cancelled during verification")]
    ReceiveCancelledDuringVerification,
}

/// Canonicalizes inbound `Any` values into the hash map used by QBFT messages.
pub(crate) fn values_by_hash(values: &[Any]) -> Result<ValueMap> {
    let mut out = ValueMap::new();

    for value in values {
        let decoded = decode_supported_any(value)?;
        let hash = match decoded {
            DecodedValue::UnsignedDataSet(inner) => msg::hash_proto(&inner)?,
            DecodedValue::PriorityResult(inner) => msg::hash_proto(&inner)?,
        };
        out.insert(hash, value.clone());
    }

    Ok(out)
}

/// Decodes the protobuf `Any` payload types accepted by this consensus layer.
pub(crate) fn decode_supported_any(value: &Any) -> Result<DecodedValue> {
    if value.type_url == pbcore::UnsignedDataSet::type_url() {
        let decoded = pbcore::UnsignedDataSet::decode(value.value.as_slice())
            .map_err(|_| Error::UnmarshalAny)?;
        return Ok(DecodedValue::UnsignedDataSet(decoded));
    }

    if value.type_url == pbpriority::PriorityResult::type_url() {
        let decoded = pbpriority::PriorityResult::decode(value.value.as_slice())
            .map_err(|_| Error::UnmarshalAny)?;
        return Ok(DecodedValue::PriorityResult(decoded));
    }

    Err(Error::UnmarshalAny)
}

pub(crate) enum Subscriber {
    Unsigned(UnsignedSubscriber),
    Priority(PrioritySubscriber),
}

/// Shared subscriber registry.
#[derive(Clone, Default)]
pub(crate) struct SubscriberSet(Arc<Mutex<Vec<Subscriber>>>);

impl SubscriberSet {
    /// Adds a subscriber callback to the shared registry.
    fn push(&self, subscriber: Subscriber) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(subscriber);
    }

    /// Dispatches a decoded value to subscribers that accept its payload type.
    pub(crate) fn dispatch_decoded(&self, duty: &Duty, value: &DecodedValue) {
        let subscribers = self.0.lock().unwrap_or_else(PoisonError::into_inner);

        for subscriber in subscribers.iter() {
            let result = match (subscriber, value) {
                (Subscriber::Unsigned(fn_), DecodedValue::UnsignedDataSet(value)) => {
                    fn_(duty.clone(), value.clone())
                }
                (Subscriber::Priority(fn_), DecodedValue::PriorityResult(value)) => {
                    fn_(duty.clone(), value.clone())
                }
                _ => Ok(()),
            };

            if let Err(err) = result {
                tracing::warn!(error = %err, duty = %duty, "QBFT subscriber error");
            }
        }
    }
}

/// QBFT consensus component.
pub struct Consensus {
    peers: Vec<Peer>,
    peer_labels: Vec<String>,
    pubkeys: HashMap<i64, PublicKey>,
    local_peer_idx: i64,
    privkey: SecretKey,
    deadliner: DeadlinerHandle,
    duty_gater: DutyGater,
    broadcaster: Broadcaster,
    sniffer: SnifferSink,
    timer_func: RoundTimerFunc,
    compare_attestations: bool,
    subscribers: SubscriberSet,
    instances: Mutex<HashMap<Duty, Arc<InstanceIo<msg::Msg>>>>,
}

impl Consensus {
    /// Creates a new QBFT consensus component.
    pub fn new(config: Config) -> Result<Self> {
        let mut pubkeys = HashMap::with_capacity(config.peers.len());
        let mut peer_labels = Vec::with_capacity(config.peers.len());

        for (index, peer) in config.peers.iter().enumerate() {
            let peer_idx = i64::try_from(index).map_err(|_| Error::PeerIndexOverflow { index })?;
            pubkeys.insert(peer_idx, peer.public_key);
            peer_labels.push(format!("{}:{}", peer.index, peer.name));
        }

        if !pubkeys.contains_key(&config.local_peer_idx) {
            return Err(Error::InvalidLocalPeerIndex {
                peer_idx: config.local_peer_idx,
            });
        }

        Ok(Self {
            peers: config.peers,
            peer_labels,
            pubkeys,
            local_peer_idx: config.local_peer_idx,
            privkey: config.privkey,
            deadliner: config.deadliner,
            duty_gater: config.duty_gater,
            broadcaster: config.broadcaster,
            sniffer: config.sniffer,
            timer_func: config.timer_func,
            compare_attestations: config.compare_attestations,
            subscribers: SubscriberSet::default(),
            instances: Mutex::default(),
        })
    }

    /// Returns the QBFT v2 protocol ID.
    pub fn protocol_id(&self) -> &'static str {
        QBFT_V2_PROTOCOL_ID
    }

    /// Registers a callback for decided unsigned duty data.
    pub fn subscribe<F>(&self, fn_: F)
    where
        F: Fn(Duty, pbcore::UnsignedDataSet) -> SubscriberResult + Send + Sync + 'static,
    {
        self.subscribers.push(Subscriber::Unsigned(Box::new(fn_)));
    }

    /// Registers a callback for decided priority protocol results.
    pub fn subscribe_priority<F>(&self, fn_: F)
    where
        F: Fn(Duty, pbpriority::PriorityResult) -> SubscriberResult + Send + Sync + 'static,
    {
        self.subscribers.push(Subscriber::Priority(Box::new(fn_)));
    }

    /// Validates, wraps, and queues an inbound QBFT consensus message.
    pub async fn handle(
        &self,
        pb_msg: pbconsensus::QbftConsensusMsg,
        ct: &CancellationToken,
    ) -> Result<()> {
        let msg = pb_msg.msg.as_ref().ok_or(Error::InvalidConsensusMessage)?;

        self.verify_msg(msg)?;
        let duty = duty_from_msg(msg)?;

        if !(self.duty_gater)(&duty) {
            return Err(Error::InvalidDuty);
        }

        for justification in &pb_msg.justification {
            self.verify_msg(justification)
                .map_err(|err| Error::InvalidJustification(Box::new(err)))?;

            let just_duty = duty_from_msg(justification)
                .map_err(|err| Error::InvalidJustification(Box::new(err)))?;
            if just_duty != duty {
                return Err(Error::JustificationDutyDiffers);
            }
        }

        let values = values_by_hash(&pb_msg.values)?;
        let wrapped = msg::Msg::new(msg.clone(), pb_msg.justification.clone(), Arc::new(values))?;

        if ct.is_cancelled() {
            return Err(Error::ReceiveCancelledDuringVerification);
        }

        if self.add_deadline(duty.clone()).await != AddOutcome::Scheduled {
            return Err(Error::DutyExpired);
        }

        let inst = self.get_instance_io(duty);
        tokio::select! {
            result = inst.recv_tx.send(wrapped) => {
                match result {
                    Ok(()) => Ok(()),
                    // A completed instance is retained until the duty deadline
                    // expires. Its receive task is gone, but late messages
                    // should not abort the sender's broadcast.
                    Err(_) if inst.has_started() => Ok(()),
                    Err(_) => Err(Error::TimeoutEnqueuingReceiveBuffer),
                }
            }
            () = ct.cancelled() => Err(Error::TimeoutEnqueuingReceiveBuffer),
        }
    }

    /// Verifies fields and signature for one raw QBFT message.
    pub(crate) fn verify_msg(&self, msg: &pbconsensus::QbftMsg) -> Result<()> {
        if msg.duty.is_none() {
            return Err(Error::InvalidConsensusMessage);
        }

        if !qbft::MessageType::from_wire(msg.r#type).valid() {
            return Err(Error::InvalidConsensusMessageType);
        }

        let duty = msg.duty.as_ref().ok_or(Error::InvalidConsensusMessage)?;
        let duty_type =
            DutyType::try_from(duty.r#type).map_err(|_| Error::InvalidConsensusMessageDutyType)?;
        if !duty_type.is_valid() {
            return Err(Error::InvalidConsensusMessageDutyType);
        }

        if msg.round <= 0 {
            return Err(Error::InvalidConsensusMessageRound);
        }

        if msg.prepared_round < 0 {
            return Err(Error::InvalidConsensusMessagePreparedRound);
        }

        let pubkey = self.pubkey(msg.peer_idx).ok_or(Error::InvalidPeerIndex)?;
        let signature_ok =
            msg::verify_msg_sig(msg, pubkey).map_err(Error::VerifyConsensusMessageSignature)?;
        if !signature_ok {
            return Err(Error::InvalidConsensusMessageSignature);
        }

        Ok(())
    }

    /// Runs the internal expired-duty cleanup loop until cancellation.
    pub fn start(
        self: Arc<Self>,
        mut expired_rx: mpsc::Receiver<Duty>,
        ct: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = ct.cancelled() => return,
                    duty = expired_rx.recv() => match duty {
                        Some(duty) => self.delete_instance_io(&duty),
                        None => return,
                    },
                }
            }
        })
    }

    /// Returns existing instance I/O for `duty`, or creates an empty one.
    pub(crate) fn get_instance_io(&self, duty: Duty) -> Arc<InstanceIo<msg::Msg>> {
        let mut instances = self
            .instances
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        instances
            .entry(duty)
            .or_insert_with(|| Arc::new(InstanceIo::new()))
            .clone()
    }

    /// Drops cached I/O for a completed or expired duty instance.
    pub(crate) fn delete_instance_io(&self, duty: &Duty) {
        self.instances
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(duty);
    }

    /// Returns the local zero-based peer index used by QBFT messages.
    pub(crate) fn get_peer_idx(&self) -> i64 {
        self.local_peer_idx
    }

    /// Returns the public key registered for a QBFT peer index.
    pub(crate) fn pubkey(&self, peer_idx: i64) -> Option<&PublicKey> {
        self.pubkeys.get(&peer_idx)
    }

    /// Registers the duty with the deadline scheduler.
    pub(crate) async fn add_deadline(&self, duty: Duty) -> AddOutcome {
        self.deadliner.add(duty).await
    }

    /// Returns a clone of the subscriber registry handle.
    pub(crate) fn subscribers(&self) -> SubscriberSet {
        self.subscribers.clone()
    }

    /// Returns the configured QBFT node count.
    pub(crate) fn node_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns the local signing key for outbound QBFT messages.
    pub(crate) fn privkey(&self) -> SecretKey {
        self.privkey.clone()
    }

    /// Returns the outbound broadcaster callback.
    pub(crate) fn broadcaster(&self) -> Broadcaster {
        Arc::clone(&self.broadcaster)
    }

    /// Returns the completed-instance sniffer sink.
    pub(crate) fn sniffer(&self) -> SnifferSink {
        Arc::clone(&self.sniffer)
    }

    /// Returns whether attester values should be compared before commit.
    pub(crate) fn compare_attestations(&self) -> bool {
        self.compare_attestations
    }

    /// Creates a round timer for one duty instance.
    pub(crate) fn round_timer(&self, duty: Duty) -> Box<dyn RoundTimer> {
        (self.timer_func)(duty)
    }

    /// Proposes unsigned duty data for a consensus instance.
    pub async fn propose(
        &self,
        duty: Duty,
        value: pbcore::UnsignedDataSet,
        ct: &CancellationToken,
    ) -> runner::Result<()> {
        runner::propose_unsigned(self, duty, value, ct).await
    }

    /// Proposes priority protocol data for a consensus instance.
    pub async fn propose_priority(
        &self,
        duty: Duty,
        value: pbpriority::PriorityResult,
        ct: &CancellationToken,
    ) -> runner::Result<()> {
        runner::propose_priority(self, duty, value, ct).await
    }

    /// Starts participating in a consensus instance.
    pub async fn participate(&self, duty: Duty, ct: &CancellationToken) -> runner::Result<()> {
        runner::participate(self, duty, ct).await
    }

    pub(crate) fn peer_labels(&self) -> &[String] {
        self.peer_labels.as_slice()
    }

    pub(crate) fn peer_names(&self) -> Vec<String> {
        self.peers.iter().map(|peer| peer.name.clone()).collect()
    }
}

/// Extracts the domain duty from a validated raw QBFT message.
fn duty_from_msg(msg: &pbconsensus::QbftMsg) -> Result<Duty> {
    let duty = msg.duty.as_ref().ok_or(Error::InvalidConsensusMessage)?;
    Duty::try_from(duty).map_err(|_| Error::InvalidConsensusMessageDutyType)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex as StdMutex;

    use prost::{Message, bytes::Bytes};
    use prost_types::Any;
    use test_case::test_case;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::timer::get_round_timer_func;
    use pluto_core::{
        deadline::{DeadlineCalculator, DeadlinerTask},
        qbft::SomeMsg,
        types::{DutyType, SlotNumber},
    };

    const REFERENCE_VALUE_HASH: &str =
        "0a0c0a0430783939120401020304000000000000000000000000000000000000";
    const REFERENCE_PAYLOAD: &str = "0a6f08021204082a1002200142414cf90756a4241bce7b71e18c6fb9cf91dc96abc6ef1739218974d96e75faf0a15921d47997210232cf064b5e401c6de800fb1f654fcadca0e293dea335fe9242005a200a0c0a04307839391204010203040000000000000000000000000000000000001a440a32747970652e676f6f676c65617069732e636f6d2f636f72652e636f726570622e76312e556e7369676e656444617461536574120e0a0c0a0430783939120401020304";

    struct FutureCalculator;

    impl DeadlineCalculator for FutureCalculator {
        fn deadline(
            &self,
            _duty: &Duty,
        ) -> pluto_core::deadline::Result<Option<chrono::DateTime<chrono::Utc>>> {
            Ok(Some(
                chrono::Utc::now()
                    .checked_add_signed(chrono::Duration::hours(1))
                    .expect("one hour deadline fits DateTime"),
            ))
        }
    }

    #[tokio::test]
    async fn constructor_builds_pubkey_map_by_peer_order() {
        let consensus = consensus(1, true);

        assert_eq!(consensus.pubkey(0), Some(&secret_key(1).public_key()));
        assert_eq!(consensus.pubkey(1), Some(&secret_key(2).public_key()));
        assert_eq!(consensus.pubkey(2), None);
        assert_eq!(consensus.peer_labels(), ["10:node-0", "20:node-1"]);
    }

    #[tokio::test]
    async fn constructor_rejects_invalid_local_peer_idx() {
        let result = Consensus::new(Config {
            peers: peers(),
            local_peer_idx: 3,
            ..config_base(true)
        });
        let err = match result {
            Ok(_) => panic!("constructor accepted invalid local peer index"),
            Err(err) => err,
        };

        assert!(matches!(err, Error::InvalidLocalPeerIndex { peer_idx: 3 }));
    }

    #[tokio::test]
    async fn protocol_id_returns_qbft_v2() {
        assert_eq!(consensus(0, true).protocol_id(), QBFT_V2_PROTOCOL_ID);
    }

    #[tokio::test]
    async fn start_deletes_expired_instance_io_until_cancelled() {
        let consensus = Arc::new(consensus(0, true));
        let duty = duty();
        let first = consensus.get_instance_io(duty.clone());
        let cancel = CancellationToken::new();
        let (expired_tx, expired_rx) = mpsc::channel(1);
        let task = Arc::clone(&consensus).start(expired_rx, cancel.clone());

        expired_tx.send(duty.clone()).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_until_recreated(&consensus, &duty, &first),
        )
        .await
        .expect("expired instance was not deleted");

        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn get_instance_io_returns_same_arc_for_same_duty() {
        let consensus = consensus(0, true);
        let duty = duty();

        let first = consensus.get_instance_io(duty.clone());
        let second = consensus.get_instance_io(duty);

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn delete_instance_io_causes_next_get_to_create_new_arc() {
        let consensus = consensus(0, true);
        let duty = duty();
        let first = consensus.get_instance_io(duty.clone());

        consensus.delete_instance_io(&duty);
        let second = consensus.get_instance_io(duty);

        assert!(!Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn subscribers_are_invoked_in_registration_order() {
        let consensus = consensus(0, true);
        let calls = Arc::new(StdMutex::new(Vec::new()));

        {
            let calls = Arc::clone(&calls);
            consensus.subscribe(move |_, _| {
                calls.lock().unwrap().push("unsigned-1");
                Ok(())
            });
        }
        {
            let calls = Arc::clone(&calls);
            consensus.subscribe_priority(move |_, _| {
                calls.lock().unwrap().push("priority-ignored");
                Ok(())
            });
        }
        {
            let calls = Arc::clone(&calls);
            consensus.subscribe(move |_, _| {
                calls.lock().unwrap().push("unsigned-2");
                Ok(())
            });
        }

        consensus.subscribers().dispatch_decoded(
            &duty(),
            &DecodedValue::UnsignedDataSet(pbcore::UnsignedDataSet::default()),
        );

        assert_eq!(
            calls.lock().unwrap().as_slice(),
            ["unsigned-1", "unsigned-2"]
        );
    }

    #[tokio::test]
    async fn handle_rejects_missing_inner_message() {
        let err = consensus(0, true)
            .handle(
                pbconsensus::QbftConsensusMsg::default(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "invalid consensus message");
    }

    #[test_case(|msg: &mut pbconsensus::QbftMsg| msg.r#type = 99, "invalid consensus message type" ; "invalid_message_type")]
    #[test_case(|msg: &mut pbconsensus::QbftMsg| msg.duty.as_mut().unwrap().r#type = 99, "invalid consensus message duty type" ; "invalid_duty_type")]
    #[test_case(|msg: &mut pbconsensus::QbftMsg| msg.round = 0, "invalid consensus message round" ; "invalid_round")]
    #[test_case(|msg: &mut pbconsensus::QbftMsg| msg.prepared_round = -1, "invalid consensus message prepared round" ; "invalid_prepared_round")]
    #[test_case(|msg: &mut pbconsensus::QbftMsg| msg.peer_idx = 9, "invalid peer index" ; "invalid_peer_idx")]
    #[tokio::test]
    async fn verify_msg_rejects_invalid_fields(mutate: fn(&mut pbconsensus::QbftMsg), want: &str) {
        let consensus = consensus(0, true);
        let mut msg = signed_msg(0);
        mutate(&mut msg);
        if want != "invalid consensus message signature" {
            msg.signature.clear();
            msg = sign_for_peer(msg, 0);
            mutate(&mut msg);
        }

        let err = consensus.verify_msg(&msg).unwrap_err();

        assert_eq!(err.to_string(), want);
    }

    #[tokio::test]
    async fn verify_msg_rejects_missing_duty() {
        let consensus = consensus(0, true);
        let mut msg = signed_msg(0);
        msg.duty = None;

        let err = consensus.verify_msg(&msg).unwrap_err();

        assert_eq!(err.to_string(), "invalid consensus message");
    }

    #[tokio::test]
    async fn verify_msg_rejects_empty_signature() {
        let consensus = consensus(0, true);
        let mut msg = unsigned_msg(0);
        msg.signature.clear();

        let err = consensus.verify_msg(&msg).unwrap_err();

        assert_eq!(
            err.to_string(),
            "verify consensus message signature: empty signature"
        );
    }

    #[tokio::test]
    async fn verify_msg_rejects_malformed_signature() {
        let consensus = consensus(0, true);
        let mut msg = unsigned_msg(0);
        msg.signature = vec![0x42; 64].into();

        let err = consensus.verify_msg(&msg).unwrap_err();

        assert!(
            err.to_string()
                .starts_with("verify consensus message signature: recover pubkey")
        );
    }

    #[tokio::test]
    async fn verify_msg_rejects_wrong_signature() {
        let consensus = consensus(0, true);
        let mut msg = unsigned_msg(0);
        msg.signature = msg::sign_msg(&msg, &secret_key(1)).unwrap().signature;
        msg.peer_idx = 1;

        let err = consensus.verify_msg(&msg).unwrap_err();

        assert_eq!(err.to_string(), "invalid consensus message signature");
    }

    #[tokio::test]
    async fn verify_msg_accepts_valid_signature() {
        let consensus = consensus(0, true);

        consensus.verify_msg(&signed_msg(0)).unwrap();
    }

    #[tokio::test]
    async fn handle_rejects_duty_gate_false() {
        let err = consensus(0, false)
            .handle(consensus_msg(signed_msg(0)), &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "invalid duty");
    }

    #[tokio::test]
    async fn handle_rejects_invalid_justification() {
        let mut invalid = signed_msg(0);
        invalid.round = 0;
        let outer = pbconsensus::QbftConsensusMsg {
            msg: Some(signed_msg(0)),
            justification: vec![invalid],
            values: vec![],
        };

        let err = consensus(0, true)
            .handle(outer, &CancellationToken::new())
            .await
            .unwrap_err();

        assert!(err.to_string().starts_with("invalid justification"));
    }

    #[tokio::test]
    async fn handle_rejects_justification_duty_mismatch() {
        let mut justification = unsigned_msg(0);
        justification.duty = Some(pbcore::Duty {
            slot: 43,
            r#type: i32::try_from(&DutyType::Attester).unwrap(),
        });
        let justification = sign_for_peer(justification, 0);
        let outer = pbconsensus::QbftConsensusMsg {
            msg: Some(signed_msg(0)),
            justification: vec![justification],
            values: vec![],
        };

        let err = consensus(0, true)
            .handle(outer, &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "qbft justification duty differs from message duty"
        );
    }

    #[tokio::test]
    async fn handle_accepts_same_duty_justification() {
        let consensus = consensus(0, true);
        let inst = consensus.get_instance_io(duty());
        let mut justification = unsigned_msg(0);
        justification.r#type = i64::from(qbft::MSG_ROUND_CHANGE);
        justification.value_hash = Bytes::new();
        let mut outer = valid_consensus_msg(0);
        outer.justification = vec![sign_for_peer(justification, 0)];

        consensus
            .handle(outer, &CancellationToken::new())
            .await
            .unwrap();

        let mut recv_rx = inst.take_recv_rx().unwrap();
        assert_eq!(recv_rx.try_recv().unwrap().justification().len(), 1);
    }

    #[test]
    fn values_by_hash_rejects_invalid_type_url() {
        let err = values_by_hash(&[Any {
            type_url: "type.googleapis.com/unknown.Type".to_string(),
            value: vec![],
        }])
        .unwrap_err();

        assert_eq!(err.to_string(), "unmarshal any");
    }

    #[test]
    fn values_by_hash_rejects_malformed_any_value() {
        let err = values_by_hash(&[Any {
            type_url: pbcore::UnsignedDataSet::type_url(),
            value: b"not-protobuf".to_vec(),
        }])
        .unwrap_err();

        assert_eq!(err.to_string(), "unmarshal any");
    }

    #[test]
    fn values_by_hash_hashes_decoded_inner_message() {
        let any = unsigned_any("a", b"first");
        let values = values_by_hash(std::slice::from_ref(&any)).unwrap();
        let decoded = pbcore::UnsignedDataSet::decode(any.value.as_slice()).unwrap();
        let hash = msg::hash_proto(&decoded).unwrap();

        assert_eq!(values.get(&hash), Some(&any));
    }

    #[tokio::test]
    async fn handle_rejects_missing_value_hash() {
        let mut msg = unsigned_msg(0);
        msg.value_hash = [9u8; 32].to_vec().into();
        let msg = sign_for_peer(msg, 0);

        let err = consensus(0, true)
            .handle(consensus_msg(msg), &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "value hash not found in values");
    }

    #[test_case(vec![] ; "empty")]
    #[test_case(vec![0; 32] ; "zero")]
    #[test_case(vec![1; 31] ; "short")]
    #[test_case(vec![1; 33] ; "long")]
    #[tokio::test]
    async fn handle_rejects_invalid_value_hash(hash: Vec<u8>) {
        let mut msg = unsigned_msg(0);
        msg.value_hash = hash.into();
        let msg = sign_for_peer(msg, 0);

        let err = consensus(0, true)
            .handle(consensus_msg(msg), &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "invalid value hash");
    }

    #[test_case(vec![] ; "empty")]
    #[test_case(vec![0; 32] ; "zero")]
    #[test_case(vec![1; 31] ; "short")]
    #[test_case(vec![1; 33] ; "long")]
    #[tokio::test]
    async fn handle_rejects_invalid_prepared_round_change_hash(hash: Vec<u8>) {
        let mut msg = unsigned_msg(0);
        msg.r#type = i64::from(qbft::MSG_ROUND_CHANGE);
        msg.prepared_round = 1;
        msg.prepared_value_hash = hash.into();
        let msg = sign_for_peer(msg, 0);

        let err = consensus(0, true)
            .handle(consensus_msg(msg), &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "invalid prepared value hash");
    }

    #[tokio::test]
    async fn handle_rejects_missing_prepared_round_change_hash() {
        let mut msg = unsigned_msg(0);
        msg.r#type = i64::from(qbft::MSG_ROUND_CHANGE);
        msg.prepared_round = 1;
        msg.prepared_value_hash = [2u8; 32].to_vec().into();
        let msg = sign_for_peer(msg, 0);

        let err = consensus(0, true)
            .handle(consensus_msg(msg), &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "prepared value hash not found in values");
    }

    #[test_case(vec![] ; "empty")]
    #[test_case(vec![0; 32] ; "zero")]
    #[tokio::test]
    async fn handle_accepts_null_unprepared_round_change_hash(hash: Vec<u8>) {
        let consensus = consensus(0, true);
        let mut msg = unsigned_msg(0);
        msg.r#type = i64::from(qbft::MSG_ROUND_CHANGE);
        msg.value_hash = Bytes::new();
        msg.prepared_round = 0;
        msg.prepared_value_hash = hash.into();
        let msg = sign_for_peer(msg, 0);
        let inst = consensus.get_instance_io(duty());

        consensus
            .handle(consensus_msg(msg), &CancellationToken::new())
            .await
            .unwrap();

        let mut recv_rx = inst.take_recv_rx().unwrap();
        let received = recv_rx.try_recv().unwrap();
        assert_eq!(received.type_(), qbft::MSG_ROUND_CHANGE);
        assert_eq!(received.prepared_round(), 0);
        assert_eq!(received.prepared_value(), [0u8; 32]);
    }

    #[tokio::test]
    async fn handle_enqueues_valid_message() {
        let consensus = consensus(0, true);
        let any = unsigned_any("a", b"first");
        let value = pbcore::UnsignedDataSet::decode(any.value.as_slice()).unwrap();
        let value_hash = msg::hash_proto(&value).unwrap();
        let mut msg = unsigned_msg(0);
        msg.value_hash = value_hash.to_vec().into();
        let msg = sign_for_peer(msg, 0);
        let duty = duty();
        let inst = consensus.get_instance_io(duty.clone());

        consensus
            .handle(
                pbconsensus::QbftConsensusMsg {
                    msg: Some(msg),
                    justification: vec![],
                    values: vec![any],
                },
                &CancellationToken::new(),
            )
            .await
            .unwrap();

        let mut recv_rx = inst.take_recv_rx().unwrap();
        let received = recv_rx.try_recv().unwrap();
        assert_eq!(received.value(), value_hash);
    }

    #[tokio::test]
    async fn handle_rejects_deadliner_false_as_duty_expired() {
        let consensus = Consensus::new(Config {
            peers: peers(),
            local_peer_idx: 0,
            ..config_base(true)
        })
        .unwrap();

        let err = consensus
            .handle(valid_consensus_msg(0), &CancellationToken::new())
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "duty expired");
    }

    #[tokio::test]
    async fn handle_rejects_cancellation_after_verification() {
        let ct = CancellationToken::new();
        ct.cancel();

        let err = consensus(0, true)
            .handle(valid_consensus_msg(0), &ct)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "receive cancelled during verification");
    }

    #[tokio::test]
    async fn handle_waits_for_receive_buffer_capacity() {
        let consensus = consensus(0, true);
        let inst = consensus.get_instance_io(duty());
        let mut recv_rx = inst.take_recv_rx().unwrap();
        for _ in 0..crate::instance::RECV_BUFFER_SIZE {
            inst.recv_tx.try_send(wrapped_msg()).unwrap();
        }

        let ct = CancellationToken::new();
        let handle = consensus.handle(valid_consensus_msg(0), &ct);
        tokio::pin!(handle);

        tokio::select! {
            result = &mut handle => panic!(
                "handle completed while receive buffer was full: {result:?}"
            ),
            () = tokio::task::yield_now() => {}
        }

        recv_rx.recv().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn handle_rejects_full_receive_buffer_after_cancellation() {
        let consensus = consensus(0, true);
        let inst = consensus.get_instance_io(duty());
        let _recv_rx = inst.take_recv_rx().unwrap();
        for _ in 0..crate::instance::RECV_BUFFER_SIZE {
            inst.recv_tx.try_send(wrapped_msg()).unwrap();
        }

        let ct = CancellationToken::new();
        let handle = consensus.handle(valid_consensus_msg(0), &ct);
        tokio::pin!(handle);

        tokio::select! {
            result = &mut handle => panic!(
                "handle completed while receive buffer was full: {result:?}"
            ),
            () = tokio::task::yield_now() => {}
        }
        ct.cancel();
        let err = tokio::time::timeout(std::time::Duration::from_secs(1), &mut handle)
            .await
            .unwrap()
            .unwrap_err();

        assert_eq!(err.to_string(), "timeout enqueuing receive buffer");
    }

    #[tokio::test]
    async fn handle_drops_late_message_after_started_receiver_closed() {
        let consensus = consensus(0, true);
        let duty = duty();
        let inst = consensus.get_instance_io(duty.clone());
        assert!(inst.maybe_start());
        drop(inst.take_recv_rx().unwrap());
        let any = unsigned_any("a", b"first");
        let value = pbcore::UnsignedDataSet::decode(any.value.as_slice()).unwrap();
        let value_hash = msg::hash_proto(&value).unwrap();
        let mut msg = unsigned_msg(0);
        msg.value_hash = value_hash.to_vec().into();
        let msg = sign_for_peer(msg, 0);

        consensus
            .handle(
                pbconsensus::QbftConsensusMsg {
                    msg: Some(msg),
                    justification: vec![],
                    values: vec![any],
                },
                &CancellationToken::new(),
            )
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&inst, &consensus.get_instance_io(duty)));
    }

    #[tokio::test]
    async fn reference_signed_message_is_admitted() {
        let consensus = consensus(0, true);
        let mut recv_rx = consensus
            .get_instance_io(duty())
            .take_recv_rx()
            .expect("recv receiver should be available");

        consensus
            .handle(reference_consensus_msg(), &CancellationToken::new())
            .await
            .expect("reference message should be admitted");

        let received = recv_rx.recv().await.expect("admitted message");
        assert_eq!(received.source(), 0);
        assert_eq!(hex::encode(received.value()), REFERENCE_VALUE_HASH);
        assert_eq!(
            received.value_source().expect("value source should exist"),
            reference_any_value()
        );
    }

    fn consensus_msg(msg: pbconsensus::QbftMsg) -> pbconsensus::QbftConsensusMsg {
        pbconsensus::QbftConsensusMsg {
            msg: Some(msg),
            justification: vec![],
            values: vec![],
        }
    }

    fn unsigned_msg(peer_idx: i64) -> pbconsensus::QbftMsg {
        pbconsensus::QbftMsg {
            r#type: i64::from(qbft::MSG_PRE_PREPARE),
            duty: Some(pbcore::Duty::try_from(&duty()).unwrap()),
            peer_idx,
            round: 1,
            prepared_round: 0,
            ..Default::default()
        }
    }

    fn signed_msg(peer_idx: i64) -> pbconsensus::QbftMsg {
        sign_for_peer(unsigned_msg(peer_idx), peer_idx)
    }

    fn valid_consensus_msg(peer_idx: i64) -> pbconsensus::QbftConsensusMsg {
        let any = unsigned_any("a", b"first");
        let value = pbcore::UnsignedDataSet::decode(any.value.as_slice()).unwrap();
        let value_hash = msg::hash_proto(&value).unwrap();
        let mut msg = unsigned_msg(peer_idx);
        msg.value_hash = value_hash.to_vec().into();

        pbconsensus::QbftConsensusMsg {
            msg: Some(sign_for_peer(msg, peer_idx)),
            justification: vec![],
            values: vec![any],
        }
    }

    fn sign_for_peer(msg: pbconsensus::QbftMsg, peer_idx: i64) -> pbconsensus::QbftMsg {
        let seed = u8::try_from(peer_idx.checked_add(1).unwrap()).unwrap();
        msg::sign_msg(&msg, &secret_key(seed)).unwrap()
    }

    fn unsigned_any(key: &str, value: &'static [u8]) -> Any {
        Any::from_msg(&pbcore::UnsignedDataSet {
            set: [(key.to_string(), Bytes::from_static(value))].into(),
        })
        .unwrap()
    }

    fn reference_consensus_msg() -> pbconsensus::QbftConsensusMsg {
        pbconsensus::QbftConsensusMsg::decode(
            hex::decode(REFERENCE_PAYLOAD)
                .expect("valid fixture hex")
                .as_slice(),
        )
        .expect("reference payload should decode")
    }

    fn reference_value() -> pbcore::UnsignedDataSet {
        let mut set = std::collections::BTreeMap::new();
        set.insert("0x99".to_string(), Bytes::from_static(&[1, 2, 3, 4]));
        pbcore::UnsignedDataSet { set }
    }

    fn reference_any_value() -> Any {
        Any::from_msg(&reference_value()).expect("value should pack")
    }

    fn wrapped_msg() -> msg::Msg {
        let any = unsigned_any("a", b"first");
        let value = pbcore::UnsignedDataSet::decode(any.value.as_slice()).unwrap();
        let value_hash = msg::hash_proto(&value).unwrap();
        let mut msg = unsigned_msg(0);
        msg.value_hash = value_hash.to_vec().into();

        msg::Msg::new(msg, vec![], Arc::new(ValueMap::from([(value_hash, any)]))).unwrap()
    }

    pub(crate) fn consensus(local_peer_idx: i64, duty_allowed: bool) -> Consensus {
        Consensus::new(Config {
            peers: peers(),
            local_peer_idx,
            duty_gater: Arc::new(move |_| duty_allowed),
            ..config_base(false)
        })
        .unwrap()
    }

    pub(crate) fn config_base(never_expiring: bool) -> Config {
        let cancel = CancellationToken::new();
        let (deadliner, _expired_rx) = if never_expiring {
            DeadlinerTask::start(
                cancel,
                "qbft-test",
                pluto_core::deadline::NeverExpiringCalculator,
            )
        } else {
            DeadlinerTask::start(cancel, "qbft-test", FutureCalculator)
        };

        Config {
            peers: vec![],
            local_peer_idx: 0,
            privkey: secret_key(1),
            deadliner,
            duty_gater: Arc::new(|_| true),
            broadcaster: Arc::new(|_, _| Box::pin(async { Ok(()) })),
            sniffer: Arc::new(|_| {}),
            compare_attestations: false,
            timer_func: get_round_timer_func(),
        }
    }

    pub(crate) fn peers() -> Vec<Peer> {
        vec![
            Peer {
                index: 10,
                name: "node-0".to_string(),
                public_key: secret_key(1).public_key(),
            },
            Peer {
                index: 20,
                name: "node-1".to_string(),
                public_key: secret_key(2).public_key(),
            },
        ]
    }

    pub(crate) fn duty() -> Duty {
        Duty::new(SlotNumber::new(42), DutyType::Attester)
    }

    pub(crate) fn secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    async fn wait_until_recreated(
        consensus: &Consensus,
        duty: &Duty,
        old: &Arc<InstanceIo<msg::Msg>>,
    ) {
        loop {
            if !Arc::ptr_eq(&consensus.get_instance_io(duty.clone()), old) {
                return;
            }
            tokio::task::yield_now().await;
        }
    }
}
