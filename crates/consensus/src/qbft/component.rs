//! QBFT consensus component state.

use std::{
    collections::HashMap,
    error::Error as StdError,
    sync::{Arc, Mutex, PoisonError},
};

use futures::future::BoxFuture;
use k256::{PublicKey, SecretKey};
use tokio::{
    sync::{mpsc, mpsc::error::TrySendError},
    task::JoinHandle,
};
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

use super::{admission, msg, runner};

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
    #[cfg(test)]
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

/// Component result.
pub type Result<T> = std::result::Result<T, Error>;

/// Component construction errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
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
}

impl Consensus {
    /// Creates a new QBFT consensus component.
    pub fn new(config: Config) -> Result<Self> {
        let mut pubkeys = HashMap::with_capacity(config.peers.len());
        #[cfg(test)]
        let mut peer_labels = Vec::with_capacity(config.peers.len());

        for (index, peer) in config.peers.iter().enumerate() {
            let peer_idx = i64::try_from(index).map_err(|_| Error::PeerIndexOverflow { index })?;
            pubkeys.insert(peer_idx, peer.public_key);
            #[cfg(test)]
            peer_labels.push(format!("{}:{}", peer.index, peer.name));
        }

        if !pubkeys.contains_key(&config.local_peer_idx) {
            return Err(Error::InvalidLocalPeerIndex {
                peer_idx: config.local_peer_idx,
            });
        }

        Ok(Self {
            peers: config.peers,
            #[cfg(test)]
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
        ct: &CancellationToken,
        req: Option<pbconsensus::QbftConsensusMsg>,
    ) -> admission::Result<()> {
        let pb_msg = req.ok_or(admission::Error::InvalidConsensusMessage)?;
        let msg = pb_msg
            .msg
            .as_ref()
            .ok_or(admission::Error::InvalidConsensusMessage)?;

        self.verify_msg(msg)?;
        let duty = duty_from_msg(msg)?;

        if !self.duty_allowed(&duty) {
            return Err(admission::Error::InvalidDuty);
        }

        for justification in &pb_msg.justification {
            self.verify_msg(justification)
                .map_err(|err| admission::Error::InvalidJustification(Box::new(err)))?;

            let just_duty = duty_from_msg(justification)
                .map_err(|err| admission::Error::InvalidJustification(Box::new(err)))?;
            if just_duty != duty {
                return Err(admission::Error::JustificationDutyDiffers);
            }
        }

        let values = admission::values_by_hash(&pb_msg.values)?;
        let wrapped = msg::Msg::new(msg.clone(), pb_msg.justification.clone(), Arc::new(values))?;

        if ct.is_cancelled() {
            return Err(admission::Error::ReceiveCancelledDuringVerification);
        }

        if self.add_deadline(duty.clone()).await != AddOutcome::Scheduled {
            return Err(admission::Error::DutyExpired);
        }

        self.get_recv_buffer(duty)
            .try_send(wrapped)
            .map_err(|err| match err {
                TrySendError::Full(_) | TrySendError::Closed(_) => {
                    admission::Error::TimeoutEnqueuingReceiveBuffer
                }
            })
    }

    /// Verifies fields and signature for one raw QBFT message.
    pub(crate) fn verify_msg(&self, msg: &pbconsensus::QbftMsg) -> admission::Result<()> {
        if msg.duty.is_none() {
            return Err(admission::Error::InvalidConsensusMessage);
        }

        if !qbft::MessageType::from_wire(msg.r#type).valid() {
            return Err(admission::Error::InvalidConsensusMessageType);
        }

        let duty = msg
            .duty
            .as_ref()
            .ok_or(admission::Error::InvalidConsensusMessage)?;
        let duty_type = DutyType::try_from(duty.r#type)
            .map_err(|_| admission::Error::InvalidConsensusMessageDutyType)?;
        if !duty_type.is_valid() {
            return Err(admission::Error::InvalidConsensusMessageDutyType);
        }

        if msg.round <= 0 {
            return Err(admission::Error::InvalidConsensusMessageRound);
        }

        if msg.prepared_round < 0 {
            return Err(admission::Error::InvalidConsensusMessagePreparedRound);
        }

        let pubkey = self
            .pubkey(msg.peer_idx)
            .ok_or(admission::Error::InvalidPeerIndex)?;
        let signature_ok = msg::verify_msg_sig(msg, pubkey)
            .map_err(admission::Error::VerifyConsensusMessageSignature)?;
        if !signature_ok {
            return Err(admission::Error::InvalidConsensusMessageSignature);
        }

        Ok(())
    }

    /// Runs the internal expired-duty cleanup loop until cancellation.
    pub fn start(
        self: Arc<Self>,
        ct: CancellationToken,
        mut expired_rx: mpsc::Receiver<Duty>,
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

    /// Returns the inbound message buffer for a duty instance.
    pub(crate) fn get_recv_buffer(&self, duty: Duty) -> mpsc::Sender<msg::Msg> {
        self.get_instance_io(duty).recv_tx.clone()
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

    /// Returns whether local policy admits consensus for the duty.
    pub(crate) fn duty_allowed(&self, duty: &Duty) -> bool {
        (self.duty_gater)(duty)
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
        ct: &CancellationToken,
        duty: Duty,
        value: pbcore::UnsignedDataSet,
    ) -> runner::Result<()> {
        runner::propose_unsigned(self, ct, duty, value).await
    }

    /// Proposes priority protocol data for a consensus instance.
    pub async fn propose_priority(
        &self,
        ct: &CancellationToken,
        duty: Duty,
        value: pbpriority::PriorityResult,
    ) -> runner::Result<()> {
        runner::propose_priority(self, ct, duty, value).await
    }

    /// Starts participating in a consensus instance.
    pub async fn participate(&self, ct: &CancellationToken, duty: Duty) -> runner::Result<()> {
        runner::participate(self, ct, duty).await
    }

    #[cfg(test)]
    pub(crate) fn pubkeys(&self) -> &HashMap<i64, PublicKey> {
        &self.pubkeys
    }

    #[cfg(test)]
    pub(crate) fn peer_labels(&self) -> &[String] {
        &self.peer_labels
    }
}

/// Extracts the domain duty from a validated raw QBFT message.
fn duty_from_msg(msg: &pbconsensus::QbftMsg) -> admission::Result<Duty> {
    let duty = msg
        .duty
        .as_ref()
        .ok_or(admission::Error::InvalidConsensusMessage)?;
    Duty::try_from(duty).map_err(|_| admission::Error::InvalidConsensusMessageDutyType)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex as StdMutex;

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::timer::get_round_timer_func;
    use pluto_core::{
        deadline::{DeadlineCalculator, DeadlinerTask},
        types::{DutyType, SlotNumber},
    };

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

        assert_eq!(consensus.pubkeys().len(), 2);
        assert_eq!(consensus.pubkey(0), Some(&secret_key(1).public_key()));
        assert_eq!(consensus.pubkey(1), Some(&secret_key(2).public_key()));
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

        assert_eq!(err, Error::InvalidLocalPeerIndex { peer_idx: 3 });
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
        let task = Arc::clone(&consensus).start(cancel.clone(), expired_rx);

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
