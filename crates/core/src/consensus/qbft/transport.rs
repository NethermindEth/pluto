//! QBFT consensus transport adapter.

// TODO: Remove once the consensus runner wires this transport.
#![allow(dead_code)]

use std::sync::{self, Mutex, PoisonError};

use futures::future::BoxFuture;
use k256::SecretKey;
use prost_types::Any;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    corepb::v1::{consensus as pbconsensus, core as pbcore},
    qbft::{self, SomeMsg},
    types::{Duty, DutyTypeError},
};

use super::{
    msg::{self, ConsensusQbftTypes, ValueMap},
    sniffer::Sniffer,
};

/// Transport result.
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// External consensus-message broadcaster seam.
pub(crate) type Broadcaster = Box<
    dyn Fn(CancellationToken, pbconsensus::QbftConsensusMsg) -> BoxFuture<'static, Result<()>>
        + Send
        + Sync,
>;

/// Parameters for broadcasting a QBFT message.
pub(crate) struct BroadcastRequest {
    pub(crate) ct: CancellationToken,
    pub(crate) type_: qbft::MessageType,
    pub(crate) duty: Duty,
    pub(crate) peer_idx: i64,
    pub(crate) round: i64,
    pub(crate) value_hash: [u8; 32],
    pub(crate) prepared_round: i64,
    pub(crate) prepared_value_hash: [u8; 32],
    pub(crate) justification: Vec<qbft::Msg<ConsensusQbftTypes>>,
}

/// Errors returned by the QBFT consensus transport.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// Hash was not available in the value cache.
    #[error("unknown value")]
    UnknownValue,

    /// Broadcast justification was not the consensus QBFT message wrapper.
    #[error("invalid justification message")]
    InvalidJustificationMessage,

    /// Message creation justification was not the consensus QBFT message
    /// wrapper.
    #[error("invalid justification")]
    InvalidJustification,

    /// Duty conversion failed.
    #[error("invalid duty")]
    InvalidDuty(#[source] DutyTypeError),

    /// Inner receive buffer was closed.
    #[error("receive buffer closed")]
    ReceiveBufferClosed,

    /// Consensus message wrapping/signing failed.
    #[error("{0}")]
    Msg(#[from] msg::Error),
}

/// Transport adapter for one QBFT consensus instance.
pub(crate) struct Transport {
    broadcaster: Broadcaster,
    privkey: SecretKey,
    // Async admission buffer for wrapped QBFT messages. Runner wiring bridges
    // this tokio channel into the crossbeam receiver used by core::qbft::run.
    recv_tx: mpsc::Sender<qbft::Msg<ConsensusQbftTypes>>,
    sniffer: sync::Arc<Sniffer>,
    values: Mutex<ValueStore>,
}

struct ValueStore {
    value_rx: mpsc::Receiver<Any>,
    values: ValueMap,
}

impl Transport {
    /// Creates a new QBFT consensus transport.
    ///
    /// Callers must cancel the tokens passed to [`Transport::broadcast`] when
    /// the consensus instance ends. Detached self-send tasks use those tokens
    /// to stop if the inner receive buffer stays full.
    pub(crate) fn new(
        broadcaster: Broadcaster,
        privkey: SecretKey,
        value_rx: mpsc::Receiver<Any>,
        recv_tx: mpsc::Sender<qbft::Msg<ConsensusQbftTypes>>,
        sniffer: Sniffer,
    ) -> Self {
        Self {
            broadcaster,
            privkey,
            recv_tx,
            sniffer: sync::Arc::new(sniffer),
            values: Mutex::new(ValueStore {
                value_rx,
                values: ValueMap::new(),
            }),
        }
    }

    /// Caches values carried by a consensus message.
    pub(crate) fn set_values(&self, msg: &msg::Msg) {
        self.values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values
            .extend(
                msg.values()
                    .iter()
                    .map(|(hash, value)| (*hash, value.clone())),
            );
    }

    /// Returns a cached value by hash, after draining at most one local value.
    pub(crate) fn get_value(&self, hash: [u8; 32]) -> Result<Any> {
        let mut store = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        if let Ok(local) = store.value_rx.try_recv() {
            // Any::value is hashable here because the local producer must pack
            // canonical deterministic bytes for the concrete inner protobuf.
            // Inbound values must be decoded and canonicalized before caching.
            let hash = msg::hash_proto_bytes(&local.value)?;
            store.values.insert(hash, local);
        }

        store.values.get(&hash).cloned().ok_or(Error::UnknownValue)
    }

    /// Creates, self-enqueues, sniffs, and externally broadcasts a QBFT
    /// message.
    ///
    /// The self-send task exits when the message is accepted by the inner
    /// receive buffer or when `request.ct` is cancelled. Instance teardown must
    /// cancel that token so blocked self-send tasks cannot outlive the
    /// transport.
    pub(crate) async fn broadcast(&self, request: BroadcastRequest) -> Result<()> {
        let BroadcastRequest {
            ct,
            type_,
            duty,
            peer_idx,
            round,
            value_hash,
            prepared_round,
            prepared_value_hash,
            justification,
        } = request;

        let mut hashes = vec![value_hash, prepared_value_hash];

        for justification_msg in &justification {
            let msg = justification_msg
                .as_any()
                .downcast_ref::<msg::Msg>()
                .ok_or(Error::InvalidJustificationMessage)?;
            hashes.push(msg.value());
            hashes.push(msg.prepared_value());
        }

        let mut values = ValueMap::new();
        for hash in hashes {
            if hash == [0u8; 32] || values.contains_key(&hash) {
                continue;
            }

            values.insert(hash, self.get_value(hash)?);
        }

        let msg = create_msg(CreateMsgRequest {
            type_,
            duty: &duty,
            peer_idx,
            round,
            value_hash,
            prepared_round,
            prepared_value_hash,
            values,
            justification: &justification,
            privkey: &self.privkey,
        })?;
        let msg = sync::Arc::new(msg);
        let consensus_msg = msg.to_consensus_msg();
        let inner_msg: qbft::Msg<ConsensusQbftTypes> = msg.clone();

        let task_ct = ct.clone();
        let recv_tx = self.recv_tx.clone();
        let sniffer = sync::Arc::clone(&self.sniffer);
        let sniffed_msg = consensus_msg.clone();
        // Self-send is intentionally detached: the inner receive buffer can
        // block, but network broadcast must still proceed.
        tokio::spawn(async move {
            tokio::select! {
                () = task_ct.cancelled() => {}
                result = recv_tx.send(inner_msg) => {
                    if result.is_ok() {
                        sniffer.add(sniffed_msg);
                    }
                }
            }
        });

        (self.broadcaster)(ct, consensus_msg).await
    }

    /// Processes admitted outer messages until cancellation or channel close.
    pub(crate) async fn process_receives(
        &self,
        ct: CancellationToken,
        mut outer_rx: mpsc::Receiver<msg::Msg>,
    ) -> Result<()> {
        loop {
            let msg = tokio::select! {
                () = ct.cancelled() => return Ok(()),
                msg = outer_rx.recv() => match msg {
                    Some(msg) => msg,
                    None => return Ok(()),
                },
            };

            self.set_values(&msg);
            let consensus_msg = msg.to_consensus_msg();
            let inner_msg: qbft::Msg<ConsensusQbftTypes> = sync::Arc::new(msg);

            tokio::select! {
                () = ct.cancelled() => return Ok(()),
                result = self.recv_tx.send(inner_msg) => {
                    result.map_err(|_| Error::ReceiveBufferClosed)?;
                    self.sniffer.add(consensus_msg);
                }
            }
        }
    }

    /// Returns the current sniffed consensus instance.
    pub(crate) fn sniffer_instance(&self) -> pbconsensus::SniffedConsensusInstance {
        self.sniffer.instance()
    }
}

struct CreateMsgRequest<'a> {
    type_: qbft::MessageType,
    duty: &'a Duty,
    peer_idx: i64,
    round: i64,
    value_hash: [u8; 32],
    prepared_round: i64,
    prepared_value_hash: [u8; 32],
    values: ValueMap,
    justification: &'a [qbft::Msg<ConsensusQbftTypes>],
    privkey: &'a SecretKey,
}

/// Creates a signed consensus QBFT message wrapper.
fn create_msg(request: CreateMsgRequest<'_>) -> Result<msg::Msg> {
    let CreateMsgRequest {
        type_,
        duty,
        peer_idx,
        round,
        value_hash,
        prepared_round,
        prepared_value_hash,
        values,
        justification,
        privkey,
    } = request;

    let pb_msg = pbconsensus::QbftMsg {
        r#type: i64::from(type_),
        duty: Some(pbcore::Duty::try_from(duty).map_err(Error::InvalidDuty)?),
        peer_idx,
        round,
        value_hash: value_hash.to_vec().into(),
        prepared_round,
        prepared_value_hash: prepared_value_hash.to_vec().into(),
        ..Default::default()
    };
    let pb_msg = msg::sign_msg(&pb_msg, privkey)?;

    let mut justifications = Vec::with_capacity(justification.len());
    for msg in justification {
        let msg = msg
            .as_any()
            .downcast_ref::<msg::Msg>()
            .ok_or(Error::InvalidJustification)?;
        justifications.push(msg.msg().clone());
    }

    Ok(msg::Msg::new(
        pb_msg,
        justifications,
        sync::Arc::new(values),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::qbft::{msg::hash_proto, sniffer::Sniffer},
        corepb::v1::consensus::QbftMsg,
        qbft::SomeMsg,
        types::{DutyType, SlotNumber},
    };
    use prost_types::Timestamp;
    use tokio::time::{Duration, timeout};

    const SIGNING_PRIVKEY: &str =
        "41d3ff12045b73c870529fe44f70dca2745bafbe1698ffc3c8759eef3cfbaee1";

    #[test]
    fn set_values_caches_message_values() {
        let transport = test_transport(empty_value_rx()).0;
        let value_hash = value_hash(1);
        let msg = wrapped_msg(qbft::MSG_PRE_PREPARE, value_hash, [0u8; 32], vec![]);

        transport.set_values(&msg);

        assert_eq!(transport.get_value(value_hash).unwrap(), any_timestamp(1));
    }

    #[test]
    fn get_value_returns_cached_value() {
        let transport = test_transport(empty_value_rx()).0;
        let value_hash = value_hash(1);
        let msg = wrapped_msg(qbft::MSG_PRE_PREPARE, value_hash, [0u8; 32], vec![]);
        transport.set_values(&msg);

        assert_eq!(transport.get_value(value_hash).unwrap(), any_timestamp(1));
    }

    #[test]
    fn get_value_drains_local_value() {
        let (value_tx, value_rx) = mpsc::channel(1);
        let value_hash = value_hash(1);
        value_tx.try_send(any_timestamp(1)).unwrap();
        let transport = test_transport(value_rx).0;

        assert_eq!(transport.get_value(value_hash).unwrap(), any_timestamp(1));
    }

    #[test]
    fn get_value_unknown_value_errors() {
        let transport = test_transport(empty_value_rx()).0;

        let err = transport.get_value([9u8; 32]).unwrap_err();

        assert_eq!(err.to_string(), "unknown value");
    }

    #[test]
    fn create_msg_signs_and_wraps() {
        let key = secret_key();
        let duty = duty();
        let value_hash = value_hash(1);
        let mut request = create_msg_request(&duty, &key);
        request.peer_idx = 2;
        request.round = 3;
        request.value_hash = value_hash;
        request.values = value_map(vec![(value_hash, any_timestamp(1))]);

        let msg = create_msg(request).unwrap();

        assert_eq!(msg.msg().r#type, 1);
        assert_eq!(msg.msg().peer_idx, 2);
        assert_eq!(msg.msg().round, 3);
        assert_eq!(msg.value(), value_hash);
        assert!(!msg.msg().signature.is_empty());
        assert!(msg::verify_msg_sig(msg.msg(), &key.public_key()).unwrap());
    }

    #[test]
    fn create_msg_preserves_unknown_message_type() {
        let key = secret_key();
        let duty = duty();
        let mut request = create_msg_request(&duty, &key);
        request.type_ = qbft::MessageType::from_wire(99);
        request.peer_idx = 2;
        request.round = 3;

        let msg = create_msg(request).unwrap();

        assert_eq!(msg.msg().r#type, 99);
    }

    #[test]
    fn create_msg_uses_raw_justifications_only() {
        let key = secret_key();
        let duty = duty();
        let nested = QbftMsg {
            r#type: 3,
            round: 9,
            ..Default::default()
        };
        let raw_justification = QbftMsg {
            r#type: 2,
            round: 4,
            ..Default::default()
        };
        let justification = msg::Msg::new(
            raw_justification.clone(),
            vec![nested],
            sync::Arc::default(),
        )
        .unwrap();
        let justification: qbft::Msg<ConsensusQbftTypes> = sync::Arc::new(justification);
        let justifications = [justification];
        let mut request = create_msg_request(&duty, &key);
        request.type_ = qbft::MSG_ROUND_CHANGE;
        request.peer_idx = 2;
        request.round = 5;
        request.justification = &justifications;

        let msg = create_msg(request).unwrap();

        assert_eq!(
            msg.to_consensus_msg().justification,
            vec![raw_justification]
        );
    }

    #[test]
    fn create_msg_rejects_invalid_justification_type() {
        let key = secret_key();
        let duty = duty();
        let justification: qbft::Msg<ConsensusQbftTypes> = sync::Arc::new(OtherMsg);
        let justifications = [justification];
        let mut request = create_msg_request(&duty, &key);
        request.justification = &justifications;

        let err = create_msg(request).unwrap_err();

        assert_eq!(err.to_string(), "invalid justification");
    }

    #[tokio::test]
    async fn broadcast_resolves_hashes_and_calls_broadcaster() {
        let value_hash = value_hash(1);
        let (transport, _recv_rx, sent) =
            test_transport(local_value_rx(value_hash, any_timestamp(1)));

        transport
            .broadcast(broadcast_request(value_hash))
            .await
            .unwrap();

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].msg.as_ref().unwrap().value_hash,
            value_hash.to_vec()
        );
        assert_eq!(sent[0].values, vec![any_timestamp(1)]);
    }

    #[tokio::test]
    async fn broadcast_skips_zero_and_duplicate_hashes() {
        let value_hash = value_hash(1);
        let justification = wrapped_msg(qbft::MSG_PREPARE, value_hash, [0u8; 32], vec![]);
        let justification: qbft::Msg<ConsensusQbftTypes> = sync::Arc::new(justification);
        let (transport, _recv_rx, sent) =
            test_transport(local_value_rx(value_hash, any_timestamp(1)));
        let mut request = broadcast_request(value_hash);
        request.type_ = qbft::MSG_ROUND_CHANGE;
        request.justification = vec![justification];

        transport.broadcast(request).await.unwrap();

        let sent = sent.lock().unwrap();
        assert_eq!(sent[0].values.len(), 1);
        assert_eq!(sent[0].values[0], any_timestamp(1));
    }

    #[tokio::test]
    async fn broadcast_self_enqueues_message() {
        let value_hash = value_hash(1);
        let (transport, mut recv_rx, _sent) =
            test_transport(local_value_rx(value_hash, any_timestamp(1)));

        transport
            .broadcast(broadcast_request(value_hash))
            .await
            .unwrap();

        let received = timeout(Duration::from_secs(1), recv_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.value(), value_hash);
        wait_for_sniffer_len(&transport, 1).await;
    }

    #[tokio::test]
    async fn broadcast_unknown_value_errors() {
        let (transport, _recv_rx, sent) = test_transport(empty_value_rx());

        let err = transport
            .broadcast(broadcast_request([8u8; 32]))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "unknown value");
        assert!(sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn broadcast_rejects_invalid_justification_message() {
        let justification: qbft::Msg<ConsensusQbftTypes> = sync::Arc::new(OtherMsg);
        let (transport, _recv_rx, _sent) = test_transport(empty_value_rx());
        let mut request = broadcast_request([0u8; 32]);
        request.type_ = qbft::MSG_ROUND_CHANGE;
        request.justification = vec![justification];

        let err = transport.broadcast(request).await.unwrap_err();

        assert_eq!(err.to_string(), "invalid justification message");
    }

    #[tokio::test]
    async fn process_receives_caches_values_and_forwards() {
        let value_hash = value_hash(1);
        let msg = wrapped_msg(qbft::MSG_PRE_PREPARE, value_hash, [0u8; 32], vec![]);
        let (transport, mut recv_rx, _sent) = test_transport(empty_value_rx());
        let transport = sync::Arc::new(transport);
        let (outer_tx, outer_rx) = mpsc::channel(1);
        let ct = CancellationToken::new();
        let runner = {
            let transport = sync::Arc::clone(&transport);
            let ct = ct.clone();
            tokio::spawn(async move { transport.process_receives(ct, outer_rx).await })
        };

        outer_tx.send(msg).await.unwrap();

        let received = timeout(Duration::from_secs(1), recv_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.value(), value_hash);
        assert_eq!(transport.get_value(value_hash).unwrap(), any_timestamp(1));
        assert_eq!(transport.sniffer_instance().msgs.len(), 1);

        ct.cancel();
        runner.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn process_receives_stops_on_cancel() {
        let (transport, _recv_rx, _sent) = test_transport(empty_value_rx());
        let (_outer_tx, outer_rx) = mpsc::channel(1);
        let ct = CancellationToken::new();
        ct.cancel();

        transport.process_receives(ct, outer_rx).await.unwrap();
    }

    #[tokio::test]
    async fn process_receives_errors_when_receive_buffer_closed() {
        let value_hash = value_hash(1);
        let msg = wrapped_msg(qbft::MSG_PRE_PREPARE, value_hash, [0u8; 32], vec![]);
        let (transport, recv_rx, _sent) = test_transport(empty_value_rx());
        drop(recv_rx);

        let (outer_tx, outer_rx) = mpsc::channel(1);
        outer_tx.send(msg).await.unwrap();

        let err = transport
            .process_receives(CancellationToken::new(), outer_rx)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "receive buffer closed");
    }

    #[derive(Debug)]
    struct OtherMsg;

    impl SomeMsg<ConsensusQbftTypes> for OtherMsg {
        fn type_(&self) -> qbft::MessageType {
            qbft::MSG_PRE_PREPARE
        }

        fn instance(&self) -> Duty {
            duty()
        }

        fn source(&self) -> i64 {
            1
        }

        fn round(&self) -> i64 {
            1
        }

        fn value(&self) -> [u8; 32] {
            [0u8; 32]
        }

        fn value_source(&self) -> std::result::Result<Any, qbft::QbftError> {
            Ok(Any::default())
        }

        fn prepared_round(&self) -> i64 {
            0
        }

        fn prepared_value(&self) -> [u8; 32] {
            [0u8; 32]
        }

        fn justification(&self) -> Vec<qbft::Msg<ConsensusQbftTypes>> {
            vec![]
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    type SentMessages = sync::Arc<Mutex<Vec<pbconsensus::QbftConsensusMsg>>>;

    fn test_transport(
        value_rx: mpsc::Receiver<Any>,
    ) -> (
        Transport,
        mpsc::Receiver<qbft::Msg<ConsensusQbftTypes>>,
        SentMessages,
    ) {
        let (recv_tx, recv_rx) = mpsc::channel(8);
        let sent = SentMessages::default();
        let broadcaster = recording_broadcaster(sync::Arc::clone(&sent));
        let transport = Transport::new(
            broadcaster,
            secret_key(),
            value_rx,
            recv_tx,
            Sniffer::new(4, 1),
        );

        (transport, recv_rx, sent)
    }

    fn recording_broadcaster(sent: SentMessages) -> Broadcaster {
        Box::new(move |_ct, msg| {
            let sent = sync::Arc::clone(&sent);
            Box::pin(async move {
                sent.lock().unwrap().push(msg);
                Ok(())
            })
        })
    }

    async fn wait_for_sniffer_len(transport: &Transport, expected: usize) {
        timeout(Duration::from_secs(1), async {
            while transport.sniffer_instance().msgs.len() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    fn create_msg_request<'a>(duty: &'a Duty, privkey: &'a SecretKey) -> CreateMsgRequest<'a> {
        CreateMsgRequest {
            type_: qbft::MSG_PRE_PREPARE,
            duty,
            peer_idx: 1,
            round: 1,
            value_hash: [0u8; 32],
            prepared_round: 0,
            prepared_value_hash: [0u8; 32],
            values: ValueMap::new(),
            justification: &[],
            privkey,
        }
    }

    fn broadcast_request(value_hash: [u8; 32]) -> BroadcastRequest {
        BroadcastRequest {
            ct: CancellationToken::new(),
            type_: qbft::MSG_PRE_PREPARE,
            duty: duty(),
            peer_idx: 1,
            round: 2,
            value_hash,
            prepared_round: 0,
            prepared_value_hash: [0u8; 32],
            justification: vec![],
        }
    }

    fn empty_value_rx() -> mpsc::Receiver<Any> {
        let (_tx, rx) = mpsc::channel(1);
        rx
    }

    fn local_value_rx(hash: [u8; 32], value: Any) -> mpsc::Receiver<Any> {
        let (tx, rx) = mpsc::channel(1);
        assert_eq!(msg::hash_proto_bytes(&value.value).unwrap(), hash);
        tx.try_send(value).unwrap();
        rx
    }

    fn wrapped_msg(
        type_: qbft::MessageType,
        value_hash: [u8; 32],
        prepared_value_hash: [u8; 32],
        justification: Vec<QbftMsg>,
    ) -> msg::Msg {
        let mut values = ValueMap::new();
        if value_hash != [0u8; 32] {
            values.insert(value_hash, any_timestamp(1));
        }
        if prepared_value_hash != [0u8; 32] {
            values.insert(prepared_value_hash, any_timestamp(2));
        }

        msg::Msg::new(
            QbftMsg {
                r#type: i64::from(type_),
                duty: Some(pbcore::Duty::try_from(&duty()).unwrap()),
                peer_idx: 1,
                round: 2,
                value_hash: value_hash.to_vec().into(),
                prepared_round: 0,
                prepared_value_hash: prepared_value_hash.to_vec().into(),
                ..Default::default()
            },
            justification,
            sync::Arc::new(values),
        )
        .unwrap()
    }

    fn value_map(values: Vec<([u8; 32], Any)>) -> ValueMap {
        values.into_iter().collect()
    }

    fn value_hash(seconds: i64) -> [u8; 32] {
        hash_proto(&timestamp(seconds)).unwrap()
    }

    fn timestamp(seconds: i64) -> Timestamp {
        Timestamp { seconds, nanos: 0 }
    }

    fn any_timestamp(seconds: i64) -> Any {
        Any::from_msg(&timestamp(seconds)).unwrap()
    }

    fn duty() -> Duty {
        Duty::new(SlotNumber::new(42), DutyType::Attester)
    }

    fn secret_key() -> SecretKey {
        SecretKey::from_slice(&hex::decode(SIGNING_PRIVKEY).unwrap()).unwrap()
    }
}
