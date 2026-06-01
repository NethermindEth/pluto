//! QBFT inbound message admission.

use prost::{Message, Name};
use prost_types::Any;

use pluto_core::corepb::v1::{core as pbcore, priority as pbpriority};

use super::{
    component::DecodedValue,
    msg::{self, ValueMap},
};

/// Admission result.
pub type Result<T> = std::result::Result<T, Error>;

/// Admission errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prost::bytes::Bytes;
    use prost_types::Any;
    use test_case::test_case;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::qbft::{
        Consensus,
        component::tests::{config_base, consensus, duty, peers, secret_key},
    };
    use pluto_core::{
        corepb::v1::{consensus as pbconsensus, core as pbcore},
        qbft::{self, SomeMsg},
        types::DutyType,
    };

    #[tokio::test]
    async fn handle_rejects_invalid_outer_message() {
        let err = consensus(0, true)
            .handle(&CancellationToken::new(), None)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "invalid consensus message");
    }

    #[tokio::test]
    async fn handle_rejects_missing_inner_message() {
        let err = consensus(0, true)
            .handle(
                &CancellationToken::new(),
                Some(pbconsensus::QbftConsensusMsg::default()),
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
            .handle(
                &CancellationToken::new(),
                Some(consensus_msg(signed_msg(0))),
            )
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
            .handle(&CancellationToken::new(), Some(outer))
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
            .handle(&CancellationToken::new(), Some(outer))
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "qbft justification duty differs from message duty"
        );
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
            .handle(&CancellationToken::new(), Some(consensus_msg(msg)))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "value hash not found in values");
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
                &CancellationToken::new(),
                Some(pbconsensus::QbftConsensusMsg {
                    msg: Some(msg),
                    justification: vec![],
                    values: vec![any],
                }),
            )
            .await
            .unwrap();

        let mut recv_rx = inst.take_recv_rx().unwrap();
        let received = recv_rx.try_recv().unwrap();
        assert_eq!(received.value(), value_hash);
    }

    #[tokio::test]
    async fn handle_rejects_deadliner_false_as_duty_expired() {
        let consensus = Consensus::new(super::super::component::Config {
            peers: peers(),
            local_peer_idx: 0,
            ..config_base(true)
        })
        .unwrap();

        let err = consensus
            .handle(
                &CancellationToken::new(),
                Some(consensus_msg(signed_msg(0))),
            )
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "duty expired");
    }

    #[tokio::test]
    async fn handle_rejects_cancellation_after_verification() {
        let ct = CancellationToken::new();
        ct.cancel();

        let err = consensus(0, true)
            .handle(&ct, Some(consensus_msg(signed_msg(0))))
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
        let handle = consensus.handle(&ct, Some(consensus_msg(signed_msg(0))));
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
        let handle = consensus.handle(&ct, Some(consensus_msg(signed_msg(0))));
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
                &CancellationToken::new(),
                Some(pbconsensus::QbftConsensusMsg {
                    msg: Some(msg),
                    justification: vec![],
                    values: vec![any],
                }),
            )
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&inst, &consensus.get_instance_io(duty)));
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

    fn wrapped_msg() -> msg::Msg {
        msg::Msg::new(unsigned_msg(0), vec![], Arc::default()).unwrap()
    }
}
