//! Wire protocol for the priority request/response protocol.
//!
//! A single round-trip exchanges one [`PriorityMsg`] request for one
//! [`PriorityMsg`] response, length-delimited on the wire as
//! `[unsigned varint length][protobuf bytes]`.

use std::time::Duration;

use libp2p::{core::upgrade::ReadyUpgrade, swarm::Stream};
use pluto_core::corepb::v1::priority::PriorityMsg;

use crate::PROTOCOL_ID;

/// Upgrade negotiating the priority protocol on inbound and outbound streams.
///
/// Uses `&'static str` rather than `StreamProtocol`: the latter is sealed and
/// rejects [`PROTOCOL_ID`]'s slash-less token, while `ReadyUpgrade` only
/// requires `AsRef<str> + Clone`. Negotiation of the slash-less token is
/// enabled by the patched multistream-select (see
/// third_party/multistream-select).
pub(crate) type PriorityUpgrade = ReadyUpgrade<&'static str>;

/// Returns the upgrade used to negotiate the priority protocol.
pub(crate) fn upgrade() -> PriorityUpgrade {
    ReadyUpgrade::new(PROTOCOL_ID)
}

/// Maximum protobuf message size (128MB).
pub(crate) const MAX_MESSAGE_SIZE: usize = 128 << 20;

/// Maximum time a peer is given to deliver an inbound request.
///
/// A peer that opens a stream but does not write within this window has its
/// stream dropped.
pub(crate) const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time for a full outbound exchange (open, write, read).
///
/// Exceeds [`RECEIVE_TIMEOUT`] by the round-trip hop allowance, matching the
/// send deadline applied to the whole request/response round-trip.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(7);

/// Sends a request and reads the peer's response on a fresh outbound stream.
pub(crate) async fn send_receive(
    stream: &mut Stream,
    request: &PriorityMsg,
) -> std::io::Result<PriorityMsg> {
    pluto_p2p::proto::write_protobuf(stream, request).await?;
    pluto_p2p::proto::read_protobuf_with_max_size(stream, MAX_MESSAGE_SIZE).await
}

/// Reads an inbound request from a stream.
pub(crate) async fn read_request(stream: &mut Stream) -> std::io::Result<PriorityMsg> {
    pluto_p2p::proto::read_protobuf_with_max_size(stream, MAX_MESSAGE_SIZE).await
}

/// Rejects a decoded request that omits a required message field.
///
/// Applies the pre-handler proto validation to received messages: any
/// non-optional nested message field that is absent makes the whole message
/// invalid. For [`PriorityMsg`] the absent-field cases reachable from the wire
/// are the `duty` field and the `topic` of any proposed topic; an empty
/// `topics` or `priorities` list is valid.
pub(crate) fn check_required_fields(msg: &PriorityMsg) -> bool {
    if msg.duty.is_none() {
        return false;
    }

    msg.topics.iter().all(|proposal| proposal.topic.is_some())
}

/// Writes a response to a stream.
pub(crate) async fn write_response(
    stream: &mut Stream,
    response: &PriorityMsg,
) -> std::io::Result<()> {
    pluto_p2p::proto::write_protobuf(stream, response).await
}

#[cfg(test)]
mod tests {
    use pluto_core::corepb::v1::{
        core::Duty,
        priority::{PriorityMsg, PriorityTopicProposal},
    };
    use prost_types::Any;

    use super::*;

    /// The protocol identifier is the slash-less wire token, matching the
    /// reference implementation exactly for cross-implementation interop.
    #[test]
    fn protocol_id_matches_reference_wire_token() {
        assert_eq!(PROTOCOL_ID, "charon/priority/2.0.0");
        assert!(!PROTOCOL_ID.starts_with('/'));
    }

    fn any() -> Any {
        Any {
            type_url: "type.googleapis.com/google.protobuf.Value".to_owned(),
            value: Vec::new(),
        }
    }

    #[test]
    fn required_fields_accepts_present_fields() {
        let msg = PriorityMsg {
            duty: Some(Duty { slot: 1, r#type: 0 }),
            topics: vec![PriorityTopicProposal {
                topic: Some(any()),
                priorities: vec![any()],
            }],
            peer_id: "p".to_owned(),
            signature: Default::default(),
        };
        assert!(check_required_fields(&msg));
    }

    #[test]
    fn required_fields_rejects_missing_duty() {
        let msg = PriorityMsg {
            duty: None,
            topics: Vec::new(),
            peer_id: "p".to_owned(),
            signature: Default::default(),
        };
        assert!(!check_required_fields(&msg));
    }

    #[test]
    fn required_fields_rejects_missing_topic_any() {
        let msg = PriorityMsg {
            duty: Some(Duty { slot: 1, r#type: 0 }),
            topics: vec![PriorityTopicProposal {
                topic: None,
                priorities: Vec::new(),
            }],
            peer_id: "p".to_owned(),
            signature: Default::default(),
        };
        assert!(!check_required_fields(&msg));
    }

    #[test]
    fn required_fields_accepts_empty_topics() {
        let msg = PriorityMsg {
            duty: Some(Duty { slot: 1, r#type: 0 }),
            topics: Vec::new(),
            peer_id: "p".to_owned(),
            signature: Default::default(),
        };
        assert!(check_required_fields(&msg));
    }
}
