//! Wire protocol for the priority request/response protocol.
//!
//! A single round-trip exchanges one [`PriorityMsg`] request for one
//! [`PriorityMsg`] response, length-delimited on the wire as
//! `[unsigned varint length][protobuf bytes]`.

use std::time::Duration;

use libp2p::{core::upgrade::ReadyUpgrade, swarm::Stream};
use pluto_core::corepb::v1::priority::PriorityMsg;

use crate::PROTOCOL_ID;

/// Wire token negotiated for the priority protocol.
///
/// The canonical protocol identifier is the slug-less [`PROTOCOL_ID`]. The
/// negotiated token derives from it directly, so [`PROTOCOL_ID`] is the single
/// source of truth.
///
/// `libp2p`'s multistream-select requires every negotiated protocol token to
/// begin with `/` and rejects any other form before it reaches the wire, so the
/// token offered for negotiation is [`PROTOCOL_ID`] with a leading `/`. This is
/// the one place where the wire form differs from the canonical identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityProtocol;

/// Negotiated wire token: the canonical identifier with the leading `/` that
/// multistream-select mandates. Tied to [`PROTOCOL_ID`] by a compile-time
/// assertion below, keeping the canonical identifier the single source of
/// truth.
const WIRE_TOKEN: &str = "/charon/priority/2.0.0";

/// The wire token must be the canonical identifier prefixed with `/`.
const _: () = {
    let id = PROTOCOL_ID.as_bytes();
    let wire = WIRE_TOKEN.as_bytes();
    assert!(
        wire.len() == id.len() + 1,
        "wire token must be /<protocol id>"
    );
    assert!(wire[0] == b'/', "wire token must start with /");
    let mut i = 0;
    while i < id.len() {
        assert!(wire[i + 1] == id[i], "wire token must equal /<protocol id>");
        i += 1;
    }
};

impl AsRef<str> for PriorityProtocol {
    fn as_ref(&self) -> &str {
        WIRE_TOKEN
    }
}

/// Upgrade negotiating the priority protocol on inbound and outbound streams.
pub(crate) type PriorityUpgrade = ReadyUpgrade<PriorityProtocol>;

/// Returns the upgrade used to negotiate the priority protocol.
pub(crate) fn upgrade() -> PriorityUpgrade {
    ReadyUpgrade::new(PriorityProtocol)
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

    /// The canonical protocol identifier carries no leading slug, exactly as
    /// the reference implementation registers it.
    #[test]
    fn canonical_protocol_id_has_no_leading_slash() {
        assert_eq!(PROTOCOL_ID, "charon/priority/2.0.0");
        assert!(!PROTOCOL_ID.starts_with('/'));
    }

    /// The token offered for negotiation is the canonical identifier with the
    /// leading `/` that multistream-select mandates; no other divergence.
    #[test]
    fn wire_token_is_canonical_id_with_leading_slash() {
        assert_eq!(PriorityProtocol.as_ref(), "/charon/priority/2.0.0");
        assert_eq!(PriorityProtocol.as_ref(), format!("/{PROTOCOL_ID}"));
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
