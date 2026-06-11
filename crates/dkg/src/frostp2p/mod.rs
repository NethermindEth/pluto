//! FROST DKG P2P transport.
//!
//! This module provides the network transport used by `frost.rs`. The local
//! FROST code creates cryptographic round messages; this module moves those
//! messages between cluster nodes over libp2p.
//!
//! Round 1 has a public broadcast path and a private direct-P2P path:
//!
//! ```text
//! ROUND 1
//! =======
//!
//! Public broadcast, same data to everyone:
//!
//!   node1 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!   node2 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!   node3 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!   node4 === Round1Bcast(commitments/proof) ===> node1,node2,node3,node4
//!
//! Private direct P2P, different data per target:
//!
//!              +-- ShamirShare(for share_idx 2) --> node2
//!   node1 -----+-- ShamirShare(for share_idx 3) --> node3
//!              +-- ShamirShare(for share_idx 4) --> node4
//!
//!              +-- ShamirShare(for share_idx 1) --> node1
//!   node2 -----+-- ShamirShare(for share_idx 3) --> node3
//!              +-- ShamirShare(for share_idx 4) --> node4
//!
//!   ... same pattern for node3 and node4.
//!
//! Each direct message contains the private shares for that target node across
//! all validators in the DKG run. The shares cannot be broadcast because they
//! are secret, and node X does not send the same share to every peer.
//! ```
//!
//! Round 2 is broadcast-only. After round 1, each node has public commitments
//! from all nodes and private shares sent specifically to itself. It verifies
//! those private shares and broadcasts public verification material:
//!
//! ```text
//! ROUND 2
//! =======
//!
//!   node1 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!   node2 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!   node3 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!   node4 === Round2Bcast(public verification shares) ===> node1,node2,node3,node4
//!
//! No direct P2P is needed in round 2 because there is no new per-target secret.
//! ```
//!
//! End-to-end this module bridges the async FROST transport API to libp2p's
//! event-driven swarm:
//!
//! ```text
//! run_frost_parallel
//!        |
//!        v
//!   FrostP2P::round1
//!        |-----------------------> bcast::Component::broadcast_and_wait
//!        |
//!        +-----------------------> FrostP2PSender
//!                                       |
//!                                       v
//!                                FrostP2PBehaviour
//!                                       |
//!                                       v
//!                                FrostP2PHandler
//!                                       |
//!                                       v
//!                              direct libp2p streams
//!
//!   FrostP2P::round2
//!        |
//!        +-----------------------> bcast::Component
//! ```
//!
//! The module is split across two integration surfaces:
//!
//! - [`FrostP2PBehaviour`] owns the direct round-1 P2P libp2p protocol.
//! - [`FrostP2P`] implements the FROST transport by combining direct P2P with
//!   reliable broadcast through [`bcast::Component`].
//!
//! The outer DKG network behaviour must install both `bcast::Behaviour` and
//! [`FrostP2PBehaviour`]. [`FrostP2P`] uses
//! [`bcast::Component::broadcast_and_wait`] so each round observes reliable
//! broadcast completion before continuing.
//!
//! FROST observation events are emitted through [`FrostP2PBehaviour`] as swarm
//! events. Transport-level code forwards round and broadcast milestones back to
//! the behaviour through the same command channel used for direct sends.
//!
//! These transport objects are single-use for one DKG run. Dedup state is
//! intentionally not reset; create a fresh [`FrostP2PBehaviour`],
//! [`FrostP2PHandle`], and [`FrostP2P`] for each DKG.

use std::time::Duration;

use libp2p::{PeerId, swarm::StreamProtocol};

mod behaviour;
mod codec;
mod event;
mod handler;
mod transport;

pub(crate) use behaviour::{FrostP2PBehaviour, FrostP2PHandle, FrostP2PSender};
pub(crate) use event::FrostP2PEvent;
#[allow(unused_imports)]
pub(crate) use transport::{FrostP2P, new_frost_p2p};

/// bcast message ID for FROST round-1 broadcasts.
pub(crate) const ROUND1_CAST_ID: &str = "/charon/dkg/frost/2.0.0/round1/cast";
/// bcast message ID for FROST round-2 broadcasts.
pub(crate) const ROUND2_CAST_ID: &str = "/charon/dkg/frost/2.0.0/round2/cast";
/// Direct P2P protocol for FROST round-1 Shamir share delivery.
pub(crate) const ROUND1_P2P_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/charon/dkg/frost/2.0.0/round1/p2p");

/// Charon's default direct-P2P inbound read timeout.
pub(crate) const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Charon's default direct-P2P send timeout.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(7);

/// FROST direct-P2P delivery errors.
#[derive(Debug, thiserror::Error)]
pub enum FrostP2PError {
    /// The behaviour task is no longer running.
    #[error("frost p2p behaviour is no longer running")]
    BehaviourClosed,
    /// The outbound send failed.
    #[error("outbound send failed: {0}")]
    SendFailed(String),
    /// The peer was disconnected before the send completed.
    #[error("peer is not connected: {0}")]
    PeerNotConnected(PeerId),
    /// The peer is outside this FROST transport's configured peer set.
    #[error("unknown frost p2p peer: {0}")]
    UnknownPeer(PeerId),
    /// The send result channel closed.
    #[error("send result channel closed")]
    ResultClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_reference() {
        assert_eq!(ROUND1_CAST_ID, "/charon/dkg/frost/2.0.0/round1/cast");
        assert_eq!(
            ROUND1_P2P_PROTOCOL.as_ref(),
            "/charon/dkg/frost/2.0.0/round1/p2p"
        );
        assert_eq!(ROUND2_CAST_ID, "/charon/dkg/frost/2.0.0/round2/cast");
        assert_eq!(pluto_p2p::proto::MAX_MESSAGE_SIZE, 128 << 20);
        assert_eq!(RECEIVE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(SEND_TIMEOUT, Duration::from_secs(7));
    }
}
