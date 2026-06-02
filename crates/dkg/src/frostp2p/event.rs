//! Observation events emitted by the FROST P2P transport.

use libp2p::PeerId;

/// Event emitted while the FROST P2P transport progresses through its rounds.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum FrostP2PEvent {
    /// A FROST transport round started.
    RoundStarted {
        /// Round number.
        round: u8,
    },
    /// A FROST broadcast was started.
    BroadcastStarted {
        /// Round number.
        round: u8,
    },
    /// A FROST broadcast completed.
    BroadcastCompleted {
        /// Round number.
        round: u8,
    },
    /// A FROST broadcast failed.
    BroadcastFailed {
        /// Round number.
        round: u8,
        /// Failure message.
        error: String,
    },
    /// Round-1 direct P2P sends started.
    DirectSendStarted {
        /// Number of target peers.
        peer_count: usize,
    },
    /// A round-1 direct P2P message was delivered to a peer.
    DirectSent {
        /// Target peer.
        peer_id: PeerId,
    },
    /// A round-1 direct P2P message failed to deliver.
    DirectSendFailed {
        /// Target peer.
        peer_id: PeerId,
        /// Failure message.
        error: String,
    },
    /// A valid round-1 direct P2P message was received from a peer.
    DirectReceived {
        /// Source peer.
        peer_id: PeerId,
    },
    /// A FROST transport round completed.
    RoundCompleted {
        /// Round number.
        round: u8,
    },
    /// Both FROST P2P transport rounds completed.
    ProtocolCompleted,
}
