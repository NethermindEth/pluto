//! Priority protocol: deterministic cluster-wide priority resolution.
//!
//! Coordinates a cluster-wide priority result per duty by exchanging signed
//! priority messages between peers and computing a deterministic
//! [`calculate::calculate_result`].

/// Deterministic priority result calculation and message validation.
pub mod calculate;
/// Friendly priority API: domain types, signing, and proto conversions.
pub mod component;
/// Consensus seam for proposing and subscribing to priority results.
pub mod consensus;
/// Error types for the priority protocol.
pub mod error;
/// libp2p request/response transport for the priority protocol.
pub mod p2p;
/// Priority protocol engine: per-duty exchange and consensus orchestration.
pub mod prioritiser;

pub use component::{
    Component, ComponentSubscriber, ScoredPriority, TopicProposal, TopicResult, new_component,
};
pub use consensus::{Consensus, ConsensusError, PrioritySubscriber};
pub use error::{Error, Result};
pub use prioritiser::{PROTOCOL_ID, Prioritiser};

/// Returns the priority protocol identifiers this implementation supports.
///
/// Used to register protocol support in a peer store.
pub fn protocols() -> Vec<&'static str> {
    vec![PROTOCOL_ID]
}
