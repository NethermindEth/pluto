//! Partial signature exchange protocol.
//!
//! In-memory exchange test helpers are intentionally not part of this module.
//! We should revisit that only when wiring higher-level integration coverage in
//! `testutil/integration`.
//!
//! The reason is dependency direction: `core` sits above `testutil` in the
//! dependency tree, so test scaffolding for integration-style exchange should
//! not live in `core`.

pub mod behaviour;
mod handler;
mod protocol;
pub(crate) mod signed_data;

use libp2p::PeerId;

pub use behaviour::{
    Behaviour, Config, DutyGater, Error as BehaviourError, Event, Handle, Verifier, VerifyError,
};
pub use handler::Handler;
pub use protocol::{decode_message, encode_message};

/// The protocol name for partial signature exchange (version 2.0.0).
pub const PROTOCOL_NAME: libp2p::swarm::StreamProtocol =
    libp2p::swarm::StreamProtocol::new("/charon/parsigex/2.0.0");

/// Returns the supported protocols in precedence order.
pub fn protocols() -> Vec<libp2p::swarm::StreamProtocol> {
    vec![PROTOCOL_NAME]
}

/// Error type for proto and conversion operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Missing duty or data set fields.
    #[error("invalid parsigex msg fields")]
    InvalidMessageFields,

    /// Invalid partial signed data set proto.
    #[error("invalid partial signed data set proto fields")]
    InvalidParSignedDataSetFields,

    /// Invalid partial signed proto.
    #[error("invalid partial signed proto")]
    InvalidParSignedProto,

    /// Invalid duty type.
    #[error("invalid duty")]
    InvalidDuty,

    /// Unsupported duty type.
    #[error("unsupported duty type")]
    UnsupportedDutyType,

    /// Deprecated builder proposer duty.
    #[error("deprecated duty builder proposer")]
    DeprecatedBuilderProposer,

    /// Failed to parse a public key.
    #[error("invalid public key: {0}")]
    InvalidPubKey(String),

    /// Invalid share index.
    #[error("invalid share index")]
    InvalidShareIndex,

    /// Serialization failed.
    #[error("marshal signed data: {0}")]
    Serialize(#[from] serde_json::Error),

    /// Broadcast failed for a peer.
    #[error("broadcast to peer {peer} failed")]
    BroadcastPeer {
        /// Peer for which the broadcast failed.
        peer: PeerId,
    },
}

/// Result type for partial signature exchange operations.
pub type Result<T> = std::result::Result<T, Error>;
