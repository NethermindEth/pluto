//! Error types for the priority protocol.

use libp2p::PeerId;
use pluto_core::{deadline::DeadlineError, types::Duty};
use thiserror::Error;

/// Result alias for the priority crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the priority protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// No messages were provided to calculate a result.
    #[error("messages empty")]
    MessagesEmpty,

    /// Messages did not all carry the same duty.
    #[error("mismatching duties")]
    MismatchingDuties,

    /// Two messages claimed the same peer id.
    #[error("duplicate peer")]
    DuplicatePeer,

    /// A single peer proposed the same topic twice.
    #[error("duplicate topic")]
    DuplicateTopic,

    /// A topic proposed at least `maxPriorities` priorities.
    #[error("max priority reached")]
    MaxPriorityReached,

    /// A topic proposed the same priority twice.
    #[error("duplicate priority")]
    DuplicatePriority,

    /// A prioritise instance is already running for this duty.
    #[error("duplicate priority instance for duty {0}")]
    DuplicateInstance(Duty),

    /// Hashing a topic or priority protobuf failed.
    #[error("hash proto: {0}")]
    HashProto(#[source] pluto_consensus::qbft::msg::Error),

    /// A message carried no signature.
    #[error("empty signature")]
    EmptySignature,

    /// A message claimed a peer id not in the cluster.
    #[error("unknown peer id")]
    UnknownPeerId,

    /// A message signature did not match the claimed peer's public key.
    #[error("invalid signature")]
    InvalidSignature,

    /// A message was missing required proto fields (duty).
    #[error("invalid priority msg proto fields")]
    InvalidMsgProtoFields,

    /// An `Any`-wrapped topic or priority value was not a structpb string.
    #[error("topic value not a string")]
    TopicValueNotString,

    /// An `Any` envelope could not be decoded as a structpb value: it carried
    /// the wrong `type_url` or undecodable bytes.
    #[error("mismatched message type")]
    MismatchedMessageType,

    /// Decoding a topic result's topic `Any` failed.
    #[error("anypb topic: {0}")]
    AnypbTopic(#[source] Box<Error>),

    /// Decoding a topic result's priority `Any` failed.
    #[error("anypb priority: {0}")]
    AnypbPriority(#[source] Box<Error>),

    /// Signing a message hash failed.
    #[error("sign: {0}")]
    Sign(#[source] pluto_k1util::K1UtilError),

    /// Recovering a public key from a signature failed.
    #[error("sig to pub: {0}")]
    Recover(#[source] pluto_k1util::K1UtilError),

    /// Deriving a peer's public key from its peer id failed.
    #[error("peer id to key: {0}")]
    PeerKey(#[source] pluto_p2p::peer::PeerError),

    /// Decoding an `Any`-wrapped structpb value failed.
    #[error("anypb decode: {0}")]
    DecodeAny(#[source] prost::DecodeError),

    /// A peer does not support the priority protocol.
    #[error("priority protocol not supported")]
    Unsupported,

    /// A configured cluster peer is absent from the shared `P2PContext`'s
    /// known-peer set. Such a peer would be gated to a no-op handler, so its
    /// exchange would be silently skipped and consensus could proceed on a
    /// partial message set. Rejected at construction so a mis-wired context
    /// fails fast instead of degrading silently.
    #[error("peer {peer} not in p2p context known peers")]
    PeerNotInContext {
        /// The peer present in the prioritiser's peer set but missing from the
        /// context.
        peer: PeerId,
    },

    /// A libp2p stream or dial error occurred during an exchange.
    #[error("priority transport: {0}")]
    Transport(String),

    /// The prioritiser transport was shut down.
    #[error("prioritiser shutdown")]
    Shutdown,

    /// Calculating the deterministic priority result failed.
    #[error("calculate priority protocol result: {0}")]
    CalculateResult(#[source] Box<Error>),

    /// Enqueuing a received request timed out before the deadline.
    #[error("timeout enqueuing request")]
    TimeoutEnqueuing,

    /// Waiting for this node's proposed priorities timed out before the
    /// deadline.
    #[error("timeout waiting for proposed priorities")]
    TimeoutWaiting,

    /// A received message's peer id did not match the connection's peer id.
    #[error("invalid priority message peer id")]
    InvalidPeerId,

    /// The duty for a received message had already expired.
    #[error("duty expired")]
    DutyExpired,

    /// The duty has no future deadline when a prioritise instance was started.
    #[error("duty already expired")]
    DutyAlreadyExpired,

    /// Computing the duty's deadline failed.
    #[error("compute deadline: {0}")]
    Deadline(#[source] DeadlineError),

    /// The deadliner could not compute the duty's deadline (computation error
    /// or shutdown), as distinct from the duty being expired.
    #[error("deadline computation failed")]
    DeadlineComputeFailed,

    /// The prioritise instance was cancelled via its `CancellationToken`.
    #[error("prioritise cancelled")]
    Cancelled,

    /// A prioritise instance failed for a non-cancelled reason.
    ///
    /// Carries the `duty` as context and wraps the underlying failure.
    #[error("prioritise: {source}")]
    Prioritise {
        /// The duty whose prioritisation failed.
        duty: Duty,
        /// The underlying failure.
        #[source]
        source: Box<Error>,
    },
}
