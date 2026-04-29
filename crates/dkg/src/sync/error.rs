use libp2p::PeerId;

/// Sync result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for the DKG sync protocol.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// The sync client was canceled.
    #[error("sync client canceled")]
    Canceled,

    /// The peer returned an application-level error.
    #[error("peer responded with error: {0}")]
    PeerRespondedWithError(String),

    /// The remote peer version did not match.
    #[error("mismatching version; expect={expected}, got={got}")]
    VersionMismatch {
        /// The expected version string.
        expected: String,
        /// The received version string.
        got: String,
    },

    /// The definition hash signature was invalid.
    #[error("invalid definition hash signature")]
    InvalidDefinitionHashSignature,

    /// The peer reported a step lower than the previous known step.
    #[error("peer reported step is behind the last known step")]
    PeerStepBehind,

    /// The peer reported a step too far ahead of the previous known step.
    #[error("peer reported step is ahead the last known step")]
    PeerStepAhead,

    /// The peer reported an invalid first step.
    #[error("peer reported abnormal initial step, expected 0 or 1")]
    AbnormalInitialStep,

    /// A peer was too far ahead for the awaited step.
    #[error("peer step is too far ahead")]
    PeerStepTooFarAhead,

    /// A checked step arithmetic operation overflowed.
    #[error("step overflow")]
    StepOverflow,

    /// The stream protocol could not be negotiated.
    #[error("protocol negotiation failed")]
    Unsupported,

    /// Failed to parse the peer version.
    #[error("parse peer version: {0}")]
    ParsePeerVersion(String),

    /// Failed to sign the definition hash.
    #[error("sign definition hash: {0}")]
    SignDefinitionHash(String),

    /// Failed to convert the local key to a libp2p keypair.
    #[error("convert secret key to libp2p keypair: {0}")]
    KeyConversion(String),

    /// An I/O error occurred while reading or writing the stream.
    #[error("i/o error: {0}")]
    Io(String),

    /// A peer ID could not be converted to a public key.
    #[error("peer error: {0}")]
    Peer(String),

    /// A sync server operation was attempted before the server was started.
    #[error("sync server not started")]
    ServerNotStarted,

    /// The sync client completion channel was closed unexpectedly.
    #[error("sync client completion channel closed")]
    CompletionChannelClosed,

    /// The sync client activation channel was unavailable.
    #[error("sync client activation channel unavailable")]
    ActivationChannelUnavailable,

    /// An inbound sync message failed validation.
    #[error("invalid sync message: peer={peer} err={error}")]
    InvalidSyncMessage {
        /// The peer whose message was invalid.
        peer: PeerId,
        /// The validation error.
        error: String,
    },

    /// The local peer ID was missing from the shared P2P context.
    #[error("local peer id missing from p2p context")]
    LocalPeerMissing,

    /// The configured peer set did not include the local peer ID.
    #[error("local peer id missing from sync peer set")]
    LocalPeerNotInPeerSet,
}
