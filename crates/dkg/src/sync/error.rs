use pluto_core::version::SemVer;

/// Sync result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for the DKG sync protocol.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Generic message.
    #[error("{0}")]
    Message(String),

    /// The sync client was canceled.
    #[error("sync client canceled")]
    Canceled,

    /// The peer returned an application-level error.
    #[error("peer responded with error: {0}")]
    PeerRespondedWithError(String),

    /// The remote peer version did not match.
    #[error("mismatching charon version; expect={expected}, got={got}")]
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

    /// The stream protocol could not be negotiated.
    #[error("protocol negotiation failed")]
    Unsupported,

    /// A message length prefix was invalid.
    #[error("invalid sized protobuf length: {0}")]
    InvalidMessageLength(i64),

    /// Failed to parse the peer version.
    #[error("parse peer version: {0}")]
    ParsePeerVersion(String),

    /// Failed to sign the definition hash.
    #[error("sign definition hash: {0}")]
    SignDefinitionHash(String),

    /// Failed to convert the local key to a libp2p keypair.
    #[error("convert secret key to libp2p keypair: {0}")]
    KeyConversion(String),

    /// Failed to decode a protobuf message.
    #[error("protobuf decode failed: {0}")]
    Decode(String),

    /// Failed to encode a protobuf message.
    #[error("protobuf encode failed: {0}")]
    Encode(String),

    /// An I/O error occurred while reading or writing the stream.
    #[error("i/o error: {0}")]
    Io(String),

    /// A peer ID could not be converted to a public key.
    #[error("peer error: {0}")]
    Peer(String),

    /// A sync server operation was attempted before the server was started.
    #[error("sync server not started")]
    ServerNotStarted,

    /// The local peer ID was missing from the shared P2P context.
    #[error("local peer id missing from p2p context")]
    LocalPeerMissing,
}

impl Error {
    /// Creates a new generic message error.
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    /// Creates an I/O error from the given source.
    pub fn io(error: impl std::fmt::Display) -> Self {
        Self::Io(error.to_string())
    }

    /// Creates a protobuf decode error from the given source.
    pub fn decode(error: impl std::fmt::Display) -> Self {
        Self::Decode(error.to_string())
    }

    /// Creates a protobuf encode error from the given source.
    pub fn encode(error: impl std::fmt::Display) -> Self {
        Self::Encode(error.to_string())
    }

    /// Creates a peer conversion error from the given source.
    pub fn peer(error: impl std::fmt::Display) -> Self {
        Self::Peer(error.to_string())
    }

    /// Creates a version mismatch error matching Go's wire string.
    pub fn version_mismatch(expected: &SemVer, got: &str) -> Self {
        Self::VersionMismatch {
            expected: expected.to_string(),
            got: got.to_string(),
        }
    }

    /// Returns true if the error should be treated like Go's relay reset path.
    pub fn is_relay_error(&self) -> bool {
        matches!(self, Self::Io(message) if {
            let lowercase = message.to_ascii_lowercase();
            lowercase.contains("connection reset")
                || lowercase.contains("resource scope closed")
                || lowercase.contains("broken pipe")
        })
    }
}
