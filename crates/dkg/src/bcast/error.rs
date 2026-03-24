//! Error types for the DKG reliable-broadcast protocol.

use std::{error::Error as StdError, fmt};

use libp2p::PeerId;

/// Result type returned by the public reliable-broadcast API.
pub type Result<T> = std::result::Result<T, Error>;

/// Cloneable failure used for handler-to-behaviour communication.
#[derive(Debug, Clone)]
pub enum Failure {
    /// The operation timed out.
    Timeout,
    /// The remote peer does not support the protocol.
    Unsupported,
    /// The operation failed due to an I/O error.
    Io {
        /// The underlying error message.
        message: String,
    },
    /// The operation failed for another reason.
    Other {
        /// The underlying error message.
        message: String,
    },
}

impl Failure {
    /// Creates a new [`Failure::Io`] value.
    pub fn io(error: impl fmt::Display) -> Self {
        Self::Io {
            message: error.to_string(),
        }
    }

    /// Creates a new [`Failure::Other`] value.
    pub fn other(error: impl fmt::Display) -> Self {
        Self::Other {
            message: error.to_string(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("operation timed out"),
            Self::Unsupported => f.write_str("protocol negotiation failed"),
            Self::Io { message } => write!(f, "i/o error: {message}"),
            Self::Other { message } => f.write_str(message),
        }
    }
}

impl StdError for Failure {}

/// User-facing reliable-broadcast error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The message ID was registered more than once.
    #[error("message id already registered: {0}")]
    DuplicateMessageId(String),

    /// The message ID is unknown.
    #[error("unknown message id: {0}")]
    UnknownMessageId(String),

    /// The local peer is missing from the configured peer list.
    #[error("local peer is not present in the configured peer list")]
    LocalPeerMissing,

    /// The remote peer is not currently connected.
    #[error("peer is not connected: {0}")]
    PeerNotConnected(PeerId),

    /// The behaviour task is no longer running.
    #[error("bcast behaviour is no longer running")]
    BehaviourClosed,

    /// The broadcast was cancelled before completion.
    #[error("broadcast was cancelled before completion")]
    BroadcastCancelled,

    /// The outbound operation failed.
    #[error("outbound operation to {peer} failed: {failure}")]
    OutboundFailure {
        /// The peer involved in the failure.
        peer: PeerId,
        /// The handler-level failure reason.
        failure: Failure,
    },

    /// The number of signatures does not match the configured peer list.
    #[error("invalid number of signatures: expected {expected}, actual {actual}")]
    InvalidSignatureCount {
        /// Expected signature count.
        expected: usize,
        /// Actual signature count.
        actual: usize,
    },

    /// A signature did not have the expected 65-byte length.
    #[error("invalid signature length: expected 65 bytes, actual {0}")]
    InvalidSignatureLength(usize),

    /// A signature could not be verified.
    #[error("invalid signature for peer {0}")]
    InvalidSignature(PeerId),

    /// The repeated hash for the same `(peer, msg_id)` differed.
    #[error("duplicate id with mismatching hash")]
    DuplicateMismatchingHash,

    /// A required message body field was absent.
    #[error("missing protobuf field: {0}")]
    MissingField(&'static str),

    /// Protobuf encoding failed.
    #[error("protobuf encode failed: {0}")]
    Encode(#[from] prost::EncodeError),

    /// Protobuf decoding failed.
    #[error("protobuf decode failed: {0}")]
    Decode(#[from] prost::DecodeError),

    /// An I/O operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A libp2p peer/public-key conversion failed.
    #[error("peer conversion failed: {0}")]
    Peer(#[from] pluto_p2p::peer::PeerError),

    /// A secp256k1 signing or verification step failed.
    #[error("k1 operation failed: {0}")]
    K1(#[from] pluto_k1util::K1UtilError),

    /// A user-supplied check or callback failed.
    #[error("{0}")]
    Message(String),
}
