//! Error types for the partial signature exchange protocol.

use pluto_core::{
    ParSigExCodecError,
    eth2signeddata::Eth2SignedDataError,
    types::{Duty, DutyTypeError},
};

/// Result type for partial signature exchange.
pub type Result<T> = std::result::Result<T, Error>;

/// Handler-to-behaviour failure.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// Stream negotiation or operation timed out.
    #[error("parsigex timed out")]
    Timeout,
    /// Invalid payload received.
    #[error("invalid parsigex payload")]
    InvalidPayload,
    /// Duty not accepted by the gater.
    #[error("invalid duty")]
    InvalidDuty,
    /// Signature verification failed.
    #[error("invalid partial signature: {0}")]
    InvalidPartialSignature(String),
    /// I/O error.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// Codec error.
    #[error("codec error: {0}")]
    Codec(String),
}

impl Clone for Failure {
    fn clone(&self) -> Self {
        match self {
            Self::Timeout => Self::Timeout,
            Self::InvalidPayload => Self::InvalidPayload,
            Self::InvalidDuty => Self::InvalidDuty,
            Self::InvalidPartialSignature(error) => Self::InvalidPartialSignature(error.clone()),
            Self::Io(error) => Self::Io(std::io::Error::new(error.kind(), error.to_string())),
            Self::Codec(error) => Self::Codec(error.clone()),
        }
    }
}

/// Error type for signature verification callbacks.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Unknown validator public key.
    #[error("unknown pubkey, not part of cluster lock")]
    UnknownPubKey,
    /// Invalid share index for the validator.
    #[error("invalid shareIdx")]
    InvalidShareIndex,
    /// Invalid signed-data family for the duty.
    #[error("invalid eth2 signed data")]
    InvalidSignedDataFamily,
    /// The eth2 BLS signature failed to verify against the sender's public
    /// share.
    #[error("invalid signature for duty {duty}: {source}")]
    InvalidSignature {
        /// Duty whose partial signature failed verification.
        duty: Duty,
        /// Underlying verification failure.
        #[source]
        source: Eth2SignedDataError,
    },
}

/// Error type for partial signature exchange operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Message conversion failed.
    #[error(transparent)]
    Codec(#[from] ParSigExCodecError),
    /// Handle channel closed.
    #[error("parsigex handle closed")]
    Closed,
    /// Broadcast failed after being accepted by the behaviour.
    #[error("parsigex broadcast {request_id} failed: {error}")]
    BroadcastFailed {
        /// Request identifier.
        request_id: u64,
        /// Failure reason.
        #[source]
        error: Failure,
    },
    /// Duty type error.
    #[error(transparent)]
    DutyTypeError(#[from] DutyTypeError),
}
