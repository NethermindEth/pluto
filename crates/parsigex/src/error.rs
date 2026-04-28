//! Error types for the partial signature exchange protocol.

use pluto_core::{ParSigExCodecError, types::DutyTypeError};

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
    /// Generic verification error.
    #[error("{0}")]
    Other(String),
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
    /// Duty type error.
    #[error(transparent)]
    DutyTypeError(#[from] DutyTypeError),
}
