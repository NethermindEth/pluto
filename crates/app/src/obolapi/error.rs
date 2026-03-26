//! Error types for the Obol API client.

use reqwest::{Method, StatusCode};

/// Result type for Obol API operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for Obol API client operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No exit found for the given validator public key (HTTP 404).
    #[error("no exit for the given validator public key")]
    NoExit,

    /// HTTP request failed with status code and response body.
    #[error("HTTP {method} request failed: status {status}, body: {body}")]
    HttpError {
        /// HTTP method (GET, POST, DELETE).
        method: Method,
        /// HTTP status code.
        status: StatusCode,
        /// Response body.
        body: String,
    },

    /// Failed to parse URL.
    #[error("failed to parse URL: {0}")]
    UrlParse(#[from] url::ParseError),

    /// HTTP client error.
    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex decoding error.
    #[error("hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Empty hex string.
    #[error("empty hex string")]
    EmptyHex,

    /// SSZ hashing error from [`pluto_cluster`].
    #[error("SSZ hashing error: {0}")]
    Ssz(#[from] pluto_cluster::ssz::SSZError<pluto_ssz::Hasher>),

    /// K1 signing error.
    #[error("K1 signing error: {0}")]
    K1Sign(#[from] pluto_k1util::K1UtilError),

    /// Crypto/threshold aggregation error.
    #[error("crypto error: {0}")]
    Crypto(#[from] pluto_crypto::types::Error),

    /// Invalid signature string size.
    #[error("signature string has invalid size: {0}")]
    InvalidSignatureSize(usize),

    /// Failed to convert share index to u8.
    #[error("failed to convert share index to u8: {0}")]
    FailedToConvertShareIndexToU8(#[from] std::num::TryFromIntError),

    /// Math overflow error.
    #[error("math overflow error")]
    MathOverflow,

    /// Epoch parsing error.
    #[error("epoch parsing error: {0}")]
    EpochParse(#[from] std::num::ParseIntError),

    /// SSZ hasher error.
    #[error("SSZ hasher error: {0}")]
    HasherError(#[from] pluto_ssz::HasherError),
}

impl From<pluto_ssz::Error<pluto_ssz::HasherError>> for Error {
    fn from(error: pluto_ssz::Error<pluto_ssz::HasherError>) -> Self {
        Self::Ssz(pluto_cluster::ssz::SSZError::from(error))
    }
}
