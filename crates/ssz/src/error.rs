//! Generic SSZ error types.

/// Error type returned by SSZ helpers and hashing primitives.
#[derive(Debug, thiserror::Error)]
pub enum Error<E: std::error::Error> {
    /// Invalid list size or fixed-length byte size.
    #[error(
        "Invalid list size: function: {namespace}, field: {field}, actual: {actual}, expected: {expected}"
    )]
    IncorrectListSize {
        /// Namespace of the helper reporting the error.
        namespace: &'static str,
        /// Field name, if relevant.
        field: String,
        /// Actual length.
        actual: usize,
        /// Expected or maximum length.
        expected: usize,
    },

    /// Error returned by the underlying hash walker.
    #[error("Hash walker error: {0}")]
    HashWalkerError(E),

    /// Failed to decode or validate a hex string.
    #[error("Failed to convert hex string: {0}")]
    FailedToConvertHexString(hex::FromHexError),
}

/// Result type used by SSZ helper functions.
pub type Result<T, E> = std::result::Result<T, Error<E>>;
