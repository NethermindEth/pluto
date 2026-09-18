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
    FailedToConvertHexString(HexDecodeError),
}

/// Error type returned when decoding a hex string of an expected byte length.
#[pluto_stacktrace::located]
#[derive(Debug, thiserror::Error)]
pub enum HexDecodeError {
    /// The string is not valid hex.
    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// The string decoded successfully, but to the wrong number of bytes.
    #[error("invalid decoded length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        actual: usize,
    },
}

/// Result type used by SSZ helper functions.
pub type Result<T, E> = std::result::Result<T, Error<E>>;

#[cfg(test)]
mod tests {
    use super::HexDecodeError;

    fn decode_hex(input: &str) -> std::result::Result<Vec<u8>, HexDecodeError> {
        Ok(hex::decode(input)?)
    }

    #[test]
    fn located_from_conversion_keeps_message_and_carries_a_trace() {
        let err = decode_hex("zz").expect_err("`zz` is not valid hex");

        assert_eq!(
            err.to_string(),
            "invalid hex string: Invalid character 'z' at position 0"
        );

        let debug = format!("{err:?}");
        assert!(
            debug.contains("FromHexError"),
            "Debug lost the inner error: {debug}"
        );
        assert!(
            debug.contains(file!()),
            "Debug lost the raise location: {debug}"
        );
        assert!(
            debug.contains("\tat "),
            "Debug lost the captured trace: {debug}"
        );
    }
}
