//! Serialization helpers for hex encoding/decoding with 0x prefix.
//!
//! These helpers match the behavior of the Go implementation for handling
//! hex-encoded data with optional 0x prefixes and strict length validation.

use crate::obolapi::error::{Error, Result};

/// Decodes a hex-encoded string and expects it to be exactly `expected_len`
/// bytes. Accepts both 0x-prefixed strings and plain hex strings.
pub fn from_0x(data: &str, expected_len: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::EmptyHex);
    }

    let hex_str = data.strip_prefix("0x").unwrap_or(data);
    let bytes = hex::decode(hex_str)?;

    if bytes.len() != expected_len {
        return Err(Error::InvalidHexLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }

    Ok(bytes)
}

/// Encodes bytes to a hex string with 0x prefix.
/// Uses lowercase hex encoding and includes the 0x prefix.
pub fn to_0x(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

/// Formats bytes as a bearer token string.
pub fn bearer_string(data: &[u8]) -> String {
    format!("Bearer {}", to_0x(data))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_0x_with_prefix() {
        let bytes = from_0x("0x1234", 2).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34]);
    }

    #[test]
    fn test_from_0x_without_prefix() {
        let bytes = from_0x("1234", 2).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34]);
    }

    #[test]
    fn test_from_0x_empty_string() {
        let result = from_0x("", 2);
        assert!(matches!(result, Err(Error::EmptyHex)));
    }

    #[test]
    fn test_from_0x_wrong_length() {
        let result = from_0x("0x1234", 3);
        assert!(matches!(result, Err(Error::InvalidHexLength { .. })));
    }

    #[test]
    fn test_to_0x() {
        let hex = to_0x(&[0x12, 0x34]);
        assert_eq!(hex, "0x1234");
    }

    #[test]
    fn test_bearer_string() {
        let bearer = bearer_string(&[0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(bearer, "Bearer 0x1234abcd");
    }
}
