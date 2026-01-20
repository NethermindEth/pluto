use charon_cluster::helpers::to_0x_hex;

use crate::obolapi::error::{Error, Result};

/// Decodes a hex-encoded string and expects it to be exactly `expected_len`
/// bytes. Accepts both 0x-prefixed strings and plain hex strings.
pub(crate) fn from_0x(data: &str, expected_len: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::EmptyHex);
    }
    Ok(charon_cluster::helpers::from_0x_hex_str(
        data,
        expected_len,
    )?)
}

/// Formats bytes as a bearer token string.
pub(crate) fn bearer_string(data: &[u8]) -> String {
    format!("Bearer {}", to_0x_hex(data))
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
        assert!(result.is_err());
    }

    #[test]
    fn test_bearer_string() {
        let bearer = bearer_string(&[0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(bearer, "Bearer 0x1234abcd");
    }
}
