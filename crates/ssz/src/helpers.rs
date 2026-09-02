//! Generic SSZ helper functions.

use crate::{Error, HashWalker, HexDecodeError, Result};

/// Decodes a `0x`-prefixed hex string and enforces an exact byte length.
pub fn from_0x_hex_str(s: &str, len: usize) -> std::result::Result<Vec<u8>, HexDecodeError> {
    if s.is_empty() {
        return Ok(vec![]);
    }

    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != len {
        return Err(HexDecodeError::InvalidLength {
            expected: len,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Appends an SSZ byte list with the provided maximum size.
pub fn put_byte_list<H: HashWalker>(
    hh: &mut H,
    bytes: &[u8],
    limit: usize,
    field: &str,
) -> Result<(), H::Error> {
    let elem_indx = hh.index();
    let byte_len = bytes.len();

    if byte_len > limit {
        return Err(Error::IncorrectListSize {
            namespace: "put_byte_list",
            field: field.to_string(),
            actual: byte_len,
            expected: limit,
        });
    }

    hh.append_bytes32(bytes).map_err(Error::HashWalkerError)?;
    hh.merkleize_with_mixin(elem_indx, byte_len, limit.div_ceil(32))
        .map_err(Error::HashWalkerError)?;

    Ok(())
}

/// Appends bytes as an SSZ fixed-size byte vector of length `n`.
pub fn put_bytes_n<H: HashWalker>(hh: &mut H, bytes: &[u8], n: usize) -> Result<(), H::Error> {
    if bytes.len() > n {
        return Err(Error::IncorrectListSize {
            namespace: "put_bytes_n",
            field: String::new(),
            actual: bytes.len(),
            expected: n,
        });
    }

    hh.put_bytes(&left_pad(bytes, n))
        .map_err(Error::HashWalkerError)?;

    Ok(())
}

/// Appends fixed-size bytes decoded from a `0x`-prefixed hex string.
pub fn put_hex_bytes_n<H: HashWalker>(hh: &mut H, hex: &str, n: usize) -> Result<(), H::Error> {
    let bytes = from_0x_hex_str(hex, n).map_err(Error::FailedToConvertHexString)?;
    hh.put_bytes(&left_pad(&bytes, n))
        .map_err(Error::HashWalkerError)?;
    Ok(())
}

/// Left-pads the input bytes with zeros up to `len`.
pub fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes.to_vec();
    }

    let pad_count = len.saturating_sub(bytes.len());
    let mut padded = vec![0; pad_count];
    padded.extend_from_slice(bytes);
    padded
}

/// Encodes bytes as a `0x`-prefixed lowercase hex string.
pub fn to_0x_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_0x_hex_str_separates_bad_hex_from_bad_length() {
        assert_eq!(from_0x_hex_str("0x1234", 2).unwrap(), vec![0x12, 0x34]);
        assert!(matches!(
            from_0x_hex_str("0xzz", 1),
            Err(HexDecodeError::InvalidHex(_))
        ));
        // Valid hex, wrong byte count: previously reported as bad hex.
        assert!(matches!(
            from_0x_hex_str("0x1234", 3),
            Err(HexDecodeError::InvalidLength {
                expected: 3,
                actual: 2
            })
        ));
    }

    #[test]
    fn left_pad_works() {
        assert_eq!(left_pad(&[0x12, 0x34], 4), vec![0x00, 0x00, 0x12, 0x34]);
        assert_eq!(left_pad(&[0xab], 3), vec![0x00, 0x00, 0xab]);
        assert_eq!(left_pad(&[1, 2, 3], 3), vec![1, 2, 3]);
        assert_eq!(left_pad(&[1, 2, 3], 2), vec![1, 2, 3]);
    }
}
