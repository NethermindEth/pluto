//! Low-level SSZ binary decoding helpers.

use crate::SszBinaryError;

/// Decodes a `u32` from 4 little-endian bytes.
pub fn decode_u32(bytes: &[u8]) -> Result<u32, SszBinaryError> {
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| SszBinaryError::InvalidLength {
            expected: 4,
            actual: bytes.len(),
        })?;
    Ok(u32::from_le_bytes(arr))
}

/// Decodes a `u64` from 8 little-endian bytes.
pub fn decode_u64(bytes: &[u8]) -> Result<u64, SszBinaryError> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SszBinaryError::InvalidLength {
            expected: 8,
            actual: bytes.len(),
        })?;
    Ok(u64::from_le_bytes(arr))
}
