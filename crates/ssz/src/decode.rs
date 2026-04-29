//! Low-level SSZ binary decoding helpers.

use crate::SszBinaryError;

/// Decodes a `u8` from a single byte.
pub fn decode_u8(bytes: &[u8]) -> Result<u8, SszBinaryError> {
    let arr: [u8; 1] = bytes
        .try_into()
        .map_err(|_| SszBinaryError::InvalidLength {
            expected: 1,
            actual: bytes.len(),
        })?;
    Ok(arr[0])
}

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

/// Decodes a `bool` from a single SSZ byte.
pub fn decode_bool(bytes: &[u8]) -> Result<bool, SszBinaryError> {
    match decode_u8(bytes)? {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(SszBinaryError::InvalidBool(v)),
    }
}

/// Decodes a fixed-size byte array from a slice.
pub fn decode_fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SszBinaryError> {
    bytes.try_into().map_err(|_| SszBinaryError::InvalidLength {
        expected: N,
        actual: bytes.len(),
    })
}
