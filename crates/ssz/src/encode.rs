//! Low-level SSZ binary encoding helpers.

/// Encodes a `u32` value as 4 little-endian bytes.
pub fn encode_u32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Encodes a `u64` value as 8 little-endian bytes.
pub fn encode_u64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}
