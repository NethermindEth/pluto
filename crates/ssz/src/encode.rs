//! Low-level SSZ binary encoding helpers.

/// Encodes a `u8` value as a single byte.
pub fn encode_u8(value: u8) -> [u8; 1] {
    [value]
}

/// Encodes a `u32` value as 4 little-endian bytes.
pub fn encode_u32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Encodes a `u64` value as 8 little-endian bytes.
pub fn encode_u64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Encodes a `bool` as a single SSZ byte (`0x01` for `true`, `0x00` for
/// `false`).
pub fn encode_bool(value: bool) -> [u8; 1] {
    [u8::from(value)]
}
