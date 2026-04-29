//! Shared SSZ hashing primitives, helpers, and container wrappers.

pub mod decode;
pub mod encode;
mod error;
mod hasher;
mod helpers;
pub mod serde_utils;
mod types;

/// Generic SSZ error types.
pub use error::{Error, Result};
/// SSZ hashing walker and merkleization runtime.
pub use hasher::{HashFn, HashWalker, Hasher, HasherError, calculate_limit};
/// Generic SSZ helper utilities.
pub use helpers::{
    from_0x_hex_str, left_pad, put_byte_list, put_bytes_n, put_hex_bytes_n, to_0x_hex,
};
/// Generic SSZ list, vector, and bitfield wrappers.
pub use types::{BitList, BitVector, SszList, SszVector};

/// Error type for SSZ binary encode/decode operations.
#[derive(Debug, thiserror::Error)]
pub enum SszBinaryError {
    /// Byte slice length does not match the expected size.
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// Invalid byte value for a boolean field.
    #[error("invalid bool byte: {0}")]
    InvalidBool(u8),
}
