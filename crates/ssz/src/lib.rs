//! Shared SSZ hashing primitives, helpers, and container wrappers.

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
