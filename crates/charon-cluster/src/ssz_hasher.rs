use std::sync::LazyLock;

use k256::sha2::{Digest, Sha256};

const fn calculate_bool_bytes(b: bool) -> [u8; 32] {
    if b {
        let mut res = ZERO_BYTES;
        res[0] = 1;
        res
    } else {
        ZERO_BYTES
    }
}

const ZERO_BYTES: [u8; 32] = [0; 32];
const TRUE_BYTES: [u8; 32] = calculate_bool_bytes(true);
const FALSE_BYTES: [u8; 32] = calculate_bool_bytes(false);

/// Precomputed zero hashes for each depth level (0-64)
static ZERO_HASHES: LazyLock<[[u8; 32]; 65]> = LazyLock::new(|| {
    let mut hashes = [[0u8; 32]; 65];

    for i in 0..64 {
        let mut hasher = Sha256::new();
        hasher.update(hashes[i]);
        hasher.update(hashes[i]);
        hashes[i + 1].copy_from_slice(&hasher.finalize());
    }

    hashes
});

/// Trait for objects that can walk (traverse/append) data for
/// merkleization/hash calculations.
pub trait HashWalker {
    /// The error type that can occur during hashing.
    type Error: std::error::Error;

    /// Finalize and return the hash result.
    fn hash(&self) -> Result<[u8; 32], Self::Error>;
    /// Append a single byte.
    fn append_u8(&mut self, i: u8) -> Result<(), Self::Error>;
    /// Append a u32 integer.
    fn append_u32(&mut self, i: u32) -> Result<(), Self::Error>;
    /// Append a u64 integer.
    fn append_u64(&mut self, i: u64) -> Result<(), Self::Error>;
    /// Append a bytes array, and fill up to `k * 32` bytes if the length is not
    /// a multiple of 32.
    fn append_bytes32(&mut self, b: &[u8]) -> Result<(), Self::Error>;
    /// Append an array of 32 u64 values.
    fn put_uint64_array(
        &mut self,
        b: &[u64],
        max_capacity: Option<usize>,
    ) -> Result<(), Self::Error>;
    /// Append a u64 value.
    fn put_uint64(&mut self, i: u64) -> Result<(), Self::Error>;
    /// Append a u32 value.
    fn put_uint32(&mut self, i: u32) -> Result<(), Self::Error>;
    /// Append a u16 value.
    fn put_uint16(&mut self, i: u16) -> Result<(), Self::Error>;
    /// Append a u8 value.
    fn put_uint8(&mut self, i: u8) -> Result<(), Self::Error>;
    /// Pad data up to 32 bytes.
    fn fill_up_to_32(&mut self) -> Result<(), Self::Error>;
    /// Append a byte slice.
    fn append(&mut self, b: &[u8]) -> Result<(), Self::Error>;
    /// Append a bitlist, with given max size.
    fn put_bitlist(&mut self, bb: &[u8], max_size: usize) -> Result<(), Self::Error>;
    /// Append a boolean value.
    fn put_bool(&mut self, b: bool) -> Result<(), Self::Error>;
    /// Append a byte slice, if the length is less than or equal to 32, it will
    /// be appended as is + padding to 32 bytes, otherwise it will be
    /// merkleized.
    fn put_bytes(&mut self, b: &[u8]) -> Result<(), Self::Error>;
    /// Current byte index or position in buffer.
    fn index(&self) -> usize;
    /// Perform merkleization at given index.
    fn merkleize(&mut self, index: usize) -> Result<(), Self::Error>;
    /// Perform merkleization with mixin (limit value).
    fn merkleize_with_mixin(
        &mut self,
        index: usize,
        num: usize,
        limit: usize,
    ) -> Result<(), Self::Error>;

    /// Get the current buffer.
    fn get_buf(&self) -> &Vec<u8>;
}

/// Hash function for hashing SSZ data.
pub type HashFn = fn(src: &[u8]) -> Result<Vec<u8>, HasherError>;

/// Errors that may occur during hashing/merkleization.
#[derive(Debug, thiserror::Error)]
pub enum HasherError {
    /// Invalid buffer length
    #[error("Invalid buffer length")]
    InvalidBufferLength,
    /// Unsupported version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
    /// Integer overflow
    #[error("Integer overflow")]
    IntegerOverflow,
    /// Integer underflow
    #[error("Integer underflow")]
    IntegerUnderflow,
    /// Count greater than limit
    #[error("Count greater than limit: count {count}, limit {limit}")]
    CountGreaterThanLimit {
        /// Count
        count: usize,
        /// Limit
        limit: usize,
    },
}

/// SSZ hasher for calculating merkle roots.
#[derive(Debug)]
pub struct Hasher {
    buf: Vec<u8>,

    tmp: Vec<u8>,

    hash: HashFn,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new(Self::default_hash_fn())
    }
}

impl Hasher {
    /// Create a new hasher.
    pub fn new(hash: HashFn) -> Self {
        Self {
            buf: Vec::new(),
            tmp: Vec::new(),
            hash,
        }
    }

    /// Default hash function.
    pub fn default_hash_fn() -> HashFn {
        |src: &[u8]| -> Result<Vec<u8>, HasherError> {
            let mut result = Vec::with_capacity(src.len() / 2);

            for pair in src.chunks(64) {
                let mut hasher = Sha256::new();
                hasher.update(&pair[..32]);
                hasher.update(&pair[32..]);
                result.extend_from_slice(&hasher.finalize());
            }

            Ok(result)
        }
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn next_power_of_two(mut v: usize) -> usize {
        v -= 1;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;
        v += 1;
        v
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn get_depth(d: usize) -> usize {
        if d <= 1 {
            return 0;
        }

        let i = Self::next_power_of_two(d);
        64 - i.leading_zeros() as usize - 1
    }

    fn merkleize_impl(&mut self, input: &[u8], mut limit: usize) -> Result<Vec<u8>, HasherError> {
        let count = input.len().div_ceil(32);
        let mut input = input.to_vec();

        if limit == 0 {
            limit = count;
        } else if count > limit {
            return Err(HasherError::CountGreaterThanLimit { count, limit });
        }

        if limit == 0 {
            return Ok(ZERO_BYTES.to_vec());
        }
        if limit == 1 {
            if count == 1 {
                return Ok(input[..32].to_vec());
            } else {
                return Ok(ZERO_BYTES.to_vec());
            }
        }

        let depth = Self::get_depth(limit);

        if input.is_empty() {
            return Ok(ZERO_HASHES[depth].to_vec());
        }

        for i in 0..depth {
            let layer_len = input.len() / 32;
            let odd_node_len = layer_len % 2 == 1;

            if odd_node_len {
                input.extend_from_slice(&ZERO_HASHES[i]);
            }

            input = (self.hash)(&input)?;
        }

        Ok(input)
    }

    /// Compute the SSZ hash root.
    pub fn hash_root(&self) -> Result<[u8; 32], HasherError> {
        if self.buf.len() != 32 {
            return Err(HasherError::InvalidBufferLength);
        }
        let mut result = [0; 32];
        result.copy_from_slice(&self.hash()?);
        Ok(result)
    }

    /// Reset the hasher.
    pub fn reset(&mut self) {
        self.buf.clear();
    }
}

impl HashWalker for Hasher {
    type Error = HasherError;

    /// Return the hash of the current buffer.
    fn hash(&self) -> Result<[u8; 32], Self::Error> {
        if self.buf.len() < 32 {
            return Err(HasherError::InvalidBufferLength);
        }
        let mut result = [0; 32];
        #[allow(clippy::arithmetic_side_effects)]
        result.copy_from_slice(&self.buf[self.buf.len() - 32..]);
        Ok(result)
    }

    /// Append a single byte.
    fn append_u8(&mut self, i: u8) -> Result<(), Self::Error> {
        self.append(&[i])
    }

    /// Append a u32 integer.
    fn append_u32(&mut self, i: u32) -> Result<(), Self::Error> {
        self.append(&i.to_le_bytes())
    }

    /// Append a u64 integer.
    fn append_u64(&mut self, i: u64) -> Result<(), Self::Error> {
        self.append(&i.to_le_bytes())
    }

    /// Append a bytes array, and fill up to `k * 32` bytes if the length is not
    /// a multiple of 32.
    fn append_bytes32(&mut self, b: &[u8]) -> Result<(), Self::Error> {
        self.buf.extend_from_slice(b);
        let rest = b.len() % 32;
        if rest != 0 {
            #[allow(clippy::arithmetic_side_effects)]
            // rest < 32, ZERO_BYTES is constant with length 32
            self.buf.extend_from_slice(&ZERO_BYTES[..32 - rest]);
        }
        Ok(())
    }

    /// Append an array of u64 values.
    fn put_uint64_array(
        &mut self,
        b: &[u64],
        max_capacity: Option<usize>,
    ) -> Result<(), Self::Error> {
        let indx = self.index();
        for i in b {
            self.append_u64(*i)?;
        }

        self.fill_up_to_32()?;

        if let Some(max_capacity) = max_capacity {
            let num_items = b.len();
            let limit = calculate_limit(max_capacity, num_items, 8);
            self.merkleize_with_mixin(indx, num_items, limit)?;
        } else {
            self.merkleize(indx)?;
        }
        Ok(())
    }

    /// Append a u64 value.
    fn put_uint64(&mut self, i: u64) -> Result<(), Self::Error> {
        self.append_bytes32(&i.to_le_bytes())
    }

    /// Append a u32 value.
    fn put_uint32(&mut self, i: u32) -> Result<(), Self::Error> {
        self.append_bytes32(&i.to_le_bytes())
    }

    /// Append a u16 value.
    fn put_uint16(&mut self, i: u16) -> Result<(), Self::Error> {
        self.append_bytes32(&i.to_le_bytes())
    }

    /// Append a u8 value.
    fn put_uint8(&mut self, i: u8) -> Result<(), Self::Error> {
        self.append_bytes32(&[i])
    }

    /// Pad data up to 32 bytes.
    fn fill_up_to_32(&mut self) -> Result<(), Self::Error> {
        let rest = self.buf.len() % 32;
        if rest != 0 {
            #[allow(clippy::arithmetic_side_effects)]
            // rest < 32, ZERO_BYTES is constant with length 32
            self.buf.extend_from_slice(&ZERO_BYTES[..32 - rest]);
        }
        Ok(())
    }

    /// Append a byte slice.
    fn append(&mut self, b: &[u8]) -> Result<(), Self::Error> {
        self.buf.extend_from_slice(b);
        Ok(())
    }

    /// Append a bitlist, with given max size.
    fn put_bitlist(&mut self, bb: &[u8], max_size: usize) -> Result<(), Self::Error> {
        let size = parse_bitlist(&mut self.tmp, bb)?;

        // merkleize the content with mix in length
        let indx = self.index();
        self.append_bytes32(&self.tmp.clone())?;
        self.merkleize_with_mixin(indx, size as usize, max_size.div_ceil(256))?;
        Ok(())
    }

    /// Append a boolean value.
    fn put_bool(&mut self, b: bool) -> Result<(), Self::Error> {
        if b {
            self.buf.extend_from_slice(&TRUE_BYTES)
        } else {
            self.buf.extend_from_slice(&FALSE_BYTES)
        }

        Ok(())
    }

    /// Append a byte slice (copy).
    fn put_bytes(&mut self, b: &[u8]) -> Result<(), Self::Error> {
        if b.len() <= 32 {
            self.append_bytes32(b)
        } else {
            let indx = self.index();
            self.append_bytes32(b)?;
            self.merkleize(indx)?;
            Ok(())
        }
    }

    /// Get the current index in the buffer.
    fn index(&self) -> usize {
        self.buf.len()
    }

    /// Perform merkleization at a given index.
    fn merkleize(&mut self, index: usize) -> Result<(), Self::Error> {
        // merkleizeImpl will expand the `input` by 32 bytes if some hashing depth
        // hits an odd chunk length. But if we're at the end of `h.buf` already,
        // appending to `input` will allocate a new buffer, *not* expand `h.buf`,
        // so the next invocation will realloc, over and over and over. We can pre-
        // emptively cater for that by ensuring that an extra 32 bytes is always
        // available.
        if self.buf.len() == self.buf.capacity() {
            self.buf.reserve(32); // Just ensure capacity
        }

        let mut input = self.buf[index..].to_vec();
        input = self.merkleize_impl(&input, 0)?;
        self.buf.truncate(index); // Truncate without filling
        self.buf.extend_from_slice(&input);

        Ok(())
    }

    /// Perform merkleization with a mixin value.
    fn merkleize_with_mixin(
        &mut self,
        index: usize,
        num: usize,
        limit: usize,
    ) -> Result<(), Self::Error> {
        self.fill_up_to_32()?;

        // merkleize the input
        let mut input = self.buf[index..].to_vec();

        input = self.merkleize_impl(&input, limit)?;
        self.buf.truncate(index);
        self.buf.extend_from_slice(&input);

        let mut tmp = [0; 32];
        let num_le = (num as u64).to_le_bytes();

        tmp[..8].copy_from_slice(&num_le);

        input.extend_from_slice(&tmp);

        let result = (self.hash)(&input)?;
        self.buf.truncate(index);
        self.buf.extend_from_slice(&result);

        Ok(())
    }

    fn get_buf(&self) -> &Vec<u8> {
        &self.buf
    }
}

/// Calculate the limit for the merkleization with a mixin value.
pub fn calculate_limit(max_capacity: usize, num_items: usize, size: usize) -> usize {
    let limit = (max_capacity.saturating_mul(size)).div_ceil(32);
    if limit != 0 {
        return limit;
    }
    if num_items == 0 {
        return 1;
    }
    num_items
}

#[allow(
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
fn parse_bitlist(tmp: &mut Vec<u8>, buf: &[u8]) -> Result<usize, HasherError> {
    if buf.is_empty() {
        return Err(HasherError::InvalidBufferLength);
    }

    // Find the most significant bit in the last byte
    let last_byte = buf[buf.len() - 1];
    let msb = 8 - last_byte.leading_zeros() as u8 - 1;
    let size = 8 * (buf.len() - 1) + msb as usize;

    tmp.clear();
    tmp.extend_from_slice(buf);

    let last_idx = tmp.len() - 1;
    tmp[last_idx] &= !(1u8 << msb);

    let mut new_len = tmp.len();
    for i in (0..tmp.len()).rev() {
        if tmp[i] != 0x00 {
            break;
        }
        new_len = i;
    }
    tmp.truncate(new_len);

    Ok(size)
}
