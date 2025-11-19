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
    /// Append a 32-byte array.
    fn append_bytes32(&mut self, b: &[u8; 32]) -> Result<(), Self::Error>;
    /// Append an array of 32 u64 values.
    fn put_uint64_array(&mut self, b: &[u64], max_capacity: usize) -> Result<(), Self::Error>;
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
    fn put_bitlist(&mut self, bb: &[u8], max_size: u64) -> Result<(), Self::Error>;
    /// Append a boolean value.
    fn put_bool(&mut self, b: bool) -> Result<(), Self::Error>;
    /// Append a byte slice (copy).
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
}

/// SSZ hasher for calculating merkle roots.
pub struct Hasher;

impl Hasher {
    /// Create a new hasher.
    pub fn new() -> Self {
        Self
    }

    /// Compute the SSZ hash root.
    pub fn hash_root(&self) -> Result<[u8; 32], HasherError> {
        todo!()
    }
}

/// Errors that may occur during hashing/merkleization.
#[derive(Debug, thiserror::Error)]
pub enum HasherError {
    /// Unsupported version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
}

impl HashWalker for Hasher {
    type Error = HasherError;

    /// Finalize and return the hash result.
    fn hash(&self) -> Result<[u8; 32], Self::Error> {
        todo!()
    }

    /// Append a single byte.
    fn append_u8(&mut self, i: u8) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a u32 integer.
    fn append_u32(&mut self, i: u32) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a u64 integer.
    fn append_u64(&mut self, i: u64) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a 32-byte array.
    fn append_bytes32(&mut self, b: &[u8; 32]) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append an array of 32 u64 values.
    fn put_uint64_array(&mut self, b: &[u64], max_capacity: usize) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a u64 value.
    fn put_uint64(&mut self, i: u64) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a u32 value.
    fn put_uint32(&mut self, i: u32) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a u16 value.
    fn put_uint16(&mut self, i: u16) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a u8 value.
    fn put_uint8(&mut self, i: u8) -> Result<(), Self::Error> {
        todo!()
    }

    /// Pad data up to 32 bytes.
    fn fill_up_to_32(&mut self) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a byte slice.
    fn append(&mut self, b: &[u8]) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a bitlist, with given max size.
    fn put_bitlist(&mut self, bb: &[u8], max_size: u64) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a boolean value.
    fn put_bool(&mut self, b: bool) -> Result<(), Self::Error> {
        todo!()
    }

    /// Append a byte slice (copy).
    fn put_bytes(&mut self, b: &[u8]) -> Result<(), Self::Error> {
        todo!()
    }

    /// Get the current index in the buffer.
    fn index(&self) -> usize {
        todo!()
    }

    /// Perform merkleization at a given index.
    fn merkleize(&mut self, index: usize) -> Result<(), Self::Error> {
        todo!()
    }

    /// Perform merkleization with a mixin value.
    fn merkleize_with_mixin(
        &mut self,
        index: usize,
        num: usize,
        limit: usize,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
