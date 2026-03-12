//! SSZ container helpers used by spec types.
//!
//! The `tree_hash` crate supports SSZ TreeHash for many primitives, but does
//! not provide `TreeHash` for `Vec<T>` directly. These wrappers encode SSZ
//! list/vector semantics and include optional length enforcement during serde
//! deserialization.

use serde::{Deserialize, Serialize, de::Error as DeError};
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType, merkle_root, mix_in_length};

fn tree_hash_bytes<T: TreeHash>(values: &[T]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len().saturating_mul(32));

    if T::tree_hash_type() == TreeHashType::Basic {
        for item in values {
            bytes.extend_from_slice(item.tree_hash_packed_encoding().as_slice());
        }
    } else {
        for item in values {
            bytes.extend_from_slice(item.tree_hash_root().as_slice());
        }
    }

    bytes
}

/// SSZ variable-length list wrapper with optional max length and TreeHash
/// support.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SszList<T, const MAX: usize = 0>(
    /// Elements in the SSZ list.
    pub Vec<T>,
);

impl<T, const MAX: usize> From<Vec<T>> for SszList<T, MAX> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T, const MAX: usize> From<SszList<T, MAX>> for Vec<T> {
    fn from(value: SszList<T, MAX>) -> Self {
        value.0
    }
}

impl<T: Serialize, const MAX: usize> Serialize for SszList<T, MAX> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for SszList<T, MAX> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = Vec::<T>::deserialize(deserializer)?;
        if MAX > 0 && values.len() > MAX {
            return Err(D::Error::custom(format!(
                "list length {} exceeds max {}",
                values.len(),
                MAX
            )));
        }
        Ok(Self(values))
    }
}

impl<const MAX: usize> AsRef<[u8]> for SszList<u8, MAX> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<T: TreeHash, const MAX: usize> TreeHash for SszList<T, MAX> {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        let bytes = tree_hash_bytes(&self.0);

        let minimum_leaf_count = if MAX == 0 {
            0
        } else if T::tree_hash_type() == TreeHashType::Basic {
            MAX.div_ceil(T::tree_hash_packing_factor())
        } else {
            MAX
        };

        let root = merkle_root(bytes.as_slice(), minimum_leaf_count);
        mix_in_length(&root, self.0.len())
    }
}

/// SSZ fixed-size vector wrapper with TreeHash support.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SszVector<T, const SIZE: usize>(
    /// Elements in the SSZ vector.
    pub Vec<T>,
);

impl<T, const SIZE: usize> From<Vec<T>> for SszVector<T, SIZE> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T: Serialize, const SIZE: usize> Serialize for SszVector<T, SIZE> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const SIZE: usize> Deserialize<'de> for SszVector<T, SIZE> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = Vec::<T>::deserialize(deserializer)?;
        if values.len() != SIZE {
            return Err(D::Error::custom(format!(
                "vector length {} does not match required {}",
                values.len(),
                SIZE
            )));
        }
        Ok(Self(values))
    }
}

impl<const SIZE: usize> AsRef<[u8]> for SszVector<u8, SIZE> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<T: TreeHash, const SIZE: usize> TreeHash for SszVector<T, SIZE> {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        let bytes = tree_hash_bytes(&self.0);

        let minimum_leaf_count = if T::tree_hash_type() == TreeHashType::Basic {
            SIZE.div_ceil(T::tree_hash_packing_factor())
        } else {
            SIZE
        };

        merkle_root(bytes.as_slice(), minimum_leaf_count)
    }
}

/// Lookup table for single-bit masks, avoiding shift operators.
const BIT_MASK: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

/// SSZ variable-length bitfield with maximum capacity.
///
/// Stores packed bit data (no sentinel) internally. The SSZ sentinel bit is
/// added during serialization and stripped during deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitList<const MAX: usize> {
    /// Packed data bits, little-endian bit order (no sentinel).
    bytes: Vec<u8>,
    /// Number of data bits.
    len: usize,
}

impl<const MAX: usize> Default for BitList<MAX> {
    fn default() -> Self {
        Self {
            bytes: vec![],
            len: 0,
        }
    }
}

impl<const MAX: usize> BitList<MAX> {
    /// Returns the number of data bits.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the bitfield contains no data bits.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Creates a `BitList` from SSZ-encoded bytes (with sentinel bit).
    fn from_ssz_bytes(ssz: Vec<u8>) -> Self {
        if ssz.is_empty() {
            return Self::default();
        }
        let last_byte = ssz[ssz.len().saturating_sub(1)];
        if last_byte == 0 {
            return Self::default();
        }
        // Sentinel is the highest set bit in the last byte.
        let sentinel_pos = 7_u32.saturating_sub(last_byte.leading_zeros()) as usize;
        let len = ssz
            .len()
            .saturating_sub(1)
            .saturating_mul(8)
            .saturating_add(sentinel_pos);
        let data_byte_len = len.div_ceil(8);
        let mut bytes = ssz;
        bytes.truncate(data_byte_len);
        // Clear sentinel bit if it shares a byte with data.
        let rem = len % 8;
        if rem != 0
            && let Some(last) = bytes.last_mut()
        {
            *last &= !BIT_MASK[rem];
        }
        Self { bytes, len }
    }

    /// Encodes as SSZ bytes (with sentinel bit appended).
    fn to_ssz_bytes(&self) -> Vec<u8> {
        let sentinel_byte = self.len / 8;
        let sentinel_bit = self.len % 8;
        let mut ssz = self.bytes.clone();
        if sentinel_byte >= ssz.len() {
            ssz.resize(sentinel_byte.saturating_add(1), 0);
        }
        ssz[sentinel_byte] |= BIT_MASK[sentinel_bit];
        ssz
    }

    /// Consumes the `BitList` and returns the SSZ-encoded bytes (with
    /// sentinel).
    pub fn into_bytes(mut self) -> Vec<u8> {
        let sentinel_byte = self.len / 8;
        let sentinel_bit = self.len % 8;
        if sentinel_byte >= self.bytes.len() {
            self.bytes.resize(sentinel_byte.saturating_add(1), 0);
        }
        self.bytes[sentinel_byte] |= BIT_MASK[sentinel_bit];
        self.bytes
    }
}

impl<const MAX: usize> Serialize for BitList<MAX> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ssz = self.to_ssz_bytes();
        let hex_str = format!("0x{}", hex::encode(ssz));
        serializer.serialize_str(hex_str.as_str())
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BitList<MAX> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let trimmed = crate::spec::serde_utils::trim_0x_prefix(s.as_str());
        let ssz = hex::decode(trimmed).map_err(D::Error::custom)?;
        Ok(Self::from_ssz_bytes(ssz))
    }
}

impl<const MAX: usize> TreeHash for BitList<MAX> {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("BitList should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("BitList should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        // 256 bits per 32-byte chunk.
        let minimum_leaf_count = MAX.div_ceil(256);
        let root = merkle_root(self.bytes.as_slice(), minimum_leaf_count);
        mix_in_length(&root, self.len)
    }
}

/// SSZ fixed-length bitfield.
///
/// Stores `SIZE` bits packed in little-endian byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitVector<const SIZE: usize> {
    /// Packed bits, little-endian bit order.
    bytes: Vec<u8>,
}

impl<const SIZE: usize> Default for BitVector<SIZE> {
    fn default() -> Self {
        Self {
            bytes: vec![0u8; SIZE.div_ceil(8)],
        }
    }
}

impl<const SIZE: usize> BitVector<SIZE> {
    /// Creates an all-zero bit vector.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<const SIZE: usize> Serialize for BitVector<SIZE> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex_str = format!("0x{}", hex::encode(self.bytes.as_slice()));
        serializer.serialize_str(hex_str.as_str())
    }
}

impl<'de, const SIZE: usize> Deserialize<'de> for BitVector<SIZE> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let trimmed = crate::spec::serde_utils::trim_0x_prefix(s.as_str());
        let bytes = hex::decode(trimmed).map_err(D::Error::custom)?;
        let expected = SIZE.div_ceil(8);
        if bytes.len() != expected {
            return Err(D::Error::custom(format!(
                "bitvector byte length {} does not match required {expected}",
                bytes.len(),
            )));
        }
        Ok(Self { bytes })
    }
}

impl<const SIZE: usize> TreeHash for BitVector<SIZE> {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("BitVector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("BitVector should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        let minimum_leaf_count = SIZE.div_ceil(256);
        merkle_root(self.bytes.as_slice(), minimum_leaf_count)
    }
}

#[cfg(test)]
impl<const MAX: usize> BitList<MAX> {
    /// Creates a `BitList` with the given capacity and specified bits set.
    pub(crate) fn with_bits(capacity: usize, set_bits: &[usize]) -> Self {
        let byte_len = capacity.div_ceil(8);
        let mut bytes = vec![0u8; byte_len];
        for &bit in set_bits {
            bytes[bit / 8] |= BIT_MASK[bit % 8];
        }
        Self {
            bytes,
            len: capacity,
        }
    }
}

#[cfg(test)]
impl<const SIZE: usize> BitVector<SIZE> {
    /// Creates a `BitVector` with specified bits set.
    pub(crate) fn with_bits(set_bits: &[usize]) -> Self {
        let mut v = Self::new();
        for &bit in set_bits {
            v.bytes[bit / 8] |= BIT_MASK[bit % 8];
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    #[test]
    fn ssz_list_deserialize_enforces_max_len() {
        let json = "[1,2,3]";
        let parsed: Result<SszList<u64, 2>, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn ssz_vector_deserialize_enforces_exact_len() {
        let json = "[1,2,3]";
        let parsed: Result<SszVector<u64, 2>, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn ssz_list_tree_hash_depends_on_max_len() {
        // For SSZ List[T, MAX], the tree hash uses `minimum_leaf_count` derived from
        // MAX. If MAX is wrong/ignored, roots can silently diverge from spec
        // implementations.
        let list_max_4: SszList<u64, 4> = vec![42].into();
        let list_max_8: SszList<u64, 8> = vec![42].into();
        assert_ne!(list_max_4.tree_hash_root(), list_max_8.tree_hash_root());
    }

    #[test]
    fn ssz_vector_tree_hash_depends_on_size() {
        // For basic types, packing can make different sizes hash to the same single
        // chunk (e.g. size 1 vs 2 `u64`s). Use sizes that force a different
        // leaf count.
        let vec_size_4: SszVector<u64, 4> = vec![42, 0, 0, 0].into();
        let vec_size_5: SszVector<u64, 5> = vec![42, 0, 0, 0, 0].into();
        assert_ne!(vec_size_4.tree_hash_root(), vec_size_5.tree_hash_root());
    }

    #[test]
    fn ssz_list_u8_as_ref_matches_inner_bytes() {
        let list: SszList<u8, 8> = vec![1, 2, 3].into();
        assert_eq!(list.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn ssz_vector_u8_as_ref_matches_inner_bytes() {
        let vec: SszVector<u8, 3> = vec![1, 2, 3].into();
        assert_eq!(vec.as_ref(), &[1, 2, 3]);
    }
}
