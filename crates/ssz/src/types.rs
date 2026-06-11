//! Generic SSZ list, vector, and bitfield wrappers.

use crate::serde_utils::{decode_0x_hex, encode_0x_hex};
use serde::{Deserialize, Serialize, de::Error as DeError};
use ssz::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode};
use tree_hash::{
    BYTES_PER_CHUNK, Hash256, PackedEncoding, TreeHash, TreeHashType, merkle_root, mix_in_length,
};

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

fn minimum_leaf_count_for_elements<T: TreeHash>(len: usize) -> usize {
    if T::tree_hash_type() == TreeHashType::Basic {
        len.div_ceil(T::tree_hash_packing_factor())
    } else {
        len
    }
}

fn minimum_leaf_count_for_bits(len: usize) -> usize {
    len.div_ceil(BYTES_PER_CHUNK * 8)
}

/// SSZ variable-length list wrapper with optional max length and `TreeHash`
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

impl<T: Encode, const MAX: usize> Encode for SszList<T, MAX> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }
}

impl<T: Decode, const MAX: usize> Decode for SszList<T, MAX> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let values = Vec::<T>::from_ssz_bytes(bytes)?;
        if MAX > 0 && values.len() > MAX {
            return Err(DecodeError::BytesInvalid(format!(
                "list length {} exceeds max {MAX}",
                values.len(),
            )));
        }
        Ok(Self(values))
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
        } else {
            minimum_leaf_count_for_elements::<T>(MAX)
        };

        let root = merkle_root(bytes.as_slice(), minimum_leaf_count);
        mix_in_length(&root, self.0.len())
    }
}

/// SSZ fixed-size vector wrapper with `TreeHash` support.
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

impl<T: Encode, const SIZE: usize> Encode for SszVector<T, SIZE> {
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        if T::is_ssz_fixed_len() {
            #[allow(clippy::arithmetic_side_effects)]
            {
                T::ssz_fixed_len() * SIZE
            }
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }
}

impl<T: Decode, const SIZE: usize> Decode for SszVector<T, SIZE> {
    fn is_ssz_fixed_len() -> bool {
        T::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        if T::is_ssz_fixed_len() {
            #[allow(clippy::arithmetic_side_effects)]
            {
                T::ssz_fixed_len() * SIZE
            }
        } else {
            BYTES_PER_LENGTH_OFFSET
        }
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let values = Vec::<T>::from_ssz_bytes(bytes)?;
        if values.len() != SIZE {
            return Err(DecodeError::InvalidByteLength {
                len: values.len(),
                expected: SIZE,
            });
        }
        Ok(Self(values))
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
        let minimum_leaf_count = minimum_leaf_count_for_elements::<T>(SIZE);

        merkle_root(bytes.as_slice(), minimum_leaf_count)
    }
}

const BIT_MASK: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

/// Error returned by bitfield combinators that require operands of equal
/// length.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BitfieldError {
    /// The two bitlists have different bit lengths and cannot be combined.
    #[error("bitlists are different lengths")]
    DifferentLength,
}

/// SSZ variable-length bitfield with maximum capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitList<const MAX: usize> {
    /// Packed data bits, little-endian bit order without the sentinel bit.
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
    fn append_sentinel(bytes: &mut Vec<u8>, len: usize) {
        let sentinel_byte = len / 8;
        let sentinel_bit = len % 8;
        if sentinel_byte >= bytes.len() {
            bytes.resize(sentinel_byte.saturating_add(1), 0);
        }
        bytes[sentinel_byte] |= BIT_MASK[sentinel_bit];
    }

    /// Returns the number of data bits.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the bitfield contains no data bits.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Decodes SSZ-encoded bytes (with sentinel bit) into a `BitList`.
    pub fn from_ssz_bytes(ssz: Vec<u8>) -> Self {
        if ssz.is_empty() {
            return Self::default();
        }
        let last_byte = ssz[ssz.len().saturating_sub(1)];
        if last_byte == 0 {
            return Self::default();
        }

        let sentinel_pos = 7_u32.saturating_sub(last_byte.leading_zeros()) as usize;
        let len = ssz
            .len()
            .saturating_sub(1)
            .saturating_mul(8)
            .saturating_add(sentinel_pos);
        let data_byte_len = len.div_ceil(8);
        let mut bytes = ssz;
        bytes.truncate(data_byte_len);
        let rem = len % 8;
        if rem != 0
            && let Some(last) = bytes.last_mut()
        {
            *last &= !BIT_MASK[rem];
        }
        Self { bytes, len }
    }

    /// Encodes the `BitList` as SSZ bytes with sentinel bit appended.
    pub fn to_ssz_bytes(&self) -> Vec<u8> {
        let mut ssz = self.bytes.clone();
        Self::append_sentinel(&mut ssz, self.len);
        ssz
    }

    /// Consumes the `BitList` and returns the SSZ-encoded bytes with sentinel.
    pub fn into_bytes(mut self) -> Vec<u8> {
        Self::append_sentinel(&mut self.bytes, self.len);
        self.bytes
    }

    /// Creates a `BitList` with the given capacity and specified bits set.
    pub fn with_bits(capacity: usize, set_bits: &[usize]) -> Self {
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

    /// Returns the bit at index `i`, or `false` if `i` is out of range.
    pub fn bit_at(&self, i: usize) -> bool {
        if i >= self.len {
            return false;
        }
        self.bytes[i / 8] & BIT_MASK[i % 8] != 0
    }

    /// Sets the bit at index `i` to `value`; out-of-range indices are ignored.
    pub fn set_bit_at(&mut self, i: usize, value: bool) {
        if i >= self.len {
            return;
        }
        if value {
            self.bytes[i / 8] |= BIT_MASK[i % 8];
        } else {
            self.bytes[i / 8] &= !BIT_MASK[i % 8];
        }
    }

    /// Returns the indices of all set bits in ascending order.
    pub fn bit_indices(&self) -> Vec<usize> {
        (0..self.len).filter(|&i| self.bit_at(i)).collect()
    }

    /// Returns `true` if every bit set in `other` is also set in `self`.
    ///
    /// Errors with [`BitfieldError::DifferentLength`] if the two bitlists do
    /// not have the same bit length.
    pub fn contains(&self, other: &Self) -> Result<bool, BitfieldError> {
        if self.len != other.len {
            return Err(BitfieldError::DifferentLength);
        }
        Ok(other
            .bytes
            .iter()
            .zip(&self.bytes)
            .all(|(o, s)| o & s == *o))
    }

    /// Returns the bitwise OR (union) of `self` and `other`.
    ///
    /// Errors with [`BitfieldError::DifferentLength`] if the two bitlists do
    /// not have the same bit length.
    pub fn or(&self, other: &Self) -> Result<Self, BitfieldError> {
        if self.len != other.len {
            return Err(BitfieldError::DifferentLength);
        }
        let bytes = self
            .bytes
            .iter()
            .zip(&other.bytes)
            .map(|(a, b)| a | b)
            .collect();
        Ok(Self {
            bytes,
            len: self.len,
        })
    }
}

impl<const MAX: usize> Serialize for BitList<MAX> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_0x_hex(&self.to_ssz_bytes()))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BitList<MAX> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let ssz = decode_0x_hex::<D::Error>(s.as_str())?;
        Ok(Self::from_ssz_bytes(ssz))
    }
}

impl<const MAX: usize> Encode for BitList<MAX> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_ssz_bytes());
    }

    fn ssz_bytes_len(&self) -> usize {
        self.to_ssz_bytes().len()
    }
}

impl<const MAX: usize> Decode for BitList<MAX> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_ssz_bytes(bytes.to_vec()))
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
        let minimum_leaf_count = minimum_leaf_count_for_bits(MAX);
        let root = merkle_root(self.bytes.as_slice(), minimum_leaf_count);
        mix_in_length(&root, self.len)
    }
}

/// SSZ fixed-length bitfield.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitVector<const SIZE: usize> {
    /// Packed bits, little-endian bit order.
    pub bytes: Vec<u8>,
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

    /// Creates a `BitVector` with specified bits set.
    pub fn with_bits(set_bits: &[usize]) -> Self {
        let mut v = Self::new();
        for &bit in set_bits {
            v.bytes[bit / 8] |= BIT_MASK[bit % 8];
        }
        v
    }

    /// Returns the bit at index `i`, or `false` if `i` is out of range.
    pub fn bit_at(&self, i: usize) -> bool {
        if i >= SIZE {
            return false;
        }
        self.bytes[i / 8] & BIT_MASK[i % 8] != 0
    }

    /// Sets the bit at index `i` to `value`; out-of-range indices are ignored.
    pub fn set_bit_at(&mut self, i: usize, value: bool) {
        if i >= SIZE {
            return;
        }
        if value {
            self.bytes[i / 8] |= BIT_MASK[i % 8];
        } else {
            self.bytes[i / 8] &= !BIT_MASK[i % 8];
        }
    }

    /// Returns the indices of all set bits in ascending order.
    pub fn bit_indices(&self) -> Vec<usize> {
        (0..SIZE).filter(|&i| self.bit_at(i)).collect()
    }
}

impl<const SIZE: usize> Serialize for BitVector<SIZE> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_0x_hex(self.bytes.as_slice()))
    }
}

impl<'de, const SIZE: usize> Deserialize<'de> for BitVector<SIZE> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = decode_0x_hex::<D::Error>(s.as_str())?;
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

impl<const SIZE: usize> Encode for BitVector<SIZE> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        SIZE.div_ceil(8)
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.bytes);
    }

    fn ssz_bytes_len(&self) -> usize {
        SIZE.div_ceil(8)
    }
}

impl<const SIZE: usize> Decode for BitVector<SIZE> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        SIZE.div_ceil(8)
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let expected = SIZE.div_ceil(8);
        if bytes.len() != expected {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
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
        let minimum_leaf_count = minimum_leaf_count_for_bits(SIZE);
        merkle_root(self.bytes.as_slice(), minimum_leaf_count)
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
        let list_max_4: SszList<u64, 4> = vec![42].into();
        let list_max_8: SszList<u64, 8> = vec![42].into();
        assert_ne!(list_max_4.tree_hash_root(), list_max_8.tree_hash_root());
    }

    #[test]
    fn ssz_vector_tree_hash_depends_on_size() {
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

    #[test]
    fn bitlist_bit_at_and_indices() {
        let bl = BitList::<2048>::with_bits(3, &[0, 2]);
        assert!(bl.bit_at(0));
        assert!(!bl.bit_at(1));
        assert!(bl.bit_at(2));
        // Out-of-range index reads as unset.
        assert!(!bl.bit_at(3));
        assert!(!bl.bit_at(9001));
        assert_eq!(bl.bit_indices(), vec![0, 2]);
    }

    #[test]
    fn bitlist_bit_at_matches_ssz_round_trip() {
        // SSZ byte 0x0D = sentinel at bit 3 ⇒ 3 data bits with bits 0 and 2 set,
        // matching the bytes returned by `aggregation_bits()`.
        let bl = BitList::<2048>::from_ssz_bytes(vec![0x0D]);
        assert_eq!(bl.len(), 3);
        assert_eq!(bl.bit_indices(), vec![0, 2]);
    }

    #[test]
    fn bitlist_set_bit_at() {
        let mut bl = BitList::<2048>::with_bits(8, &[0]);
        bl.set_bit_at(3, true);
        assert_eq!(bl.bit_indices(), vec![0, 3]);
        bl.set_bit_at(0, false);
        assert_eq!(bl.bit_indices(), vec![3]);
        // Out-of-range set is a no-op.
        bl.set_bit_at(8, true);
        assert_eq!(bl.bit_indices(), vec![3]);
    }

    #[test]
    fn bitlist_contains() {
        let superset = BitList::<2048>::with_bits(4, &[0, 1, 2]);
        let subset = BitList::<2048>::with_bits(4, &[0, 2]);
        assert_eq!(superset.contains(&subset), Ok(true));
        assert_eq!(subset.contains(&superset), Ok(false));

        let other_len = BitList::<2048>::with_bits(8, &[0]);
        assert_eq!(
            superset.contains(&other_len),
            Err(BitfieldError::DifferentLength)
        );
    }

    #[test]
    fn bitlist_or() {
        let a = BitList::<2048>::with_bits(4, &[0]);
        let b = BitList::<2048>::with_bits(4, &[1, 3]);
        assert_eq!(a.or(&b).unwrap().bit_indices(), vec![0, 1, 3]);

        let other_len = BitList::<2048>::with_bits(8, &[0]);
        assert_eq!(a.or(&other_len), Err(BitfieldError::DifferentLength));
    }

    #[test]
    fn bitvector_bit_ops() {
        let mut bv = BitVector::<64>::with_bits(&[0, 2]);
        assert!(bv.bit_at(0));
        assert!(!bv.bit_at(1));
        assert_eq!(bv.bit_indices(), vec![0, 2]);

        bv.set_bit_at(1, true);
        assert_eq!(bv.bit_indices(), vec![0, 1, 2]);

        // Out-of-range access is a no-op / reads as unset.
        bv.set_bit_at(64, true);
        assert!(!bv.bit_at(64));
        assert_eq!(bv.bit_indices(), vec![0, 1, 2]);
    }
}
