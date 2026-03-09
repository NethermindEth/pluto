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
