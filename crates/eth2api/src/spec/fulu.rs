//! Fulu consensus types from the Ethereum beacon chain specification.

use serde::{Deserialize, Serialize};

use crate::spec::{deneb, electra};

/// Fulu signed block contents container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlockContents {
    /// Signed block.
    pub signed_block: electra::SignedBeaconBlock,
    /// KZG proofs accompanying blobs.
    pub kzg_proofs: Vec<deneb::KZGProof>,
    /// Blob sidecars.
    pub blobs: Vec<deneb::Blob>,
}

#[cfg(test)]
mod tests {
    use crate::test_fixtures;
    use test_case::test_case;

    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::fulu_beacon_block_body_fixture()),
        test_fixtures::VECTORS.fulu_beacon_block_body_root;
        "beacon_block_body_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::fulu_beacon_block_fixture()),
        test_fixtures::VECTORS.fulu_beacon_block_root;
        "beacon_block_root"
    )]
    fn tree_hash_matches_go_vector(actual: String, expected: &'static str) {
        assert_eq!(actual, expected);
    }
}
