//! Altair consensus types from the Ethereum beacon chain specification.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ssz::BitVector;
use tree_hash_derive::TreeHash;
use typenum::{U128, U512};

use crate::spec::phase0;

/// Sync aggregate included in Altair+ block bodies.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/beacon-chain.md#syncaggregate>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SyncAggregate {
    /// Sync committee participation bits.
    pub sync_committee_bits: BitVector<U512>,
    /// Aggregate sync committee signature.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub sync_committee_signature: phase0::BLSSignature,
}

/// Altair beacon block body.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/beacon-chain.md#beaconblockbody>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BeaconBlockBody {
    /// RANDAO reveal.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub randao_reveal: phase0::BLSSignature,
    /// ETH1 data vote.
    pub eth1_data: phase0::ETH1Data,
    /// Graffiti bytes.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub graffiti: phase0::Root,
    /// Proposer slashings included in the block.
    pub proposer_slashings:
        phase0::SszList<phase0::ProposerSlashing, { phase0::MAX_PROPOSER_SLASHINGS }>,
    /// Attester slashings included in the block.
    pub attester_slashings:
        phase0::SszList<phase0::AttesterSlashing, { phase0::MAX_ATTESTER_SLASHINGS }>,
    /// Attestations included in the block.
    pub attestations: phase0::SszList<phase0::Attestation, { phase0::MAX_ATTESTATIONS }>,
    /// Deposits included in the block.
    pub deposits: phase0::SszList<phase0::Deposit, { phase0::MAX_DEPOSITS }>,
    /// Voluntary exits included in the block.
    pub voluntary_exits:
        phase0::SszList<phase0::SignedVoluntaryExit, { phase0::MAX_VOLUNTARY_EXITS }>,
    /// Sync committee aggregate.
    pub sync_aggregate: SyncAggregate,
}

/// Altair beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/beacon-chain.md#beaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BeaconBlock {
    /// Block slot.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: phase0::Slot,
    /// Proposer validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub proposer_index: phase0::ValidatorIndex,
    /// Parent root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub parent_root: phase0::Root,
    /// State root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub state_root: phase0::Root,
    /// Block body.
    pub body: BeaconBlockBody,
}

/// Altair signed beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/beacon-chain.md#signedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    /// Unsigned block message.
    pub message: BeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Sync committee message.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/validator.md#synccommitteemessage>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SyncCommitteeMessage {
    /// Slot for the sync committee message.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: phase0::Slot,
    /// Beacon block root being signed.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub beacon_block_root: phase0::Root,
    /// Validator index emitting the message.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: phase0::ValidatorIndex,
    /// Signature over the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Sync committee contribution.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/validator.md#synccommitteecontribution>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SyncCommitteeContribution {
    /// Slot for the contribution.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: phase0::Slot,
    /// Beacon block root being contributed for.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub beacon_block_root: phase0::Root,
    /// Subcommittee index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub subcommittee_index: u64,
    /// Aggregation bits for the contribution.
    pub aggregation_bits: BitVector<U128>,
    /// Contribution signature.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Contribution-and-proof payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/validator.md#contributionandproof>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ContributionAndProof {
    /// Aggregator validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub aggregator_index: phase0::ValidatorIndex,
    /// Sync committee contribution.
    pub contribution: SyncCommitteeContribution,
    /// Selection proof.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub selection_proof: phase0::BLSSignature,
}

/// Signed contribution-and-proof payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/validator.md#signedcontributionandproof>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedContributionAndProof {
    /// Unsigned contribution-and-proof message.
    pub message: ContributionAndProof,
    /// Signature over the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Selection data used for sync committee selection proofs.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/altair/validator.md#syncaggregatorselectiondata>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SyncAggregatorSelectionData {
    /// Slot to be signed.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: phase0::Slot,
    /// Subcommittee index to be signed.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub subcommittee_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures;
    use test_case::test_case;
    use tree_hash::TreeHash;

    fn assert_tree_hash<T: TreeHash>(value: &T, expected_hex: &str) {
        let expected = hex::decode(expected_hex).expect("hex");
        let actual = value.tree_hash_root();
        assert_eq!(actual.0, expected.as_slice(), "tree hash mismatch");
    }

    #[test]
    fn sync_aggregator_selection_data_tree_hash_vector() {
        let data = SyncAggregatorSelectionData {
            slot: 1,
            subcommittee_index: 2,
        };

        assert_tree_hash(
            &data,
            "ff55c97976a840b4ced964ed49e3794594ba3f675238b5fd25d282b60f70a194",
        );
    }

    #[test]
    fn sync_committee_message_tree_hash_vector() {
        let message = SyncCommitteeMessage {
            slot: 9,
            beacon_block_root: [0x66; 32],
            validator_index: 7,
            signature: [0xAB; 96],
        };

        assert_tree_hash(
            &message,
            "1f19f8c17b45b399e9b621991b8bca6f27ddd33163e52601605744bd4c4192d7",
        );
    }

    #[test]
    fn contribution_and_proof_tree_hash_vector() {
        let mut aggregation_bits = BitVector::<U128>::new();
        aggregation_bits.set(0, true).expect("set bit");

        let message = ContributionAndProof {
            aggregator_index: 5,
            contribution: SyncCommitteeContribution {
                slot: 9,
                beacon_block_root: [0x66; 32],
                subcommittee_index: 3,
                aggregation_bits,
                signature: [0x77; 96],
            },
            selection_proof: [0x88; 96],
        };

        assert_tree_hash(
            &message,
            "b7d72ecce54e0d0d8a12a888880489e2b465a06e877cca4eaac40e54faa2790e",
        );
    }

    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::altair_beacon_block_body_fixture()),
        test_fixtures::VECTORS.altair_beacon_block_body_root;
        "beacon_block_body_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::altair_beacon_block_fixture()),
        test_fixtures::VECTORS.altair_beacon_block_root;
        "beacon_block_root"
    )]
    fn tree_hash_matches_go_vector(actual: String, expected: &'static str) {
        assert_eq!(actual, expected);
    }
}
