//! API v1 types from the Ethereum beacon chain and builder API specifications.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tree_hash_derive::TreeHash;

use crate::spec::{
    bellatrix::ExecutionAddress,
    phase0::{BLSPubKey, BLSSignature, Slot, ValidatorIndex},
};

/// Validator registration message for the builder API.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/builder.md#validatorregistrationv1>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    /// Fee recipient address (20 bytes).
    #[serde(with = "crate::spec::bellatrix::execution_address_serde")]
    pub fee_recipient: ExecutionAddress,
    /// Gas limit.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub gas_limit: u64,
    /// Registration timestamp in unix seconds.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub timestamp: u64,
    /// Validator BLS public key (48 bytes).
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub pubkey: BLSPubKey,
}

/// Signed validator registration payload.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/builder.md#signedvalidatorregistration>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedValidatorRegistration {
    /// Unsigned validator registration message.
    pub message: ValidatorRegistration,
    /// Signature over the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: BLSSignature,
}

/// Beacon committee selection payload.
///
/// Spec: <https://github.com/ethereum/beacon-APIs/blob/master/beacon-node-oapi.yaml#/paths/~1eth~1v1~1validator~1beacon_committee_selections>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BeaconCommitteeSelection {
    /// Selection slot.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: Slot,
    /// Validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
    /// Selection proof.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub selection_proof: BLSSignature,
}

/// Sync committee selection payload.
///
/// Spec: <https://github.com/ethereum/beacon-APIs/blob/master/beacon-node-oapi.yaml#/paths/~1eth~1v1~1validator~1sync_committee_selections>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SyncCommitteeSelection {
    /// Selection slot.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: Slot,
    /// Validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
    /// Subcommittee index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub subcommittee_index: u64,
    /// Selection proof.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub selection_proof: BLSSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures;
    use test_case::test_case;
    use tree_hash::TreeHash;

    #[test]
    fn validator_registration_tree_hash() {
        let reg = ValidatorRegistration {
            fee_recipient: [0xAA; 20],
            gas_limit: 30_000_000,
            timestamp: 1_000_000,
            pubkey: [0xBB; 48],
        };

        let root = reg.tree_hash_root();
        let expected =
            hex::decode("51334aceeda4bd921bad529aa54c00536d02950213c44da638ef541efe024d5e")
                .unwrap();
        assert_eq!(root.0, expected.as_slice());
    }

    #[test_case(
        test_fixtures::to_json_value(&ValidatorRegistration {
            fee_recipient: test_fixtures::seq::<20>(0xD1),
            gas_limit: 30_000_000,
            timestamp: 1_700_000_789,
            pubkey: test_fixtures::seq::<48>(0xD2),
        }),
        test_fixtures::VECTORS.v1_validator_registration_json;
        "validator_registration_json"
    )]
    #[test_case(
        test_fixtures::to_json_value(&BeaconCommitteeSelection {
            slot: 66,
            validator_index: 55,
            selection_proof: test_fixtures::seq::<96>(0xD3),
        }),
        test_fixtures::VECTORS.v1_beacon_committee_selection_json;
        "beacon_committee_selection_json"
    )]
    #[test_case(
        test_fixtures::to_json_value(&SyncCommitteeSelection {
            slot: 88,
            validator_index: 77,
            subcommittee_index: 99,
            selection_proof: test_fixtures::seq::<96>(0xD4),
        }),
        test_fixtures::VECTORS.v1_sync_committee_selection_json;
        "sync_committee_selection_json"
    )]
    fn json_matches_vector(actual: serde_json::Value, expected_json: &'static str) {
        test_fixtures::assert_json_eq(actual, expected_json);
    }
}
