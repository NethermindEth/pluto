//! API v1 types from the Ethereum beacon chain and builder API specifications.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::spec::{
    bellatrix::ExecutionAddress,
    phase0::{self, BLSPubKey, BLSSignature, Epoch, Gwei, Root, Slot, ValidatorIndex, Version},
};

/// Attester duty of one validator for one slot.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttesterDuty {
    /// Public key of the attesting validator.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub pubkey: BLSPubKey,
    /// Index of the attesting validator.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
    /// Index of the committee the validator sits in.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub committee_index: u64,
    /// Number of validators in the committee.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub committee_length: u64,
    /// Number of committees at the slot.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub committees_at_slot: u64,
    /// Position of the validator within the committee.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_committee_index: u64,
    /// Slot the attestation is due in.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: Slot,
}

/// Proposer duty of one validator for one slot.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerDuty {
    /// Public key of the proposing validator.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub pubkey: BLSPubKey,
    /// Index of the proposing validator.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
    /// Slot the proposal is due in.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub slot: Slot,
}

/// Sync committee duty of one validator for one sync committee period.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeDuty {
    /// Public key of the validator.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub pubkey: BLSPubKey,
    /// Index of the validator.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
    /// Positions of the validator within the sync committee.
    #[serde_as(as = "Vec<serde_with::DisplayFromStr>")]
    pub validator_sync_committee_indices: Vec<u64>,
}

/// Lifecycle status of a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorStatus {
    /// Deposited, not yet eligible for activation.
    PendingInitialized,
    /// Eligible for activation, waiting in the queue.
    PendingQueued,
    /// Active and not exiting.
    ActiveOngoing,
    /// Active and voluntarily exiting.
    ActiveExiting,
    /// Active and slashed.
    ActiveSlashed,
    /// Exited without being slashed.
    ExitedUnslashed,
    /// Exited after being slashed.
    ExitedSlashed,
    /// Exited and eligible to withdraw.
    WithdrawalPossible,
    /// Fully withdrawn.
    WithdrawalDone,
}

impl ValidatorStatus {
    /// Returns true if the validator is in one of the active states.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ValidatorStatus::ActiveOngoing
                | ValidatorStatus::ActiveExiting
                | ValidatorStatus::ActiveSlashed
        )
    }

    /// Returns the status name used on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingInitialized => "pending_initialized",
            Self::PendingQueued => "pending_queued",
            Self::ActiveOngoing => "active_ongoing",
            Self::ActiveExiting => "active_exiting",
            Self::ActiveSlashed => "active_slashed",
            Self::ExitedUnslashed => "exited_unslashed",
            Self::ExitedSlashed => "exited_slashed",
            Self::WithdrawalPossible => "withdrawal_possible",
            Self::WithdrawalDone => "withdrawal_done",
        }
    }
}

impl std::fmt::Display for ValidatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validator entry of a beacon state, with its balance and status.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// Index in the validator registry.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub index: ValidatorIndex,
    /// Current balance in Gwei.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub balance: Gwei,
    /// Current lifecycle status.
    pub status: ValidatorStatus,
    /// Registry entry.
    pub validator: phase0::Validator,
}

/// Sync status of a beacon node.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// Slot of the node's head.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub head_slot: Slot,
    /// Slots between the head and the current slot.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub sync_distance: u64,
    /// Whether the node is still syncing.
    pub is_syncing: bool,
    /// Whether the head is optimistically imported.
    #[serde(default)]
    pub is_optimistic: bool,
    /// Whether the execution layer is offline.
    #[serde(default)]
    pub el_offline: bool,
}

/// Peer counts of a beacon node by connection state.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCount {
    /// Connected peers.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub connected: u64,
    /// Peers being connected to.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub connecting: u64,
    /// Disconnected peers.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub disconnected: u64,
    /// Peers being disconnected from.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub disconnecting: u64,
}

/// Genesis details of the chain.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    /// Genesis time as a unix timestamp in seconds.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub genesis_time: u64,
    /// Root of the genesis validator set.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub genesis_validators_root: Root,
    /// Fork version at genesis.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub genesis_fork_version: Version,
}

/// Fee recipient the beacon node should build blocks with for a validator.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalPreparation {
    /// Index of the validator the preparation applies to.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
    /// Execution-layer address that should receive block rewards.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub fee_recipient: ExecutionAddress,
}

/// Sync committee subnet subscription of one validator.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeSubscription {
    /// Index of the validator.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: ValidatorIndex,
    /// Positions of the validator within the sync committee.
    #[serde_as(as = "Vec<serde_with::DisplayFromStr>")]
    pub sync_committee_indices: Vec<u64>,
    /// Epoch until which the subscription lasts.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub until_epoch: Epoch,
}

/// Signed header of a block, with its root and canonicity.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    /// Root of the block.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub root: Root,
    /// Whether the block is on the canonical chain.
    pub canonical: bool,
    /// Signed block header.
    pub header: phase0::SignedBeaconBlockHeader,
}

/// Validator registration message for the builder API.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/builder.md#validatorregistrationv1>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
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
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub pubkey: BLSPubKey,
}

/// Signed validator registration payload.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/builder.md#signedvalidatorregistration>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedValidatorRegistration {
    /// Unsigned validator registration message.
    pub message: ValidatorRegistration,
    /// Signature over the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
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
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
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
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub selection_proof: BLSSignature,
}

impl ValidatorRegistration {
    /// Returns the SSZ message root of the unsigned builder registration.
    pub fn message_root(&self) -> crate::spec::phase0::Root {
        self.tree_hash_root().0
    }
}

impl BeaconCommitteeSelection {
    /// Returns the message root used for aggregation selection proofs.
    pub fn message_root(&self) -> crate::spec::phase0::Root {
        self.slot.tree_hash_root().0
    }
}

impl SyncCommitteeSelection {
    /// Returns the message root used for sync committee selection proofs.
    pub fn message_root(&self) -> crate::spec::phase0::Root {
        crate::spec::altair::SyncAggregatorSelectionData {
            slot: self.slot,
            subcommittee_index: self.subcommittee_index,
        }
        .tree_hash_root()
        .0
    }
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

    fn roundtrip<T>(wire: serde_json::Value) -> T
    where
        T: serde::de::DeserializeOwned + serde::Serialize,
    {
        let value: T = serde_json::from_value(wire.clone()).expect("deserialize");
        assert_eq!(serde_json::to_value(&value).expect("serialize"), wire);
        value
    }

    #[test]
    fn attester_duty_json_uses_wire_encoding() {
        let duty: AttesterDuty = roundtrip(serde_json::json!({
            "pubkey": format!("0x{}", "aa".repeat(48)),
            "validator_index": "7",
            "committee_index": "2",
            "committee_length": "128",
            "committees_at_slot": "64",
            "validator_committee_index": "5",
            "slot": "321",
        }));
        assert_eq!(duty.pubkey, [0xaa; 48]);
        assert_eq!(duty.validator_index, 7);
        assert_eq!(duty.committee_index, 2);
        assert_eq!(duty.committee_length, 128);
        assert_eq!(duty.committees_at_slot, 64);
        assert_eq!(duty.validator_committee_index, 5);
        assert_eq!(duty.slot, 321);
    }

    #[test]
    fn proposer_and_sync_duties_json_use_wire_encoding() {
        let proposer: ProposerDuty = roundtrip(serde_json::json!({
            "pubkey": format!("0x{}", "bb".repeat(48)),
            "validator_index": "9",
            "slot": "10",
        }));
        assert_eq!((proposer.validator_index, proposer.slot), (9, 10));

        let sync: SyncCommitteeDuty = roundtrip(serde_json::json!({
            "pubkey": format!("0x{}", "cc".repeat(48)),
            "validator_index": "11",
            "validator_sync_committee_indices": ["3", "400"],
        }));
        assert_eq!(sync.validator_sync_committee_indices, vec![3, 400]);
    }

    #[test]
    fn validator_json_uses_wire_encoding() {
        let validator: Validator = roundtrip(serde_json::json!({
            "index": "42",
            "balance": "32000000000",
            "status": "active_ongoing",
            "validator": {
                "pubkey": format!("0x{}", "dd".repeat(48)),
                "withdrawal_credentials": format!("0x{}", "00".repeat(32)),
                "effective_balance": "32000000000",
                "slashed": false,
                "activation_eligibility_epoch": "0",
                "activation_epoch": "1",
                "exit_epoch": "18446744073709551615",
                "withdrawable_epoch": "18446744073709551615",
            },
        }));
        assert_eq!(validator.index, 42);
        assert_eq!(validator.status, ValidatorStatus::ActiveOngoing);
        assert!(validator.status.is_active());
        assert_eq!(validator.validator.activation_epoch, 1);
    }

    #[test]
    fn validator_status_json_is_snake_case() {
        for (status, wire) in [
            (ValidatorStatus::PendingInitialized, "pending_initialized"),
            (ValidatorStatus::PendingQueued, "pending_queued"),
            (ValidatorStatus::ActiveOngoing, "active_ongoing"),
            (ValidatorStatus::ActiveExiting, "active_exiting"),
            (ValidatorStatus::ActiveSlashed, "active_slashed"),
            (ValidatorStatus::ExitedUnslashed, "exited_unslashed"),
            (ValidatorStatus::ExitedSlashed, "exited_slashed"),
            (ValidatorStatus::WithdrawalPossible, "withdrawal_possible"),
            (ValidatorStatus::WithdrawalDone, "withdrawal_done"),
        ] {
            assert_eq!(
                serde_json::to_value(status).expect("serialize"),
                serde_json::json!(wire)
            );
            assert_eq!(status.to_string(), wire);
        }
    }

    #[test]
    fn node_and_chain_info_json_use_wire_encoding() {
        let sync: SyncState = roundtrip(serde_json::json!({
            "head_slot": "100",
            "sync_distance": "3",
            "is_syncing": true,
            "is_optimistic": false,
            "el_offline": false,
        }));
        assert_eq!((sync.head_slot, sync.sync_distance), (100, 3));
        assert!(sync.is_syncing);

        // Older nodes omit the optimistic and execution-layer flags.
        let minimal: SyncState = serde_json::from_value(serde_json::json!({
            "head_slot": "1",
            "sync_distance": "0",
            "is_syncing": false,
        }))
        .expect("deserialize without optional flags");
        assert!(!minimal.is_optimistic && !minimal.el_offline);

        let peers: PeerCount = roundtrip(serde_json::json!({
            "connected": "80",
            "connecting": "1",
            "disconnected": "20",
            "disconnecting": "0",
        }));
        assert_eq!(peers.connected, 80);

        let genesis: Genesis = roundtrip(serde_json::json!({
            "genesis_time": "1606824023",
            "genesis_validators_root": format!("0x{}", "4b".repeat(32)),
            "genesis_fork_version": "0x00000000",
        }));
        assert_eq!(genesis.genesis_time, 1606824023);
        assert_eq!(genesis.genesis_validators_root, [0x4b; 32]);
    }

    #[test]
    fn validator_side_requests_json_use_wire_encoding() {
        let preparation: ProposalPreparation = roundtrip(serde_json::json!({
            "validator_index": "1",
            "fee_recipient": "0x0101010101010101010101010101010101010101",
        }));
        assert_eq!(preparation.fee_recipient, [0x01; 20]);

        let subscription: SyncCommitteeSubscription = roundtrip(serde_json::json!({
            "validator_index": "2",
            "sync_committee_indices": ["0", "511"],
            "until_epoch": "256",
        }));
        assert_eq!(subscription.sync_committee_indices, vec![0, 511]);
        assert_eq!(subscription.until_epoch, 256);
    }

    #[test]
    fn beacon_block_header_json_uses_wire_encoding() {
        let header: BeaconBlockHeader = roundtrip(serde_json::json!({
            "root": format!("0x{}", "ee".repeat(32)),
            "canonical": true,
            "header": {
                "message": {
                    "slot": "5",
                    "proposer_index": "6",
                    "parent_root": format!("0x{}", "01".repeat(32)),
                    "state_root": format!("0x{}", "02".repeat(32)),
                    "body_root": format!("0x{}", "03".repeat(32)),
                },
                "signature": format!("0x{}", "04".repeat(96)),
            },
        }));
        assert_eq!(header.root, [0xee; 32]);
        assert!(header.canonical);
        assert_eq!(header.header.message.slot, 5);
    }
}
