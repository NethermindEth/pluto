//! Capella consensus types from the Ethereum beacon chain specification.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tree_hash_derive::TreeHash;

use crate::spec::{altair, bellatrix, phase0};

/// Maximum number of withdrawals per execution payload.
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
/// Maximum number of BLS-to-execution changes per block.
pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;

/// Withdrawal operation.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#withdrawal>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct Withdrawal {
    /// Withdrawal index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub index: u64,
    /// Validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: phase0::ValidatorIndex,
    /// Destination execution address.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub address: bellatrix::ExecutionAddress,
    /// Amount in gwei.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub amount: phase0::Gwei,
}

/// BLS-to-execution change message.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#blstoexecutionchange>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BLSToExecutionChange {
    /// Validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub validator_index: phase0::ValidatorIndex,
    /// BLS public key to change from.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub from_bls_pubkey: phase0::BLSPubKey,
    /// Execution address to change to.
    #[serde(with = "bellatrix::execution_address_serde")]
    pub to_execution_address: bellatrix::ExecutionAddress,
}

/// Signed BLS-to-execution change.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#signedblstoexecutionchange>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedBLSToExecutionChange {
    /// Unsigned message.
    pub message: BLSToExecutionChange,
    /// Signature over the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Capella execution payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#executionpayload>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ExecutionPayload {
    /// Parent execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub parent_hash: phase0::Hash32,
    /// Fee recipient address.
    #[serde(with = "bellatrix::execution_address_serde")]
    pub fee_recipient: bellatrix::ExecutionAddress,
    /// State root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub state_root: phase0::Root,
    /// Receipts root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub receipts_root: phase0::Root,
    /// Logs bloom.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub logs_bloom: [u8; 256],
    /// Prev randao value.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub prev_randao: [u8; 32],
    /// Block number.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub block_number: u64,
    /// Gas limit.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub gas_limit: u64,
    /// Gas used.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub gas_used: u64,
    /// Execution timestamp.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub timestamp: u64,
    /// Extra data bytes.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub extra_data: phase0::SszList<u8, { bellatrix::MAX_EXTRA_DATA_BYTES }>,
    /// Base fee per gas.
    #[serde(with = "crate::spec::serde_utils::u256_dec_serde")]
    pub base_fee_per_gas: bellatrix::BaseFeePerGas,
    /// Execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub block_hash: phase0::Hash32,
    /// Transactions in the payload.
    pub transactions:
        phase0::SszList<bellatrix::Transaction, { bellatrix::MAX_TRANSACTIONS_PER_PAYLOAD }>,
    /// Withdrawals included in the payload.
    pub withdrawals: phase0::SszList<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
}

/// Capella execution payload header for blinded blocks.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#executionpayloadheader>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ExecutionPayloadHeader {
    /// Parent execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub parent_hash: phase0::Hash32,
    /// Fee recipient address.
    #[serde(with = "bellatrix::execution_address_serde")]
    pub fee_recipient: bellatrix::ExecutionAddress,
    /// State root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub state_root: phase0::Root,
    /// Receipts root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub receipts_root: phase0::Root,
    /// Logs bloom.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub logs_bloom: [u8; 256],
    /// Prev randao value.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub prev_randao: [u8; 32],
    /// Block number.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub block_number: u64,
    /// Gas limit.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub gas_limit: u64,
    /// Gas used.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub gas_used: u64,
    /// Execution timestamp.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub timestamp: u64,
    /// Extra data bytes.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub extra_data: phase0::SszList<u8, { bellatrix::MAX_EXTRA_DATA_BYTES }>,
    /// Base fee per gas.
    #[serde(with = "crate::spec::serde_utils::u256_dec_serde")]
    pub base_fee_per_gas: bellatrix::BaseFeePerGas,
    /// Execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub block_hash: phase0::Hash32,
    /// Transactions root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub transactions_root: phase0::Root,
    /// Withdrawals root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub withdrawals_root: phase0::Root,
}

/// Capella beacon block body.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#beaconblockbody>
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
    pub sync_aggregate: altair::SyncAggregate,
    /// Execution payload.
    pub execution_payload: ExecutionPayload,
    /// Signed BLS-to-execution changes.
    pub bls_to_execution_changes:
        phase0::SszList<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
}

/// Capella beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#beaconblock>
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

/// Capella blinded beacon block body.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/capella/blinded-beacon-block.md#blindedbeaconblockbody>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BlindedBeaconBlockBody {
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
    pub sync_aggregate: altair::SyncAggregate,
    /// Execution payload header.
    pub execution_payload_header: ExecutionPayloadHeader,
    /// Signed BLS-to-execution changes.
    pub bls_to_execution_changes:
        phase0::SszList<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
}

/// Capella blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/capella/blinded-beacon-block.md#blindedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BlindedBeaconBlock {
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
    /// Blinded block body.
    pub body: BlindedBeaconBlockBody,
}

/// Capella signed beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md#signedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    /// Unsigned block message.
    pub message: BeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Capella signed blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/capella/blinded-beacon-block.md#signedblindedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedBlindedBeaconBlock {
    /// Unsigned blinded block message.
    pub message: BlindedBeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

#[cfg(test)]
mod tests {
    use crate::test_fixtures;
    use test_case::test_case;

    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::capella_beacon_block_body_fixture()),
        test_fixtures::VECTORS.capella_beacon_block_body_root;
        "beacon_block_body_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::capella_beacon_block_fixture()),
        test_fixtures::VECTORS.capella_beacon_block_root;
        "beacon_block_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::capella_execution_payload_fixture()),
        test_fixtures::VECTORS.capella_execution_payload_root;
        "execution_payload_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::capella_execution_payload_header_fixture()),
        test_fixtures::VECTORS.capella_execution_payload_header_root;
        "execution_payload_header_root"
    )]
    fn tree_hash_matches_vector(actual: String, expected: &'static str) {
        assert_eq!(actual, expected);
    }

    #[test_case(
        test_fixtures::to_json_value(&test_fixtures::capella_execution_payload_fixture()),
        test_fixtures::VECTORS.capella_execution_payload_json;
        "execution_payload_json"
    )]
    #[test_case(
        test_fixtures::to_json_value(&test_fixtures::capella_execution_payload_header_fixture()),
        test_fixtures::VECTORS.capella_execution_payload_header_json;
        "execution_payload_header_json"
    )]
    fn json_matches_vector(actual: serde_json::Value, expected_json: &'static str) {
        test_fixtures::assert_json_eq(actual, expected_json);
    }
}
