//! Deneb consensus types from the Ethereum beacon chain specification.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tree_hash_derive::TreeHash;

use crate::spec::{altair, bellatrix, capella, phase0};

/// KZG proof length in bytes.
pub const KZG_PROOF_LEN: usize = 48;
/// Blob length in bytes.
pub const BLOB_LEN: usize = 131_072;
/// Maximum blob commitments per block.
pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4_096;

/// Base fee per gas integer.
pub type BaseFeePerGas = bellatrix::BaseFeePerGas;

/// KZG commitment bytes.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KZGCommitment {
    /// Raw commitment bytes.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub bytes: [u8; 48],
}

impl From<[u8; 48]> for KZGCommitment {
    fn from(value: [u8; 48]) -> Self {
        Self { bytes: value }
    }
}

impl AsRef<[u8]> for KZGCommitment {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// KZG proof bytes.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KZGProof(
    /// Raw proof bytes.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub [u8; KZG_PROOF_LEN],
);

impl From<[u8; KZG_PROOF_LEN]> for KZGProof {
    fn from(value: [u8; KZG_PROOF_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for KZGProof {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Blob payload.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Blob(
    /// Raw blob bytes.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub [u8; BLOB_LEN],
);

impl From<[u8; BLOB_LEN]> for Blob {
    fn from(value: [u8; BLOB_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Deneb execution payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/beacon-chain.md#executionpayload>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ExecutionPayload {
    /// Parent execution block hash.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub parent_hash: phase0::Hash32,
    /// Fee recipient address.
    #[serde(with = "bellatrix::execution_address_serde")]
    pub fee_recipient: bellatrix::ExecutionAddress,
    /// State root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub state_root: phase0::Root,
    /// Receipts root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub receipts_root: phase0::Root,
    /// Logs bloom.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub logs_bloom: [u8; 256],
    /// Prev randao value.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
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
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub extra_data: phase0::SszList<u8, { bellatrix::MAX_EXTRA_DATA_BYTES }>,
    /// Base fee per gas.
    #[serde(with = "crate::spec::serde_utils::u256_dec_serde")]
    pub base_fee_per_gas: BaseFeePerGas,
    /// Execution block hash.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub block_hash: phase0::Hash32,
    /// Transactions in the payload.
    pub transactions:
        phase0::SszList<bellatrix::Transaction, { bellatrix::MAX_TRANSACTIONS_PER_PAYLOAD }>,
    /// Withdrawals included in the payload.
    pub withdrawals: phase0::SszList<capella::Withdrawal, { capella::MAX_WITHDRAWALS_PER_PAYLOAD }>,
    /// Blob gas used.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub blob_gas_used: u64,
    /// Excess blob gas.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub excess_blob_gas: u64,
}

/// Deneb execution payload header for blinded blocks.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/beacon-chain.md#executionpayloadheader>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ExecutionPayloadHeader {
    /// Parent execution block hash.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub parent_hash: phase0::Hash32,
    /// Fee recipient address.
    #[serde(with = "bellatrix::execution_address_serde")]
    pub fee_recipient: bellatrix::ExecutionAddress,
    /// State root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub state_root: phase0::Root,
    /// Receipts root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub receipts_root: phase0::Root,
    /// Logs bloom.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub logs_bloom: [u8; 256],
    /// Prev randao value.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
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
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub extra_data: phase0::SszList<u8, { bellatrix::MAX_EXTRA_DATA_BYTES }>,
    /// Base fee per gas.
    #[serde(with = "crate::spec::serde_utils::u256_dec_serde")]
    pub base_fee_per_gas: BaseFeePerGas,
    /// Execution block hash.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub block_hash: phase0::Hash32,
    /// Transactions root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub transactions_root: phase0::Root,
    /// Withdrawals root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub withdrawals_root: phase0::Root,
    /// Blob gas used.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub blob_gas_used: u64,
    /// Excess blob gas.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub excess_blob_gas: u64,
}

/// Deneb beacon block body.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/beacon-chain.md#beaconblockbody>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BeaconBlockBody {
    /// RANDAO reveal.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub randao_reveal: phase0::BLSSignature,
    /// ETH1 data vote.
    pub eth1_data: phase0::ETH1Data,
    /// Graffiti bytes.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
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
    pub bls_to_execution_changes: phase0::SszList<
        capella::SignedBLSToExecutionChange,
        { capella::MAX_BLS_TO_EXECUTION_CHANGES },
    >,
    /// Blob KZG commitments.
    pub blob_kzg_commitments: phase0::SszList<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

/// Deneb beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/beacon-chain.md#beaconblock>
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
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub parent_root: phase0::Root,
    /// State root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub state_root: phase0::Root,
    /// Block body.
    pub body: BeaconBlockBody,
}

/// Deneb blinded beacon block body.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/deneb/blinded-beacon-block.md#blindedbeaconblockbody>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct BlindedBeaconBlockBody {
    /// RANDAO reveal.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub randao_reveal: phase0::BLSSignature,
    /// ETH1 data vote.
    pub eth1_data: phase0::ETH1Data,
    /// Graffiti bytes.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
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
    pub bls_to_execution_changes: phase0::SszList<
        capella::SignedBLSToExecutionChange,
        { capella::MAX_BLS_TO_EXECUTION_CHANGES },
    >,
    /// Blob KZG commitments.
    pub blob_kzg_commitments: phase0::SszList<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
}

/// Deneb blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/deneb/blinded-beacon-block.md#blindedbeaconblock>
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
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub parent_root: phase0::Root,
    /// State root.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub state_root: phase0::Root,
    /// Blinded block body.
    pub body: BlindedBeaconBlockBody,
}

/// Deneb signed beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/beacon-chain.md#signedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    /// Unsigned block message.
    pub message: BeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Deneb signed blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/deneb/blinded-beacon-block.md#signedblindedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedBlindedBeaconBlock {
    /// Unsigned blinded block message.
    pub message: BlindedBeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Deneb signed block contents container.
///
/// Spec: <https://ethereum.github.io/beacon-APIs/#/Validator/publishBlockV2>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlockContents {
    /// Signed block.
    pub signed_block: SignedBeaconBlock,
    /// KZG proofs accompanying blobs.
    pub kzg_proofs: Vec<KZGProof>,
    /// Blob sidecars.
    pub blobs: Vec<Blob>,
}

#[cfg(test)]
mod tests {
    use crate::test_fixtures;
    use test_case::test_case;

    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::deneb_beacon_block_body_fixture()),
        test_fixtures::VECTORS.deneb_beacon_block_body_root;
        "beacon_block_body_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::deneb_beacon_block_fixture()),
        test_fixtures::VECTORS.deneb_beacon_block_root;
        "beacon_block_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::deneb_execution_payload_fixture()),
        test_fixtures::VECTORS.deneb_execution_payload_root;
        "execution_payload_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::deneb_execution_payload_header_fixture()),
        test_fixtures::VECTORS.deneb_execution_payload_header_root;
        "execution_payload_header_root"
    )]
    fn tree_hash_matches_vector(actual: String, expected: &'static str) {
        assert_eq!(actual, expected);
    }

    #[test_case(
        test_fixtures::to_json_value(&test_fixtures::deneb_execution_payload_fixture()),
        test_fixtures::VECTORS.deneb_execution_payload_json;
        "execution_payload_json"
    )]
    #[test_case(
        test_fixtures::to_json_value(&test_fixtures::deneb_execution_payload_header_fixture()),
        test_fixtures::VECTORS.deneb_execution_payload_header_json;
        "execution_payload_header_json"
    )]
    #[test_case(
        test_fixtures::to_json_value(&test_fixtures::deneb_kzg_commitment_fixture()),
        test_fixtures::VECTORS.deneb_kzg_commitment_json;
        "kzg_commitment_json"
    )]
    fn json_matches_vector(actual: serde_json::Value, expected_json: &'static str) {
        test_fixtures::assert_json_eq(actual, expected_json);
    }
}
