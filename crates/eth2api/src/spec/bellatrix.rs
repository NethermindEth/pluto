//! Bellatrix consensus types from the Ethereum beacon chain specification.
//!
//! See: <https://github.com/ethereum/consensus-specs/blob/master/specs/bellatrix/beacon-chain.md>
use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tree_hash_derive::TreeHash;

use crate::spec::{altair, phase0};

/// An execution layer address (20 bytes).
pub type ExecutionAddress = [u8; 20];

/// Maximum number of extra data bytes.
pub const MAX_EXTRA_DATA_BYTES: usize = 32;
/// Maximum number of transactions per payload.
pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576;
/// Maximum number of bytes in a single transaction.
pub const MAX_BYTES_PER_TRANSACTION: usize = 1_073_741_824;
/// Base fee per gas integer.
pub type BaseFeePerGas = U256;

/// Raw execution transaction bytes.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Transaction {
    /// Transaction bytes.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub bytes: phase0::SszList<u8, MAX_BYTES_PER_TRANSACTION>,
}

impl From<Vec<u8>> for Transaction {
    fn from(value: Vec<u8>) -> Self {
        Self {
            bytes: value.into(),
        }
    }
}

impl AsRef<[u8]> for Transaction {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

/// JSON (de)serialization helpers for execution addresses.
pub(crate) mod execution_address_serde {
    use alloy::primitives::Address;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as DeError};

    use crate::spec::{bellatrix::ExecutionAddress, serde_utils};

    pub fn serialize<S: Serializer>(
        value: &ExecutionAddress,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let address = Address::from_slice(value.as_slice());
        let checksum = address.to_checksum(None);
        serializer.serialize_str(checksum.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ExecutionAddress, D::Error> {
        let value = String::deserialize(deserializer)?;
        let trimmed = serde_utils::trim_0x_prefix(value.as_str());
        let bytes = hex::decode(trimmed).map_err(D::Error::custom)?;
        if bytes.len() != 20 {
            return Err(D::Error::custom(format!(
                "incorrect length {} for execution address",
                bytes.len()
            )));
        }

        let mut out = [0_u8; 20];
        out.copy_from_slice(bytes.as_slice());
        Ok(out)
    }
}

/// Bellatrix execution payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/bellatrix/beacon-chain.md#executionpayload>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ExecutionPayload {
    /// Parent execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub parent_hash: phase0::Hash32,
    /// Fee recipient address.
    #[serde(with = "execution_address_serde")]
    pub fee_recipient: ExecutionAddress,
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
    pub extra_data: phase0::SszList<u8, MAX_EXTRA_DATA_BYTES>,
    /// Base fee per gas.
    #[serde(with = "crate::spec::serde_utils::u256_dec_serde")]
    pub base_fee_per_gas: BaseFeePerGas,
    /// Execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub block_hash: phase0::Hash32,
    /// Transactions in the payload.
    pub transactions: phase0::SszList<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD>,
}

/// Bellatrix execution payload header for blinded blocks.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/bellatrix/beacon-chain.md#executionpayloadheader>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct ExecutionPayloadHeader {
    /// Parent execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub parent_hash: phase0::Hash32,
    /// Fee recipient address.
    #[serde(with = "execution_address_serde")]
    pub fee_recipient: ExecutionAddress,
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
    pub extra_data: phase0::SszList<u8, MAX_EXTRA_DATA_BYTES>,
    /// Base fee per gas.
    #[serde(with = "crate::spec::serde_utils::u256_dec_serde")]
    pub base_fee_per_gas: BaseFeePerGas,
    /// Execution block hash.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub block_hash: phase0::Hash32,
    /// Transactions root.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub transactions_root: phase0::Root,
}

/// Bellatrix beacon block body.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/bellatrix/beacon-chain.md#beaconblockbody>
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
}

/// Bellatrix beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/bellatrix/beacon-chain.md#beaconblock>
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

/// Bellatrix blinded beacon block body.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/blinded-beacon-block.md#blindedbeaconblockbody>
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
}

/// Bellatrix blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/blinded-beacon-block.md#blindedbeaconblock>
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

/// Bellatrix signed beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/bellatrix/beacon-chain.md#signedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    /// Unsigned block message.
    pub message: BeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "crate::spec::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Bellatrix signed blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/blinded-beacon-block.md#signedblindedbeaconblock>
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
        test_fixtures::tree_hash_hex(&test_fixtures::bellatrix_beacon_block_body_fixture()),
        test_fixtures::VECTORS.bellatrix_beacon_block_body_root;
        "beacon_block_body_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::bellatrix_beacon_block_fixture()),
        test_fixtures::VECTORS.bellatrix_beacon_block_root;
        "beacon_block_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::bellatrix_execution_payload_fixture()),
        test_fixtures::VECTORS.bellatrix_execution_payload_root;
        "execution_payload_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::bellatrix_execution_payload_header_fixture()),
        test_fixtures::VECTORS.bellatrix_execution_payload_header_root;
        "execution_payload_header_root"
    )]
    fn tree_hash_matches_vector(actual: String, expected: &'static str) {
        assert_eq!(actual, expected);
    }

    #[test_case(
        test_fixtures::to_json_value(&test_fixtures::bellatrix_execution_payload_fixture()),
        test_fixtures::VECTORS.bellatrix_execution_payload_json;
        "execution_payload_json"
    )]
    #[test_case(
        test_fixtures::to_json_value(&test_fixtures::bellatrix_execution_payload_header_fixture()),
        test_fixtures::VECTORS.bellatrix_execution_payload_header_json;
        "execution_payload_header_json"
    )]
    fn json_matches_vector(actual: serde_json::Value, expected_json: &'static str) {
        test_fixtures::assert_json_eq(actual, expected_json);
    }
}
