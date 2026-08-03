//! Electra consensus types from the Ethereum beacon chain specification.

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use pluto_ssz::{BitList, BitVector};

use crate::spec::{
    altair, bellatrix, capella, deneb, phase0,
    serde_utils::{ConversionError, decode_hex_fixed, decode_hex_var},
};

/// Maximum number of attester slashings per block (Electra).
pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
/// Maximum number of attestations per block (Electra).
pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;
/// Maximum number of deposit requests per payload (Electra).
pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8_192;
/// Maximum number of withdrawal requests per payload (Electra).
pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;
/// Maximum number of consolidation requests per payload (Electra).
pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;

/// Electra indexed attestation.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#indexedattestation>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct IndexedAttestation {
    /// Indices of attesting validators.
    #[serde(with = "pluto_ssz::serde_utils::ssz_list_u64_string_serde")]
    pub attesting_indices: phase0::SszList<phase0::ValidatorIndex, 131_072>,
    /// Attestation data.
    pub data: phase0::AttestationData,
    /// Aggregate signature.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Electra attester slashing.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#attesterslashing>
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct AttesterSlashing {
    /// First conflicting indexed attestation.
    pub attestation_1: IndexedAttestation,
    /// Second conflicting indexed attestation.
    pub attestation_2: IndexedAttestation,
}

/// Electra attestation.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#singleattestation>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct Attestation {
    /// Aggregation bits.
    pub aggregation_bits: BitList<131_072>,
    /// Attestation data.
    pub data: phase0::AttestationData,
    /// Aggregate signature.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
    /// Committee bits.
    pub committee_bits: BitVector<64>,
}

/// Electra single attestation, the wire form a validator client submits to
/// `POST /eth/v2/beacon/pool/attestations` for Electra and Fulu.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#singleattestation>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SingleAttestation {
    /// Committee index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub committee_index: u64,
    /// Attesting validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub attester_index: phase0::ValidatorIndex,
    /// Attestation data.
    pub data: phase0::AttestationData,
    /// Validator signature.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

impl TryFrom<&crate::GetBlockAttestationsV2ResponseResponseDataArray> for Attestation {
    type Error = ConversionError;

    fn try_from(
        value: &crate::GetBlockAttestationsV2ResponseResponseDataArray,
    ) -> Result<Self, Self::Error> {
        const COMMITTEE_BITS_FIELD: &str = "attestation.committee_bits";
        const AGGREGATION_BITS_FIELD: &str = "attestation.aggregation_bits";
        let committee_bits = <BitVector<64> as ssz::Decode>::from_ssz_bytes(&decode_hex_var(
            &value.committee_bits,
            COMMITTEE_BITS_FIELD,
        )?)
        .map_err(|_| ConversionError::DecodeHex {
            field: COMMITTEE_BITS_FIELD,
        })?;
        let aggregation_bits = BitList::from_ssz_bytes(decode_hex_var(
            &value.aggregation_bits,
            AGGREGATION_BITS_FIELD,
        )?)
        .map_err(|_| ConversionError::DecodeHex {
            field: AGGREGATION_BITS_FIELD,
        })?;

        Ok(Self {
            aggregation_bits,
            data: phase0::AttestationData::try_from(&value.data)?,
            signature: decode_hex_fixed(&value.signature, "attestation.signature")?,
            committee_bits,
        })
    }
}

/// Execution-layer deposit request.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#depositrequest>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct DepositRequest {
    /// Validator public key.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub pubkey: phase0::BLSPubKey,
    /// Withdrawal credentials.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub withdrawal_credentials: phase0::WithdrawalCredentials,
    /// Amount in gwei.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub amount: phase0::Gwei,
    /// Signature.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
    /// Request index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub index: u64,
}

/// Execution-layer withdrawal request.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#withdrawalrequest>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// Source execution address.
    #[serde(with = "bellatrix::execution_address_serde")]
    pub source_address: bellatrix::ExecutionAddress,
    /// Validator public key.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub validator_pubkey: phase0::BLSPubKey,
    /// Amount in gwei.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub amount: phase0::Gwei,
}

/// Execution-layer consolidation request.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#consolidationrequest>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct ConsolidationRequest {
    /// Source execution address.
    #[serde(with = "bellatrix::execution_address_serde")]
    pub source_address: bellatrix::ExecutionAddress,
    /// Source validator public key.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub source_pubkey: phase0::BLSPubKey,
    /// Target validator public key.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub target_pubkey: phase0::BLSPubKey,
}

/// Electra execution requests container.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#executionrequests>
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct ExecutionRequests {
    /// Deposit requests.
    pub deposits: phase0::SszList<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>,
    /// Withdrawal requests.
    pub withdrawals: phase0::SszList<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>,
    /// Consolidation requests.
    pub consolidations:
        phase0::SszList<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>,
}

/// Electra beacon block body.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#beaconblockbody>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
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
    pub attester_slashings: phase0::SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS_ELECTRA>,
    /// Attestations included in the block.
    pub attestations: phase0::SszList<Attestation, MAX_ATTESTATIONS_ELECTRA>,
    /// Deposits included in the block.
    pub deposits: phase0::SszList<phase0::Deposit, { phase0::MAX_DEPOSITS }>,
    /// Voluntary exits included in the block.
    pub voluntary_exits:
        phase0::SszList<phase0::SignedVoluntaryExit, { phase0::MAX_VOLUNTARY_EXITS }>,
    /// Sync committee aggregate.
    pub sync_aggregate: altair::SyncAggregate,
    /// Execution payload.
    pub execution_payload: deneb::ExecutionPayload,
    /// Signed BLS-to-execution changes.
    pub bls_to_execution_changes: phase0::SszList<
        capella::SignedBLSToExecutionChange,
        { capella::MAX_BLS_TO_EXECUTION_CHANGES },
    >,
    /// Blob KZG commitments.
    pub blob_kzg_commitments:
        phase0::SszList<deneb::KZGCommitment, { deneb::MAX_BLOB_COMMITMENTS_PER_BLOCK }>,
    /// Execution requests.
    pub execution_requests: ExecutionRequests,
}

/// Electra beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#beaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
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

/// Electra blinded beacon block body.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/deneb/blinded-beacon-block.md#blindedbeaconblockbody>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
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
    pub attester_slashings: phase0::SszList<AttesterSlashing, MAX_ATTESTER_SLASHINGS_ELECTRA>,
    /// Attestations included in the block.
    pub attestations: phase0::SszList<Attestation, MAX_ATTESTATIONS_ELECTRA>,
    /// Deposits included in the block.
    pub deposits: phase0::SszList<phase0::Deposit, { phase0::MAX_DEPOSITS }>,
    /// Voluntary exits included in the block.
    pub voluntary_exits:
        phase0::SszList<phase0::SignedVoluntaryExit, { phase0::MAX_VOLUNTARY_EXITS }>,
    /// Sync committee aggregate.
    pub sync_aggregate: altair::SyncAggregate,
    /// Execution payload header.
    pub execution_payload_header: deneb::ExecutionPayloadHeader,
    /// Signed BLS-to-execution changes.
    pub bls_to_execution_changes: phase0::SszList<
        capella::SignedBLSToExecutionChange,
        { capella::MAX_BLS_TO_EXECUTION_CHANGES },
    >,
    /// Blob KZG commitments.
    pub blob_kzg_commitments:
        phase0::SszList<deneb::KZGCommitment, { deneb::MAX_BLOB_COMMITMENTS_PER_BLOCK }>,
    /// Execution requests.
    pub execution_requests: ExecutionRequests,
}

/// Electra blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/deneb/blinded-beacon-block.md#blindedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
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

/// Electra signed beacon block.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/beacon-chain.md#signedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    /// Unsigned block message.
    pub message: BeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Electra signed blinded beacon block.
///
/// Spec: <https://github.com/ethereum/builder-specs/blob/main/specs/deneb/blinded-beacon-block.md#signedblindedbeaconblock>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedBlindedBeaconBlock {
    /// Unsigned blinded block message.
    pub message: BlindedBeaconBlock,
    /// Signature of the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

/// Electra signed block contents container.
///
/// Spec: <https://ethereum.github.io/beacon-APIs/#/Validator/publishBlockV2>
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SignedBlockContents {
    /// Signed block.
    pub signed_block: SignedBeaconBlock,
    /// KZG proofs accompanying blobs.
    pub kzg_proofs: Vec<deneb::KZGProof>,
    /// Blob sidecars.
    pub blobs: Vec<deneb::Blob>,
}

/// Electra aggregate-and-proof payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/validator.md#aggregateandproof>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct AggregateAndProof {
    /// Aggregator validator index.
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub aggregator_index: phase0::ValidatorIndex,
    /// Aggregate attestation.
    pub aggregate: Attestation,
    /// Selection proof.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub selection_proof: phase0::BLSSignature,
}

/// Electra signed aggregate-and-proof payload.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/master/specs/electra/validator.md#signedaggregateandproof>
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash, Serialize, Deserialize)]
pub struct SignedAggregateAndProof {
    /// Unsigned message.
    pub message: AggregateAndProof,
    /// Signature over the message.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub signature: phase0::BLSSignature,
}

#[cfg(test)]
mod tests {
    use crate::test_fixtures;
    use test_case::test_case;

    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::electra_beacon_block_body_fixture()),
        test_fixtures::VECTORS.electra_beacon_block_body_root;
        "beacon_block_body_root"
    )]
    #[test_case(
        test_fixtures::tree_hash_hex(&test_fixtures::electra_beacon_block_fixture()),
        test_fixtures::VECTORS.electra_beacon_block_root;
        "beacon_block_root"
    )]
    fn tree_hash_matches_vector(actual: String, expected: &'static str) {
        assert_eq!(actual, expected);
    }

    #[test]
    fn oversized_attestation_from_vector_deserializes() {
        let attestation: super::Attestation =
            serde_json::from_str(test_fixtures::VECTORS.electra_oversized_attestation_json)
                .expect("electra attestation");
        assert!(attestation.aggregation_bits.len() > 2048);
    }

    #[test]
    fn indexed_attestation_indices_json_are_strings() {
        let body = test_fixtures::electra_beacon_block_body_fixture();
        let indexed = body.attester_slashings.0[0].attestation_1.clone();

        let json = serde_json::to_value(&indexed).expect("serialize indexed attestation");
        assert_eq!(json["attesting_indices"], serde_json::json!(["21", "22"]));

        let roundtrip: super::IndexedAttestation =
            serde_json::from_value(json).expect("deserialize indexed attestation");
        assert_eq!(roundtrip.attesting_indices.0, vec![21, 22]);
    }

    #[test]
    fn attestation_try_from_matches_json_roundtrip() {
        let wire = serde_json::json!({
            "aggregation_bits": "0x0102",
            "committee_bits": format!("0x{}", "00".repeat(8)),
            "data": {
                "slot": "42",
                "index": "3",
                "beacon_block_root": format!("0x{}", "11".repeat(32)),
                "source": { "epoch": "5", "root": format!("0x{}", "22".repeat(32)) },
                "target": { "epoch": "6", "root": format!("0x{}", "33".repeat(32)) },
            },
            "signature": format!("0x{}", "44".repeat(96)),
        });
        let generated: crate::GetBlockAttestationsV2ResponseResponseDataArray =
            serde_json::from_value(wire.clone()).expect("deserialize generated attestation");

        // Direct conversion must equal the loosely-typed JSON round-trip it
        // replaces.
        let direct = super::Attestation::try_from(&generated).expect("convert");
        let via_json: super::Attestation = serde_json::from_value(wire).expect("json round-trip");
        assert_eq!(direct, via_json);
        assert_eq!(direct.data.slot, 42);
        assert_eq!(direct.signature, [0x44; 96]);
    }
}
