//! Beacon API request and response types, shaped after the Ethereum
//! beacon-APIs OpenAPI specification v4.0.0 (consensus spec v1.5.0).
//!
//! Values follow the API's JSON conventions: integers are quoted decimal
//! strings and byte values are `0x`-prefixed hex strings.

use serde::{Deserialize, Serialize};
use validator::Validate;
static REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE: std::sync::LazyLock<
    regex::Regex,
> = std::sync::LazyLock::new(|| {
    regex::Regex::new("^0x[a-fA-F0-9]{192}$").expect("invalid regex")
});
static REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT: std::sync::LazyLock<
    regex::Regex,
> = std::sync::LazyLock::new(|| {
    regex::Regex::new("^0x[a-fA-F0-9]{64}$").expect("invalid regex")
});
static REGEX_CAPELLA_SIGNED_BLS_TO_EXECUTION_CHANGE_MESSAGE_FROM_BLS_PUBKEY: std::sync::LazyLock<
    regex::Regex,
> = std::sync::LazyLock::new(|| {
    regex::Regex::new("^0x[a-fA-F0-9]{96}$").expect("invalid regex")
});
static REGEX_CAPELLA_SIGNED_BLS_TO_EXECUTION_CHANGE_MESSAGE_TO_EXECUTION_ADDRESS: std::sync::LazyLock<
    regex::Regex,
> = std::sync::LazyLock::new(|| {
    regex::Regex::new("^0x[a-fA-F0-9]{40}$").expect("invalid regex")
});
static REGEX_CONTRIBUTION_AGGREGATION_BITS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(||
regex::Regex::new("^0x[a-fA-F0-9]{2,}$").expect("invalid regex"));
pub const ETH_CONSENSUS_VERSION: http::HeaderName = http::HeaderName::from_static(
    "eth-consensus-version",
);
#[derive(Debug, Clone, PartialEq, Serialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum AggregateAndProofRequestBody {
    #[default]
    Array(Vec<AggregateAndProofRequestBodyArray>),
    Array2(Vec<AggregateAndProofRequestBodyArray2>),
}
///The [`SignedAggregateAndProof`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/validator.md#signedaggregateandproof) object
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct AggregateAndProofRequestBodyArray {
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`SignedAggregateAndProof`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#signedaggregateandproof) object
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct AggregateAndProofRequestBodyArray2 {
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#beaconblockbody) object from the CL Altair spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct AltairBeaconBlockBody {
    pub attestations: Vec<GetBlockAttestationsV2ResponseResponseDataArray2>,
    pub attester_slashings: Vec<GetPoolAttesterSlashingsV2ResponseResponseDataArray2>,
    pub deposits: Vec<AltairBeaconBlockBodyDeposit>,
    ///The [`Eth1Data`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#eth1data) object from the CL spec.
    pub eth1_data: Eth1Data,
    pub graffiti: String,
    pub proposer_slashings: Vec<GetPoolProposerSlashingsResponseResponseDatum>,
    ///The RanDAO reveal value provided by the validator.
    pub randao_reveal: String,
    ///The [`SyncAggregate`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#syncaggregate) object from the CL Altair spec.
    pub sync_aggregate: SyncAggregate,
    pub voluntary_exits: Vec<GetPoolVoluntaryExitsResponseResponseDatum>,
}
///The [`Deposit`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#deposit) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct AltairBeaconBlockBodyDeposit {
    ///The [`DepositData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#depositdata) object from the CL spec.
    pub data: AltairBeaconBlockBodyDepositData,
    ///Branch in the deposit tree.
    pub proof: Vec<String>,
}
///The [`DepositData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#depositdata) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct AltairBeaconBlockBodyDepositData {
    ///Amount in Gwei.
    pub amount: String,
    ///The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub pubkey: String,
    ///Container self-signature.
    pub signature: String,
    ///The withdrawal credentials.
    pub withdrawal_credentials: String,
}
///The [`Checkpoint`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#checkpoint) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct AltairBeaconStateCurrentJustifiedCheckpoint {
    #[validate(length(min = 1u64))]
    pub epoch: String,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT")
    )]
    pub root: String,
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct AltairSignedContributionAndProofMessage {
    ///Index of validator in validator registry.
    #[validate(length(min = 1u64))]
    pub aggregator_index: String,
    #[validate(nested)]
    pub contribution: Contribution,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub selection_proof: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum AttestationRequestBody2 {
    #[default]
    Array(Vec<AttestationRequestBody2Array>),
    Array2(Vec<GetBlockAttestationsV2ResponseResponseDataArray2>),
}
///The [`SingleAttestation`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/beacon-chain.md#singleattestation) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct AttestationRequestBody2Array {
    ///The validator index that signed this attestation.
    #[validate(length(min = 1u64))]
    pub attester_index: String,
    ///The attestations committee index.
    #[validate(length(min = 1u64))]
    pub committee_index: String,
    ///The [`AttestationData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestationdata) object from the CL spec.
    #[validate(nested)]
    pub data: Data,
    ///BLS aggregate signature.
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct BeaconCommitteeSelection501Response {
    ///Either specific error code in case of invalid request or http status code
    pub code: f64,
    ///Message describing error
    pub message: String,
    ///Optional stacktraces, sent when node is in debug mode
    pub stacktraces: Option<Vec<String>>,
}
pub type BeaconCommitteeSelectionRequestRequestBody = Vec<
    BeaconCommitteeSelectionRequestRequestBodyItem,
>;
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct BeaconCommitteeSelectionRequestRequestBodyItem {
    ///The `slot_signature` calculated by the validator for the upcoming attestation slot
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub selection_proof: String,
    ///The slot at which a validator is assigned to attest
    #[validate(length(min = 1u64))]
    pub slot: String,
    ///Index of the validator
    #[validate(length(min = 1u64))]
    pub validator_index: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct BeaconCommitteeSelectionResponseResponse {
    pub data: Vec<BeaconCommitteeSelectionRequestRequestBodyItem>,
}
///The [`Fork`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#fork) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct BeaconStateFork {
    ///a fork version number
    pub current_version: String,
    pub epoch: String,
    ///a fork version number
    pub previous_version: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct BlindedBlock400Response {
    ///Either specific error code in case of invalid request or http status code
    pub code: f64,
    ///Message describing error
    pub message: String,
    ///Optional stacktraces, sent when node is in debug mode
    pub stacktraces: Option<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct BlindedBlock406Response {
    ///The media type in "Accept" header is unsupported, and the request has been rejected. This occurs when the server cannot produce a response in the format accepted by the client.
    pub code: f64,
    ///Message describing error
    pub message: String,
    ///Optional stacktraces, sent when node is in debug mode
    pub stacktraces: Option<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, Serialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum BlockRequestBody {
    ///The required signed components of block production according to the Fulu CL spec.
    #[default]
    Object(BlockRequestBodyObject),
    ///The required signed components of block production according to the Electra CL spec.
    Object2(BlockRequestBodyObject2),
    ///The required signed components of block production according to the Deneb CL spec.
    Object3(BlockRequestBodyObject3),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Capella spec.
    Object4(BlockRequestBodyObject4),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Bellatrix spec.
    Object5(BlockRequestBodyObject5),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Altair spec.
    Object6(GetBlindedBlockResponseResponseDataObject5),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL spec.
    Object7(GetBlindedBlockResponseResponseDataObject6),
}
///The required signed components of block production according to the Fulu CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct BlockRequestBodyObject {
    #[validate(length(min = 0u64, max = 4_096u64))]
    pub blobs: Vec<String>,
    ///Cell proofs of the blobs as defined in EIP-7594
    #[validate(length(min = 0u64, max = 33_554_432u64))]
    pub kzg_proofs: Vec<String>,
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Electra spec.
    #[validate(nested)]
    pub signed_block: SignedBlockContentsSignedBlock,
}
///The required signed components of block production according to the Electra CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct BlockRequestBodyObject2 {
    #[validate(length(min = 0u64, max = 4_096u64))]
    pub blobs: Vec<String>,
    #[validate(length(min = 0u64, max = 4_096u64))]
    pub kzg_proofs: Vec<String>,
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Electra spec.
    #[validate(nested)]
    pub signed_block: SignedBlockContentsSignedBlock,
}
///The required signed components of block production according to the Deneb CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct BlockRequestBodyObject3 {
    #[validate(length(min = 0u64, max = 4_096u64))]
    pub blobs: Vec<String>,
    #[validate(length(min = 0u64, max = 4_096u64))]
    pub kzg_proofs: Vec<String>,
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Deneb spec.
    #[validate(nested)]
    pub signed_block: DenebSignedBlockContentsSignedBlock,
}
///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Capella spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct BlockRequestBodyObject4 {
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Capella spec.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Bellatrix spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct BlockRequestBodyObject5 {
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Bellatrix spec.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct BlsToExecutionChange400Response {
    ///Either specific error code in case of invalid request or http status code
    pub code: f64,
    ///List of individual items that have failed
    pub failures: Vec<BlsToExecutionChange400ResponseFailure>,
    ///Message describing error
    pub message: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct BlsToExecutionChange400ResponseFailure {
    ///Index of item in the request list that caused the error
    pub index: f64,
    ///Message describing error
    pub message: String,
}
///Level of validation that must be applied to a block before it is broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, oas3_gen_support::Default)]
pub enum BroadcastValidation {
    #[serde(rename = "gossip")]
    #[default]
    Gossip,
    #[serde(rename = "consensus")]
    Consensus,
    #[serde(rename = "consensus_and_equivocation")]
    ConsensusAndEquivocation,
}
impl core::fmt::Display for BroadcastValidation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Gossip => write!(f, "gossip"),
            Self::Consensus => write!(f, "consensus"),
            Self::ConsensusAndEquivocation => write!(f, "consensus_and_equivocation"),
        }
    }
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    oas3_gen_support::Default
)]
pub enum ConsensusVersion {
    #[serde(rename = "phase0")]
    #[default]
    Phase0,
    #[serde(rename = "altair")]
    Altair,
    #[serde(rename = "bellatrix")]
    Bellatrix,
    #[serde(rename = "capella")]
    Capella,
    #[serde(rename = "deneb")]
    Deneb,
    #[serde(rename = "electra")]
    Electra,
    #[serde(rename = "fulu")]
    Fulu,
}
impl core::fmt::Display for ConsensusVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Phase0 => write!(f, "phase0"),
            Self::Altair => write!(f, "altair"),
            Self::Bellatrix => write!(f, "bellatrix"),
            Self::Capella => write!(f, "capella"),
            Self::Deneb => write!(f, "deneb"),
            Self::Electra => write!(f, "electra"),
            Self::Fulu => write!(f, "fulu"),
        }
    }
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct Contribution {
    ///A bit is set if a signature from the validator at the corresponding index in the subcommittee is present in the aggregate `signature`.
    #[validate(length(min = 1u64), regex(path = "REGEX_CONTRIBUTION_AGGREGATION_BITS"))]
    pub aggregation_bits: String,
    ///Block root for this contribution.
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT")
    )]
    pub beacon_block_root: String,
    ///Signature by the validator(s) over the block root of `slot`
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
    ///The slot at which the validator is providing a sync committee contribution.
    #[validate(length(min = 1u64))]
    pub slot: String,
    ///The index of the subcommittee that the contribution pertains to.
    #[validate(length(min = 1u64))]
    pub subcommittee_index: String,
}
pub type ContributionAndProofRequestBody = Vec<ContributionAndProofRequestBodyItem>;
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct ContributionAndProofRequestBodyItem {
    #[validate(nested)]
    pub message: AltairSignedContributionAndProofMessage,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`AttestationData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestationdata) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct Data {
    ///LMD GHOST vote.
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT")
    )]
    pub beacon_block_root: String,
    #[validate(length(min = 1u64))]
    pub index: String,
    #[validate(length(min = 1u64))]
    pub slot: String,
    ///The [`Checkpoint`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#checkpoint) object from the CL spec.
    #[validate(nested)]
    pub source: AltairBeaconStateCurrentJustifiedCheckpoint,
    ///The [`Checkpoint`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#checkpoint) object from the CL spec.
    #[validate(nested)]
    pub target: AltairBeaconStateCurrentJustifiedCheckpoint,
}
///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Deneb spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct DenebSignedBlockContentsSignedBlock {
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Deneb spec.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`Eth1Data`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#eth1data) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct Eth1Data {
    ///Ethereum 1.x block hash.
    pub block_hash: String,
    ///Total number of deposits.
    pub deposit_count: String,
    ///Root of the deposit tree.
    pub deposit_root: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, oas3_gen_support::Default)]
pub enum EventstreamRequestQueryTopic {
    #[serde(rename = "head")]
    #[default]
    Head,
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "block_gossip")]
    BlockGossip,
    #[serde(rename = "attestation")]
    Attestation,
    #[serde(rename = "single_attestation")]
    SingleAttestation,
    #[serde(rename = "voluntary_exit")]
    VoluntaryExit,
    #[serde(rename = "bls_to_execution_change")]
    BlsToExecutionChange,
    #[serde(rename = "proposer_slashing")]
    ProposerSlashing,
    #[serde(rename = "attester_slashing")]
    AttesterSlashing,
    #[serde(rename = "finalized_checkpoint")]
    FinalizedCheckpoint,
    #[serde(rename = "chain_reorg")]
    ChainReorg,
    #[serde(rename = "contribution_and_proof")]
    ContributionAndProof,
    #[serde(rename = "light_client_finality_update")]
    LightClientFinalityUpdate,
    #[serde(rename = "light_client_optimistic_update")]
    LightClientOptimisticUpdate,
    #[serde(rename = "payload_attributes")]
    PayloadAttributes,
    #[serde(rename = "blob_sidecar")]
    BlobSidecar,
    #[serde(rename = "data_column_sidecar")]
    DataColumnSidecar,
}
impl core::fmt::Display for EventstreamRequestQueryTopic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Head => write!(f, "head"),
            Self::Block => write!(f, "block"),
            Self::BlockGossip => write!(f, "block_gossip"),
            Self::Attestation => write!(f, "attestation"),
            Self::SingleAttestation => write!(f, "single_attestation"),
            Self::VoluntaryExit => write!(f, "voluntary_exit"),
            Self::BlsToExecutionChange => write!(f, "bls_to_execution_change"),
            Self::ProposerSlashing => write!(f, "proposer_slashing"),
            Self::AttesterSlashing => write!(f, "attester_slashing"),
            Self::FinalizedCheckpoint => write!(f, "finalized_checkpoint"),
            Self::ChainReorg => write!(f, "chain_reorg"),
            Self::ContributionAndProof => write!(f, "contribution_and_proof"),
            Self::LightClientFinalityUpdate => write!(f, "light_client_finality_update"),
            Self::LightClientOptimisticUpdate => {
                write!(f, "light_client_optimistic_update")
            }
            Self::PayloadAttributes => write!(f, "payload_attributes"),
            Self::BlobSidecar => write!(f, "blob_sidecar"),
            Self::DataColumnSidecar => write!(f, "data_column_sidecar"),
        }
    }
}
///Aggregates all attestations matching given attestation data root, slot and committee index.
///
///A 503 error must be returned if the block identified by the response
///`beacon_block_root` is optimistic (i.e. the aggregated attestation attests
///to a block that has not been fully verified by an execution engine).
///
///A 404 error must be returned if no attestation is available for the requested
///`attestation_data_root`.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetAggregatedAttestationV2Request {
    #[validate(nested)]
    pub query: GetAggregatedAttestationV2RequestQuery,
}
#[bon::bon]
impl GetAggregatedAttestationV2Request {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        attestation_data_root: String,
        slot: String,
        committee_index: String,
    ) -> anyhow::Result<Self> {
        let request = Self {
            query: GetAggregatedAttestationV2RequestQuery {
                attestation_data_root,
                slot,
                committee_index,
            },
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetAggregatedAttestationV2RequestQuery {
    ///HashTreeRoot of AttestationData that validator wants aggregated
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT")
    )]
    pub attestation_data_root: String,
    #[validate(length(min = 1u64))]
    pub slot: String,
    #[validate(length(min = 1u64))]
    pub committee_index: String,
}
///Response types for getAggregatedAttestationV2
#[derive(Debug, Clone)]
pub enum GetAggregatedAttestationV2Response {
    ///200: Returns aggregated `Attestation` object with same `AttestationData` root, slot and committee index.
    Ok(GetAggregatedAttestationV2ResponseResponse),
    ///200: Returns aggregated `Attestation` object with same `AttestationData` root, slot and committee index.
    OkBinary(Vec<u8>),
    ///400: Invalid request syntax.
    BadRequest(PendingConsolidation400Response),
    ///404: Not found
    NotFound(BlindedBlock400Response),
    ///406: Accepted media type is not supported.
    NotAcceptable(BlindedBlock406Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetAggregatedAttestationV2ResponseResponse {
    pub data: GetAggregatedAttestationV2ResponseResponseData,
    pub version: ConsensusVersion,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum GetAggregatedAttestationV2ResponseResponseData {
    ///The [`Attestation`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/beacon-chain.md#attestation) object from the CL spec.
    #[default]
    Object(GetBlockAttestationsV2ResponseResponseDataArray),
    ///The [`Attestation`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestation) object from the CL spec.
    Object2(GetBlockAttestationsV2ResponseResponseDataArray2),
}
pub type GetAttesterDutiesBodyRequestBody = Vec<String>;
///Requests the beacon node to provide a set of attestation duties, which should be performed by validators, for a particular epoch.
///Duties should only need to be checked once per epoch, however a chain reorganization (of > MIN_SEED_LOOKAHEAD epochs) could occur, resulting in a change of duties. For full safety, you should monitor head events and confirm the dependent root in this response matches:
///- event.previous_duty_dependent_root when `compute_epoch_at_slot(event.slot) == epoch`
///- event.current_duty_dependent_root when `compute_epoch_at_slot(event.slot) + 1 == epoch`
///- event.block otherwise
///
///The dependent_root value is `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch - 1) - 1)` or the genesis block root in the case of underflow.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetAttesterDutiesRequest {
    #[validate(nested)]
    pub path: GetAttesterDutiesRequestPath,
    ///An array of the validator indices for which to obtain the duties.
    pub body: GetAttesterDutiesBodyRequestBody,
}
#[bon::bon]
impl GetAttesterDutiesRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        epoch: String,
        body: GetAttesterDutiesBodyRequestBody,
    ) -> anyhow::Result<Self> {
        let request = Self {
            path: GetAttesterDutiesRequestPath {
                epoch,
            },
            body,
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct GetAttesterDutiesRequestPath {
    ///Should only be allowed 1 epoch ahead
    #[validate(length(min = 1u64))]
    pub epoch: String,
}
///Response types for getAttesterDuties
#[derive(Debug, Clone)]
pub enum GetAttesterDutiesResponse {
    ///200: Success response
    Ok(GetAttesterDutiesResponseResponse),
    ///400: Invalid epoch or index
    BadRequest(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetAttesterDutiesResponseResponse {
    pub data: Vec<GetAttesterDutiesResponseResponseDatum>,
    ///The block root that this response is dependent on.
    pub dependent_root: String,
    ///True if the response references an unverified execution payload. Optimistic information may be invalidated at a later time. If the field is not present, assume the False value.
    pub execution_optimistic: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetAttesterDutiesResponseResponseDatum {
    ///The committee index
    pub committee_index: String,
    ///Number of validators in committee
    pub committee_length: String,
    ///Number of committees at the provided slot
    pub committees_at_slot: String,
    ///The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub pubkey: String,
    ///The slot at which the validator must attest.
    pub slot: String,
    ///Index of validator in committee
    pub validator_committee_index: String,
    ///Index of validator in validator registry
    pub validator_index: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum GetBlindedBlockResponseResponseData {
    ///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Electra spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
    #[default]
    Object(GetBlindedBlockResponseResponseDataObject),
    ///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Deneb spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
    Object2(GetBlindedBlockResponseResponseDataObject2),
    ///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Capella spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
    Object3(GetBlindedBlockResponseResponseDataObject3),
    ///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Bellatrix spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
    Object4(GetBlindedBlockResponseResponseDataObject4),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Altair spec.
    Object5(GetBlindedBlockResponseResponseDataObject5),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL spec.
    Object6(GetBlindedBlockResponseResponseDataObject6),
}
///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Electra spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetBlindedBlockResponseResponseDataObject {
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Electra spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Deneb spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetBlindedBlockResponseResponseDataObject2 {
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Deneb spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Capella spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetBlindedBlockResponseResponseDataObject3 {
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Capella spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///A variant of the [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Bellatrix spec, which contains a `BlindedBeaconBlock` rather than a `BeaconBlock`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetBlindedBlockResponseResponseDataObject4 {
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Bellatrix spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Altair spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetBlindedBlockResponseResponseDataObject5 {
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Altair spec.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetBlindedBlockResponseResponseDataObject6 {
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL spec.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`Attestation`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/beacon-chain.md#attestation) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetBlockAttestationsV2ResponseResponseDataArray {
    ///Attester aggregation bits.
    pub aggregation_bits: String,
    ///Committee bits.
    pub committee_bits: String,
    ///The [`AttestationData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestationdata) object from the CL spec.
    pub data: Data,
    ///BLS aggregate signature.
    pub signature: String,
}
///The [`Attestation`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestation) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetBlockAttestationsV2ResponseResponseDataArray2 {
    ///Attester aggregation bits.
    #[validate(length(min = 1u64), regex(path = "REGEX_CONTRIBUTION_AGGREGATION_BITS"))]
    pub aggregation_bits: String,
    ///The [`AttestationData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestationdata) object from the CL spec.
    #[validate(nested)]
    pub data: Data,
    ///BLS aggregate signature.
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///Retrieves block header for given block id.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetBlockHeaderRequest {
    #[validate(nested)]
    pub path: GetBlockHeaderRequestPath,
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct GetBlockHeaderRequestPath {
    ///Block identifier.
    ///Can be one of: "head" (canonical head in node's view), "genesis", "finalized", \<slot\>, \<hex encoded blockRoot with 0x prefix\>.
    ///- Example: `"head".to_string()`
    #[validate(length(min = 1u64))]
    pub block_id: String,
}
///Response types for getBlockHeader
#[derive(Debug, Clone)]
pub enum GetBlockHeaderResponse {
    ///200: Success
    Ok(GetBlockHeaderResponseResponse),
    ///400: The block ID supplied could not be parsed
    BadRequest(BlindedBlock400Response),
    ///404: Block not found
    NotFound(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetBlockHeaderResponseResponse {
    pub data: GetBlockHeadersResponseResponseDatum,
    ///True if the response references an unverified execution payload. Optimistic information may be invalidated at a later time. If the field is not present, assume the False value.
    pub execution_optimistic: bool,
    ///True if the response references the finalized history of the chain, as determined by fork choice. If the field is not present, additional calls are necessary to compare the epoch of the requested information with the finalized checkpoint.
    pub finalized: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetBlockHeadersResponseResponseDatum {
    pub canonical: bool,
    ///The [`SignedBeaconBlockHeader`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblockheader) object envelope from the CL spec.
    pub header: Phase0ProposerSlashingSignedHeader1,
    pub root: String,
}
///Retrieves hashTreeRoot of BeaconBlock/BeaconBlockHeader
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetBlockRootRequest {
    #[validate(nested)]
    pub path: GetBlockRootRequestPath,
}
#[bon::bon]
impl GetBlockRootRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(block_id: String) -> anyhow::Result<Self> {
        let request = Self {
            path: GetBlockRootRequestPath {
                block_id,
            },
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct GetBlockRootRequestPath {
    ///Block identifier.
    ///Can be one of: "head" (canonical head in node's view), "genesis", "finalized", \<slot\>, \<hex encoded blockRoot with 0x prefix\>.
    ///- Example: `"head".to_string()`
    #[validate(length(min = 1u64))]
    pub block_id: String,
}
///Response types for getBlockRoot
#[derive(Debug, Clone)]
pub enum GetBlockRootResponse {
    ///200: Success
    Ok(GetBlockRootResponseResponse),
    ///400: The block ID supplied could not be parsed
    BadRequest(BlindedBlock400Response),
    ///404: Block not found
    NotFound(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetBlockRootResponseResponse {
    pub data: GetBlockRootResponseResponseData,
    ///True if the response references an unverified execution payload. Optimistic information may be invalidated at a later time. If the field is not present, assume the False value.
    pub execution_optimistic: bool,
    ///True if the response references the finalized history of the chain, as determined by fork choice. If the field is not present, additional calls are necessary to compare the epoch of the requested information with the finalized checkpoint.
    pub finalized: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetBlockRootResponseResponseData {
    ///HashTreeRoot of BeaconBlock/BeaconBlockHeader object
    pub root: String,
}
///Retrieves block details for given block id.
///Depending on `Accept` header it can be returned either as json or as bytes serialized by SSZ
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetBlockV2Request {
    #[validate(nested)]
    pub path: GetBlockV2RequestPath,
}
#[bon::bon]
impl GetBlockV2Request {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(block_id: String) -> anyhow::Result<Self> {
        let request = Self {
            path: GetBlockV2RequestPath { block_id },
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct GetBlockV2RequestPath {
    ///Block identifier.
    ///Can be one of: "head" (canonical head in node's view), "genesis", "finalized", \<slot\>, \<hex encoded blockRoot with 0x prefix\>.
    ///- Example: `"head".to_string()`
    #[validate(length(min = 1u64))]
    pub block_id: String,
}
///Response types for getBlockV2
#[derive(Debug, Clone)]
pub enum GetBlockV2Response {
    ///200: Successful response
    Ok(GetBlockV2ResponseResponse),
    ///200: Successful response
    OkBinary(Vec<u8>),
    ///400: The block ID supplied could not be parsed
    BadRequest(BlindedBlock400Response),
    ///404: Block not found
    NotFound(BlindedBlock400Response),
    ///406: Accepted media type is not supported.
    NotAcceptable(BlindedBlock406Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetBlockV2ResponseResponse {
    pub data: GetBlockV2ResponseResponseData,
    ///True if the response references an unverified execution payload. Optimistic information may be invalidated at a later time. If the field is not present, assume the False value.
    pub execution_optimistic: bool,
    ///True if the response references the finalized history of the chain, as determined by fork choice. If the field is not present, additional calls are necessary to compare the epoch of the requested information with the finalized checkpoint.
    pub finalized: bool,
    pub version: ConsensusVersion,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum GetBlockV2ResponseResponseData {
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Electra spec.
    #[default]
    Object(SignedBlockContentsSignedBlock),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Deneb spec.
    Object2(DenebSignedBlockContentsSignedBlock),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Capella spec.
    Object3(BlockRequestBodyObject4),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Bellatrix spec.
    Object4(BlockRequestBodyObject5),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Altair spec.
    Object5(GetBlindedBlockResponseResponseDataObject5),
    ///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL spec.
    Object6(GetBlindedBlockResponseResponseDataObject6),
}
///Retrieve all forks, past present and future, of which this node is aware.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetForkScheduleRequest {}
///Response types for getForkSchedule
#[derive(Debug, Clone)]
pub enum GetForkScheduleResponse {
    ///200: Success
    Ok(GetForkScheduleResponseResponse),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetForkScheduleResponseResponse {
    pub data: Vec<BeaconStateFork>,
}
///Retrieve details of the chain's genesis which can be used to identify chain.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetGenesisRequest {}
///Response types for getGenesis
#[derive(Debug, Clone)]
pub enum GetGenesisResponse {
    ///200: Request successful
    Ok(GetGenesisResponseResponse),
    ///404: Chain genesis info is not yet known
    NotFound(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetGenesisResponseResponse {
    pub data: GetGenesisResponseResponseData,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetGenesisResponseResponseData {
    ///a fork version number
    pub genesis_fork_version: String,
    ///The genesis_time configured for the beacon node, which is the unix time in seconds at which the Eth2.0 chain began.
    pub genesis_time: String,
    pub genesis_validators_root: String,
}
///Requests that the beacon node identify information about its implementation in a format similar to a  [HTTP User-Agent](https://tools.ietf.org/html/rfc7231#section-5.5.3) field.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetNodeVersionRequest {}
///Response types for getNodeVersion
#[derive(Debug, Clone)]
pub enum GetNodeVersionResponse {
    ///200: Request successful
    Ok(GetVersionResponseResponse),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///Retrieves number of known peers.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetPeerCountRequest {}
///Response types for getPeerCount
#[derive(Debug, Clone)]
pub enum GetPeerCountResponse {
    ///200: Request successful
    Ok(GetPeerCountResponseResponse),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetPeerCountResponseResponse {
    pub data: GetPeerCountResponseResponseData,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetPeerCountResponseResponseData {
    pub connected: String,
    pub connecting: String,
    pub disconnected: String,
    pub disconnecting: String,
}
///The [`AttesterSlashing`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attesterslashing) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetPoolAttesterSlashingsV2ResponseResponseDataArray2 {
    ///The [`IndexedAttestation`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#indexedattestation) object from the CL spec.
    #[validate(nested)]
    pub attestation_1: Phase0AttesterSlashingAttestation1,
    ///The [`IndexedAttestation`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#indexedattestation) object from the CL spec.
    #[validate(nested)]
    pub attestation_2: Phase0AttesterSlashingAttestation1,
}
///The [`ProposerSlashing`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#proposerslashing) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetPoolProposerSlashingsResponseResponseDatum {
    ///The [`SignedBeaconBlockHeader`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblockheader) object envelope from the CL spec.
    #[validate(nested)]
    pub signed_header_1: Phase0ProposerSlashingSignedHeader1,
    ///The [`SignedBeaconBlockHeader`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblockheader) object envelope from the CL spec.
    #[validate(nested)]
    pub signed_header_2: Phase0ProposerSlashingSignedHeader1,
}
///The [`SignedVoluntaryExit`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedvoluntaryexit) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct GetPoolVoluntaryExitsResponseResponseDatum {
    ///The [`VoluntaryExit`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#voluntaryexit) object from the CL spec.
    #[validate(nested)]
    pub message: Phase0SignedVoluntaryExitMessage,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///Request beacon node to provide all validators that are scheduled to propose a block in the given epoch.
///Duties should only need to be checked once per epoch, however a chain reorganization could occur that results in a change of duties. For full safety, you should monitor head events and confirm the dependent root in this response matches:
///- event.current_duty_dependent_root when `compute_epoch_at_slot(event.slot) == epoch`
///- event.block otherwise
///
///The dependent_root value is `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)` or the genesis block root in the case of underflow.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetProposerDutiesRequest {
    #[validate(nested)]
    pub path: GetProposerDutiesRequestPath,
}
#[bon::bon]
impl GetProposerDutiesRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(epoch: String) -> anyhow::Result<Self> {
        let request = Self {
            path: GetProposerDutiesRequestPath {
                epoch,
            },
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct GetProposerDutiesRequestPath {
    #[validate(length(min = 1u64))]
    pub epoch: String,
}
///Response types for getProposerDuties
#[derive(Debug, Clone)]
pub enum GetProposerDutiesResponse {
    ///200: Success response
    Ok(GetProposerDutiesResponseResponse),
    ///400: Invalid epoch
    BadRequest(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetProposerDutiesResponseResponse {
    pub data: Vec<GetProposerDutiesResponseResponseDatum>,
    ///The block root that this response is dependent on.
    pub dependent_root: String,
    ///True if the response references an unverified execution payload. Optimistic information may be invalidated at a later time. If the field is not present, assume the False value.
    pub execution_optimistic: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetProposerDutiesResponseResponseDatum {
    ///The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub pubkey: String,
    ///The slot at which the validator must propose block.
    pub slot: String,
    ///Index of validator in validator registry.
    pub validator_index: String,
}
///Retrieve specification configuration used on this node.  The configuration should include:
///  - Constants for all hard forks known by the beacon node, for example the [phase 0](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#constants) and [altair](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#constants) values
///  - Presets for all hard forks supplied to the beacon node, for example the [phase 0](https://github.com/ethereum/consensus-specs/blob/v1.3.0/presets/mainnet/phase0.yaml) and [altair](https://github.com/ethereum/consensus-specs/blob/v1.3.0/presets/mainnet/altair.yaml) values
///  - Configuration for the beacon node, for example the [mainnet](https://github.com/ethereum/consensus-specs/blob/v1.3.0/configs/mainnet.yaml) values
///
///Values are returned with following format:
///  - any value starting with 0x in the spec is returned as a hex string
///  - numeric values are returned as a quoted integer
///  - array values are returned as a JSON array
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetSpecRequest {}
///Response types for getSpec
#[derive(Debug, Clone)]
pub enum GetSpecResponse {
    ///200: Success
    Ok(GetSpecResponseResponse),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetSpecResponseResponse {
    ///Key value mapping of all constants, presets and configuration values for all known hard forks
    ///Values are returned with following format:
    ///  - any value starting with 0x in the spec is returned as a hex string
    ///  - numeric values are returned as a quoted integer
    pub data: serde_json::Value,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetStateValidatorsResponseResponse {
    pub data: Vec<GetStateValidatorsResponseResponseDatum>,
    ///True if the response references an unverified execution payload. Optimistic information may be invalidated at a later time. If the field is not present, assume the False value.
    pub execution_optimistic: bool,
    ///True if the response references the finalized history of the chain, as determined by fork choice. If the field is not present, additional calls are necessary to compare the epoch of the requested information with the finalized checkpoint.
    pub finalized: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetStateValidatorsResponseResponseDatum {
    ///Current validator balance in gwei.
    pub balance: String,
    ///Index of validator in validator registry.
    pub index: String,
    ///Possible statuses:
    ///- **pending_initialized** - When the first deposit is processed, but not enough funds are available (or not yet the end of the first epoch) to get validator into the activation queue.
    ///- **pending_queued** - When validator is waiting to get activated, and have enough funds etc. while in the queue, validator activation epoch keeps changing until it gets to the front and make it through (finalization is a requirement here too).
    ///- **active_ongoing** - When validator must be attesting, and have not initiated any exit.
    ///- **active_exiting** - When validator is still active, but filed a voluntary request to exit.
    ///- **active_slashed** - When validator is still active, but have a slashed status and is scheduled to exit.
    ///- **exited_unslashed** - When validator has reached regular exit epoch, not being slashed, and doesn't have to attest any more, but cannot withdraw yet.
    ///- **exited_slashed** - When validator has reached regular exit epoch, but was slashed, have to wait for a longer withdrawal period.
    ///- **withdrawal_possible** - After validator has exited, a while later is permitted to move funds, and is truly out of the system.
    ///- **withdrawal_done** - (not possible in phase0, except slashing full balance) - actually having moved funds away
    ///
    ///[Validator status specification](https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ)
    pub status: ValidatorStatus,
    ///The [`Validator`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#validator) object from the CL spec.
    pub validator: ValidatorResponseValidator,
}
pub type GetSyncCommitteeDutiesBodyRequestBody = Vec<String>;
///Requests the beacon node to provide a set of sync committee duties for a particular epoch.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetSyncCommitteeDutiesRequest {
    #[validate(nested)]
    pub path: GetSyncCommitteeDutiesRequestPath,
    ///An array of the validator indices for which to obtain the duties.
    pub body: GetSyncCommitteeDutiesBodyRequestBody,
}
#[bon::bon]
impl GetSyncCommitteeDutiesRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        epoch: String,
        body: GetSyncCommitteeDutiesBodyRequestBody,
    ) -> anyhow::Result<Self> {
        let request = Self {
            path: GetSyncCommitteeDutiesRequestPath {
                epoch,
            },
            body,
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct GetSyncCommitteeDutiesRequestPath {
    ///epoch // EPOCHS_PER_SYNC_COMMITTEE_PERIOD <= current_epoch // EPOCHS_PER_SYNC_COMMITTEE_PERIOD + 1
    #[validate(length(min = 1u64))]
    pub epoch: String,
}
///Response types for getSyncCommitteeDuties
#[derive(Debug, Clone)]
pub enum GetSyncCommitteeDutiesResponse {
    ///200: Success response
    Ok(GetSyncCommitteeDutiesResponseResponse),
    ///400: Invalid epoch or index
    BadRequest(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetSyncCommitteeDutiesResponseResponse {
    pub data: Vec<GetSyncCommitteeDutiesResponseResponseDatum>,
    ///True if the response references an unverified execution payload. Optimistic information may be invalidated at a later time. If the field is not present, assume the False value.
    pub execution_optimistic: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetSyncCommitteeDutiesResponseResponseDatum {
    ///The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub pubkey: String,
    ///Index of validator in validator registry.
    pub validator_index: String,
    ///The indices of the validator in the sync committee.
    pub validator_sync_committee_indices: Vec<String>,
}
///Requests the beacon node to describe if it's currently syncing or not, and if it is, what block it is up to.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct GetSyncingStatusRequest {}
///Response types for getSyncingStatus
#[derive(Debug, Clone)]
pub enum GetSyncingStatusResponse {
    ///200: Request successful
    Ok(GetSyncingStatusResponseResponse),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetSyncingStatusResponseResponse {
    pub data: GetSyncingStatusResponseResponseData,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetSyncingStatusResponseResponseData {
    ///Set to true if the execution client is offline.
    pub el_offline: bool,
    ///Head slot node is trying to reach
    pub head_slot: String,
    ///Set to true if the node is optimistically tracking head.
    pub is_optimistic: bool,
    ///Set to true if the node is syncing, false if the node is synced.
    pub is_syncing: bool,
    ///How many slots node needs to process to reach head. 0 if synced.
    pub sync_distance: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetVersionResponseResponse {
    pub data: GetVersionResponseResponseData,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct GetVersionResponseResponseData {
    ///A string which uniquely identifies the client implementation and its version; similar to [HTTP User-Agent](https://tools.ietf.org/html/rfc7231#section-5.5.3).
    pub version: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct PendingConsolidation400Response {
    ///Either specific error code in case of invalid request or http status code
    pub code: f64,
    ///Message describing error
    pub message: String,
    ///Optional stacktraces, sent when node is in debug mode
    pub stacktraces: Option<Vec<String>>,
}
///The [`IndexedAttestation`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#indexedattestation) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct Phase0AttesterSlashingAttestation1 {
    ///Attesting validator indices
    #[validate(length(max = 2_048u64))]
    pub attesting_indices: Vec<String>,
    ///The [`AttestationData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestationdata) object from the CL spec.
    #[validate(nested)]
    pub data: Data,
    ///The BLS signature of the `IndexedAttestation`, created by the validator of the attestation.
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblockbody) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct Phase0BeaconBlockBody {
    pub attestations: Vec<GetBlockAttestationsV2ResponseResponseDataArray2>,
    pub attester_slashings: Vec<GetPoolAttesterSlashingsV2ResponseResponseDataArray2>,
    pub deposits: Vec<AltairBeaconBlockBodyDeposit>,
    ///The [`Eth1Data`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#eth1data) object from the CL spec.
    pub eth1_data: Eth1Data,
    pub graffiti: String,
    pub proposer_slashings: Vec<GetPoolProposerSlashingsResponseResponseDatum>,
    ///The RanDAO reveal value provided by the validator.
    pub randao_reveal: String,
    pub voluntary_exits: Vec<GetPoolVoluntaryExitsResponseResponseDatum>,
}
///The [`SignedBeaconBlockHeader`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#signedbeaconblockheader) object envelope from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct Phase0ProposerSlashingSignedHeader1 {
    ///The [`BeaconBlockHeader`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblockheader) object from the CL spec.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The [`VoluntaryExit`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#voluntaryexit) object from the CL spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct Phase0SignedVoluntaryExitMessage {
    ///Minimum epoch for processing exit.
    #[validate(length(min = 1u64))]
    pub epoch: String,
    ///Index of the exiting validator.
    #[validate(length(min = 1u64))]
    pub validator_index: String,
}
///Returns filterable list of validators with their balance, status and index.
///
///Information will be returned for all indices or public key that match known validators.  If an index or public key does not
///match any known validator, no information will be returned but this will not cause an error.  There are no guarantees for the
///returned data in terms of ordering; both the index and public key are returned for each validator, and can be used to confirm
///for which inputs a response has been returned.
///
///The POST variant of this endpoint has the same semantics as the GET endpoint but passes
///the lists of IDs and statuses via a POST body in order to enable larger requests.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct PostStateValidatorsRequest {
    #[validate(nested)]
    pub path: PostStateValidatorsRequestPath,
    ///The lists of validator IDs and statuses to filter on. Either or both may be `null` to signal that no filtering on that attribute is desired.
    pub body: ValidatorRequestBody,
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct PostStateValidatorsRequestPath {
    ///State identifier.
    ///Can be one of: "head" (canonical head in node's view), "genesis", "finalized", "justified", \<slot\>, \<hex encoded stateRoot with 0x prefix\>.
    ///- Example: `"head".to_string()`
    #[validate(length(min = 1u64))]
    pub state_id: String,
}
///Response types for postStateValidators
#[derive(Debug, Clone)]
pub enum PostStateValidatorsResponse {
    ///200: Success
    Ok(GetStateValidatorsResponseResponse),
    ///400: Invalid state or validator ID, or status
    BadRequest(BlindedBlock400Response),
    ///404: State not found
    NotFound(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///Prepares the beacon node for potential proposers by supplying information
///required when proposing blocks for the given validators.  The information
///supplied for each validator index will persist through the epoch in which
///the call is submitted and for a further two epochs after that, or until the
///beacon node restarts.  It is expected that validator clients will send this
///information periodically, for example each epoch, to ensure beacon nodes have
///correct and timely fee recipient information.
///
///Note that there is no guarantee that the beacon node will use the supplied fee
///recipient when creating a block proposal, so on receipt of a proposed block the
///validator should confirm that it finds the fee recipient within the block
///acceptable before signing it.
///
///Also note that requests containing currently inactive or unknown validator
///indices will be accepted, as they may become active at a later epoch.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct PrepareBeaconProposerRequest {
    pub body: PrepareBeaconProposerRequestBody,
}
pub type PrepareBeaconProposerRequestBody = Vec<PrepareBeaconProposerRequestBodyItem>;
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct PrepareBeaconProposerRequestBodyItem {
    ///An address on the execution (Ethereum 1) network.
    #[validate(
        length(min = 1u64),
        regex(
            path = "REGEX_CAPELLA_SIGNED_BLS_TO_EXECUTION_CHANGE_MESSAGE_TO_EXECUTION_ADDRESS"
        )
    )]
    pub fee_recipient: String,
    #[validate(length(min = 1u64))]
    pub validator_index: String,
}
///Response types for prepareBeaconProposer
#[derive(Debug, Clone)]
pub enum PrepareBeaconProposerResponse {
    /**200: Preparation information has been received.
*/
    Ok,
    ///400: Invalid request syntax.
    BadRequest(PendingConsolidation400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///Subscribe to a number of sync committee subnets
///
///Sync committees are not present in phase0, but are required for Altair networks.
///
///Subscribing to sync committee subnets is an action performed by VC to enable network participation in Altair networks, and only required if the VC has an active validator in an active sync committee.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct PrepareSyncCommitteeSubnetsRequest {
    pub body: SyncCommitteeSubscriptionRequestBody,
}
#[bon::bon]
impl PrepareSyncCommitteeSubnetsRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(body: SyncCommitteeSubscriptionRequestBody) -> anyhow::Result<Self> {
        let request = Self { body };
        request.validate()?;
        Ok(request)
    }
}
///Requests that the beacon node produce an AttestationData. For `slot`s in
///Electra and later, this AttestationData must have a `committee_index` of 0.
///
///A 503 error must be returned if the block identified by the response
///`beacon_block_root` is optimistic (i.e. the attestation attests to a block
///that has not been fully verified by an execution engine).
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct ProduceAttestationDataRequest {
    #[validate(nested)]
    pub query: ProduceAttestationDataRequestQuery,
}
#[bon::bon]
impl ProduceAttestationDataRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(slot: String, committee_index: String) -> anyhow::Result<Self> {
        let request = Self {
            query: ProduceAttestationDataRequestQuery {
                slot,
                committee_index,
            },
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct ProduceAttestationDataRequestQuery {
    ///The slot for which an attestation data should be created.
    #[validate(length(min = 1u64))]
    pub slot: String,
    ///The committee index for which an attestation data should be created. For `slot`s in
    ///Electra and later, this parameter MAY always be set to 0.
    #[validate(length(min = 1u64))]
    pub committee_index: String,
}
///Response types for produceAttestationData
#[derive(Debug, Clone)]
pub enum ProduceAttestationDataResponse {
    ///200: Success response
    Ok(ProduceAttestationDataResponseResponse),
    ///200: Success response
    OkBinary(Vec<u8>),
    ///400: Invalid request syntax.
    BadRequest(PendingConsolidation400Response),
    ///406: Accepted media type is not supported.
    NotAcceptable(BlindedBlock406Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceAttestationDataResponseResponse {
    ///The [`AttestationData`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#attestationdata) object from the CL spec.
    pub data: Data,
}
///Requests a beacon node to produce a valid block, which can then be signed by a validator. The
///returned block may be blinded or unblinded, depending on the current state of the network as
///decided by the execution and beacon nodes.
///
///The beacon node must return an unblinded block if it obtains the execution payload from its
///paired execution node. It must only return a blinded block if it obtains the execution payload
///header from an MEV relay.
///
///Metadata in the response indicates the type of block produced, and the supported types of block
///will be added to as forks progress.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct ProduceBlockV3Request {
    #[validate(nested)]
    pub path: ProduceBlockV3RequestPath,
    #[validate(nested)]
    pub query: ProduceBlockV3RequestQuery,
}
#[bon::bon]
impl ProduceBlockV3Request {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        slot: String,
        randao_reveal: String,
        graffiti: Option<String>,
        skip_randao_verification: Option<String>,
        builder_boost_factor: Option<String>,
    ) -> anyhow::Result<Self> {
        let request = Self {
            path: ProduceBlockV3RequestPath { slot },
            query: ProduceBlockV3RequestQuery {
                randao_reveal,
                graffiti,
                skip_randao_verification,
                builder_boost_factor,
            },
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, validator::Validate, oas3_gen_support::Default)]
pub struct ProduceBlockV3RequestPath {
    ///The slot for which the block should be proposed.
    #[validate(length(min = 1u64))]
    pub slot: String,
}
#[serde_with::skip_serializing_none]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct ProduceBlockV3RequestQuery {
    ///The validator's randao reveal value.
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub randao_reveal: String,
    ///Arbitrary data validator wants to include in block.
    #[validate(
        regex(path = "REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT")
    )]
    pub graffiti: Option<String>,
    ///Skip verification of the `randao_reveal` value. If this flag is set then the
    ///`randao_reveal` must be set to the point at infinity (`0xc0..00`).
    #[validate(length(min = 0u64, max = 0u64))]
    pub skip_randao_verification: Option<String>,
    ///Percentage multiplier to apply to the builder's payload value when choosing between a
    ///builder payload header and payload from the paired execution node. This parameter is only
    ///relevant if the beacon node is connected to a builder, deems it safe to produce a builder
    ///payload, and receives valid responses from both the builder endpoint _and_ the paired
    ///execution node. When these preconditions are met, the server MUST act as follows:
    ///
    ///* if `exec_node_payload_value >= builder_boost_factor * (builder_payload_value // 100)`,
    ///  then return a full (unblinded) block containing the execution node payload.
    ///* otherwise, return a blinded block containing the builder payload header.
    ///
    ///Servers must support the following values of the boost factor which encode common
    ///preferences:
    ///
    ///* `builder_boost_factor=0`: prefer the local execution node payload unless an error makes it
    ///  unviable.
    ///* `builder_boost_factor=100`: profit maximization mode; choose whichever
    ///  payload pays more.
    ///* `builder_boost_factor=2**64 - 1`: prefer the external builder payload unless an error or
    ///  beacon node health check makes it unviable.
    ///
    ///Servers should use saturating arithmetic or another technique to ensure that large values of
    ///the `builder_boost_factor` do not trigger overflows or errors. If this parameter is
    ///provided and the beacon node is not configured with a builder then the beacon node MUST
    ///respond with a full block, which the caller can choose to reject if it wishes.
    ///If the value is provided but out of range for a 64-bit unsigned integer, then an error
    ///response with status code 400 MUST be returned.
    pub builder_boost_factor: Option<String>,
}
///Response types for produceBlockV3
#[derive(Debug, Clone)]
pub enum ProduceBlockV3Response {
    ///200: Success response
    Ok(ProduceBlockV3ResponseResponse),
    ///200: Success response
    OkBinary(Vec<u8>),
    ///400: Invalid block production request
    BadRequest(BlindedBlock400Response),
    ///406: Accepted media type is not supported.
    NotAcceptable(BlindedBlock406Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponse {
    pub consensus_block_value: String,
    pub data: ProduceBlockV3ResponseResponseData,
    pub execution_payload_blinded: bool,
    pub execution_payload_value: String,
    pub version: ConsensusVersion,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum ProduceBlockV3ResponseResponseData {
    ///The required object for block production according to the Fulu CL spec.
    #[default]
    Object(ProduceBlockV3ResponseResponseDataObject),
    ///The required object for block production according to the Electra CL spec.
    Object2(ProduceBlockV3ResponseResponseDataObject2),
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Electra spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    Variant2(ProduceBlockV3ResponseResponseDataVariant2),
    ///The required object for block production according to the Deneb CL spec.
    Object3(ProduceBlockV3ResponseResponseDataObject3),
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Deneb spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    Variant4(ProduceBlockV3ResponseResponseDataVariant4),
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Capella spec.
    Variant5(ProduceBlockV3ResponseResponseDataVariant5),
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Capella spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    Variant6(ProduceBlockV3ResponseResponseDataVariant6),
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Bellatrix spec.
    Variant7(ProduceBlockV3ResponseResponseDataVariant7),
    ///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Bellatrix spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
    Variant8(ProduceBlockV3ResponseResponseDataVariant8),
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Altair spec.
    Variant9(ProduceBlockV3ResponseResponseDataVariant9),
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL spec.
    Variant10(ProduceBlockV3ResponseResponseDataVariant10),
}
///The required object for block production according to the Fulu CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataObject {
    pub blobs: Vec<String>,
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Electra spec.
    pub block: serde_json::Value,
    ///Cell proofs of the blobs as defined in EIP-7594
    pub kzg_proofs: Vec<String>,
}
///The required object for block production according to the Electra CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataObject2 {
    pub blobs: Vec<String>,
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Electra spec.
    pub block: serde_json::Value,
    pub kzg_proofs: Vec<String>,
}
///The required object for block production according to the Deneb CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataObject3 {
    pub blobs: Vec<String>,
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Deneb spec.
    pub block: serde_json::Value,
    pub kzg_proofs: Vec<String>,
}
///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant10 {
    ///The [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblockbody) object from the CL spec.
    pub body: Phase0BeaconBlockBody,
    ///The signing merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Electra spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant2 {
    ///A variant of the [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/beacon-chain.md#beaconblockbody) object from the CL Electra spec, which contains a transactions root rather than a full transactions list.
    pub body: serde_json::Value,
    ///The signing Merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash Merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Deneb spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant4 {
    ///A variant of the [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/deneb/beacon-chain.md#beaconblockbody) object from the CL Deneb spec, which contains a transactions root rather than a full transactions list.
    pub body: serde_json::Value,
    ///The signing Merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash Merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Capella spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant5 {
    pub body: serde_json::Value,
    ///The signing Merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash Merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Capella spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant6 {
    ///A variant of the [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#beaconblockbody) object from the CL Capella spec, which contains a transactions root rather than a full transactions list.
    pub body: serde_json::Value,
    ///The signing Merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash Merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Bellatrix spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant7 {
    pub body: serde_json::Value,
    ///The signing Merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash Merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///A variant of the [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Bellatrix spec, which contains a `BlindedBeaconBlockBody` rather than a `BeaconBlockBody`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant8 {
    ///A variant of the [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/beacon-chain.md#beaconblockbody) object from the CL Bellatrix spec, which contains a transactions root rather than a full transactions list.
    pub body: serde_json::Value,
    ///The signing Merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash Merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Altair spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceBlockV3ResponseResponseDataVariant9 {
    ///The [`BeaconBlockBody`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#beaconblockbody) object from the CL Altair spec.
    pub body: AltairBeaconBlockBody,
    ///The signing Merkle root of the parent `BeaconBlock`.
    pub parent_root: String,
    ///Index of validator in validator registry.
    pub proposer_index: String,
    ///The slot to which this block corresponds.
    pub slot: String,
    ///The tree hash Merkle root of the `BeaconState` for the `BeaconBlock`.
    pub state_root: String,
}
///Requests that the beacon node produce a sync committee contribution.
///
///A 503 error must be returned if the block identified by the response
///`beacon_block_root` is optimistic (i.e. the sync committee contribution
///refers to a block that has not been fully verified by an execution engine).
///
///A 404 error must be returned if no sync committee contribution is available
///for the requested `beacon_block_root`.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct ProduceSyncCommitteeContributionRequest {
    #[validate(nested)]
    pub query: ProduceSyncCommitteeContributionRequestQuery,
}
#[bon::bon]
impl ProduceSyncCommitteeContributionRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        slot: String,
        subcommittee_index: String,
        beacon_block_root: String,
    ) -> anyhow::Result<Self> {
        let request = Self {
            query: ProduceSyncCommitteeContributionRequestQuery {
                slot,
                subcommittee_index,
                beacon_block_root,
            },
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct ProduceSyncCommitteeContributionRequestQuery {
    ///The slot for which a sync committee contribution should be created.
    #[validate(length(min = 1u64))]
    pub slot: String,
    ///the subcommittee index for which to produce the contribution.
    #[validate(length(min = 1u64))]
    pub subcommittee_index: String,
    ///the block root for which to produce the contribution.
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT")
    )]
    pub beacon_block_root: String,
}
///Response types for produceSyncCommitteeContribution
#[derive(Debug, Clone)]
pub enum ProduceSyncCommitteeContributionResponse {
    ///200: Success response
    Ok(ProduceSyncCommitteeContributionResponseResponse),
    ///400: Invalid request syntax.
    BadRequest(PendingConsolidation400Response),
    ///404: Not found
    NotFound(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ProduceSyncCommitteeContributionResponseResponse {
    pub data: Contribution,
}
///Verifies given aggregate and proofs and publishes them on appropriate gossipsub topic.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct PublishAggregateAndProofsV2Request {
    pub header: PublishAggregateAndProofsV2RequestHeader,
    pub body: AggregateAndProofRequestBody,
}
#[derive(Debug, Clone, PartialEq, oas3_gen_support::Default)]
pub struct PublishAggregateAndProofsV2RequestHeader {
    ///The active consensus version to which the aggregate and proofs being submitted belong.
    pub eth_consensus_version: ConsensusVersion,
}
///Instructs the beacon node to use the components of the `SignedBlindedBeaconBlock` to construct and publish a
///`SignedBeaconBlock` by swapping out the `transactions_root` for the corresponding full list of `transactions`.
///The beacon node should broadcast a newly constructed `SignedBeaconBlock` to the beacon network,
///to be included in the beacon chain. The beacon node is not required to validate the signed
///`BeaconBlock`, and a successful response (20X) only indicates that the broadcast has been
///successful. The beacon node is expected to integrate the new block into its state, and
///therefore validate the block internally, however blocks which fail the validation are still
///broadcast but a different status code is returned (202). Before Bellatrix, this endpoint will accept
///a `SignedBeaconBlock`. The broadcast behaviour may be adjusted via the `broadcast_validation`
///query parameter.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct PublishBlindedBlockV2Request {
    pub query: PublishBlindedBlockV2RequestQuery,
    pub header: PublishBlindedBlockV2RequestHeader,
    ///The `SignedBlindedBeaconBlock` object composed of `BlindedBeaconBlock` object (produced by beacon node) and validator signature.
    pub body: GetBlindedBlockResponseResponseData,
}
#[bon::bon]
impl PublishBlindedBlockV2Request {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        broadcast_validation: Option<BroadcastValidation>,
        eth_consensus_version: ConsensusVersion,
        body: GetBlindedBlockResponseResponseData,
    ) -> anyhow::Result<Self> {
        let request = Self {
            query: PublishBlindedBlockV2RequestQuery {
                broadcast_validation,
            },
            header: PublishBlindedBlockV2RequestHeader {
                eth_consensus_version,
            },
            body,
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, oas3_gen_support::Default)]
pub struct PublishBlindedBlockV2RequestHeader {
    ///The active consensus version to which the block being submitted belongs.
    pub eth_consensus_version: ConsensusVersion,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, oas3_gen_support::Default)]
pub struct PublishBlindedBlockV2RequestQuery {
    ///Level of validation that must be applied to a block before it is broadcast.
    ///
    ///Possible values:
    ///- **`gossip`** (default): lightweight gossip checks only
    ///- **`consensus`**: full consensus checks, including validation of all signatures and
    ///  blocks fields _except_ for the execution payload transactions.
    ///- **`consensus_and_equivocation`**: the same as `consensus`, with an extra equivocation
    ///  check immediately before the block is broadcast. If the block is found to be an
    ///  equivocation it fails validation.
    ///
    ///If the block fails the requested level of a validation a 400 status MUST be returned
    ///immediately and the block MUST NOT be broadcast to the network.
    ///
    ///If validation succeeds, the block must still be fully verified before it is
    ///incorporated into the state and a 20x status is returned to the caller.
    pub broadcast_validation: Option<BroadcastValidation>,
}
///Instructs the beacon node to broadcast a newly signed beacon block to the beacon network,
///to be included in the beacon chain. A success response (20x) indicates that the block
///passed gossip validation and was successfully broadcast onto the network.
///The beacon node is also expected to integrate the block into the state, but may broadcast it
///before doing so, so as to aid timely delivery of the block. Should the block fail full
///validation, a separate success response code (202) is used to indicate that the block was
///successfully broadcast but failed integration. After Deneb, this additionally instructs
///the beacon node to broadcast all given blobs. The broadcast behaviour may be adjusted via the
///`broadcast_validation` query parameter.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct PublishBlockV2Request {
    pub query: PublishBlockV2RequestQuery,
    pub header: PublishBlockV2RequestHeader,
    ///The `SignedBeaconBlock` object composed of `BeaconBlock` object (produced by beacon node) and validator signature.
    pub body: BlockRequestBody,
}
#[bon::bon]
impl PublishBlockV2Request {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        broadcast_validation: Option<BroadcastValidation>,
        eth_consensus_version: ConsensusVersion,
        body: BlockRequestBody,
    ) -> anyhow::Result<Self> {
        let request = Self {
            query: PublishBlockV2RequestQuery {
                broadcast_validation,
            },
            header: PublishBlockV2RequestHeader {
                eth_consensus_version,
            },
            body,
        };
        request.validate()?;
        Ok(request)
    }
}
#[derive(Debug, Clone, PartialEq, oas3_gen_support::Default)]
pub struct PublishBlockV2RequestHeader {
    ///The active consensus version to which the block being submitted belongs.
    pub eth_consensus_version: ConsensusVersion,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, oas3_gen_support::Default)]
pub struct PublishBlockV2RequestQuery {
    ///Level of validation that must be applied to a block before it is broadcast.
    ///
    ///Possible values:
    ///- **`gossip`** (default): lightweight gossip checks only
    ///- **`consensus`**: full consensus checks, including validation of all signatures and
    ///  blocks fields _except_ for the execution payload transactions.
    ///- **`consensus_and_equivocation`**: the same as `consensus`, with an extra equivocation
    ///  check immediately before the block is broadcast. If the block is found to be an
    ///  equivocation it fails validation.
    ///
    ///If the block fails the requested level of a validation a 400 status MUST be returned
    ///immediately and the block MUST NOT be broadcast to the network.
    ///
    ///If validation succeeds, the block must still be fully verified before it is
    ///incorporated into the state and a 20x status is returned to the caller.
    pub broadcast_validation: Option<BroadcastValidation>,
}
///Response types for publishBlockV2
#[derive(Debug, Clone)]
pub enum PublishBlockV2Response {
    ///200: The block was validated successfully and has been broadcast. It has also been integrated into the beacon node's database.
    Ok,
    ///202: The block could not be integrated into the beacon node's database as it failed validation, but was successfully broadcast.
    Accepted,
    ///400: The `SignedBeaconBlock` object is invalid or broadcast validation failed
    BadRequest(BlindedBlock400Response),
    ///415: Supplied content-type is not supported.
    UnsupportedMediaType(RegisterValidator415Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///Publish multiple signed sync committee contribution and proofs
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct PublishContributionAndProofsRequest {
    pub body: ContributionAndProofRequestBody,
}
#[bon::bon]
impl PublishContributionAndProofsRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(body: ContributionAndProofRequestBody) -> anyhow::Result<Self> {
        let request = Self { body };
        request.validate()?;
        Ok(request)
    }
}
///Response types for publishContributionAndProofs
#[derive(Debug, Clone)]
pub enum PublishContributionAndProofsResponse {
    ///200: Successful response
    Ok,
    ///400: Errors with one or more contribution and proofs
    BadRequest(BlsToExecutionChange400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct RegisterValidator415Response {
    ///The media type in "Content-Type" header is unsupported, and the request has been rejected. This occurs when a HTTP request supplies a payload in a content-type that the server is not able to handle.
    pub code: f64,
    ///Message describing error
    pub message: String,
    ///Optional stacktraces, sent when node is in debug mode
    pub stacktraces: Option<Vec<String>>,
}
///Prepares the beacon node for engaging with external builders. The
///information must be sent by the beacon node to the builder network. It is
///expected that the validator client will send this information periodically
///to ensure the beacon node has correct and timely registration information
///to provide to builders.
///
///Note that only registrations for active or pending validators must be sent to the builder network.
///Registrations for unknown or exited validators must be filtered out and not sent to the builder network.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct RegisterValidatorRequest {
    pub body: RegisterValidatorRequestBody,
}
#[bon::bon]
impl RegisterValidatorRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(body: RegisterValidatorRequestBody) -> anyhow::Result<Self> {
        let request = Self { body };
        request.validate()?;
        Ok(request)
    }
}
pub type RegisterValidatorRequestBody = Vec<RegisterValidatorRequestBodyItem>;
///The `SignedValidatorRegistration` object from the Builder API specification.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct RegisterValidatorRequestBodyItem {
    ///The `ValidatorRegistration` object from the Builder API specification.
    #[validate(nested)]
    pub message: SignedValidatorRegistrationMessage,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///Response types for registerValidator
#[derive(Debug, Clone)]
pub enum RegisterValidatorResponse {
    ///200: Registration information has been received.
    Ok,
    ///400: Invalid request syntax.
    BadRequest(PendingConsolidation400Response),
    ///415: Supplied content-type is not supported.
    UnsupportedMediaType(RegisterValidator415Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///The [`SignedBeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#signedbeaconblock) object envelope from the CL Electra spec.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct SignedBlockContentsSignedBlock {
    ///The [`BeaconBlock`](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md#beaconblock) object from the CL Electra spec.
    pub message: serde_json::Value,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
}
///The `ValidatorRegistration` object from the Builder API specification.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct SignedValidatorRegistrationMessage {
    ///An address on the execution (Ethereum 1) network.
    #[validate(
        length(min = 1u64),
        regex(
            path = "REGEX_CAPELLA_SIGNED_BLS_TO_EXECUTION_CHANGE_MESSAGE_TO_EXECUTION_ADDRESS"
        )
    )]
    pub fee_recipient: String,
    ///Preferred gas limit of validator.
    #[validate(length(min = 1u64))]
    pub gas_limit: String,
    ///The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    #[validate(
        length(min = 1u64),
        regex(
            path = "REGEX_CAPELLA_SIGNED_BLS_TO_EXECUTION_CHANGE_MESSAGE_FROM_BLS_PUBKEY"
        )
    )]
    pub pubkey: String,
    ///Unix timestamp of registration.
    #[validate(length(min = 1u64))]
    pub timestamp: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, oas3_gen_support::Default)]
#[serde(untagged)]
pub enum StatusKind {
    ///Possible statuses:
    ///- **pending_initialized** - When the first deposit is processed, but not enough funds are available (or not yet the end of the first epoch) to get validator into the activation queue.
    ///- **pending_queued** - When validator is waiting to get activated, and have enough funds etc. while in the queue, validator activation epoch keeps changing until it gets to the front and make it through (finalization is a requirement here too).
    ///- **active_ongoing** - When validator must be attesting, and have not initiated any exit.
    ///- **active_exiting** - When validator is still active, but filed a voluntary request to exit.
    ///- **active_slashed** - When validator is still active, but have a slashed status and is scheduled to exit.
    ///- **exited_unslashed** - When validator has reached regular exit epoch, not being slashed, and doesn't have to attest any more, but cannot withdraw yet.
    ///- **exited_slashed** - When validator has reached regular exit epoch, but was slashed, have to wait for a longer withdrawal period.
    ///- **withdrawal_possible** - After validator has exited, a while later is permitted to move funds, and is truly out of the system.
    ///- **withdrawal_done** - (not possible in phase0, except slashing full balance) - actually having moved funds away
    ///
    ///[Validator status specification](https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ)
    #[default]
    Enum(serde_json::Value),
    Enum2(serde_json::Value),
}
///This endpoint should be used by a validator client running as part of a distributed validator cluster, and is
///implemented by a distributed validator middleware client. This endpoint is used to exchange partial
///selection proofs for combined/aggregated selection proofs to allow a validator client
///to correctly determine if any of its validators has been selected to perform an attestation aggregation duty in a slot.
///Validator clients running in a distributed validator cluster must query this endpoint at the start of an epoch for the current and lookahead (next) epochs for
///all validators that have attester duties in the current and lookahead epochs. Consensus clients need not support this
///endpoint and may return a 501.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct SubmitBeaconCommitteeSelectionsRequest {
    pub body: BeaconCommitteeSelectionRequestRequestBody,
}
#[bon::bon]
impl SubmitBeaconCommitteeSelectionsRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(
        body: BeaconCommitteeSelectionRequestRequestBody,
    ) -> anyhow::Result<Self> {
        let request = Self { body };
        request.validate()?;
        Ok(request)
    }
}
///Response types for submitBeaconCommitteeSelections
#[derive(Debug, Clone)]
pub enum SubmitBeaconCommitteeSelectionsResponse {
    /**200: Returns the threshold aggregated beacon committee selection proofs.
*/
    Ok(BeaconCommitteeSelectionResponseResponse),
    ///400: Invalid request syntax.
    BadRequest(PendingConsolidation400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///501: Endpoint not implemented.
    NotImplemented(BeaconCommitteeSelection501Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///Submits attestations to the node. Each attestation in the request body is processed individually.
///
///If an attestation is validated successfully, the node MUST publish that attestation on the appropriate subnet.
///
///If one or more attestations fail validation, the node MUST return a 400 error with details of which attestations have failed, and why.
///
///Prior to the Electra hard fork, this endpoint MUST be sent Attestation objects only.  At and after the Electra hard fork, this endpoint MUST be sent SingleAttestation objects only.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct SubmitPoolAttestationsV2Request {
    pub header: SubmitPoolAttestationsV2RequestHeader,
    pub body: AttestationRequestBody2,
}
#[derive(Debug, Clone, PartialEq, oas3_gen_support::Default)]
pub struct SubmitPoolAttestationsV2RequestHeader {
    ///The consensus version to which the attestations being submitted belong.
    pub eth_consensus_version: ConsensusVersion,
}
///Response types for submitPoolAttestationsV2
#[derive(Debug, Clone)]
pub enum SubmitPoolAttestationsV2Response {
    ///200: Attestations are stored in pool and broadcast on the appropriate subnet
    Ok,
    ///400: Errors with one or more attestations
    BadRequest(BlsToExecutionChange400Response),
    ///415: Supplied content-type is not supported.
    UnsupportedMediaType(RegisterValidator415Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///Submits sync committee signature objects to the node.
///
///Sync committee signatures are not present in phase0, but are required for Altair networks.
///
///If a sync committee signature is validated successfully the node MUST publish that sync committee signature on all applicable subnets.
///
///If one or more sync committee signatures fail validation the node MUST return a 400 error with details of which sync committee signatures have failed, and why.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct SubmitPoolSyncCommitteeSignaturesRequest {
    pub body: SyncCommitteeRequestBody,
}
#[bon::bon]
impl SubmitPoolSyncCommitteeSignaturesRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(body: SyncCommitteeRequestBody) -> anyhow::Result<Self> {
        let request = Self { body };
        request.validate()?;
        Ok(request)
    }
}
///Submits SignedVoluntaryExit object to node's pool and if passes validation node MUST broadcast it to network.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct SubmitPoolVoluntaryExitRequest {
    #[validate(nested)]
    pub body: GetPoolVoluntaryExitsResponseResponseDatum,
}
///Response types for submitPoolVoluntaryExit
#[derive(Debug, Clone)]
pub enum SubmitPoolVoluntaryExitResponse {
    ///200: Voluntary exit is stored in node and broadcasted to network
    Ok,
    ///400: Invalid voluntary exit
    BadRequest(BlindedBlock400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///Submit sync committee selections to a DVT middleware client. It returns the threshold aggregated sync
///committee selection. This endpoint should be used by a validator client running as part of a distributed
///validator cluster, and is implemented by a distributed validator middleware client. This endpoint is
///used to exchange partial selection proofs (slot signatures) for combined/aggregated selection proofs to
///allow a validator client to correctly determine if any of its validators has been selected to perform a
///sync committee contribution (sync aggregation) duty in a slot. Validator clients running in a distributed validator cluster must query this endpoint
///at the start of each slot for all validators that are included in the current sync committee. Consensus
///clients need not support this endpoint and may return a 501.
#[derive(Debug, Clone, validator::Validate, oas3_gen_support::Default)]
pub struct SubmitSyncCommitteeSelectionsRequest {
    pub body: SyncCommitteeSelectionRequestRequestBody,
}
#[bon::bon]
impl SubmitSyncCommitteeSelectionsRequest {
    ///Create a new request with the given parameters.
    #[builder]
    pub fn new(body: SyncCommitteeSelectionRequestRequestBody) -> anyhow::Result<Self> {
        let request = Self { body };
        request.validate()?;
        Ok(request)
    }
}
///Response types for submitSyncCommitteeSelections
#[derive(Debug, Clone)]
pub enum SubmitSyncCommitteeSelectionsResponse {
    /**200: Returns the threshold aggregated sync committee selection proofs.
*/
    Ok(SyncCommitteeSelectionResponseResponse),
    ///400: Invalid request syntax.
    BadRequest(PendingConsolidation400Response),
    ///500: Beacon node internal error.
    InternalServerError(BlindedBlock400Response),
    ///501: Endpoint not implemented.
    NotImplemented(BeaconCommitteeSelection501Response),
    ///503: Beacon node is currently syncing, try again later.
    ServiceUnavailable(BlindedBlock400Response),
    ///default: Unknown response
    Unknown,
}
///The [`SyncAggregate`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/altair/beacon-chain.md#syncaggregate) object from the CL Altair spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct SyncAggregate {
    ///Aggregation bits of sync
    pub sync_committee_bits: String,
    pub sync_committee_signature: String,
}
pub type SyncCommitteeRequestBody = Vec<SyncCommitteeRequestBodyItem>;
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct SyncCommitteeRequestBodyItem {
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_ALTAIR_BEACON_STATE_CURRENT_JUSTIFIED_CHECKPOINT_ROOT")
    )]
    pub beacon_block_root: String,
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub signature: String,
    #[validate(length(min = 1u64))]
    pub slot: String,
    #[validate(length(min = 1u64))]
    pub validator_index: String,
}
pub type SyncCommitteeSelectionRequestRequestBody = Vec<
    SyncCommitteeSelectionRequestRequestBodyItem,
>;
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct SyncCommitteeSelectionRequestRequestBodyItem {
    ///The `slot_signature` calculated by the validator for the upcoming sync committee slot
    #[validate(
        length(min = 1u64),
        regex(path = "REGEX_AGGREGATE_AND_PROOF_REQUEST_BODY_ARRAY_SIGNATURE")
    )]
    pub selection_proof: String,
    ///The slot at which validator is assigned to produce a sync committee contribution
    #[validate(length(min = 1u64))]
    pub slot: String,
    ///SubcommitteeIndex to which the validator is assigned
    #[validate(length(min = 1u64))]
    pub subcommittee_index: String,
    ///Index of the validator
    #[validate(length(min = 1u64))]
    pub validator_index: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct SyncCommitteeSelectionResponseResponse {
    pub data: Vec<SyncCommitteeSelectionRequestRequestBodyItem>,
}
pub type SyncCommitteeSubscriptionRequestBody = Vec<
    SyncCommitteeSubscriptionRequestBodyItem,
>;
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    validator::Validate,
    oas3_gen_support::Default
)]
pub struct SyncCommitteeSubscriptionRequestBodyItem {
    pub sync_committee_indices: Vec<String>,
    ///The final epoch (exclusive value) that the specified validator requires the subscription for.
    #[validate(length(min = 1u64))]
    pub until_epoch: String,
    #[validate(length(min = 1u64))]
    pub validator_index: String,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, oas3_gen_support::Default)]
pub struct ValidatorRequestBody {
    ///An array of values, with each value either a hex encoded public key (any bytes48 with 0x prefix) or a validator index.
    ///
    ///If the supplied list is empty (i.e. the value is `[]`) or the property is omitted then all validators will be returned.
    pub ids: Option<Vec<String>>,
    ///An array of validator statuses to filter on.
    ///
    ///If the supplied list is empty (i.e. the value is `[]`) or the property is omitted then validators with all statuses will be returned.
    pub statuses: Option<Vec<StatusKind>>,
}
///The [`Validator`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#validator) object from the CL spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, oas3_gen_support::Default)]
pub struct ValidatorResponseValidator {
    ///When criteria for activation were met.
    pub activation_eligibility_epoch: String,
    ///Epoch when validator activated. 'FAR_FUTURE_EPOCH' if not activated
    pub activation_epoch: String,
    ///Balance at stake in Gwei.
    pub effective_balance: String,
    ///Epoch when validator exited. 'FAR_FUTURE_EPOCH' if not exited.
    pub exit_epoch: String,
    ///The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub pubkey: String,
    ///Was validator slashed (not longer active).
    pub slashed: bool,
    ///When validator can withdraw or transfer funds. 'FAR_FUTURE_EPOCH' if not defined
    pub withdrawable_epoch: String,
    ///Root of withdrawal credentials
    pub withdrawal_credentials: String,
}
///Possible statuses:
///- **pending_initialized** - When the first deposit is processed, but not enough funds are available (or not yet the end of the first epoch) to get validator into the activation queue.
///- **pending_queued** - When validator is waiting to get activated, and have enough funds etc. while in the queue, validator activation epoch keeps changing until it gets to the front and make it through (finalization is a requirement here too).
///- **active_ongoing** - When validator must be attesting, and have not initiated any exit.
///- **active_exiting** - When validator is still active, but filed a voluntary request to exit.
///- **active_slashed** - When validator is still active, but have a slashed status and is scheduled to exit.
///- **exited_unslashed** - When validator has reached regular exit epoch, not being slashed, and doesn't have to attest any more, but cannot withdraw yet.
///- **exited_slashed** - When validator has reached regular exit epoch, but was slashed, have to wait for a longer withdrawal period.
///- **withdrawal_possible** - After validator has exited, a while later is permitted to move funds, and is truly out of the system.
///- **withdrawal_done** - (not possible in phase0, except slashing full balance) - actually having moved funds away
///
///[Validator status specification](https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, oas3_gen_support::Default)]
pub enum ValidatorStatus {
    #[serde(rename = "pending_initialized")]
    #[default]
    PendingInitialized,
    #[serde(rename = "pending_queued")]
    PendingQueued,
    #[serde(rename = "active_ongoing")]
    ActiveOngoing,
    #[serde(rename = "active_exiting")]
    ActiveExiting,
    #[serde(rename = "active_slashed")]
    ActiveSlashed,
    #[serde(rename = "exited_unslashed")]
    ExitedUnslashed,
    #[serde(rename = "exited_slashed")]
    ExitedSlashed,
    #[serde(rename = "withdrawal_possible")]
    WithdrawalPossible,
    #[serde(rename = "withdrawal_done")]
    WithdrawalDone,
}
impl core::fmt::Display for ValidatorStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PendingInitialized => write!(f, "pending_initialized"),
            Self::PendingQueued => write!(f, "pending_queued"),
            Self::ActiveOngoing => write!(f, "active_ongoing"),
            Self::ActiveExiting => write!(f, "active_exiting"),
            Self::ActiveSlashed => write!(f, "active_slashed"),
            Self::ExitedUnslashed => write!(f, "exited_unslashed"),
            Self::ExitedSlashed => write!(f, "exited_slashed"),
            Self::WithdrawalPossible => write!(f, "withdrawal_possible"),
            Self::WithdrawalDone => write!(f, "withdrawal_done"),
        }
    }
}
