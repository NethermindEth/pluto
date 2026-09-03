//! Client-level types of the Beacon API: request options, response envelopes
//! that carry metadata alongside `data`, error bodies and string enums.
//!
//! Values follow the API's JSON conventions: integers are quoted decimal
//! strings and byte values are `0x`-prefixed hex strings.

use std::{collections::HashMap, fmt};

use pluto_ssz::serde_utils::Hex0x;
use reqwest::{StatusCode, header::HeaderName};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_with::{DisplayFromStr, serde_as};

use crate::{
    spec::{
        DataVersion,
        phase0::{BLSPubKey, BLSSignature, DomainType, Epoch, Root, Slot, ValidatorIndex, Version},
    },
    v1, versioned,
};

/// Header carrying the consensus version of a request or response body.
pub const ETH_CONSENSUS_VERSION: HeaderName = HeaderName::from_static("eth-consensus-version");

/// A beacon node answered with a non-2xx status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("beacon node returned {status}: {}", body.message)]
pub struct HttpError {
    /// Status of the response.
    pub status: StatusCode,
    /// Decoded body, or the raw text as `message` when it is not JSON.
    pub body: ErrorBody,
}

impl HttpError {
    /// Returns the HTTP error behind `error`, if that is what it wraps.
    pub fn from_error(error: &anyhow::Error) -> Option<&HttpError> {
        error.downcast_ref()
    }
}

/// Body of a non-2xx response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Status code repeated in the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u64>,
    /// Human-readable description.
    #[serde(default)]
    pub message: String,
    /// Stack traces, when the node includes them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stacktraces: Vec<String>,
    /// Per-item failures of a batch submission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<IndexedFailure>,
}

/// Failure of one item of a batch submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedFailure {
    /// Position of the item in the submitted array.
    pub index: u64,
    /// Human-readable description.
    pub message: String,
}

/// Validation a beacon node performs before broadcasting a published block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastValidation {
    /// Gossip validation only.
    Gossip,
    /// Full consensus validation.
    Consensus,
    /// Full consensus validation plus equivocation checks.
    ConsensusAndEquivocation,
}

impl BroadcastValidation {
    /// Returns the query parameter value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gossip => "gossip",
            Self::Consensus => "consensus",
            Self::ConsensusAndEquivocation => "consensus_and_equivocation",
        }
    }
}

impl fmt::Display for BroadcastValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Topic of the beacon node event stream (`GET /eth/v1/events`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventTopic {
    /// New chain head.
    Head,
    /// New imported block.
    Block,
    /// Block received over gossip.
    BlockGossip,
    /// New attestation in the pool.
    Attestation,
    /// New single attestation in the pool.
    SingleAttestation,
    /// New voluntary exit in the pool.
    VoluntaryExit,
    /// New BLS to execution change in the pool.
    BlsToExecutionChange,
    /// New proposer slashing in the pool.
    ProposerSlashing,
    /// New attester slashing in the pool.
    AttesterSlashing,
    /// New finalized checkpoint.
    FinalizedCheckpoint,
    /// Chain reorganisation.
    ChainReorg,
    /// New sync committee contribution and proof.
    ContributionAndProof,
    /// Light client finality update.
    LightClientFinalityUpdate,
    /// Light client optimistic update.
    LightClientOptimisticUpdate,
    /// Payload attributes for the next slot.
    PayloadAttributes,
    /// New blob sidecar.
    BlobSidecar,
    /// New data column sidecar.
    DataColumnSidecar,
}

impl EventTopic {
    /// Returns the topic name used in the query string and SSE `event` field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Block => "block",
            Self::BlockGossip => "block_gossip",
            Self::Attestation => "attestation",
            Self::SingleAttestation => "single_attestation",
            Self::VoluntaryExit => "voluntary_exit",
            Self::BlsToExecutionChange => "bls_to_execution_change",
            Self::ProposerSlashing => "proposer_slashing",
            Self::AttesterSlashing => "attester_slashing",
            Self::FinalizedCheckpoint => "finalized_checkpoint",
            Self::ChainReorg => "chain_reorg",
            Self::ContributionAndProof => "contribution_and_proof",
            Self::LightClientFinalityUpdate => "light_client_finality_update",
            Self::LightClientOptimisticUpdate => "light_client_optimistic_update",
            Self::PayloadAttributes => "payload_attributes",
            Self::BlobSidecar => "blob_sidecar",
            Self::DataColumnSidecar => "data_column_sidecar",
        }
    }
}

impl fmt::Display for EventTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Inputs of `GET /eth/v3/validator/blocks/{slot}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProduceBlockOpts {
    /// Slot to build the block for.
    pub slot: Slot,
    /// RANDAO reveal signature for the slot.
    pub randao_reveal: BLSSignature,
    /// Graffiti to embed in the block body.
    pub graffiti: Option<Root>,
    /// Asks the node not to verify the RANDAO reveal, which must then be the
    /// point at infinity.
    pub skip_randao_verification: bool,
    /// Relative weight of a builder payload against a local one.
    pub builder_boost_factor: Option<u64>,
}

/// A validator, addressed by index or public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorId {
    /// Registry index.
    Index(ValidatorIndex),
    /// BLS public key.
    PubKey(BLSPubKey),
}

impl Serialize for ValidatorId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Index(index) => serializer.collect_str(index),
            Self::PubKey(pubkey) => serializer.serialize_str(&pluto_ssz::to_0x_hex(pubkey)),
        }
    }
}

impl<'de> Deserialize<'de> for ValidatorId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if let Some(hex) = pluto_ssz::serde_utils::strip_0x_prefix(&value) {
            let bytes = hex::decode(hex).map_err(D::Error::custom)?;
            let pubkey = bytes
                .try_into()
                .map_err(|_| D::Error::custom("public key must be 48 bytes"))?;
            return Ok(Self::PubKey(pubkey));
        }
        value.parse().map(Self::Index).map_err(D::Error::custom)
    }
}

/// Body of `POST /eth/v1/beacon/states/{state_id}/validators`. Empty lists
/// leave the corresponding filter out, matching every validator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorsFilter {
    /// Validators to return.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<ValidatorId>,
    /// Statuses to return.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<v1::ValidatorStatus>,
}

/// Chain configuration as served by `GET /eth/v1/config/spec`, narrowed to the
/// values Pluto reads. Keys the node serves beyond these are ignored.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct Spec {
    /// Seconds per slot.
    #[serde_as(as = "DisplayFromStr")]
    pub seconds_per_slot: u64,
    /// Slots per epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub slots_per_epoch: u64,

    /// Altair fork version.
    #[serde_as(as = "Hex0x")]
    pub altair_fork_version: Version,
    /// Altair activation epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub altair_fork_epoch: Epoch,
    /// Bellatrix fork version.
    #[serde_as(as = "Hex0x")]
    pub bellatrix_fork_version: Version,
    /// Bellatrix activation epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub bellatrix_fork_epoch: Epoch,
    /// Capella fork version.
    #[serde_as(as = "Hex0x")]
    pub capella_fork_version: Version,
    /// Capella activation epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub capella_fork_epoch: Epoch,
    /// Deneb fork version.
    #[serde_as(as = "Hex0x")]
    pub deneb_fork_version: Version,
    /// Deneb activation epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub deneb_fork_epoch: Epoch,
    /// Electra fork version.
    #[serde_as(as = "Hex0x")]
    pub electra_fork_version: Version,
    /// Electra activation epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub electra_fork_epoch: Epoch,
    /// Fulu fork version.
    #[serde_as(as = "Hex0x")]
    pub fulu_fork_version: Version,
    /// Fulu activation epoch.
    #[serde_as(as = "DisplayFromStr")]
    pub fulu_fork_epoch: Epoch,

    /// Target number of aggregators per beacon committee.
    #[serde_as(as = "DisplayFromStr")]
    pub target_aggregators_per_committee: u64,
    /// Sync committee size.
    #[serde_as(as = "DisplayFromStr")]
    pub sync_committee_size: u64,
    /// Number of sync committee subnets.
    #[serde_as(as = "DisplayFromStr")]
    pub sync_committee_subnet_count: u64,
    /// Target number of aggregators per sync subcommittee.
    #[serde_as(as = "DisplayFromStr")]
    pub target_aggregators_per_sync_subcommittee: u64,

    /// Domain type for block proposals.
    #[serde_as(as = "Hex0x")]
    pub domain_beacon_proposer: DomainType,
    /// Domain type for attestations.
    #[serde_as(as = "Hex0x")]
    pub domain_beacon_attester: DomainType,
    /// Domain type for RANDAO reveals.
    #[serde_as(as = "Hex0x")]
    pub domain_randao: DomainType,
    /// Domain type for deposits.
    #[serde_as(as = "Hex0x")]
    pub domain_deposit: DomainType,
    /// Domain type for voluntary exits.
    #[serde_as(as = "Hex0x")]
    pub domain_voluntary_exit: DomainType,
    /// Domain type for aggregator selection proofs.
    #[serde_as(as = "Hex0x")]
    pub domain_selection_proof: DomainType,
    /// Domain type for aggregate and proof messages.
    #[serde_as(as = "Hex0x")]
    pub domain_aggregate_and_proof: DomainType,
    /// Domain type for sync committee messages.
    #[serde_as(as = "Hex0x")]
    pub domain_sync_committee: DomainType,
    /// Domain type for sync committee selection proofs.
    #[serde_as(as = "Hex0x")]
    pub domain_sync_committee_selection_proof: DomainType,
    /// Domain type for sync committee contribution and proof messages.
    #[serde_as(as = "Hex0x")]
    pub domain_contribution_and_proof: DomainType,
    /// Domain type for builder registrations. Defaults to the builder-specs
    /// constant when the node omits it, as go-eth2-client does.
    #[serde_as(as = "Hex0x")]
    #[serde(default = "application_builder_domain_type")]
    pub domain_application_builder: DomainType,
}

const fn application_builder_domain_type() -> DomainType {
    [0x00, 0x00, 0x00, 0x01]
}

/// Fork version and activation epoch of one fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSchedule {
    /// The fork version.
    pub version: Version,
    /// The epoch at which the fork activates.
    pub epoch: Epoch,
}

impl Spec {
    /// Returns the version and activation epoch of every fork after phase0.
    pub fn fork_schedule(&self) -> HashMap<DataVersion, ForkSchedule> {
        let fork = |version, epoch| ForkSchedule { version, epoch };
        HashMap::from([
            (
                DataVersion::Altair,
                fork(self.altair_fork_version, self.altair_fork_epoch),
            ),
            (
                DataVersion::Bellatrix,
                fork(self.bellatrix_fork_version, self.bellatrix_fork_epoch),
            ),
            (
                DataVersion::Capella,
                fork(self.capella_fork_version, self.capella_fork_epoch),
            ),
            (
                DataVersion::Deneb,
                fork(self.deneb_fork_version, self.deneb_fork_epoch),
            ),
            (
                DataVersion::Electra,
                fork(self.electra_fork_version, self.electra_fork_epoch),
            ),
            (
                DataVersion::Fulu,
                fork(self.fulu_fork_version, self.fulu_fork_epoch),
            ),
        ])
    }
}

/// Response of `POST /eth/v1/validator/duties/attester/{epoch}`.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttesterDutiesResponse {
    /// Root of the block the duties depend on.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub dependent_root: Root,
    /// Whether the node's head is optimistically imported.
    #[serde(default)]
    pub execution_optimistic: bool,
    /// The duties.
    pub data: Vec<v1::AttesterDuty>,
}

/// Response of `GET /eth/v1/validator/duties/proposer/{epoch}`.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerDutiesResponse {
    /// Root of the block the duties depend on.
    #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
    pub dependent_root: Root,
    /// Whether the node's head is optimistically imported.
    #[serde(default)]
    pub execution_optimistic: bool,
    /// The duties.
    pub data: Vec<v1::ProposerDuty>,
}

/// Response of `POST /eth/v1/validator/duties/sync/{epoch}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeDutiesResponse {
    /// Whether the node's head is optimistically imported.
    #[serde(default)]
    pub execution_optimistic: bool,
    /// The duties.
    pub data: Vec<v1::SyncCommitteeDuty>,
}

/// Response of `POST /eth/v1/beacon/states/{state_id}/validators`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorsResponse {
    /// Whether the state is optimistically imported.
    #[serde(default)]
    pub execution_optimistic: bool,
    /// Whether the state is finalized.
    #[serde(default)]
    pub finalized: bool,
    /// The validators.
    pub data: Vec<v1::Validator>,
}

/// Response of `GET /eth/v1/beacon/blocks/{block_id}/root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRootResponse {
    /// Whether the block is optimistically imported.
    #[serde(default)]
    pub execution_optimistic: bool,
    /// Whether the block is finalized.
    #[serde(default)]
    pub finalized: bool,
    /// Root of the block.
    #[serde(with = "root_data")]
    pub data: Root,
}

/// `{ "root": "0x.." }`, the `data` object of a block root response.
mod root_data {
    use super::*;

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    struct RootData {
        #[serde_as(as = "pluto_ssz::serde_utils::Hex0x")]
        root: Root,
    }

    pub fn serialize<S: Serializer>(root: &Root, serializer: S) -> Result<S::Ok, S::Error> {
        RootData { root: *root }.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Root, D::Error> {
        RootData::deserialize(deserializer).map(|data| data.root)
    }
}

/// Response of `GET /eth/v1/beacon/headers/{block_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeaderResponse {
    /// Whether the block is optimistically imported.
    #[serde(default)]
    pub execution_optimistic: bool,
    /// Whether the block is finalized.
    #[serde(default)]
    pub finalized: bool,
    /// The header.
    pub data: v1::BeaconBlockHeader,
}

/// Response of `GET /eth/v2/beacon/blocks/{block_id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlockResponse {
    /// Fork version of the block.
    pub version: DataVersion,
    /// Whether the block is optimistically imported.
    pub execution_optimistic: bool,
    /// Whether the block is finalized.
    pub finalized: bool,
    /// The block.
    pub data: versioned::SignedBeaconBlock,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn roundtrip<T>(wire: serde_json::Value) -> T
    where
        T: serde::de::DeserializeOwned + Serialize,
    {
        let value: T = serde_json::from_value(wire.clone()).expect("deserialize");
        assert_eq!(serde_json::to_value(&value).expect("serialize"), wire);
        value
    }

    #[test]
    fn error_body_tolerates_missing_fields() {
        let full: ErrorBody = roundtrip(json!({
            "code": 400,
            "message": "bad request",
            "stacktraces": ["at a", "at b"],
            "failures": [{ "index": 1, "message": "bad signature" }],
        }));
        assert_eq!(full.code, Some(400));
        assert_eq!(full.failures[0].index, 1);

        let minimal: ErrorBody = roundtrip(json!({ "message": "boom" }));
        assert_eq!(minimal.code, None);
        assert!(minimal.failures.is_empty());
    }

    #[test]
    fn validator_id_json_is_a_decimal_or_hex_string() {
        let pubkey = [0xab; 48];
        let ids: Vec<ValidatorId> = roundtrip(json!(["12", format!("0x{}", "ab".repeat(48))]));
        assert_eq!(ids, [ValidatorId::Index(12), ValidatorId::PubKey(pubkey)]);

        serde_json::from_value::<ValidatorId>(json!("0x0102")).expect_err("short pubkey");
        serde_json::from_value::<ValidatorId>(json!("twelve")).expect_err("not a number");
    }

    #[test]
    fn validators_filter_omits_empty_lists() {
        assert_eq!(
            serde_json::to_value(ValidatorsFilter::default()).expect("serialize"),
            json!({})
        );
        let filter: ValidatorsFilter = roundtrip(json!({
            "ids": ["7"],
            "statuses": ["active_ongoing", "pending_queued"],
        }));
        assert_eq!(filter.ids, [ValidatorId::Index(7)]);
        assert_eq!(filter.statuses.len(), 2);
    }

    #[test]
    fn spec_decodes_wire_encoding_and_ignores_unknown_keys() {
        let spec: Spec =
            serde_json::from_value(crate::test_fixtures::spec_json()).expect("deserialize");

        assert_eq!(spec.seconds_per_slot, 12);
        assert_eq!(spec.slots_per_epoch, 32);
        assert_eq!(spec.domain_beacon_attester, [1, 0, 0, 0]);
        assert_eq!(spec.target_aggregators_per_committee, 16);
        assert_eq!(
            spec.fork_schedule()[&DataVersion::Capella],
            ForkSchedule {
                version: [3, 4, 5, 6],
                epoch: 30,
            }
        );
        assert_eq!(spec.fork_schedule().len(), 6);
    }

    #[test]
    fn spec_defaults_the_builder_domain_type() {
        let mut wire = crate::test_fixtures::spec_json();
        wire.as_object_mut()
            .expect("object")
            .remove("DOMAIN_APPLICATION_BUILDER");

        let spec: Spec = serde_json::from_value(wire).expect("deserialize");

        assert_eq!(spec.domain_application_builder, [0, 0, 0, 1]);
    }

    #[test]
    fn duty_envelopes_use_wire_encoding() {
        let attester: AttesterDutiesResponse = roundtrip(json!({
            "dependent_root": format!("0x{}", "01".repeat(32)),
            "execution_optimistic": false,
            "data": [],
        }));
        assert_eq!(attester.dependent_root, [0x01; 32]);

        // Nodes may omit the optimistic flag.
        let proposer: ProposerDutiesResponse = serde_json::from_value(json!({
            "dependent_root": format!("0x{}", "02".repeat(32)),
            "data": [{
                "pubkey": format!("0x{}", "aa".repeat(48)),
                "validator_index": "1",
                "slot": "2",
            }],
        }))
        .expect("deserialize");
        assert!(!proposer.execution_optimistic);
        assert_eq!(proposer.data[0].slot, 2);

        let sync: SyncCommitteeDutiesResponse = roundtrip(json!({
            "execution_optimistic": true,
            "data": [],
        }));
        assert!(sync.execution_optimistic);
    }

    #[test]
    fn state_envelopes_use_wire_encoding() {
        let validators: ValidatorsResponse = roundtrip(json!({
            "execution_optimistic": false,
            "finalized": true,
            "data": [],
        }));
        assert!(validators.finalized);

        let root: BlockRootResponse = roundtrip(json!({
            "execution_optimistic": false,
            "finalized": false,
            "data": { "root": format!("0x{}", "cd".repeat(32)) },
        }));
        assert_eq!(root.data, [0xcd; 32]);
    }

    #[test]
    fn string_enums_use_snake_case() {
        assert_eq!(
            serde_json::to_value(BroadcastValidation::ConsensusAndEquivocation).expect("json"),
            json!("consensus_and_equivocation")
        );
        assert_eq!(
            BroadcastValidation::ConsensusAndEquivocation.to_string(),
            "consensus_and_equivocation"
        );
        assert_eq!(EventTopic::ChainReorg.to_string(), "chain_reorg");
        assert_eq!(
            serde_json::from_value::<EventTopic>(json!("light_client_finality_update"))
                .expect("json"),
            EventTopic::LightClientFinalityUpdate
        );
    }
}
