//! Request and response payloads for the [`Handler`](super::handler::Handler)
//! trait.
//!
//! Most data payloads are empty placeholders for now and will be swapped
//! for the proper consensus-spec types in a later phase.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

pub use pluto_crypto::types::{PublicKey as BlsPubKey, Signature as BlsSignature};
pub use pluto_eth2api::{
    GetAttesterDutiesResponseResponse as AttesterDutiesResponse,
    GetAttesterDutiesResponseResponseDatum as AttesterDuty,
    GetProposerDutiesResponseResponse as ProposerDutiesResponse,
    GetProposerDutiesResponseResponseDatum as ProposerDuty,
    GetStateValidatorsResponseResponseDatum as Validator,
    GetSyncCommitteeDutiesResponseResponse as SyncCommitteeDutiesResponse,
    GetSyncCommitteeDutiesResponseResponseDatum as SyncCommitteeDuty,
    GetVersionResponseResponse as NodeVersionResponse,
    GetVersionResponseResponseData as NodeVersionData,
    spec::{
        altair::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        phase0::{self, Epoch, Root, Slot, ValidatorIndex},
    },
    v1::{BeaconCommitteeSelection, SyncCommitteeSelection},
    versioned,
};

/// Attestation data alias for the consensus-spec phase0 type.
pub type AttestationData = phase0::AttestationData;

/// Index of a beacon committee within a slot.
pub type CommitteeIndex = u64;

/// Response envelope carrying the payload alongside beacon-API metadata.
#[derive(Debug, Clone)]
pub struct EthResponse<T> {
    /// Response payload.
    pub data: T,
    /// `execution_optimistic` flag from the upstream beacon node.
    pub execution_optimistic: bool,
    /// `finalized` flag from the upstream beacon node.
    pub finalized: bool,
    /// `dependent_root` returned with attester/proposer duties responses.
    pub dependent_root: Option<Root>,
}

/// Options for
/// [`Handler::attester_duties`](super::handler::Handler::attester_duties).
#[derive(Debug, Clone)]
pub struct AttesterDutiesOpts {
    /// Epoch to fetch duties for.
    pub epoch: Epoch,
    /// Validator indices to fetch duties for. Carried as strings since the
    /// upstream auto-generated client takes string-typed indices.
    pub indices: Vec<String>,
}

/// Options for
/// [`Handler::proposer_duties`](super::handler::Handler::proposer_duties).
#[derive(Debug, Clone)]
pub struct ProposerDutiesOpts {
    /// Epoch to fetch duties for.
    pub epoch: Epoch,
}

/// Options for
/// [`Handler::sync_committee_duties`](super::handler::Handler::sync_committee_duties).
#[derive(Debug, Clone)]
pub struct SyncCommitteeDutiesOpts {
    /// Epoch to fetch duties for.
    pub epoch: Epoch,
    /// Validator indices to fetch duties for. Carried as strings since the
    /// upstream auto-generated client takes string-typed indices.
    pub indices: Vec<String>,
}

/// Options for
/// [`Handler::attestation_data`](super::handler::Handler::attestation_data).
#[derive(Debug, Clone)]
pub struct AttestationDataOpts {
    /// Slot the attestation references.
    pub slot: Slot,
    /// Committee index the attestation references.
    pub committee_index: CommitteeIndex,
}

/// Options for [`Handler::validators`](super::handler::Handler::validators).
#[derive(Debug, Clone)]
pub struct ValidatorsOpts {
    /// State identifier (`head`, `finalized`, slot number, root, …).
    pub state: String,
    /// Filter by validator public keys.
    pub pubkeys: Vec<BlsPubKey>,
    /// Filter by validator indices.
    pub indices: Vec<ValidatorIndex>,
}

/// Options for [`Handler::proposal`](super::handler::Handler::proposal).
#[derive(Debug, Clone)]
pub struct ProposalOpts {
    /// Slot to produce a block for.
    pub slot: Slot,
    /// RANDAO reveal signature for the slot.
    pub randao_reveal: BlsSignature,
    /// Graffiti to embed in the block.
    pub graffiti: [u8; 32],
    /// Builder boost factor — controls preference for builder vs local
    /// payloads.
    pub builder_boost_factor: Option<u64>,
}

/// Options for
/// [`Handler::aggregate_attestation`](super::handler::Handler::aggregate_attestation).
#[derive(Debug, Clone)]
pub struct AggregateAttestationOpts {
    /// Slot the attestation references.
    pub slot: Slot,
    /// Hash-tree root of the attestation data to aggregate.
    pub attestation_data_root: Root,
    /// Committee index the attestation references.
    pub committee_index: CommitteeIndex,
}

/// Options for
/// [`Handler::sync_committee_contribution`](super::handler::Handler::sync_committee_contribution).
#[derive(Debug, Clone)]
pub struct SyncCommitteeContributionOpts {
    /// Slot the contribution references.
    pub slot: Slot,
    /// Index of the sync subcommittee.
    pub subcommittee_index: u64,
    /// Hash-tree root of the beacon block the contribution signs over.
    pub beacon_block_root: Root,
}

/// Response envelope for the `attestation_data` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDataResponse {
    /// Unsigned attestation data produced by the consensus pipeline.
    pub data: AttestationData,
}

/// Response envelope for the `beacon_committee_selections` endpoint — a `data`
/// array of aggregated selection proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconCommitteeSelectionsResponse {
    /// Aggregated beacon-committee selection proofs.
    pub data: Vec<BeaconCommitteeSelection>,
}

/// Response envelope for the `sync_committee_selections` endpoint — a `data`
/// array of aggregated selection proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCommitteeSelectionsResponse {
    /// Aggregated sync-committee selection proofs.
    pub data: Vec<SyncCommitteeSelection>,
}

/// Versioned unsigned proposal payload — alias of the signeddata wrapper.
pub use crate::signeddata::VersionedProposal;

/// Versioned signed proposal payload — alias of the signeddata wrapper.
pub use crate::signeddata::VersionedSignedProposal;

/// Versioned signed blinded proposal payload — alias of the eth2api versioned
/// wrapper.
pub use pluto_eth2api::versioned::VersionedSignedBlindedProposal;

/// Versioned attestation payload. Placeholder.
#[derive(Debug, Clone)]
pub struct VersionedAttestation {}

/// Versioned signed aggregate-and-proof payload. Placeholder.
#[derive(Debug, Clone)]
pub struct VersionedSignedAggregateAndProof {}

/// Signed validator (builder) registration payload.
///
/// Wraps the versioned eth2api registration so the
/// [`Handler::submit_validator_registrations`](super::handler::Handler::submit_validator_registrations)
/// implementation has access to the same data the Go
/// `*eth2api.VersionedSignedValidatorRegistration` carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedValidatorRegistration(
    /// Wrapped versioned registration.
    pub versioned::VersionedSignedValidatorRegistration,
);

/// Signed voluntary exit payload.
///
/// Wraps `phase0::SignedVoluntaryExit` so the
/// [`Handler::submit_voluntary_exit`](super::handler::Handler::submit_voluntary_exit)
/// implementation has access to the same data the Go
/// `*eth2p0.SignedVoluntaryExit` carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedVoluntaryExit(
    /// Wrapped phase0 signed voluntary exit.
    pub phase0::SignedVoluntaryExit,
);

/// Validator-index request body for the `attester_duties` and
/// `sync_committee_duties` endpoints.
///
/// Accepts both numeric (`[1, 2]`) and string-encoded (`["1", "2"]`) JSON
/// arrays. Indices are stored as decimal strings so they pass straight through
/// to the auto-generated request builders.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ValIndexes(pub Vec<String>);

/// Hard cap on the number of validator indices accepted per request. A real
/// cluster has at most a few hundred validators; the cap is set generously
/// above that to leave room for future growth while still bounding the work
/// per request so a single misbehaving caller cannot drive unbounded
/// allocation. Pairs with the route-level [`DUTIES_BODY_LIMIT`]
/// (`router.rs`) which limits the *bytes* the deserializer ever sees;
/// this limits the *count* even within those bytes.
pub const VAL_INDEXES_MAX_LEN: usize = 8192;

impl<'de> Deserialize<'de> for ValIndexes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Custom visitor: streams elements via `SeqAccess::next_element`,
        // validates each on read, and aborts as soon as the cap is exceeded.
        // Avoids the `#[serde(untagged)]` two-pass behavior (which buffers the
        // input via serde's `Content` cache before retrying) and the
        // single-allocation `Vec<String>` materialization.
        struct ValIndexesVisitor;

        impl<'de> Visitor<'de> for ValIndexesVisitor {
            type Value = ValIndexes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of validator indices (numeric or decimal string)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64));
                while let Some(elem) = seq.next_element::<Element>()? {
                    if out.len() >= VAL_INDEXES_MAX_LEN {
                        return Err(de::Error::custom(format!(
                            "too many validator indices (max {VAL_INDEXES_MAX_LEN})"
                        )));
                    }
                    out.push(elem.0);
                }
                Ok(ValIndexes(out))
            }
        }

        deserializer.deserialize_seq(ValIndexesVisitor)
    }
}

/// One validator-index element. Accepts either a JSON number (formatted into
/// a decimal string) or a JSON string (validated as a `u64` then kept
/// verbatim). Single-pass; no untagged-enum buffering.
struct Element(String);

impl<'de> Deserialize<'de> for Element {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ElemVisitor;

        impl Visitor<'_> for ElemVisitor {
            type Value = Element;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a validator index (u64 or decimal string)")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Element(v.to_string()))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                u64::try_from(v)
                    .map(|n| Element(n.to_string()))
                    .map_err(|_| de::Error::custom("validator index must be non-negative"))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse::<u64>().map_err(de::Error::custom)?;
                Ok(Element(v.to_owned()))
            }
        }

        deserializer.deserialize_any(ElemVisitor)
    }
}
