//! Request and response payloads for the [`Handler`](super::handler::Handler)
//! trait.
//!
//! Most data payloads are empty placeholders for now and will be swapped
//! for the proper consensus-spec types in a later phase.

pub use pluto_crypto::types::{PublicKey as BlsPubKey, Signature as BlsSignature};
pub use pluto_eth2api::{
    GetProposerDutiesResponseResponse as ProposerDutiesResponse,
    GetProposerDutiesResponseResponseDatum as ProposerDuty,
    GetVersionResponseResponse as NodeVersionResponse,
    GetVersionResponseResponseData as NodeVersionData,
    spec::phase0::{Epoch, Root, Slot, ValidatorIndex},
};

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
    /// Validator indices to fetch duties for.
    pub indices: Vec<ValidatorIndex>,
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
    /// Validator indices to fetch duties for.
    pub indices: Vec<ValidatorIndex>,
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

/// Attester duty payload. Placeholder.
#[derive(Debug, Clone)]
pub struct AttesterDuty {}

/// Sync-committee duty payload. Placeholder.
#[derive(Debug, Clone)]
pub struct SyncCommitteeDuty {}

/// Attestation data payload. Placeholder.
#[derive(Debug, Clone)]
pub struct AttestationData {}

/// Validator payload. Placeholder.
#[derive(Debug, Clone)]
pub struct Validator {}

/// Versioned unsigned proposal payload. Placeholder.
#[derive(Debug, Clone)]
pub struct VersionedProposal {}

/// Versioned signed proposal payload. Placeholder.
#[derive(Debug, Clone)]
pub struct VersionedSignedProposal {}

/// Versioned signed blinded proposal payload. Placeholder.
#[derive(Debug, Clone)]
pub struct VersionedSignedBlindedProposal {}

/// Versioned attestation payload. Placeholder.
#[derive(Debug, Clone)]
pub struct VersionedAttestation {}

/// Versioned signed aggregate-and-proof payload. Placeholder.
#[derive(Debug, Clone)]
pub struct VersionedSignedAggregateAndProof {}

/// Signed validator registration payload. Placeholder.
#[derive(Debug, Clone)]
pub struct SignedValidatorRegistration {}

/// Signed voluntary exit payload. Placeholder.
#[derive(Debug, Clone)]
pub struct SignedVoluntaryExit {}

/// Sync-committee message payload. Placeholder.
#[derive(Debug, Clone)]
pub struct SyncCommitteeMessage {}

/// Sync-committee contribution payload. Placeholder.
#[derive(Debug, Clone)]
pub struct SyncCommitteeContribution {}

/// Signed contribution-and-proof payload. Placeholder.
#[derive(Debug, Clone)]
pub struct SignedContributionAndProof {}

/// Beacon-committee selection payload. Placeholder.
#[derive(Debug, Clone)]
pub struct BeaconCommitteeSelection {}

/// Sync-committee selection payload. Placeholder.
#[derive(Debug, Clone)]
pub struct SyncCommitteeSelection {}
