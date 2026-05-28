//! Validator API request handler trait.

use async_trait::async_trait;

use super::{
    error::ApiError,
    types::{
        AggregateAttestationOpts, AttestationData, AttestationDataOpts, AttesterDutiesOpts,
        AttesterDuty, BeaconCommitteeSelection, EthResponse, ProposalOpts, ProposerDutiesOpts,
        ProposerDuty, SignedContributionAndProof, SignedValidatorRegistration, SignedVoluntaryExit,
        SyncCommitteeContribution, SyncCommitteeContributionOpts, SyncCommitteeDutiesOpts,
        SyncCommitteeDuty, SyncCommitteeMessage, SyncCommitteeSelection, Validator, ValidatorsOpts,
        VersionedAttestation, VersionedProposal, VersionedSignedAggregateAndProof,
        VersionedSignedBlindedProposal, VersionedSignedProposal,
    },
};

/// Validator API request handler.
///
/// Implementors provide the business logic invoked by each HTTP endpoint
/// registered in [`new_router`](super::router::new_router). All methods
/// return [`ApiError`] on failure; the router converts that into the
/// `errorResponse` JSON body.
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    /// `POST /eth/v1/validator/duties/attester/{epoch}`.
    async fn attester_duties(
        &self,
        opts: AttesterDutiesOpts,
    ) -> Result<EthResponse<Vec<AttesterDuty>>, ApiError>;

    /// `GET /eth/v1/validator/duties/proposer/{epoch}`.
    async fn proposer_duties(
        &self,
        opts: ProposerDutiesOpts,
    ) -> Result<EthResponse<Vec<ProposerDuty>>, ApiError>;

    /// `POST /eth/v1/validator/duties/sync/{epoch}`.
    async fn sync_committee_duties(
        &self,
        opts: SyncCommitteeDutiesOpts,
    ) -> Result<EthResponse<Vec<SyncCommitteeDuty>>, ApiError>;

    /// `GET /eth/v1/validator/attestation_data`.
    async fn attestation_data(
        &self,
        opts: AttestationDataOpts,
    ) -> Result<EthResponse<AttestationData>, ApiError>;

    /// `POST /eth/v2/beacon/pool/attestations`.
    async fn submit_attestations(
        &self,
        attestations: Vec<VersionedAttestation>,
    ) -> Result<(), ApiError>;

    /// `GET /eth/v3/validator/blocks/{slot}`.
    async fn proposal(
        &self,
        opts: ProposalOpts,
    ) -> Result<EthResponse<VersionedProposal>, ApiError>;

    /// `POST /eth/v{1,2}/beacon/blocks`.
    async fn submit_proposal(&self, proposal: VersionedSignedProposal) -> Result<(), ApiError>;

    /// `POST /eth/v{1,2}/beacon/blinded_blocks`.
    async fn submit_blinded_proposal(
        &self,
        proposal: VersionedSignedBlindedProposal,
    ) -> Result<(), ApiError>;

    /// `GET /eth/v2/validator/aggregate_attestation`.
    async fn aggregate_attestation(
        &self,
        opts: AggregateAttestationOpts,
    ) -> Result<EthResponse<VersionedAttestation>, ApiError>;

    /// `POST /eth/v2/validator/aggregate_and_proofs`.
    async fn submit_aggregate_attestations(
        &self,
        aggregates: Vec<VersionedSignedAggregateAndProof>,
    ) -> Result<(), ApiError>;

    /// `POST /eth/v1/validator/beacon_committee_selections`.
    async fn beacon_committee_selections(
        &self,
        selections: Vec<BeaconCommitteeSelection>,
    ) -> Result<EthResponse<Vec<BeaconCommitteeSelection>>, ApiError>;

    /// `POST /eth/v1/validator/sync_committee_selections`.
    async fn sync_committee_selections(
        &self,
        selections: Vec<SyncCommitteeSelection>,
    ) -> Result<EthResponse<Vec<SyncCommitteeSelection>>, ApiError>;

    /// `GET,POST /eth/v1/beacon/states/{state_id}/validators(/{validator_id})`.
    async fn validators(
        &self,
        opts: ValidatorsOpts,
    ) -> Result<EthResponse<Vec<Validator>>, ApiError>;

    /// `POST /eth/v1/validator/register_validator`.
    async fn submit_validator_registrations(
        &self,
        registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), ApiError>;

    /// `POST /eth/v1/beacon/pool/voluntary_exits`.
    async fn submit_voluntary_exit(&self, exit: SignedVoluntaryExit) -> Result<(), ApiError>;

    /// `GET /eth/v1/validator/sync_committee_contribution`.
    async fn sync_committee_contribution(
        &self,
        opts: SyncCommitteeContributionOpts,
    ) -> Result<EthResponse<SyncCommitteeContribution>, ApiError>;

    /// `POST /eth/v1/validator/contribution_and_proofs`.
    async fn submit_sync_committee_contributions(
        &self,
        contributions: Vec<SignedContributionAndProof>,
    ) -> Result<(), ApiError>;

    /// `POST /eth/v1/beacon/pool/sync_committees`.
    async fn submit_sync_committee_messages(
        &self,
        messages: Vec<SyncCommitteeMessage>,
    ) -> Result<(), ApiError>;

    /// `GET /eth/v1/node/version`.
    async fn node_version(&self) -> Result<EthResponse<String>, ApiError>;
}
