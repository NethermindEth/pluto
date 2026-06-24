//! Test helpers for the validator API router.
//!
//! [`TestHandler`] implements [`Handler`] with `unimplemented!()` stubs for
//! every method. As each router endpoint is ported, the relevant method is
//! overridden here so the route's unit test can drive it.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::{
    error::ApiError,
    handler::Handler,
    types::{
        AggregateAttestationOpts, AttestationDataOpts, AttestationDataResponse, AttesterDutiesOpts,
        AttesterDutiesResponse, BeaconCommitteeSelection, EthResponse, NodeVersionData,
        NodeVersionResponse, ProposalOpts, ProposerDutiesOpts, ProposerDutiesResponse,
        SignedContributionAndProof, SignedValidatorRegistration, SignedVoluntaryExit,
        SyncCommitteeContribution, SyncCommitteeContributionOpts, SyncCommitteeDutiesOpts,
        SyncCommitteeDutiesResponse, SyncCommitteeMessage, SyncCommitteeSelection, Validator,
        ValidatorsOpts, VersionedAttestation, VersionedProposal, VersionedSignedAggregateAndProof,
        VersionedSignedBlindedProposal, VersionedSignedProposal,
    },
};

/// Mock [`Handler`] used by router unit tests.
#[derive(Debug, Default, Clone)]
pub struct TestHandler {
    /// Value returned by [`Handler::node_version`].
    pub version: String,
    /// Value returned by [`Handler::proposer_duties`].
    pub proposer_duties_response: Option<ProposerDutiesResponse>,
    /// Value returned by [`Handler::attester_duties`].
    pub attester_duties_response: Option<AttesterDutiesResponse>,
    /// Value returned by [`Handler::sync_committee_duties`].
    pub sync_committee_duties_response: Option<SyncCommitteeDutiesResponse>,
    /// Value returned by [`Handler::attestation_data`].
    pub attestation_data_response: Option<AttestationDataResponse>,
    /// Value returned by [`Handler::proposal`].
    pub proposal_response: Option<EthResponse<VersionedProposal>>,
    /// Value returned by [`Handler::validators`].
    pub validators_response: Option<EthResponse<Vec<Validator>>>,
    /// Records the last [`ProposalOpts`] passed to [`Handler::proposal`].
    pub proposal_opts: Arc<Mutex<Option<ProposalOpts>>>,
    /// Records the last proposal submitted via [`Handler::submit_proposal`].
    pub submitted_proposal: Arc<Mutex<Option<VersionedSignedProposal>>>,
    /// Records the last proposal submitted via
    /// [`Handler::submit_blinded_proposal`].
    pub submitted_blinded_proposal: Arc<Mutex<Option<VersionedSignedBlindedProposal>>>,
    /// Records the last [`ValidatorsOpts`] passed to [`Handler::validators`].
    pub validators_opts: Arc<Mutex<Option<ValidatorsOpts>>>,
    /// Value returned by [`Handler::sync_committee_contribution`].
    pub sync_committee_contribution_response: Option<EthResponse<SyncCommitteeContribution>>,
    /// Records the last registrations submitted via
    /// [`Handler::submit_validator_registrations`].
    pub submitted_registrations: Arc<Mutex<Option<Vec<SignedValidatorRegistration>>>>,
    /// Records the last exit submitted via [`Handler::submit_voluntary_exit`].
    pub submitted_exit: Arc<Mutex<Option<SignedVoluntaryExit>>>,
    /// Records the attestations submitted via [`Handler::submit_attestations`].
    pub submitted_attestations: Arc<Mutex<Option<Vec<VersionedAttestation>>>>,
    /// Records the aggregate-and-proofs submitted via
    /// [`Handler::submit_aggregate_attestations`].
    pub submitted_aggregates: Arc<Mutex<Option<Vec<VersionedSignedAggregateAndProof>>>>,
    /// Records the selections passed to
    /// [`Handler::beacon_committee_selections`].
    pub beacon_committee_selections_opts: Arc<Mutex<Option<Vec<BeaconCommitteeSelection>>>>,
    /// Value returned by [`Handler::aggregate_attestation`].
    pub aggregate_attestation_response: Option<EthResponse<VersionedAttestation>>,
    /// Records the last [`AggregateAttestationOpts`] passed to
    /// [`Handler::aggregate_attestation`].
    pub aggregate_attestation_opts: Arc<Mutex<Option<AggregateAttestationOpts>>>,
    /// Value returned by [`Handler::beacon_committee_selections`].
    pub beacon_committee_selections_response: Option<EthResponse<Vec<BeaconCommitteeSelection>>>,
    /// Value returned by [`Handler::sync_committee_selections`].
    pub sync_committee_selections_response: Option<EthResponse<Vec<SyncCommitteeSelection>>>,
    /// Records the messages submitted via
    /// [`Handler::submit_sync_committee_messages`].
    pub submitted_sync_messages: Arc<Mutex<Option<Vec<SyncCommitteeMessage>>>>,
    /// Records the contributions submitted via
    /// [`Handler::submit_sync_committee_contributions`].
    pub submitted_sync_contributions: Arc<Mutex<Option<Vec<SignedContributionAndProof>>>>,
    /// Records the selections passed to
    /// [`Handler::sync_committee_selections`].
    pub submitted_sync_selections: Arc<Mutex<Option<Vec<SyncCommitteeSelection>>>>,
    /// Records the last [`SyncCommitteeContributionOpts`] passed to
    /// [`Handler::sync_committee_contribution`].
    pub sync_committee_contribution_opts: Arc<Mutex<Option<SyncCommitteeContributionOpts>>>,
}

impl TestHandler {
    /// Builds a [`TestHandler`] with the given node version string.
    pub fn with_version(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            ..Self::default()
        }
    }

    /// Sets the response returned by [`Handler::proposal`].
    pub fn with_proposal(mut self, response: EthResponse<VersionedProposal>) -> Self {
        self.proposal_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::validators`].
    pub fn with_validators(mut self, response: EthResponse<Vec<Validator>>) -> Self {
        self.validators_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::proposer_duties`].
    pub fn with_proposer_duties(mut self, response: ProposerDutiesResponse) -> Self {
        self.proposer_duties_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::attester_duties`].
    pub fn with_attester_duties(mut self, response: AttesterDutiesResponse) -> Self {
        self.attester_duties_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::sync_committee_duties`].
    pub fn with_sync_committee_duties(mut self, response: SyncCommitteeDutiesResponse) -> Self {
        self.sync_committee_duties_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::attestation_data`].
    pub fn with_attestation_data(mut self, response: AttestationDataResponse) -> Self {
        self.attestation_data_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::sync_committee_contribution`].
    pub fn with_sync_committee_contribution(
        mut self,
        response: EthResponse<SyncCommitteeContribution>,
    ) -> Self {
        self.sync_committee_contribution_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::aggregate_attestation`].
    pub fn with_aggregate_attestation(
        mut self,
        response: EthResponse<VersionedAttestation>,
    ) -> Self {
        self.aggregate_attestation_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::beacon_committee_selections`].
    pub fn with_beacon_committee_selections(
        mut self,
        response: EthResponse<Vec<BeaconCommitteeSelection>>,
    ) -> Self {
        self.beacon_committee_selections_response = Some(response);
        self
    }

    /// Sets the response returned by [`Handler::sync_committee_selections`].
    pub fn with_sync_committee_selections(
        mut self,
        response: EthResponse<Vec<SyncCommitteeSelection>>,
    ) -> Self {
        self.sync_committee_selections_response = Some(response);
        self
    }
}

#[async_trait]
impl Handler for TestHandler {
    async fn node_version(&self) -> Result<NodeVersionResponse, ApiError> {
        Ok(NodeVersionResponse {
            data: NodeVersionData {
                version: self.version.clone(),
            },
        })
    }

    async fn attester_duties(
        &self,
        _opts: AttesterDutiesOpts,
    ) -> Result<AttesterDutiesResponse, ApiError> {
        match self.attester_duties_response.as_ref() {
            Some(r) => Ok(r.clone()),
            None => unimplemented!("attester_duties not stubbed in TestHandler"),
        }
    }

    async fn proposer_duties(
        &self,
        _opts: ProposerDutiesOpts,
    ) -> Result<ProposerDutiesResponse, ApiError> {
        match self.proposer_duties_response.as_ref() {
            Some(r) => Ok(r.clone()),
            None => unimplemented!("proposer_duties not stubbed in TestHandler"),
        }
    }

    async fn sync_committee_duties(
        &self,
        _opts: SyncCommitteeDutiesOpts,
    ) -> Result<SyncCommitteeDutiesResponse, ApiError> {
        match self.sync_committee_duties_response.as_ref() {
            Some(r) => Ok(r.clone()),
            None => unimplemented!("sync_committee_duties not stubbed in TestHandler"),
        }
    }

    async fn attestation_data(
        &self,
        _opts: AttestationDataOpts,
    ) -> Result<AttestationDataResponse, ApiError> {
        match self.attestation_data_response.as_ref() {
            Some(r) => Ok(r.clone()),
            None => unimplemented!("attestation_data not stubbed in TestHandler"),
        }
    }

    async fn submit_attestations(
        &self,
        attestations: Vec<VersionedAttestation>,
    ) -> Result<(), ApiError> {
        *self
            .submitted_attestations
            .lock()
            .expect("submitted_attestations lock") = Some(attestations);
        Ok(())
    }

    async fn proposal(
        &self,
        opts: ProposalOpts,
    ) -> Result<EthResponse<VersionedProposal>, ApiError> {
        *self.proposal_opts.lock().expect("proposal_opts lock") = Some(opts);
        Ok(self
            .proposal_response
            .clone()
            .expect("proposal not stubbed in TestHandler"))
    }

    async fn submit_proposal(&self, proposal: VersionedSignedProposal) -> Result<(), ApiError> {
        *self
            .submitted_proposal
            .lock()
            .expect("submitted_proposal lock") = Some(proposal);
        Ok(())
    }

    async fn submit_blinded_proposal(
        &self,
        proposal: VersionedSignedBlindedProposal,
    ) -> Result<(), ApiError> {
        *self
            .submitted_blinded_proposal
            .lock()
            .expect("submitted_blinded_proposal lock") = Some(proposal);
        Ok(())
    }

    async fn aggregate_attestation(
        &self,
        opts: AggregateAttestationOpts,
    ) -> Result<EthResponse<VersionedAttestation>, ApiError> {
        *self
            .aggregate_attestation_opts
            .lock()
            .expect("aggregate_attestation_opts lock") = Some(opts);
        Ok(self
            .aggregate_attestation_response
            .clone()
            .expect("aggregate_attestation not stubbed in TestHandler"))
    }

    async fn submit_aggregate_attestations(
        &self,
        aggregates: Vec<VersionedSignedAggregateAndProof>,
    ) -> Result<(), ApiError> {
        *self
            .submitted_aggregates
            .lock()
            .expect("submitted_aggregates lock") = Some(aggregates);
        Ok(())
    }

    async fn beacon_committee_selections(
        &self,
        selections: Vec<BeaconCommitteeSelection>,
    ) -> Result<EthResponse<Vec<BeaconCommitteeSelection>>, ApiError> {
        *self
            .beacon_committee_selections_opts
            .lock()
            .expect("beacon_committee_selections_opts lock") = Some(selections);
        Ok(self
            .beacon_committee_selections_response
            .clone()
            .expect("beacon_committee_selections not stubbed in TestHandler"))
    }

    async fn sync_committee_selections(
        &self,
        selections: Vec<SyncCommitteeSelection>,
    ) -> Result<EthResponse<Vec<SyncCommitteeSelection>>, ApiError> {
        *self
            .submitted_sync_selections
            .lock()
            .expect("submitted_sync_selections lock") = Some(selections);
        match self.sync_committee_selections_response.as_ref() {
            Some(r) => Ok(r.clone()),
            None => unimplemented!("sync_committee_selections not stubbed in TestHandler"),
        }
    }

    async fn validators(
        &self,
        opts: ValidatorsOpts,
    ) -> Result<EthResponse<Vec<Validator>>, ApiError> {
        *self.validators_opts.lock().expect("validators_opts lock") = Some(opts);
        Ok(self
            .validators_response
            .clone()
            .expect("validators not stubbed in TestHandler"))
    }

    async fn submit_validator_registrations(
        &self,
        registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), ApiError> {
        *self
            .submitted_registrations
            .lock()
            .expect("submitted_registrations lock") = Some(registrations);
        Ok(())
    }

    async fn submit_voluntary_exit(&self, exit: SignedVoluntaryExit) -> Result<(), ApiError> {
        *self.submitted_exit.lock().expect("submitted_exit lock") = Some(exit);
        Ok(())
    }

    async fn sync_committee_contribution(
        &self,
        opts: SyncCommitteeContributionOpts,
    ) -> Result<EthResponse<SyncCommitteeContribution>, ApiError> {
        *self
            .sync_committee_contribution_opts
            .lock()
            .expect("sync_committee_contribution_opts lock") = Some(opts);
        Ok(self
            .sync_committee_contribution_response
            .clone()
            .expect("sync_committee_contribution not stubbed in TestHandler"))
    }

    async fn submit_sync_committee_contributions(
        &self,
        contributions: Vec<SignedContributionAndProof>,
    ) -> Result<(), ApiError> {
        *self
            .submitted_sync_contributions
            .lock()
            .expect("submitted_sync_contributions lock") = Some(contributions);
        Ok(())
    }

    async fn submit_sync_committee_messages(
        &self,
        messages: Vec<SyncCommitteeMessage>,
    ) -> Result<(), ApiError> {
        *self
            .submitted_sync_messages
            .lock()
            .expect("submitted_sync_messages lock") = Some(messages);
        Ok(())
    }
}
