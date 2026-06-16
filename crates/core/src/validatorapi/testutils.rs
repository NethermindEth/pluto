//! Test helpers for the validator API router.
//!
//! [`TestHandler`] implements [`Handler`] with `unimplemented!()` stubs for
//! every method. As each router endpoint is ported, the relevant method is
//! overridden here so the route's unit test can drive it.

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
    /// Value returned by [`Handler::beacon_committee_selections`].
    pub beacon_committee_selections_response: Option<EthResponse<Vec<BeaconCommitteeSelection>>>,
    /// Value returned by [`Handler::sync_committee_selections`].
    pub sync_committee_selections_response: Option<EthResponse<Vec<SyncCommitteeSelection>>>,
}

impl TestHandler {
    /// Builds a [`TestHandler`] with the given node version string.
    pub fn with_version(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            ..Self::default()
        }
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
        _attestations: Vec<VersionedAttestation>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_attestations not stubbed in TestHandler")
    }

    async fn proposal(
        &self,
        _opts: ProposalOpts,
    ) -> Result<EthResponse<VersionedProposal>, ApiError> {
        unimplemented!("proposal not stubbed in TestHandler")
    }

    async fn submit_proposal(&self, _proposal: VersionedSignedProposal) -> Result<(), ApiError> {
        unimplemented!("submit_proposal not stubbed in TestHandler")
    }

    async fn submit_blinded_proposal(
        &self,
        _proposal: VersionedSignedBlindedProposal,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_blinded_proposal not stubbed in TestHandler")
    }

    async fn aggregate_attestation(
        &self,
        _opts: AggregateAttestationOpts,
    ) -> Result<EthResponse<VersionedAttestation>, ApiError> {
        unimplemented!("aggregate_attestation not stubbed in TestHandler")
    }

    async fn submit_aggregate_attestations(
        &self,
        _aggregates: Vec<VersionedSignedAggregateAndProof>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_aggregate_attestations not stubbed in TestHandler")
    }

    async fn beacon_committee_selections(
        &self,
        _selections: Vec<BeaconCommitteeSelection>,
    ) -> Result<EthResponse<Vec<BeaconCommitteeSelection>>, ApiError> {
        match self.beacon_committee_selections_response.as_ref() {
            Some(r) => Ok(r.clone()),
            None => unimplemented!("beacon_committee_selections not stubbed in TestHandler"),
        }
    }

    async fn sync_committee_selections(
        &self,
        _selections: Vec<SyncCommitteeSelection>,
    ) -> Result<EthResponse<Vec<SyncCommitteeSelection>>, ApiError> {
        match self.sync_committee_selections_response.as_ref() {
            Some(r) => Ok(r.clone()),
            None => unimplemented!("sync_committee_selections not stubbed in TestHandler"),
        }
    }

    async fn validators(
        &self,
        _opts: ValidatorsOpts,
    ) -> Result<EthResponse<Vec<Validator>>, ApiError> {
        unimplemented!("validators not stubbed in TestHandler")
    }

    async fn submit_validator_registrations(
        &self,
        _registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_validator_registrations not stubbed in TestHandler")
    }

    async fn submit_voluntary_exit(&self, _exit: SignedVoluntaryExit) -> Result<(), ApiError> {
        unimplemented!("submit_voluntary_exit not stubbed in TestHandler")
    }

    async fn sync_committee_contribution(
        &self,
        _opts: SyncCommitteeContributionOpts,
    ) -> Result<EthResponse<SyncCommitteeContribution>, ApiError> {
        unimplemented!("sync_committee_contribution not stubbed in TestHandler")
    }

    async fn submit_sync_committee_contributions(
        &self,
        _contributions: Vec<SignedContributionAndProof>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_sync_committee_contributions not stubbed in TestHandler")
    }

    async fn submit_sync_committee_messages(
        &self,
        _messages: Vec<SyncCommitteeMessage>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_sync_committee_messages not stubbed in TestHandler")
    }
}
