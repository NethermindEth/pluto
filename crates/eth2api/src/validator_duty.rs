//! Beacon API helpers used by validator duty flows.

use crate::{
    EthBeaconNodeApiClient, HttpError,
    spec::{altair, phase0},
    v1, versioned,
};

type Result<T> = std::result::Result<T, ValidatorDutyError>;

/// Error returned by validator duty beacon API helpers.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ValidatorDutyError(String);

/// Attester duty data needed by validator duty flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttesterDuty {
    /// Duty slot.
    pub slot: phase0::Slot,
    /// Validator index.
    pub validator_index: phase0::ValidatorIndex,
    /// Validator public key.
    pub pubkey: phase0::BLSPubKey,
}

impl EthBeaconNodeApiClient {
    /// Fetches attester duties for the provided validator indices.
    pub async fn fetch_attester_duties_for_indices(
        &self,
        epoch: phase0::Epoch,
        indices: Vec<phase0::ValidatorIndex>,
    ) -> Result<Vec<AttesterDuty>> {
        let response =
            crate::instrument("attester_duties", self.get_attester_duties(epoch, &indices))
                .await
                .map_err(|error| request_error("get attester duties", &error))?;

        Ok(response
            .data
            .into_iter()
            .map(|duty| AttesterDuty {
                slot: duty.slot,
                validator_index: duty.validator_index,
                pubkey: duty.pubkey,
            })
            .collect())
    }

    /// Fetches the beacon attester signing domain.
    pub async fn fetch_beacon_attester_domain(
        &self,
        epoch: phase0::Epoch,
    ) -> Result<phase0::Domain> {
        let domain_type = self
            .fetch_domain_type("DOMAIN_BEACON_ATTESTER")
            .await
            .map_err(error_message)?;

        self.fetch_domain(domain_type, epoch)
            .await
            .map_err(error_message)
    }

    /// Submits signed attestations to the beacon node.
    pub async fn submit_attestations(
        &self,
        attestations: Vec<versioned::VersionedAttestation>,
    ) -> Result<()> {
        crate::instrument(
            "submit_attestations",
            self.submit_pool_attestations_v2(&attestations),
        )
        .await
        .map_err(|error| request_error("submit attestations", &error))
    }

    /// Submits a signed block proposal to the beacon node.
    pub async fn submit_signed_proposal(
        &self,
        proposal: versioned::VersionedSignedProposal,
    ) -> Result<()> {
        crate::instrument("submit_proposal", self.publish_block_v2(&proposal, None))
            .await
            .map_err(|error| request_error("submit proposal", &error))
    }

    /// Submits a signed blinded block proposal to the beacon node.
    pub async fn submit_signed_blinded_proposal(
        &self,
        proposal: versioned::VersionedSignedBlindedProposal,
    ) -> Result<()> {
        crate::instrument(
            "submit_blinded_proposal",
            self.publish_blinded_block_v2(&proposal, None),
        )
        .await
        .map_err(|error| request_error("submit blinded proposal", &error))
    }

    /// Submits signed validator registrations to the beacon node.
    pub async fn submit_validator_registrations(
        &self,
        registrations: Vec<versioned::VersionedSignedValidatorRegistration>,
    ) -> Result<()> {
        let registrations =
            registrations
                .into_iter()
                .map(|registration| {
                    match (registration.version, registration.v1) {
                (versioned::BuilderVersion::V1, Some(registration)) => Ok(registration),
                _ => Err(ValidatorDutyError(
                    "validator registration request body: unsupported builder registration version"
                        .to_string(),
                )),
            }
                })
                .collect::<Result<Vec<v1::SignedValidatorRegistration>>>()?;

        crate::instrument(
            "submit_validator_registrations",
            self.register_validator(&registrations),
        )
        .await
        .map_err(|error| request_error("submit validator registrations", &error))
    }

    /// Submits a signed voluntary exit to the beacon node.
    pub async fn submit_voluntary_exit(&self, exit: phase0::SignedVoluntaryExit) -> Result<()> {
        crate::instrument(
            "submit_voluntary_exit",
            self.submit_pool_voluntary_exit(&exit),
        )
        .await
        .map_err(|error| request_error("submit voluntary exit", &error))
    }

    /// Submits signed aggregate-and-proof messages to the beacon node.
    pub async fn submit_aggregate_attestations(
        &self,
        aggregate_and_proofs: Vec<versioned::VersionedSignedAggregateAndProof>,
    ) -> Result<()> {
        crate::instrument(
            "submit_aggregate_attestations",
            self.publish_aggregate_and_proofs_v2(&aggregate_and_proofs),
        )
        .await
        .map_err(|error| request_error("submit aggregate attestations", &error))
    }

    /// Submits sync committee messages to the beacon node.
    pub async fn submit_sync_committee_messages(
        &self,
        messages: Vec<altair::SyncCommitteeMessage>,
    ) -> Result<()> {
        crate::instrument(
            "submit_sync_committee_messages",
            self.submit_pool_sync_committee_signatures(&messages),
        )
        .await
        .map_err(|error| request_error("submit sync committee messages", &error))
    }

    /// Submits sync committee contributions to the beacon node.
    pub async fn submit_sync_committee_contributions(
        &self,
        contributions: Vec<altair::SignedContributionAndProof>,
    ) -> Result<()> {
        crate::instrument(
            "submit_sync_committee_contributions",
            self.publish_contribution_and_proofs(&contributions),
        )
        .await
        .map_err(|error| request_error("submit sync committee contributions", &error))
    }
}

/// Returns true for data versions that use pre-Electra attestation wire shape.
pub fn data_version_is_before_electra(version: versioned::DataVersion) -> bool {
    matches!(
        version,
        versioned::DataVersion::Unknown
            | versioned::DataVersion::Phase0
            | versioned::DataVersion::Altair
            | versioned::DataVersion::Bellatrix
            | versioned::DataVersion::Capella
            | versioned::DataVersion::Deneb
    )
}

fn error_message(source: impl ToString) -> ValidatorDutyError {
    ValidatorDutyError(source.to_string())
}

/// Describes a failed request, listing the per-item failures a beacon node
/// reports for batch submissions.
fn request_error(context: &'static str, error: &anyhow::Error) -> ValidatorDutyError {
    let Some(http) = HttpError::from_error(error) else {
        return ValidatorDutyError(format!("{context}: {error:#}"));
    };

    let details = http
        .body
        .failures
        .iter()
        .map(|failure| failure.message.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    if details.is_empty() {
        ValidatorDutyError(format!("{context}: {http}"))
    } else {
        ValidatorDutyError(format!("{context}: {http}: {details}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorBody, IndexedFailure};

    #[test]
    fn request_error_lists_batch_failures() {
        let error = anyhow::Error::from(HttpError {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: ErrorBody {
                code: Some(400),
                message: "some failed".to_string(),
                stacktraces: Vec::new(),
                failures: vec![
                    IndexedFailure {
                        index: 0,
                        message: "bad signature".to_string(),
                    },
                    IndexedFailure {
                        index: 2,
                        message: "unknown validator".to_string(),
                    },
                ],
            },
        });

        assert_eq!(
            request_error("submit attestations", &error).to_string(),
            "submit attestations: beacon node returned 400 Bad Request: some failed: bad signature; unknown validator"
        );
        assert_eq!(
            request_error("submit proposal", &anyhow::anyhow!("boom")).to_string(),
            "submit proposal: boom"
        );
    }
}
