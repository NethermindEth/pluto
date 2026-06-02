//! Validator API [`Handler`] implementation.
//!
//! The component owns the upstream beacon-node client plus the public-key
//! and public-share mappings needed to translate between distributed-validator
//! root keys and this node's threshold-BLS share.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use axum::http::StatusCode;
use pluto_eth2api::{
    EthBeaconNodeApiClient, GetProposerDutiesRequest, GetProposerDutiesResponse,
    spec::phase0::BLSPubKey,
};

use super::{
    error::ApiError,
    handler::Handler,
    types::{
        AggregateAttestationOpts, AttestationData, AttestationDataOpts, AttesterDutiesOpts,
        AttesterDuty, BeaconCommitteeSelection, EthResponse, NodeVersionData, NodeVersionResponse,
        ProposalOpts, ProposerDutiesOpts, ProposerDutiesResponse, ProposerDuty,
        SignedContributionAndProof, SignedValidatorRegistration, SignedVoluntaryExit,
        SyncCommitteeContribution, SyncCommitteeContributionOpts, SyncCommitteeDutiesOpts,
        SyncCommitteeDuty, SyncCommitteeMessage, SyncCommitteeSelection, Validator, ValidatorsOpts,
        VersionedAttestation, VersionedProposal, VersionedSignedAggregateAndProof,
        VersionedSignedBlindedProposal, VersionedSignedProposal,
    },
};
use crate::version;

/// Validator API [`Handler`] implementation.
///
/// Holds the upstream beacon-node client and the cluster's public-key /
/// public-share mappings. Each per-endpoint method calls upstream, rewrites
/// root pubkeys to this node's share where the endpoint exposes data to the
/// validator client, and emits partial-signed-data to subscribers on submit
/// endpoints.
pub struct Component {
    /// Upstream beacon-node API client.
    eth2_cl: Arc<EthBeaconNodeApiClient>,
    /// Threshold BLS share index assigned to this node (1-indexed).
    #[allow(dead_code, reason = "consumed by submit_* handlers in later PRs")]
    share_idx: u64,
    /// Maps DV root public keys to this node's public share. Used to rewrite
    /// validator-client-facing endpoints (proposer/attester duties, etc.) so
    /// the VC sees the share it is configured to sign with.
    pub_share_by_pubkey: HashMap<BLSPubKey, BLSPubKey>,
    /// Whether builder mode is enabled. Read by `propose_block_v3` and the
    /// validator-registration submitter.
    #[allow(
        dead_code,
        reason = "consumed by propose_block_v3 / submit_validator_registrations"
    )]
    builder_enabled: bool,
    /// Skip signature verification on partial-signed submissions. Test-only.
    #[allow(dead_code, reason = "consumed by submit_* handlers in later PRs")]
    insecure_test: bool,
}

impl Component {
    /// Builds a new component.
    pub fn new(
        eth2_cl: Arc<EthBeaconNodeApiClient>,
        share_idx: u64,
        pub_share_by_pubkey: HashMap<BLSPubKey, BLSPubKey>,
        builder_enabled: bool,
    ) -> Self {
        Self {
            eth2_cl,
            share_idx,
            pub_share_by_pubkey,
            builder_enabled,
            insecure_test: false,
        }
    }

    /// Builds a component that skips partial-signature verification on
    /// submit endpoints. Test use only.
    pub fn new_insecure(eth2_cl: Arc<EthBeaconNodeApiClient>, share_idx: u64) -> Self {
        Self {
            eth2_cl,
            share_idx,
            pub_share_by_pubkey: HashMap::new(),
            builder_enabled: false,
            insecure_test: true,
        }
    }
}

#[async_trait]
impl Handler for Component {
    async fn node_version(&self) -> Result<NodeVersionResponse, ApiError> {
        let (commit, _) = version::git_commit();
        let version = format!(
            "obolnetwork/pluto/{}-{}/{}-{}",
            *version::VERSION,
            commit,
            std::env::consts::ARCH,
            std::env::consts::OS,
        );

        Ok(NodeVersionResponse {
            data: NodeVersionData { version },
        })
    }

    async fn proposer_duties(
        &self,
        opts: ProposerDutiesOpts,
    ) -> Result<ProposerDutiesResponse, ApiError> {
        let request = GetProposerDutiesRequest::builder()
            .epoch(opts.epoch.to_string())
            .build()
            .map_err(|err| {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid epoch").with_source(
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
                )
            })?;

        let response = self
            .eth2_cl
            .get_proposer_duties(request)
            .await
            .map_err(|err| {
                ApiError::new(StatusCode::BAD_GATEWAY, "upstream proposer duties failed")
                    .with_source(std::io::Error::other(err.to_string()))
            })?;

        let mut payload = match response {
            GetProposerDutiesResponse::Ok(payload) => payload,
            other => {
                return Err(ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("unexpected upstream proposer duties response: {other:?}"),
                ));
            }
        };

        swap_proposer_pubshares(&mut payload.data, &self.pub_share_by_pubkey)?;

        Ok(payload)
    }

    async fn attester_duties(
        &self,
        _opts: AttesterDutiesOpts,
    ) -> Result<EthResponse<Vec<AttesterDuty>>, ApiError> {
        unimplemented!("attester_duties not yet ported")
    }

    async fn sync_committee_duties(
        &self,
        _opts: SyncCommitteeDutiesOpts,
    ) -> Result<EthResponse<Vec<SyncCommitteeDuty>>, ApiError> {
        unimplemented!("sync_committee_duties not yet ported")
    }

    async fn attestation_data(
        &self,
        _opts: AttestationDataOpts,
    ) -> Result<EthResponse<AttestationData>, ApiError> {
        unimplemented!("attestation_data not yet ported")
    }

    async fn submit_attestations(
        &self,
        _attestations: Vec<VersionedAttestation>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_attestations not yet ported")
    }

    async fn proposal(
        &self,
        _opts: ProposalOpts,
    ) -> Result<EthResponse<VersionedProposal>, ApiError> {
        unimplemented!("proposal not yet ported")
    }

    async fn submit_proposal(&self, _proposal: VersionedSignedProposal) -> Result<(), ApiError> {
        unimplemented!("submit_proposal not yet ported")
    }

    async fn submit_blinded_proposal(
        &self,
        _proposal: VersionedSignedBlindedProposal,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_blinded_proposal not yet ported")
    }

    async fn aggregate_attestation(
        &self,
        _opts: AggregateAttestationOpts,
    ) -> Result<EthResponse<VersionedAttestation>, ApiError> {
        unimplemented!("aggregate_attestation not yet ported")
    }

    async fn submit_aggregate_attestations(
        &self,
        _aggregates: Vec<VersionedSignedAggregateAndProof>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_aggregate_attestations not yet ported")
    }

    async fn beacon_committee_selections(
        &self,
        _selections: Vec<BeaconCommitteeSelection>,
    ) -> Result<EthResponse<Vec<BeaconCommitteeSelection>>, ApiError> {
        unimplemented!("beacon_committee_selections not yet ported")
    }

    async fn sync_committee_selections(
        &self,
        _selections: Vec<SyncCommitteeSelection>,
    ) -> Result<EthResponse<Vec<SyncCommitteeSelection>>, ApiError> {
        unimplemented!("sync_committee_selections not yet ported")
    }

    async fn validators(
        &self,
        _opts: ValidatorsOpts,
    ) -> Result<EthResponse<Vec<Validator>>, ApiError> {
        unimplemented!("validators not yet ported")
    }

    async fn submit_validator_registrations(
        &self,
        _registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_validator_registrations not yet ported")
    }

    async fn submit_voluntary_exit(&self, _exit: SignedVoluntaryExit) -> Result<(), ApiError> {
        unimplemented!("submit_voluntary_exit not yet ported")
    }

    async fn sync_committee_contribution(
        &self,
        _opts: SyncCommitteeContributionOpts,
    ) -> Result<EthResponse<SyncCommitteeContribution>, ApiError> {
        unimplemented!("sync_committee_contribution not yet ported")
    }

    async fn submit_sync_committee_contributions(
        &self,
        _contributions: Vec<SignedContributionAndProof>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_sync_committee_contributions not yet ported")
    }

    async fn submit_sync_committee_messages(
        &self,
        _messages: Vec<SyncCommitteeMessage>,
    ) -> Result<(), ApiError> {
        unimplemented!("submit_sync_committee_messages not yet ported")
    }
}

/// Rewrites each duty's root public key to this node's public share. Duties
/// whose pubkey is not in `pub_share_by_pubkey` are passed through unchanged
/// (the upstream returns all proposers for the epoch, not just ours).
fn swap_proposer_pubshares(
    duties: &mut [ProposerDuty],
    pub_share_by_pubkey: &HashMap<BLSPubKey, BLSPubKey>,
) -> Result<(), ApiError> {
    for duty in duties {
        let pubkey = parse_bls_pubkey(&duty.pubkey)?;
        if let Some(share) = pub_share_by_pubkey.get(&pubkey) {
            duty.pubkey = format_bls_pubkey(share);
        }
    }
    Ok(())
}

fn parse_bls_pubkey(s: &str) -> Result<BLSPubKey, ApiError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|err| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("invalid pubkey hex: {err}"),
        )
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("invalid pubkey length: got {}, want 48", bytes.len()),
        )
    })
}

fn format_bls_pubkey(pubkey: &BLSPubKey) -> String {
    format!("0x{}", hex::encode(pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_replaces_known_pubkeys_and_keeps_unknown() {
        let root = [0xAA_u8; 48];
        let share = [0xBB_u8; 48];
        let stranger = [0xCC_u8; 48];

        let map = HashMap::from([(root, share)]);

        let mut duties = vec![
            ProposerDuty {
                pubkey: format_bls_pubkey(&root),
                slot: "10".to_owned(),
                validator_index: "1".to_owned(),
            },
            ProposerDuty {
                pubkey: format_bls_pubkey(&stranger),
                slot: "11".to_owned(),
                validator_index: "2".to_owned(),
            },
        ];

        swap_proposer_pubshares(&mut duties, &map).unwrap();

        assert_eq!(duties[0].pubkey, format_bls_pubkey(&share));
        assert_eq!(duties[1].pubkey, format_bls_pubkey(&stranger));
    }

    #[test]
    fn swap_rejects_malformed_pubkey() {
        let mut duties = vec![ProposerDuty {
            pubkey: "0xnothex".to_owned(),
            slot: "0".to_owned(),
            validator_index: "0".to_owned(),
        }];
        let err = swap_proposer_pubshares(&mut duties, &HashMap::new()).unwrap_err();
        assert_eq!(err.status_code, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn node_version_formats_pluto_string() {
        // Use an unreachable upstream — node_version doesn't call it.
        let eth2_cl =
            Arc::new(EthBeaconNodeApiClient::with_base_url("http://127.0.0.1:0").unwrap());
        let component = Component::new_insecure(eth2_cl, 1);

        let response = component.node_version().await.unwrap();

        assert!(response.data.version.starts_with("obolnetwork/pluto/"));
        assert!(response.data.version.contains(std::env::consts::ARCH));
        assert!(response.data.version.contains(std::env::consts::OS));
    }
}
