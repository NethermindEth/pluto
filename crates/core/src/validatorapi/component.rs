//! Validator API [`Handler`] implementation.
//!
//! The component owns the upstream beacon-node client plus the public-key
//! and public-share mappings needed to translate between distributed-validator
//! root keys and this node's threshold-BLS share.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::http::StatusCode;
use pluto_eth2api::{
    EthBeaconNodeApiClient, GetAttesterDutiesRequest, GetAttesterDutiesResponse,
    GetProposerDutiesRequest, GetProposerDutiesResponse, GetSyncCommitteeDutiesRequest,
    GetSyncCommitteeDutiesResponse, spec::phase0::BLSPubKey,
};
use tokio::time::error::Elapsed;

use super::{
    error::ApiError,
    handler::Handler,
    types::{
        AggregateAttestationOpts, AttestationDataOpts, AttestationDataResponse, AttesterDutiesOpts,
        AttesterDutiesResponse, AttesterDuty, BeaconCommitteeSelection, EthResponse,
        NodeVersionData, NodeVersionResponse, ProposalOpts, ProposerDutiesOpts,
        ProposerDutiesResponse, ProposerDuty, SignedContributionAndProof,
        SignedValidatorRegistration, SignedVoluntaryExit, SyncCommitteeContribution,
        SyncCommitteeContributionOpts, SyncCommitteeDutiesOpts, SyncCommitteeDutiesResponse,
        SyncCommitteeDuty, SyncCommitteeMessage, SyncCommitteeSelection, Validator, ValidatorsOpts,
        VersionedAttestation, VersionedProposal, VersionedSignedAggregateAndProof,
        VersionedSignedBlindedProposal, VersionedSignedProposal,
    },
};
use crate::{
    dutydb::{Error as DutyDbError, MemDB},
    version,
};

/// Hard deadline for upstream beacon-node calls. Bounds the worst-case
/// handler latency when the upstream hangs or stalls. Mirrors Charon's
/// `defaultRequestTimeout` (`core/validatorapi/router.go:61`).
const UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard deadline for the `attestation_data` await on the local DutyDB.
/// Bounded so a request whose slot never produces consensus output cannot
/// hold a handler task indefinitely. Sized at roughly two slots so a real
/// attestation duty has time to flow through the pipeline.
const ATTESTATION_DATA_TIMEOUT: Duration = Duration::from_secs(24);

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
    /// In-memory DutyDB used to await consensus output (e.g. attestation
    /// data) produced by the rest of the pipeline.
    dutydb: Arc<MemDB>,
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
        dutydb: Arc<MemDB>,
        share_idx: u64,
        pub_share_by_pubkey: HashMap<BLSPubKey, BLSPubKey>,
        builder_enabled: bool,
    ) -> Self {
        Self {
            eth2_cl,
            dutydb,
            share_idx,
            pub_share_by_pubkey,
            builder_enabled,
            insecure_test: false,
        }
    }

    /// Builds a component that skips partial-signature verification on
    /// submit endpoints. Gated to test builds — `insecure_test: true` must
    /// never reach production, since later submit handlers consult this flag
    /// to bypass signature checks.
    #[cfg(test)]
    pub fn new_insecure(
        eth2_cl: Arc<EthBeaconNodeApiClient>,
        dutydb: Arc<MemDB>,
        share_idx: u64,
    ) -> Self {
        Self {
            eth2_cl,
            dutydb,
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
                ApiError::new(StatusCode::BAD_REQUEST, "invalid epoch")
                    .with_boxed_source(err.into())
            })?;

        let response = tokio::time::timeout(
            UPSTREAM_REQUEST_TIMEOUT,
            self.eth2_cl.get_proposer_duties(request),
        )
        .await
        .map_err(|_| upstream_timeout("proposer duties"))?
        .map_err(|err| upstream_call_failed("proposer duties", err.into()))?;

        let mut payload = match response {
            GetProposerDutiesResponse::Ok(payload) => payload,
            GetProposerDutiesResponse::BadRequest(body) => {
                return Err(upstream_status_error(
                    StatusCode::BAD_REQUEST,
                    "proposer duties",
                    body,
                ));
            }
            GetProposerDutiesResponse::ServiceUnavailable(body) => {
                return Err(upstream_status_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "proposer duties",
                    body,
                ));
            }
            other @ (GetProposerDutiesResponse::InternalServerError(_)
            | GetProposerDutiesResponse::Unknown) => {
                return Err(upstream_unexpected("proposer duties", other));
            }
        };

        swap_proposer_pubshares(&mut payload.data, &self.pub_share_by_pubkey)?;

        Ok(payload)
    }

    async fn attester_duties(
        &self,
        opts: AttesterDutiesOpts,
    ) -> Result<AttesterDutiesResponse, ApiError> {
        let request = GetAttesterDutiesRequest::builder()
            .epoch(opts.epoch.to_string())
            .body(opts.indices)
            .build()
            .map_err(|err| {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid attester duties request")
                    .with_boxed_source(err.into())
            })?;

        let response = tokio::time::timeout(
            UPSTREAM_REQUEST_TIMEOUT,
            self.eth2_cl.get_attester_duties(request),
        )
        .await
        .map_err(|_| upstream_timeout("attester duties"))?
        .map_err(|err| upstream_call_failed("attester duties", err.into()))?;

        let mut payload = match response {
            GetAttesterDutiesResponse::Ok(payload) => payload,
            GetAttesterDutiesResponse::BadRequest(body) => {
                return Err(upstream_status_error(
                    StatusCode::BAD_REQUEST,
                    "attester duties",
                    body,
                ));
            }
            GetAttesterDutiesResponse::ServiceUnavailable(body) => {
                return Err(upstream_status_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "attester duties",
                    body,
                ));
            }
            other @ (GetAttesterDutiesResponse::InternalServerError(_)
            | GetAttesterDutiesResponse::Unknown) => {
                return Err(upstream_unexpected("attester duties", other));
            }
        };

        swap_attester_pubshares(&mut payload.data, &self.pub_share_by_pubkey)?;

        Ok(payload)
    }

    async fn sync_committee_duties(
        &self,
        opts: SyncCommitteeDutiesOpts,
    ) -> Result<SyncCommitteeDutiesResponse, ApiError> {
        let request = GetSyncCommitteeDutiesRequest::builder()
            .epoch(opts.epoch.to_string())
            .body(opts.indices)
            .build()
            .map_err(|err| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid sync committee duties request",
                )
                .with_boxed_source(err.into())
            })?;

        let response = tokio::time::timeout(
            UPSTREAM_REQUEST_TIMEOUT,
            self.eth2_cl.get_sync_committee_duties(request),
        )
        .await
        .map_err(|_| upstream_timeout("sync committee duties"))?
        .map_err(|err| upstream_call_failed("sync committee duties", err.into()))?;

        let mut payload = match response {
            GetSyncCommitteeDutiesResponse::Ok(payload) => payload,
            GetSyncCommitteeDutiesResponse::BadRequest(body) => {
                return Err(upstream_status_error(
                    StatusCode::BAD_REQUEST,
                    "sync committee duties",
                    body,
                ));
            }
            GetSyncCommitteeDutiesResponse::ServiceUnavailable(body) => {
                return Err(upstream_status_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "sync committee duties",
                    body,
                ));
            }
            other @ (GetSyncCommitteeDutiesResponse::InternalServerError(_)
            | GetSyncCommitteeDutiesResponse::Unknown) => {
                return Err(upstream_unexpected("sync committee duties", other));
            }
        };

        swap_sync_committee_pubshares(&mut payload.data, &self.pub_share_by_pubkey)?;

        Ok(payload)
    }

    async fn attestation_data(
        &self,
        opts: AttestationDataOpts,
    ) -> Result<AttestationDataResponse, ApiError> {
        let data = tokio::time::timeout(
            ATTESTATION_DATA_TIMEOUT,
            self.dutydb
                .await_attestation(opts.slot, opts.committee_index),
        )
        .await
        .map_err(|_: Elapsed| {
            ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "attestation data not available before deadline",
            )
        })?
        .map_err(map_dutydb_error)?;

        Ok(AttestationDataResponse { data })
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

/// Builds the `ApiError` returned when an upstream beacon-node call elapses
/// past [`UPSTREAM_REQUEST_TIMEOUT`].
fn upstream_timeout(endpoint: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::GATEWAY_TIMEOUT,
        format!("upstream {endpoint} timed out"),
    )
}

/// Builds the `ApiError` returned when an upstream beacon-node call returns a
/// transport-level error. Boxed so `anyhow::Error` (which doesn't itself
/// implement `std::error::Error`) can be attached via `.into()`.
fn upstream_call_failed(
    endpoint: &'static str,
    err: Box<dyn std::error::Error + Send + Sync + 'static>,
) -> ApiError {
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        format!("upstream {endpoint} failed"),
    )
    .with_boxed_source(err)
}

/// Builds the `ApiError` returned when the upstream responds with a faithful
/// HTTP status that we propagate (e.g. 400, 503). The upstream body is
/// attached as a `source` for debug logging — never serialized into the
/// client-visible message.
fn upstream_status_error<B: std::fmt::Debug>(
    status: StatusCode,
    endpoint: &'static str,
    body: B,
) -> ApiError {
    ApiError::new(
        status,
        format!("upstream {endpoint} returned {}", status.as_u16()),
    )
    .with_source(std::io::Error::other(format!(
        "upstream {endpoint} body: {body:?}"
    )))
}

/// Builds the `ApiError` returned when the upstream responds with an
/// unexpected variant (e.g. `Unknown`, or `InternalServerError`). The variant
/// is attached as a `source` so the debug log retains it but the client
/// message stays generic.
fn upstream_unexpected<R: std::fmt::Debug>(endpoint: &'static str, response: R) -> ApiError {
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        format!("unexpected upstream {endpoint} response"),
    )
    .with_source(std::io::Error::other(format!(
        "upstream {endpoint} variant: {response:?}"
    )))
}

/// Maps a [`crate::dutydb::Error`] into the `ApiError` returned to the client
/// when an `attestation_data` await fails. `Shutdown` propagates as 503 so the
/// VC can retry; `AwaitDutyExpired` propagates as 408 — same as a timeout —
/// since the duty is gone and the data will never arrive. Anything else is a
/// programming error here and becomes 500.
fn map_dutydb_error(err: DutyDbError) -> ApiError {
    let (status, message) = match err {
        DutyDbError::Shutdown => (StatusCode::SERVICE_UNAVAILABLE, "dutydb is shutting down"),
        DutyDbError::AwaitDutyExpired => (
            StatusCode::REQUEST_TIMEOUT,
            "attestation duty expired before data was stored",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "await attestation failed",
        ),
    };
    ApiError::new(status, message).with_source(err)
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

/// Like [`swap_proposer_pubshares`] but for attester duties. Attester duties
/// only ever come back for validators owned by this cluster, so an unknown
/// pubkey indicates a misconfiguration and is rejected.
fn swap_attester_pubshares(
    duties: &mut [AttesterDuty],
    pub_share_by_pubkey: &HashMap<BLSPubKey, BLSPubKey>,
) -> Result<(), ApiError> {
    for duty in duties {
        let pubkey = parse_bls_pubkey(&duty.pubkey)?;
        let share = pub_share_by_pubkey.get(&pubkey).ok_or_else(|| {
            // Cluster/lock-file misconfiguration — the upstream returned a
            // well-formed duty, but this node has no share for that validator.
            // 500 (not 502): the failure is local, not gateway-level.
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "pubshare not found for attester duty",
            )
        })?;
        duty.pubkey = format_bls_pubkey(share);
    }
    Ok(())
}

/// Sync-committee duties variant of [`swap_attester_pubshares`].
fn swap_sync_committee_pubshares(
    duties: &mut [SyncCommitteeDuty],
    pub_share_by_pubkey: &HashMap<BLSPubKey, BLSPubKey>,
) -> Result<(), ApiError> {
    for duty in duties {
        let pubkey = parse_bls_pubkey(&duty.pubkey)?;
        let share = pub_share_by_pubkey.get(&pubkey).ok_or_else(|| {
            // See `swap_attester_pubshares` — same 500-not-502 reasoning.
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "pubshare not found for sync committee duty",
            )
        })?;
        duty.pubkey = format_bls_pubkey(share);
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
    use chrono::{DateTime, Utc};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        deadline::{DeadlineCalculator, DeadlinerTask, Result as DeadlineResult},
        dutydb::{UnsignedDataSet, UnsignedDutyData},
        signeddata::{
            AttestationData as SignedAttestationData, AttesterDuty as SignedAttesterDuty,
        },
        testutils::random_core_pub_key,
        types::{Duty, DutyType, SlotNumber},
        validatorapi::types::AttestationDataOpts,
    };

    /// Schedules every duty with a deadline at `MAX_UTC`, so duties are
    /// `Scheduled` but never naturally expire.
    struct FarFutureCalculator;

    impl DeadlineCalculator for FarFutureCalculator {
        fn deadline(&self, _: &Duty) -> DeadlineResult<Option<DateTime<Utc>>> {
            Ok(Some(DateTime::<Utc>::MAX_UTC))
        }
    }

    /// Build a Component backed by a real (but never-expiring) DutyDB plus a
    /// dummy upstream client. Useful for tests that only exercise endpoints
    /// served from the DB.
    fn make_test_component() -> (Component, Arc<MemDB>) {
        let cancel = CancellationToken::new();
        let (deadliner, _deadliner_rx) =
            DeadlinerTask::start(cancel.clone(), "validatorapi-tests", FarFutureCalculator);
        // Held to keep the eviction channel's sender alive so the dutydb's
        // `evict_rx` doesn't observe a closed channel.
        let (_evict_tx, evict_rx) = mpsc::channel(1);
        let dutydb = Arc::new(MemDB::new(deadliner, evict_rx, &cancel));
        let eth2_cl =
            Arc::new(EthBeaconNodeApiClient::with_base_url("http://127.0.0.1:0").unwrap());
        let component = Component::new_insecure(eth2_cl, Arc::clone(&dutydb), 1);
        (component, dutydb)
    }

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
    fn swap_attester_replaces_pubkeys_and_rejects_unknown() {
        let root = [0x11_u8; 48];
        let share = [0x22_u8; 48];
        let unknown = [0x33_u8; 48];

        let map = HashMap::from([(root, share)]);

        let mut duties = vec![AttesterDuty {
            pubkey: format_bls_pubkey(&root),
            slot: "1".to_owned(),
            committee_index: "0".to_owned(),
            committee_length: "16".to_owned(),
            committees_at_slot: "4".to_owned(),
            validator_committee_index: "0".to_owned(),
            validator_index: "5".to_owned(),
        }];

        swap_attester_pubshares(&mut duties, &map).unwrap();
        assert_eq!(duties[0].pubkey, format_bls_pubkey(&share));

        let mut stranger_duties = vec![AttesterDuty {
            pubkey: format_bls_pubkey(&unknown),
            slot: "2".to_owned(),
            committee_index: "0".to_owned(),
            committee_length: "16".to_owned(),
            committees_at_slot: "4".to_owned(),
            validator_committee_index: "0".to_owned(),
            validator_index: "6".to_owned(),
        }];
        let err = swap_attester_pubshares(&mut stranger_duties, &map).unwrap_err();
        assert_eq!(err.status_code, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn swap_sync_committee_replaces_pubkeys_and_rejects_unknown() {
        let root = [0x44_u8; 48];
        let share = [0x55_u8; 48];
        let unknown = [0x66_u8; 48];

        let map = HashMap::from([(root, share)]);

        let mut duties = vec![SyncCommitteeDuty {
            pubkey: format_bls_pubkey(&root),
            validator_index: "12".to_owned(),
            validator_sync_committee_indices: vec!["0".to_owned()],
        }];
        swap_sync_committee_pubshares(&mut duties, &map).unwrap();
        assert_eq!(duties[0].pubkey, format_bls_pubkey(&share));

        let mut stranger = vec![SyncCommitteeDuty {
            pubkey: format_bls_pubkey(&unknown),
            validator_index: "13".to_owned(),
            validator_sync_committee_indices: vec![],
        }];
        let err = swap_sync_committee_pubshares(&mut stranger, &map).unwrap_err();
        assert_eq!(err.status_code, StatusCode::INTERNAL_SERVER_ERROR);
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
        let (component, _db) = make_test_component();

        let response = component.node_version().await.unwrap();

        assert!(response.data.version.starts_with("obolnetwork/pluto/"));
        assert!(response.data.version.contains(std::env::consts::ARCH));
        assert!(response.data.version.contains(std::env::consts::OS));
    }

    #[tokio::test]
    async fn attestation_data_returns_data_stored_in_dutydb() {
        const SLOT: u64 = 100;
        const COMM_IDX: u64 = 4;
        const V_IDX: u64 = 1;

        let (component, db) = make_test_component();

        let unsigned = SignedAttestationData {
            data: pluto_eth2api::spec::phase0::AttestationData {
                slot: SLOT,
                index: COMM_IDX,
                beacon_block_root: [0x11; 32],
                source: pluto_eth2api::spec::phase0::Checkpoint::default(),
                target: pluto_eth2api::spec::phase0::Checkpoint::default(),
            },
            duty: SignedAttesterDuty {
                slot: SLOT,
                validator_index: V_IDX,
                committee_index: COMM_IDX,
                committee_length: 8,
                committees_at_slot: 1,
                validator_committee_index: 0,
            },
        };
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(unsigned.clone()),
        );
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Attester), set)
            .await
            .unwrap();

        let response = component
            .attestation_data(AttestationDataOpts {
                slot: SLOT,
                committee_index: COMM_IDX,
            })
            .await
            .unwrap();
        assert_eq!(response.data.slot, SLOT);
        assert_eq!(response.data.index, COMM_IDX);
        assert_eq!(response.data.beacon_block_root, [0x11; 32]);
    }

    /// Storing `(SLOT, COMM_IDX)` must NOT satisfy an `attestation_data`
    /// request for `(SLOT, COMM_IDX + 1)`. Verifies the dutydb is keyed on
    /// the full `(slot, committee_index)` tuple, not just the slot.
    #[tokio::test(start_paused = true)]
    async fn attestation_data_does_not_resolve_for_wrong_committee_index() {
        const SLOT: u64 = 200;
        const COMM_IDX: u64 = 7;

        let (component, db) = make_test_component();

        let unsigned = SignedAttestationData {
            data: pluto_eth2api::spec::phase0::AttestationData {
                slot: SLOT,
                index: COMM_IDX,
                beacon_block_root: [0x22; 32],
                source: pluto_eth2api::spec::phase0::Checkpoint::default(),
                target: pluto_eth2api::spec::phase0::Checkpoint::default(),
            },
            duty: SignedAttesterDuty {
                slot: SLOT,
                validator_index: 9,
                committee_index: COMM_IDX,
                committee_length: 8,
                committees_at_slot: 1,
                validator_committee_index: 0,
            },
        };
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(unsigned),
        );
        db.store(Duty::new(SlotNumber::new(SLOT), DutyType::Attester), set)
            .await
            .unwrap();

        // Auto-advance past the handler timeout so the await trips on the
        // wrong committee_index, not on the existing one.
        let err = component
            .attestation_data(AttestationDataOpts {
                slot: SLOT,
                committee_index: COMM_IDX + 1,
            })
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::REQUEST_TIMEOUT);
    }

    /// Verifies the handler enforces `ATTESTATION_DATA_TIMEOUT` — an
    /// `await_attestation` for a slot that is never stored returns 408
    /// instead of hanging.
    #[tokio::test(start_paused = true)]
    async fn attestation_data_times_out_when_data_never_arrives() {
        let (component, _db) = make_test_component();

        let err = component
            .attestation_data(AttestationDataOpts {
                slot: 999,
                committee_index: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::REQUEST_TIMEOUT);
    }

    /// Verifies that when the dutydb evicts the awaited duty (via the
    /// deadliner), the in-flight handler exits promptly with
    /// `REQUEST_TIMEOUT` instead of parking on the notify forever.
    #[tokio::test]
    async fn attestation_data_returns_408_when_duty_is_evicted() {
        use tokio::sync::mpsc::channel;

        const SLOT: u64 = 333;
        const COMM_IDX: u64 = 1;

        // Hand-build a Component whose dutydb shares its eviction channel
        // with the test, so we can drive eviction deterministically.
        let cancel = CancellationToken::new();
        let (deadliner, _deadliner_rx) =
            DeadlinerTask::start(cancel.clone(), "validatorapi-tests", FarFutureCalculator);
        let (trim_tx, trim_rx) = channel::<Duty>(8);
        let dutydb = Arc::new(MemDB::new(deadliner, trim_rx, &cancel));
        let eth2_cl =
            Arc::new(EthBeaconNodeApiClient::with_base_url("http://127.0.0.1:0").unwrap());
        let component = Component::new_insecure(eth2_cl, Arc::clone(&dutydb), 1);

        // Start an await before any data is stored.
        let waiter = {
            let component = Arc::new(component);
            let c = Arc::clone(&component);
            tokio::spawn(async move {
                c.attestation_data(AttestationDataOpts {
                    slot: SLOT,
                    committee_index: COMM_IDX,
                })
                .await
            })
        };

        // Yield so the waiter parks.
        tokio::task::yield_now().await;

        // Simulate the deadliner emitting an eviction for this slot…
        trim_tx
            .send(Duty::new(SlotNumber::new(SLOT), DutyType::Attester))
            .await
            .unwrap();

        // …then trigger eviction processing by storing an unrelated duty.
        let unsigned = SignedAttestationData {
            data: pluto_eth2api::spec::phase0::AttestationData {
                slot: SLOT.saturating_add(1),
                index: 0,
                beacon_block_root: [0x33; 32],
                source: pluto_eth2api::spec::phase0::Checkpoint::default(),
                target: pluto_eth2api::spec::phase0::Checkpoint::default(),
            },
            duty: SignedAttesterDuty {
                slot: SLOT.saturating_add(1),
                validator_index: 0,
                committee_index: 0,
                committee_length: 8,
                committees_at_slot: 1,
                validator_committee_index: 0,
            },
        };
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(unsigned),
        );
        dutydb
            .store(
                Duty::new(SlotNumber::new(SLOT.saturating_add(1)), DutyType::Attester),
                set,
            )
            .await
            .unwrap();

        let err = waiter.await.unwrap().unwrap_err();
        assert_eq!(err.status_code, StatusCode::REQUEST_TIMEOUT);
    }

    /// Verifies that dropping the handler future releases the dutydb
    /// waiter — the next store() should not see a hanging reader on the
    /// state lock.
    #[tokio::test]
    async fn attestation_data_drops_waiter_when_future_dropped() {
        let (component, db) = make_test_component();
        let component = Arc::new(component);

        let waiter = {
            let component = Arc::clone(&component);
            tokio::spawn(async move {
                component
                    .attestation_data(AttestationDataOpts {
                        slot: 4242,
                        committee_index: 0,
                    })
                    .await
            })
        };

        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;

        // Confirm db is still usable — store should not deadlock.
        let unsigned = SignedAttestationData {
            data: pluto_eth2api::spec::phase0::AttestationData {
                slot: 1,
                index: 0,
                beacon_block_root: [0x44; 32],
                source: pluto_eth2api::spec::phase0::Checkpoint::default(),
                target: pluto_eth2api::spec::phase0::Checkpoint::default(),
            },
            duty: SignedAttesterDuty {
                slot: 1,
                validator_index: 0,
                committee_index: 0,
                committee_length: 8,
                committees_at_slot: 1,
                validator_committee_index: 0,
            },
        };
        let mut set = UnsignedDataSet::new();
        set.insert(
            random_core_pub_key(),
            UnsignedDutyData::Attestation(unsigned),
        );
        db.store(Duty::new(SlotNumber::new(1), DutyType::Attester), set)
            .await
            .unwrap();
    }

    /// `map_dutydb_error` covers the three distinguishable variants from
    /// `crate::dutydb::Error`.
    #[test]
    fn map_dutydb_error_status_codes() {
        assert_eq!(
            map_dutydb_error(DutyDbError::Shutdown).status_code,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            map_dutydb_error(DutyDbError::AwaitDutyExpired).status_code,
            StatusCode::REQUEST_TIMEOUT
        );
        assert_eq!(
            map_dutydb_error(DutyDbError::UnsupportedDutyType).status_code,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// `upstream_status_error` keeps the upstream response body out of the
    /// client-visible message but preserves it on `source()` so it lands in
    /// the debug log.
    #[test]
    fn upstream_status_error_does_not_leak_body_into_message() {
        use pluto_eth2api::BlindedBlock400Response;

        let body = BlindedBlock400Response {
            code: 503.0,
            message: "secret upstream stacktrace path=/etc/secret".to_owned(),
            stacktraces: Some(vec!["at /etc/secret/lighthouse:42".to_owned()]),
        };
        let err = upstream_status_error(StatusCode::SERVICE_UNAVAILABLE, "attester duties", body);

        assert_eq!(err.status_code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!err.message.contains("secret"));
        assert!(!err.message.contains("stacktrace"));
        // But the source carries it for debug logging.
        let src = err.source.as_ref().unwrap().to_string();
        assert!(src.contains("secret"));
    }

    /// `upstream_unexpected` mirrors `upstream_status_error`'s no-leak shape
    /// for the `Unknown` / `InternalServerError` arms.
    #[test]
    fn upstream_unexpected_does_not_leak_variant_into_message() {
        let err = upstream_unexpected("attester duties", GetAttesterDutiesResponse::Unknown);
        assert_eq!(err.status_code, StatusCode::BAD_GATEWAY);
        assert!(!err.message.contains("Unknown"));
        assert!(err.source.as_ref().unwrap().to_string().contains("Unknown"));
    }
}
