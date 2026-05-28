//! Validator API HTTP router.
//!
//! The endpoint table preserves the order of the upstream definition,
//! including which endpoints unconditionally respond `404`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;

use super::{
    error::ApiError,
    handler::Handler,
    types::{
        AttestationDataOpts, AttestationDataResponse, AttesterDutiesOpts, AttesterDutiesResponse,
        CommitteeIndex, NodeVersionResponse, ProposerDutiesOpts, ProposerDutiesResponse,
        SyncCommitteeDutiesOpts, SyncCommitteeDutiesResponse, ValIndexes,
    },
};

/// Query parameters for `GET /eth/v1/validator/attestation_data`.
#[derive(Debug, Clone, Deserialize)]
struct AttestationDataQuery {
    slot: u64,
    committee_index: CommitteeIndex,
}

/// Shared router state. Cloned per request via [`Arc`].
pub(super) struct AppState {
    /// Request handler invoked by each route.
    pub handler: Arc<dyn Handler>,
    /// Whether builder mode is enabled. Read by `propose_block_v3`.
    #[allow(dead_code, reason = "consumed by propose_block_v3 in a later PR")]
    pub builder_enabled: bool,
}

/// Builds the validator API HTTP router.
///
/// Registers the distributed-validator-related endpoints and a fallback
/// that reverse-proxies everything else to the upstream beacon node.
///
/// `builder_enabled` is consumed by `propose_block_v3` to maximise the
/// builder boost factor.
pub fn new_router(handler: Arc<dyn Handler>, builder_enabled: bool) -> Router {
    let state = Arc::new(AppState {
        handler,
        builder_enabled,
    });

    Router::new()
        .route(
            "/eth/v1/validator/duties/attester/{epoch}",
            post(attester_duties),
        )
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(proposer_duties),
        )
        .route(
            "/eth/v1/validator/duties/sync/{epoch}",
            post(sync_committee_duties),
        )
        .route("/eth/v1/validator/attestation_data", get(attestation_data))
        .route("/eth/v1/beacon/pool/attestations", post(respond_404))
        .route(
            "/eth/v2/beacon/pool/attestations",
            post(submit_attestations),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators",
            get(get_validators).post(get_validators),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
            get(get_validator),
        )
        .route("/eth/v2/validator/blocks/{slot}", get(respond_404))
        .route("/eth/v1/validator/blinded_blocks/{slot}", get(respond_404))
        .route("/eth/v3/validator/blocks/{slot}", get(propose_block_v3))
        .route("/eth/v1/beacon/blocks", post(submit_proposal))
        .route("/eth/v2/beacon/blocks", post(submit_proposal))
        .route("/eth/v1/beacon/blinded_blocks", post(submit_blinded_block))
        .route("/eth/v2/beacon/blinded_blocks", post(submit_blinded_block))
        .route(
            "/eth/v1/validator/register_validator",
            post(submit_validator_registrations),
        )
        .route("/eth/v1/beacon/pool/voluntary_exits", post(submit_exit))
        .route("/teku_proposer_config", get(respond_404))
        .route("/proposer_config", get(respond_404))
        .route(
            "/eth/v1/validator/beacon_committee_selections",
            post(beacon_committee_selections),
        )
        .route("/eth/v1/validator/aggregate_attestation", get(respond_404))
        .route(
            "/eth/v2/validator/aggregate_attestation",
            get(aggregate_attestation),
        )
        .route("/eth/v1/validator/aggregate_and_proofs", post(respond_404))
        .route(
            "/eth/v2/validator/aggregate_and_proofs",
            post(submit_aggregate_attestations),
        )
        .route(
            "/eth/v1/beacon/pool/sync_committees",
            post(submit_sync_committee_messages),
        )
        .route(
            "/eth/v1/validator/sync_committee_contribution",
            get(sync_committee_contribution),
        )
        .route(
            "/eth/v1/validator/contribution_and_proofs",
            post(submit_contribution_and_proofs),
        )
        .route(
            "/eth/v1/validator/prepare_beacon_proposer",
            post(submit_proposal_preparations),
        )
        .route(
            "/eth/v1/validator/sync_committee_selections",
            post(sync_committee_selections),
        )
        .route("/eth/v1/node/version", get(node_version))
        .fallback(proxy_handler)
        .with_state(state)
}

async fn attester_duties(
    State(state): State<Arc<AppState>>,
    Path(epoch): Path<u64>,
    Json(indices): Json<ValIndexes>,
) -> Result<Json<AttesterDutiesResponse>, ApiError> {
    let response = state
        .handler
        .attester_duties(AttesterDutiesOpts {
            epoch,
            indices: indices.0,
        })
        .await?;

    Ok(Json(response))
}

async fn proposer_duties(
    State(state): State<Arc<AppState>>,
    Path(epoch): Path<u64>,
) -> Result<Json<ProposerDutiesResponse>, ApiError> {
    let response = state
        .handler
        .proposer_duties(ProposerDutiesOpts { epoch })
        .await?;

    Ok(Json(response))
}

async fn sync_committee_duties(
    State(state): State<Arc<AppState>>,
    Path(epoch): Path<u64>,
    Json(indices): Json<ValIndexes>,
) -> Result<Json<SyncCommitteeDutiesResponse>, ApiError> {
    let response = state
        .handler
        .sync_committee_duties(SyncCommitteeDutiesOpts {
            epoch,
            indices: indices.0,
        })
        .await?;

    Ok(Json(response))
}

async fn attestation_data(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AttestationDataQuery>,
) -> Result<Json<AttestationDataResponse>, ApiError> {
    let response = state
        .handler
        .attestation_data(AttestationDataOpts {
            slot: query.slot,
            committee_index: query.committee_index,
        })
        .await?;

    Ok(Json(response))
}

async fn submit_attestations() {
    todo!("vapi: submit_attestations");
}

async fn get_validators() {
    todo!("vapi: get_validators");
}

async fn get_validator() {
    todo!("vapi: get_validator");
}

async fn propose_block_v3() {
    todo!("vapi: propose_block_v3");
}

async fn submit_proposal() {
    todo!("vapi: submit_proposal");
}

async fn submit_blinded_block() {
    todo!("vapi: submit_blinded_block");
}

async fn submit_validator_registrations() {
    todo!("vapi: submit_validator_registrations");
}

async fn submit_exit() {
    todo!("vapi: submit_exit");
}

async fn beacon_committee_selections() {
    todo!("vapi: beacon_committee_selections");
}

async fn aggregate_attestation() {
    todo!("vapi: aggregate_attestation");
}

async fn submit_aggregate_attestations() {
    todo!("vapi: submit_aggregate_attestations");
}

async fn submit_sync_committee_messages() {
    todo!("vapi: submit_sync_committee_messages");
}

async fn sync_committee_contribution() {
    todo!("vapi: sync_committee_contribution");
}

async fn submit_contribution_and_proofs() {
    todo!("vapi: submit_contribution_and_proofs");
}

async fn submit_proposal_preparations() {
    todo!("vapi: submit_proposal_preparations");
}

async fn sync_committee_selections() {
    todo!("vapi: sync_committee_selections");
}

async fn node_version(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NodeVersionResponse>, ApiError> {
    let response = state.handler.node_version().await?;

    Ok(Json(response))
}

async fn respond_404() -> impl IntoResponse {
    ApiError::not_found()
}

async fn proxy_handler() {
    todo!("vapi: proxy_handler");
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_eth2api::spec::phase0;

    use crate::validatorapi::{
        testutils::TestHandler,
        types::{
            AttestationDataResponse, AttesterDutiesResponse, AttesterDuty, ProposerDutiesResponse,
            ProposerDuty, SyncCommitteeDutiesResponse, SyncCommitteeDuty, ValIndexes,
        },
    };

    #[tokio::test]
    async fn node_version_wraps_handler_value() {
        let state = Arc::new(AppState {
            handler: Arc::new(TestHandler::with_version("pluto/test/v1.0")),
            builder_enabled: false,
        });

        let Json(body) = node_version(State(state)).await.unwrap();

        assert_eq!(body.data.version, "pluto/test/v1.0");
    }

    #[tokio::test]
    async fn attester_duties_wraps_handler_value() {
        let duty = AttesterDuty {
            pubkey: "0xaabbccddeeff".to_owned(),
            slot: "12".to_owned(),
            committee_index: "3".to_owned(),
            committee_length: "16".to_owned(),
            committees_at_slot: "4".to_owned(),
            validator_committee_index: "2".to_owned(),
            validator_index: "7".to_owned(),
        };
        let handler = TestHandler::default().with_attester_duties(AttesterDutiesResponse {
            data: vec![duty],
            dependent_root: "0xab".to_owned(),
            execution_optimistic: false,
        });
        let state = Arc::new(AppState {
            handler: Arc::new(handler),
            builder_enabled: false,
        });

        let Json(body) = attester_duties(
            State(state),
            Path(42u64),
            Json(ValIndexes(vec!["7".to_owned()])),
        )
        .await
        .unwrap();

        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["dependent_root"], "0xab");
        assert_eq!(json["execution_optimistic"], false);
        assert_eq!(json["data"][0]["slot"], "12");
        assert_eq!(json["data"][0]["committee_index"], "3");
        assert_eq!(json["data"][0]["validator_index"], "7");
    }

    #[tokio::test]
    async fn sync_committee_duties_wraps_handler_value() {
        let duty = SyncCommitteeDuty {
            pubkey: "0x112233".to_owned(),
            validator_index: "9".to_owned(),
            validator_sync_committee_indices: vec!["0".to_owned(), "5".to_owned()],
        };
        let handler =
            TestHandler::default().with_sync_committee_duties(SyncCommitteeDutiesResponse {
                data: vec![duty],
                execution_optimistic: true,
            });
        let state = Arc::new(AppState {
            handler: Arc::new(handler),
            builder_enabled: false,
        });

        let Json(body) = sync_committee_duties(
            State(state),
            Path(7u64),
            Json(ValIndexes(vec!["9".to_owned()])),
        )
        .await
        .unwrap();

        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["execution_optimistic"], true);
        assert_eq!(json["data"][0]["validator_index"], "9");
        assert_eq!(json["data"][0]["validator_sync_committee_indices"][1], "5");
    }

    #[tokio::test]
    async fn attestation_data_wraps_handler_value() {
        let data = phase0::AttestationData {
            slot: 99,
            index: 3,
            beacon_block_root: [0xaa; 32],
            source: phase0::Checkpoint {
                epoch: 7,
                root: [0xbb; 32],
            },
            target: phase0::Checkpoint {
                epoch: 8,
                root: [0xcc; 32],
            },
        };
        let handler =
            TestHandler::default().with_attestation_data(AttestationDataResponse { data });
        let state = Arc::new(AppState {
            handler: Arc::new(handler),
            builder_enabled: false,
        });

        let Json(body) = attestation_data(
            State(state),
            Query(AttestationDataQuery {
                slot: 99,
                committee_index: 3,
            }),
        )
        .await
        .unwrap();

        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["data"]["slot"], "99");
        assert_eq!(json["data"]["index"], "3");
        assert_eq!(json["data"]["source"]["epoch"], "7");
    }

    #[test]
    fn val_indexes_accepts_numbers_and_strings() {
        let nums: ValIndexes = serde_json::from_str("[1, 2, 3]").unwrap();
        assert_eq!(nums.0, vec!["1", "2", "3"]);

        let strs: ValIndexes = serde_json::from_str(r#"["4", "5"]"#).unwrap();
        assert_eq!(strs.0, vec!["4", "5"]);

        let bad = serde_json::from_str::<ValIndexes>(r#"["not-a-number"]"#);
        assert!(bad.is_err());
    }

    #[tokio::test]
    async fn proposer_duties_wraps_handler_value() {
        let duty = ProposerDuty {
            pubkey: "0xaabbccddeeff".to_owned(),
            slot: "1234".to_owned(),
            validator_index: "7".to_owned(),
        };
        let handler = TestHandler::default().with_proposer_duties(ProposerDutiesResponse {
            data: vec![duty],
            dependent_root: "0xcd".to_owned(),
            execution_optimistic: true,
        });
        let state = Arc::new(AppState {
            handler: Arc::new(handler),
            builder_enabled: false,
        });

        let Json(body) = proposer_duties(State(state), Path(99u64)).await.unwrap();

        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["dependent_root"], "0xcd");
        assert_eq!(json["execution_optimistic"], true);
        assert_eq!(json["data"][0]["slot"], "1234");
        assert_eq!(json["data"][0]["validator_index"], "7");
        assert_eq!(json["data"][0]["pubkey"], "0xaabbccddeeff");
    }
}
