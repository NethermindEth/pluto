//! Validator API HTTP router.
//!
//! The endpoint table preserves the order of the upstream definition,
//! including which endpoints unconditionally respond `404`.

use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};

use super::{error::ApiError, handler::Handler};

/// Builds the validator API HTTP router.
///
/// Registers the distributed-validator-related endpoints and a fallback
/// that reverse-proxies everything else to the upstream beacon node.
///
/// `_handler` will be threaded into Axum router state once request bodies
/// and responses are wired. `_builder_enabled` is consumed only by
/// `propose_block_v3`.
pub fn new_router<H: Handler>(_handler: H, _builder_enabled: bool) -> Router {
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
}

async fn attester_duties() {
    todo!("vapi: attester_duties");
}

async fn proposer_duties() {
    todo!("vapi: proposer_duties");
}

async fn sync_committee_duties() {
    todo!("vapi: sync_committee_duties");
}

async fn attestation_data() {
    todo!("vapi: attestation_data");
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

async fn node_version() {
    todo!("vapi: node_version");
}

async fn respond_404() -> impl IntoResponse {
    ApiError::not_found()
}

async fn proxy_handler() {
    todo!("vapi: proxy_handler");
}
