//! Validator API HTTP router.
//!
//! The endpoint table preserves the order of the upstream definition,
//! including which endpoints unconditionally respond `404`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use serde::Deserialize;

/// Cap on the `POST /eth/v1/validator/duties/{attester,sync}/{epoch}` request
/// bodies. A realistic cluster ships at most a few thousand validator indices;
/// 64 KiB still allows ~10k indices in either numeric or string encoding,
/// well above any plausible workload.
const DUTIES_BODY_LIMIT: usize = 64 * 1024;

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
            duties_post(attester_duties),
        )
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(proposer_duties),
        )
        .route(
            "/eth/v1/validator/duties/sync/{epoch}",
            duties_post(sync_committee_duties),
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
    indices: Result<Json<ValIndexes>, JsonRejection>,
) -> Result<Json<AttesterDutiesResponse>, ApiError> {
    let Json(indices) = indices.map_err(json_rejection_to_api_error)?;
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
    indices: Result<Json<ValIndexes>, JsonRejection>,
) -> Result<Json<SyncCommitteeDutiesResponse>, ApiError> {
    let Json(indices) = indices.map_err(json_rejection_to_api_error)?;
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
    query: Result<Query<AttestationDataQuery>, QueryRejection>,
) -> Result<Json<AttestationDataResponse>, ApiError> {
    let Query(query) = query.map_err(query_rejection_to_api_error)?;
    let response = state
        .handler
        .attestation_data(AttestationDataOpts {
            slot: query.slot,
            committee_index: query.committee_index,
        })
        .await?;

    Ok(Json(response))
}

/// Wraps a `POST /eth/v1/validator/duties/*` handler with a body-size cap
/// and the Charon-parity content-type policy. The cap is local to these
/// two routes so unrelated POST handlers (e.g. `submit_attestations`) keep
/// axum's default 2 MiB.
fn duties_post<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler)
        .route_layer(DefaultBodyLimit::max(DUTIES_BODY_LIMIT))
        .route_layer(middleware::from_fn(enforce_json_content_type))
}

/// Matches Charon's content-type handling at `core/validatorapi/router.go:365`:
/// a missing `Content-Type` is treated as `application/json`; an unrecognized
/// content type is rejected with `415 Unsupported Media Type`. SSZ is not
/// supported yet — when it lands, this is the right seam to extend.
///
/// Without this layer, axum's `Json` extractor would reject a missing header
/// with `MissingJsonContentType`, which our envelope normalises to `400` —
/// diverging from Charon, which lets VCs that don't set the header through.
async fn enforce_json_content_type(mut req: Request, next: Next) -> Result<Response, ApiError> {
    match req.headers().get(header::CONTENT_TYPE) {
        None => {
            req.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        Some(value) => {
            let s = value.to_str().unwrap_or("");
            if !s.contains("application/json") {
                return Err(ApiError::new(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    format!("unsupported media type {s}"),
                ));
            }
        }
    }
    Ok(next.run(req).await)
}

/// Renders an axum query-extractor rejection as Pluto's standard
/// [`ApiError`] body shape, so all 4xx responses from this router share the
/// same `{ "code", "message" }` schema.
fn query_rejection_to_api_error(rejection: QueryRejection) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "invalid query parameters")
        .with_source(std::io::Error::other(rejection.body_text()))
}

/// Renders an axum JSON body-extractor rejection as Pluto's standard
/// [`ApiError`] body shape, so it shares the `{ "code", "message" }` schema
/// instead of axum's default plain-text response.
///
/// Genuine parse failures — malformed JSON (`400`) and wrong element type
/// (`422`) — are normalised to a uniform `400`, matching Charon's `unmarshal`,
/// which returns `400` for all body unmarshal failures. Content-Type rejections
/// no longer reach this function: [`enforce_json_content_type`] intercepts
/// them upstream so missing/JSON requests pass through and non-JSON requests
/// return `415`. The body-size-limit rejection from [`DefaultBodyLimit`]
/// surfaces here (the limit is enforced as the `Json` extractor reads the
/// body); its `413 Payload Too Large` is preserved, since that is Pluto's
/// DoS defense rather than a parse error.
fn json_rejection_to_api_error(rejection: JsonRejection) -> ApiError {
    let (status, message) = match rejection.status() {
        StatusCode::PAYLOAD_TOO_LARGE => (StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
        _ => (StatusCode::BAD_REQUEST, "invalid request body"),
    };
    ApiError::new(status, message).with_source(std::io::Error::other(rejection.body_text()))
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
            Ok(Json(ValIndexes(vec!["7".to_owned()]))),
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
            Ok(Json(ValIndexes(vec!["9".to_owned()]))),
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
            Ok(Query(AttestationDataQuery {
                slot: 99,
                committee_index: 3,
            })),
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

    /// Verifies the manual `Query` rejection path emits the same
    /// `{ code, message }` envelope as the rest of the router, instead of
    /// axum's default plain-text 400.
    #[tokio::test]
    async fn attestation_data_returns_api_error_shape_on_bad_query() {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;

        let handler = TestHandler::default().with_attestation_data(AttestationDataResponse {
            data: phase0::AttestationData {
                slot: 0,
                index: 0,
                beacon_block_root: [0; 32],
                source: phase0::Checkpoint::default(),
                target: phase0::Checkpoint::default(),
            },
        });
        let app = new_router(Arc::new(handler), false);

        // Missing `committee_index`.
        let req = Request::builder()
            .uri("/eth/v1/validator/attestation_data?slot=10")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], 400);
        assert!(json["message"].is_string());

        // Non-numeric `slot`.
        let req = Request::builder()
            .uri("/eth/v1/validator/attestation_data?slot=foo&committee_index=1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], 400);
    }

    /// Verifies the body-limit layer on `POST /eth/v1/validator/duties/*`
    /// rejects oversized bodies — defense against the `Vec<u64>` parse
    /// amplification on the duties endpoints.
    #[tokio::test]
    async fn attester_duties_rejects_oversized_body() {
        use axum::{
            body::Body,
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let handler = TestHandler::default();
        let app = new_router(Arc::new(handler), false);

        // 128 KiB of zeros — well past the 64 KiB cap, valid JSON or not.
        let big = vec![b'0'; 128 * 1024];
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/duties/attester/42")
            .header("content-type", "application/json")
            .header("content-length", big.len())
            .body(Body::from(big))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// A malformed duties body emits the same `{ code, message }` envelope and
    /// uniform 400 as the rest of the router, rather than axum's default
    /// plain-text rejection (which would be 400 for a syntax error but 422 for
    /// a type error). Mirrors Charon's `unmarshal`, which returns 400 for every
    /// body parse failure.
    #[tokio::test]
    async fn attester_duties_returns_api_error_shape_on_bad_body() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let app = new_router(Arc::new(TestHandler::default()), false);

        // Valid JSON, wrong shape (object, not an array) — axum's default
        // would surface this as a 422 type error.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/duties/attester/42")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"not":"an array"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], 400);
        assert!(json["message"].is_string());
    }

    /// Charon-parity: a duties request that omits `Content-Type` is
    /// treated as `application/json` rather than rejected — the
    /// `enforce_json_content_type` middleware injects the header before
    /// the `Json` extractor sees the request. See `core/validatorapi/
    /// router.go:365` (`if contentHeader == "" || ...`).
    #[tokio::test]
    async fn attester_duties_accepts_missing_content_type() {
        use axum::{
            body::Body,
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let handler = TestHandler::default().with_attester_duties(AttesterDutiesResponse {
            data: vec![],
            dependent_root: "0x00".to_owned(),
            execution_optimistic: false,
        });
        let app = new_router(Arc::new(handler), false);

        // No Content-Type header at all.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/duties/attester/42")
            .body(Body::from("[]"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Charon-parity: a duties request with a non-JSON `Content-Type`
    /// returns `415 Unsupported Media Type`, not the `400` that the
    /// generic body-parse normaliser would produce.
    #[tokio::test]
    async fn attester_duties_rejects_non_json_content_type() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let app = new_router(Arc::new(TestHandler::default()), false);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/duties/attester/42")
            .header("content-type", "text/plain")
            .body(Body::from("[]"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], 415);
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|m| m.contains("text/plain"))
        );
    }

    /// `[]` is a valid request body — the upstream returns an empty duty
    /// list — and `ValIndexes` should accept it.
    #[test]
    fn val_indexes_accepts_empty_array() {
        let v: ValIndexes = serde_json::from_str("[]").unwrap();
        assert!(v.0.is_empty());
    }

    /// Mixed numeric + string elements are accepted; each element is
    /// validated independently. The previous untagged-enum implementation
    /// rejected this entirely.
    #[test]
    fn val_indexes_accepts_mixed_elements() {
        let v: ValIndexes = serde_json::from_str(r#"[1, "2", 3, "4"]"#).unwrap();
        assert_eq!(v.0, vec!["1", "2", "3", "4"]);
    }

    /// Caps the request to `VAL_INDEXES_MAX_LEN` elements.
    #[test]
    fn val_indexes_rejects_oversized_array() {
        use crate::validatorapi::types::VAL_INDEXES_MAX_LEN;

        let too_many = (0..=VAL_INDEXES_MAX_LEN)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("[{too_many}]");
        let err = serde_json::from_str::<ValIndexes>(&json).unwrap_err();
        assert!(err.to_string().contains("too many validator indices"));
    }

    /// Negative integers are rejected (validator indices are u64).
    #[test]
    fn val_indexes_rejects_negative_numbers() {
        let bad = serde_json::from_str::<ValIndexes>("[-1]");
        assert!(bad.is_err());
    }
}
