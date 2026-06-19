//! Validator API HTTP router.
//!
//! The endpoint table preserves the order of the upstream definition,
//! including which endpoints unconditionally respond `404`.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, Query, RawQuery, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use pluto_crypto::types::PublicKey as BlsPubKey;
use pluto_eth2api::{
    spec::DataVersion,
    versioned::{
        SignedBlindedProposalBlock, SignedProposalBlock, VersionedSignedBlindedProposal,
        VersionedSignedProposal as RawVersionedSignedProposal,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    error::ApiError,
    handler::Handler,
    metrics::{ApiLatencyTimer, ProxyLatencyTimer},
    types::{
        AttestationDataOpts, AttestationDataResponse, AttesterDutiesOpts, AttesterDutiesResponse,
        BeaconCommitteeSelection, BeaconCommitteeSelectionsResponse, CommitteeIndex,
        NodeVersionResponse, ProposalOpts, ProposerDutiesOpts, ProposerDutiesResponse,
        SyncCommitteeDutiesOpts, SyncCommitteeDutiesResponse, SyncCommitteeSelection,
        SyncCommitteeSelectionsResponse, ValIndexes, ValidatorsOpts,
    },
};
use crate::signeddata::{ProposalBlock, VersionedSignedProposal};

/// Cap on the `POST /eth/v1/validator/duties/{attester,sync}/{epoch}` request
/// bodies. A realistic cluster ships at most a few thousand validator indices;
/// 64 KiB still allows ~10k indices in either numeric or string encoding,
/// well above any plausible workload.
const DUTIES_BODY_LIMIT: usize = 64 * 1024;

/// Cap on the block-submission bodies (`POST /eth/v{1,2}/beacon/blocks` and
/// `.../blinded_blocks`). These carry a full `SignedBlockContents`, which for
/// Electra/Fulu bundles up to `MAX_BLOBS_PER_BLOCK_FULU` (12) blobs of 128 KiB
/// each alongside the block. Blobs are `0x`-hex in the JSON encoding (~2× their
/// binary size), so 12 blobs alone are ~3 MiB of JSON and a blob-carrying block
/// comfortably exceeds axum's 2 MiB default `body: Bytes` limit — missing those
/// proposals. 16 MiB gives several× headroom over a realistic max-blob block
/// while still bounding per-request memory; the Go reference (`router.go`,
/// `submitProposal`) reads the body uncapped via `io.ReadAll`.
const PROPOSAL_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Response/request header carrying the consensus fork name (e.g. `deneb`).
const VERSION_HEADER: &str = "Eth-Consensus-Version";
/// Response header signalling whether the returned proposal is blinded.
const EXECUTION_PAYLOAD_BLINDED_HEADER: &str = "Eth-Execution-Payload-Blinded";
/// Response header carrying the execution payload value, in Wei.
const EXECUTION_PAYLOAD_VALUE_HEADER: &str = "Eth-Execution-Payload-Value";
/// Response header carrying the consensus block value, in Wei.
const CONSENSUS_BLOCK_VALUE_HEADER: &str = "Eth-Consensus-Block-Value";

/// Cap on the `POST /eth/v1/validator/{beacon,sync}_committee_selections`
/// request bodies. Each selection is ~210-250 bytes of JSON (slot, validator
/// index, optional subcommittee index, 96-byte BLS proof in `0x` hex), so
/// 64 KiB admits ~250-300 entries — far more than a realistic cluster while
/// bounding the per-request CPU cost of the BLS verifications and AggSigDB
/// awaits the handler performs.
const SELECTIONS_BODY_LIMIT: usize = 64 * 1024;

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
    /// Whether builder mode is enabled. Read by `propose_block_v3` to maximise
    /// the builder boost factor.
    pub builder_enabled: bool,
    /// Upstream beacon-node base URL. The fallback reverse-proxies every
    /// non-DV request here. A `userinfo` component (`user:pass@host`) is
    /// applied as HTTP basic auth on the proxied request.
    pub upstream_base_url: reqwest::Url,
    /// HTTP client used by the reverse-proxy fallback.
    pub proxy_client: reqwest::Client,
}

/// Builds the validator API HTTP router.
///
/// Registers the distributed-validator-related endpoints and a fallback
/// that reverse-proxies everything else to `upstream_base_url`.
///
/// `builder_enabled` is consumed by `propose_block_v3` to maximise the
/// builder boost factor. `upstream_base_url` is the beacon-node address the
/// fallback proxies to; a `user:pass@host` component is applied as HTTP basic
/// auth on each proxied request.
pub fn new_router(
    handler: Arc<dyn Handler>,
    builder_enabled: bool,
    upstream_base_url: reqwest::Url,
) -> Router {
    let state = Arc::new(AppState {
        handler,
        builder_enabled,
        upstream_base_url,
        proxy_client: reqwest::Client::new(),
    });

    Router::new()
        .route(
            "/eth/v1/validator/duties/attester/{epoch}",
            bounded_post(attester_duties, DUTIES_BODY_LIMIT),
        )
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(proposer_duties),
        )
        .route(
            "/eth/v1/validator/duties/sync/{epoch}",
            bounded_post(sync_committee_duties, DUTIES_BODY_LIMIT),
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
        .route(
            "/eth/v1/beacon/blocks",
            sized_post(submit_proposal, PROPOSAL_BODY_LIMIT),
        )
        .route(
            "/eth/v2/beacon/blocks",
            sized_post(submit_proposal, PROPOSAL_BODY_LIMIT),
        )
        .route(
            "/eth/v1/beacon/blinded_blocks",
            sized_post(submit_blinded_block, PROPOSAL_BODY_LIMIT),
        )
        .route(
            "/eth/v2/beacon/blinded_blocks",
            sized_post(submit_blinded_block, PROPOSAL_BODY_LIMIT),
        )
        .route(
            "/eth/v1/validator/register_validator",
            post(submit_validator_registrations),
        )
        .route("/eth/v1/beacon/pool/voluntary_exits", post(submit_exit))
        .route("/teku_proposer_config", get(respond_404))
        .route("/proposer_config", get(respond_404))
        .route(
            "/eth/v1/validator/beacon_committee_selections",
            bounded_post(beacon_committee_selections, SELECTIONS_BODY_LIMIT),
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
            bounded_post(sync_committee_selections, SELECTIONS_BODY_LIMIT),
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

/// Wraps a `POST` handler with a body-size cap and the JSON content-type
/// policy. The cap is local to the route so unrelated POST handlers (e.g.
/// `submit_attestations`) keep axum's default 2 MiB.
fn bounded_post<H, T, S>(handler: H, body_limit: usize) -> MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler)
        .route_layer(DefaultBodyLimit::max(body_limit))
        .route_layer(middleware::from_fn(enforce_json_content_type))
}

/// `POST` route with an explicit body-size limit but no content-type
/// enforcement, for endpoints that accept either JSON or SSZ
/// (`application/octet-stream`) bodies — i.e. the block-submission routes.
/// Without the limit these inherit axum's 2 MiB default, which a blob-carrying
/// Electra/Fulu block exceeds (see [`PROPOSAL_BODY_LIMIT`]).
fn sized_post<H, T, S>(handler: H, body_limit: usize) -> MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler).route_layer(DefaultBodyLimit::max(body_limit))
}

/// Content-type handling: a missing `Content-Type` is treated as
/// `application/json`; an unrecognized content type is rejected with `415
/// Unsupported Media Type`. SSZ is not supported yet — when it lands, this is
/// the right seam to extend.
///
/// Without this layer, axum's `Json` extractor would reject a missing header
/// with `MissingJsonContentType`, which our envelope normalises to `400`. We
/// instead let VCs that don't set the header through.
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
/// (`422`) — are normalised to a uniform `400` for all body unmarshal
/// failures. Content-Type rejections
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

/// `GET,POST /eth/v1/beacon/states/{state_id}/validators`.
///
/// Validator ids arrive as repeated/CSV `id` query parameters; when the query
/// carries none and the request has a JSON body, the body's `ids` array is
/// used instead. The whole id batch is dispatched on the first element's
/// `0x` prefix exactly as Charon's `getValidatorsByID` does: all-pubkeys if
/// `ids[0]` begins `0x`, otherwise all decimal indices.
async fn get_validators(
    State(state): State<Arc<AppState>>,
    Path(state_id): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let mut ids = validator_ids_from_query(query.as_deref());
    if ids.is_empty() && !body.is_empty() {
        ids = validator_ids_from_json_body(&body)?;
    }

    let opts = validators_opts(state_id, &ids)?;
    let response = state.handler.validators(opts).await?;

    let data = serde_json::to_value(&response.data)
        .map_err(|err| internal_error("could not serialize validators", err))?;
    Ok(Json(json!({
        "execution_optimistic": response.execution_optimistic,
        "finalized": response.finalized,
        "data": data,
    })))
}

/// `GET /eth/v1/beacon/states/{state_id}/validators/{validator_id}`.
///
/// Returns a single validator; `404` when the upstream has none and `500`
/// when it unexpectedly returns more than one. Mirrors `getValidator`.
async fn get_validator(
    State(state): State<Arc<AppState>>,
    Path((state_id, validator_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let opts = validators_opts(state_id, std::slice::from_ref(&validator_id))?;
    let response = state.handler.validators(opts).await?;

    let mut data = response.data;
    match data.len() {
        0 => Err(ApiError::not_found()),
        1 => {
            let validator = serde_json::to_value(data.remove(0))
                .map_err(|err| internal_error("could not serialize validator", err))?;
            Ok(Json(json!({
                "execution_optimistic": response.execution_optimistic,
                "finalized": response.finalized,
                "data": validator,
            })))
        }
        _ => Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected number of validators",
        )),
    }
}

/// `GET /eth/v3/validator/blocks/{slot}`.
///
/// Produces an unsigned (possibly blinded) beacon block. `builder_enabled`
/// maximises the builder boost factor so builder payloads win. The block is
/// returned as JSON with the consensus-version / payload-blinded / value
/// headers Charon sets in `proposeBlockV3`.
async fn propose_block_v3(
    State(state): State<Arc<AppState>>,
    Path(slot): Path<u64>,
    RawQuery(query): RawQuery,
) -> Result<Response, ApiError> {
    let params = parse_query(query.as_deref());

    let randao_reveal = hex_query_fixed::<96>(&params, "randao_reveal")?;
    let graffiti = graffiti_query(&params, "graffiti")?;

    // Builder mode gives maximum priority to builder blocks (`u64::MAX`);
    // otherwise the factor is `0`. Charon always sends the factor (it is never
    // omitted), so use `Some` in both branches.
    let builder_boost_factor = Some(if state.builder_enabled { u64::MAX } else { 0 });

    let response = state
        .handler
        .proposal(ProposalOpts {
            slot,
            randao_reveal,
            graffiti,
            builder_boost_factor,
        })
        .await?;

    let proposal = &response.data;
    let version = proposal.version();
    let blinded = proposal.is_blinded();
    let execution_value = proposal.execution_payload_value.to_string();
    let consensus_value = proposal.consensus_block_value.to_string();

    let body = json!({
        "version": version.as_str(),
        "execution_payload_blinded": blinded,
        "execution_payload_value": execution_value,
        "consensus_block_value": consensus_value,
        "data": serialize_proposal_block(&proposal.block)?,
    });

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, VERSION_HEADER, version.as_str())?;
    insert_header(
        &mut headers,
        EXECUTION_PAYLOAD_BLINDED_HEADER,
        &blinded.to_string(),
    )?;
    insert_header(
        &mut headers,
        EXECUTION_PAYLOAD_VALUE_HEADER,
        &execution_value,
    )?;
    insert_header(&mut headers, CONSENSUS_BLOCK_VALUE_HEADER, &consensus_value)?;

    Ok((headers, Json(body)).into_response())
}

/// `POST /eth/v{1,2}/beacon/blocks`.
///
/// Decodes the submitted full signed block, selecting the fork from the
/// `Eth-Consensus-Version` header (JSON or SSZ body per content type), then
/// forwards it to the handler. Mirrors `submitProposal`.
async fn submit_proposal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let version = consensus_version_header(&headers)?;
    let ssz = request_is_ssz(&headers)?;

    let block = decode_signed_proposal_block(version, &body, ssz)?;
    let proposal = VersionedSignedProposal::new(RawVersionedSignedProposal {
        version,
        blinded: false,
        block,
    })
    .map_err(|err| {
        ApiError::new(StatusCode::BAD_REQUEST, "invalid submitted block").with_source(err)
    })?;

    state.handler.submit_proposal(proposal).await?;
    Ok(StatusCode::OK.into_response())
}

/// `POST /eth/v{1,2}/beacon/blinded_blocks`.
///
/// Decodes the submitted blinded signed block, selecting the fork from the
/// `Eth-Consensus-Version` header, then forwards it to the handler.
/// Mirrors `submitBlindedBlock`.
async fn submit_blinded_block(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let version = consensus_version_header(&headers)?;
    let ssz = request_is_ssz(&headers)?;

    let block = decode_signed_blinded_proposal_block(version, &body, ssz)?;
    let proposal = VersionedSignedBlindedProposal { version, block };

    state.handler.submit_blinded_proposal(proposal).await?;
    Ok(StatusCode::OK.into_response())
}

async fn submit_validator_registrations() {
    todo!("vapi: submit_validator_registrations");
}

async fn submit_exit() {
    todo!("vapi: submit_exit");
}

async fn beacon_committee_selections(
    State(state): State<Arc<AppState>>,
    selections: Result<Json<Vec<BeaconCommitteeSelection>>, JsonRejection>,
) -> Result<Json<BeaconCommitteeSelectionsResponse>, ApiError> {
    let Json(selections) = selections.map_err(json_rejection_to_api_error)?;
    let response = state
        .handler
        .beacon_committee_selections(selections)
        .await?;

    Ok(Json(BeaconCommitteeSelectionsResponse {
        data: response.data,
    }))
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

/// `POST /eth/v1/validator/prepare_beacon_proposer`.
///
/// Swallows the fee-recipient preparation: Charon derives the fee recipient
/// from `cluster-lock.json`, so the validator client need not be configured
/// with one. Returns `200` with no body. Mirrors `submitProposalPreparations`.
async fn submit_proposal_preparations() -> impl IntoResponse {
    StatusCode::OK
}

async fn sync_committee_selections(
    State(state): State<Arc<AppState>>,
    selections: Result<Json<Vec<SyncCommitteeSelection>>, JsonRejection>,
) -> Result<Json<SyncCommitteeSelectionsResponse>, ApiError> {
    let Json(selections) = selections.map_err(json_rejection_to_api_error)?;
    let response = state.handler.sync_committee_selections(selections).await?;

    Ok(Json(SyncCommitteeSelectionsResponse {
        data: response.data,
    }))
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

/// Reverse-proxy fallback: forwards every request not handled by a registered
/// distributed-validator route to the upstream beacon node. Mirrors
/// `proxyHandler`.
///
/// Basic-auth credentials in the upstream URL's `userinfo` are applied to the
/// proxied request and the `Host` header is rewritten to the upstream host,
/// matching Charon's reverse-proxy director. The upstream response body is
/// streamed straight through (not buffered), so long-lived endpoints such as
/// the SSE `/eth/v1/events` stream proxy incrementally. Charon clones the
/// request with the lifecycle context so in-flight proxied requests are
/// cancelled on soft shutdown; here the proxied request inherits the axum
/// request's own lifetime, which is cancelled when the connection/server is
/// torn down.
async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let path = uri.path().to_owned();
    let _proxy_timer = ProxyLatencyTimer::start(&path);
    let _api_timer = ApiLatencyTimer::start("proxy");

    // Build the target URL: upstream base + request path (+ query). The
    // userinfo is stripped from the URL and applied as a basic-auth header
    // instead (below), mirroring Charon's reverse-proxy director and avoiding
    // a duplicate Authorization header from URL-embedded credentials.
    let mut target = state.upstream_base_url.clone();
    target.set_path(uri.path());
    target.set_query(uri.query());
    // These setters only fail on cannot-be-a-base URLs, which an HTTP(S) base
    // URL never is; ignore the result to keep the proxy infallible here.
    let _ = target.set_username("");
    let _ = target.set_password(None);

    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|err| internal_error("invalid proxy method", err))?;

    let mut request = state
        .proxy_client
        .request(reqwest_method, target.clone())
        .body(reqwest::Body::from(body));

    // When the upstream URL carries credentials we own the auth, so the
    // client's own Authorization header must not be relayed (it would produce
    // a second, conflicting Authorization header on the proxied request).
    let upstream_user = state.upstream_base_url.username();
    let has_upstream_auth = !upstream_user.is_empty();

    // Forward request headers, skipping the Host (rewritten below),
    // Content-Length (reqwest sets it from the body), the hop-by-hop headers a
    // proxy must not relay, and — when we apply our own basic auth — the
    // client Authorization header.
    for (name, value) in &headers {
        if name == header::HOST
            || name == header::CONTENT_LENGTH
            || is_hop_by_hop_header(name)
            || (has_upstream_auth && name == header::AUTHORIZATION)
        {
            continue;
        }
        request = request.header(name.as_str(), value.as_bytes());
    }
    if let Some(host) = target.host_str() {
        let host_header = match target.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        request = request.header(header::HOST, host_header);
    }

    // Apply basic auth from the upstream URL's userinfo, if present.
    if has_upstream_auth {
        request = request.basic_auth(upstream_user, state.upstream_base_url.password());
    }

    let upstream = request.send().await.map_err(|err| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "proxy request to beacon node failed",
        )
        .with_source(err)
    })?;

    let status = StatusCode::from_u16(upstream.status().as_u16())
        .map_err(|err| internal_error("invalid upstream status", err))?;

    // Re-emit upstream response headers, dropping Content-Length (axum derives
    // it from the streamed body) and hop-by-hop headers.
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream.headers() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            if name == header::CONTENT_LENGTH || is_hop_by_hop_header(&name) {
                continue;
            }
            response_headers.append(name, value);
        }
    }

    // Stream the body straight through rather than buffering it, so
    // long-lived/streaming endpoints (e.g. the SSE `/eth/v1/events`) are
    // proxied incrementally. Charon achieves the same with a flushing reverse
    // proxy writer.
    let body = axum::body::Body::from_stream(upstream.bytes_stream());

    Ok((status, response_headers, body).into_response())
}

/// Reports whether `name` is an HTTP hop-by-hop header that a proxy must not
/// forward end to end (RFC 7230 §6.1). Comparison is case-insensitive via the
/// normalised [`HeaderName`].
fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Parses a raw URL query string into decoded `(key, value)` pairs, preserving
/// order and duplicate keys. An absent query yields an empty list.
fn parse_query(query: Option<&str>) -> Vec<(String, String)> {
    match query {
        Some(q) => url::form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
        None => Vec::new(),
    }
}

/// Collects validator ids from the `id` query parameter, splitting CSV values
/// and trimming each, mirroring Charon's `getQueryArrayParameter`.
fn validator_ids_from_query(query: Option<&str>) -> Vec<String> {
    parse_query(query)
        .into_iter()
        .filter(|(key, _)| key == "id")
        .flat_map(|(_, value)| {
            value
                .split(',')
                .map(|id| id.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Validator-ids POST body: `{ "ids": [...] }`. Mirrors
/// `getValidatorIDsFromJSON`.
#[derive(Debug, Deserialize)]
struct ValidatorIdsBody {
    #[serde(default)]
    ids: Vec<String>,
}

/// Extracts validator ids from a JSON POST body. A parse failure surfaces as
/// `400`, matching Charon's wrapped "failed to parse request body" error.
fn validator_ids_from_json_body(body: &[u8]) -> Result<Vec<String>, ApiError> {
    let parsed: ValidatorIdsBody = serde_json::from_slice(body).map_err(|err| {
        ApiError::new(StatusCode::BAD_REQUEST, "failed to parse request body").with_source(err)
    })?;
    Ok(parsed.ids)
}

/// Builds [`ValidatorsOpts`] from a state id and a batch of validator ids.
///
/// The whole batch is dispatched on `ids[0]`'s `0x` prefix exactly as Charon's
/// `getValidatorsByID` does: if the first id is `0x`-prefixed every id is
/// parsed as a public key, otherwise every id is parsed as a decimal validator
/// index. An empty batch forwards no filter.
fn validators_opts(state: String, ids: &[String]) -> Result<ValidatorsOpts, ApiError> {
    let mut pubkeys = Vec::new();
    let mut indices = Vec::new();

    if ids.first().is_some_and(|id| id.starts_with("0x")) {
        for id in ids {
            pubkeys.push(parse_pubkey_id(id)?);
        }
    } else {
        for id in ids {
            let index = id.parse::<u64>().map_err(|err| {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid validator index").with_source(err)
            })?;
            indices.push(index);
        }
    }

    Ok(ValidatorsOpts {
        state,
        pubkeys,
        indices,
    })
}

/// Parses a `0x`-prefixed 48-byte hex public key.
fn parse_pubkey_id(id: &str) -> Result<BlsPubKey, ApiError> {
    let stripped = id.strip_prefix("0x").unwrap_or(id);
    let bytes = hex::decode(stripped).map_err(|err| {
        ApiError::new(StatusCode::BAD_REQUEST, "invalid validator public key hex").with_source(err)
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid validator public key length",
        )
    })
}

/// Returns the value of the first query parameter named `name`, if present.
fn query_value<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Decodes a required fixed-length `0x`-hex query parameter into an `N`-byte
/// array. Mirrors Charon's `hexQueryFixed`.
fn hex_query_fixed<const N: usize>(
    params: &[(String, String)],
    name: &str,
) -> Result<[u8; N], ApiError> {
    optional_hex_query_fixed::<N>(params, name)?.ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("missing 0x-hex query parameter {name}"),
        )
    })
}

/// Decodes an optional fixed-length `0x`-hex query parameter into an `N`-byte
/// array. Returns `None` when absent; rejects wrong lengths. Mirrors Charon's
/// `hexQuery` + `hexQueryFixed` length check.
fn optional_hex_query_fixed<const N: usize>(
    params: &[(String, String)],
    name: &str,
) -> Result<Option<[u8; N]>, ApiError> {
    let Some(value) = query_value(params, name) else {
        return Ok(None);
    };
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(stripped).map_err(|err| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("invalid 0x-hex query parameter {name} [{value}]"),
        )
        .with_source(err)
    })?;
    let array: [u8; N] = bytes.as_slice().try_into().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("invalid length for 0x-hex query parameter {name}, expect {N} bytes"),
        )
    })?;
    Ok(Some(array))
}

/// Decodes the optional `graffiti` query parameter into a 32-byte array.
///
/// Graffiti is lenient on length, mirroring Charon's `getProposeBlockParams`
/// (`hexQuery` + `copy(graffiti[:], graffitiBytes)`): any-length hex is
/// accepted, then left-aligned into 32 bytes — longer input is truncated and
/// shorter input is zero-padded. An absent parameter yields all-zero graffiti.
fn graffiti_query(params: &[(String, String)], name: &str) -> Result<[u8; 32], ApiError> {
    let Some(value) = query_value(params, name) else {
        return Ok([0u8; 32]);
    };
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(stripped).map_err(|err| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("invalid 0x-hex query parameter {name} [{value}]"),
        )
        .with_source(err)
    })?;
    let mut graffiti = [0u8; 32];
    let len = bytes.len().min(32);
    graffiti[..len].copy_from_slice(&bytes[..len]);
    Ok(graffiti)
}

/// Parses the `Eth-Consensus-Version` request header into a [`DataVersion`].
///
/// The header is matched case-insensitively (lowercased before lookup) to
/// mirror go-eth2-client's `DataVersion.UnmarshalJSON`. A missing or
/// unrecognised value is a `400`, matching Charon's "missing consensus version
/// header".
fn consensus_version_header(headers: &HeaderMap) -> Result<DataVersion, ApiError> {
    let missing = || ApiError::new(StatusCode::BAD_REQUEST, "missing consensus version header");
    let raw = headers.get(VERSION_HEADER).ok_or_else(missing)?;
    let value = raw.to_str().map_err(|_| missing())?.to_ascii_lowercase();
    match value.as_str() {
        "phase0" => Ok(DataVersion::Phase0),
        "altair" => Ok(DataVersion::Altair),
        "bellatrix" => Ok(DataVersion::Bellatrix),
        "capella" => Ok(DataVersion::Capella),
        "deneb" => Ok(DataVersion::Deneb),
        "electra" => Ok(DataVersion::Electra),
        "fulu" => Ok(DataVersion::Fulu),
        _ => Err(missing()),
    }
}

/// Classifies the request body encoding from its `Content-Type`, mirroring
/// Charon's `wrap` content negotiation for JSON+SSZ endpoints: a missing or
/// `application/json` header is JSON, `application/octet-stream` is SSZ, and
/// anything else is rejected with `415 Unsupported Media Type` carrying the
/// offending content type. Returns `true` for SSZ.
fn request_is_ssz(headers: &HeaderMap) -> Result<bool, ApiError> {
    let Some(value) = headers.get(header::CONTENT_TYPE) else {
        return Ok(false);
    };
    // A present but non-ASCII header is unrecognised, not JSON: surface it as
    // 415 like any other unsupported type rather than silently defaulting.
    let unsupported = || {
        ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("unsupported media type {value:?}"),
        )
    };
    let value = value.to_str().map_err(|_| unsupported())?;
    if value.is_empty() || value.contains("application/json") {
        Ok(false)
    } else if value.contains("application/octet-stream") {
        Ok(true)
    } else {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("unsupported media type {value}"),
        ))
    }
}

/// Decodes a submitted full signed proposal block (JSON or SSZ) for the given
/// fork. A decode failure surfaces as `400`, mirroring Charon's
/// "invalid submitted <fork> block".
fn decode_signed_proposal_block(
    version: DataVersion,
    body: &[u8],
    ssz: bool,
) -> Result<SignedProposalBlock, ApiError> {
    if body.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "empty request body"));
    }
    let invalid = |source: Box<dyn std::error::Error + Send + Sync>| {
        ApiError::new(StatusCode::BAD_REQUEST, "invalid submitted block").with_boxed_source(source)
    };

    if ssz {
        return crate::ssz_codec::decode_signed_proposal_block_body(version, body)
            .map_err(|err| invalid(Box::new(err)));
    }

    let value: Value = serde_json::from_slice(body).map_err(|err| invalid(Box::new(err)))?;
    decode_signed_proposal_block_json(version, value).map_err(invalid)
}

/// Selects the per-fork (non-blinded) `SignedProposalBlock` variant and parses
/// the JSON block body into it. Mirrors the `submitProposal` version switch.
fn decode_signed_proposal_block_json(
    version: DataVersion,
    value: Value,
) -> Result<SignedProposalBlock, Box<dyn std::error::Error + Send + Sync>> {
    Ok(match version {
        DataVersion::Phase0 => SignedProposalBlock::Phase0(serde_json::from_value(value)?),
        DataVersion::Altair => SignedProposalBlock::Altair(serde_json::from_value(value)?),
        DataVersion::Bellatrix => SignedProposalBlock::Bellatrix(serde_json::from_value(value)?),
        DataVersion::Capella => SignedProposalBlock::Capella(serde_json::from_value(value)?),
        DataVersion::Deneb => SignedProposalBlock::Deneb(serde_json::from_value(value)?),
        DataVersion::Electra => SignedProposalBlock::Electra(serde_json::from_value(value)?),
        DataVersion::Fulu => SignedProposalBlock::Fulu(serde_json::from_value(value)?),
        DataVersion::Unknown => return Err("unknown consensus version".into()),
    })
}

/// Decodes a submitted blinded signed proposal block (JSON or SSZ) for the
/// given fork. Mirrors `submitBlindedBlock`.
fn decode_signed_blinded_proposal_block(
    version: DataVersion,
    body: &[u8],
    ssz: bool,
) -> Result<SignedBlindedProposalBlock, ApiError> {
    if body.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "empty request body"));
    }
    let invalid = |source: Box<dyn std::error::Error + Send + Sync>| {
        ApiError::new(StatusCode::BAD_REQUEST, "invalid submitted blinded block")
            .with_boxed_source(source)
    };

    if ssz {
        return crate::ssz_codec::decode_signed_blinded_proposal_block_body(version, body)
            .map_err(|err| invalid(Box::new(err)));
    }

    let value: Value = serde_json::from_slice(body).map_err(|err| invalid(Box::new(err)))?;
    decode_signed_blinded_proposal_block_json(version, value).map_err(invalid)
}

/// Selects the per-fork blinded variant and parses the JSON block body into
/// it. Mirrors the `submitBlindedBlock` version switch; pre-Bellatrix forks
/// have no blinded form and are rejected.
fn decode_signed_blinded_proposal_block_json(
    version: DataVersion,
    value: Value,
) -> Result<SignedBlindedProposalBlock, Box<dyn std::error::Error + Send + Sync>> {
    Ok(match version {
        DataVersion::Bellatrix => {
            SignedBlindedProposalBlock::Bellatrix(serde_json::from_value(value)?)
        }
        DataVersion::Capella => SignedBlindedProposalBlock::Capella(serde_json::from_value(value)?),
        DataVersion::Deneb => SignedBlindedProposalBlock::Deneb(serde_json::from_value(value)?),
        DataVersion::Electra => SignedBlindedProposalBlock::Electra(serde_json::from_value(value)?),
        // Fulu blinded blocks share the Electra layout.
        DataVersion::Fulu => SignedBlindedProposalBlock::Fulu(serde_json::from_value(value)?),
        DataVersion::Phase0 | DataVersion::Altair | DataVersion::Unknown => {
            return Err("invalid blinded block version".into());
        }
    })
}

/// Serializes an unsigned [`ProposalBlock`] to the JSON shape Charon's
/// `createProposeBlockResponse` puts in the `data` field: the bare block for
/// pre-Deneb forks (and all blinded forks), and the `BlockContents` object
/// (`{ block, kzg_proofs, blobs }`) for Deneb, Electra, and Fulu full blocks.
fn serialize_proposal_block(block: &ProposalBlock) -> Result<Value, ApiError> {
    let to_value = |value: Result<Value, serde_json::Error>| {
        value.map_err(|err| internal_error("could not serialize proposal block", err))
    };
    match block {
        ProposalBlock::Phase0(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::Altair(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::Bellatrix(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::BellatrixBlinded(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::Capella(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::CapellaBlinded(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::DenebBlinded(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::ElectraBlinded(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::FuluBlinded(b) => to_value(serde_json::to_value(b)),
        ProposalBlock::Deneb {
            block,
            kzg_proofs,
            blobs,
        } => block_contents_value(block.as_ref(), kzg_proofs, blobs),
        // Electra and Fulu full blocks both carry an `electra::BeaconBlock`.
        ProposalBlock::Electra {
            block,
            kzg_proofs,
            blobs,
        }
        | ProposalBlock::Fulu {
            block,
            kzg_proofs,
            blobs,
        } => block_contents_value(block.as_ref(), kzg_proofs, blobs),
    }
}

/// Builds the `BlockContents` JSON object (`{ block, kzg_proofs, blobs }`) for
/// a Deneb-or-later full proposal, matching go-eth2-client's
/// `apiv1<fork>.BlockContents` wire shape.
fn block_contents_value<B: serde::Serialize>(
    block: &B,
    kzg_proofs: &[pluto_eth2api::spec::deneb::KZGProof],
    blobs: &[pluto_eth2api::spec::deneb::Blob],
) -> Result<Value, ApiError> {
    Ok(json!({
        "block": serde_json::to_value(block)
            .map_err(|err| internal_error("could not serialize block", err))?,
        "kzg_proofs": serde_json::to_value(kzg_proofs)
            .map_err(|err| internal_error("could not serialize kzg_proofs", err))?,
        "blobs": serde_json::to_value(blobs)
            .map_err(|err| internal_error("could not serialize blobs", err))?,
    }))
}

/// Inserts a header, mapping an invalid name or value into a `500` (both are
/// derived from internal data here, so a failure is a bug, not bad input).
fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), ApiError> {
    let header_name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| internal_error("invalid header name", err))?;
    let header_value =
        HeaderValue::from_str(value).map_err(|err| internal_error("invalid header value", err))?;
    headers.insert(header_name, header_value);
    Ok(())
}

/// Builds a `500 Internal Server Error` [`ApiError`] with an attached source.
fn internal_error<E>(message: &'static str, source: E) -> ApiError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, message).with_source(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_eth2api::spec::phase0;

    use crate::validatorapi::{
        testutils::TestHandler,
        types::{
            AttestationDataResponse, AttesterDutiesResponse, AttesterDuty,
            BeaconCommitteeSelection, EthResponse, ProposerDutiesResponse, ProposerDuty,
            SyncCommitteeDutiesResponse, SyncCommitteeDuty, SyncCommitteeSelection, ValIndexes,
        },
    };

    /// Placeholder upstream URL for tests that never reach the proxy fallback.
    fn test_upstream_url() -> reqwest::Url {
        "http://127.0.0.1:0".parse().expect("valid test url")
    }

    /// Builds an [`AppState`] around `handler` for direct-handler unit tests.
    /// `builder_enabled` defaults off; the upstream URL is a placeholder.
    fn test_state(handler: Arc<dyn Handler>) -> Arc<AppState> {
        Arc::new(AppState {
            handler,
            builder_enabled: false,
            upstream_base_url: test_upstream_url(),
            proxy_client: reqwest::Client::new(),
        })
    }

    /// Builds a router for oneshot tests with the proxy disabled (placeholder
    /// upstream) and the given builder mode.
    fn test_router(handler: Arc<dyn Handler>, builder_enabled: bool) -> Router {
        new_router(handler, builder_enabled, test_upstream_url())
    }

    #[tokio::test]
    async fn node_version_wraps_handler_value() {
        let state = test_state(Arc::new(TestHandler::with_version("pluto/test/v1.0")));

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
        let state = test_state(Arc::new(handler));

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
        let state = test_state(Arc::new(handler));

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
        let state = test_state(Arc::new(handler));

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
        let state = test_state(Arc::new(handler));

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
        let app = test_router(Arc::new(handler), false);

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
        let app = test_router(Arc::new(handler), false);

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
    /// a type error).
    #[tokio::test]
    async fn attester_duties_returns_api_error_shape_on_bad_body() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let app = test_router(Arc::new(TestHandler::default()), false);

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

    /// A duties request that omits `Content-Type` is treated as
    /// `application/json` rather than rejected — the
    /// `enforce_json_content_type` middleware injects the header before
    /// the `Json` extractor sees the request.
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
        let app = test_router(Arc::new(handler), false);

        // No Content-Type header at all.
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/duties/attester/42")
            .body(Body::from("[]"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A duties request with a non-JSON `Content-Type` returns `415
    /// Unsupported Media Type`, not the `400` that the generic body-parse
    /// normaliser would produce.
    #[tokio::test]
    async fn attester_duties_rejects_non_json_content_type() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let app = test_router(Arc::new(TestHandler::default()), false);

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

    // -----------------------------------------------------------------------
    // PR 1: proxy + proposal/validators handler tests
    // -----------------------------------------------------------------------

    use alloy::primitives::U256;
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use pluto_eth2api::{
        GetStateValidatorsResponseResponseDatum as ValidatorDatum, ValidatorResponseValidator,
        ValidatorStatus,
        spec::{bellatrix, phase0 as p0},
    };
    use tower::ServiceExt;

    // `ProposalBlock`, `SignedProposalBlock`, `SignedBlindedProposalBlock` and
    // `DataVersion` come in via `super::*`.
    use crate::signeddata::VersionedProposal;

    fn empty_sync_bits() -> pluto_ssz::BitVector<512> {
        pluto_ssz::BitVector::new()
    }

    /// Minimal phase0 unsigned beacon block at `slot`.
    fn phase0_unsigned_block(slot: u64) -> p0::BeaconBlock {
        p0::BeaconBlock {
            slot,
            proposer_index: 7,
            parent_root: [0; 32],
            state_root: [0; 32],
            body: p0::BeaconBlockBody {
                randao_reveal: [0; 96],
                eth1_data: p0::ETH1Data {
                    deposit_root: [0; 32],
                    deposit_count: 0,
                    block_hash: [0; 32],
                },
                graffiti: [0; 32],
                proposer_slashings: vec![].into(),
                attester_slashings: vec![].into(),
                attestations: vec![].into(),
                deposits: vec![].into(),
                voluntary_exits: vec![].into(),
            },
        }
    }

    /// Phase0 unsigned `VersionedProposal` returned by the proposal handler.
    fn phase0_proposal(slot: u64) -> VersionedProposal {
        VersionedProposal {
            block: ProposalBlock::Phase0(phase0_unsigned_block(slot)),
            consensus_block_value: U256::from(1u8),
            execution_payload_value: U256::from(1u8),
        }
    }

    /// Phase0 signed beacon block for submit tests.
    fn phase0_signed_block(slot: u64) -> p0::SignedBeaconBlock {
        p0::SignedBeaconBlock {
            message: phase0_unsigned_block(slot),
            signature: [0; 96],
        }
    }

    /// Bellatrix blinded signed block for blinded-submit tests.
    fn bellatrix_blinded_signed_block(slot: u64) -> bellatrix::SignedBlindedBeaconBlock {
        let header = bellatrix::ExecutionPayloadHeader {
            parent_hash: [0; 32],
            fee_recipient: [0; 20],
            state_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom: [0; 256],
            prev_randao: [0; 32],
            block_number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0,
            extra_data: vec![].into(),
            base_fee_per_gas: U256::ZERO,
            block_hash: [0; 32],
            transactions_root: [0; 32],
        };
        let block = bellatrix::BlindedBeaconBlock {
            slot,
            proposer_index: 7,
            parent_root: [0; 32],
            state_root: [0; 32],
            body: bellatrix::BlindedBeaconBlockBody {
                randao_reveal: [0; 96],
                eth1_data: p0::ETH1Data {
                    deposit_root: [0; 32],
                    deposit_count: 0,
                    block_hash: [0; 32],
                },
                graffiti: [0; 32],
                proposer_slashings: vec![].into(),
                attester_slashings: vec![].into(),
                attestations: vec![].into(),
                deposits: vec![].into(),
                voluntary_exits: vec![].into(),
                sync_aggregate: pluto_eth2api::spec::altair::SyncAggregate {
                    sync_committee_bits: empty_sync_bits(),
                    sync_committee_signature: [0; 96],
                },
                execution_payload_header: header,
            },
        };
        bellatrix::SignedBlindedBeaconBlock {
            message: block,
            signature: [0; 96],
        }
    }

    fn sample_validator_datum(index: u64, pubkey_hex: &str) -> ValidatorDatum {
        ValidatorDatum {
            index: index.to_string(),
            balance: "32000000000".to_owned(),
            status: ValidatorStatus::ActiveOngoing,
            validator: ValidatorResponseValidator {
                pubkey: pubkey_hex.to_owned(),
                withdrawal_credentials: format!("0x{}", "00".repeat(32)),
                effective_balance: "32000000000".to_owned(),
                slashed: false,
                activation_eligibility_epoch: "0".to_owned(),
                activation_epoch: "0".to_owned(),
                exit_epoch: "18446744073709551615".to_owned(),
                withdrawable_epoch: "18446744073709551615".to_owned(),
            },
        }
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// `submit_proposal_preparations` swallows the request and returns 200.
    #[tokio::test]
    async fn prepare_beacon_proposer_swallows_and_returns_200() {
        let app = test_router(Arc::new(TestHandler::default()), false);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/prepare_beacon_proposer")
            .header("content-type", "application/json")
            .body(Body::from("[]"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// `propose_block_v3` returns the versioned block plus the four
    /// consensus/value response headers; builder mode maximises the boost.
    #[tokio::test]
    async fn propose_block_v3_returns_block_with_headers() {
        let handler = TestHandler::default().with_proposal(EthResponse {
            data: phase0_proposal(42),
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let opts_handle = handler.proposal_opts.clone();
        let app = test_router(Arc::new(handler), true);

        let randao = format!("0x{}", "ab".repeat(96));
        let req = Request::builder()
            .uri(format!(
                "/eth/v3/validator/blocks/42?randao_reveal={randao}"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let headers = resp.headers();
        assert_eq!(headers.get(VERSION_HEADER).unwrap(), "phase0");
        assert_eq!(
            headers.get(EXECUTION_PAYLOAD_BLINDED_HEADER).unwrap(),
            "false"
        );
        assert_eq!(headers.get(EXECUTION_PAYLOAD_VALUE_HEADER).unwrap(), "1");
        assert_eq!(headers.get(CONSENSUS_BLOCK_VALUE_HEADER).unwrap(), "1");

        let json = body_json(resp).await;
        assert_eq!(json["version"], "phase0");
        assert_eq!(json["execution_payload_blinded"], false);
        assert_eq!(json["data"]["slot"], "42");

        // builder_enabled → boost factor maxed.
        let opts = opts_handle.lock().unwrap().clone().unwrap();
        assert_eq!(opts.slot, 42);
        assert_eq!(opts.builder_boost_factor, Some(u64::MAX));
        assert_eq!(opts.randao_reveal, [0xab; 96]);
    }

    /// Graffiti is length-lenient: a short value is zero-padded into the
    /// 32-byte array, matching Charon's `copy(graffiti[:], graffitiBytes)`.
    #[tokio::test]
    async fn propose_block_v3_pads_short_graffiti() {
        let handler = TestHandler::default().with_proposal(EthResponse {
            data: phase0_proposal(42),
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let opts_handle = handler.proposal_opts.clone();
        let app = test_router(Arc::new(handler), false);

        let randao = format!("0x{}", "ab".repeat(96));
        let req = Request::builder()
            .uri(format!(
                "/eth/v3/validator/blocks/42?randao_reveal={randao}&graffiti=0xdeadbeef"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let opts = opts_handle.lock().unwrap().clone().unwrap();
        let mut expected = [0u8; 32];
        expected[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(opts.graffiti, expected);
        // builder disabled → boost factor 0 (always sent, never omitted).
        assert_eq!(opts.builder_boost_factor, Some(0));
    }

    /// Missing `randao_reveal` is a 400.
    #[tokio::test]
    async fn propose_block_v3_rejects_missing_randao() {
        let handler = TestHandler::default().with_proposal(EthResponse {
            data: phase0_proposal(42),
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let app = test_router(Arc::new(handler), false);
        let req = Request::builder()
            .uri("/eth/v3/validator/blocks/42")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// `submit_proposal` decodes the JSON block keyed by the version header and
    /// forwards it; the handler records the right version + blinded flag.
    #[tokio::test]
    async fn submit_proposal_decodes_and_forwards() {
        let handler = TestHandler::default();
        let submitted = handler.submitted_proposal.clone();
        let app = test_router(Arc::new(handler), false);

        let block = SignedProposalBlock::Phase0(phase0_signed_block(9));
        let body = serde_json::to_vec(&block).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blocks")
            .header("content-type", "application/json")
            .header(VERSION_HEADER, "phase0")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let got = submitted.lock().unwrap().clone().unwrap();
        assert_eq!(got.0.version, DataVersion::Phase0);
        assert!(!got.0.blinded);
    }

    /// `submit_proposal` decodes an SSZ (`application/octet-stream`) body via
    /// the bare per-fork block codec keyed by the version header.
    #[tokio::test]
    async fn submit_proposal_decodes_ssz_body() {
        use ssz::Encode;

        let handler = TestHandler::default();
        let submitted = handler.submitted_proposal.clone();
        let app = test_router(Arc::new(handler), false);

        // The SSZ body is the bare per-fork block, not the Charon versioned
        // wire format.
        let body = phase0_signed_block(9).as_ssz_bytes();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blocks")
            .header("content-type", "application/octet-stream")
            .header(VERSION_HEADER, "phase0")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let got = submitted.lock().unwrap().clone().unwrap();
        assert_eq!(got.0.version, DataVersion::Phase0);
        assert!(matches!(got.0.block, SignedProposalBlock::Phase0(_)));
    }

    /// A block-submission body larger than axum's 2 MiB default (a realistic
    /// blob-carrying Electra/Fulu block) reaches the decoder instead of being
    /// rejected up front with `413`. The garbage body then fails to decode as
    /// `400`, but the point is that the body-limit layer let it through — with
    /// the default limit this would have been `413` and the proposal missed.
    #[tokio::test]
    async fn submit_proposal_accepts_body_over_default_limit() {
        let app = test_router(Arc::new(TestHandler::default()), false);

        let big = vec![0u8; 3 * 1024 * 1024];
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blocks")
            .header("content-type", "application/octet-stream")
            .header(VERSION_HEADER, "deneb")
            .header("content-length", big.len())
            .body(Body::from(big))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A body beyond [`PROPOSAL_BODY_LIMIT`] is still rejected with `413`,
    /// bounding per-request memory.
    #[tokio::test]
    async fn submit_proposal_rejects_body_over_limit() {
        let app = test_router(Arc::new(TestHandler::default()), false);

        let big = vec![0u8; PROPOSAL_BODY_LIMIT + 1];
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blocks")
            .header("content-type", "application/octet-stream")
            .header(VERSION_HEADER, "deneb")
            .header("content-length", big.len())
            .body(Body::from(big))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// A capitalised version header is accepted (case-insensitive, mirroring
    /// go-eth2-client's UnmarshalJSON).
    #[tokio::test]
    async fn submit_proposal_accepts_capitalised_version_header() {
        let handler = TestHandler::default();
        let app = test_router(Arc::new(handler), false);

        let block = SignedProposalBlock::Phase0(phase0_signed_block(9));
        let body = serde_json::to_vec(&block).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v2/beacon/blocks")
            .header("content-type", "application/json")
            .header(VERSION_HEADER, "Phase0")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Missing version header → 400.
    #[tokio::test]
    async fn submit_proposal_rejects_missing_version_header() {
        let app = test_router(Arc::new(TestHandler::default()), false);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blocks")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// An unsupported content type → 415, mirroring Charon's `wrap`.
    #[tokio::test]
    async fn submit_proposal_rejects_unsupported_content_type() {
        let app = test_router(Arc::new(TestHandler::default()), false);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blocks")
            .header("content-type", "text/plain")
            .header(VERSION_HEADER, "phase0")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// A body that does not match the declared fork → 400.
    #[tokio::test]
    async fn submit_proposal_rejects_bad_body() {
        let app = test_router(Arc::new(TestHandler::default()), false);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blocks")
            .header("content-type", "application/json")
            .header(VERSION_HEADER, "phase0")
            .body(Body::from(r#"{"not":"a block"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// `submit_blinded_block` decodes the blinded JSON block and forwards it.
    #[tokio::test]
    async fn submit_blinded_block_decodes_and_forwards() {
        let handler = TestHandler::default();
        let submitted = handler.submitted_blinded_proposal.clone();
        let app = test_router(Arc::new(handler), false);

        let block = SignedBlindedProposalBlock::Bellatrix(bellatrix_blinded_signed_block(9));
        let body = serde_json::to_vec(&block).unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blinded_blocks")
            .header("content-type", "application/json")
            .header(VERSION_HEADER, "bellatrix")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let got = submitted.lock().unwrap().clone().unwrap();
        assert_eq!(got.version, DataVersion::Bellatrix);
    }

    /// A pre-Bellatrix fork has no blinded form → 400.
    #[tokio::test]
    async fn submit_blinded_block_rejects_phase0() {
        let app = test_router(Arc::new(TestHandler::default()), false);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/blinded_blocks")
            .header("content-type", "application/json")
            .header(VERSION_HEADER, "phase0")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// `get_validators` via repeated/CSV `id` query and the JSON response
    /// shape.
    #[tokio::test]
    async fn get_validators_by_query_id() {
        let handler = TestHandler::default().with_validators(EthResponse {
            data: vec![sample_validator_datum(7, &format!("0x{}", "11".repeat(48)))],
            execution_optimistic: false,
            finalized: true,
            dependent_root: None,
        });
        let opts_handle = handler.validators_opts.clone();
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .uri("/eth/v1/beacon/states/head/validators?id=7,8")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        assert_eq!(json["finalized"], true);
        assert_eq!(json["data"][0]["index"], "7");

        let opts = opts_handle.lock().unwrap().clone().unwrap();
        assert_eq!(opts.state, "head");
        assert_eq!(opts.indices, vec![7, 8]);
        assert!(opts.pubkeys.is_empty());
    }

    /// A `0x`-prefixed first id routes the whole batch as pubkeys, per Go's
    /// `getValidatorsByID` first-element dispatch.
    #[tokio::test]
    async fn get_validators_by_pubkey_dispatch_on_first_id() {
        let pubkey_hex = format!("0x{}", "11".repeat(48));
        let handler = TestHandler::default().with_validators(EthResponse {
            data: vec![],
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let opts_handle = handler.validators_opts.clone();
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .uri(format!(
                "/eth/v1/beacon/states/head/validators?id={pubkey_hex}"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Empty result serializes to `[]`, not null.
        let json = body_json(resp).await;
        assert_eq!(json["data"], serde_json::json!([]));

        let opts = opts_handle.lock().unwrap().clone().unwrap();
        assert_eq!(opts.pubkeys.len(), 1);
        assert_eq!(opts.pubkeys[0], [0x11; 48]);
        assert!(opts.indices.is_empty());
    }

    /// POST with `{"ids":[...]}` body when the query carries no ids.
    #[tokio::test]
    async fn get_validators_by_json_body_ids() {
        let handler = TestHandler::default().with_validators(EthResponse {
            data: vec![],
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let opts_handle = handler.validators_opts.clone();
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/beacon/states/head/validators")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"ids":["3","4"]}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let opts = opts_handle.lock().unwrap().clone().unwrap();
        assert_eq!(opts.indices, vec![3, 4]);
    }

    /// `get_validator` returns a single object on exactly one result.
    #[tokio::test]
    async fn get_validator_single_result() {
        let handler = TestHandler::default().with_validators(EthResponse {
            data: vec![sample_validator_datum(7, &format!("0x{}", "11".repeat(48)))],
            execution_optimistic: false,
            finalized: true,
            dependent_root: None,
        });
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .uri("/eth/v1/beacon/states/head/validators/7")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["data"]["index"], "7");
        assert!(json["data"].is_object());
    }

    /// `get_validator` returns 404 when the upstream has no match.
    #[tokio::test]
    async fn get_validator_not_found() {
        let handler = TestHandler::default().with_validators(EthResponse {
            data: vec![],
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .uri("/eth/v1/beacon/states/head/validators/7")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `get_validator` returns 500 when the upstream returns more than one.
    #[tokio::test]
    async fn get_validator_multiple_results_is_500() {
        let handler = TestHandler::default().with_validators(EthResponse {
            data: vec![
                sample_validator_datum(7, &format!("0x{}", "11".repeat(48))),
                sample_validator_datum(8, &format!("0x{}", "22".repeat(48))),
            ],
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .uri("/eth/v1/beacon/states/head/validators/7")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// The reverse-proxy fallback forwards method, path, query and body to the
    /// upstream beacon node, applies basic auth from the URL userinfo, and
    /// returns the upstream response.
    #[tokio::test]
    async fn proxy_forwards_to_upstream() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{basic_auth, method, path, query_param},
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/some/passthrough"))
            .and(query_param("foo", "bar"))
            .and(basic_auth("user", "pass"))
            .respond_with(ResponseTemplate::new(200).set_body_string("upstream-ok"))
            .mount(&server)
            .await;

        // Inject basic-auth userinfo into the upstream URL.
        let mut upstream: reqwest::Url = server.uri().parse().unwrap();
        upstream.set_username("user").unwrap();
        upstream.set_password(Some("pass")).unwrap();

        let app = new_router(Arc::new(TestHandler::default()), false, upstream);
        let req = Request::builder()
            .uri("/eth/v1/some/passthrough?foo=bar")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&bytes[..], b"upstream-ok");
    }

    /// The proxy propagates a non-2xx upstream status to the client.
    #[tokio::test]
    async fn proxy_propagates_upstream_error_status() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_string("nope"))
            .mount(&server)
            .await;

        let upstream: reqwest::Url = server.uri().parse().unwrap();
        let app = new_router(Arc::new(TestHandler::default()), false, upstream);
        let req = Request::builder()
            .uri("/eth/v1/missing")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Verifies the router wraps the `Handler::beacon_committee_selections`
    /// payload into the `{ "data": [...] }` wire shape, dropping the
    /// `execution_optimistic` / `finalized` / `dependent_root` metadata that
    /// the trait method carries internally.
    #[tokio::test]
    async fn beacon_committee_selections_wraps_handler_value() {
        let selection = BeaconCommitteeSelection {
            slot: 10,
            validator_index: 5,
            selection_proof: [0xAA; 96],
        };
        let handler = TestHandler::default().with_beacon_committee_selections(EthResponse {
            data: vec![selection],
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let state = test_state(Arc::new(handler));

        let Json(body) = beacon_committee_selections(State(state), Ok(Json(vec![])))
            .await
            .unwrap();

        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("execution_optimistic").is_none());
        assert!(json.get("finalized").is_none());
        assert!(json.get("dependent_root").is_none());
        assert_eq!(json["data"][0]["slot"], "10");
        assert_eq!(json["data"][0]["validator_index"], "5");
    }

    /// Counterpart of [`beacon_committee_selections_wraps_handler_value`] for
    /// the sync-committee variant.
    #[tokio::test]
    async fn sync_committee_selections_wraps_handler_value() {
        let selection = SyncCommitteeSelection {
            slot: 20,
            validator_index: 7,
            subcommittee_index: 2,
            selection_proof: [0xBB; 96],
        };
        let handler = TestHandler::default().with_sync_committee_selections(EthResponse {
            data: vec![selection],
            execution_optimistic: false,
            finalized: false,
            dependent_root: None,
        });
        let state = test_state(Arc::new(handler));

        let Json(body) = sync_committee_selections(State(state), Ok(Json(vec![])))
            .await
            .unwrap();

        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("execution_optimistic").is_none());
        assert_eq!(json["data"][0]["slot"], "20");
        assert_eq!(json["data"][0]["validator_index"], "7");
        assert_eq!(json["data"][0]["subcommittee_index"], "2");
    }

    /// Verifies the body-limit layer on the selection POST routes rejects
    /// oversized bodies before any BLS verification work happens.
    #[tokio::test]
    async fn beacon_committee_selections_rejects_oversized_body() {
        use axum::{
            body::Body,
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let handler = TestHandler::default();
        let app = test_router(Arc::new(handler), false);

        let big = vec![b'0'; SELECTIONS_BODY_LIMIT * 2];
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/beacon_committee_selections")
            .header("content-type", "application/json")
            .header("content-length", big.len())
            .body(Body::from(big))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Counterpart of [`beacon_committee_selections_rejects_oversized_body`].
    #[tokio::test]
    async fn sync_committee_selections_rejects_oversized_body() {
        use axum::{
            body::Body,
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let handler = TestHandler::default();
        let app = test_router(Arc::new(handler), false);

        let big = vec![b'0'; SELECTIONS_BODY_LIMIT * 2];
        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/sync_committee_selections")
            .header("content-type", "application/json")
            .header("content-length", big.len())
            .body(Body::from(big))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Malformed JSON on the selection POST routes is normalised into the
    /// router's standard `{ code, message }` envelope rather than axum's
    /// default plain-text 400 / 422 / 415 — every body unmarshal failure
    /// surfaces as a uniform `400`. The
    /// same plumbing covers the duties endpoints; see
    /// [`attester_duties_returns_api_error_shape_on_malformed_body`] for the
    /// duties variant.
    #[tokio::test]
    async fn beacon_committee_selections_returns_api_error_shape_on_malformed_body() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let handler = TestHandler::default();
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/beacon_committee_selections")
            .header("content-type", "application/json")
            .body(Body::from(r#"{ "not": "an array" }"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], 400);
        assert!(json["message"].is_string());
    }

    /// Counterpart of
    /// [`beacon_committee_selections_returns_api_error_shape_on_malformed_body`].
    #[tokio::test]
    async fn sync_committee_selections_returns_api_error_shape_on_malformed_body() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let handler = TestHandler::default();
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/sync_committee_selections")
            .header("content-type", "application/json")
            .body(Body::from("not-json-at-all"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], 400);
        assert!(json["message"].is_string());
    }

    /// Duties POST endpoints share the same `json_rejection_to_api_error`
    /// plumbing as the selection routes — this test locks the envelope
    /// contract on the duties side so a future refactor that re-introduces
    /// bare `Json<ValIndexes>` extraction is caught by a failing test rather
    /// than only by manual review.
    #[tokio::test]
    async fn attester_duties_returns_api_error_shape_on_malformed_body() {
        use axum::{
            body::{Body, to_bytes},
            http::{Method, Request},
        };
        use tower::ServiceExt;

        let handler = TestHandler::default();
        let app = test_router(Arc::new(handler), false);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/eth/v1/validator/duties/attester/42")
            .header("content-type", "application/json")
            .body(Body::from(r#"{ "not": "an array" }"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], 400);
        assert!(json["message"].is_string());
    }
}
