//! HTTP client for a single beacon node.
//!
//! One method per Beacon API endpoint Pluto uses. Each method takes the
//! endpoint's request struct and returns its response enum: every status the
//! API documents maps to a variant (`Ok`, `BadRequest`, ...), any other status
//! maps to `Unknown` with the body discarded, and only request validation,
//! transport and body decoding failures surface as `Err`.

use crate::types::*;
use anyhow::Context;
use reqwest::{Client, Response, Url, header::CONTENT_TYPE};
use serde::de::DeserializeOwned;
use validator::Validate;

/// Client for one beacon node.
#[derive(Debug, Clone)]
pub struct EthBeaconNodeApiClient {
    /// HTTP client the requests are sent with.
    pub client: Client,
    /// Beacon node URL; endpoint paths are appended to its path.
    pub base_url: Url,
}

/// Body of a 2xx response from an endpoint that can answer JSON or SSZ.
enum SuccessBody<T> {
    Json(T),
    Binary(Vec<u8>),
    /// A content type the client does not decode; the body has been read and
    /// discarded.
    Unsupported,
}

/// Decodes a JSON body, naming the offending field path on failure.
async fn json_body<T: DeserializeOwned>(response: Response) -> anyhow::Result<T> {
    let body = response.text().await.context("reading response body")?;
    let mut deserializer = serde_json::Deserializer::from_str(&body);
    serde_path_to_error::deserialize(&mut deserializer).context("decoding JSON response body")
}

/// Reads and discards the body of a response with no typed payload.
async fn drain(response: Response) -> anyhow::Result<()> {
    response.bytes().await.context("reading response body")?;
    Ok(())
}

/// Decodes a 2xx body by `Content-Type`: JSON when the type mentions `json`
/// or the header is absent, raw bytes for `application/octet-stream`.
async fn json_or_binary_body<T: DeserializeOwned>(
    response: Response,
) -> anyhow::Result<SuccessBody<T>> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();

    if content_type.contains("json") {
        return Ok(SuccessBody::Json(json_body(response).await?));
    }
    if content_type.starts_with("application/octet-stream") {
        let bytes = response.bytes().await.context("reading response body")?;
        return Ok(SuccessBody::Binary(bytes.to_vec()));
    }

    drain(response).await?;
    Ok(SuccessBody::Unsupported)
}

impl EthBeaconNodeApiClient {
    /// Creates a client for `base_url` with a default [`reqwest::Client`].
    pub fn with_base_url(base_url: impl AsRef<str>) -> anyhow::Result<Self> {
        let client = Client::builder()
            .build()
            .context("building reqwest client")?;
        Self::with_client(base_url, client)
    }

    /// Creates a client for `base_url` that sends its requests with `client`.
    pub fn with_client(base_url: impl AsRef<str>, client: Client) -> anyhow::Result<Self> {
        let base_url = Url::parse(base_url.as_ref()).context("parsing base url")?;
        Ok(Self { client, base_url })
    }

    /// Appends `segments` to the base URL path.
    fn url(&self, segments: &[&str]) -> anyhow::Result<Url> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("URL cannot be a base"))?
            .extend(segments);
        Ok(url)
    }

    /// `GET /eth/v1/beacon/genesis`: genesis time, validators root and fork
    /// version.
    pub async fn get_genesis(
        &self,
        request: GetGenesisRequest,
    ) -> anyhow::Result<GetGenesisResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "beacon", "genesis"])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetGenesisResponse::Ok(json_body(response).await?),
            404 => GetGenesisResponse::NotFound(json_body(response).await?),
            500 => GetGenesisResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetGenesisResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/beacon/blocks/{block_id}/root`: the root of a block.
    pub async fn get_block_root(
        &self,
        request: GetBlockRootRequest,
    ) -> anyhow::Result<GetBlockRootResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&[
            "eth",
            "v1",
            "beacon",
            "blocks",
            &request.path.block_id,
            "root",
        ])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetBlockRootResponse::Ok(json_body(response).await?),
            400 => GetBlockRootResponse::BadRequest(json_body(response).await?),
            404 => GetBlockRootResponse::NotFound(json_body(response).await?),
            500 => GetBlockRootResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetBlockRootResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/beacon/headers/{block_id}`: the signed header of a block.
    pub async fn get_block_header(
        &self,
        request: GetBlockHeaderRequest,
    ) -> anyhow::Result<GetBlockHeaderResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "beacon", "headers", &request.path.block_id])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetBlockHeaderResponse::Ok(json_body(response).await?),
            400 => GetBlockHeaderResponse::BadRequest(json_body(response).await?),
            404 => GetBlockHeaderResponse::NotFound(json_body(response).await?),
            500 => GetBlockHeaderResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetBlockHeaderResponse::Unknown
            }
        })
    }

    /// `GET /eth/v2/beacon/blocks/{block_id}`: a full signed block, as JSON
    /// or SSZ depending on the node's `Content-Type`.
    pub async fn get_block_v2(
        &self,
        request: GetBlockV2Request,
    ) -> anyhow::Result<GetBlockV2Response> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v2", "beacon", "blocks", &request.path.block_id])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => match json_or_binary_body(response).await? {
                SuccessBody::Json(data) => GetBlockV2Response::Ok(data),
                SuccessBody::Binary(bytes) => GetBlockV2Response::OkBinary(bytes),
                SuccessBody::Unsupported => GetBlockV2Response::Unknown,
            },
            400 => GetBlockV2Response::BadRequest(json_body(response).await?),
            404 => GetBlockV2Response::NotFound(json_body(response).await?),
            406 => GetBlockV2Response::NotAcceptable(json_body(response).await?),
            500 => GetBlockV2Response::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetBlockV2Response::Unknown
            }
        })
    }

    /// `POST /eth/v1/beacon/states/{state_id}/validators`: validators of a
    /// state, filtered by the ids and statuses in the body.
    pub async fn post_state_validators(
        &self,
        request: PostStateValidatorsRequest,
    ) -> anyhow::Result<PostStateValidatorsResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&[
            "eth",
            "v1",
            "beacon",
            "states",
            &request.path.state_id,
            "validators",
        ])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => PostStateValidatorsResponse::Ok(json_body(response).await?),
            400 => PostStateValidatorsResponse::BadRequest(json_body(response).await?),
            404 => PostStateValidatorsResponse::NotFound(json_body(response).await?),
            500 => PostStateValidatorsResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                PostStateValidatorsResponse::Unknown
            }
        })
    }

    /// `POST /eth/v2/beacon/blocks`: publishes a signed block (with blobs from
    /// Deneb on), tagged with its consensus version.
    pub async fn publish_block_v2(
        &self,
        request: PublishBlockV2Request,
    ) -> anyhow::Result<PublishBlockV2Response> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v2", "beacon", "blocks"])?;
        let response = self
            .client
            .post(url)
            .query(&request.query)
            .header(
                ETH_CONSENSUS_VERSION,
                request.header.eth_consensus_version.to_string(),
            )
            .json(&request.body)
            .send()
            .await?;

        parse_publish_block_response(response).await
    }

    /// `POST /eth/v2/beacon/blinded_blocks`: publishes a signed blinded
    /// block, tagged with its consensus version.
    pub async fn publish_blinded_block_v2(
        &self,
        request: PublishBlindedBlockV2Request,
    ) -> anyhow::Result<PublishBlockV2Response> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v2", "beacon", "blinded_blocks"])?;
        let response = self
            .client
            .post(url)
            .query(&request.query)
            .header(
                ETH_CONSENSUS_VERSION,
                request.header.eth_consensus_version.to_string(),
            )
            .json(&request.body)
            .send()
            .await?;

        parse_publish_block_response(response).await
    }

    /// `POST /eth/v2/beacon/pool/attestations`: submits signed attestations,
    /// tagged with their consensus version.
    pub async fn submit_pool_attestations_v2(
        &self,
        request: SubmitPoolAttestationsV2Request,
    ) -> anyhow::Result<SubmitPoolAttestationsV2Response> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v2", "beacon", "pool", "attestations"])?;
        let response = self
            .client
            .post(url)
            .header(
                ETH_CONSENSUS_VERSION,
                request.header.eth_consensus_version.to_string(),
            )
            .json(&request.body)
            .send()
            .await?;

        parse_submit_pool_attestations_response(response).await
    }

    /// `POST /eth/v1/beacon/pool/sync_committees`: submits sync committee
    /// messages.
    pub async fn submit_pool_sync_committee_signatures(
        &self,
        request: SubmitPoolSyncCommitteeSignaturesRequest,
    ) -> anyhow::Result<PublishContributionAndProofsResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "beacon", "pool", "sync_committees"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        parse_publish_contribution_and_proofs_response(response).await
    }

    /// `POST /eth/v1/beacon/pool/voluntary_exits`: submits a signed voluntary
    /// exit.
    pub async fn submit_pool_voluntary_exit(
        &self,
        request: SubmitPoolVoluntaryExitRequest,
    ) -> anyhow::Result<SubmitPoolVoluntaryExitResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "beacon", "pool", "voluntary_exits"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => {
                drain(response).await?;
                SubmitPoolVoluntaryExitResponse::Ok
            }
            400 => SubmitPoolVoluntaryExitResponse::BadRequest(json_body(response).await?),
            500 => SubmitPoolVoluntaryExitResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                SubmitPoolVoluntaryExitResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/config/fork_schedule`: every fork the node knows about.
    pub async fn get_fork_schedule(
        &self,
        request: GetForkScheduleRequest,
    ) -> anyhow::Result<GetForkScheduleResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "config", "fork_schedule"])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetForkScheduleResponse::Ok(json_body(response).await?),
            500 => GetForkScheduleResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetForkScheduleResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/config/spec`: the chain constants, presets and
    /// configuration.
    pub async fn get_spec(&self, request: GetSpecRequest) -> anyhow::Result<GetSpecResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "config", "spec"])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetSpecResponse::Ok(json_body(response).await?),
            500 => GetSpecResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetSpecResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/node/peer_count`: the node's peer counts by connection
    /// state.
    pub async fn get_peer_count(
        &self,
        request: GetPeerCountRequest,
    ) -> anyhow::Result<GetPeerCountResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "node", "peer_count"])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetPeerCountResponse::Ok(json_body(response).await?),
            500 => GetPeerCountResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetPeerCountResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/node/syncing`: the node's sync status.
    pub async fn get_syncing_status(
        &self,
        request: GetSyncingStatusRequest,
    ) -> anyhow::Result<GetSyncingStatusResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "node", "syncing"])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetSyncingStatusResponse::Ok(json_body(response).await?),
            500 => GetSyncingStatusResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetSyncingStatusResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/node/version`: the node's client version string.
    pub async fn get_node_version(
        &self,
        request: GetNodeVersionRequest,
    ) -> anyhow::Result<GetNodeVersionResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "node", "version"])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetNodeVersionResponse::Ok(json_body(response).await?),
            500 => GetNodeVersionResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetNodeVersionResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/validator/attestation_data`: unsigned attestation data
    /// for a slot and committee index, as JSON or SSZ depending on the node's
    /// `Content-Type`.
    pub async fn produce_attestation_data(
        &self,
        request: ProduceAttestationDataRequest,
    ) -> anyhow::Result<ProduceAttestationDataResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "attestation_data"])?;
        let response = self.client.get(url).query(&request.query).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => match json_or_binary_body(response).await? {
                SuccessBody::Json(data) => ProduceAttestationDataResponse::Ok(data),
                SuccessBody::Binary(bytes) => ProduceAttestationDataResponse::OkBinary(bytes),
                SuccessBody::Unsupported => ProduceAttestationDataResponse::Unknown,
            },
            400 => ProduceAttestationDataResponse::BadRequest(json_body(response).await?),
            406 => ProduceAttestationDataResponse::NotAcceptable(json_body(response).await?),
            500 => ProduceAttestationDataResponse::InternalServerError(json_body(response).await?),
            503 => ProduceAttestationDataResponse::ServiceUnavailable(json_body(response).await?),
            _ => {
                drain(response).await?;
                ProduceAttestationDataResponse::Unknown
            }
        })
    }

    /// `POST /eth/v1/validator/beacon_committee_selections`: exchanges
    /// partial beacon committee selection proofs for aggregated ones.
    pub async fn submit_beacon_committee_selections(
        &self,
        request: SubmitBeaconCommitteeSelectionsRequest,
    ) -> anyhow::Result<SubmitBeaconCommitteeSelectionsResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "beacon_committee_selections"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => SubmitBeaconCommitteeSelectionsResponse::Ok(json_body(response).await?),
            400 => SubmitBeaconCommitteeSelectionsResponse::BadRequest(json_body(response).await?),
            500 => SubmitBeaconCommitteeSelectionsResponse::InternalServerError(
                json_body(response).await?,
            ),
            501 => {
                SubmitBeaconCommitteeSelectionsResponse::NotImplemented(json_body(response).await?)
            }
            503 => SubmitBeaconCommitteeSelectionsResponse::ServiceUnavailable(
                json_body(response).await?,
            ),
            _ => {
                drain(response).await?;
                SubmitBeaconCommitteeSelectionsResponse::Unknown
            }
        })
    }

    /// `POST /eth/v1/validator/contribution_and_proofs`: submits signed sync
    /// committee contributions and proofs.
    pub async fn publish_contribution_and_proofs(
        &self,
        request: PublishContributionAndProofsRequest,
    ) -> anyhow::Result<PublishContributionAndProofsResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "contribution_and_proofs"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        parse_publish_contribution_and_proofs_response(response).await
    }

    /// `POST /eth/v1/validator/duties/attester/{epoch}`: attester duties of
    /// the validator indices in the body.
    pub async fn get_attester_duties(
        &self,
        request: GetAttesterDutiesRequest,
    ) -> anyhow::Result<GetAttesterDutiesResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&[
            "eth",
            "v1",
            "validator",
            "duties",
            "attester",
            &request.path.epoch,
        ])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetAttesterDutiesResponse::Ok(json_body(response).await?),
            400 => GetAttesterDutiesResponse::BadRequest(json_body(response).await?),
            500 => GetAttesterDutiesResponse::InternalServerError(json_body(response).await?),
            503 => GetAttesterDutiesResponse::ServiceUnavailable(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetAttesterDutiesResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/validator/duties/proposer/{epoch}`: the proposer of every
    /// slot in an epoch.
    pub async fn get_proposer_duties(
        &self,
        request: GetProposerDutiesRequest,
    ) -> anyhow::Result<GetProposerDutiesResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&[
            "eth",
            "v1",
            "validator",
            "duties",
            "proposer",
            &request.path.epoch,
        ])?;
        let response = self.client.get(url).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetProposerDutiesResponse::Ok(json_body(response).await?),
            400 => GetProposerDutiesResponse::BadRequest(json_body(response).await?),
            500 => GetProposerDutiesResponse::InternalServerError(json_body(response).await?),
            503 => GetProposerDutiesResponse::ServiceUnavailable(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetProposerDutiesResponse::Unknown
            }
        })
    }

    /// `POST /eth/v1/validator/duties/sync/{epoch}`: sync committee duties of
    /// the validator indices in the body.
    pub async fn get_sync_committee_duties(
        &self,
        request: GetSyncCommitteeDutiesRequest,
    ) -> anyhow::Result<GetSyncCommitteeDutiesResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&[
            "eth",
            "v1",
            "validator",
            "duties",
            "sync",
            &request.path.epoch,
        ])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => GetSyncCommitteeDutiesResponse::Ok(json_body(response).await?),
            400 => GetSyncCommitteeDutiesResponse::BadRequest(json_body(response).await?),
            500 => GetSyncCommitteeDutiesResponse::InternalServerError(json_body(response).await?),
            503 => GetSyncCommitteeDutiesResponse::ServiceUnavailable(json_body(response).await?),
            _ => {
                drain(response).await?;
                GetSyncCommitteeDutiesResponse::Unknown
            }
        })
    }

    /// `POST /eth/v1/validator/prepare_beacon_proposer`: tells the node which
    /// fee recipient to build blocks with for each validator.
    pub async fn prepare_beacon_proposer(
        &self,
        request: PrepareBeaconProposerRequest,
    ) -> anyhow::Result<PrepareBeaconProposerResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "prepare_beacon_proposer"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        parse_prepare_beacon_proposer_response(response).await
    }

    /// `POST /eth/v1/validator/register_validator`: forwards signed builder
    /// registrations to the node.
    pub async fn register_validator(
        &self,
        request: RegisterValidatorRequest,
    ) -> anyhow::Result<RegisterValidatorResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "register_validator"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => {
                drain(response).await?;
                RegisterValidatorResponse::Ok
            }
            400 => RegisterValidatorResponse::BadRequest(json_body(response).await?),
            415 => RegisterValidatorResponse::UnsupportedMediaType(json_body(response).await?),
            500 => RegisterValidatorResponse::InternalServerError(json_body(response).await?),
            _ => {
                drain(response).await?;
                RegisterValidatorResponse::Unknown
            }
        })
    }

    /// `GET /eth/v1/validator/sync_committee_contribution`: the aggregated
    /// sync committee contribution for a slot, subcommittee and block root.
    pub async fn produce_sync_committee_contribution(
        &self,
        request: ProduceSyncCommitteeContributionRequest,
    ) -> anyhow::Result<ProduceSyncCommitteeContributionResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "sync_committee_contribution"])?;
        let response = self.client.get(url).query(&request.query).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => ProduceSyncCommitteeContributionResponse::Ok(json_body(response).await?),
            400 => ProduceSyncCommitteeContributionResponse::BadRequest(json_body(response).await?),
            404 => ProduceSyncCommitteeContributionResponse::NotFound(json_body(response).await?),
            500 => ProduceSyncCommitteeContributionResponse::InternalServerError(
                json_body(response).await?,
            ),
            503 => ProduceSyncCommitteeContributionResponse::ServiceUnavailable(
                json_body(response).await?,
            ),
            _ => {
                drain(response).await?;
                ProduceSyncCommitteeContributionResponse::Unknown
            }
        })
    }

    /// `POST /eth/v1/validator/sync_committee_selections`: exchanges partial
    /// sync committee selection proofs for aggregated ones.
    pub async fn submit_sync_committee_selections(
        &self,
        request: SubmitSyncCommitteeSelectionsRequest,
    ) -> anyhow::Result<SubmitSyncCommitteeSelectionsResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "sync_committee_selections"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => SubmitSyncCommitteeSelectionsResponse::Ok(json_body(response).await?),
            400 => SubmitSyncCommitteeSelectionsResponse::BadRequest(json_body(response).await?),
            500 => SubmitSyncCommitteeSelectionsResponse::InternalServerError(
                json_body(response).await?,
            ),
            501 => {
                SubmitSyncCommitteeSelectionsResponse::NotImplemented(json_body(response).await?)
            }
            503 => SubmitSyncCommitteeSelectionsResponse::ServiceUnavailable(
                json_body(response).await?,
            ),
            _ => {
                drain(response).await?;
                SubmitSyncCommitteeSelectionsResponse::Unknown
            }
        })
    }

    /// `POST /eth/v1/validator/sync_committee_subscriptions`: subscribes the
    /// node to sync committee subnets.
    pub async fn prepare_sync_committee_subnets(
        &self,
        request: PrepareSyncCommitteeSubnetsRequest,
    ) -> anyhow::Result<PrepareBeaconProposerResponse> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v1", "validator", "sync_committee_subscriptions"])?;
        let response = self.client.post(url).json(&request.body).send().await?;

        parse_prepare_beacon_proposer_response(response).await
    }

    /// `GET /eth/v2/validator/aggregate_attestation`: the aggregate
    /// attestation for a slot, committee index and attestation data root, as
    /// JSON or SSZ depending on the node's `Content-Type`.
    pub async fn get_aggregated_attestation_v2(
        &self,
        request: GetAggregatedAttestationV2Request,
    ) -> anyhow::Result<GetAggregatedAttestationV2Response> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v2", "validator", "aggregate_attestation"])?;
        let response = self.client.get(url).query(&request.query).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => match json_or_binary_body(response).await? {
                SuccessBody::Json(data) => GetAggregatedAttestationV2Response::Ok(data),
                SuccessBody::Binary(bytes) => GetAggregatedAttestationV2Response::OkBinary(bytes),
                SuccessBody::Unsupported => GetAggregatedAttestationV2Response::Unknown,
            },
            400 => GetAggregatedAttestationV2Response::BadRequest(json_body(response).await?),
            404 => GetAggregatedAttestationV2Response::NotFound(json_body(response).await?),
            406 => GetAggregatedAttestationV2Response::NotAcceptable(json_body(response).await?),
            500 => {
                GetAggregatedAttestationV2Response::InternalServerError(json_body(response).await?)
            }
            _ => {
                drain(response).await?;
                GetAggregatedAttestationV2Response::Unknown
            }
        })
    }

    /// `POST /eth/v2/validator/aggregate_and_proofs`: submits signed
    /// aggregate-and-proof messages, tagged with their consensus version.
    pub async fn publish_aggregate_and_proofs_v2(
        &self,
        request: PublishAggregateAndProofsV2Request,
    ) -> anyhow::Result<SubmitPoolAttestationsV2Response> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v2", "validator", "aggregate_and_proofs"])?;
        let response = self
            .client
            .post(url)
            .header(
                ETH_CONSENSUS_VERSION,
                request.header.eth_consensus_version.to_string(),
            )
            .json(&request.body)
            .send()
            .await?;

        parse_submit_pool_attestations_response(response).await
    }

    /// `GET /eth/v3/validator/blocks/{slot}`: an unsigned block (blinded or
    /// not) for the slot, as JSON or SSZ depending on the node's
    /// `Content-Type`.
    pub async fn produce_block_v3(
        &self,
        request: ProduceBlockV3Request,
    ) -> anyhow::Result<ProduceBlockV3Response> {
        request.validate().context("parameter validation")?;
        let url = self.url(&["eth", "v3", "validator", "blocks", &request.path.slot])?;
        let response = self.client.get(url).query(&request.query).send().await?;

        Ok(match response.status().as_u16() {
            200..=299 => match json_or_binary_body(response).await? {
                SuccessBody::Json(data) => ProduceBlockV3Response::Ok(data),
                SuccessBody::Binary(bytes) => ProduceBlockV3Response::OkBinary(bytes),
                SuccessBody::Unsupported => ProduceBlockV3Response::Unknown,
            },
            400 => ProduceBlockV3Response::BadRequest(json_body(response).await?),
            406 => ProduceBlockV3Response::NotAcceptable(json_body(response).await?),
            500 => ProduceBlockV3Response::InternalServerError(json_body(response).await?),
            503 => ProduceBlockV3Response::ServiceUnavailable(json_body(response).await?),
            _ => {
                drain(response).await?;
                ProduceBlockV3Response::Unknown
            }
        })
    }
}

/// Response mapping shared by the block and blinded-block publish endpoints.
async fn parse_publish_block_response(
    response: Response,
) -> anyhow::Result<PublishBlockV2Response> {
    Ok(match response.status().as_u16() {
        202 => {
            drain(response).await?;
            PublishBlockV2Response::Accepted
        }
        200..=299 => {
            drain(response).await?;
            PublishBlockV2Response::Ok
        }
        400 => PublishBlockV2Response::BadRequest(json_body(response).await?),
        415 => PublishBlockV2Response::UnsupportedMediaType(json_body(response).await?),
        500 => PublishBlockV2Response::InternalServerError(json_body(response).await?),
        503 => PublishBlockV2Response::ServiceUnavailable(json_body(response).await?),
        _ => {
            drain(response).await?;
            PublishBlockV2Response::Unknown
        }
    })
}

/// Response mapping shared by the attestation and aggregate-and-proof
/// submit endpoints.
async fn parse_submit_pool_attestations_response(
    response: Response,
) -> anyhow::Result<SubmitPoolAttestationsV2Response> {
    Ok(match response.status().as_u16() {
        200..=299 => {
            drain(response).await?;
            SubmitPoolAttestationsV2Response::Ok
        }
        400 => SubmitPoolAttestationsV2Response::BadRequest(json_body(response).await?),
        415 => SubmitPoolAttestationsV2Response::UnsupportedMediaType(json_body(response).await?),
        500 => SubmitPoolAttestationsV2Response::InternalServerError(json_body(response).await?),
        _ => {
            drain(response).await?;
            SubmitPoolAttestationsV2Response::Unknown
        }
    })
}

/// Response mapping shared by the sync committee message and contribution
/// submit endpoints.
async fn parse_publish_contribution_and_proofs_response(
    response: Response,
) -> anyhow::Result<PublishContributionAndProofsResponse> {
    Ok(match response.status().as_u16() {
        200..=299 => {
            drain(response).await?;
            PublishContributionAndProofsResponse::Ok
        }
        400 => PublishContributionAndProofsResponse::BadRequest(json_body(response).await?),
        500 => {
            PublishContributionAndProofsResponse::InternalServerError(json_body(response).await?)
        }
        _ => {
            drain(response).await?;
            PublishContributionAndProofsResponse::Unknown
        }
    })
}

/// Response mapping shared by the proposer preparation and sync committee
/// subscription endpoints.
async fn parse_prepare_beacon_proposer_response(
    response: Response,
) -> anyhow::Result<PrepareBeaconProposerResponse> {
    Ok(match response.status().as_u16() {
        200..=299 => {
            drain(response).await?;
            PrepareBeaconProposerResponse::Ok
        }
        400 => PrepareBeaconProposerResponse::BadRequest(json_body(response).await?),
        500 => PrepareBeaconProposerResponse::InternalServerError(json_body(response).await?),
        _ => {
            drain(response).await?;
            PrepareBeaconProposerResponse::Unknown
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{any, method, path},
    };

    /// A status no endpoint documents, so every method maps it to `Unknown`.
    const UNDOCUMENTED_STATUS: u16 = 418;

    fn signature() -> String {
        format!("0x{}", "ab".repeat(96))
    }

    fn root() -> String {
        format!("0x{}", "cd".repeat(32))
    }

    fn test_client(server: &MockServer) -> EthBeaconNodeApiClient {
        EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid mock server URL")
    }

    fn signed_block_body() -> BlockRequestBody {
        BlockRequestBody::Object7(GetBlindedBlockResponseResponseDataObject6 {
            message: json!({}),
            signature: signature(),
        })
    }

    fn publish_block_request() -> PublishBlockV2Request {
        PublishBlockV2Request {
            query: PublishBlockV2RequestQuery {
                broadcast_validation: Some(BroadcastValidation::Gossip),
            },
            header: PublishBlockV2RequestHeader {
                eth_consensus_version: ConsensusVersion::Electra,
            },
            body: signed_block_body(),
        }
    }

    fn produce_block_request() -> ProduceBlockV3Request {
        ProduceBlockV3Request {
            path: ProduceBlockV3RequestPath { slot: "7".into() },
            query: ProduceBlockV3RequestQuery {
                randao_reveal: signature(),
                graffiti: None,
                skip_randao_verification: None,
                builder_boost_factor: None,
            },
        }
    }

    /// Every endpoint sends the documented method, path, query and headers,
    /// and maps an undocumented status to its `Unknown` variant.
    #[tokio::test]
    async fn requests_have_the_documented_shape() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(UNDOCUMENTED_STATUS))
            .mount(&server)
            .await;
        let client = test_client(&server);

        let contribution_query =
            format!("slot=1&subcommittee_index=0&beacon_block_root={}", root());
        let aggregate_query = format!("attestation_data_root={}&slot=1&committee_index=2", root());
        let block_query = format!("randao_reveal={}", signature());

        // (method, path, query, consensus version header), in call order.
        let mut expected: Vec<(&str, &str, Option<&str>, Option<&str>)> = Vec::new();
        macro_rules! check {
            ($call:expr, $unknown:path, $method:literal, $path:literal, $query:expr, $version:expr) => {{
                let response = $call.await.expect("request succeeds");
                assert!(
                    matches!(response, $unknown),
                    "{} answered {response:?}",
                    $path
                );
                expected.push(($method, $path, $query, $version));
            }};
        }

        check!(
            client.get_genesis(GetGenesisRequest {}),
            GetGenesisResponse::Unknown,
            "GET",
            "/eth/v1/beacon/genesis",
            None,
            None
        );
        check!(
            client.get_block_root(GetBlockRootRequest {
                path: GetBlockRootRequestPath {
                    block_id: "head".into(),
                },
            }),
            GetBlockRootResponse::Unknown,
            "GET",
            "/eth/v1/beacon/blocks/head/root",
            None,
            None
        );
        check!(
            client.get_block_header(GetBlockHeaderRequest {
                path: GetBlockHeaderRequestPath {
                    block_id: "finalized".into(),
                },
            }),
            GetBlockHeaderResponse::Unknown,
            "GET",
            "/eth/v1/beacon/headers/finalized",
            None,
            None
        );
        check!(
            client.get_block_v2(GetBlockV2Request {
                path: GetBlockV2RequestPath {
                    block_id: "42".into(),
                },
            }),
            GetBlockV2Response::Unknown,
            "GET",
            "/eth/v2/beacon/blocks/42",
            None,
            None
        );
        check!(
            client.post_state_validators(PostStateValidatorsRequest {
                path: PostStateValidatorsRequestPath {
                    state_id: "head".into(),
                },
                body: ValidatorRequestBody::default(),
            }),
            PostStateValidatorsResponse::Unknown,
            "POST",
            "/eth/v1/beacon/states/head/validators",
            None,
            None
        );
        check!(
            client.publish_block_v2(publish_block_request()),
            PublishBlockV2Response::Unknown,
            "POST",
            "/eth/v2/beacon/blocks",
            Some("broadcast_validation=gossip"),
            Some("electra")
        );
        check!(
            client.publish_blinded_block_v2(PublishBlindedBlockV2Request {
                query: PublishBlindedBlockV2RequestQuery {
                    broadcast_validation: None,
                },
                header: PublishBlindedBlockV2RequestHeader {
                    eth_consensus_version: ConsensusVersion::Deneb,
                },
                body: GetBlindedBlockResponseResponseData::Object(
                    GetBlindedBlockResponseResponseDataObject {
                        message: json!({}),
                        signature: signature(),
                    },
                ),
            }),
            PublishBlockV2Response::Unknown,
            "POST",
            "/eth/v2/beacon/blinded_blocks",
            None,
            Some("deneb")
        );
        check!(
            client.submit_pool_attestations_v2(SubmitPoolAttestationsV2Request {
                header: SubmitPoolAttestationsV2RequestHeader {
                    eth_consensus_version: ConsensusVersion::Fulu,
                },
                body: AttestationRequestBody2::Array(Vec::new()),
            }),
            SubmitPoolAttestationsV2Response::Unknown,
            "POST",
            "/eth/v2/beacon/pool/attestations",
            None,
            Some("fulu")
        );
        check!(
            client.submit_pool_sync_committee_signatures(
                SubmitPoolSyncCommitteeSignaturesRequest { body: Vec::new() }
            ),
            PublishContributionAndProofsResponse::Unknown,
            "POST",
            "/eth/v1/beacon/pool/sync_committees",
            None,
            None
        );
        check!(
            client.submit_pool_voluntary_exit(SubmitPoolVoluntaryExitRequest {
                body: GetPoolVoluntaryExitsResponseResponseDatum {
                    message: Phase0SignedVoluntaryExitMessage {
                        epoch: "1".into(),
                        validator_index: "2".into(),
                    },
                    signature: signature(),
                },
            }),
            SubmitPoolVoluntaryExitResponse::Unknown,
            "POST",
            "/eth/v1/beacon/pool/voluntary_exits",
            None,
            None
        );
        check!(
            client.get_fork_schedule(GetForkScheduleRequest {}),
            GetForkScheduleResponse::Unknown,
            "GET",
            "/eth/v1/config/fork_schedule",
            None,
            None
        );
        check!(
            client.get_spec(GetSpecRequest {}),
            GetSpecResponse::Unknown,
            "GET",
            "/eth/v1/config/spec",
            None,
            None
        );
        check!(
            client.get_peer_count(GetPeerCountRequest {}),
            GetPeerCountResponse::Unknown,
            "GET",
            "/eth/v1/node/peer_count",
            None,
            None
        );
        check!(
            client.get_syncing_status(GetSyncingStatusRequest {}),
            GetSyncingStatusResponse::Unknown,
            "GET",
            "/eth/v1/node/syncing",
            None,
            None
        );
        check!(
            client.get_node_version(GetNodeVersionRequest {}),
            GetNodeVersionResponse::Unknown,
            "GET",
            "/eth/v1/node/version",
            None,
            None
        );
        check!(
            client.produce_attestation_data(ProduceAttestationDataRequest {
                query: ProduceAttestationDataRequestQuery {
                    slot: "1".into(),
                    committee_index: "2".into(),
                },
            }),
            ProduceAttestationDataResponse::Unknown,
            "GET",
            "/eth/v1/validator/attestation_data",
            Some("slot=1&committee_index=2"),
            None
        );
        check!(
            client.submit_beacon_committee_selections(SubmitBeaconCommitteeSelectionsRequest {
                body: Vec::new(),
            }),
            SubmitBeaconCommitteeSelectionsResponse::Unknown,
            "POST",
            "/eth/v1/validator/beacon_committee_selections",
            None,
            None
        );
        check!(
            client.publish_contribution_and_proofs(PublishContributionAndProofsRequest {
                body: Vec::new(),
            }),
            PublishContributionAndProofsResponse::Unknown,
            "POST",
            "/eth/v1/validator/contribution_and_proofs",
            None,
            None
        );
        check!(
            client.get_attester_duties(GetAttesterDutiesRequest {
                path: GetAttesterDutiesRequestPath { epoch: "3".into() },
                body: vec!["1".into()],
            }),
            GetAttesterDutiesResponse::Unknown,
            "POST",
            "/eth/v1/validator/duties/attester/3",
            None,
            None
        );
        check!(
            client.get_proposer_duties(GetProposerDutiesRequest {
                path: GetProposerDutiesRequestPath { epoch: "3".into() },
            }),
            GetProposerDutiesResponse::Unknown,
            "GET",
            "/eth/v1/validator/duties/proposer/3",
            None,
            None
        );
        check!(
            client.get_sync_committee_duties(GetSyncCommitteeDutiesRequest {
                path: GetSyncCommitteeDutiesRequestPath { epoch: "3".into() },
                body: Vec::new(),
            }),
            GetSyncCommitteeDutiesResponse::Unknown,
            "POST",
            "/eth/v1/validator/duties/sync/3",
            None,
            None
        );
        check!(
            client.prepare_beacon_proposer(PrepareBeaconProposerRequest { body: Vec::new() }),
            PrepareBeaconProposerResponse::Unknown,
            "POST",
            "/eth/v1/validator/prepare_beacon_proposer",
            None,
            None
        );
        check!(
            client.register_validator(RegisterValidatorRequest { body: Vec::new() }),
            RegisterValidatorResponse::Unknown,
            "POST",
            "/eth/v1/validator/register_validator",
            None,
            None
        );
        check!(
            client.produce_sync_committee_contribution(ProduceSyncCommitteeContributionRequest {
                query: ProduceSyncCommitteeContributionRequestQuery {
                    slot: "1".into(),
                    subcommittee_index: "0".into(),
                    beacon_block_root: root(),
                },
            }),
            ProduceSyncCommitteeContributionResponse::Unknown,
            "GET",
            "/eth/v1/validator/sync_committee_contribution",
            Some(contribution_query.as_str()),
            None
        );
        check!(
            client.submit_sync_committee_selections(SubmitSyncCommitteeSelectionsRequest {
                body: Vec::new(),
            }),
            SubmitSyncCommitteeSelectionsResponse::Unknown,
            "POST",
            "/eth/v1/validator/sync_committee_selections",
            None,
            None
        );
        check!(
            client.prepare_sync_committee_subnets(PrepareSyncCommitteeSubnetsRequest {
                body: Vec::new(),
            }),
            PrepareBeaconProposerResponse::Unknown,
            "POST",
            "/eth/v1/validator/sync_committee_subscriptions",
            None,
            None
        );
        check!(
            client.get_aggregated_attestation_v2(GetAggregatedAttestationV2Request {
                query: GetAggregatedAttestationV2RequestQuery {
                    attestation_data_root: root(),
                    slot: "1".into(),
                    committee_index: "2".into(),
                },
            }),
            GetAggregatedAttestationV2Response::Unknown,
            "GET",
            "/eth/v2/validator/aggregate_attestation",
            Some(aggregate_query.as_str()),
            None
        );
        check!(
            client.publish_aggregate_and_proofs_v2(PublishAggregateAndProofsV2Request {
                header: PublishAggregateAndProofsV2RequestHeader {
                    eth_consensus_version: ConsensusVersion::Electra,
                },
                body: AggregateAndProofRequestBody::Array(Vec::new()),
            }),
            SubmitPoolAttestationsV2Response::Unknown,
            "POST",
            "/eth/v2/validator/aggregate_and_proofs",
            None,
            Some("electra")
        );
        check!(
            client.produce_block_v3(produce_block_request()),
            ProduceBlockV3Response::Unknown,
            "GET",
            "/eth/v3/validator/blocks/7",
            Some(block_query.as_str()),
            None
        );

        let received = server
            .received_requests()
            .await
            .expect("request recording is enabled");
        assert_eq!(received.len(), expected.len());
        for (request, (method, path, query, version)) in received.iter().zip(expected) {
            assert_eq!(request.method.as_str(), method, "{path}");
            assert_eq!(request.url.path(), path);
            assert_eq!(request.url.query(), query, "{path}");
            let header = |name: &str| {
                request
                    .headers
                    .get(name)
                    .map(|value| value.to_str().expect("ASCII header"))
            };
            assert_eq!(header("eth-consensus-version"), version, "{path}");
            if method == "POST" {
                assert_eq!(header("content-type"), Some("application/json"), "{path}");
            }
        }
    }

    #[tokio::test]
    async fn json_success_maps_to_ok() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": { "SLOTS": "32" } })),
            )
            .mount(&server)
            .await;

        let GetSpecResponse::Ok(spec) = test_client(&server)
            .get_spec(GetSpecRequest {})
            .await
            .expect("request succeeds")
        else {
            panic!("expected Ok");
        };
        assert_eq!(spec.data["SLOTS"], "32");
    }

    /// JSON-only endpoints decode a 2xx body whatever the `Content-Type`.
    #[tokio::test]
    async fn json_success_ignores_content_type() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(r#"{"data":{}}"#, "text/plain"))
            .mount(&server)
            .await;

        let response = test_client(&server)
            .get_spec(GetSpecRequest {})
            .await
            .expect("request succeeds");
        assert!(matches!(response, GetSpecResponse::Ok(_)), "{response:?}");
    }

    #[tokio::test]
    async fn documented_error_statuses_map_to_typed_variants() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/3"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({ "code": 400, "message": "bad epoch" })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(json!({ "code": 500, "message": "boom" })),
            )
            .mount(&server)
            .await;
        let client = test_client(&server);

        let GetAttesterDutiesResponse::BadRequest(error) = client
            .get_attester_duties(GetAttesterDutiesRequest {
                path: GetAttesterDutiesRequestPath { epoch: "3".into() },
                body: Vec::new(),
            })
            .await
            .expect("request succeeds")
        else {
            panic!("expected BadRequest");
        };
        assert_eq!(error.message, "bad epoch");

        let GetSpecResponse::InternalServerError(error) = client
            .get_spec(GetSpecRequest {})
            .await
            .expect("request succeeds")
        else {
            panic!("expected InternalServerError");
        };
        assert_eq!(error.message, "boom");
    }

    #[tokio::test]
    async fn binary_success_maps_to_ok_binary() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/7"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(vec![1, 2, 3], "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let response = test_client(&server)
            .produce_block_v3(produce_block_request())
            .await
            .expect("request succeeds");
        assert!(
            matches!(response, ProduceBlockV3Response::OkBinary(ref bytes) if bytes == &[1, 2, 3]),
            "{response:?}"
        );
    }

    #[tokio::test]
    async fn binary_capable_success_with_foreign_content_type_is_unknown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/7"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("block", "text/plain"))
            .mount(&server)
            .await;

        let response = test_client(&server)
            .produce_block_v3(produce_block_request())
            .await
            .expect("request succeeds");
        assert!(
            matches!(response, ProduceBlockV3Response::Unknown),
            "{response:?}"
        );
    }

    #[tokio::test]
    async fn publish_block_distinguishes_accepted_from_ok() {
        for (status, accepted) in [(200, false), (202, true)] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/eth/v2/beacon/blocks"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            let response = test_client(&server)
                .publish_block_v2(publish_block_request())
                .await
                .expect("request succeeds");
            assert_eq!(
                matches!(response, PublishBlockV2Response::Accepted),
                accepted,
                "status {status} answered {response:?}"
            );
            assert_eq!(
                matches!(response, PublishBlockV2Response::Ok),
                !accepted,
                "status {status} answered {response:?}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_success_body_names_the_failing_field() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "genesis_time": 1606824023,
                    "genesis_validators_root": root(),
                    "genesis_fork_version": "0x00000000",
                }
            })))
            .mount(&server)
            .await;

        let error = test_client(&server)
            .get_genesis(GetGenesisRequest {})
            .await
            .expect_err("a non-string genesis_time must fail decoding");
        assert!(
            format!("{error:#}").contains("data.genesis_time"),
            "error does not name the field: {error:#}"
        );
    }

    #[tokio::test]
    async fn invalid_request_is_rejected_before_sending() {
        let server = MockServer::start().await;
        let mut request = produce_block_request();
        request.query.randao_reveal = "not-a-signature".into();

        let error = test_client(&server)
            .produce_block_v3(request)
            .await
            .expect_err("validation must fail");
        assert!(
            format!("{error:#}").contains("parameter validation"),
            "{error:#}"
        );
        assert!(
            server
                .received_requests()
                .await
                .expect("recording")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn transport_failure_is_an_error() {
        // Nothing listens on the reserved port 1.
        let client = EthBeaconNodeApiClient::with_base_url("http://127.0.0.1:1").expect("valid");
        client
            .get_spec(GetSpecRequest {})
            .await
            .expect_err("connection refused must surface as an error");
    }

    #[test]
    fn url_keeps_the_base_path_prefix() {
        let client = EthBeaconNodeApiClient::with_base_url("http://beacon.example:5052/prefix")
            .expect("valid");
        assert_eq!(
            client
                .url(&["eth", "v1", "config", "spec"])
                .expect("url")
                .as_str(),
            "http://beacon.example:5052/prefix/eth/v1/config/spec"
        );
    }

    #[test]
    fn url_rejects_a_base_that_cannot_have_a_path() {
        let client = EthBeaconNodeApiClient::with_base_url("mailto:node@example").expect("valid");
        let error = client.url(&["eth"]).expect_err("cannot-be-a-base URL");
        assert!(error.to_string().contains("cannot be a base"), "{error}");
    }
}
