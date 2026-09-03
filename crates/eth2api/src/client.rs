//! HTTP client for a single beacon node.
//!
//! One method per Beacon API endpoint Pluto uses. Methods take typed
//! parameters, exchange JSON, and return the decoded payload: the `data`
//! value for endpoints whose envelope carries nothing else, a named envelope
//! struct where the node adds metadata. A non-2xx status is
//! [`EthBeaconNodeApiClientError::Http`]; transport and decoding failures are
//! [`EthBeaconNodeApiClientError::Transport`] and
//! [`EthBeaconNodeApiClientError::Decode`].
//!
//! The `fetch_*` methods derive values from several endpoints and cache the
//! static chain configuration (spec, genesis, fork schedule) per endpoint.

use crate::{
    EthBeaconNodeApiClientError, PayloadError,
    spec::{BuilderVersion, DataVersion, altair, electra, phase0},
    types::*,
    v1, versioned,
};
use alloy::primitives::U256;
use chrono::{DateTime, Utc};
use eventsource_stream::Eventsource;
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url, header::ACCEPT};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock, Mutex},
    time,
};
use tokio::sync::OnceCell;
use tokio_stream::{Stream, StreamExt};

type Result<T> = std::result::Result<T, EthBeaconNodeApiClientError>;

/// Client for one beacon node.
#[derive(Debug, Clone)]
pub struct EthBeaconNodeApiClient {
    /// HTTP client the requests are sent with.
    pub client: Client,
    /// Beacon node URL; endpoint paths are appended to its path.
    pub base_url: Url,
}

/// `{ "data": .. }`, the envelope of endpoints that return nothing else.
#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

/// `{ "version": .., "data": .. }`, the envelope of endpoints whose payload
/// shape depends on the fork.
#[derive(Deserialize)]
struct Versioned<'a> {
    version: DataVersion,
    #[serde(default)]
    execution_optimistic: bool,
    #[serde(default)]
    finalized: bool,
    #[serde(borrow)]
    data: &'a RawValue,
}

/// Envelope of `GET /eth/v3/validator/blocks/{slot}`.
#[derive(Deserialize)]
struct Proposal<'a> {
    version: DataVersion,
    #[serde(default)]
    execution_payload_blinded: bool,
    #[serde(default, with = "crate::spec::serde_utils::u256_dec_serde")]
    execution_payload_value: U256,
    #[serde(default, with = "crate::spec::serde_utils::u256_dec_serde")]
    consensus_block_value: U256,
    #[serde(borrow)]
    data: &'a RawValue,
}

#[derive(Deserialize)]
struct NodeVersion {
    version: String,
}

/// Decodes JSON, naming the offending field path on failure.
fn decode<'a, T: Deserialize<'a>>(body: &'a str) -> Result<T> {
    let mut deserializer = serde_json::Deserializer::from_str(body);
    Ok(serde_path_to_error::deserialize(&mut deserializer)?)
}

/// Decodes the JSON body of a 2xx response.
async fn json<T: DeserializeOwned>(response: Response) -> Result<T> {
    let body = response.text().await?;
    decode(&body)
}

/// Decodes the `data` field of a 2xx response.
async fn data<T: DeserializeOwned>(response: Response) -> Result<T> {
    Ok(json::<Data<T>>(response).await?.data)
}

/// Drains a 2xx response without a payload.
async fn empty(response: Response) -> Result<()> {
    response.bytes().await?;
    Ok(())
}

/// Returns the `Eth-Consensus-Version` header value for `version`.
fn consensus_version(version: DataVersion) -> Result<&'static str> {
    if version == DataVersion::Unknown {
        return Err(PayloadError::UnknownVersion.into());
    }
    Ok(version.as_str())
}

/// Returns the version shared by every element of `versions`.
fn common_version(mut versions: impl Iterator<Item = DataVersion>) -> Result<&'static str> {
    let first = versions.next().ok_or(PayloadError::Empty)?;
    if !versions.all(|version| version == first) {
        return Err(PayloadError::MixedVersions.into());
    }
    consensus_version(first)
}

fn decode_proposal_block(
    version: DataVersion,
    blinded: bool,
    body: &str,
) -> Result<versioned::ProposalBlock> {
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let mut track = serde_path_to_error::Track::new();
    let tracked = serde_path_to_error::Deserializer::new(&mut deserializer, &mut track);
    versioned::ProposalBlock::from_json(version, blinded, tracked)
        .map_err(|error| serde_path_to_error::Error::new(track.path(), error).into())
}

fn decode_signed_block(version: DataVersion, body: &str) -> Result<versioned::SignedBeaconBlock> {
    use versioned::SignedBeaconBlock;

    Ok(match version {
        DataVersion::Phase0 => SignedBeaconBlock::Phase0(decode(body)?),
        DataVersion::Altair => SignedBeaconBlock::Altair(decode(body)?),
        DataVersion::Bellatrix => SignedBeaconBlock::Bellatrix(decode(body)?),
        DataVersion::Capella => SignedBeaconBlock::Capella(decode(body)?),
        DataVersion::Deneb => SignedBeaconBlock::Deneb(decode(body)?),
        DataVersion::Electra => SignedBeaconBlock::Electra(decode(body)?),
        DataVersion::Fulu => SignedBeaconBlock::Fulu(decode(body)?),
        DataVersion::Unknown => return Err(PayloadError::UnknownVersion.into()),
    })
}

fn decode_attestation(version: DataVersion, body: &str) -> Result<versioned::AttestationPayload> {
    use versioned::AttestationPayload;

    Ok(match version {
        DataVersion::Phase0 => AttestationPayload::Phase0(decode(body)?),
        DataVersion::Altair => AttestationPayload::Altair(decode(body)?),
        DataVersion::Bellatrix => AttestationPayload::Bellatrix(decode(body)?),
        DataVersion::Capella => AttestationPayload::Capella(decode(body)?),
        DataVersion::Deneb => AttestationPayload::Deneb(decode(body)?),
        DataVersion::Electra => AttestationPayload::Electra(decode(body)?),
        DataVersion::Fulu => AttestationPayload::Fulu(decode(body)?),
        DataVersion::Unknown => return Err(PayloadError::UnknownVersion.into()),
    })
}

/// Position of the lowest set bit, i.e. the committee index a single-committee
/// `committee_bits` vector denotes.
fn first_set_bit(bytes: &[u8]) -> Option<u64> {
    let (byte_index, byte) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0)?;
    u64::try_from(byte_index)
        .ok()?
        .checked_mul(8)?
        .checked_add(u64::from(byte.trailing_zeros()))
}

/// Body of `POST /eth/v2/beacon/pool/attestations`, whose element shape
/// changes at Electra.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum PoolAttestations<'a> {
    Legacy(Vec<&'a phase0::Attestation>),
    Single(Vec<electra::SingleAttestation>),
}

fn pool_attestations(
    version: DataVersion,
    attestations: &[versioned::VersionedAttestation],
) -> std::result::Result<PoolAttestations<'_>, PayloadError> {
    use versioned::AttestationPayload;

    let wrong_fork = |attestation: &versioned::VersionedAttestation| PayloadError::WrongFork {
        submission: version,
        payload: attestation.version,
    };

    if version.is_before_electra() {
        let items = attestations
            .iter()
            .map(|attestation| match attestation.attestation.as_ref() {
                Some(
                    AttestationPayload::Phase0(payload)
                    | AttestationPayload::Altair(payload)
                    | AttestationPayload::Bellatrix(payload)
                    | AttestationPayload::Capella(payload)
                    | AttestationPayload::Deneb(payload),
                ) => Ok(payload),
                Some(AttestationPayload::Electra(_) | AttestationPayload::Fulu(_)) => {
                    Err(wrong_fork(attestation))
                }
                None => Err(PayloadError::MissingAttestation),
            })
            .collect::<std::result::Result<_, _>>()?;
        return Ok(PoolAttestations::Legacy(items));
    }

    let items = attestations
        .iter()
        .map(|attestation| {
            let payload = match attestation.attestation.as_ref() {
                Some(AttestationPayload::Electra(payload) | AttestationPayload::Fulu(payload)) => {
                    payload
                }
                Some(_) => return Err(wrong_fork(attestation)),
                None => return Err(PayloadError::MissingAttestation),
            };
            let attester_index = attestation
                .validator_index
                .ok_or(PayloadError::MissingValidatorIndex)?;
            let committee_index =
                first_set_bit(&payload.committee_bits.bytes).ok_or(PayloadError::NoCommitteeBit)?;
            Ok(electra::SingleAttestation {
                committee_index,
                attester_index,
                data: payload.data.clone(),
                signature: payload.signature,
            })
        })
        .collect::<std::result::Result<_, _>>()?;
    Ok(PoolAttestations::Single(items))
}

impl EthBeaconNodeApiClient {
    /// Creates a client for `base_url` with a default [`reqwest::Client`].
    pub fn with_base_url(base_url: impl AsRef<str>) -> Result<Self> {
        Self::with_client(base_url, Client::builder().build()?)
    }

    /// Creates a client for `base_url` that sends its requests with `client`.
    pub fn with_client(base_url: impl AsRef<str>, client: Client) -> Result<Self> {
        let base_url = Url::parse(base_url.as_ref())?;
        if base_url.cannot_be_a_base() {
            return Err(EthBeaconNodeApiClientError::UrlCannotBeABase);
        }
        Ok(Self { client, base_url })
    }

    /// Appends `segments` to the base URL path.
    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("with_client rejects URLs that cannot be a base")
            .extend(segments);
        url
    }

    fn get(&self, segments: &[&str]) -> RequestBuilder {
        self.client
            .get(self.url(segments))
            .header(ACCEPT, "application/json")
    }

    fn post(&self, segments: &[&str]) -> RequestBuilder {
        self.client.post(self.url(segments))
    }

    /// Sends `request` and returns the response for a 2xx status, an
    /// [`HttpError`] otherwise.
    async fn send(&self, request: RequestBuilder) -> Result<Response> {
        let request = request.build()?;
        let method = request.method().clone();
        let response = self.client.execute(request).await?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let endpoint = response.url().path().to_owned();
        let text = response.text().await?;
        let body = serde_json::from_str(&text).unwrap_or_else(|_| ErrorBody {
            message: text,
            ..ErrorBody::default()
        });
        Err(HttpError {
            status,
            method,
            endpoint,
            body,
        }
        .into())
    }

    /// `GET /eth/v1/beacon/genesis`: genesis time, validators root and fork
    /// version.
    pub async fn get_genesis(&self) -> Result<v1::Genesis> {
        data(
            self.send(self.get(&["eth", "v1", "beacon", "genesis"]))
                .await?,
        )
        .await
    }

    /// `GET /eth/v1/beacon/blocks/{block_id}/root`: the root of a block.
    pub async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse> {
        json(
            self.send(self.get(&["eth", "v1", "beacon", "blocks", block_id, "root"]))
                .await?,
        )
        .await
    }

    /// `GET /eth/v1/beacon/headers/{block_id}`: the signed header of a block.
    pub async fn get_block_header(&self, block_id: &str) -> Result<BlockHeaderResponse> {
        json(
            self.send(self.get(&["eth", "v1", "beacon", "headers", block_id]))
                .await?,
        )
        .await
    }

    /// `GET /eth/v2/beacon/blocks/{block_id}`: a full signed block, or `None`
    /// when no block exists for `block_id`.
    pub async fn get_block_v2(&self, block_id: &str) -> Result<Option<SignedBlockResponse>> {
        let response = match self
            .send(self.get(&["eth", "v2", "beacon", "blocks", block_id]))
            .await
        {
            Err(EthBeaconNodeApiClientError::Http(http))
                if http.status == StatusCode::NOT_FOUND =>
            {
                return Ok(None);
            }
            response => response?,
        };
        let body = response.text().await?;
        let envelope: Versioned<'_> = decode(&body)?;

        Ok(Some(SignedBlockResponse {
            version: envelope.version,
            execution_optimistic: envelope.execution_optimistic,
            finalized: envelope.finalized,
            data: decode_signed_block(envelope.version, envelope.data.get())?,
        }))
    }

    /// `POST /eth/v1/beacon/states/{state_id}/validators`: validators of a
    /// state, narrowed by `filter`.
    pub async fn post_state_validators(
        &self,
        state_id: &str,
        filter: &ValidatorsFilter,
    ) -> Result<ValidatorsResponse> {
        json(
            self.send(
                self.post(&["eth", "v1", "beacon", "states", state_id, "validators"])
                    .json(filter),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v2/beacon/blocks`: publishes a signed block (with blobs from
    /// Deneb on).
    pub async fn publish_block_v2(
        &self,
        proposal: &versioned::VersionedSignedProposal,
        broadcast_validation: Option<BroadcastValidation>,
    ) -> Result<()> {
        if proposal.blinded {
            return Err(PayloadError::BlindedOnUnblindedEndpoint.into());
        }
        let mut request = self
            .post(&["eth", "v2", "beacon", "blocks"])
            .header(ETH_CONSENSUS_VERSION, consensus_version(proposal.version)?)
            .json(&proposal.block);
        if let Some(validation) = broadcast_validation {
            request = request.query(&[("broadcast_validation", validation.as_str())]);
        }
        empty(self.send(request).await?).await
    }

    /// `POST /eth/v2/beacon/blinded_blocks`: publishes a signed blinded block.
    pub async fn publish_blinded_block_v2(
        &self,
        proposal: &versioned::VersionedSignedBlindedProposal,
        broadcast_validation: Option<BroadcastValidation>,
    ) -> Result<()> {
        let mut request = self
            .post(&["eth", "v2", "beacon", "blinded_blocks"])
            .header(ETH_CONSENSUS_VERSION, consensus_version(proposal.version)?)
            .json(&proposal.block);
        if let Some(validation) = broadcast_validation {
            request = request.query(&[("broadcast_validation", validation.as_str())]);
        }
        empty(self.send(request).await?).await
    }

    /// `POST /eth/v2/beacon/pool/attestations`: submits signed attestations.
    /// From Electra on the node expects single attestations, so each payload
    /// is sent with its validator index and the committee its bits denote.
    pub async fn submit_pool_attestations_v2(
        &self,
        attestations: &[versioned::VersionedAttestation],
    ) -> Result<()> {
        let version = attestations
            .first()
            .map_or(DataVersion::Phase0, |attestation| attestation.version);
        let body = pool_attestations(version, attestations)?;
        let request = self
            .post(&["eth", "v2", "beacon", "pool", "attestations"])
            .header(ETH_CONSENSUS_VERSION, consensus_version(version)?)
            .json(&body);
        empty(self.send(request).await?).await
    }

    /// `POST /eth/v1/beacon/pool/sync_committees`: submits sync committee
    /// messages.
    pub async fn submit_pool_sync_committee_signatures(
        &self,
        messages: &[altair::SyncCommitteeMessage],
    ) -> Result<()> {
        empty(
            self.send(
                self.post(&["eth", "v1", "beacon", "pool", "sync_committees"])
                    .json(messages),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/beacon/pool/voluntary_exits`: submits a signed voluntary
    /// exit.
    pub async fn submit_pool_voluntary_exit(
        &self,
        exit: &phase0::SignedVoluntaryExit,
    ) -> Result<()> {
        empty(
            self.send(
                self.post(&["eth", "v1", "beacon", "pool", "voluntary_exits"])
                    .json(exit),
            )
            .await?,
        )
        .await
    }

    /// `GET /eth/v1/config/fork_schedule`: every fork the node knows about.
    pub async fn get_fork_schedule(&self) -> Result<Vec<phase0::Fork>> {
        data(
            self.send(self.get(&["eth", "v1", "config", "fork_schedule"]))
                .await?,
        )
        .await
    }

    /// `GET /eth/v1/config/spec`: the chain constants, presets and
    /// configuration.
    pub async fn get_spec(&self) -> Result<Spec> {
        data(
            self.send(self.get(&["eth", "v1", "config", "spec"]))
                .await?,
        )
        .await
    }

    /// `GET /eth/v1/node/peer_count`: the node's peer counts by connection
    /// state.
    pub async fn get_peer_count(&self) -> Result<v1::PeerCount> {
        data(
            self.send(self.get(&["eth", "v1", "node", "peer_count"]))
                .await?,
        )
        .await
    }

    /// `GET /eth/v1/node/syncing`: the node's sync status.
    pub async fn get_syncing_status(&self) -> Result<v1::SyncState> {
        data(
            self.send(self.get(&["eth", "v1", "node", "syncing"]))
                .await?,
        )
        .await
    }

    /// `GET /eth/v1/node/version`: the node's client version string.
    pub async fn get_node_version(&self) -> Result<String> {
        let version: NodeVersion = data(
            self.send(self.get(&["eth", "v1", "node", "version"]))
                .await?,
        )
        .await?;
        Ok(version.version)
    }

    /// `GET /eth/v1/validator/attestation_data`: unsigned attestation data
    /// for a slot and committee index.
    pub async fn produce_attestation_data(
        &self,
        slot: phase0::Slot,
        committee_index: u64,
    ) -> Result<phase0::AttestationData> {
        data(
            self.send(
                self.get(&["eth", "v1", "validator", "attestation_data"])
                    .query(&[
                        ("slot", slot.to_string()),
                        ("committee_index", committee_index.to_string()),
                    ]),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/beacon_committee_selections`: exchanges
    /// partial beacon committee selection proofs for aggregated ones.
    pub async fn submit_beacon_committee_selections(
        &self,
        selections: &[v1::BeaconCommitteeSelection],
    ) -> Result<Vec<v1::BeaconCommitteeSelection>> {
        data(
            self.send(
                self.post(&["eth", "v1", "validator", "beacon_committee_selections"])
                    .json(selections),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/contribution_and_proofs`: submits signed sync
    /// committee contributions and proofs.
    pub async fn publish_contribution_and_proofs(
        &self,
        contributions: &[altair::SignedContributionAndProof],
    ) -> Result<()> {
        empty(
            self.send(
                self.post(&["eth", "v1", "validator", "contribution_and_proofs"])
                    .json(contributions),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/duties/attester/{epoch}`: attester duties of
    /// `indices`.
    pub async fn get_attester_duties(
        &self,
        epoch: phase0::Epoch,
        indices: &[phase0::ValidatorIndex],
    ) -> Result<AttesterDutiesResponse> {
        json(
            self.send(
                self.post(&[
                    "eth",
                    "v1",
                    "validator",
                    "duties",
                    "attester",
                    &epoch.to_string(),
                ])
                .json(&decimal_strings(indices)),
            )
            .await?,
        )
        .await
    }

    /// `GET /eth/v1/validator/duties/proposer/{epoch}`: the proposer of every
    /// slot in an epoch.
    pub async fn get_proposer_duties(
        &self,
        epoch: phase0::Epoch,
    ) -> Result<ProposerDutiesResponse> {
        json(
            self.send(self.get(&[
                "eth",
                "v1",
                "validator",
                "duties",
                "proposer",
                &epoch.to_string(),
            ]))
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/duties/sync/{epoch}`: sync committee duties of
    /// `indices`.
    pub async fn get_sync_committee_duties(
        &self,
        epoch: phase0::Epoch,
        indices: &[phase0::ValidatorIndex],
    ) -> Result<SyncCommitteeDutiesResponse> {
        json(
            self.send(
                self.post(&[
                    "eth",
                    "v1",
                    "validator",
                    "duties",
                    "sync",
                    &epoch.to_string(),
                ])
                .json(&decimal_strings(indices)),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/prepare_beacon_proposer`: tells the node which
    /// fee recipient to build blocks with for each validator.
    pub async fn prepare_beacon_proposer(
        &self,
        preparations: &[v1::ProposalPreparation],
    ) -> Result<()> {
        empty(
            self.send(
                self.post(&["eth", "v1", "validator", "prepare_beacon_proposer"])
                    .json(preparations),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/register_validator`: forwards signed builder
    /// registrations to the node.
    pub async fn register_validator(
        &self,
        registrations: &[v1::SignedValidatorRegistration],
    ) -> Result<()> {
        empty(
            self.send(
                self.post(&["eth", "v1", "validator", "register_validator"])
                    .json(registrations),
            )
            .await?,
        )
        .await
    }

    /// `GET /eth/v1/validator/sync_committee_contribution`: the aggregated
    /// sync committee contribution for a slot, subcommittee and block root.
    pub async fn produce_sync_committee_contribution(
        &self,
        slot: phase0::Slot,
        subcommittee_index: u64,
        beacon_block_root: phase0::Root,
    ) -> Result<altair::SyncCommitteeContribution> {
        data(
            self.send(
                self.get(&["eth", "v1", "validator", "sync_committee_contribution"])
                    .query(&[
                        ("slot", slot.to_string()),
                        ("subcommittee_index", subcommittee_index.to_string()),
                        (
                            "beacon_block_root",
                            pluto_ssz::to_0x_hex(&beacon_block_root),
                        ),
                    ]),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/sync_committee_selections`: exchanges partial
    /// sync committee selection proofs for aggregated ones.
    pub async fn submit_sync_committee_selections(
        &self,
        selections: &[v1::SyncCommitteeSelection],
    ) -> Result<Vec<v1::SyncCommitteeSelection>> {
        data(
            self.send(
                self.post(&["eth", "v1", "validator", "sync_committee_selections"])
                    .json(selections),
            )
            .await?,
        )
        .await
    }

    /// `POST /eth/v1/validator/sync_committee_subscriptions`: subscribes the
    /// node to sync committee subnets.
    pub async fn prepare_sync_committee_subnets(
        &self,
        subscriptions: &[v1::SyncCommitteeSubscription],
    ) -> Result<()> {
        empty(
            self.send(
                self.post(&["eth", "v1", "validator", "sync_committee_subscriptions"])
                    .json(subscriptions),
            )
            .await?,
        )
        .await
    }

    /// `GET /eth/v2/validator/aggregate_attestation`: the aggregate
    /// attestation for a slot, committee index and attestation data root.
    pub async fn get_aggregated_attestation_v2(
        &self,
        slot: phase0::Slot,
        committee_index: u64,
        attestation_data_root: phase0::Root,
    ) -> Result<versioned::VersionedAttestation> {
        let response = self
            .send(
                self.get(&["eth", "v2", "validator", "aggregate_attestation"])
                    .query(&[
                        (
                            "attestation_data_root",
                            pluto_ssz::to_0x_hex(&attestation_data_root),
                        ),
                        ("slot", slot.to_string()),
                        ("committee_index", committee_index.to_string()),
                    ]),
            )
            .await?;
        let body = response.text().await?;
        let envelope: Versioned<'_> = decode(&body)?;

        Ok(versioned::VersionedAttestation {
            version: envelope.version,
            validator_index: None,
            attestation: Some(decode_attestation(envelope.version, envelope.data.get())?),
        })
    }

    /// `POST /eth/v2/validator/aggregate_and_proofs`: submits signed
    /// aggregate-and-proof messages, which must all share one consensus
    /// version.
    pub async fn publish_aggregate_and_proofs_v2(
        &self,
        aggregates: &[versioned::VersionedSignedAggregateAndProof],
    ) -> Result<()> {
        let version = common_version(aggregates.iter().map(|aggregate| aggregate.version))?;
        let body: Vec<_> = aggregates
            .iter()
            .map(|aggregate| &aggregate.aggregate_and_proof)
            .collect();
        empty(
            self.send(
                self.post(&["eth", "v2", "validator", "aggregate_and_proofs"])
                    .header(ETH_CONSENSUS_VERSION, version)
                    .json(&body),
            )
            .await?,
        )
        .await
    }

    /// `GET /eth/v3/validator/blocks/{slot}`: an unsigned block, blinded or
    /// not, for the slot.
    pub async fn produce_block_v3(
        &self,
        opts: &ProduceBlockOpts,
    ) -> Result<versioned::VersionedProposal> {
        let mut query = vec![("randao_reveal", pluto_ssz::to_0x_hex(&opts.randao_reveal))];
        if let Some(graffiti) = &opts.graffiti {
            query.push(("graffiti", pluto_ssz::to_0x_hex(graffiti)));
        }
        if opts.skip_randao_verification {
            query.push(("skip_randao_verification", String::new()));
        }
        if let Some(factor) = opts.builder_boost_factor {
            query.push(("builder_boost_factor", factor.to_string()));
        }

        let response = self
            .send(
                self.get(&["eth", "v3", "validator", "blocks", &opts.slot.to_string()])
                    .query(&query),
            )
            .await?;
        let body = response.text().await?;
        let envelope: Proposal<'_> = decode(&body)?;

        Ok(versioned::VersionedProposal {
            block: decode_proposal_block(
                envelope.version,
                envelope.execution_payload_blinded,
                envelope.data.get(),
            )?,
            consensus_block_value: envelope.consensus_block_value,
            execution_payload_value: envelope.execution_payload_value,
        })
    }
}

/// Validator indices as the API's array of decimal strings.
fn decimal_strings(indices: &[phase0::ValidatorIndex]) -> Vec<String> {
    indices.iter().map(u64::to_string).collect()
}

/// Resolves the fork version active at `epoch` from the fork-schedule
/// endpoint entries, mirroring go-eth2-client's `forkAtEpoch` (which backs
/// Charon's `Domain()`): entries are scanned in server order, the last entry
/// with `epoch <= target` wins, and before any entry activates the first
/// entry is used.
///
/// Signing domains must come from `/eth/v1/config/fork_schedule` rather than
/// the spec's `*_FORK_VERSION`/`*_FORK_EPOCH` keys: the two sources can
/// disagree (Charon's beaconmock overrides the spec fork keys but serves its
/// static fork schedule unchanged), and cross-client signature verification
/// only works when both sides derive the fork version the same way.
fn fork_version_from_schedule(
    schedule: &[phase0::Fork],
    epoch: phase0::Epoch,
) -> Result<phase0::Version> {
    let mut current = schedule
        .first()
        .ok_or(EthBeaconNodeApiClientError::EmptyForkSchedule)?;

    for fork in schedule {
        if fork.epoch > epoch {
            break;
        }
        current = fork;
    }

    Ok(current.current_version)
}

/// Cached static chain config for one beacon endpoint: spec, genesis, and
/// fork schedule. These are constant for the lifetime of a beacon-node
/// process, but fetching them live put up to four sequential HTTP round-trips
/// on every signature verification.
///
/// Cached for the lifetime of *this* process: picking up a fork schedule
/// changed by a beacon-node upgrade requires a pluto restart. Request
/// failures are never cached (the `OnceCell` stays empty and the next caller
/// retries); a successful response is cached as-is, so a malformed 200 body
/// persists until restart.
///
/// TODO(#563): interim process-global cache. Moves into the client when the
/// client owns its state.
#[derive(Default)]
struct ChainConfigCache {
    spec: OnceCell<Arc<Spec>>,
    genesis: OnceCell<Arc<v1::Genesis>>,
    fork_schedule: OnceCell<Arc<Vec<phase0::Fork>>>,
}

/// Keyed by endpoint, so every client for one beacon node (e.g. the
/// scheduling and submission clients) shares the same entries.
///
/// TODO(#563): removed once the client owns its state.
static CONFIG_CACHES: LazyLock<Mutex<HashMap<Url, Arc<ChainConfigCache>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Returns the config cache for `base_url`. The map lock is only held to
/// get-or-insert the entry, never across a fetch.
fn config_cache_for(base_url: &Url) -> Arc<ChainConfigCache> {
    let mut caches = CONFIG_CACHES.lock().expect("config cache mutex poisoned");
    Arc::clone(caches.entry(base_url.clone()).or_default())
}

/// Removes the cached chain config for `base_url`.
///
/// Test support: wiremock pools listeners, so mock servers reuse ports within
/// one test process and a later test would inherit an earlier test's cached
/// config for the same URL. Production never needs this.
#[doc(hidden)]
pub fn purge_chain_config_cache(base_url: &Url) {
    CONFIG_CACHES
        .lock()
        .expect("config cache mutex poisoned")
        .remove(base_url);
}

impl EthBeaconNodeApiClient {
    /// Fetches the chain spec (cached per endpoint).
    pub async fn fetch_spec(&self) -> Result<Arc<Spec>> {
        let cache = config_cache_for(&self.base_url);
        cache
            .spec
            .get_or_try_init(|| async {
                let spec = crate::instrument("spec", self.get_spec()).await?;
                Ok(Arc::new(spec))
            })
            .await
            .map(Arc::clone)
    }

    async fn fetch_genesis_data(&self) -> Result<Arc<v1::Genesis>> {
        let cache = config_cache_for(&self.base_url);
        cache
            .genesis
            .get_or_try_init(|| async {
                let genesis = crate::instrument("genesis", self.get_genesis()).await?;
                Ok(Arc::new(genesis))
            })
            .await
            .map(Arc::clone)
    }

    /// Fetches the genesis time.
    pub async fn fetch_genesis_time(&self) -> Result<DateTime<Utc>> {
        let genesis = self.fetch_genesis_data().await?;

        i64::try_from(genesis.genesis_time)
            .ok()
            .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0))
            .ok_or(EthBeaconNodeApiClientError::InvalidGenesisTime(
                genesis.genesis_time,
            ))
    }

    /// Fetches the slot duration and slots per epoch.
    pub async fn fetch_slots_config(&self) -> Result<(time::Duration, u64)> {
        let spec = self.fetch_spec().await?;

        if spec.seconds_per_slot == 0 || spec.slots_per_epoch == 0 {
            return Err(EthBeaconNodeApiClientError::ZeroSlotDurationOrSlotsPerEpoch);
        }

        Ok((
            time::Duration::from_secs(spec.seconds_per_slot),
            spec.slots_per_epoch,
        ))
    }

    /// Fetches the attester duties of `indices` for `epoch`.
    pub async fn fetch_attester_duties_for_indices(
        &self,
        epoch: phase0::Epoch,
        indices: Vec<phase0::ValidatorIndex>,
    ) -> Result<Vec<v1::AttesterDuty>> {
        let response =
            crate::instrument("attester_duties", self.get_attester_duties(epoch, &indices)).await?;
        Ok(response.data)
    }

    /// Fetches the proposer duties for `epoch`, keeping only the duties that
    /// belong to `indices`. An empty `indices` returns them all.
    ///
    /// The endpoint takes no validator parameter (it always answers with the
    /// proposer of every slot in the epoch), so narrowing it is the client's
    /// job.
    pub async fn fetch_proposer_duties(
        &self,
        epoch: phase0::Epoch,
        slots_per_epoch: u64,
        indices: &HashSet<phase0::ValidatorIndex>,
    ) -> Result<Vec<v1::ProposerDuty>> {
        if slots_per_epoch == 0 {
            return Err(EthBeaconNodeApiClientError::ZeroSlotDurationOrSlotsPerEpoch);
        }

        let duties = crate::instrument("proposer_duties", self.get_proposer_duties(epoch))
            .await?
            .data;

        // Reject duties outside the requested epoch before dropping any:
        // filtering first would silently discard a bogus duty that happens to
        // belong to a validator we did not ask about. Comparing epochs avoids
        // the slot-bound multiplication overflowing on a bogus epoch.
        for duty in &duties {
            let duty_epoch = duty
                .slot
                .checked_div(slots_per_epoch)
                .ok_or(EthBeaconNodeApiClientError::ZeroSlotDurationOrSlotsPerEpoch)?;
            if duty_epoch != epoch {
                return Err(EthBeaconNodeApiClientError::DutySlotOutsideEpoch {
                    slot: duty.slot,
                    epoch,
                });
            }
        }

        Ok(duties
            .into_iter()
            .filter(|duty| indices.is_empty() || indices.contains(&duty.validator_index))
            .collect())
    }

    /// Fetches the fork schedule for all known forks.
    pub async fn fetch_fork_config(&self) -> Result<HashMap<DataVersion, ForkSchedule>> {
        Ok(self.fetch_spec().await?.fork_schedule())
    }

    /// Fetches the genesis domain for the provided domain type.
    pub async fn fetch_genesis_domain(
        &self,
        domain_type: phase0::DomainType,
    ) -> Result<phase0::Domain> {
        let genesis = self.fetch_genesis_data().await?;

        Ok(compute_domain(
            domain_type,
            genesis.genesis_fork_version,
            phase0::Root::default(),
        ))
    }

    /// Fetches the fork schedule entries from `/eth/v1/config/fork_schedule`
    /// (cached per endpoint).
    async fn fetch_fork_schedule_data(&self) -> Result<Arc<Vec<phase0::Fork>>> {
        let cache = config_cache_for(&self.base_url);
        cache
            .fork_schedule
            .get_or_try_init(|| async {
                let schedule = crate::instrument("fork_schedule", self.get_fork_schedule()).await?;
                Ok(Arc::new(schedule))
            })
            .await
            .map(Arc::clone)
    }

    /// Fetches the `current_version` of every entry in the beacon node's fork
    /// schedule (`/eth/v1/config/fork_schedule`), in the order provided by the
    /// endpoint (oldest-to-newest per spec). The first entry is the genesis
    /// fork version, which identifies the beacon node's network.
    pub async fn fetch_fork_schedule_versions(&self) -> Result<Vec<phase0::Version>> {
        Ok(self
            .fetch_fork_schedule_data()
            .await?
            .iter()
            .map(|fork| fork.current_version)
            .collect())
    }

    /// Fetches the resolved beacon domain for the provided domain type and
    /// epoch. Non-exit domains resolve the fork version from the
    /// fork-schedule endpoint (go-eth2-client parity, see
    /// `fork_version_from_schedule`); voluntary exits stay pinned to the
    /// Capella fork per EIP-7044, read from the node's own spec so devnets
    /// and other custom networks keep working.
    pub async fn fetch_domain(
        &self,
        domain_type: phase0::DomainType,
        epoch: phase0::Epoch,
    ) -> Result<phase0::Domain> {
        let spec = self.fetch_spec().await?;
        let genesis = self.fetch_genesis_data().await?;

        let fork_version = if domain_type == spec.domain_voluntary_exit {
            spec.capella_fork_version
        } else {
            let schedule = self.fetch_fork_schedule_data().await?;
            fork_version_from_schedule(&schedule, epoch)?
        };

        Ok(compute_domain(
            domain_type,
            fork_version,
            genesis.genesis_validators_root,
        ))
    }

    /// Fetches the beacon attester signing domain for `epoch`.
    pub async fn fetch_beacon_attester_domain(
        &self,
        epoch: phase0::Epoch,
    ) -> Result<phase0::Domain> {
        let spec = self.fetch_spec().await?;
        self.fetch_domain(spec.domain_beacon_attester, epoch).await
    }

    /// Submits signed builder registrations, which must all be V1.
    pub async fn submit_validator_registrations(
        &self,
        registrations: Vec<versioned::VersionedSignedValidatorRegistration>,
    ) -> Result<()> {
        let registrations = registrations
            .into_iter()
            .map(
                |registration| match (registration.version, registration.v1) {
                    (BuilderVersion::V1, Some(registration)) => Ok(registration),
                    (version, _) => Err(PayloadError::UnsupportedBuilderVersion(version)),
                },
            )
            .collect::<std::result::Result<Vec<_>, _>>()?;

        crate::instrument(
            "submit_validator_registrations",
            self.register_validator(&registrations),
        )
        .await
    }

    /// Subscribes to the beacon node SSE stream (`GET /eth/v1/events`) for the
    /// given topics.
    ///
    /// The returned stream preserves each event's topic and yields its raw
    /// JSON `data` unparsed, so callers can dispatch on the topic and
    /// deserialize the payload themselves.
    pub async fn event_stream(
        &self,
        topics: &[EventTopic],
    ) -> Result<impl Stream<Item = Result<BeaconNodeEvent>> + Send> {
        // Topics are sent as repeated `topics=<value>` query pairs.
        let query: Vec<(&str, &str)> = topics
            .iter()
            .map(|topic| ("topics", topic.as_str()))
            .collect();

        let response = self
            .send(
                self.client
                    .get(self.url(&["eth", "v1", "events"]))
                    .query(&query)
                    .header(ACCEPT, "text/event-stream"),
            )
            .await?;

        let stream = response.bytes_stream().eventsource().map(|item| {
            item.map(|event| BeaconNodeEvent {
                topic: event.event,
                data: event.data,
            })
            .map_err(EthBeaconNodeApiClientError::EventStreamRead)
        });

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{spec::deneb, test_fixtures};
    use pluto_ssz::{BitList, BitVector};
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{any, method, path},
    };

    /// A status no endpoint documents.
    const UNDOCUMENTED_STATUS: u16 = 418;

    const SIGNATURE: phase0::BLSSignature = [0xab; 96];
    const ROOT: phase0::Root = [0xcd; 32];

    fn hex(bytes: &[u8]) -> String {
        pluto_ssz::to_0x_hex(bytes)
    }

    fn test_client(server: &MockServer) -> EthBeaconNodeApiClient {
        EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid mock server URL")
    }

    fn signed_altair_block() -> altair::SignedBeaconBlock {
        altair::SignedBeaconBlock {
            message: test_fixtures::altair_beacon_block_fixture(),
            signature: SIGNATURE,
        }
    }

    fn signed_proposal() -> versioned::VersionedSignedProposal {
        versioned::VersionedSignedProposal {
            version: DataVersion::Altair,
            blinded: false,
            block: versioned::SignedProposalBlock::Altair(signed_altair_block()),
        }
    }

    fn attestation_data() -> phase0::AttestationData {
        phase0::AttestationData {
            slot: 12,
            index: 3,
            beacon_block_root: [1; 32],
            source: phase0::Checkpoint {
                epoch: 2,
                root: [2; 32],
            },
            target: phase0::Checkpoint {
                epoch: 3,
                root: [3; 32],
            },
        }
    }

    fn electra_attestation(committee: usize) -> versioned::VersionedAttestation {
        versioned::VersionedAttestation {
            version: DataVersion::Electra,
            validator_index: Some(99),
            attestation: Some(versioned::AttestationPayload::Electra(
                electra::Attestation {
                    aggregation_bits: BitList::with_bits(8, &[0]),
                    data: attestation_data(),
                    signature: [4; 96],
                    committee_bits: BitVector::with_bits(&[committee]),
                },
            )),
        }
    }

    fn produce_block_opts() -> ProduceBlockOpts {
        ProduceBlockOpts {
            slot: 7,
            randao_reveal: SIGNATURE,
            graffiti: None,
            skip_randao_verification: false,
            builder_boost_factor: None,
        }
    }

    fn http_error(error: &EthBeaconNodeApiClientError) -> &HttpError {
        match error {
            EthBeaconNodeApiClientError::Http(http) => http,
            other => panic!("not an HTTP error: {other:?}"),
        }
    }

    /// Every endpoint sends the documented method, path, query and headers,
    /// and surfaces an undocumented status as an [`HttpError`]. Bodies the
    /// client derives from a payload's serde form are only checked for
    /// presence; the encodings are covered by the type tests. Bodies the
    /// client assembles itself are checked exactly.
    #[tokio::test]
    async fn requests_have_the_documented_shape() {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(UNDOCUMENTED_STATUS))
            .mount(&server)
            .await;
        let client = test_client(&server);

        let contribution_query = format!(
            "slot=1&subcommittee_index=0&beacon_block_root={}",
            hex(&ROOT)
        );
        let aggregate_query = format!(
            "attestation_data_root={}&slot=1&committee_index=2",
            hex(&ROOT)
        );
        let block_query = format!("randao_reveal={}", hex(&SIGNATURE));
        let selection = v1::BeaconCommitteeSelection {
            slot: 1,
            validator_index: 2,
            selection_proof: SIGNATURE,
        };
        let sync_selection = v1::SyncCommitteeSelection {
            slot: 1,
            validator_index: 2,
            subcommittee_index: 3,
            selection_proof: SIGNATURE,
        };
        let exit = phase0::SignedVoluntaryExit {
            message: phase0::VoluntaryExit {
                epoch: 1,
                validator_index: 2,
            },
            signature: SIGNATURE,
        };
        let preparation = v1::ProposalPreparation {
            validator_index: 1,
            fee_recipient: [0x11; 20],
        };
        let subscription = v1::SyncCommitteeSubscription {
            validator_index: 1,
            sync_committee_indices: vec![5],
            until_epoch: 9,
        };
        let filter = ValidatorsFilter {
            ids: vec![ValidatorId::Index(1)],
            statuses: Vec::new(),
        };

        enum Body {
            None,
            Json,
            Exact(serde_json::Value),
        }
        // (method, path, query, consensus version header, body), in call
        // order.
        type ExpectedRequest<'a> = (&'a str, &'a str, Option<&'a str>, Option<&'a str>, Body);
        let mut expected: Vec<ExpectedRequest<'_>> = Vec::new();
        macro_rules! check {
            ($call:expr, $method:literal, $path:literal, $query:expr, $version:expr, $body:expr) => {{
                let error = $call.await.expect_err("undocumented status is an error");
                assert_eq!(
                    http_error(&error).status.as_u16(),
                    UNDOCUMENTED_STATUS,
                    "{}",
                    $path
                );
                expected.push(($method, $path, $query, $version, $body));
            }};
        }

        check!(
            client.get_genesis(),
            "GET",
            "/eth/v1/beacon/genesis",
            None,
            None,
            Body::None
        );
        check!(
            client.get_block_root("head"),
            "GET",
            "/eth/v1/beacon/blocks/head/root",
            None,
            None,
            Body::None
        );
        check!(
            client.get_block_header("finalized"),
            "GET",
            "/eth/v1/beacon/headers/finalized",
            None,
            None,
            Body::None
        );
        check!(
            client.get_block_v2("42"),
            "GET",
            "/eth/v2/beacon/blocks/42",
            None,
            None,
            Body::None
        );
        check!(
            client.post_state_validators("head", &filter),
            "POST",
            "/eth/v1/beacon/states/head/validators",
            None,
            None,
            Body::Json
        );
        check!(
            client.publish_block_v2(&signed_proposal(), Some(BroadcastValidation::Gossip)),
            "POST",
            "/eth/v2/beacon/blocks",
            Some("broadcast_validation=gossip"),
            Some("altair"),
            Body::Json
        );
        check!(
            client.publish_blinded_block_v2(
                &versioned::VersionedSignedBlindedProposal {
                    version: DataVersion::Deneb,
                    block: versioned::SignedBlindedProposalBlock::Deneb(
                        deneb::SignedBlindedBeaconBlock {
                            message: test_fixtures::deneb_blinded_beacon_block_fixture(),
                            signature: SIGNATURE,
                        },
                    ),
                },
                None,
            ),
            "POST",
            "/eth/v2/beacon/blinded_blocks",
            None,
            Some("deneb"),
            Body::Json
        );
        check!(
            client.submit_pool_attestations_v2(&[electra_attestation(3)]),
            "POST",
            "/eth/v2/beacon/pool/attestations",
            None,
            Some("electra"),
            Body::Exact(json!([{
                "committee_index": "3",
                "attester_index": "99",
                "data": attestation_data(),
                "signature": hex(&[4; 96]),
            }]))
        );
        check!(
            client.submit_pool_sync_committee_signatures(&[altair::SyncCommitteeMessage {
                slot: 1,
                beacon_block_root: ROOT,
                validator_index: 2,
                signature: SIGNATURE,
            }]),
            "POST",
            "/eth/v1/beacon/pool/sync_committees",
            None,
            None,
            Body::Json
        );
        check!(
            client.submit_pool_voluntary_exit(&exit),
            "POST",
            "/eth/v1/beacon/pool/voluntary_exits",
            None,
            None,
            Body::Json
        );
        check!(
            client.get_fork_schedule(),
            "GET",
            "/eth/v1/config/fork_schedule",
            None,
            None,
            Body::None
        );
        check!(
            client.get_spec(),
            "GET",
            "/eth/v1/config/spec",
            None,
            None,
            Body::None
        );
        check!(
            client.get_peer_count(),
            "GET",
            "/eth/v1/node/peer_count",
            None,
            None,
            Body::None
        );
        check!(
            client.get_syncing_status(),
            "GET",
            "/eth/v1/node/syncing",
            None,
            None,
            Body::None
        );
        check!(
            client.get_node_version(),
            "GET",
            "/eth/v1/node/version",
            None,
            None,
            Body::None
        );
        check!(
            client.produce_attestation_data(1, 2),
            "GET",
            "/eth/v1/validator/attestation_data",
            Some("slot=1&committee_index=2"),
            None,
            Body::None
        );
        check!(
            client.submit_beacon_committee_selections(&[selection]),
            "POST",
            "/eth/v1/validator/beacon_committee_selections",
            None,
            None,
            Body::Json
        );
        check!(
            client.publish_contribution_and_proofs(&[]),
            "POST",
            "/eth/v1/validator/contribution_and_proofs",
            None,
            None,
            Body::Json
        );
        check!(
            client.get_attester_duties(3, &[1, 20]),
            "POST",
            "/eth/v1/validator/duties/attester/3",
            None,
            None,
            Body::Exact(json!(["1", "20"]))
        );
        check!(
            client.get_proposer_duties(3),
            "GET",
            "/eth/v1/validator/duties/proposer/3",
            None,
            None,
            Body::None
        );
        check!(
            client.get_sync_committee_duties(3, &[]),
            "POST",
            "/eth/v1/validator/duties/sync/3",
            None,
            None,
            Body::Json
        );
        check!(
            client.prepare_beacon_proposer(&[preparation]),
            "POST",
            "/eth/v1/validator/prepare_beacon_proposer",
            None,
            None,
            Body::Json
        );
        check!(
            client.register_validator(&[]),
            "POST",
            "/eth/v1/validator/register_validator",
            None,
            None,
            Body::Json
        );
        check!(
            client.produce_sync_committee_contribution(1, 0, ROOT),
            "GET",
            "/eth/v1/validator/sync_committee_contribution",
            Some(contribution_query.as_str()),
            None,
            Body::None
        );
        check!(
            client.submit_sync_committee_selections(&[sync_selection]),
            "POST",
            "/eth/v1/validator/sync_committee_selections",
            None,
            None,
            Body::Json
        );
        check!(
            client.prepare_sync_committee_subnets(&[subscription]),
            "POST",
            "/eth/v1/validator/sync_committee_subscriptions",
            None,
            None,
            Body::Json
        );
        check!(
            client.get_aggregated_attestation_v2(1, 2, ROOT),
            "GET",
            "/eth/v2/validator/aggregate_attestation",
            Some(aggregate_query.as_str()),
            None,
            Body::None
        );
        check!(
            client.publish_aggregate_and_proofs_v2(&[
                versioned::VersionedSignedAggregateAndProof {
                    version: DataVersion::Electra,
                    aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Electra(
                        electra::SignedAggregateAndProof {
                            message: electra::AggregateAndProof {
                                aggregator_index: 5,
                                aggregate: electra::Attestation {
                                    aggregation_bits: BitList::with_bits(8, &[0]),
                                    data: attestation_data(),
                                    signature: [4; 96],
                                    committee_bits: BitVector::with_bits(&[3]),
                                },
                                selection_proof: SIGNATURE,
                            },
                            signature: SIGNATURE,
                        },
                    ),
                }
            ]),
            "POST",
            "/eth/v2/validator/aggregate_and_proofs",
            None,
            Some("electra"),
            Body::Json
        );
        check!(
            client.produce_block_v3(&produce_block_opts()),
            "GET",
            "/eth/v3/validator/blocks/7",
            Some(block_query.as_str()),
            None,
            Body::None
        );

        let received = server
            .received_requests()
            .await
            .expect("request recording is enabled");
        assert_eq!(received.len(), expected.len());
        for (request, (method, path, query, version, body)) in received.iter().zip(expected) {
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
            if method == "GET" {
                assert_eq!(header("accept"), Some("application/json"), "{path}");
            }
            match body {
                Body::None => assert!(request.body.is_empty(), "{path}"),
                Body::Json | Body::Exact(_) => {
                    assert_eq!(header("content-type"), Some("application/json"), "{path}");
                    let sent: serde_json::Value =
                        serde_json::from_slice(&request.body).expect("JSON body");
                    if let Body::Exact(expected) = body {
                        assert_eq!(sent, expected, "{path}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn data_envelope_is_unwrapped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": crate::test_fixtures::spec_json() })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "version": "Lighthouse/v8" } })),
            )
            .mount(&server)
            .await;
        let client = test_client(&server);

        let spec = client.get_spec().await.expect("request succeeds");
        assert_eq!(spec.slots_per_epoch, 32);
        assert_eq!(client.get_node_version().await.unwrap(), "Lighthouse/v8");
    }

    /// A 2xx body decodes whatever the `Content-Type`.
    #[tokio::test]
    async fn success_ignores_content_type() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(r#"{"data":{"version":"Lighthouse/v8"}}"#, "text/plain"),
            )
            .mount(&server)
            .await;

        test_client(&server)
            .get_node_version()
            .await
            .expect("request succeeds");
    }

    #[tokio::test]
    async fn error_status_carries_the_decoded_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "code": 400,
                "message": "some failed",
                "failures": [{ "index": 0, "message": "bad signature" }],
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream exploded"))
            .mount(&server)
            .await;
        let client = test_client(&server);

        let error = client
            .submit_pool_attestations_v2(&[electra_attestation(1)])
            .await
            .expect_err("400 is an error");
        let http = http_error(&error);
        assert_eq!(http.status.as_u16(), 400);
        assert_eq!(http.method, reqwest::Method::POST);
        assert_eq!(http.endpoint, "/eth/v2/beacon/pool/attestations");
        assert_eq!(http.body.code, Some(400));
        assert_eq!(http.body.message, "some failed");
        assert_eq!(http.body.failures[0].message, "bad signature");

        let error = client.get_spec().await.expect_err("500 is an error");
        let http = http_error(&error);
        assert_eq!(http.status.as_u16(), 500);
        assert_eq!(http.method, reqwest::Method::GET);
        assert_eq!(http.endpoint, "/eth/v1/config/spec");
        assert_eq!(http.body.message, "upstream exploded");
    }

    #[tokio::test]
    async fn produce_block_v3_decodes_by_version_and_blinded_flag() {
        let server = MockServer::start().await;
        let deneb_block = test_fixtures::deneb_beacon_block_fixture();
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/7"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": "deneb",
                "execution_payload_blinded": false,
                "execution_payload_value": "12345",
                "consensus_block_value": "678",
                "data": { "block": deneb_block, "kzg_proofs": [], "blobs": [] },
            })))
            .mount(&server)
            .await;
        let electra_blinded = test_fixtures::electra_blinded_beacon_block_fixture();
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/8"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": "electra",
                "execution_payload_blinded": true,
                "execution_payload_value": "1",
                "consensus_block_value": "2",
                "data": electra_blinded,
            })))
            .mount(&server)
            .await;
        let client = test_client(&server);

        let proposal = client
            .produce_block_v3(&produce_block_opts())
            .await
            .expect("deneb proposal");
        assert_eq!(proposal.execution_payload_value, U256::from(12345));
        assert_eq!(proposal.consensus_block_value, U256::from(678));
        assert!(!proposal.is_blinded());
        let versioned::ProposalBlock::Deneb { block, blobs, .. } = proposal.block else {
            panic!("expected deneb block contents, got {proposal:?}");
        };
        assert_eq!(*block, deneb_block);
        assert!(blobs.is_empty());

        let proposal = client
            .produce_block_v3(&ProduceBlockOpts {
                slot: 8,
                ..produce_block_opts()
            })
            .await
            .expect("electra blinded proposal");
        assert_eq!(
            proposal.block,
            versioned::ProposalBlock::ElectraBlinded(electra_blinded)
        );
    }

    #[tokio::test]
    async fn get_aggregated_attestation_v2_decodes_by_version() {
        let server = MockServer::start().await;
        let phase0_attestation = phase0::Attestation {
            aggregation_bits: BitList::with_bits(8, &[1]),
            data: attestation_data(),
            signature: SIGNATURE,
        };
        Mock::given(method("GET"))
            .and(path("/eth/v2/validator/aggregate_attestation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": "capella",
                "data": phase0_attestation,
            })))
            .mount(&server)
            .await;

        let attestation = test_client(&server)
            .get_aggregated_attestation_v2(1, 2, ROOT)
            .await
            .expect("request succeeds");
        assert_eq!(attestation.version, DataVersion::Capella);
        assert_eq!(
            attestation.attestation,
            Some(versioned::AttestationPayload::Capella(phase0_attestation))
        );
    }

    #[tokio::test]
    async fn get_block_v2_decodes_by_version() {
        let server = MockServer::start().await;
        let block = signed_altair_block();
        Mock::given(method("GET"))
            .and(path("/eth/v2/beacon/blocks/head"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": "altair",
                "execution_optimistic": false,
                "finalized": true,
                "data": block,
            })))
            .mount(&server)
            .await;

        let response = test_client(&server)
            .get_block_v2("head")
            .await
            .expect("request succeeds")
            .expect("block exists");
        assert!(response.finalized);
        assert_eq!(response.data, versioned::SignedBeaconBlock::Altair(block));
    }

    /// A `404` means no block exists for the id, not a failed request.
    #[tokio::test]
    async fn get_block_v2_returns_none_for_a_missing_block() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v2/beacon/blocks/42"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "code": 404,
                "message": "Block not found",
            })))
            .mount(&server)
            .await;

        let response = test_client(&server)
            .get_block_v2("42")
            .await
            .expect("request succeeds");
        assert_eq!(response, None);
    }

    #[tokio::test]
    async fn publish_block_v2_rejects_blinded_proposals_before_sending() {
        let server = MockServer::start().await;
        let proposal = versioned::VersionedSignedProposal {
            version: DataVersion::Deneb,
            blinded: true,
            block: versioned::SignedProposalBlock::DenebBlinded(deneb::SignedBlindedBeaconBlock {
                message: test_fixtures::deneb_blinded_beacon_block_fixture(),
                signature: SIGNATURE,
            }),
        };

        let error = test_client(&server)
            .publish_block_v2(&proposal, None)
            .await
            .expect_err("blinded proposal must be rejected");
        assert!(
            matches!(
                error,
                EthBeaconNodeApiClientError::Payload(PayloadError::BlindedOnUnblindedEndpoint)
            ),
            "{error:?}"
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
    async fn publish_block_v2_accepts_any_2xx() {
        for status in [200, 202] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/eth/v2/beacon/blocks"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            test_client(&server)
                .publish_block_v2(&signed_proposal(), None)
                .await
                .unwrap_or_else(|error| panic!("status {status}: {error:#}"));
        }
    }

    #[tokio::test]
    async fn submit_pool_attestations_v2_sends_legacy_shape_before_electra() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let attestation = phase0::Attestation {
            aggregation_bits: BitList::with_bits(8, &[1]),
            data: attestation_data(),
            signature: SIGNATURE,
        };

        test_client(&server)
            .submit_pool_attestations_v2(&[versioned::VersionedAttestation {
                version: DataVersion::Deneb,
                validator_index: Some(1),
                attestation: Some(versioned::AttestationPayload::Deneb(attestation.clone())),
            }])
            .await
            .expect("request succeeds");

        let received = server.received_requests().await.expect("recording");
        assert_eq!(
            received[0].headers.get("eth-consensus-version").unwrap(),
            "deneb"
        );
        let sent: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(sent, json!([attestation]));
    }

    #[tokio::test]
    async fn publish_aggregate_and_proofs_v2_rejects_mixed_versions() {
        let server = MockServer::start().await;
        let aggregate = |version| versioned::VersionedSignedAggregateAndProof {
            version,
            aggregate_and_proof: versioned::SignedAggregateAndProofPayload::Deneb(
                phase0::SignedAggregateAndProof {
                    message: phase0::AggregateAndProof {
                        aggregator_index: 1,
                        aggregate: phase0::Attestation {
                            aggregation_bits: BitList::with_bits(8, &[1]),
                            data: attestation_data(),
                            signature: SIGNATURE,
                        },
                        selection_proof: SIGNATURE,
                    },
                    signature: SIGNATURE,
                },
            ),
        };

        let error = test_client(&server)
            .publish_aggregate_and_proofs_v2(&[
                aggregate(DataVersion::Deneb),
                aggregate(DataVersion::Capella),
            ])
            .await
            .expect_err("mixed versions must be rejected");
        assert!(
            matches!(
                error,
                EthBeaconNodeApiClientError::Payload(PayloadError::MixedVersions)
            ),
            "{error:?}"
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
    async fn malformed_success_body_names_the_failing_field() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "genesis_time": 1606824023,
                    "genesis_validators_root": hex(&ROOT),
                    "genesis_fork_version": "0x00000000",
                }
            })))
            .mount(&server)
            .await;

        let error = test_client(&server)
            .get_genesis()
            .await
            .expect_err("a non-string genesis_time must fail decoding");
        let EthBeaconNodeApiClientError::Decode(error) = error else {
            panic!("expected a decode error, got {error:?}");
        };
        assert_eq!(error.path().to_string(), "data.genesis_time");
    }

    #[tokio::test]
    async fn transport_failure_is_an_error() {
        // Nothing listens on the reserved port 1.
        let client = EthBeaconNodeApiClient::with_base_url("http://127.0.0.1:1").expect("valid");
        let error = client
            .get_spec()
            .await
            .expect_err("connection refused must surface as an error");
        assert!(
            matches!(error, EthBeaconNodeApiClientError::Transport(_)),
            "{error:?}"
        );
    }

    #[test]
    fn first_set_bit_finds_the_lowest_bit() {
        assert_eq!(first_set_bit(&[0b0000_1000, 0]), Some(3));
        assert_eq!(first_set_bit(&[0, 0b0000_0001]), Some(8));
        assert_eq!(first_set_bit(&[0, 0]), None);
    }

    #[test]
    fn url_keeps_the_base_path_prefix() {
        let client = EthBeaconNodeApiClient::with_base_url("http://beacon.example:5052/prefix")
            .expect("valid");
        assert_eq!(
            client.url(&["eth", "v1", "config", "spec"]).as_str(),
            "http://beacon.example:5052/prefix/eth/v1/config/spec"
        );
    }

    #[test]
    fn with_base_url_rejects_a_base_that_cannot_have_a_path() {
        let error = EthBeaconNodeApiClient::with_base_url("mailto:node@example")
            .expect_err("cannot-be-a-base URL");
        assert!(
            matches!(error, EthBeaconNodeApiClientError::UrlCannotBeABase),
            "{error:?}"
        );
    }

    const SPEC_PATH: &str = "/eth/v1/config/spec";
    const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";
    const FORK_SCHEDULE_PATH: &str = "/eth/v1/config/fork_schedule";

    fn genesis_body() -> serde_json::Value {
        json!({ "data": {
            "genesis_time": "1606824023",
            "genesis_validators_root":
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            "genesis_fork_version": "0x00000000",
        }})
    }

    fn fork_schedule_body() -> serde_json::Value {
        json!({ "data": [
            {
                "previous_version": "0x00000000",
                "current_version": "0x00000000",
                "epoch": "0"
            },
            {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "10"
            },
        ]})
    }

    fn cache_spec_body() -> serde_json::Value {
        json!({ "data": crate::test_fixtures::spec_json() })
    }

    fn config_client(server: &MockServer) -> EthBeaconNodeApiClient {
        let client =
            EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid mock server URL");
        // The pooled port may have served an earlier test.
        purge_chain_config_cache(&client.base_url);
        client
    }

    /// Every config-derived lookup after the first is served from the
    /// process-global cache, including from a second client for the same
    /// endpoint (the submission client in production). Enforced by the
    /// `.expect(1)` mocks on drop.
    #[tokio::test]
    async fn config_fetches_are_cached_per_endpoint() {
        let server = MockServer::start().await;
        for (endpoint, body) in [
            (SPEC_PATH, cache_spec_body()),
            (GENESIS_PATH, genesis_body()),
            (FORK_SCHEDULE_PATH, fork_schedule_body()),
        ] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let client = config_client(&server);

        let spec = client.fetch_spec().await.unwrap();
        let domain_type = spec.domain_beacon_attester;
        let first = client.fetch_domain(domain_type, 20).await.unwrap();
        assert_eq!(first, client.fetch_domain(domain_type, 20).await.unwrap());
        // Fork selection across the epoch-10 boundary yields distinct domains.
        assert_ne!(first, client.fetch_domain(domain_type, 5).await.unwrap());
        client.fetch_slots_config().await.unwrap();
        client.fetch_fork_config().await.unwrap();
        client.fetch_genesis_time().await.unwrap();
        client.fetch_fork_schedule_versions().await.unwrap();
        // Voluntary exits are pinned to the Capella fork version.
        assert_eq!(
            client
                .fetch_domain(spec.domain_voluntary_exit, 20)
                .await
                .unwrap(),
            compute_domain(
                spec.domain_voluntary_exit,
                spec.capella_fork_version,
                client
                    .fetch_genesis_data()
                    .await
                    .unwrap()
                    .genesis_validators_root,
            )
        );

        // Constructed directly (`config_client` purges): a second client for
        // the same endpoint shares the already-warmed entries.
        let second_client = EthBeaconNodeApiClient::with_base_url(server.uri()).unwrap();
        second_client.fetch_slots_config().await.unwrap();
        second_client.fetch_genesis_time().await.unwrap();

        purge_chain_config_cache(&client.base_url);
    }

    /// Concurrent cold lookups coalesce into one upstream request.
    #[tokio::test]
    async fn concurrent_cold_fetches_coalesce() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(SPEC_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(cache_spec_body())
                    // Force overlap with the first in-flight fetch.
                    .set_delay(std::time::Duration::from_millis(100)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = config_client(&server);

        // Spawn all tasks before awaiting any (a lazy `map` would run them
        // sequentially) so they race on the cold cache.
        let lookups: Vec<_> = (0..16)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(async move { client.fetch_slots_config().await })
            })
            .collect();
        for lookup in lookups {
            lookup.await.unwrap().unwrap();
        }

        purge_chain_config_cache(&client.base_url);
    }

    /// Request failures are never cached: the next call retries and succeeds
    /// once the endpoint recovers.
    #[tokio::test]
    async fn config_fetch_failures_are_not_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(GENESIS_PATH))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let client = config_client(&server);
        client.fetch_genesis_time().await.unwrap_err();

        Mock::given(method("GET"))
            .and(path(GENESIS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(genesis_body()))
            .expect(1)
            .mount(&server)
            .await;
        client.fetch_genesis_time().await.unwrap();

        purge_chain_config_cache(&client.base_url);
    }

    /// Fork-schedule entries as served by Charon's beaconmock static.json:
    /// versions differ from its (overridden) spec keys and the last entries
    /// activate at capella=256 / deneb=29696.
    fn schedule_fixture() -> Vec<phase0::Fork> {
        let entry = |prev: [u8; 4], cur: [u8; 4], epoch: u64| phase0::Fork {
            previous_version: prev,
            current_version: cur,
            epoch,
        };
        vec![
            entry([0x01, 0x01, 0x70, 0x00], [0x01, 0x01, 0x70, 0x00], 0),
            entry([0x01, 0x01, 0x70, 0x00], [0x02, 0x01, 0x70, 0x00], 0),
            entry([0x02, 0x01, 0x70, 0x00], [0x03, 0x01, 0x70, 0x00], 0),
            entry([0x03, 0x01, 0x70, 0x00], [0x04, 0x01, 0x70, 0x00], 256),
            entry([0x04, 0x01, 0x70, 0x00], [0x05, 0x01, 0x70, 0x00], 29696),
        ]
    }

    #[test]
    fn fork_version_from_schedule_picks_last_activated_entry() {
        let schedule = schedule_fixture();

        // Same-epoch ties resolve to the last listed entry (server order).
        assert_eq!(
            fork_version_from_schedule(&schedule, 0).unwrap(),
            [0x03, 0x01, 0x70, 0x00]
        );
        assert_eq!(
            fork_version_from_schedule(&schedule, 300).unwrap(),
            [0x04, 0x01, 0x70, 0x00]
        );
        // Far past the last fork: the final entry stays active.
        assert_eq!(
            fork_version_from_schedule(&schedule, 10_448_552).unwrap(),
            [0x05, 0x01, 0x70, 0x00]
        );
    }

    #[test]
    fn fork_version_from_schedule_rejects_empty_schedule() {
        assert!(matches!(
            fork_version_from_schedule(&[], 0),
            Err(EthBeaconNodeApiClientError::EmptyForkSchedule)
        ));
    }

    #[tokio::test]
    async fn event_stream_preserves_topic_and_raw_data() {
        use tokio_stream::StreamExt;

        let server = MockServer::start().await;

        let body = "event: head\ndata: {\"slot\":\"10\"}\n\n\
                    event: chain_reorg\ndata: {\"slot\":\"20\",\"depth\":\"2\"}\n\n";

        Mock::given(method("GET"))
            .and(path("/eth/v1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
            .mount(&server)
            .await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");
        let stream = client
            .event_stream(&[EventTopic::Head, EventTopic::ChainReorg])
            .await
            .expect("open stream");
        let mut stream = std::pin::pin!(stream);

        let first = stream.next().await.expect("first event").expect("ok event");
        assert_eq!(first.topic, "head");
        assert_eq!(first.data, r#"{"slot":"10"}"#);

        let second = stream
            .next()
            .await
            .expect("second event")
            .expect("ok event");
        assert_eq!(second.topic, "chain_reorg");
        assert_eq!(second.data, r#"{"slot":"20","depth":"2"}"#);

        let received = server.received_requests().await.expect("recording");
        assert_eq!(
            received[0].url.query(),
            Some("topics=head&topics=chain_reorg")
        );
    }

    /// Slots per epoch used by the proposer-duty tests.
    const TEST_SLOTS_PER_EPOCH: u64 = 8;

    /// A well-formed proposer duty for `index`, proposing at `slot`.
    fn proposer_duty(index: u64, slot: u64) -> serde_json::Value {
        serde_json::json!({
            "pubkey": format!("0x{:096x}", index),
            "slot": slot.to_string(),
            "validator_index": index.to_string(),
        })
    }

    /// Serves `data` from the epoch-0 proposer-duties endpoint.
    async fn serve_proposer_duties(data: Vec<serde_json::Value>) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": format!("0x{:064x}", 0),
                "execution_optimistic": false,
                "data": data,
            })))
            .mount(&server)
            .await;

        server
    }

    /// An epoch of duties, one per slot, for validators `0..count`.
    async fn proposer_duties_server(count: u64) -> MockServer {
        serve_proposer_duties((0..count).map(|i| proposer_duty(i, i)).collect()).await
    }

    #[tokio::test]
    async fn fetch_proposer_duties_keeps_only_requested_indices() {
        let server = proposer_duties_server(5).await;
        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");

        let duties = client
            .fetch_proposer_duties(0, TEST_SLOTS_PER_EPOCH, &HashSet::from([1, 3]))
            .await
            .expect("fetch duties");

        assert_eq!(
            duties
                .iter()
                .map(|duty| duty.validator_index)
                .collect::<Vec<_>>(),
            [1, 3],
        );
    }

    /// An empty index set must still yield the whole epoch's proposers.
    #[tokio::test]
    async fn fetch_proposer_duties_without_indices_is_unfiltered() {
        let server = proposer_duties_server(5).await;
        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");

        let duties = client
            .fetch_proposer_duties(0, TEST_SLOTS_PER_EPOCH, &HashSet::new())
            .await
            .expect("fetch duties");

        assert_eq!(duties.len(), 5);
    }

    /// A malformed duty fails the response even when it belongs to a validator
    /// the caller did not ask about.
    #[tokio::test]
    async fn fetch_proposer_duties_rejects_malformed_unrequested_duty() {
        let mut data = vec![proposer_duty(1, 1)];
        data.push(serde_json::json!({
            "pubkey": "0xnot-a-pubkey",
            "slot": "2",
            "validator_index": "2",
        }));

        let server = serve_proposer_duties(data).await;
        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");

        // Index 2 is filtered out, but its malformed pubkey must still surface.
        let err = client
            .fetch_proposer_duties(0, TEST_SLOTS_PER_EPOCH, &HashSet::from([1]))
            .await
            .expect_err("malformed duty should fail the response");

        let EthBeaconNodeApiClientError::Decode(err) = err else {
            panic!("expected a decode error, got {err:?}");
        };
        assert_eq!(err.path().to_string(), "data[1].pubkey");
    }

    #[tokio::test]
    async fn fetch_proposer_duties_rejects_duty_outside_requested_epoch() {
        // Epoch 0 spans slots 0..=7, so slot 9 belongs to another epoch.
        let server = serve_proposer_duties(vec![proposer_duty(1, 1), proposer_duty(2, 9)]).await;
        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");

        let err = client
            .fetch_proposer_duties(0, TEST_SLOTS_PER_EPOCH, &HashSet::from([1]))
            .await
            .expect_err("out-of-epoch duty should fail the response");

        assert!(
            matches!(
                err,
                EthBeaconNodeApiClientError::DutySlotOutsideEpoch { slot: 9, epoch: 0 }
            ),
            "expected out-of-epoch error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn prepare_beacon_proposer_posts_expected_body() {
        use wiremock::matchers::body_json;

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .and(body_json(json!([
                {
                    "validator_index": "1",
                    "fee_recipient": "0x0101010101010101010101010101010101010101"
                },
                {
                    "validator_index": "42",
                    "fee_recipient": "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
                }
            ])))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");
        client
            .prepare_beacon_proposer(&[
                v1::ProposalPreparation {
                    validator_index: 1,
                    fee_recipient: [0x01; 20],
                },
                v1::ProposalPreparation {
                    validator_index: 42,
                    fee_recipient: [0x2a; 20],
                },
            ])
            .await
            .expect("submit succeeds");
        // The mock's `.expect(1)` verifies on drop that the posted body
        // matched.
    }

    #[tokio::test]
    async fn prepare_beacon_proposer_surfaces_error_status() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "code": 500,
                "message": "internal error"
            })))
            .mount(&server)
            .await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid url");
        let error = client
            .prepare_beacon_proposer(&[v1::ProposalPreparation {
                validator_index: 1,
                fee_recipient: [0x01; 20],
            }])
            .await
            .expect_err("a 500 response must surface as an error");

        let http = http_error(&error);
        assert_eq!(http.status.as_u16(), 500);
        assert_eq!(http.method, reqwest::Method::POST);
        assert_eq!(http.endpoint, "/eth/v1/validator/prepare_beacon_proposer");
        assert_eq!(http.body.message, "internal error");
    }
}
