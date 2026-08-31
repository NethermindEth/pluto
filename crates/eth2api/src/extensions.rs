use crate::{
    BeaconStateFork, ConsensusVersion, EthBeaconNodeApiClient, EventstreamRequestQueryTopic,
    GetForkScheduleRequest, GetForkScheduleResponse, GetGenesisRequest, GetGenesisResponse,
    GetGenesisResponseResponseData, GetProposerDutiesRequest, GetProposerDutiesResponse,
    GetSpecRequest, GetSpecResponse, PrepareBeaconProposerRequest,
    PrepareBeaconProposerRequestBodyItem, PrepareBeaconProposerResponse, ValidatorStatus,
    spec::{bellatrix, phase0},
};
use chrono::{DateTime, Utc};
use eventsource_stream::Eventsource;
use reqwest::Url;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock, Mutex},
    time,
};
use tokio::sync::OnceCell;
use tokio_stream::{Stream, StreamExt};
use tree_hash::TreeHash;

/// Error that can occur when using the
/// [`EthBeaconNodeApiClient`].
#[derive(Debug, thiserror::Error)]
pub enum EthBeaconNodeApiClientError {
    /// Underlying error from [`EthBeaconNodeApiClient`] when
    /// making a request.
    #[error("Request error: {0}")]
    RequestError(#[from] anyhow::Error),

    /// Unexpected response, e.g, got an error when an Ok response was expected
    #[error("Unexpected response")]
    UnexpectedResponse,

    /// Unexpected type in response
    #[error("Unexpected type in response")]
    UnexpectedType,

    /// Failed to parse a response field.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Zero slot duration or slots per epoch in network spec
    #[error("Zero slot duration or slots per epoch in network spec")]
    ZeroSlotDurationOrSlotsPerEpoch,

    /// A duty was returned for a slot outside the epoch it was requested for.
    #[error("Received duty for slot {slot} outside of requested epoch {epoch}")]
    DutySlotOutsideEpoch {
        /// Slot the beacon node reported the duty for.
        slot: phase0::Slot,
        /// Epoch the duties were requested for.
        epoch: phase0::Epoch,
    },

    /// Domain type not found in the beacon spec response
    #[error("Domain type not found: {0}")]
    DomainTypeNotFound(String),

    /// Error while opening the beacon node SSE event stream (request send or
    /// non-success status).
    #[error("Event stream request error: {0}")]
    EventStreamRequest(#[from] reqwest::Error),

    /// Error while reading from the beacon node SSE event stream.
    #[error("Event stream read error: {0}")]
    EventStreamRead(#[from] eventsource_stream::EventStreamError<reqwest::Error>),
}

/// A single Server-Sent Event from a beacon node: the event topic (the SSE
/// `event:` field, e.g. `head` or `chain_reorg`) and its raw, unparsed JSON
/// `data` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconNodeEvent {
    /// The SSE event topic.
    pub topic: String,
    /// The raw JSON data payload.
    pub data: String,
}

/// A single proposal preparation submitted to the beacon node
/// (`prepare_beacon_proposer`), associating a validator index with the fee
/// recipient the node should use when building blocks for it.
///
/// Mirrors go-eth2-client's `eth2v1.ProposalPreparation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalPreparation {
    /// Index of the validator the preparation applies to.
    pub validator_index: phase0::ValidatorIndex,
    /// Execution-layer address that should receive block rewards.
    pub fee_recipient: bellatrix::ExecutionAddress,
}

// Ordered oldest-to-newest. `resolve_fork_version` relies on this order to
// break equal-epoch ties (the latest fork wins), so keep it chronological.
const FORKS: [ConsensusVersion; 6] = [
    ConsensusVersion::Altair,
    ConsensusVersion::Bellatrix,
    ConsensusVersion::Capella,
    ConsensusVersion::Deneb,
    ConsensusVersion::Electra,
    ConsensusVersion::Fulu,
];

/// The schedule of given fork, containing the fork version and the epoch at
/// which it activates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSchedule {
    /// The fork version, as a 4-byte array.
    pub version: phase0::Version,
    /// The epoch at which the fork activates.
    pub epoch: phase0::Epoch,
}

/// A proposer duty with its fields decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerDuty {
    /// The proposer's BLS public key.
    pub pubkey: phase0::BLSPubKey,
    /// Index of the proposer in the validator registry.
    pub validator_index: phase0::ValidatorIndex,
    /// The slot at which the validator must propose a block.
    pub slot: phase0::Slot,
}

fn required_str_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, EthBeaconNodeApiClientError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| EthBeaconNodeApiClientError::ParseError(format!("missing {field}")))
}

fn parse_u64_field(
    value: &serde_json::Value,
    field: &str,
) -> Result<u64, EthBeaconNodeApiClientError> {
    required_str_field(value, field)?
        .parse::<u64>()
        .map_err(|_| EthBeaconNodeApiClientError::ParseError(format!("parse {field}")))
}

pub(crate) fn decode_fixed_hex<const N: usize, F: Fn() -> String>(
    value: &str,
    step: F,
) -> Result<[u8; N], EthBeaconNodeApiClientError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|_| EthBeaconNodeApiClientError::ParseError(step()))?;

    bytes
        .try_into()
        .map_err(|_| EthBeaconNodeApiClientError::ParseError(step()))
}

fn parse_genesis_fork_version_and_validators_root(
    genesis_data: &GetGenesisResponseResponseData,
) -> Result<(phase0::Version, phase0::Root), EthBeaconNodeApiClientError> {
    let fork_version = decode_fixed_hex(&genesis_data.genesis_fork_version, || {
        "decode genesis_fork_version".to_string()
    })?;
    let validators_root = decode_fixed_hex(&genesis_data.genesis_validators_root, || {
        "decode genesis_validators_root".to_string()
    })?;

    Ok((fork_version, validators_root))
}

fn fork_schedule_from_spec(
    spec_data: &serde_json::Value,
) -> Result<HashMap<ConsensusVersion, ForkSchedule>, EthBeaconNodeApiClientError> {
    fn fetch_fork(
        fork: &ConsensusVersion,
        spec_data: &serde_json::Value,
    ) -> Result<ForkSchedule, EthBeaconNodeApiClientError> {
        let version_field = format!("{}_FORK_VERSION", fork.to_string().to_uppercase());
        let version = spec_data
            .as_object()
            .and_then(|o| o.get(&version_field))
            .and_then(|f| f.as_str())
            .ok_or_else(|| {
                EthBeaconNodeApiClientError::ParseError(format!("missing {version_field}"))
            })
            .and_then(|value| decode_fixed_hex(value, || format!("decode {version_field}")))?;

        let epoch_field = format!("{}_FORK_EPOCH", fork.to_string().to_uppercase());
        let epoch = parse_u64_field(spec_data, &epoch_field)?;

        Ok(ForkSchedule { version, epoch })
    }

    let mut result = HashMap::new();
    for fork in FORKS {
        let fork_schedule = fetch_fork(&fork, spec_data)?;
        result.insert(fork, fork_schedule);
    }

    Ok(result)
}

/// Computes the final 32-byte beacon domain from domain type, fork version, and
/// genesis root.
pub fn compute_domain(
    domain_type: phase0::DomainType,
    fork_version: phase0::Version,
    genesis_validators_root: phase0::Root,
) -> phase0::Domain {
    let fork_data = phase0::ForkData {
        current_version: fork_version,
        genesis_validators_root,
    };
    let fork_data_root = fork_data.tree_hash_root();

    let mut domain = phase0::Domain::default();
    domain[..phase0::DOMAIN_TYPE_LEN].copy_from_slice(&domain_type);
    domain[phase0::DOMAIN_TYPE_LEN..]
        .copy_from_slice(&fork_data_root.0[..(phase0::DOMAIN_LEN - phase0::DOMAIN_TYPE_LEN)]);

    domain
}

/// Computes the builder domain using `GENESIS_FORK_VERSION` and a zero
/// validators root.
///
/// Builder registrations do not use the fork-at-epoch beacon domain.
/// References:
/// - <https://github.com/ethereum/builder-specs/blob/100d4faf32e5dc672c963741769390ff09ab194a/specs/bellatrix/builder.md#signing>
/// - <https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_domain>
pub fn compute_builder_domain(
    domain_type: phase0::DomainType,
    genesis_fork_version: phase0::Version,
) -> phase0::Domain {
    compute_domain(domain_type, genesis_fork_version, phase0::Root::default())
}

/// Resolves the domain type from the beacon spec.
pub fn resolve_domain_type(
    spec_data: &serde_json::Value,
    spec_key: &str,
) -> Result<phase0::DomainType, EthBeaconNodeApiClientError> {
    let raw = spec_data
        .as_object()
        .and_then(|o| o.get(spec_key))
        .and_then(|value| value.as_str())
        .ok_or_else(|| EthBeaconNodeApiClientError::DomainTypeNotFound(spec_key.to_string()))?;

    decode_fixed_hex(raw, || format!("decode {spec_key}"))
}

/// Resolves the active fork version at the given epoch.
pub fn resolve_fork_version(
    epoch: phase0::Epoch,
    genesis_fork_version: phase0::Version,
    fork_schedule: &HashMap<ConsensusVersion, ForkSchedule>,
) -> phase0::Version {
    let mut active_version = genesis_fork_version;
    for fork in FORKS {
        let Some(schedule) = fork_schedule.get(&fork) else {
            continue;
        };
        if schedule.epoch <= epoch {
            active_version = schedule.version;
        }
    }

    active_version
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
    schedule: &[BeaconStateFork],
    epoch: phase0::Epoch,
) -> Result<phase0::Version, EthBeaconNodeApiClientError> {
    let mut current = schedule.first().ok_or_else(|| {
        EthBeaconNodeApiClientError::ParseError("empty fork schedule".to_string())
    })?;

    for fork in schedule {
        let fork_epoch = fork.epoch.parse::<u64>().map_err(|_| {
            EthBeaconNodeApiClientError::ParseError("parse fork schedule epoch".to_string())
        })?;
        if fork_epoch > epoch {
            break;
        }
        current = fork;
    }

    decode_fixed_hex(&current.current_version, || {
        "decode fork schedule current_version".to_string()
    })
}

/// Returns the fork version for voluntary-exit domains: EIP-7044 pins them to
/// the Capella fork (spec-derived), falling back to the genesis fork version
/// when the spec has no Capella entry.
///
/// Reading the version from the beacon node's own spec keeps devnets and other
/// custom networks working. The genesis fallback is defensive: a spec without
/// a Capella version already fails while the schedule is built.
fn voluntary_exit_fork_version(
    spec_data: &serde_json::Value,
    genesis_fork_version: phase0::Version,
) -> Result<phase0::Version, EthBeaconNodeApiClientError> {
    Ok(fork_schedule_from_spec(spec_data)?
        .get(&ConsensusVersion::Capella)
        .map(|fork| fork.version)
        .unwrap_or(genesis_fork_version))
}

impl ValidatorStatus {
    /// Returns true if the validator is in one of the active states.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ValidatorStatus::ActiveOngoing
                | ValidatorStatus::ActiveExiting
                | ValidatorStatus::ActiveSlashed
        )
    }
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
/// TODO(#563): interim process-global cache — the generated client cannot
/// hold state. Moves into the client when eth2api is redesigned.
#[derive(Default)]
struct ChainConfigCache {
    spec: OnceCell<Arc<serde_json::Value>>,
    genesis: OnceCell<Arc<GetGenesisResponseResponseData>>,
    fork_schedule: OnceCell<Arc<Vec<BeaconStateFork>>>,
}

/// Keyed by endpoint, so every client for one beacon node (e.g. the
/// scheduling and submission clients) shares the same entries.
///
/// TODO(#563): removed with the eth2api redesign.
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
    async fn fetch_spec_data(&self) -> Result<Arc<serde_json::Value>, EthBeaconNodeApiClientError> {
        let cache = config_cache_for(&self.base_url);
        cache
            .spec
            .get_or_try_init(|| async {
                match crate::instrument("spec", self.get_spec(GetSpecRequest {})).await? {
                    GetSpecResponse::Ok(spec) => Ok(Arc::new(spec.data)),
                    _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
                }
            })
            .await
            .map(Arc::clone)
    }

    async fn fetch_genesis_data(
        &self,
    ) -> Result<Arc<GetGenesisResponseResponseData>, EthBeaconNodeApiClientError> {
        let cache = config_cache_for(&self.base_url);
        cache
            .genesis
            .get_or_try_init(|| async {
                match crate::instrument("genesis", self.get_genesis(GetGenesisRequest {})).await? {
                    GetGenesisResponse::Ok(genesis) => Ok(Arc::new(genesis.data)),
                    _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
                }
            })
            .await
            .map(Arc::clone)
    }

    /// Fetches the genesis time.
    pub async fn fetch_genesis_time(&self) -> Result<DateTime<Utc>, EthBeaconNodeApiClientError> {
        let genesis = self.fetch_genesis_data().await?;

        genesis
            .genesis_time
            .parse()
            .map_err(|_| EthBeaconNodeApiClientError::ParseError("parse genesis_time".into()))
            .and_then(|timestamp| {
                DateTime::from_timestamp(timestamp, 0).ok_or_else(|| {
                    EthBeaconNodeApiClientError::ParseError(
                        "convert genesis_time to timestamp".into(),
                    )
                })
            })
    }

    /// Fetches the raw chain spec as a JSON object (cached per endpoint).
    pub async fn fetch_spec(&self) -> Result<Arc<serde_json::Value>, EthBeaconNodeApiClientError> {
        self.fetch_spec_data().await
    }

    /// Fetches the slot duration and slots per epoch.
    pub async fn fetch_slots_config(
        &self,
    ) -> Result<(time::Duration, u64), EthBeaconNodeApiClientError> {
        let spec = self.fetch_spec_data().await?;

        let slot_duration = time::Duration::from_secs(parse_u64_field(&spec, "SECONDS_PER_SLOT")?);
        let slots_per_epoch = parse_u64_field(&spec, "SLOTS_PER_EPOCH")?;

        if slot_duration == time::Duration::ZERO || slots_per_epoch == 0 {
            return Err(EthBeaconNodeApiClientError::ZeroSlotDurationOrSlotsPerEpoch);
        }

        Ok((slot_duration, slots_per_epoch))
    }

    /// Fetches the proposer duties for `epoch`, keeping only the duties that
    /// belong to `indices`. An empty `indices` returns them all.
    ///
    /// The endpoint takes no validator parameter — it always answers with the
    /// proposer of every slot in the epoch — so narrowing it is the client's
    /// job.
    pub async fn fetch_proposer_duties(
        &self,
        epoch: phase0::Epoch,
        slots_per_epoch: u64,
        indices: &HashSet<phase0::ValidatorIndex>,
    ) -> Result<Vec<ProposerDuty>, EthBeaconNodeApiClientError> {
        if slots_per_epoch == 0 {
            return Err(EthBeaconNodeApiClientError::ZeroSlotDurationOrSlotsPerEpoch);
        }

        let request = GetProposerDutiesRequest::builder()
            .epoch(epoch.to_string())
            .build()
            .map_err(EthBeaconNodeApiClientError::RequestError)?;

        let duties =
            match crate::instrument("proposer_duties", self.get_proposer_duties(request)).await? {
                GetProposerDutiesResponse::Ok(response) => response.data,
                _ => return Err(EthBeaconNodeApiClientError::UnexpectedResponse),
            };

        // Validate every duty before dropping any: filtering first would
        // silently discard a malformed duty that happens to belong to a
        // validator we did not ask about.
        let mut validated = Vec::with_capacity(duties.len());
        for duty in duties {
            let validator_index = duty
                .validator_index
                .parse::<phase0::ValidatorIndex>()
                .map_err(|_| {
                    EthBeaconNodeApiClientError::ParseError("proposer duty validator_index".into())
                })?;
            let slot = duty.slot.parse::<phase0::Slot>().map_err(|_| {
                EthBeaconNodeApiClientError::ParseError("proposer duty slot".into())
            })?;
            let pubkey =
                decode_fixed_hex(&duty.pubkey, || "decode proposer duty pubkey".to_string())?;

            // Reject duties outside the requested epoch. Comparing epochs
            // avoids the slot-bound multiplication overflowing on a bogus
            // epoch.
            let duty_epoch = slot
                .checked_div(slots_per_epoch)
                .ok_or(EthBeaconNodeApiClientError::ZeroSlotDurationOrSlotsPerEpoch)?;
            if duty_epoch != epoch {
                return Err(EthBeaconNodeApiClientError::DutySlotOutsideEpoch { slot, epoch });
            }

            validated.push(ProposerDuty {
                pubkey,
                validator_index,
                slot,
            });
        }

        Ok(validated
            .into_iter()
            .filter(|duty| indices.is_empty() || indices.contains(&duty.validator_index))
            .collect())
    }

    /// Fetches the fork schedule for all known forks.
    pub async fn fetch_fork_config(
        &self,
    ) -> Result<HashMap<ConsensusVersion, ForkSchedule>, EthBeaconNodeApiClientError> {
        let spec = self.fetch_spec_data().await?;
        fork_schedule_from_spec(&spec)
    }

    /// Fetches the domain type with the provided config/spec key.
    pub async fn fetch_domain_type(
        &self,
        spec_key: &str,
    ) -> Result<phase0::DomainType, EthBeaconNodeApiClientError> {
        let spec = self.fetch_spec_data().await?;
        resolve_domain_type(&spec, spec_key)
    }

    /// Fetches the genesis domain for the provided domain type.
    pub async fn fetch_genesis_domain(
        &self,
        domain_type: phase0::DomainType,
    ) -> Result<phase0::Domain, EthBeaconNodeApiClientError> {
        let genesis = self.fetch_genesis_data().await?;
        let (genesis_fork_version, _) = parse_genesis_fork_version_and_validators_root(&genesis)?;

        Ok(compute_domain(
            domain_type,
            genesis_fork_version,
            phase0::Root::default(),
        ))
    }

    /// Fetches the genesis validators root from the beacon node.
    pub async fn fetch_genesis_validators_root(
        &self,
    ) -> Result<phase0::Root, EthBeaconNodeApiClientError> {
        let genesis = self.fetch_genesis_data().await?;
        let (_, validators_root) = parse_genesis_fork_version_and_validators_root(&genesis)?;

        Ok(validators_root)
    }

    /// Fetches the genesis fork version from the beacon node.
    pub async fn fetch_genesis_fork_version(
        &self,
    ) -> Result<phase0::Version, EthBeaconNodeApiClientError> {
        let genesis = self.fetch_genesis_data().await?;
        let (fork_version, _) = parse_genesis_fork_version_and_validators_root(&genesis)?;

        Ok(fork_version)
    }

    /// Fetches the fork schedule entries from `/eth/v1/config/fork_schedule`
    /// (cached per endpoint).
    async fn fetch_fork_schedule_data(
        &self,
    ) -> Result<Arc<Vec<BeaconStateFork>>, EthBeaconNodeApiClientError> {
        let cache = config_cache_for(&self.base_url);
        cache
            .fork_schedule
            .get_or_try_init(|| async {
                match crate::instrument(
                    "fork_schedule",
                    self.get_fork_schedule(GetForkScheduleRequest {}),
                )
                .await?
                {
                    GetForkScheduleResponse::Ok(resp) => Ok(Arc::new(resp.data)),
                    _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
                }
            })
            .await
            .map(Arc::clone)
    }

    /// Fetches the `current_version` of every entry in the beacon node's fork
    /// schedule (`/eth/v1/config/fork_schedule`), decoded and returned in the
    /// order provided by the endpoint (oldest-to-newest per spec). The first
    /// entry is the genesis fork version, which identifies the beacon node's
    /// network.
    pub async fn fetch_fork_schedule_versions(
        &self,
    ) -> Result<Vec<phase0::Version>, EthBeaconNodeApiClientError> {
        self.fetch_fork_schedule_data()
            .await?
            .iter()
            .map(|fork| {
                decode_fixed_hex(&fork.current_version, || {
                    "decode fork schedule current_version".to_string()
                })
            })
            .collect()
    }

    /// Fetches the resolved beacon domain for the provided domain type and
    /// epoch. Non-exit domains resolve the fork version from the
    /// fork-schedule endpoint (go-eth2-client parity, see
    /// `fork_version_from_schedule`); voluntary exits stay pinned to the
    /// Capella fork per EIP-7044.
    pub async fn fetch_domain(
        &self,
        domain_type: phase0::DomainType,
        epoch: phase0::Epoch,
    ) -> Result<phase0::Domain, EthBeaconNodeApiClientError> {
        let spec = self.fetch_spec_data().await?;
        let genesis = self.fetch_genesis_data().await?;
        let (genesis_fork_version, genesis_validators_root) =
            parse_genesis_fork_version_and_validators_root(&genesis)?;
        let voluntary_exit_domain_type = resolve_domain_type(&spec, "DOMAIN_VOLUNTARY_EXIT")?;

        let fork_version = if domain_type == voluntary_exit_domain_type {
            voluntary_exit_fork_version(&spec, genesis_fork_version)?
        } else {
            let schedule = self.fetch_fork_schedule_data().await?;
            fork_version_from_schedule(&schedule, epoch)?
        };

        Ok(compute_domain(
            domain_type,
            fork_version,
            genesis_validators_root,
        ))
    }

    /// Subscribes to the beacon node SSE stream (`GET /eth/v1/events`) for the
    /// given topics.
    ///
    /// Unlike the generated [`Self::eventstream`], the returned stream
    /// preserves each event's topic and yields its raw JSON `data`
    /// unparsed, so callers can dispatch on the topic and deserialize the
    /// payload themselves.
    pub async fn event_stream(
        &self,
        topics: &[EventstreamRequestQueryTopic],
    ) -> Result<
        impl Stream<Item = Result<BeaconNodeEvent, EthBeaconNodeApiClientError>> + Send,
        EthBeaconNodeApiClientError,
    > {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| {
                EthBeaconNodeApiClientError::RequestError(anyhow::anyhow!(
                    "base URL cannot be a base"
                ))
            })?
            .push("eth")
            .push("v1")
            .push("events");

        // Topics are sent as repeated `topics=<value>` query pairs.
        let query: Vec<(&str, String)> = topics
            .iter()
            .map(|topic| ("topics", topic.to_string()))
            .collect();

        let response = self
            .client
            .get(url)
            .query(&query)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await?
            .error_for_status()?;

        let stream = response.bytes_stream().eventsource().map(|item| {
            item.map(|event| BeaconNodeEvent {
                topic: event.event,
                data: event.data,
            })
            .map_err(EthBeaconNodeApiClientError::EventStreamRead)
        });

        Ok(stream)
    }

    /// Submits proposal preparations to the beacon node
    /// (`POST /eth/v1/validator/prepare_beacon_proposer`).
    ///
    /// Each preparation tells the beacon node which fee recipient to use when
    /// it builds a block for the given validator. The information persists for
    /// the epoch of submission plus the following two epochs, so callers resend
    /// it periodically (e.g. once per epoch). Mirrors go-eth2-client's
    /// `SubmitProposalPreparations`.
    pub async fn submit_proposal_preparations(
        &self,
        preparations: &[ProposalPreparation],
    ) -> Result<(), EthBeaconNodeApiClientError> {
        let body = preparations
            .iter()
            .map(|preparation| PrepareBeaconProposerRequestBodyItem {
                validator_index: preparation.validator_index.to_string(),
                fee_recipient: format!("0x{}", hex::encode(preparation.fee_recipient)),
            })
            .collect();

        match self
            .prepare_beacon_proposer(PrepareBeaconProposerRequest { body })
            .await?
        {
            PrepareBeaconProposerResponse::Ok => Ok(()),
            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

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
        let mut spec = spec_fixture();
        spec["SECONDS_PER_SLOT"] = json!("12");
        spec["SLOTS_PER_EPOCH"] = json!("32");
        spec["DOMAIN_BEACON_ATTESTER"] = json!("0x01000000");
        json!({ "data": spec })
    }

    fn test_client(server: &MockServer) -> EthBeaconNodeApiClient {
        let client =
            EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid mock server URL");
        // The pooled port may have served an earlier test.
        purge_chain_config_cache(&client.base_url);
        client
    }

    /// Every config-derived lookup after the first is served from the
    /// process-global cache — including from a second client for the same
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
        let client = test_client(&server);

        let domain_type = client
            .fetch_domain_type("DOMAIN_BEACON_ATTESTER")
            .await
            .unwrap();
        let first = client.fetch_domain(domain_type, 20).await.unwrap();
        assert_eq!(first, client.fetch_domain(domain_type, 20).await.unwrap());
        // Fork selection across the epoch-10 boundary yields distinct domains.
        assert_ne!(first, client.fetch_domain(domain_type, 5).await.unwrap());
        client.fetch_slots_config().await.unwrap();
        client.fetch_fork_config().await.unwrap();
        client.fetch_genesis_time().await.unwrap();
        client.fetch_fork_schedule_versions().await.unwrap();

        // Constructed directly (`test_client` purges): a second client for
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
        let client = test_client(&server);

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

        let client = test_client(&server);
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

    fn spec_fixture() -> serde_json::Value {
        json!({
            "DOMAIN_BEACON_PROPOSER": "0x00000000",
            "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
            "DOMAIN_APPLICATION_BUILDER": "0x00000001",
            "ALTAIR_FORK_VERSION": "0x01020304",
            "ALTAIR_FORK_EPOCH": "10",
            "BELLATRIX_FORK_VERSION": "0x02030405",
            "BELLATRIX_FORK_EPOCH": "20",
            "CAPELLA_FORK_VERSION": "0x03040506",
            "CAPELLA_FORK_EPOCH": "30",
            "DENEB_FORK_VERSION": "0x04050607",
            "DENEB_FORK_EPOCH": "40",
            "ELECTRA_FORK_VERSION": "0x05060708",
            "ELECTRA_FORK_EPOCH": "50",
            "FULU_FORK_VERSION": "0x06070809",
            "FULU_FORK_EPOCH": "60"
        })
    }

    #[test]
    fn resolve_fork_version_uses_genesis_version_before_first_fork() {
        let spec = spec_fixture();
        let fork_schedule = fork_schedule_from_spec(&spec).unwrap();
        let genesis_fork_version = [0x11, 0x22, 0x33, 0x44];

        assert_eq!(
            resolve_fork_version(0, genesis_fork_version, &fork_schedule),
            genesis_fork_version
        );
    }

    #[test]
    fn resolve_fork_version_uses_latest_active_fork_version() {
        let spec = spec_fixture();
        let fork_schedule = fork_schedule_from_spec(&spec).unwrap();
        let genesis_fork_version = [0x11, 0x22, 0x33, 0x44];

        assert_eq!(
            resolve_fork_version(25, genesis_fork_version, &fork_schedule),
            [0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn resolve_fork_version_breaks_equal_epoch_ties_by_fork_order() {
        let spec = json!({
            "ALTAIR_FORK_VERSION": "0x01020304",
            "ALTAIR_FORK_EPOCH": "0",
            "BELLATRIX_FORK_VERSION": "0x02030405",
            "BELLATRIX_FORK_EPOCH": "0",
            "CAPELLA_FORK_VERSION": "0x03040506",
            "CAPELLA_FORK_EPOCH": "0",
            "DENEB_FORK_VERSION": "0x04050607",
            "DENEB_FORK_EPOCH": "0",
            "ELECTRA_FORK_VERSION": "0x05060708",
            "ELECTRA_FORK_EPOCH": "2048",
            "FULU_FORK_VERSION": "0x06070809",
            "FULU_FORK_EPOCH": u64::MAX.to_string(),
        });
        let fork_schedule = fork_schedule_from_spec(&spec).unwrap();
        let genesis_fork_version = [0x11, 0x22, 0x33, 0x44];

        assert_eq!(
            resolve_fork_version(0, genesis_fork_version, &fork_schedule),
            [0x04, 0x05, 0x06, 0x07]
        );
    }

    #[test]
    fn compute_builder_domain_stays_constant() {
        let genesis_fork_version = [0x01, 0x01, 0x70, 0x00];

        let at_genesis = compute_builder_domain([0x00, 0x00, 0x00, 0x01], genesis_fork_version);
        let post_forks = compute_builder_domain([0x00, 0x00, 0x00, 0x01], genesis_fork_version);

        assert_eq!(at_genesis, post_forks);
        assert_eq!(
            hex::encode(at_genesis),
            "000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387"
        );
    }

    #[test]
    fn voluntary_exit_fork_version_pins_capella() {
        let spec = spec_fixture();
        let genesis_fork_version = [0x11, 0x22, 0x33, 0x44];

        assert_eq!(
            voluntary_exit_fork_version(&spec, genesis_fork_version).unwrap(),
            [0x03, 0x04, 0x05, 0x06]
        );
    }

    /// Fork-schedule entries as served by Charon's beaconmock static.json:
    /// versions differ from its (overridden) spec keys and the last entries
    /// activate at capella=256 / deneb=29696.
    fn schedule_fixture() -> Vec<BeaconStateFork> {
        let entry = |prev: &str, cur: &str, epoch: &str| BeaconStateFork {
            previous_version: prev.to_string(),
            current_version: cur.to_string(),
            epoch: epoch.to_string(),
        };
        vec![
            entry("0x01017000", "0x01017000", "0"),
            entry("0x01017000", "0x02017000", "0"),
            entry("0x02017000", "0x03017000", "0"),
            entry("0x03017000", "0x04017000", "256"),
            entry("0x04017000", "0x05017000", "29696"),
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
            Err(EthBeaconNodeApiClientError::ParseError(_))
        ));
    }

    #[tokio::test]
    async fn event_stream_preserves_topic_and_raw_data() {
        use crate::EventstreamRequestQueryTopic;
        use tokio_stream::StreamExt;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

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
            .event_stream(&[
                EventstreamRequestQueryTopic::Head,
                EventstreamRequestQueryTopic::ChainReorg,
            ])
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
    async fn serve_proposer_duties(data: Vec<serde_json::Value>) -> wiremock::MockServer {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

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
    async fn proposer_duties_server(count: u64) -> wiremock::MockServer {
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

        assert!(
            matches!(err, EthBeaconNodeApiClientError::ParseError(_)),
            "expected parse error, got {err:?}"
        );
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
    async fn submit_proposal_preparations_posts_expected_body() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_json, method, path},
        };

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
            .submit_proposal_preparations(&[
                ProposalPreparation {
                    validator_index: 1,
                    fee_recipient: [0x01; 20],
                },
                ProposalPreparation {
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
    async fn submit_proposal_preparations_surfaces_error_status() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

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
            .submit_proposal_preparations(&[ProposalPreparation {
                validator_index: 1,
                fee_recipient: [0x01; 20],
            }])
            .await
            .expect_err("a 500 response must surface as an error");

        assert!(matches!(
            error,
            EthBeaconNodeApiClientError::UnexpectedResponse
        ));
    }
}
