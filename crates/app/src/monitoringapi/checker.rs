//! Background readiness checker for `/readyz`.

use std::{collections::HashSet, time::Duration};

use chrono::{DateTime, Utc};
use pluto_cluster::helpers;
use pluto_core::types::PubKey;
use pluto_eth2api::{
    EthBeaconNodeApiClient, GetNodeVersionRequest, GetNodeVersionResponse, GetPeerCountRequest,
    GetPeerCountResponse, GetSyncingStatusRequest, GetSyncingStatusResponse,
};
use pluto_p2p::p2p_context::P2PContext;
use tokio::{sync::mpsc, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use super::{
    metrics::MONITORING_METRICS,
    readiness::{ReadinessError, ReadyResult, ReadyState},
};
use crate::eth2wrap::version::check_beacon_node_version;

/// Slots behind head after which the beacon node is considered too far behind.
const BN_FAR_BEHIND_SLOTS: u64 = 320;

/// Number of failed peer-connectivity rounds before readiness fails.
const MIN_NOT_CONNECTED_ROUNDS: u64 = 6;

const PEER_COUNT_PERIOD: Duration = Duration::from_secs(60);

/// Interval at which the upstream beacon node version metric is refreshed.
const NODE_VERSION_PERIOD: Duration = Duration::from_secs(10 * 60);

/// Charon-compatible `/readyz` metric code for a ready node.
const READYZ_READY: i64 = 1;

/// Beacon-chain timing parameters used to compute the current epoch.
#[derive(Debug, Clone, Copy)]
struct ChainConfig {
    genesis_time: DateTime<Utc>,
    slot_duration: Duration,
    slots_per_epoch: u64,
}

/// Starts the background readiness checker and returns the shared readiness
/// state served by `/readyz`.
///
/// `seen_pubkeys` should receive validator public keys observed through the
/// validator API. `validator_api_calls` should receive one item for each
/// validator API call. The checker consumes both receivers until cancellation.
pub fn start_ready_checker(
    p2p_context: P2PContext,
    beacon_node: EthBeaconNodeApiClient,
    pubkeys: Vec<PubKey>,
    seen_pubkeys: mpsc::Receiver<PubKey>,
    validator_api_calls: mpsc::Receiver<()>,
    ct: CancellationToken,
) -> ReadyState {
    let readiness = ReadyState::new();
    // Both background tasks are detached; their lifecycle is bound to `ct` and
    // they stop when the token is cancelled.
    let _version_task = tokio::spawn(run_beacon_node_version_metric(
        beacon_node.clone(),
        ct.clone(),
    ));
    let _task = tokio::spawn(run_ready_checker(
        p2p_context,
        beacon_node,
        pubkeys,
        seen_pubkeys,
        validator_api_calls,
        ct,
        readiness.clone(),
    ));

    readiness
}

/// Periodically refreshes the upstream beacon node version gauge and runs the
/// version compatibility check, mirroring Charon's `beaconNodeVersionMetric`.
///
/// The first tick fires immediately, so the version is published on startup and
/// then every [`NODE_VERSION_PERIOD`].
async fn run_beacon_node_version_metric(
    beacon_node: EthBeaconNodeApiClient,
    ct: CancellationToken,
) {
    let mut interval = tokio::time::interval(NODE_VERSION_PERIOD);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            () = ct.cancelled() => return,
            _ = interval.tick() => set_beacon_node_version(&beacon_node).await,
        }
    }
}

async fn set_beacon_node_version(beacon_node: &EthBeaconNodeApiClient) {
    let version = match fetch_node_version(beacon_node).await {
        Ok(version) => version,
        Err(error) => {
            error!(%error, "Failed to get beacon node version");
            return;
        }
    };

    // Emulate Charon's `beaconNodeVersionGauge.Reset`: vise's `Family` cannot
    // delete series, so clear any previously-reported version before setting the
    // current one.
    for (previous, gauge) in MONITORING_METRICS.beacon_node_version.to_entries() {
        if previous != version {
            gauge.set(0);
        }
    }
    MONITORING_METRICS.beacon_node_version[&version].set(1);

    check_beacon_node_version(&version);
}

async fn fetch_node_version(
    beacon_node: &EthBeaconNodeApiClient,
) -> Result<String, ReadyCheckerError> {
    match beacon_node
        .get_node_version(GetNodeVersionRequest {})
        .await
        .map_err(ReadyCheckerError::BeaconNode)?
    {
        GetNodeVersionResponse::Ok(response) => Ok(response.data.version),
        GetNodeVersionResponse::InternalServerError(_) | GetNodeVersionResponse::Unknown => {
            Err(ReadyCheckerError::UnexpectedResponse("node_version"))
        }
    }
}

async fn run_ready_checker(
    p2p_context: P2PContext,
    beacon_node: EthBeaconNodeApiClient,
    pubkeys: Vec<PubKey>,
    mut seen_pubkeys: mpsc::Receiver<PubKey>,
    mut validator_api_calls: mpsc::Receiver<()>,
    ct: CancellationToken,
    readiness: ReadyState,
) {
    let config = match tokio::select! {
        () = ct.cancelled() => return,
        result = fetch_config(&beacon_node) => result,
    } {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "Failed to initialise ready checker");
            return;
        }
    };

    let mut checker = ReadyChecker::new(pubkeys, current_epoch(&config, Utc::now()));
    // Drop missed ticks rather than firing a catch-up burst if a round stalls,
    // so the connectivity hysteresis stays on real wall-clock periods.
    let mut slot_interval = tokio::time::interval(config.slot_duration);
    slot_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut peer_count_interval = tokio::time::interval(PEER_COUNT_PERIOD);
    peer_count_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut seen_pubkeys_open = true;
    let mut validator_api_calls_open = true;

    slot_interval.tick().await;
    peer_count_interval.tick().await;

    loop {
        tokio::select! {
            () = ct.cancelled() => return,
            _ = peer_count_interval.tick() => {
                if let Err(error) = update_beacon_node_peer_count(&beacon_node, &mut checker).await {
                    warn!(%error, "Failed to get beacon node peer count");
                }
            }
            _ = slot_interval.tick() => {
                let sync_status = match fetch_sync_status(&beacon_node).await {
                    Ok(status) => Some(status),
                    Err(error) => {
                        warn!(%error, "Failed to get beacon node sync status");
                        None
                    }
                };
                let evaluated_epoch = current_epoch(&config, Utc::now());
                let status = checker.evaluate_round(
                    quorum_peers_connected(&p2p_context),
                    evaluated_epoch,
                    sync_status,
                );
                instrument_status(&status);
                match status {
                    Ok(()) => readiness.set_ready(),
                    Err(error) => readiness.set_error(error),
                }
            }
            pubkey = seen_pubkeys.recv(), if seen_pubkeys_open => {
                match pubkey {
                    Some(pubkey) => checker.observe_pubkey(pubkey),
                    None => seen_pubkeys_open = false,
                }
            }
            call = validator_api_calls.recv(), if validator_api_calls_open => {
                match call {
                    Some(()) => checker.observe_validator_api_call(),
                    None => validator_api_calls_open = false,
                }
            }
        }
    }
}

async fn fetch_config(
    beacon_node: &EthBeaconNodeApiClient,
) -> Result<ChainConfig, ReadyCheckerError> {
    let genesis_time = beacon_node
        .fetch_genesis_time()
        .await
        .map_err(|error| ReadyCheckerError::BeaconNode(error.into()))?;
    let (slot_duration, slots_per_epoch) = beacon_node
        .fetch_slots_config()
        .await
        .map_err(|error| ReadyCheckerError::BeaconNode(error.into()))?;

    // `tokio::time::interval` panics on a zero period, so reject a zero slot
    // duration here rather than letting the checker loop panic.
    if slot_duration.is_zero() {
        return Err(ReadyCheckerError::ZeroSlotDuration);
    }

    Ok(ChainConfig {
        genesis_time,
        slot_duration,
        slots_per_epoch,
    })
}

async fn update_beacon_node_peer_count(
    beacon_node: &EthBeaconNodeApiClient,
    checker: &mut ReadyChecker,
) -> Result<(), ReadyCheckerError> {
    let connected = fetch_peer_count(beacon_node).await?;
    MONITORING_METRICS.beacon_node_peers.set(connected);
    checker.beacon_node_peer_count = Some(connected);

    Ok(())
}

async fn fetch_peer_count(beacon_node: &EthBeaconNodeApiClient) -> Result<u64, ReadyCheckerError> {
    match beacon_node
        .get_peer_count(GetPeerCountRequest {})
        .await
        .map_err(ReadyCheckerError::BeaconNode)?
    {
        GetPeerCountResponse::Ok(response) => {
            parse_u64_field("connected", &response.data.connected)
        }
        GetPeerCountResponse::InternalServerError(_) | GetPeerCountResponse::Unknown => {
            Err(ReadyCheckerError::UnexpectedResponse("peer_count"))
        }
    }
}

async fn fetch_sync_status(
    beacon_node: &EthBeaconNodeApiClient,
) -> Result<BeaconNodeSyncStatus, ReadyCheckerError> {
    match beacon_node
        .get_syncing_status(GetSyncingStatusRequest {})
        .await
        .map_err(ReadyCheckerError::BeaconNode)?
    {
        GetSyncingStatusResponse::Ok(response) => {
            let sync_distance = parse_u64_field("sync_distance", &response.data.sync_distance)?;
            MONITORING_METRICS
                .monitoring_beacon_node_syncing
                .set(i64::from(response.data.is_syncing));
            Ok(BeaconNodeSyncStatus {
                syncing: response.data.is_syncing,
                sync_distance,
            })
        }
        GetSyncingStatusResponse::InternalServerError(_) | GetSyncingStatusResponse::Unknown => {
            Err(ReadyCheckerError::UnexpectedResponse("syncing_status"))
        }
    }
}

fn parse_u64_field(field: &'static str, value: &str) -> Result<u64, ReadyCheckerError> {
    value.parse::<u64>().map_err(|_| ReadyCheckerError::Parse {
        field,
        value: value.to_owned(),
    })
}

/// Returns true if connected to enough known cluster peers for quorum.
pub fn quorum_peers_connected(p2p_context: &P2PContext) -> bool {
    // Without our own peer id we cannot exclude self from the count, and p2p is
    // not yet initialised, so we cannot have quorum.
    let Some(local_peer_id) = p2p_context.local_peer_id() else {
        return false;
    };
    let known_peers = p2p_context.known_peers();
    let known_count = u64::try_from(known_peers.len()).unwrap_or(u64::MAX);
    let required = helpers::threshold(known_count).saturating_sub(1);
    let required = usize::try_from(required).unwrap_or(usize::MAX);
    let peer_store = p2p_context.peer_store_lock();
    let connected = known_peers
        .iter()
        .filter(|peer_id| **peer_id != local_peer_id)
        .filter(|peer_id| !peer_store.connections_to_peer(peer_id).is_empty())
        .count();

    connected >= required
}

fn current_epoch(config: &ChainConfig, now: DateTime<Utc>) -> u128 {
    if config.slot_duration.is_zero() || config.slots_per_epoch == 0 {
        return 0;
    }

    let chain_age = now
        .signed_duration_since(config.genesis_time)
        .to_std()
        .unwrap_or(Duration::ZERO);
    let current_slot = chain_age
        .as_nanos()
        .checked_div(config.slot_duration.as_nanos())
        .unwrap_or(0);

    current_slot
        .checked_div(u128::from(config.slots_per_epoch))
        .unwrap_or(0)
}

fn instrument_status(status: &ReadyResult) {
    let code = match status {
        Ok(()) => READYZ_READY,
        Err(error) => error.readyz_code(),
    };
    MONITORING_METRICS.monitoring_readyz.set(code);
}

#[derive(Debug, Clone, Copy)]
struct BeaconNodeSyncStatus {
    syncing: bool,
    sync_distance: u64,
}

struct ReadyChecker {
    pubkeys: Vec<PubKey>,
    current_epoch: u128,
    beacon_node_peer_count: Option<u64>,
    not_connected_rounds: u64,
    current_validator_api_calls: u64,
    previous_validator_api_calls: u64,
    current_pubkeys: HashSet<PubKey>,
    previous_pubkeys: HashSet<PubKey>,
}

impl ReadyChecker {
    fn new(pubkeys: Vec<PubKey>, current_epoch: u128) -> Self {
        Self {
            previous_pubkeys: pubkeys.iter().copied().collect(),
            pubkeys,
            current_epoch,
            beacon_node_peer_count: None,
            not_connected_rounds: MIN_NOT_CONNECTED_ROUNDS,
            current_validator_api_calls: 0,
            previous_validator_api_calls: 1,
            current_pubkeys: HashSet::new(),
        }
    }

    fn observe_pubkey(&mut self, pubkey: PubKey) {
        self.current_pubkeys.insert(pubkey);
    }

    fn observe_validator_api_call(&mut self) {
        self.current_validator_api_calls = self.current_validator_api_calls.saturating_add(1);
    }

    fn evaluate_round(
        &mut self,
        quorum_connected: bool,
        evaluated_epoch: u128,
        sync_status: Option<BeaconNodeSyncStatus>,
    ) -> Result<(), ReadinessError> {
        if quorum_connected {
            self.not_connected_rounds = 0;
        } else {
            self.not_connected_rounds = self.not_connected_rounds.saturating_add(1);
        }

        if evaluated_epoch != self.current_epoch {
            self.current_epoch = evaluated_epoch;
            self.previous_pubkeys = std::mem::take(&mut self.current_pubkeys);
            self.previous_validator_api_calls = self.current_validator_api_calls;
            self.current_validator_api_calls = 0;
        }

        let Some(sync_status) = sync_status else {
            return Err(ReadinessError::BeaconNodeDown);
        };

        if sync_status.syncing {
            Err(ReadinessError::BeaconNodeSyncing)
        } else if self.beacon_node_peer_count == Some(0) {
            Err(ReadinessError::BeaconNodeZeroPeers)
        } else if sync_status.sync_distance > BN_FAR_BEHIND_SLOTS {
            Err(ReadinessError::BeaconNodeFarBehind)
        } else if self.not_connected_rounds >= MIN_NOT_CONNECTED_ROUNDS {
            Err(ReadinessError::InsufficientPeers)
        } else if self.previous_validator_api_calls == 0 {
            Err(ReadinessError::ValidatorClientNotConnected)
        } else if self.previous_pubkeys.len() < self.pubkeys.len()
            && self.current_pubkeys.len() < self.pubkeys.len()
        {
            Err(ReadinessError::ValidatorClientMissingValidators)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ReadyCheckerError {
    #[error("beacon node request failed: {0}")]
    BeaconNode(#[source] anyhow::Error),

    #[error("unexpected beacon node response from {0}")]
    UnexpectedResponse(&'static str),

    #[error("beacon node reported a zero slot duration")]
    ZeroSlotDuration,

    #[error("failed to parse beacon node {field}: {value}")]
    Parse { field: &'static str, value: String },
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use libp2p::{Multiaddr, PeerId, identity::Keypair, swarm::ConnectionId};
    use pluto_p2p::p2p_context::{P2PContext, Peer};

    use super::*;

    fn peer_id() -> PeerId {
        Keypair::generate_secp256k1().public().to_peer_id()
    }

    fn pubkey(byte: u8) -> PubKey {
        PubKey::from([byte; 48])
    }

    fn connected_context(peer_ids: &[PeerId], connected_peers: &[PeerId]) -> P2PContext {
        let context = P2PContext::new(peer_ids.iter().copied());
        context.set_local_peer_id(peer_ids[0]);
        {
            let mut store = context.peer_store_write_lock();
            for (index, peer_id) in connected_peers.iter().enumerate() {
                store.add_peer(Peer {
                    id: *peer_id,
                    connection_id: ConnectionId::new_unchecked(index),
                    remote_addr: Multiaddr::empty(),
                });
            }
        }
        context
    }

    fn synced() -> Option<BeaconNodeSyncStatus> {
        Some(BeaconNodeSyncStatus {
            syncing: false,
            sync_distance: 0,
        })
    }

    #[test]
    fn quorum_peers_connected_uses_p2p_context_connections() {
        let peers = [peer_id(), peer_id(), peer_id(), peer_id()];

        let context = connected_context(&peers, &peers[1..3]);
        assert!(quorum_peers_connected(&context));

        let context = connected_context(&peers, &peers[1..2]);
        assert!(!quorum_peers_connected(&context));
    }

    #[test]
    fn ready_checker_matches_go_error_precedence() {
        let pubkeys = vec![pubkey(1), pubkey(2), pubkey(3)];
        let mut checker = ReadyChecker::new(pubkeys, 0);
        checker.beacon_node_peer_count = Some(0);

        let result = checker.evaluate_round(
            true,
            0,
            Some(BeaconNodeSyncStatus {
                syncing: true,
                sync_distance: BN_FAR_BEHIND_SLOTS.saturating_add(1),
            }),
        );

        assert_eq!(result, Err(ReadinessError::BeaconNodeSyncing));
    }

    #[test]
    fn ready_checker_requires_quorum_for_six_rounds() {
        let pubkeys = vec![pubkey(1)];
        let mut checker = ReadyChecker::new(pubkeys, 0);

        assert_eq!(
            checker.evaluate_round(false, 0, synced()),
            Err(ReadinessError::InsufficientPeers)
        );

        assert_eq!(checker.evaluate_round(true, 0, synced()), Ok(()));
    }

    #[test]
    fn ready_checker_tracks_validator_api_by_epoch() {
        let pubkeys = vec![pubkey(1), pubkey(2), pubkey(3)];
        let mut checker = ReadyChecker::new(pubkeys.clone(), 0);

        checker.observe_validator_api_call();
        checker.observe_pubkey(pubkeys[0]);
        assert_eq!(
            checker.evaluate_round(true, 1, synced()),
            Err(ReadinessError::ValidatorClientMissingValidators)
        );

        for pubkey in pubkeys {
            checker.observe_pubkey(pubkey);
        }
        assert_eq!(checker.evaluate_round(true, 1, synced()), Ok(()));
    }

    #[test]
    fn ready_checker_detects_missing_validator_api_calls_on_epoch_change() {
        let pubkeys = vec![pubkey(1)];
        let mut checker = ReadyChecker::new(pubkeys, 0);

        assert_eq!(
            checker.evaluate_round(true, 1, synced()),
            Err(ReadinessError::ValidatorClientNotConnected)
        );
    }

    #[test]
    fn current_epoch_divides_chain_age_by_slot_and_epoch() {
        let genesis_time = Utc.timestamp_opt(0, 0).single().expect("valid timestamp");
        let now = Utc.timestamp_opt(768, 0).single().expect("valid timestamp");
        let config = ChainConfig {
            genesis_time,
            slot_duration: Duration::from_secs(12),
            slots_per_epoch: 32,
        };

        assert_eq!(current_epoch(&config, now), 2);
    }
}
