//! Distributed-validator node wiring.
//!
//! This module constructs every core duty-workflow component, connects them
//! together, composes the P2P behaviours, and runs the node until cancelled.
//!
//! The work is split into a load phase and a wire phase:
//!
//! * [`run`] loads the cluster lock, P2P key, and beacon clients, constructs
//!   the consensus component + P2P behaviours, then calls
//!   [`wire::wire_core_workflow`].
//! * [`wire::wire_core_workflow`] takes already-resolved inputs and produces
//!   the wired component graph (so it is unit-testable against a `BeaconMock`).
//!
//! Lifecycle is idiomatic tokio: long-lived tasks live in a [`JoinSet`], driven
//! until the [`CancellationToken`] fires or the first task fails, after which
//! an explicit ordered shutdown runs.

pub mod behaviour;
pub mod config;
pub mod wire;

pub use config::AppConfig;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime},
};

use futures::StreamExt;
use pluto_consensus::qbft;
use pluto_core::gater::DutyGaterFn;
use pluto_p2p::peer::Peer;
use pluto_testutil::{
    BeaconMock, ValidatorSet,
    validatormock::{Component as ValidatorMock, Signer, SpecMeta},
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use behaviour::{CoreBehaviour, CoreHandles};
use pluto_core::types::PubKey;
use wire::{ParSigExSeam, SlotTickFn, ValidatorInfo, WireInputs, WiredComponents};

use crate::{health, monitoringapi, privkeylock};

/// Buffer for the validator-API-call channel feeding the readiness checker.
/// Sends are non-blocking (dropped when full): the checker only needs to
/// observe that calls happened, not count every one exactly.
const VAPI_CALLS_BUFFER: usize = 128;

/// Duty factor spreading simnet duties deterministically across an epoch.
const SIMNET_DUTY_FACTOR: u64 = 100;

/// Simnet deterministic sync-committee duty schedule: active in the first 2
/// epochs of every 8.
const SIMNET_SYNC_COMM_DUTIES: (u64, u64) = (2, 8);

/// Timeout for the simnet validator mock's client calls to this node's own
/// validator API.
const SIMNET_VMOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors raised while constructing or running a distributed-validator node.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Failed to load or verify the cluster lock.
    #[error("cluster lock: {0}")]
    LoadLock(#[from] pluto_cluster::load::LoadError),

    /// Failed to derive cluster peers from the lock.
    #[error("cluster definition: {0}")]
    Definition(#[from] pluto_cluster::definition::DefinitionError),

    /// Failed to read distributed-validator data from the lock.
    #[error("distributed validator: {0}")]
    DistValidator(#[from] pluto_cluster::distvalidator::DistValidatorError),

    /// Execution-layer (eth1) client construction failed.
    #[error("eth1 client: {0}")]
    Eth1(#[source] pluto_eth1wrap::EthClientError),

    /// A distributed validator's public key was not 48 bytes.
    #[error("distributed validator pubkey is not 48 bytes")]
    InvalidValidatorPubKey,

    /// A distributed validator's fee-recipient address was missing or not a
    /// valid 20-byte execution address.
    #[error("distributed validator {index} has an invalid fee recipient address")]
    InvalidFeeRecipient {
        /// Index of the offending distributed validator.
        index: usize,
    },

    /// Failed to load the P2P private key.
    #[error("load p2p key: {0}")]
    LoadKey(#[from] pluto_k1util::K1UtilError),

    /// The local P2P key does not match any cluster operator.
    #[error("local peer not found in cluster lock")]
    LocalPeerNotFound,

    /// Private-key lock acquisition/maintenance failed.
    #[error("privkey lock: {0}")]
    PrivKeyLock(#[from] privkeylock::PrivKeyLockError),

    /// P2P peer derivation/verification failed.
    #[error("p2p peer: {0}")]
    Peer(#[from] pluto_p2p::peer::PeerError),

    /// P2P node construction failed.
    #[error("p2p node: {0}")]
    P2P(#[from] pluto_p2p::p2p::P2PError),

    /// Relay endpoint resolution failed.
    #[error("relays: {0}")]
    Relays(#[from] pluto_p2p::bootnode::BootnodeError),

    /// QBFT consensus construction failed.
    #[error("consensus: {0}")]
    Consensus(#[from] qbft::Error),

    /// QBFT p2p adapter construction failed.
    #[error("consensus p2p: {0}")]
    ConsensusP2P(#[from] qbft::p2p::Error),

    /// A beacon node API request failed.
    #[error("beacon node api: {0}")]
    BeaconApi(#[from] pluto_eth2api::EthBeaconNodeApiClientError),

    /// The beacon node URL could not be parsed.
    #[error("invalid beacon node url: {0}")]
    BeaconUrl(#[from] url::ParseError),

    /// The beacon node's fork schedule does not contain the cluster lock's fork
    /// version — the beacon node is on a different network than the cluster.
    #[error(
        "mismatch between lock file fork version and beacon node fork schedule: \
         lock file is for network {lock_network} (fork version {lock_fork_version}), \
         but the beacon node is on network {beacon_node_network}; \
         ensure the beacon node is on the correct network"
    )]
    ForkScheduleMismatch {
        /// Network the cluster lock's fork version resolves to (or its hex
        /// representation if it matches no known network).
        lock_network: String,
        /// The cluster lock's fork version, `0x`-prefixed hex.
        lock_fork_version: String,
        /// Network the beacon node's genesis fork version resolves to (or its
        /// hex representation if it matches no known network).
        beacon_node_network: String,
    },

    /// Beacon node client construction failed.
    #[error("beacon client: {0}")]
    BeaconClient(#[source] anyhow::Error),

    /// Duty gater construction failed.
    #[error("duty gater: {0}")]
    Gater(#[source] pluto_core::gater::GaterError),

    /// Deadline calculator construction failed.
    #[error("deadline calculator: {0}")]
    Deadline(#[source] pluto_core::deadline::DeadlineError),

    /// Graffiti builder construction failed.
    #[error("graffiti: {0}")]
    Graffiti(#[source] pluto_core::fetcher::GraffitiError),

    /// Signature aggregator construction failed.
    #[error("sigagg: {0}")]
    SigAgg(#[source] pluto_core::sigagg::SigAggError),

    /// Broadcaster construction failed.
    #[error("broadcaster: {0}")]
    Broadcaster(#[source] pluto_core::bcast::Error),

    /// Partial-signature exchange broadcast failed.
    #[error("parsigex: {0}")]
    ParSigEx(#[from] pluto_parsigex::Error),

    /// Scheduler construction failed.
    #[error("scheduler: {0}")]
    Scheduler(#[source] pluto_core::scheduler::SchedulerError),

    /// Validator API server failed.
    #[error("validator api: {0}")]
    ValidatorApi(#[source] std::io::Error),

    /// Monitoring API server failed.
    #[error("monitoring api: {0}")]
    MonitoringApi(#[source] std::io::Error),

    /// Simnet (beacon/validator mock) setup failed.
    #[error("simnet: {0}")]
    Simnet(String),
}

/// A wired, runnable distributed-validator node.
///
/// Construct with [`App::new`] (loads lock/keys, builds and wires every
/// component) and drive with [`App::run`].
pub struct App {
    config: AppConfig,
}

impl App {
    /// Creates a new application from its configuration.
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// Loads cluster state, wires the core workflow, and runs the node until
    /// `ct` is cancelled or a long-lived task fails.
    pub async fn run(self, ct: CancellationToken) -> Result<(), AppError> {
        run(self.config, ct).await
    }
}

/// Loads the cluster lock + key, builds the consensus component and P2P
/// behaviours, wires the core workflow, and drives the node.
async fn run(config: AppConfig, ct: CancellationToken) -> Result<(), AppError> {
    // ---- (1) Load cluster lock + key, derive peers and this node's index ----
    //
    // Operator-signature verification uses the configured execution-layer
    // client; without an `eth1_endpoint`, a no-op client is used
    // (BLS-aggregate and node signatures are still verified, but EIP-1271
    // smart-contract operator signatures are not). With `no_verify`,
    // verification still runs but failures are downgraded to warnings.
    let eth1 = pluto_eth1wrap::EthClient::new(config.eth1_endpoint.as_deref().unwrap_or_default())
        .await
        .map_err(AppError::Eth1)?;
    let lock =
        pluto_cluster::load::load_cluster_lock(&config.lock_file, config.no_verify, &eth1).await?;
    let threshold = lock.threshold;

    let key = pluto_k1util::load(&config.priv_key_file)?;

    // Guards against a second node running against the same key.
    let priv_key_lock: Option<Arc<privkeylock::Service>> = if config.priv_key_locking {
        Some(Arc::new(
            privkeylock::Service::new(
                format!("{}.lock", config.priv_key_file.display()),
                "pluto run",
            )
            .await?,
        ))
    } else {
        None
    };

    let peers = lock.peers()?;
    pluto_p2p::peer::verify_p2p_key(&peers, &key)?;

    // Cluster size + quorum for the health-checker metadata, captured before
    // `peers` is moved into the P2P wiring.
    let num_peers = i64::try_from(peers.len()).unwrap_or(i64::MAX);
    let quorum_peers = i64::try_from(pluto_cluster::helpers::threshold(
        u64::try_from(peers.len()).unwrap_or(u64::MAX),
    ))
    .unwrap_or(i64::MAX);

    let local_peer_id = pluto_p2p::peer::peer_id_from_key(key.public_key())?;
    let local_node = peers
        .iter()
        .find(|p| p.id == local_peer_id)
        .ok_or(AppError::LocalPeerNotFound)?;
    let local_idx = local_node.index;
    let share_idx = local_node.share_idx();

    // qbft peers (secp256k1 pubkeys, in process-index order).
    let qbft_peers = build_qbft_peers(&peers)?;

    // Per-validator data for this node.
    let validators = build_validators(&lock, share_idx)?;

    // DV root pubkeys + count for the monitoring readiness + health checkers,
    // captured before `validators` is moved into the core-workflow wiring.
    let monitoring_pubkeys: Vec<PubKey> = validators.iter().map(|v| v.pubkey).collect();
    let num_validators = validators.len();

    // ---- (2/3) eth2 clients ----
    //
    // Simnet: the beacon clients target an in-process `BeaconMock` (seeded with
    // the cluster's validators) instead of a real endpoint. The mock is held
    // for the node's lifetime; dropping it tears down its HTTP server and ticker.
    //
    // TODO(#402 part B): multi-endpoint fallback over `beacon_node_addrs`;
    // `EthBeaconNodeApiClient` is single-endpoint, so only the first is used.
    let simnet_slot_duration = normalize_simnet_slot_duration(config.simnet_slot_duration);
    // Fuzz mode enables the beacon mock on its own (CLI validation still
    // requires an endpoint or `--simnet-beacon-mock`, so fuzz alone is invalid).
    let simnet_beacon_mock = if config.simnet_beacon_mock || config.simnet_beacon_mock_fuzz {
        Some(
            build_simnet_beacon_mock(
                &lock.fork_version,
                simnet_slot_duration,
                config.simnet_beacon_mock_fuzz,
                &validators,
            )
            .await?,
        )
    } else {
        None
    };
    // Simnet uses the mock's URL for both the scheduling and submission clients.
    let beacon_node_addr: String = match &simnet_beacon_mock {
        Some(mock) => mock.uri(),
        None => config
            .beacon_node_addrs
            .first()
            .cloned()
            .unwrap_or_default(),
    };
    let eth2_cl = build_api_client(&beacon_node_addr, config.beacon_node_timeout)?;

    // Fail fast if the beacon node is on a different network than the cluster
    // lock (Charon's `configureEth2Client`, app.go:1022-1053). Both eth2
    // clients here target the same endpoint, so a single check suffices —
    // unlike Charon, which checks each independently-constructed client.
    //
    // Skipped for the in-process simnet mock: it is derived from the lock's own
    // fork version (`build_simnet_beacon_mock`), so a network mismatch is
    // impossible by construction.
    if simnet_beacon_mock.is_none() {
        verify_fork_schedule(&eth2_cl, &lock.fork_version).await?;
    }

    let beacon_client = pluto_eth2api::BeaconNodeClient::new(eth2_cl.clone());
    // Broadcasting uses a separate client with the (distinct) submit timeout.
    let submission_api = build_api_client(&beacon_node_addr, config.beacon_node_submit_timeout)?;
    let submission_client = pluto_eth2api::BeaconNodeClient::new(submission_api);

    // Warm both config caches before duty scheduling so signing-domain
    // resolution never blocks on a live fetch; failure aborts startup.
    tokio::try_join!(beacon_client.warm(), submission_client.warm())?;

    // ---- Beacon-derived duty-workflow inputs ----

    // Duty admission gate: validates duties against the beacon chain.
    let duty_gater: DutyGaterFn = pluto_core::gater::DutyGater::new(&beacon_client)
        .await
        .map_err(AppError::Gater)?
        .into_fn();

    // Per-component deadline calculator, shared as an `Arc<dyn ...>` so a single
    // beacon-derived instance backs every component's deadliner.
    let deadline_calc: Arc<dyn pluto_core::deadline::DeadlineCalculator> = Arc::new(
        pluto_core::deadline::DutyDeadlineCalculator::from_client(&beacon_client)
            .await
            .map_err(AppError::Deadline)?,
    );

    // Per-validator graffiti for proposed blocks.
    let graffiti_pubkeys: Vec<pluto_core::types::PubKey> =
        validators.iter().map(|v| v.pubkey).collect();
    let graffiti_builder = pluto_core::fetcher::GraffitiBuilder::new(
        &graffiti_pubkeys,
        config.graffiti.as_deref(),
        config.graffiti_disable_client_append,
        &eth2_cl,
    )
    .await
    .map_err(AppError::Graffiti)?;

    // Use the mock's echoed slot timing, not the configured value: fuzz mode
    // overrides it with a 12s default, and the validator mock's ticker must
    // match the mock. `slots_per_epoch` also feeds the Electra activation slot.
    let (fetched_slot_duration, slots_per_epoch) = beacon_client.slots_config().await?;
    let fork_config = beacon_client.fork_config().await?;
    let electra_slot = fork_config
        .get(&pluto_eth2api::ConsensusVersion::Electra)
        .map(|schedule| schedule.epoch)
        .unwrap_or(0)
        .saturating_mul(slots_per_epoch);

    // Feature set drives optional/alpha behaviors.
    let feature_set = Arc::clone(&config.feature_set);
    let fetch_only_comm_idx0 = feature_set.enabled(pluto_featureset::Feature::FetchOnlyCommIdx0);

    // ---- Consensus (built directly; shared with p2p behaviour + core stitch) ----
    //
    // TODO(#402 part B): wrap in ConsensusController for dynamic protocol
    // switching (priority/infosync).
    //
    // Resolve the broadcaster<->behaviour construction cycle with the
    // `Arc<OnceLock<Handle>>` pattern (see qbft::p2p `build_consensus_nodes`).
    let (cons_deadliner, cons_expired_rx) = pluto_core::deadline::DeadlinerTask::start(
        ct.clone(),
        "consensus.qbft",
        Arc::clone(&deadline_calc),
    );

    // TODO: the `Arc<OnceLock<Handle>>` pattern is awkward; explore alternatives.
    let handle_slot = Arc::new(OnceLock::<qbft::p2p::Handle>::new());
    let broadcaster: qbft::Broadcaster = {
        let handle_slot = Arc::clone(&handle_slot);
        Arc::new(move |_ct, msg| {
            let handle_slot = Arc::clone(&handle_slot);
            Box::pin(async move {
                let handle = handle_slot
                    .get()
                    .expect("qbft p2p handle initialized before broadcast")
                    .clone();
                handle.broadcast(msg).await
            })
        })
    };

    let consensus = Arc::new(qbft::Consensus::new(qbft::Config {
        peers: qbft_peers,
        local_peer_idx: i64::try_from(local_idx).map_err(|_| AppError::LocalPeerNotFound)?,
        privkey: key.clone(),
        deadliner: cons_deadliner,
        expired_rx: cons_expired_rx,
        duty_gater: Arc::clone(&duty_gater),
        broadcaster,
        sniffer: Arc::new(|_| {}),
        // Charon gates duplicate-attestation comparison on the alpha
        // `ChainSplitHalt` featureset flag (off by default).
        compare_attestations: feature_set.enabled(pluto_featureset::Feature::ChainSplitHalt),
        feature_set: Arc::clone(&feature_set),
        timer_func: pluto_consensus::timer::get_round_timer_func(Arc::clone(&feature_set)),
    })?);

    // Full public-share map (DV root pubkey -> share index -> public share),
    // used by the parsigex verifier to check each peer's partial signature.
    let pub_shares_by_key = build_pub_shares_by_key(&lock)?;

    // ---- P2P behaviours (relay + parsigex + qbft + peerinfo) ----
    let (node, handles) = behaviour::wire_p2p(
        key.clone(),
        config.p2p.clone(),
        peers,
        Arc::clone(&consensus),
        Arc::clone(&duty_gater),
        beacon_client.clone(),
        pub_shares_by_key,
        lock.lock_hash.clone(),
        config.builder_api,
        config.nickname.clone(),
        ct.clone(),
    )
    .await?;
    // Complete the broadcaster<->behaviour cycle.
    handle_slot
        .set(handles.consensus.clone())
        .map_err(|_| AppError::ConsensusP2P(qbft::p2p::Error::BehaviourClosed))?;

    // ---- Wire the core workflow ----
    let upstream_url = reqwest::Url::parse(&beacon_node_addr)?;

    let parsigex_seam = production_parsigex_seam(&handles);

    // Aggregated-signature verifier: verifies the reconstructed group signature
    // against the beacon-node signing domain.
    let sigagg_verifier = pluto_core::sigagg::new_verifier(beacon_client.clone());

    // The readiness checker uses its own beacon-client clone.
    let monitoring_beacon = eth2_cl.clone();

    // Readiness observes which DV root pubkeys the validator client references
    // on the validator API, so `/readyz` can tell whether the VC is exercising
    // every validator. A deduped set (not a channel) keeps this bounded by the
    // validator count on the request path: repeated validator-API calls just
    // re-insert, and the ready checker drains the set each slot.
    let seen_pubkeys: Arc<Mutex<HashSet<PubKey>>> = Arc::new(Mutex::new(HashSet::new()));
    let seen_pubkeys_observer: pluto_core::validatorapi::SeenPubkeysFn = {
        let seen_pubkeys = Arc::clone(&seen_pubkeys);
        Arc::new(move |pubkey: PubKey| {
            if let Ok(mut set) = seen_pubkeys.lock() {
                set.insert(pubkey);
            }
        })
    };

    // Simnet validator mock: drives this node's own validator API with the
    // share keys. Built here (while `eth2_cl`/`validators` are in scope) so
    // `wire_core_workflow` can register its `slot_ticked`; held past
    // `run_lifecycle` for an explicit shutdown.
    let vmock = if config.simnet_validator_mock {
        Some(
            build_simnet_validator_mock(
                &config.simnet_validator_keys_dir,
                config.validator_api_addr,
                config.builder_api,
                &validators,
                &eth2_cl,
                fetched_slot_duration,
                slots_per_epoch,
            )
            .await?,
        )
    } else {
        None
    };

    let wired = wire::wire_core_workflow(
        WireInputs {
            threshold,
            share_idx,
            beacon_client,
            submission_client,
            validators,
            consensus: Arc::clone(&consensus),
            builder_enabled: config.builder_api,
            upstream_url,
            parsigex: parsigex_seam,
            sigagg_verifier,
            deadline_calc,
            graffiti_builder,
            electra_slot,
            fetch_only_comm_idx0,
            seen_pubkeys: Some(seen_pubkeys_observer),
            slot_tick: vmock.clone().map(|v| simnet_slot_tick(v, ct.clone())),
        },
        ct.clone(),
    )
    .await?;

    // ---- Lifecycle: spawn long-lived tasks ----
    run_lifecycle(
        node,
        consensus,
        handles,
        wired,
        priv_key_lock,
        vmock,
        config.validator_api_addr,
        MonitoringInputs {
            addr: config.monitoring_addr,
            beacon_node: monitoring_beacon,
            pubkeys: monitoring_pubkeys,
            num_validators,
            num_peers,
            quorum_peers,
            seen_pubkeys,
        },
        ct,
    )
    .await
}

/// Inputs for wiring the monitoring API: the listen address plus everything the
/// readiness and health checkers need.
struct MonitoringInputs {
    /// Address the monitoring HTTP server binds to.
    addr: std::net::SocketAddr,
    /// Beacon client the readiness checker queries for sync/peer/version state.
    beacon_node: pluto_eth2api::EthBeaconNodeApiClient,
    /// DV root public keys tracked by the readiness checker.
    pubkeys: Vec<PubKey>,
    /// Number of validators (health-checker cardinality + metadata).
    num_validators: usize,
    /// Number of cluster peers (health-checker metadata).
    num_peers: i64,
    /// Peers required for quorum (health-checker metadata).
    quorum_peers: i64,
    /// Shared, deduped set of DV root pubkeys observed on the validator API,
    /// drained each slot by the readiness checker.
    seen_pubkeys: Arc<Mutex<HashSet<PubKey>>>,
}

/// Builds the production parsigex seam from the real `parsigex::Handle`.
fn production_parsigex_seam(handles: &CoreHandles) -> ParSigExSeam {
    let broadcast_handle = handles.parsigex.clone();
    let subscribe_handle = handles.parsigex.clone();
    ParSigExSeam {
        broadcast: Arc::new(move |duty, set| {
            let handle = broadcast_handle.clone();
            Box::pin(async move {
                handle
                    .broadcast(duty, set)
                    .await
                    .map(|_| ())
                    .map_err(AppError::ParSigEx)
            })
        }),
        subscribe: Box::new(move |received| {
            Box::pin(async move {
                let sub = pluto_parsigex::received_subscriber(move |duty, set| {
                    let received = Arc::clone(&received);
                    async move {
                        received(duty, set).await;
                    }
                });
                subscribe_handle.subscribe(sub).await;
            })
        }),
    }
}

/// Spawns and supervises the node's long-lived tasks, then performs an ordered
/// shutdown on cancellation or first-task failure.
#[allow(
    clippy::too_many_arguments,
    reason = "aggregates independent long-lived inputs (swarm, consensus, wired components, monitoring); a single config struct would just move the coupling"
)]
async fn run_lifecycle(
    node: pluto_p2p::p2p::Node<CoreBehaviour>,
    consensus: Arc<qbft::Consensus>,
    handles: CoreHandles,
    wired: WiredComponents,
    priv_key_lock: Option<Arc<privkeylock::Service>>,
    vmock: Option<Arc<ValidatorMock>>,
    validator_api_addr: std::net::SocketAddr,
    monitoring: MonitoringInputs,
    ct: CancellationToken,
) -> Result<(), AppError> {
    let WiredComponents {
        scheduler_task,
        dutydb,
        parsigdb,
        parsigdb_deadliner_rx,
        aggsigdb: _aggsigdb,
        fetcher: _fetcher,
        validator_api_router,
    } = wired;

    // Self-spawning actor: consensus expired-duty pruner.
    let _consensus_task = consensus.start(ct.clone());

    let mut tasks: JoinSet<Result<(), AppError>> = JoinSet::new();

    // Supervise the scheduler actor alongside the other long-lived tasks so
    // its exit triggers node shutdown (it only exits on cancellation).
    tasks.extend([async move {
        let _ = scheduler_task.await;
        Ok::<(), AppError>(())
    }]);

    // Swarm drive loop (push-based routing inside behaviours).
    {
        let ct = ct.clone();
        tasks.spawn(async move {
            drive_network(node, ct).await;
            Ok(())
        });
    }

    // ParSigDB trim task.
    {
        let parsigdb = Arc::clone(&parsigdb);
        tasks.spawn(async move {
            parsigdb.trim(parsigdb_deadliner_rx).await;
            Ok(())
        });
    }

    // Private-key lock maintenance loop. Only spawn `run` when locking is
    // enabled — `Service::close()` blocks forever unless `run` was called, so
    // spawn and close are guarded by the same `Option`.
    if let Some(svc) = &priv_key_lock {
        let svc = Arc::clone(svc);
        // A lock-maintenance failure fails the run (Charon parity); a graceful
        // `close()` returns `Ok`.
        tasks.spawn(async move { svc.run().await.map_err(AppError::PrivKeyLock) });
    }

    // ---- Monitoring API ----
    //
    // Serves Prometheus `/metrics`, `/livez` and `/readyz` on the monitoring
    // address (backed by the readiness checker), and runs the health checker
    // that publishes `app_health_checks`.
    let MonitoringInputs {
        addr: monitoring_addr,
        beacon_node: monitoring_beacon,
        pubkeys: monitoring_pubkeys,
        num_validators,
        num_peers,
        quorum_peers,
        seen_pubkeys,
    } = monitoring;

    // Every validator-API request feeds the readiness checker's "vc connected"
    // signal. Non-blocking sends drop when the buffer is full.
    let (vapi_calls_tx, vapi_calls_rx) = tokio::sync::mpsc::channel::<()>(VAPI_CALLS_BUFFER);

    // `seen_pubkeys` collects the DV root pubkeys the validator client
    // references on the validator API (via the component's observer); the
    // checker drains it each slot so readiness knows every validator is served.
    let readiness = monitoringapi::start_ready_checker(
        handles.p2p_context.clone(),
        monitoring_beacon,
        monitoring_pubkeys,
        seen_pubkeys,
        vapi_calls_rx,
        ct.clone(),
    );

    // Health checker: periodic metric scrapes → `app_health_checks` gauge.
    {
        let ct = ct.clone();
        let checker = health::Checker::new(
            health::Metadata {
                num_validators: i64::try_from(num_validators).unwrap_or(i64::MAX),
                num_peers,
                quorum_peers,
            },
            Box::new(health::ViseGatherer),
            num_validators,
        );
        tasks.spawn(async move {
            checker.run(ct).await;
            Ok(())
        });
    }

    // Validator API axum server. Each request bumps the readiness "vc
    // connected" counter via middleware.
    let validator_api_router = validator_api_router.layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let vapi_calls = vapi_calls_tx.clone();
            async move {
                let _ = vapi_calls.try_send(());
                next.run(request).await
            }
        },
    ));
    tasks.spawn(serve_validator_api(
        validator_api_addr,
        validator_api_router,
        ct.clone(),
    ));

    // Monitoring HTTP server (metrics + livez + readyz).
    tasks.spawn(serve_monitoring_api(
        monitoring_addr,
        monitoringapi::router_with_state(monitoringapi::MonitoringState::new(readiness)),
        ct.clone(),
    ));

    // Supervise: stop on cancellation or first task completion. A failed task
    // fails the whole run (Charon parity).
    let mut task_err: Option<AppError> = None;
    tokio::select! {
        () = ct.cancelled() => {
            tracing::info!("node: cancellation requested");
        }
        joined = tasks.join_next() => {
            match joined {
                Some(Ok(Err(err))) => {
                    tracing::error!(%err, "node: a long-lived task failed; shutting down");
                    task_err = Some(err);
                }
                _ => tracing::warn!("node: a long-lived task exited; shutting down"),
            }
            ct.cancel();
        }
    }

    // ---- Ordered shutdown ----
    // Simnet validator mock: stop driving new duties and drain in-flight duty
    // tasks first (its `Drop` only cancels best-effort, so shut down explicitly).
    if let Some(vmock) = &vmock {
        vmock.shutdown().await;
    }

    // Close the private-key lock (signals its `run` loop to delete the sentinel
    // file and exit, so the drain below can join it cleanly). Only ever called
    // when `run` was spawned above — otherwise `close()` would block forever.
    if let Some(svc) = &priv_key_lock {
        svc.close().await;
    }

    // Brief drain for in-flight tasks.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.shutdown().await;

    // Stop dutydb (cancels its child token).
    dutydb.shutdown();

    // Fail the run with the first task error (Charon parity).
    task_err.map_or(Ok(()), Err)
}

/// Serves an HTTP `router` on `addr` until `ct` fires. Graceful shutdown on
/// cancellation is a clean exit (`Ok`); a bind or serve failure is mapped via
/// `wrap_err` and fails the run.
async fn serve_http(
    addr: std::net::SocketAddr,
    router: axum::Router,
    ct: CancellationToken,
    wrap_err: fn(std::io::Error) -> AppError,
) -> Result<(), AppError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(wrap_err)?;

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { ct.cancelled().await })
        .await
        .map_err(wrap_err)
}

/// Serves the validator API (see [`serve_http`]).
async fn serve_validator_api(
    addr: std::net::SocketAddr,
    router: axum::Router,
    ct: CancellationToken,
) -> Result<(), AppError> {
    serve_http(addr, router, ct, AppError::ValidatorApi).await
}

/// Serves the monitoring API (see [`serve_http`]).
async fn serve_monitoring_api(
    addr: std::net::SocketAddr,
    router: axum::Router,
    ct: CancellationToken,
) -> Result<(), AppError> {
    serve_http(addr, router, ct, AppError::MonitoringApi).await
}

/// Drives the libp2p swarm. Routing is push-based inside the behaviours, so the
/// loop body only needs to keep polling the swarm.
async fn drive_network(mut node: pluto_p2p::p2p::Node<CoreBehaviour>, ct: CancellationToken) {
    loop {
        tokio::select! {
            () = ct.cancelled() => break,
            _event = node.select_next_some() => {
                // TODO(#402 part B): optional logging of
                // PlutoBehaviourEvent::Inner(CoreBehaviourEvent::...) events.
            }
        }
    }
}

/// Builds the QBFT peer list (secp256k1 pubkeys) from the cluster peers.
fn build_qbft_peers(peers: &[Peer]) -> Result<Vec<qbft::Peer>, AppError> {
    peers
        .iter()
        .map(|peer| {
            Ok(qbft::Peer {
                index: i64::try_from(peer.index).map_err(|_| AppError::LocalPeerNotFound)?,
                name: peer.name.clone(),
                public_key: peer.public_key()?,
            })
        })
        .collect()
}

/// Extracts this node's per-validator data from the cluster lock.
fn build_validators(
    lock: &pluto_cluster::lock::Lock,
    share_idx: u64,
) -> Result<Vec<ValidatorInfo>, AppError> {
    let fee_recipients = lock.fee_recipient_addresses();
    let mut out = Vec::with_capacity(lock.distributed_validators.len());
    for (i, dv) in lock.distributed_validators.iter().enumerate() {
        let pubkey_bytes: [u8; 48] = dv
            .pub_key
            .clone()
            .try_into()
            .map_err(|_| AppError::InvalidValidatorPubKey)?;
        let pubkey = pluto_core::types::PubKey::new(pubkey_bytes);
        let eth2_pubkey: pluto_eth2api::spec::phase0::BLSPubKey = pubkey_bytes;

        // share_idx is 1-indexed; pub_shares is 0-indexed.
        let share_pos = usize::try_from(share_idx)
            .map_err(|_| AppError::LocalPeerNotFound)?
            .saturating_sub(1);
        let pubshare: [u8; 48] = dv.public_share(share_pos)?;

        // A missing or malformed fee recipient is a misconfiguration, not a
        // value to paper over: the zero address is semantically invalid, so
        // fail loudly instead of defaulting (Charon errors when it hex-decodes
        // the address).
        let fee_recipient = fee_recipients
            .get(i)
            .and_then(|s| parse_execution_address(s))
            .ok_or(AppError::InvalidFeeRecipient { index: i })?;

        out.push(ValidatorInfo {
            pubkey,
            eth2_pubkey,
            pubshare,
            fee_recipient,
        });
    }
    Ok(out)
}

/// Builds the full public-share map for the cluster: for every distributed
/// validator, its group (root) public key mapped to every operator's public
/// share, keyed by 1-indexed share index.
///
/// The parsigex verifier uses this to check each inbound partial signature
/// against the sender's public share.
fn build_pub_shares_by_key(
    lock: &pluto_cluster::lock::Lock,
) -> Result<
    HashMap<pluto_core::types::PubKey, HashMap<u64, pluto_crypto::types::PublicKey>>,
    AppError,
> {
    let mut out = HashMap::with_capacity(lock.distributed_validators.len());
    for dv in &lock.distributed_validators {
        let pubkey_bytes: [u8; 48] = dv
            .pub_key
            .clone()
            .try_into()
            .map_err(|_| AppError::InvalidValidatorPubKey)?;
        let pubkey = pluto_core::types::PubKey::new(pubkey_bytes);

        let mut shares = HashMap::with_capacity(dv.pub_shares.len());
        for pos in 0..dv.pub_shares.len() {
            // Share indices are 1-based (matching `ParSignedData::share_idx`);
            // `public_share` takes the 0-based position.
            let share_idx = (pos as u64).saturating_add(1);
            shares.insert(share_idx, dv.public_share(pos)?);
        }
        out.insert(pubkey, shares);
    }
    Ok(out)
}

/// Parses a `0x`-prefixed hex execution address.
fn parse_execution_address(s: &str) -> Option<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Fails fast when the beacon node is on a different network than the cluster
/// lock.
///
/// Mirrors Charon's `configureEth2Client` fork-schedule guard.
async fn verify_fork_schedule(
    eth2_cl: &pluto_eth2api::EthBeaconNodeApiClient,
    lock_fork_version: &[u8],
) -> Result<(), AppError> {
    let versions = eth2_cl.fetch_fork_schedule_versions().await?;

    if versions.iter().any(|v| v.as_slice() == lock_fork_version) {
        return Ok(());
    }

    // Best-effort network names for the operator-facing error.
    Err(AppError::ForkScheduleMismatch {
        lock_network: network_name_or_hex(lock_fork_version),
        lock_fork_version: format!("0x{}", hex::encode(lock_fork_version)),
        beacon_node_network: versions
            .first()
            .map(|v| network_name_or_hex(v))
            .unwrap_or_else(|| "unknown".to_string()),
    })
}

/// Resolves a fork version to its network name, falling back to `0x`-prefixed
/// hex when it matches no known network.
fn network_name_or_hex(fork_version: &[u8]) -> String {
    pluto_eth2util::network::fork_version_to_network(fork_version)
        .unwrap_or_else(|_| format!("0x{}", hex::encode(fork_version)))
}

/// Builds an [`EthBeaconNodeApiClient`](pluto_eth2api::EthBeaconNodeApiClient)
/// for `base_url` with the given request timeout.
fn build_api_client(
    base_url: &str,
    timeout: std::time::Duration,
) -> Result<pluto_eth2api::EthBeaconNodeApiClient, AppError> {
    let http = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| AppError::BeaconClient(e.into()))?;
    pluto_eth2api::EthBeaconNodeApiClient::with_client(base_url, http)
        .map_err(AppError::BeaconClient)
}

/// Adapts the simnet validator mock into the abstract [`wire::SlotTickFn`] seam
/// so the core wiring stays decoupled from the mock type (mirrors
/// [`production_parsigex_seam`]).
///
/// The scheduler spawns slot callbacks detached, so the tick races `ct`: on
/// shutdown the in-flight `slot_ticked` HTTP work is dropped promptly instead
/// of outliving `run` until the mock client's timeout elapses.
fn simnet_slot_tick(vmock: Arc<ValidatorMock>, ct: CancellationToken) -> SlotTickFn {
    Arc::new(move |slot: &pluto_core::types::Slot| {
        let vmock = Arc::clone(&vmock);
        let ct = ct.clone();
        let slot = u64::from(slot.slot);
        Box::pin(async move {
            tokio::select! {
                biased;
                () = ct.cancelled() => Ok(()),
                res = vmock.slot_ticked(slot) => {
                    res.map_err(|e| AppError::Simnet(e.to_string()))
                }
            }
        })
    })
}

/// Normalizes the simnet slot duration to a whole number of seconds (minimum
/// 1s), warning when that rounds the requested value.
///
/// The beacon mock advertises `SECONDS_PER_SLOT` as an integer and every simnet
/// clock derives from it (the mock's head ticker, the scheduler, and the
/// validator mock), so a fractional duration would desync the mock's head from
/// its consumers. Truncating once here keeps them aligned.
fn normalize_simnet_slot_duration(configured: Duration) -> Duration {
    let secs = configured.as_secs().max(1);
    let normalized = Duration::from_secs(secs);
    if normalized != configured {
        tracing::warn!(
            requested = ?configured,
            normalized_secs = secs,
            "simnet slot duration rounded to whole seconds (SECONDS_PER_SLOT is integer)"
        );
    }
    normalized
}

/// Builds the in-process simnet beacon mock. Non-fuzz mode seeds the cluster's
/// distributed validators plus deterministic attester/proposer/sync-committee
/// duties; fuzz mode returns randomized responses. The returned mock owns its
/// HTTP server and slot ticker and must be held for the node's lifetime.
async fn build_simnet_beacon_mock(
    fork_version: &[u8],
    slot_duration: Duration,
    fuzz: bool,
    validators: &[ValidatorInfo],
) -> Result<BeaconMock, AppError> {
    let fork_version = <[u8; 4]>::try_from(fork_version).map_err(|_| {
        AppError::Simnet(format!(
            "cluster fork version must be 4 bytes, got {}",
            fork_version.len()
        ))
    })?;

    if fuzz {
        return BeaconMock::builder()
            .fuzzer(true)
            .fork_version(fork_version)
            .build()
            .await
            .map_err(|e| AppError::Simnet(format!("build fuzz beacon mock: {e}")));
    }

    let genesis_time = pluto_eth2util::network::fork_version_to_genesis_time(&fork_version)
        .map_err(|e| AppError::Simnet(format!("derive genesis time from fork version: {e}")))?;

    BeaconMock::builder()
        .validator_set(ValidatorSet::mock_dvs(
            validators.iter().map(|v| v.eth2_pubkey),
        ))
        .slot_duration(slot_duration)
        .genesis_time(genesis_time)
        .deterministic_attester_duties(SIMNET_DUTY_FACTOR)
        .deterministic_proposer_duties(SIMNET_DUTY_FACTOR)
        .deterministic_sync_comm_duties(SIMNET_SYNC_COMM_DUTIES)
        .build()
        .await
        .map_err(|e| AppError::Simnet(format!("build beacon mock: {e}")))
}

/// Builds the simnet validator mock: loads this node's BLS share secrets from
/// `keys_dir`, targets this node's own validator API over HTTP, and aligns to
/// the beacon mock's genesis so its scheduled duties line up with the node's
/// scheduler.
async fn build_simnet_validator_mock(
    keys_dir: &std::path::Path,
    validator_api_addr: std::net::SocketAddr,
    builder_api: bool,
    validators: &[ValidatorInfo],
    eth2_cl: &pluto_eth2api::EthBeaconNodeApiClient,
    slot_duration: Duration,
    slots_per_epoch: u64,
) -> Result<Arc<ValidatorMock>, AppError> {
    // Load this node's share secret keys from the keystore directory.
    let key_files = pluto_eth2util::keystore::load_files_unordered(keys_dir)
        .await
        .map_err(|e| {
            AppError::Simnet(format!(
                "load simnet validator keys from {}: {e}",
                keys_dir.display()
            ))
        })?;
    let secrets = key_files.keys();
    let signer =
        Signer::arc(&secrets).map_err(|e| AppError::Simnet(format!("build simnet signer: {e}")))?;

    // This node's per-DV public shares are the identities the mock signs for;
    // validate every share has a matching key.
    let pubshares: Vec<_> = validators.iter().map(|v| v.pubshare).collect();
    for (i, pubshare) in pubshares.iter().enumerate() {
        signer.sign(pubshare, b"test signing").map_err(|e| {
            AppError::Simnet(format!(
                "simnet validator key missing for share index {i}: {e}"
            ))
        })?;
    }

    // Genesis fetched from the (mock) beacon client; slot config supplied by the
    // caller (already fetched from the same client).
    let genesis_time = eth2_cl
        .fetch_genesis_time()
        .await
        .map_err(|e| AppError::Simnet(format!("fetch simnet genesis time: {e}")))?;
    let meta = SpecMeta {
        genesis_time: SystemTime::from(genesis_time),
        slot_duration,
        slots_per_epoch,
    };

    // The validator API may bind to an unspecified address (`0.0.0.0` / `[::]`);
    // that is a bind target, not a routable dial target (connecting to it is
    // unreliable). Dial loopback in that case, keeping the port.
    let vapi_dial = if validator_api_addr.ip().is_unspecified() {
        let loopback = match validator_api_addr.ip() {
            std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        };
        std::net::SocketAddr::new(loopback, validator_api_addr.port())
    } else {
        validator_api_addr
    };
    let vapi_url = format!("http://{vapi_dial}");
    let vapi_client = build_api_client(&vapi_url, SIMNET_VMOCK_TIMEOUT)?;

    Ok(Arc::new(
        ValidatorMock::builder()
            .eth2_cl(pluto_eth2api::BeaconNodeClient::new(vapi_client))
            .sign_func(signer)
            .pubkeys(pubshares)
            .meta(meta)
            .builder_api(builder_api)
            .build(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simnet_slot_duration_normalizes_to_whole_seconds() {
        // Zero and sub-second both floor up to the 1s minimum (a
        // `SECONDS_PER_SLOT` of 0 would break the consumers' slot-config parsing).
        assert_eq!(
            normalize_simnet_slot_duration(Duration::ZERO),
            Duration::from_secs(1)
        );
        assert_eq!(
            normalize_simnet_slot_duration(Duration::from_millis(500)),
            Duration::from_secs(1)
        );
        // Fractional durations truncate to whole seconds.
        assert_eq!(
            normalize_simnet_slot_duration(Duration::from_millis(1500)),
            Duration::from_secs(1)
        );
        assert_eq!(
            normalize_simnet_slot_duration(Duration::from_millis(2999)),
            Duration::from_secs(2)
        );
        // Whole seconds pass through unchanged.
        assert_eq!(
            normalize_simnet_slot_duration(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
    }

    // A failed validator-API bind must fail the run, not just log.
    #[tokio::test]
    async fn serve_validator_api_fails_when_addr_in_use() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = occupied.local_addr().expect("local addr");

        let err = serve_validator_api(addr, axum::Router::new(), CancellationToken::new())
            .await
            .expect_err("bind on an occupied port should fail");

        assert!(matches!(err, AppError::ValidatorApi(_)));
    }

    #[tokio::test]
    async fn serve_validator_api_shuts_down_gracefully_on_cancel() {
        let ct = CancellationToken::new();
        ct.cancel();

        // Graceful shutdown is a clean exit (Charon parity).
        serve_validator_api(
            "127.0.0.1:0".parse().expect("addr"),
            axum::Router::new(),
            ct,
        )
        .await
        .expect("cancelled serve should exit cleanly");
    }

    // A failed monitoring-API bind must fail the run too, tagged as a
    // monitoring (not validator API) error.
    #[tokio::test]
    async fn serve_monitoring_api_maps_bind_failure() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = occupied.local_addr().expect("local addr");

        let err = serve_monitoring_api(addr, axum::Router::new(), CancellationToken::new())
            .await
            .expect_err("bind on an occupied port should fail");

        assert!(matches!(err, AppError::MonitoringApi(_)));
    }

    // End-to-end: the wired monitoring server actually serves `/metrics`,
    // `/livez` and `/readyz` over real TCP — the path Prometheus scrapes.
    #[tokio::test]
    async fn monitoring_server_serves_all_routes_over_tcp() {
        // Reserve an ephemeral port, then release it so the server can bind it.
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral port");
            listener.local_addr().expect("local addr")
        };

        // A ready readiness state so `/readyz` returns 200, and a touched gauge
        // so `/metrics` has a series to expose.
        monitoringapi::MONITORING_METRICS.monitoring_readyz.set(1);
        let router = monitoringapi::router_with_state(monitoringapi::MonitoringState::new(
            monitoringapi::ReadyState::ready(),
        ));

        let ct = CancellationToken::new();
        let server = tokio::spawn(serve_monitoring_api(addr, router, ct.clone()));

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .expect("build client");
        let base = format!("http://{addr}");

        // Poll `/livez` until the server accepts connections (bounded).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let livez = loop {
            match client.get(format!("{base}/livez")).send().await {
                Ok(response) => break response,
                Err(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "monitoring server never came up"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        };
        assert_eq!(livez.status(), reqwest::StatusCode::OK);
        assert_eq!(livez.text().await.expect("livez body"), "ok");

        let readyz = client
            .get(format!("{base}/readyz"))
            .send()
            .await
            .expect("readyz request");
        assert_eq!(readyz.status(), reqwest::StatusCode::OK);

        let metrics = client
            .get(format!("{base}/metrics"))
            .send()
            .await
            .expect("metrics request");
        assert_eq!(metrics.status(), reqwest::StatusCode::OK);
        let content_type = metrics
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            content_type.contains("openmetrics-text"),
            "unexpected content-type: {content_type}"
        );
        assert!(
            metrics
                .text()
                .await
                .expect("metrics body")
                .contains("app_monitoring_readyz"),
            "metrics exposition missing readyz gauge"
        );

        ct.cancel();
        let _ = server.await;
    }

    // The default `BeaconMock` serves a Holesky fork schedule (genesis fork
    // version `0x01017000`).
    const HOLESKY_FORK_VERSION: [u8; 4] = [0x01, 0x01, 0x70, 0x00];
    const MAINNET_FORK_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

    // A lock on the same network as the beacon node passes the startup guard.
    #[tokio::test]
    async fn verify_fork_schedule_accepts_matching_network() {
        let mock = pluto_testutil::BeaconMock::builder()
            .build()
            .await
            .expect("beacon mock");

        verify_fork_schedule(mock.client(), &HOLESKY_FORK_VERSION)
            .await
            .expect("matching fork version should pass the startup guard");
    }

    // A lock on a different network than the beacon node fails the startup
    // guard, naming both the lock's fork version/network and the beacon node's
    // network (Charon `configureEth2Client`, app.go:1022-1053).
    #[tokio::test]
    async fn verify_fork_schedule_rejects_wrong_network() {
        let mock = pluto_testutil::BeaconMock::builder()
            .build()
            .await
            .expect("beacon mock");

        let err = verify_fork_schedule(mock.client(), &MAINNET_FORK_VERSION)
            .await
            .expect_err("mismatched fork version should fail the startup guard");

        match err {
            AppError::ForkScheduleMismatch {
                lock_network,
                lock_fork_version,
                beacon_node_network,
            } => {
                assert_eq!(lock_network, "mainnet");
                assert_eq!(lock_fork_version, "0x00000000");
                assert_eq!(beacon_node_network, "holesky");
            }
            other => panic!("expected ForkScheduleMismatch, got {other:?}"),
        }
    }
}
