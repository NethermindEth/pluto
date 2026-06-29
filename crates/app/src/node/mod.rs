//! Distributed-validator node wiring.
//!
//! This module is the Rust analog of Charon's `app/app.go`: it constructs every
//! core duty-workflow component, connects them together (the analog of Charon's
//! `core.Wire`), composes the P2P behaviours, and runs the node until
//! cancelled.
//!
//! The work is split to mirror Charon's `Run` (loads config/lock/keys, sets up
//! P2P) vs `wireCoreWorkflow` (constructs and wires the components):
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

use std::sync::{Arc, OnceLock};

use futures::StreamExt;
use pluto_consensus::qbft;
use pluto_core::gater::DutyGaterFn;
use pluto_p2p::peer::Peer;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use behaviour::{CoreBehaviour, CoreHandles};
use wire::{ParSigExSeam, ValidatorInfo, WireInputs, WiredComponents, wire_core_workflow};

/// Errors raised while constructing or running a distributed-validator node.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Failed to load the cluster lock file.
    #[error("read cluster lock {path}: {source}")]
    LoadLock {
        /// Lock file path.
        path: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to deserialize the cluster lock file.
    #[error("parse cluster lock: {0}")]
    ParseLock(#[source] serde_json::Error),

    /// Failed to derive cluster peers from the lock.
    #[error("cluster definition: {0}")]
    Definition(#[from] pluto_cluster::definition::DefinitionError),

    /// Failed to read distributed-validator data from the lock.
    #[error("distributed validator: {0}")]
    DistValidator(#[from] pluto_cluster::distvalidator::DistValidatorError),

    /// A distributed validator's public key was not 48 bytes.
    #[error("distributed validator pubkey is not 48 bytes")]
    InvalidValidatorPubKey,

    /// Failed to load the P2P private key.
    #[error("load p2p key: {0}")]
    LoadKey(#[from] pluto_k1util::K1UtilError),

    /// The local P2P key does not match any cluster operator.
    #[error("local peer not found in cluster lock")]
    LocalPeerNotFound,

    /// P2P peer derivation/verification failed.
    #[error("p2p peer: {0}")]
    Peer(#[from] pluto_p2p::peer::PeerError),

    /// P2P node construction failed.
    #[error("p2p node: {0}")]
    P2P(#[from] pluto_p2p::p2p::P2PError),

    /// QBFT consensus construction failed.
    #[error("consensus: {0}")]
    Consensus(#[from] qbft::Error),

    /// QBFT p2p adapter construction failed.
    #[error("consensus p2p: {0}")]
    ConsensusP2P(#[from] qbft::p2p::Error),

    /// Beacon node client construction failed.
    #[error("beacon client: {0}")]
    BeaconClient(String),

    /// Signature aggregator construction failed.
    #[error("sigagg: {0}")]
    SigAgg(#[source] pluto_core::sigagg::SigAggError),

    /// Broadcaster construction failed.
    #[error("broadcaster: {0}")]
    Broadcaster(#[source] pluto_core::bcast::Error),

    /// Scheduler construction failed.
    #[error("scheduler: {0}")]
    Scheduler(#[source] pluto_core::scheduler::SchedulerError),

    /// Validator API server failed.
    #[error("validator api: {0}")]
    ValidatorApi(#[source] std::io::Error),
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
    ///
    /// This is the Rust analog of Charon's `app.Run`.
    pub async fn run(self, ct: CancellationToken) -> Result<(), AppError> {
        run(self.config, ct).await
    }
}

/// Loads the cluster lock + key, builds the consensus component and P2P
/// behaviours, wires the core workflow, and drives the node.
async fn run(config: AppConfig, ct: CancellationToken) -> Result<(), AppError> {
    // ---- (1) Load cluster lock + key, derive peers and this node's index ----
    let lock = load_lock(&config.lock_file).await?;
    let threshold = lock.threshold;
    let target_gas_limit = lock.target_gas_limit;
    let _ = target_gas_limit; // TODO(#402 part B): thread into validatorapi target gas limit.

    let key = pluto_k1util::load(&config.priv_key_file)?;
    let peers = lock.peers()?;
    pluto_p2p::peer::verify_p2p_key(&peers, &key)?;

    let local_peer_id = pluto_p2p::peer::peer_id_from_key(key.public_key())?;
    let local_node = peers
        .iter()
        .find(|p| p.id == local_peer_id)
        .ok_or(AppError::LocalPeerNotFound)?;
    let local_idx = local_node.index;
    let share_idx = local_node.share_idx();

    // qbft peers (secp256k1 pubkeys, in process-index order).
    let qbft_peers = build_qbft_peers(&peers)?;

    // Per-validator data for this node (mirrors app.go:415-452).
    let validators = build_validators(&lock, share_idx)?;

    // ---- (2/3) eth2 clients ----
    let eth2_cl = build_api_client(
        config
            .beacon_node_addrs
            .first()
            .map(String::as_str)
            .unwrap_or_default(),
        config.beacon_node_timeout,
    )?;
    let beacon_client = pluto_eth2api::BeaconNodeClient::new(eth2_cl.clone());
    // TODO(#402 part B): honor `beacon_node_submit_timeout` distinctly; a
    // separate submission client is built with the submit timeout here.
    let submission_api = build_api_client(
        config
            .beacon_node_addrs
            .first()
            .map(String::as_str)
            .unwrap_or_default(),
        config.beacon_node_submit_timeout,
    )?;
    let submission_client = pluto_eth2api::BeaconNodeClient::new(submission_api);

    // Duty admission gate.
    //
    // TODO(#402 part B): use `DutyGater::new(&eth2_cl).await?.into_fn()` (Charon's
    // `core.NewDutyGater`) which validates against the beacon chain; the minimal
    // wiring admits any structurally-valid duty type.
    let duty_gater: DutyGaterFn = Arc::new(|duty| duty.duty_type.is_valid());

    // ---- Consensus (built directly; shared with p2p behaviour + core stitch) ----
    //
    // TODO(#402 part B): wrap in ConsensusController for dynamic protocol
    // switching (priority/infosync).
    //
    // Resolve the broadcaster<->behaviour construction cycle with the
    // `Arc<OnceLock<Handle>>` pattern (see qbft::p2p `build_consensus_nodes`).
    let consensus_deadliner = pluto_core::deadline::DeadlinerTask::start(
        ct.clone(),
        "consensus.qbft",
        pluto_core::deadline::NeverExpiringCalculator,
    );
    let (cons_deadliner, cons_expired_rx) = consensus_deadliner;

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
        // Charon gates this on the `ChainSplitHalt` featureset flag, which is
        // alpha (off by default).
        // TODO(#402 part B): thread the featureset flag through instead of `false`.
        compare_attestations: false,
        timer_func: pluto_consensus::timer::get_round_timer_func(),
    })?);

    // ---- P2P behaviours (parsigex + qbft + peerinfo) ----
    let (node, handles) = behaviour::wire_p2p(
        key.clone(),
        config.p2p.clone(),
        peers,
        Arc::clone(&consensus),
        Arc::clone(&duty_gater),
        lock.lock_hash.clone(),
        config.builder_api,
        config.nickname.clone(),
        ct.clone(),
    )?;
    // Complete the broadcaster<->behaviour cycle.
    handle_slot
        .set(handles.consensus.clone())
        .map_err(|_| AppError::ConsensusP2P(qbft::p2p::Error::BehaviourClosed))?;

    // ---- Wire the core workflow ----
    let upstream_url = config
        .beacon_node_addrs
        .first()
        .and_then(|addr| reqwest::Url::parse(addr).ok())
        .unwrap_or_else(|| reqwest::Url::parse("http://127.0.0.1:5052").expect("valid url"));

    let parsigex_seam = production_parsigex_seam(&handles);

    let wired = wire_core_workflow(
        WireInputs {
            threshold,
            share_idx,
            beacon_client,
            eth2_cl,
            submission_client,
            validators,
            consensus: Arc::clone(&consensus),
            builder_enabled: config.builder_api,
            upstream_url,
            parsigex: parsigex_seam,
        },
        Arc::clone(&duty_gater),
        ct.clone(),
    )
    .await?;

    // ---- Lifecycle: spawn long-lived tasks ----
    run_lifecycle(
        node,
        consensus,
        handles,
        wired,
        config.validator_api_addr,
        ct,
    )
    .await
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
                    .map_err(|e| AppError::BeaconClient(e.to_string()))
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
async fn run_lifecycle(
    node: pluto_p2p::p2p::Node<CoreBehaviour>,
    consensus: Arc<qbft::Consensus>,
    _handles: CoreHandles,
    wired: WiredComponents,
    validator_api_addr: std::net::SocketAddr,
    ct: CancellationToken,
) -> Result<(), AppError> {
    let WiredComponents {
        scheduler: _scheduler,
        dutydb,
        parsigdb,
        parsigdb_deadliner_rx,
        aggsigdb: _aggsigdb,
        fetcher: _fetcher,
        validator_api_router,
    } = wired;

    // Self-spawning actor: consensus expired-duty pruner.
    let _consensus_task = consensus.start(ct.clone());

    let mut tasks: JoinSet<()> = JoinSet::new();

    // Swarm drive loop (push-based routing inside behaviours).
    tasks.spawn(drive_network(node, ct.clone()));

    // ParSigDB trim task.
    {
        let parsigdb = Arc::clone(&parsigdb);
        tasks.spawn(async move {
            parsigdb.trim(parsigdb_deadliner_rx).await;
        });
    }

    // Validator API axum server.
    {
        let ct = ct.clone();
        tasks.spawn(async move {
            match tokio::net::TcpListener::bind(validator_api_addr).await {
                Ok(listener) => {
                    let serve = axum::serve(listener, validator_api_router)
                        .with_graceful_shutdown(async move { ct.cancelled().await });
                    if let Err(err) = serve.await {
                        tracing::error!(?err, "validator api server");
                    }
                }
                Err(err) => {
                    tracing::error!(?err, %validator_api_addr, "validator api bind");
                }
            }
        });
    }

    // Supervise: stop on cancellation or first task completion.
    tokio::select! {
        () = ct.cancelled() => {
            tracing::info!("node: cancellation requested");
        }
        _ = tasks.join_next() => {
            tracing::warn!("node: a long-lived task exited; shutting down");
            ct.cancel();
        }
    }

    // ---- Ordered shutdown ----
    // Brief drain for in-flight tasks.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.shutdown().await;

    // Stop dutydb (cancels its child token).
    dutydb.shutdown();

    Ok(())
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

/// Loads and deserializes a cluster [`Lock`](pluto_cluster::lock::Lock) from
/// disk.
async fn load_lock(path: &std::path::Path) -> Result<pluto_cluster::lock::Lock, AppError> {
    let buf = tokio::fs::read_to_string(path)
        .await
        .map_err(|source| AppError::LoadLock {
            path: path.display().to_string(),
            source,
        })?;
    // TODO(#402 part B): honor `no_verify`/`manifest_file`; verify lock hashes +
    // signatures (`lock.verify_hashes()` / `lock.verify_signatures(...)`).
    serde_json::from_str(&buf).map_err(AppError::ParseLock)
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

        let fee_recipient = fee_recipients
            .get(i)
            .and_then(|s| parse_execution_address(s))
            .unwrap_or_default();

        out.push(ValidatorInfo {
            pubkey,
            eth2_pubkey,
            pubshare,
            fee_recipient,
        });
    }
    Ok(out)
}

/// Parses a `0x`-prefixed hex execution address.
fn parse_execution_address(s: &str) -> Option<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
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
        .map_err(|e| AppError::BeaconClient(e.to_string()))?;
    pluto_eth2api::EthBeaconNodeApiClient::with_client(base_url, http)
        .map_err(|e| AppError::BeaconClient(e.to_string()))
}
