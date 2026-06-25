//! QBFT libp2p example.
//!
//! This example runs one QBFT node per terminal over the real Pluto libp2p
//! stack and the concrete `consensus::qbft::p2p` adapter. By default it runs
//! five sequential synthetic attester duties starting at `--slot` and prints
//! `-------------` after each local decision.
//!
//! Create a cluster first:
//!
//! ```text
//! cargo run -p pluto-cli -- create cluster \
//!   --cluster-dir /tmp/pluto-qbft-demo \
//!   --name qbft-demo \
//!   --network holesky \
//!   --nodes 4 \
//!   --threshold 3 \
//!   --num-validators 1 \
//!   --insecure-keys \
//!   --fee-recipient-addresses 0x000000000000000000000000000000000000dead \
//!   --withdrawal-addresses 0x000000000000000000000000000000000000dead
//! ```
//!
//! Then run one command per terminal:
//!
//! ```text
//! cargo run -p pluto-consensus --example qbft -- \
//!   --relays https://pluto-relay-0.ovh.dev-nethermind.xyz,https://pluto-relay-1.ovh.dev-nethermind.xyz \
//!   --data-dir /tmp/pluto-qbft-demo/node0
//! cargo run -p pluto-consensus --example qbft -- \
//!   --relays https://pluto-relay-0.ovh.dev-nethermind.xyz,https://pluto-relay-1.ovh.dev-nethermind.xyz \
//!   --data-dir /tmp/pluto-qbft-demo/node1
//! cargo run -p pluto-consensus --example qbft -- \
//!   --relays https://pluto-relay-0.ovh.dev-nethermind.xyz,https://pluto-relay-1.ovh.dev-nethermind.xyz \
//!   --data-dir /tmp/pluto-qbft-demo/node2
//! cargo run -p pluto-consensus --example qbft -- \
//!   --relays https://pluto-relay-0.ovh.dev-nethermind.xyz,https://pluto-relay-1.ovh.dev-nethermind.xyz \
//!   --data-dir /tmp/pluto-qbft-demo/node3
//! ```
//!
//! # Flow
//!
//! 1. **Load fixture** (`load_fixture`): reads the node's
//!    `charon-enr-private-key` and `cluster-lock.json` from `--data-dir`,
//!    derives the cluster peer IDs, locates this node's index, and builds the
//!    consensus peer set (secp256k1 public keys from each operator ENR).
//! 2. **Wire consensus** (`build_consensus`): constructs a `qbft::Consensus`
//!    with an attester-only duty gater, an `IncreasingRoundTimer`, a
//!    `DemoDeadline`, and a broadcaster that queues outbound messages for the
//!    main event loop to forward through the QBFT libp2p handle. Decided values
//!    are forwarded to a channel via `Consensus::subscribe`, and the
//!    expired-duty cleanup loop is spawned.
//! 3. **Build the libp2p node**: an `ExampleBehaviour` combining the relay
//!    client, `RelayManager`, mDNS, and the `qbft::p2p::Behaviour`, gated to
//!    the configured relays and cluster peers.
//! 4. **Connect**: cluster peers are reached over relays and/or mDNS; the event
//!    loop tracks established cluster connections and waits until
//!    `--start-after-peers` (default: all other peers) are connected.
//! 5. **Run duties sequentially**: for each of `--duties` synthetic attester
//!    duties starting at `--slot`, the round-1 leader calls
//!    `Consensus::propose` with a synthetic value while every other node calls
//!    `Consensus::participate`. QBFT runs over the p2p adapter; on local
//!    decision the subscriber prints the decided value followed by
//!    `-------------`, then the next duty starts.
//! 6. **Shut down**: after the last duty decides, the swarm is kept alive for
//!    `COMPLETION_DRAIN` so slower peers can still receive the final messages,
//!    then the process exits. `ctrl-c`, parent cancellation, or the
//!    `--timeout-secs` start deadline also stop the loop.

use std::{
    collections::{BTreeMap, HashSet},
    convert::Infallible,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail};
use chrono::{TimeDelta, Utc};
use clap::Parser;
use futures::StreamExt as _;
use libp2p::{
    PeerId, mdns,
    relay::{self},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_cluster::lock::Lock;
use pluto_consensus::{
    qbft,
    timer::{IncreasingRoundTimer, RoundTimer},
};
use pluto_core::{
    corepb::v1::{consensus as pbconsensus, core as pbcore},
    deadline::{DeadlineCalculator, DeadlinerTask},
    types::{Duty, DutyType, SlotNumber},
};
use pluto_eth2util::enr::Record;
use pluto_featureset::FeatureSet;
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    bootnode,
    config::P2PConfig,
    gater, k1,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
    relay::{RelayManager, RelayManagerEvent},
};
use pluto_tracing::TracingConfig;
use prost::bytes::Bytes;
use tokio::{fs, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

const COMPLETION_DRAIN: Duration = Duration::from_secs(2);

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ExampleBehaviourEvent")]
struct ExampleBehaviour {
    relay: relay::client::Behaviour,
    relay_manager: RelayManager,
    mdns: mdns::tokio::Behaviour,
    qbft: qbft::p2p::Behaviour,
}

#[derive(Debug)]
enum ExampleBehaviourEvent {
    Relay(relay::client::Event),
    RelayManager(RelayManagerEvent),
    Mdns(mdns::Event),
    Qbft(qbft::p2p::Event),
}

impl From<relay::client::Event> for ExampleBehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<RelayManagerEvent> for ExampleBehaviourEvent {
    fn from(event: RelayManagerEvent) -> Self {
        Self::RelayManager(event)
    }
}

impl From<mdns::Event> for ExampleBehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        Self::Mdns(event)
    }
}

impl From<qbft::p2p::Event> for ExampleBehaviourEvent {
    fn from(event: qbft::p2p::Event) -> Self {
        Self::Qbft(event)
    }
}

impl From<Infallible> for ExampleBehaviourEvent {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

#[derive(Debug, Parser)]
#[command(name = "qbft-example")]
#[command(about = "Run one relay/local-discovery QBFT demo node")]
struct Args {
    /// Directory holding `charon-enr-private-key` and `cluster-lock.json`.
    #[arg(long)]
    data_dir: PathBuf,

    /// Relay URLs or relay multiaddrs.
    #[arg(long, value_delimiter = ',')]
    relays: Vec<String>,

    /// TCP listen addresses.
    #[arg(long, value_delimiter = ',', default_value = "0.0.0.0:0")]
    tcp_addrs: Vec<String>,

    /// UDP listen addresses used for QUIC.
    #[arg(long, value_delimiter = ',', default_value = "0.0.0.0:0")]
    udp_addrs: Vec<String>,

    /// Whether to filter private addresses from advertisements.
    #[arg(long, default_value_t = false)]
    filter_private_addrs: bool,

    /// External IP address to advertise.
    #[arg(long)]
    external_ip: Option<String>,

    /// External hostname to advertise.
    #[arg(long)]
    external_host: Option<String>,

    /// Whether to disable socket reuse-port.
    #[arg(long, default_value_t = false)]
    disable_reuse_port: bool,

    /// Duty slot used by the synthetic attester value.
    #[arg(long, default_value_t = 1)]
    slot: u64,

    /// Number of sequential synthetic duties to run.
    #[arg(long, default_value_t = 5)]
    duties: u64,

    /// Connected cluster peers required before starting QBFT.
    #[arg(long)]
    start_after_peers: Option<usize>,

    /// Maximum time to wait for connections and decision.
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,

    /// Tracing filter for example logs.
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Debug)]
struct Decision {
    duty: Duty,
    value: pbcore::UnsignedDataSet,
}

struct DutyRun {
    duties: Vec<Duty>,
    index: usize,
    started: bool,
    decided: bool,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl DutyRun {
    fn new(duties: Vec<Duty>) -> Self {
        Self {
            duties,
            index: 0,
            started: false,
            decided: false,
            task: None,
        }
    }

    fn current(&self) -> Option<&Duty> {
        self.duties.get(self.index)
    }

    fn is_complete(&self) -> bool {
        self.index == self.duties.len()
    }

    fn try_start(
        &mut self,
        component: &Arc<qbft::Consensus>,
        fixture: &Fixture,
        connected_peer_count: usize,
        start_after: usize,
        cancel: CancellationToken,
    ) {
        if self.started || self.is_complete() || connected_peer_count < start_after {
            return;
        }

        let duty = self
            .current()
            .expect("incomplete duty run has duty")
            .clone();
        let leader_node = leader_index(&duty, fixture.peer_ids.len());
        let local_node = fixture.local_index;
        info!(
            node = local_node,
            duty_index = self.index.checked_add(1).expect("duty index increments"),
            duty_count = self.duties.len(),
            duty = %duty,
            leader = leader_node,
            "starting duty"
        );

        self.started = true;
        self.task = Some(start_consensus_for_node(
            Arc::clone(component),
            fixture,
            duty,
            cancel,
        ));
    }

    fn mark_decided(&mut self, duty: &Duty) -> bool {
        if self.current() != Some(duty) {
            return false;
        }

        self.decided = true;
        true
    }

    fn clear_task(&mut self) {
        self.task = None;
    }

    fn advance_if_ready(&mut self) -> bool {
        if !self.decided || self.task.is_some() {
            return false;
        }

        self.index = self.index.checked_add(1).expect("duty index increments");
        self.started = false;
        self.decided = false;
        true
    }
}

struct DemoDeadline {
    timeout: Duration,
}

impl DeadlineCalculator for DemoDeadline {
    fn deadline(
        &self,
        _duty: &Duty,
    ) -> pluto_core::deadline::Result<Option<chrono::DateTime<Utc>>> {
        let delta = TimeDelta::from_std(self.timeout)
            .map_err(|_| pluto_core::deadline::DeadlineError::DurationConversion)?;
        Ok(Some(Utc::now().checked_add_signed(delta).ok_or(
            pluto_core::deadline::DeadlineError::DateTimeCalculation,
        )?))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    pluto_tracing::init(
        &TracingConfig::builder()
            .with_default_console()
            .override_env_filter(&args.log_level)
            .build(),
    )?;

    let timeout = Duration::from_secs(args.timeout_secs);
    let duties = build_duties(args.slot, args.duties)?;
    let first_duty = duties.first().expect("duty count is non-zero");
    let fixture = load_fixture(&args).await?;
    let local_node = fixture.local_index;
    let leader = leader_index(first_duty, fixture.peer_ids.len());
    let leader_node = leader;

    let cancel = CancellationToken::new();
    let relays = bootnode::new_relays(
        cancel.child_token(),
        &args.relays,
        &hex::encode(&fixture.lock_hash),
    )
    .await
    .context("resolve relays")?;
    let conn_gater = gater::ConnGater::new(
        gater::Config::closed()
            .with_relays(relays.clone())
            .with_peer_ids(fixture.peer_ids.clone()),
    );
    let p2p_context = P2PContext::new(fixture.peer_ids.iter().copied());

    let (decision_tx, mut decision_rx) = mpsc::unbounded_channel();
    let (mut broadcast_rx, broadcaster) = queued_broadcaster();
    let (consensus, lifecycle_task) = build_consensus(
        &fixture,
        timeout,
        cancel.child_token(),
        broadcaster,
        decision_tx,
    )?;
    let (qbft_behaviour, handle) = qbft::p2p::Behaviour::new(qbft::p2p::Config {
        consensus: Arc::clone(&consensus),
        p2p_context: p2p_context.clone(),
        local_peer_id: fixture.peer_ids[fixture.local_index],
        cancellation: cancel.child_token(),
    })?;

    let p2p_config = P2PConfig {
        relays: vec![],
        external_ip: args.external_ip.clone(),
        external_host: args.external_host.clone(),
        tcp_addrs: args.tcp_addrs.clone(),
        udp_addrs: args.udp_addrs.clone(),
        disable_reuse_port: args.disable_reuse_port,
    };
    let mut node: Node<ExampleBehaviour> = Node::new(
        p2p_config,
        fixture.key.clone(),
        NodeType::QUIC,
        args.filter_private_addrs,
        p2p_context,
        |builder, keypair, relay_client| {
            let local_peer_id = keypair.public().to_peer_id();
            let p2p_context = builder.p2p_context();
            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                .expect("mDNS should initialize");
            builder.with_gater(conn_gater).with_inner(ExampleBehaviour {
                relay: relay_client,
                relay_manager: RelayManager::new(relays.clone(), p2p_context),
                mdns,
                qbft: qbft_behaviour,
            })
        },
    )?;

    info!(
        node = local_node,
        peer_id = %node.local_peer_id(),
        duties = duties.len(),
        first_duty = %first_duty,
        first_leader = leader_node,
        "QBFT example started"
    );
    info!(peers = %peer_list(&fixture.peer_ids), "cluster peers");

    let start_after = args
        .start_after_peers
        .unwrap_or_else(|| fixture.peer_ids.len().saturating_sub(1));
    let mut connected_cluster_peers = HashSet::<PeerId>::new();
    let mut duty_run = DutyRun::new(duties);
    let mut completion_drain = None;
    let start_deadline = tokio::time::sleep(timeout);
    tokio::pin!(start_deadline);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!(node = local_node, "ctrl-c received");
                break;
            }
            _ = cancel.cancelled() => break,
            _ = async {
                match &mut completion_drain {
                    Some(sleep) => sleep.await,
                    None => std::future::pending().await,
                }
            } => {
                break;
            }
            result = async {
                match &mut duty_run.task {
                    Some(task) => task.await.context("consensus task join")?,
                    None => std::future::pending::<Result<()>>().await,
                }
            }, if duty_run.task.is_some() => {
                result?;
                duty_run.clear_task();
                if duty_run.advance_if_ready() && duty_run.is_complete() {
                    info!(node = local_node, "all duties decided");
                    // Keep libp2p alive briefly so slower peers can receive
                    // final duty messages before this demo process exits.
                    completion_drain = Some(Box::pin(tokio::time::sleep(COMPLETION_DRAIN)));
                }
                duty_run.try_start(
                    &consensus,
                    &fixture,
                    connected_cluster_peers.len(),
                    start_after,
                    cancel.child_token(),
                );
            }
            Some(decision) = decision_rx.recv() => {
                if duty_run.mark_decided(&decision.duty) {
                    info!(
                        node = local_node,
                        duty = %decision.duty,
                        entries = %format_value(&decision.value),
                        "decided"
                    );
                    info!("-------------");
                    if duty_run.advance_if_ready() && duty_run.is_complete() {
                        info!(node = local_node, "all duties decided");
                        // Keep libp2p alive briefly so slower peers can receive
                        // final duty messages before this demo process exits.
                        completion_drain = Some(Box::pin(tokio::time::sleep(COMPLETION_DRAIN)));
                    }
                    duty_run.try_start(
                        &consensus,
                        &fixture,
                        connected_cluster_peers.len(),
                        start_after,
                        cancel.child_token(),
                    );
                } else {
                    debug!(
                        node = local_node,
                        duty = %decision.duty,
                        "ignoring out-of-order decision"
                    );
                }
            }
            Some(msg) = broadcast_rx.recv() => {
                handle
                    .broadcast(msg)
                    .await
                    .map_err(|error| anyhow!("broadcast QBFT message: {error}"))?;
            }
            event = node.select_next_some() => {
                handle_swarm_event(
                    event,
                    &fixture,
                    &mut node,
                    &mut connected_cluster_peers,
                )?;
                duty_run.try_start(
                    &consensus,
                    &fixture,
                    connected_cluster_peers.len(),
                    start_after,
                    cancel.child_token(),
                );
            }
            _ = &mut start_deadline, if !duty_run.started && !duty_run.is_complete() => {
                bail!("timeout waiting for enough peers to start QBFT");
            }
        }
    }

    cancel.cancel();
    if let Some(task) = duty_run.task {
        tokio::time::timeout(timeout, task)
            .await
            .context("timeout waiting for consensus task to stop")?
            .context("consensus task join")??;
    }
    lifecycle_task.await?;
    info!(node = local_node, "QBFT example stopped");

    Ok(())
}

struct Fixture {
    key: k256::SecretKey,
    peer_ids: Vec<PeerId>,
    local_index: usize,
    consensus_peers: Vec<qbft::Peer>,
    lock_hash: Vec<u8>,
}

async fn load_fixture(args: &Args) -> Result<Fixture> {
    let key = k1::load_priv_key(&args.data_dir)
        .with_context(|| format!("load private key from {}", args.data_dir.display()))?;
    let local_peer_id =
        peer_id_from_key(key.public_key()).context("derive local peer ID from private key")?;
    let lock_path = args.data_dir.join("cluster-lock.json");
    let lock_str = fs::read_to_string(&lock_path)
        .await
        .with_context(|| format!("read {}", lock_path.display()))?;
    let lock: Lock = serde_json::from_str(&lock_str)
        .with_context(|| format!("parse {}", lock_path.display()))?;
    let peer_ids = lock.peer_ids().context("derive peer IDs from lock")?;
    let Some(local_index) = peer_ids
        .iter()
        .position(|peer_id| *peer_id == local_peer_id)
    else {
        bail!("local peer ID {local_peer_id} not found in cluster lock");
    };
    let consensus_peers = lock
        .operators
        .iter()
        .enumerate()
        .map(|(index, operator)| {
            let record = Record::try_from(operator.enr.as_str()).context("parse operator ENR")?;
            let public_key = record
                .public_key
                .context("operator ENR missing public key")?;
            Ok(qbft::Peer {
                index: i64::try_from(index)?,
                name: format!("node-{index}"),
                public_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Fixture {
        key,
        peer_ids,
        local_index,
        consensus_peers,
        lock_hash: lock.lock_hash,
    })
}

// Return the consensus component for p2p admission/propose/participate calls
// and the cleanup task so main can join it during shutdown.
fn build_consensus(
    fixture: &Fixture,
    timeout: Duration,
    cancel: CancellationToken,
    broadcaster: qbft::Broadcaster,
    decision_tx: mpsc::UnboundedSender<Decision>,
) -> Result<(Arc<qbft::Consensus>, tokio::task::JoinHandle<()>)> {
    let (deadliner, expired_rx) = DeadlinerTask::start(
        cancel.child_token(),
        format!("qbft-example-node-{}", fixture.local_index),
        DemoDeadline { timeout },
    );
    let local_node = fixture.local_index;
    let feature_set = Arc::new(FeatureSet::new());
    let timer_feature_set = feature_set.clone();
    let component = Arc::new(qbft::Consensus::new(qbft::Config {
        peers: fixture.consensus_peers.clone(),
        local_peer_idx: i64::try_from(fixture.local_index)?,
        privkey: fixture.key.clone(),
        deadliner,
        expired_rx,
        duty_gater: Arc::new(|duty| duty.duty_type == DutyType::Attester),
        broadcaster,
        sniffer: Arc::new(move |instance| {
            info!(
                node = local_node,
                messages = instance.msgs.len(),
                "sniffed consensus"
            );
        }),
        compare_attestations: false,
        timer_func: Box::new(move |duty| {
            Box::new(IncreasingRoundTimer::with_duty(
                duty,
                timer_feature_set.clone(),
            )) as Box<dyn RoundTimer>
        }),
        feature_set,
    })?);
    component.subscribe(move |decision_duty, value| {
        let _ = decision_tx.send(Decision {
            duty: decision_duty,
            value,
        });
        Ok(())
    });
    let lifecycle_task = component.start(cancel.child_token());

    Ok((component, lifecycle_task))
}

/// Returns a broadcaster that queues outbound messages and the receiver that
/// main forwards through the p2p handle after the behaviour is built.
fn queued_broadcaster() -> (
    mpsc::UnboundedReceiver<pbconsensus::QbftConsensusMsg>,
    qbft::Broadcaster,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let broadcaster: qbft::Broadcaster = Arc::new(move |_ct, msg| {
        let tx = tx.clone();
        Box::pin(async move {
            tx.send(msg).map_err(|_| {
                let err = std::io::Error::other("qbft outbound queue closed");
                Box::new(err) as Box<dyn std::error::Error + Send + Sync>
            })
        })
    });

    (rx, broadcaster)
}

fn handle_swarm_event(
    event: SwarmEvent<PlutoBehaviourEvent<ExampleBehaviour>>,
    fixture: &Fixture,
    node: &mut Node<ExampleBehaviour>,
    connected_cluster_peers: &mut HashSet<PeerId>,
) -> Result<()> {
    let local_node = fixture.local_index;
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            debug!(node = local_node, %address, "listen address");
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            if fixture.peer_ids.contains(&peer_id)
                && peer_id != fixture.peer_ids[fixture.local_index]
                && connected_cluster_peers.insert(peer_id)
            {
                info!(
                    node = local_node,
                    peer = %peer_id,
                    connected = connected_cluster_peers.len(),
                    expected = fixture.peer_ids.len().saturating_sub(1),
                    "connected cluster peer"
                );
            }
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(ExampleBehaviourEvent::Mdns(
            mdns::Event::Discovered(peers),
        ))) => {
            for (peer_id, addr) in peers {
                if fixture.peer_ids.contains(&peer_id)
                    && peer_id != fixture.peer_ids[fixture.local_index]
                {
                    debug!(node = local_node, peer = %peer_id, address = %addr, "mDNS discovered cluster peer");
                    node.dial(addr)?;
                }
            }
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(ExampleBehaviourEvent::RelayManager(
            event,
        ))) => {
            debug!(node = local_node, ?event, "relay manager event");
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(ExampleBehaviourEvent::Relay(event))) => {
            debug!(node = local_node, ?event, "relay event");
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(ExampleBehaviourEvent::Qbft(event))) => {
            log_qbft_event(local_node, event);
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            debug!(node = local_node, peer = ?peer_id, %error, "outgoing connection error");
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            debug!(node = local_node, %error, "incoming connection error");
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(_))
        | SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(_))
        | SwarmEvent::Behaviour(PlutoBehaviourEvent::Autonat(_))
        | SwarmEvent::Behaviour(PlutoBehaviourEvent::ConnLogger(_))
        | SwarmEvent::Behaviour(PlutoBehaviourEvent::Gater(_))
        | SwarmEvent::Behaviour(PlutoBehaviourEvent::QuicUpgrade(_))
        | SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(ExampleBehaviourEvent::Mdns(_))) => {}
        _ => debug!(node = local_node, ?event, "swarm event"),
    }

    Ok(())
}

fn start_consensus_for_node(
    component: Arc<qbft::Consensus>,
    fixture: &Fixture,
    duty: Duty,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<Result<()>> {
    let local_node = fixture.local_index;
    let leader = leader_index(&duty, fixture.peer_ids.len());
    if fixture.local_index == leader {
        let slot = duty.slot.inner();
        info!(node = local_node, "proposing value");
        tokio::spawn(async move {
            component
                .propose(duty, demo_value(local_node, slot), &cancel)
                .await
                .map_err(|error| anyhow!(error))
        })
    } else {
        info!(node = local_node, "participating");
        tokio::spawn(async move {
            component
                .participate(duty, &cancel)
                .await
                .map_err(|error| anyhow!(error))
        })
    }
}

fn log_qbft_event(local_node: usize, event: qbft::p2p::Event) {
    match event {
        qbft::p2p::Event::BroadcastQueued {
            request_id,
            target_count,
        } => {
            debug!(
                node = local_node,
                request_id, target_count, "QBFT broadcast queued"
            );
        }
        qbft::p2p::Event::Received { peer, .. } => {
            debug!(node = local_node, peer = %peer, "QBFT message received");
        }
        qbft::p2p::Event::Sent { request_id, peer } => {
            debug!(node = local_node, request_id, peer = %peer, "QBFT message sent");
        }
        qbft::p2p::Event::SendError {
            request_id,
            peer,
            error,
        } => {
            debug!(node = local_node, request_id, peer = %peer, %error, "QBFT send error");
        }
        qbft::p2p::Event::InboundError { peer, error, .. } => {
            debug!(node = local_node, peer = %peer, %error, "QBFT inbound error");
        }
    }
}

fn leader_index(duty: &Duty, nodes: usize) -> usize {
    let nodes = i128::try_from(nodes).expect("node count fits i128");
    let duty_type = i32::try_from(&duty.duty_type).expect("duty type maps to i32");
    let total = i128::from(duty.slot.inner())
        .checked_add(i128::from(duty_type))
        .and_then(|value| value.checked_add(1))
        .expect("slot, duty type, and round fit i128");
    usize::try_from(total.rem_euclid(nodes)).expect("leader index fits usize")
}

fn build_duties(start_slot: u64, count: u64) -> Result<Vec<Duty>> {
    if count == 0 {
        bail!("--duties must be greater than zero");
    }

    (0..count)
        .map(|offset| {
            let slot = start_slot
                .checked_add(offset)
                .context("slot overflow while building duties")?;
            Ok(Duty::new_attester_duty(SlotNumber::new(slot)))
        })
        .collect()
}

fn demo_value(node: usize, slot: u64) -> pbcore::UnsignedDataSet {
    let mut set = BTreeMap::new();
    set.insert(
        "demo-validator".to_string(),
        Bytes::from(format!("qbft-demo-slot-{slot}-node-{node}")),
    );
    pbcore::UnsignedDataSet { set }
}

fn peer_list(peers: &[PeerId]) -> String {
    peers
        .iter()
        .enumerate()
        .map(|(index, peer_id)| format!("node-{index}={peer_id}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_value(value: &pbcore::UnsignedDataSet) -> String {
    value
        .set
        .iter()
        .map(|(key, value)| format!("{key}={}", String::from_utf8_lossy(value)))
        .collect::<Vec<_>>()
        .join(",")
}
