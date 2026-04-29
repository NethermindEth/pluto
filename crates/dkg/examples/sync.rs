//! Example for the DKG sync protocol.
//!
//! To try it locally:
//!
//! ```text
//! # Data preparation: create a local 3-node cluster fixture
//! cargo run -p pluto-cli -- create cluster \
//!   --cluster-dir /tmp/pluto-sync-demo \
//!   --name sync-demo \
//!   --network holesky \
//!   --nodes 3 \
//!   --num-validators 1 \
//!   --insecure-keys \
//!   --fee-recipient-addresses 0x000000000000000000000000000000000000dead \
//!   --withdrawal-addresses 0x000000000000000000000000000000000000dead
//!
//! # Run in 3 terminals against the generated node directories
//! cargo run -p pluto-dkg --example sync -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir /tmp/pluto-sync-demo/node0
//!
//! cargo run -p pluto-dkg --example sync -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir /tmp/pluto-sync-demo/node1
//!
//! cargo run -p pluto-dkg --example sync -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir /tmp/pluto-sync-demo/node2
//! ```
//!
//! For stable local repros or CI-style runs, prefer a self-hosted relay
//! instead of shared public relays.
//!
//! What to expect:
//! - all nodes must use the same `--relays` value
//! - `Relay reservation accepted`
//! - `All sync clients connected`
//! - `Sync step reached`
//! - `Sync demo is now idling until Ctrl+C`
//! - press `Ctrl+C` on one node to stop it immediately and let the other nodes
//!   observe the fault

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use anyhow::{Context as _, Result};
use clap::Parser;
use futures::StreamExt;
use libp2p::{
    PeerId, identify, ping,
    relay::{self},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_cluster::lock::Lock;
use pluto_core::version::VERSION;
use pluto_dkg::sync::{self, Client, Server};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    bootnode,
    config::P2PConfig,
    gater, k1,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    relay::{MutableRelayReservation, RelayRouter},
};
use pluto_tracing::TracingConfig;
use tokio::{fs, signal, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

#[derive(NetworkBehaviour)]
struct ExampleBehaviour {
    relay: relay::client::Behaviour,
    relay_reservation: MutableRelayReservation,
    relay_router: RelayRouter,
    sync: sync::Behaviour,
}

#[derive(Debug, Parser)]
#[command(name = "sync-example")]
#[command(about = "Run a relay-based DKG sync demo node")]
struct Args {
    /// Relay URLs or relay multiaddrs to use.
    #[arg(long, value_delimiter = ',')]
    relays: Vec<String>,

    /// Data directory containing `charon-enr-private-key` and
    /// `cluster-lock.json`, typically one of the `nodeN/` directories produced
    /// by `pluto create cluster`.
    #[arg(long)]
    data_dir: PathBuf,

    /// Additional known peers to allow and route via relays.
    #[arg(long, value_delimiter = ',')]
    known_peers: Vec<String>,

    /// Whether to filter private addresses from advertisements.
    #[arg(short, long, default_value_t = false)]
    filter_private_addrs: bool,

    /// The external IP address of the node.
    #[arg(long)]
    external_ip: Option<String>,

    /// The external host of the node.
    #[arg(long)]
    external_host: Option<String>,

    /// TCP addresses to listen on.
    #[arg(long)]
    tcp_addrs: Vec<String>,

    /// UDP addresses to listen on.
    #[arg(long)]
    udp_addrs: Vec<String>,

    /// Whether to disable reuse port.
    #[arg(long, default_value_t = false)]
    disable_reuse_port: bool,
}

#[derive(Debug, Clone)]
struct ClusterInfo {
    peers: Vec<PeerId>,
    indices: HashMap<PeerId, usize>,
    local_peer_id: PeerId,
    local_node_number: u32,
}

impl ClusterInfo {
    fn expected_connections(&self) -> usize {
        self.peers.len().saturating_sub(1)
    }

    fn peer_label(&self, peer_id: &PeerId) -> String {
        match self.indices.get(peer_id) {
            Some(index) => format!("node={} peer_id={peer_id}", index.saturating_add(1)),
            None => format!("peer_id={peer_id}"),
        }
    }

    fn peer_labels_where(&self, predicate: impl Fn(&PeerId) -> bool) -> Vec<String> {
        self.peers
            .iter()
            .filter(|peer_id| predicate(peer_id))
            .map(|peer_id| self.peer_label(peer_id))
            .collect()
    }

    fn connected_peers(&self, connected: &HashSet<PeerId>) -> Vec<String> {
        self.peer_labels_where(|peer_id| connected.contains(peer_id))
    }

    fn missing_peers(&self, connected: &HashSet<PeerId>) -> Vec<String> {
        self.peer_labels_where(|peer_id| {
            *peer_id != self.local_peer_id && !connected.contains(peer_id)
        })
    }
}

fn peer_type(
    peer_id: &PeerId,
    relay_peer_ids: &HashSet<PeerId>,
    cluster_info: &ClusterInfo,
) -> &'static str {
    if relay_peer_ids.contains(peer_id) {
        "RELAY"
    } else if cluster_info.indices.contains_key(peer_id) {
        "CLUSTER"
    } else {
        "UNKNOWN"
    }
}

fn merge_known_peers(
    cluster_peers: &[PeerId],
    configured_known_peers: &[String],
) -> Result<Vec<PeerId>> {
    let capacity = cluster_peers
        .len()
        .checked_add(configured_known_peers.len())
        .context("known peer capacity overflow")?;
    let mut known_peers = Vec::with_capacity(capacity);
    known_peers.extend(cluster_peers.iter().copied());
    let mut known_peer_ids = HashSet::with_capacity(capacity);
    known_peer_ids.extend(known_peers.iter().copied());

    for peer in configured_known_peers {
        let peer_id = PeerId::from_str(peer)
            .with_context(|| format!("failed to parse known peer id: {peer}"))?;
        if known_peer_ids.insert(peer_id) {
            known_peers.push(peer_id);
        }
    }

    Ok(known_peers)
}

fn local_node_number(cluster_peers: &[PeerId], local_peer_id: PeerId) -> Result<u32> {
    let index = cluster_peers
        .iter()
        .position(|peer_id| peer_id == &local_peer_id)
        .context("local peer id is not present in the cluster lock")?;
    let node_number = index
        .checked_add(1)
        .context("cluster peer index overflow")?;
    u32::try_from(node_number).context("cluster peer index does not fit in u32")
}

fn endpoint_address(endpoint: &libp2p::core::ConnectedPoint) -> &libp2p::Multiaddr {
    match endpoint {
        libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
        libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    }
}

fn connection_log_fields<'a>(
    peer_id: PeerId,
    endpoint: &'a libp2p::core::ConnectedPoint,
    relay_peer_ids: &HashSet<PeerId>,
    cluster_info: &ClusterInfo,
) -> (String, &'static str, &'a libp2p::Multiaddr) {
    (
        cluster_info.peer_label(&peer_id),
        peer_type(&peer_id, relay_peer_ids, cluster_info),
        endpoint_address(endpoint),
    )
}

fn log_relay_event(relay_event: relay::client::Event, cluster_info: &ClusterInfo) {
    match relay_event {
        relay::client::Event::ReservationReqAccepted {
            relay_peer_id,
            renewal,
            limit,
        } => {
            info!(
                relay_peer_id = %relay_peer_id,
                renewal,
                limit = ?limit,
                "Relay reservation accepted"
            );
        }
        relay::client::Event::OutboundCircuitEstablished {
            relay_peer_id,
            limit,
        } => {
            debug!(
                relay_peer_id = %relay_peer_id,
                limit = ?limit,
                "Outbound relay circuit established"
            );
        }
        relay::client::Event::InboundCircuitEstablished { src_peer_id, limit } => {
            debug!(
                src_peer_id = %src_peer_id,
                peer_label = %cluster_info.peer_label(&src_peer_id),
                limit = ?limit,
                "Inbound relay circuit established"
            );
        }
    }
}

fn log_connection_established(
    peer_id: PeerId,
    endpoint: &libp2p::core::ConnectedPoint,
    num_established: std::num::NonZero<u32>,
    relay_peer_ids: &HashSet<PeerId>,
    cluster_info: &ClusterInfo,
) {
    let (peer_label, peer_type, address) =
        connection_log_fields(peer_id, endpoint, relay_peer_ids, cluster_info);
    debug!(
        peer_id = %peer_id,
        peer_label = %peer_label,
        peer_type,
        address = %address,
        num_established = num_established.get(),
        "Connection established"
    );
}

fn log_identify_event(
    peer_id: PeerId,
    info: identify::Info,
    relay_peer_ids: &HashSet<PeerId>,
    cluster_info: &ClusterInfo,
) {
    debug!(
        peer_id = %peer_id,
        peer_type = peer_type(&peer_id, relay_peer_ids, cluster_info),
        agent_version = %info.agent_version,
        protocol_version = %info.protocol_version,
        num_addresses = info.listen_addrs.len(),
        "Received identify from peer"
    );
}

fn log_ping_event(
    peer: PeerId,
    result: Result<Duration, ping::Failure>,
    relay_peer_ids: &HashSet<PeerId>,
    cluster_info: &ClusterInfo,
) {
    match result {
        Ok(rtt) => debug!(
            peer_id = %peer,
            peer_type = peer_type(&peer, relay_peer_ids, cluster_info),
            rtt = ?rtt,
            "Received ping"
        ),
        Err(error) => debug!(
            peer_id = %peer,
            peer_type = peer_type(&peer, relay_peer_ids, cluster_info),
            err = %error,
            "Ping failed"
        ),
    }
}

fn log_sync_event(event: sync::Event, cluster_info: &ClusterInfo) {
    match event {
        sync::Event::PeerStepUpdated { peer_id, step } => {
            debug!(
                peer_id = %peer_id,
                peer_label = %cluster_info.peer_label(&peer_id),
                step,
                "Sync peer step updated"
            );
        }
        sync::Event::PeerShutdownObserved { peer_id } => {
            debug!(
                peer_id = %peer_id,
                peer_label = %cluster_info.peer_label(&peer_id),
                "Sync peer shutdown observed"
            );
        }
        sync::Event::SyncRejected { peer_id, error } => {
            error!(
                peer_id = %peer_id,
                peer_label = %cluster_info.peer_label(&peer_id),
                err = %error,
                "Sync message rejected"
            );
        }
        sync::Event::PeerRttObserved { peer_id, rtt } => {
            debug!(
                peer_id = %peer_id,
                peer_label = %cluster_info.peer_label(&peer_id),
                rtt = ?rtt,
                "Sync RTT observed"
            );
        }
    }
}

fn print_cluster_overview(cluster_info: &ClusterInfo) {
    info!("Cluster peer order:");
    for (index, peer_id) in cluster_info.peers.iter().enumerate() {
        let local_marker = if *peer_id == cluster_info.local_peer_id {
            " (local)"
        } else {
            ""
        };
        info!(
            peer_index = index.checked_add(1).unwrap_or(index),
            peer_id = %peer_id,
            local = %local_marker,
            "Cluster peer"
        );
    }
}

async fn run_sync(
    server: Server,
    clients: Vec<Client>,
    cluster_info: ClusterInfo,
    cancellation: CancellationToken,
) -> Result<()> {
    server.start();
    info!(
        local_node = cluster_info.local_node_number,
        expected_clients = clients.len(),
        "Started sync server"
    );

    let mut client_joins = Vec::with_capacity(clients.len());
    for client in &clients {
        let client = client.clone();
        let cancellation = cancellation.child_token();
        client_joins.push(tokio::spawn(async move { client.run(cancellation).await }));
    }

    // First wait until all local per-peer sync clients report connected.
    // The shared server barrier below then confirms the whole cluster has
    // observed all peer connections.
    let mut previous_connected = None;
    loop {
        let connected = clients
            .iter()
            .filter(|client| client.is_connected())
            .count();
        if previous_connected != Some(connected) {
            info!(
                local_node = cluster_info.local_node_number,
                connected,
                expected = clients.len(),
                "Sync client connectivity update"
            );
            previous_connected = Some(connected);
        }

        if connected == clients.len() {
            break;
        }

        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    // Once all local sync clients are connected, wait for the shared server
    // to observe the full cluster barrier and then drive the demo through a
    // couple of synchronized steps.
    if !cancellation.is_cancelled() {
        info!(
            local_node = cluster_info.local_node_number,
            connected = clients.len(),
            "All sync clients connected"
        );

        for client in &clients {
            client.disable_reconnect();
        }

        match server.await_all_connected(cancellation.child_token()).await {
            Ok(()) | Err(sync::Error::Canceled) => {}
            Err(error) => return Err(anyhow::anyhow!(error.to_string())),
        }

        for step in 1_i64..=2 {
            for client in &clients {
                client.set_step(step);
            }
            info!(
                local_node = cluster_info.local_node_number,
                step, "Waiting for sync step"
            );
            match server
                .await_all_at_step(step, cancellation.child_token())
                .await
            {
                Ok(()) => {
                    info!(
                        local_node = cluster_info.local_node_number,
                        step, "Sync step reached"
                    );
                }
                Err(sync::Error::Canceled) => break,
                Err(error) => return Err(anyhow::anyhow!(error.to_string())),
            }

            if step < 2 {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                }
            }
        }
    }

    if !cancellation.is_cancelled() {
        info!(
            local_node = cluster_info.local_node_number,
            "Sync demo is now idling until Ctrl+C"
        );

        let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = heartbeat.tick() => {
                    let connected = clients.iter().filter(|client| client.is_connected()).count();
                    info!(
                        local_node = cluster_info.local_node_number,
                        connected,
                        expected = clients.len(),
                        "Sync steady-state heartbeat"
                    );
                }
            }
        }
    }

    if cancellation.is_cancelled() {
        info!(
            local_node = cluster_info.local_node_number,
            "Cancellation received, exiting without graceful shutdown"
        );
    }

    for join in client_joins {
        match join.await {
            Ok(Ok(())) | Ok(Err(sync::Error::Canceled)) => {}
            Ok(Err(error)) => return Err(anyhow::anyhow!(error.to_string())),
            Err(error) => return Err(anyhow::anyhow!(error.to_string())),
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    pluto_tracing::init(&TracingConfig::default()).expect("failed to initialize tracing");

    let args = Args::parse();
    let key = k1::load_priv_key(&args.data_dir).expect("Failed to load private key");
    let local_peer_id = pluto_p2p::peer::peer_id_from_key(key.public_key())
        .expect("Failed to derive local peer ID");

    let lock_path = args.data_dir.join("cluster-lock.json");
    let lock_str = fs::read_to_string(&lock_path)
        .await
        .expect("Failed to load lock");
    let lock: Lock = serde_json::from_str(&lock_str).expect("Failed to parse lock");

    let cluster_peers = lock.peer_ids().expect("Failed to get lock peer IDs");
    let local_node_number = local_node_number(&cluster_peers, local_peer_id)
        .expect("Failed to derive local node number");
    let mut indices = HashMap::with_capacity(cluster_peers.len());
    for (index, peer_id) in cluster_peers.iter().copied().enumerate() {
        indices.insert(peer_id, index);
    }
    let cluster_info = ClusterInfo {
        peers: cluster_peers.clone(),
        indices,
        local_peer_id,
        local_node_number,
    };

    let cancellation = CancellationToken::new();
    let definition_hash_hex = hex::encode(&lock.definition_hash);
    let relays = bootnode::new_relays(
        cancellation.child_token(),
        &args.relays,
        &definition_hash_hex,
    )
    .await
    .context("failed to resolve relays")?;
    let relay_peer_ids = relays
        .iter()
        .filter_map(|relay| relay.peer().ok().flatten().map(|peer| peer.id))
        .collect::<HashSet<_>>();

    let known_peers = merge_known_peers(&cluster_peers, &args.known_peers)?;

    let conn_gater = gater::ConnGater::new(
        gater::Config::closed()
            .with_relays(relays.clone())
            .with_peer_ids(known_peers.clone()),
    );
    let p2p_context = P2PContext::new(known_peers);

    let p2p_config = P2PConfig {
        relays: vec![],
        external_ip: args.external_ip,
        external_host: args.external_host,
        tcp_addrs: args.tcp_addrs,
        udp_addrs: args.udp_addrs,
        disable_reuse_port: args.disable_reuse_port,
    };

    let version = VERSION.to_minor();
    let sync_key = key.clone();
    let sync_definition_hash = lock.definition_hash.clone();
    let mut sync_runtime = None;

    let mut node: Node<ExampleBehaviour> = Node::new(
        p2p_config,
        key,
        NodeType::QUIC,
        args.filter_private_addrs,
        p2p_context,
        |builder, keypair, relay_client| {
            let p2p_context = builder.p2p_context();
            let local_peer_id = keypair.public().to_peer_id();

            let (sync_behaviour, server, clients) = sync::new(
                cluster_peers.clone(),
                p2p_context.clone(),
                &sync_key,
                sync_definition_hash.clone(),
                version.clone(),
            )
            .expect("sync example should initialize for a local cluster peer");
            sync_runtime = Some((server, clients));

            builder.with_gater(conn_gater).with_inner(ExampleBehaviour {
                relay: relay_client,
                relay_reservation: MutableRelayReservation::new(relays.clone()),
                relay_router: RelayRouter::new(relays.clone(), p2p_context, local_peer_id),
                sync: sync_behaviour,
            })
        },
    )?;
    let (server, clients) = sync_runtime.expect("sync runtime was not initialized");

    info!(
        local_peer_id = %local_peer_id,
        local_node = local_node_number,
        data_dir = %args.data_dir.display(),
        "Started sync example"
    );
    print_cluster_overview(&cluster_info);

    let mut connected_cluster_peers =
        HashSet::<PeerId>::with_capacity(cluster_info.expected_connections());
    let mut demo_task: JoinHandle<Result<()>> = tokio::spawn(run_sync(
        server,
        clients,
        cluster_info.clone(),
        cancellation.child_token(),
    ));

    loop {
        tokio::select! {
            event = node.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        ExampleBehaviourEvent::Relay(relay_event),
                    )) => {
                        log_relay_event(relay_event, &cluster_info);
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        ExampleBehaviourEvent::Sync(sync_event),
                    )) => {
                        log_sync_event(sync_event, &cluster_info);
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event {
                        peer,
                        result,
                        ..
                    })) => {
                        log_ping_event(peer, result, &relay_peer_ids, &cluster_info);
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) => {
                        log_identify_event(peer_id, info, &relay_peer_ids, &cluster_info);
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint,
                        num_established,
                        ..
                    } => {
                        log_connection_established(
                            peer_id,
                            &endpoint,
                            num_established,
                            &relay_peer_ids,
                            &cluster_info,
                        );
                        if cluster_info.indices.contains_key(&peer_id) {
                            connected_cluster_peers.insert(peer_id);
                            debug!(
                                connected = connected_cluster_peers.len(),
                                expected = cluster_info.expected_connections(),
                                connected_peers = ?cluster_info.connected_peers(&connected_cluster_peers),
                                missing_peers = ?cluster_info.missing_peers(&connected_cluster_peers),
                                "Cluster connectivity update"
                            );
                        }
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        cause,
                        ..
                    } if cluster_info.indices.contains_key(&peer_id)
                        && connected_cluster_peers.remove(&peer_id) =>
                    {
                        error!(
                            local_node = cluster_info.local_node_number,
                            peer_id = %peer_id,
                            peer_label = %cluster_info.peer_label(&peer_id),
                            connected = connected_cluster_peers.len(),
                            expected = cluster_info.expected_connections(),
                            missing_peers = ?cluster_info.missing_peers(&connected_cluster_peers),
                            cause = ?cause,
                            "Cluster peer disconnected"
                        );
                    }
                    SwarmEvent::OutgoingConnectionError {
                        peer_id,
                        connection_id,
                        error: err,
                    } => {
                        debug!(
                            ?peer_id,
                            ?connection_id,
                            %err,
                            "Outgoing connection error"
                        );
                    }
                    SwarmEvent::IncomingConnectionError {
                        connection_id,
                        local_addr,
                        send_back_addr,
                        error: err,
                        ..
                    } => {
                        debug!(
                            ?connection_id,
                            %local_addr,
                            %send_back_addr,
                            %err,
                            "Incoming connection error"
                        );
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        debug!(%address, "Listening on address");
                    }
                    _ => {}
                }
            }
            result = &mut demo_task => {
                match result {
                    Ok(Ok(())) => {
                        info!("Sync demo completed successfully");
                        break;
                    }
                    Ok(Err(error)) => {
                        error!(err = %error, "Sync demo failed");
                        break;
                    }
                    Err(error) => {
                        error!(err = %error, "Sync demo task failed");
                        break;
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down");
                cancellation.cancel();
            }
        }
    }

    cancellation.cancel();
    Ok(())
}
