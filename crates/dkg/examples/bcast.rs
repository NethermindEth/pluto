//! Example for the DKG reliable-broadcast protocol.
//!
//! To try it locally:
//!
//! ```text
//! # Data preparation: create a local 3-node cluster fixture
//! cargo run -p pluto-cli -- create cluster \
//!   --cluster-dir /tmp/pluto-bcast-demo \
//!   --name bcast-demo \
//!   --network holesky \
//!   --nodes 3 \
//!   --num-validators 1 \
//!   --insecure-keys \
//!   --fee-recipient-addresses 0x000000000000000000000000000000000000dead \
//!   --withdrawal-addresses 0x000000000000000000000000000000000000dead
//!
//! # Run in 3 terminals against the generated node directories
//! cargo run -p pluto-dkg --example bcast -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir /tmp/pluto-bcast-demo/node0
//!
//! cargo run -p pluto-dkg --example bcast -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir /tmp/pluto-bcast-demo/node1
//!
//! cargo run -p pluto-dkg --example bcast -- \
//!   --relays https://0.relay.obol.tech,https://1.relay.obol.tech \
//!   --data-dir /tmp/pluto-bcast-demo/node2
//! ```
//!
//! For stable local repros or CI-style runs, prefer a self-hosted relay
//! instead of shared public relays.
//!
//! What to expect:
//! - all nodes must use the same `--relays` value
//! - `Relay reservation accepted`
//! - `Sending broadcast`
//! - `Received signature request`
//! - `Received broadcast`
//!
//! The demo uses a single fixed message ID because `bcast` is intended for
//! one-shot protocol-step messages, not a changing heartbeat stream.

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
use pluto_dkg::bcast::{self, Component};
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
use prost::Name;
use tokio::{fs, signal};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

const DEMO_MSG_ID: &str = "demo.tick";

#[derive(NetworkBehaviour)]
struct ExampleBehaviour {
    relay: relay::client::Behaviour,
    relay_reservation: MutableRelayReservation,
    relay_router: RelayRouter,
    bcast: bcast::Behaviour,
}

#[derive(Debug, Parser)]
#[command(name = "bcast-example")]
#[command(about = "Run a relay-based DKG bcast demo node")]
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
            Some(index) => format!(
                "node={} peer_id={peer_id}",
                index.checked_add(1).unwrap_or(*index)
            ),
            None => format!("peer_id={peer_id}"),
        }
    }

    fn peer_labels_where<F>(&self, mut predicate: F) -> Vec<String>
    where
        F: FnMut(&PeerId) -> bool,
    {
        self.peers
            .iter()
            .filter(|peer_id| predicate(peer_id))
            .map(|peer_id| self.peer_label(peer_id))
            .collect()
    }

    fn recipients_description(&self) -> String {
        self.peer_labels_where(|peer_id| *peer_id != self.local_peer_id)
            .join(", ")
    }

    fn missing_peers(&self, connected_cluster_peers: &HashSet<PeerId>) -> Vec<String> {
        self.peer_labels_where(|peer_id| {
            *peer_id != self.local_peer_id && !connected_cluster_peers.contains(peer_id)
        })
    }

    fn connected_peers(&self, connected_cluster_peers: &HashSet<PeerId>) -> Vec<String> {
        self.peer_labels_where(|peer_id| connected_cluster_peers.contains(peer_id))
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct DemoTick {
    #[prost(uint32, tag = "1")]
    node_index: u32,
    #[prost(int64, tag = "2")]
    timestamp_seconds: i64,
}

impl Name for DemoTick {
    const NAME: &'static str = "DemoTick";
    const PACKAGE: &'static str = "dkg.example";

    fn full_name() -> String {
        "dkg.example.DemoTick".to_string()
    }

    fn type_url() -> String {
        "type.googleapis.com/dkg.example.DemoTick".to_string()
    }
}

fn now_unix_seconds() -> Result<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before unix epoch")?;
    i64::try_from(duration.as_secs()).context("unix timestamp does not fit in i64")
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

fn endpoint_address(endpoint: &libp2p::core::ConnectedPoint) -> &libp2p::Multiaddr {
    match endpoint {
        libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
        libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    }
}

fn connection_log_fields<'a>(
    peer_id: &'a PeerId,
    endpoint: &'a libp2p::core::ConnectedPoint,
    relay_peer_ids: &'a HashSet<PeerId>,
    cluster_info: &'a ClusterInfo,
) -> (&'a libp2p::Multiaddr, String, &'static str) {
    let address = endpoint_address(endpoint);
    let peer_label = cluster_info.peer_label(peer_id);
    let peer_type = peer_type(peer_id, relay_peer_ids, cluster_info);

    (address, peer_label, peer_type)
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

fn merge_known_peers(
    cluster_peers: &[PeerId],
    configured_known_peers: &[String],
) -> Result<Vec<PeerId>> {
    let mut known_peers = cluster_peers.to_vec();
    let mut known_peer_ids = known_peers.iter().copied().collect::<HashSet<_>>();

    for peer in configured_known_peers {
        let peer_id = PeerId::from_str(peer)
            .with_context(|| format!("failed to parse known peer id: {peer}"))?;
        if known_peer_ids.insert(peer_id) {
            known_peers.push(peer_id);
        }
    }

    Ok(known_peers)
}

async fn register_message(component: &Component, local_node_number: u32) -> bcast::Result<()> {
    component
        .register_message::<DemoTick>(
            DEMO_MSG_ID,
            Box::new(move |peer_id, msg| {
                info!(
                    local_node = local_node_number,
                    sender = %peer_id,
                    msg_id = DEMO_MSG_ID,
                    msg = ?msg,
                    "Received signature request"
                );
                Ok(())
            }),
            Box::new(move |peer_id, received_msg_id, msg| {
                Box::pin(async move {
                    info!(
                        local_node = local_node_number,
                        sender = %peer_id,
                        msg_id = received_msg_id,
                        msg = ?msg,
                        "Received broadcast"
                    );
                    Ok(())
                })
            }),
        )
        .await
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

async fn maybe_start_broadcast(
    broadcast_started: &mut bool,
    component: &Component,
    cluster_info: &ClusterInfo,
    connected_cluster_peers: &HashSet<PeerId>,
) -> Result<()> {
    if *broadcast_started || connected_cluster_peers.len() != cluster_info.expected_connections() {
        return Ok(());
    }

    info!(
        connected = connected_cluster_peers.len(),
        expected = cluster_info.expected_connections(),
        "All cluster peers connected, starting demo bcast"
    );
    let msg = DemoTick {
        node_index: cluster_info.local_node_number,
        timestamp_seconds: now_unix_seconds()?,
    };
    info!(
        local_node = cluster_info.local_node_number,
        msg_id = DEMO_MSG_ID,
        recipients = %cluster_info.recipients_description(),
        msg = ?msg,
        "Sending broadcast"
    );

    match component.broadcast(DEMO_MSG_ID, &msg).await {
        Ok(()) => {
            *broadcast_started = true;
            Ok(())
        }
        Err(error) => {
            error!(
                local_node = cluster_info.local_node_number,
                msg_id = DEMO_MSG_ID,
                err = %error,
                "Failed to enqueue broadcast"
            );
            Ok(())
        }
    }
}

fn log_bcast_event(event: bcast::Event, local_node_number: u32) {
    match event {
        bcast::Event::BroadcastCompleted { msg_id } => {
            info!(
                local_node = local_node_number,
                msg_id, "Broadcast completed"
            );
        }
        bcast::Event::BroadcastFailed {
            msg_id,
            error: event_error,
        } => {
            error!(
                local_node = local_node_number,
                msg_id,
                err = %event_error,
                "Broadcast failed"
            );
        }
    }
}

fn log_cluster_connectivity(cluster_info: &ClusterInfo, connected_cluster_peers: &HashSet<PeerId>) {
    let connected = cluster_info.connected_peers(connected_cluster_peers);
    let missing = cluster_info.missing_peers(connected_cluster_peers);
    debug!(
        connected = connected_cluster_peers.len(),
        expected = cluster_info.expected_connections(),
        connected_peers = ?connected,
        missing_peers = ?missing,
        "Cluster connectivity update"
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
        Err(error) => warn!(
            peer_id = %peer,
            peer_type = peer_type(&peer, relay_peer_ids, cluster_info),
            err = %error,
            "Ping failed"
        ),
    }
}

fn log_connection_established(
    peer_id: PeerId,
    endpoint: &libp2p::core::ConnectedPoint,
    num_established: std::num::NonZero<u32>,
    relay_peer_ids: &HashSet<PeerId>,
    cluster_info: &ClusterInfo,
) {
    let (address, peer_label, peer_type) =
        connection_log_fields(&peer_id, endpoint, relay_peer_ids, cluster_info);
    info!(
        peer_id = %peer_id,
        peer_label = %peer_label,
        peer_type,
        address = %address,
        num_established = num_established.get(),
        "Connection established"
    );
}

fn log_connection_closed(
    peer_id: PeerId,
    endpoint: &libp2p::core::ConnectedPoint,
    num_established: u32,
    cause: Option<&libp2p::swarm::ConnectionError>,
    relay_peer_ids: &HashSet<PeerId>,
    cluster_info: &ClusterInfo,
) {
    let (address, peer_label, peer_type) =
        connection_log_fields(&peer_id, endpoint, relay_peer_ids, cluster_info);
    warn!(
        peer_id = %peer_id,
        peer_label = %peer_label,
        peer_type,
        address = %address,
        num_established,
        cause = ?cause,
        "Connection closed"
    );
}

fn log_relay_event(relay_event: relay::client::Event, cluster_info: &ClusterInfo) {
    match relay_event {
        relay::client::Event::ReservationReqAccepted {
            relay_peer_id,
            renewal,
            limit,
        } => {
            debug!(
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
    let indices = cluster_peers
        .iter()
        .copied()
        .enumerate()
        .map(|(index, peer_id)| (peer_id, index))
        .collect::<HashMap<_, _>>();
    let cluster_info = ClusterInfo {
        peers: cluster_peers.clone(),
        indices,
        local_peer_id,
        local_node_number,
    };

    let cancellation = CancellationToken::new();
    let lock_hash_hex = hex::encode(&lock.lock_hash);
    let relays = bootnode::new_relays(cancellation.child_token(), &args.relays, &lock_hash_hex)
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

    let p2p_config = P2PConfig {
        relays: vec![],
        external_ip: args.external_ip,
        external_host: args.external_host,
        tcp_addrs: args.tcp_addrs,
        udp_addrs: args.udp_addrs,
        disable_reuse_port: args.disable_reuse_port,
    };

    let p2p_context = P2PContext::new(known_peers.clone());
    let mut component = None;
    let mut node: Node<ExampleBehaviour> = Node::new(
        p2p_config,
        key.clone(),
        NodeType::QUIC,
        args.filter_private_addrs,
        p2p_context,
        |builder, keypair, relay_client| {
            let p2p_context = builder.p2p_context();
            let local_peer_id = keypair.public().to_peer_id();

            let (bcast_behaviour, c) =
                bcast::Behaviour::new(cluster_peers.clone(), p2p_context.clone(), key.clone());
            component = Some(c);

            builder.with_gater(conn_gater).with_inner(ExampleBehaviour {
                relay: relay_client,
                relay_reservation: MutableRelayReservation::new(relays.clone()),
                relay_router: RelayRouter::new(relays.clone(), p2p_context, local_peer_id),
                bcast: bcast_behaviour,
            })
        },
    )?;

    let component = component.expect("BCast component was not initialized");
    register_message(&component, local_node_number)
        .await
        .expect("Failed to register demo bcast message");

    info!(
        local_peer_id = %local_peer_id,
        local_node = local_node_number,
        data_dir = %args.data_dir.display(),
        msg_id = DEMO_MSG_ID,
        "Started relay-based bcast example"
    );
    print_cluster_overview(&cluster_info);

    let mut connected_cluster_peers = HashSet::<PeerId>::new();
    let mut broadcast_started = false;

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
                        ExampleBehaviourEvent::Bcast(bcast_event),
                    )) => {
                        log_bcast_event(bcast_event, local_node_number);
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
                        if cluster_info.indices.contains_key(&peer_id) && peer_id != local_peer_id {
                            connected_cluster_peers.insert(peer_id);
                            log_cluster_connectivity(&cluster_info, &connected_cluster_peers);
                            maybe_start_broadcast(
                                &mut broadcast_started,
                                &component,
                                &cluster_info,
                                &connected_cluster_peers,
                            )
                            .await?;
                        }
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        endpoint,
                        num_established,
                        cause,
                        ..
                    } => {
                        log_connection_closed(
                            peer_id,
                            &endpoint,
                            num_established,
                            cause.as_ref(),
                            &relay_peer_ids,
                            &cluster_info,
                        );
                        if connected_cluster_peers.remove(&peer_id) {
                            log_cluster_connectivity(&cluster_info, &connected_cluster_peers);
                        }
                    }
                    SwarmEvent::OutgoingConnectionError {
                        peer_id,
                        connection_id,
                        error: dial_error,
                    } => {
                        error!(
                            peer_id = ?peer_id,
                            connection_id = ?connection_id,
                            err = %dial_error,
                            "Outgoing connection error"
                        );
                    }
                    SwarmEvent::IncomingConnectionError {
                        connection_id,
                        local_addr,
                        send_back_addr,
                        error: incoming_error,
                        ..
                    } => {
                        warn!(
                            connection_id = ?connection_id,
                            local_addr = %local_addr,
                            send_back_addr = %send_back_addr,
                            err = %incoming_error,
                            "Incoming connection error"
                        );
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(address = %address, "Listening on address");
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        warn!(address = %address, "Listen address expired");
                    }
                    _ => {}
                }
            }
            _ = signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down");
                cancellation.cancel();
                break;
            }
        }
    }

    Ok(())
}
