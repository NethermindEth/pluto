//! Peerinfo example
//!
//! See the [README](./README.md) for usage instructions.
#![allow(missing_docs)]
use std::{
    collections::HashMap,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use clap::Parser;
use libp2p::{
    Multiaddr,
    futures::StreamExt,
    identify, mdns, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_cluster::lock::Lock;
use pluto_core::version::{VERSION, git_commit};
use pluto_p2p::{
    behaviours::pluto::{PlutoBehaviour, PlutoBehaviourEvent},
    config::P2PConfig,
    k1,
    name::peer_name,
    p2p::{Node, NodeType},
};
use pluto_peerinfo::{Behaviour, Config, Event, LocalPeerInfo};
use pluto_tracing::{LokiConfig, TracingConfig};
use tokio::signal;
use vise::MetricsCollection;
use vise_exporter::MetricsExporter;

/// Command line arguments
#[derive(Debug, Parser)]
#[command(name = "peerinfo-example")]
#[command(about = "Demonstrates the peerinfo protocol with mDNS discovery")]
pub struct Args {
    /// The port to listen on
    #[arg(short, long, default_value = "4001")]
    pub port: u16,

    /// Addresses to dial (multiaddr format, e.g., /ip4/127.0.0.1/tcp/3610). Can
    /// be specified multiple times.
    #[arg(short, long)]
    pub dial: Vec<Multiaddr>,

    /// Nickname for this node
    #[arg(short, long, default_value = "example-node")]
    pub nickname: String,

    /// Peer info exchange interval in seconds
    #[arg(short, long, default_value = "5")]
    pub interval: u64,

    /// Data directory for storing the private key and cluster lock
    #[arg(long)]
    pub data_dir: PathBuf,

    /// Metrics port to bind to
    #[arg(long, default_value = "9465")]
    pub metrics_port: u16,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Loki URL for log aggregation (e.g., http://localhost:3100)
    #[arg(long)]
    pub loki_url: Option<String>,

    /// Additional Loki labels in key=value format (can be specified multiple
    /// times)
    #[arg(long = "loki-label", value_parser = parse_key_value)]
    pub loki_labels: Vec<(String, String)>,
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid key=value format: {}", s));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Combined behaviour with peerinfo, relay client, and mdns.
///
/// Note: identify and ping are handled by PlutoBehaviour which wraps this.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "CombinedBehaviourEvent")]
pub struct CombinedBehaviour {
    pub peer_info: Behaviour,
    pub relay: relay::client::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

/// Events from the combined behaviour.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum CombinedBehaviourEvent {
    PeerInfo(Event),
    Relay(relay::client::Event),
    Mdns(mdns::Event),
}

impl From<Event> for CombinedBehaviourEvent {
    fn from(event: Event) -> Self {
        CombinedBehaviourEvent::PeerInfo(event)
    }
}

impl From<relay::client::Event> for CombinedBehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        CombinedBehaviourEvent::Relay(event)
    }
}

impl From<mdns::Event> for CombinedBehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        CombinedBehaviourEvent::Mdns(event)
    }
}

pub type FullEvent = PlutoBehaviourEvent<CombinedBehaviour>;

fn handle_event(event: SwarmEvent<FullEvent>, node: &mut Node<CombinedBehaviour>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::info!("Listening on {address}");
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            tracing::info!(
                "Connection established with {peer_id} via {}",
                endpoint.get_remote_address()
            );
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            tracing::info!("Connection closed with {peer_id}: {cause:?}");
        }
        SwarmEvent::Behaviour(FullEvent::Inner(CombinedBehaviourEvent::PeerInfo(
            Event::Received { peer, info, .. },
        ))) => {
            tracing::info!(
                "Received PeerInfo from {peer}:\n\
                 │  Version: {}\n\
                 │  Git Hash: {}\n\
                 │  Nickname: {}\n\
                 │  Builder API: {}\n\
                 │  Lock Hash: {:?}",
                info.pluto_version,
                info.git_hash,
                info.nickname,
                info.builder_api_enabled,
                hex::encode(&info.lock_hash),
            );
        }
        SwarmEvent::Behaviour(FullEvent::Inner(CombinedBehaviourEvent::PeerInfo(
            Event::Error { peer, error, .. },
        ))) => {
            tracing::warn!("PeerInfo error with {peer}: {error}");
        }
        SwarmEvent::Behaviour(FullEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            tracing::debug!(
                "Identify received from {peer_id}: {} {}",
                info.protocol_version,
                info.agent_version
            );
        }
        SwarmEvent::Behaviour(FullEvent::Ping(ping::Event { peer, result, .. })) => match result {
            Ok(rtt) => tracing::debug!("Ping to {peer}: {rtt:?}"),
            Err(e) => tracing::debug!("Ping to {peer} failed: {e}"),
        },
        SwarmEvent::Behaviour(FullEvent::Inner(CombinedBehaviourEvent::Mdns(
            mdns::Event::Discovered(peers),
        ))) => {
            for (peer_id, addr) in peers {
                tracing::info!("mDNS discovered peer {peer_id} at {addr}");
                if let Err(e) = node.dial(addr) {
                    tracing::warn!("Failed to dial discovered peer: {e}");
                }
            }
        }
        SwarmEvent::Behaviour(FullEvent::Inner(CombinedBehaviourEvent::Mdns(
            mdns::Event::Expired(peers),
        ))) => {
            for (peer_id, addr) in peers {
                tracing::debug!("mDNS peer expired: {peer_id} at {addr}");
            }
        }
        SwarmEvent::IncomingConnection { local_addr, .. } => {
            tracing::debug!("Incoming connection on {local_addr}");
        }
        _ => {}
    }
}

fn build_tracing_config(args: &Args) -> TracingConfig {
    let mut builder = TracingConfig::builder()
        .with_default_console()
        .override_env_filter(&args.log_level);

    if let Some(loki_url) = &args.loki_url {
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert("app".to_string(), "peerinfo-example".to_string());
        labels.insert("nickname".to_string(), args.nickname.clone());

        // Add user-provided labels
        for (key, value) in &args.loki_labels {
            labels.insert(key.clone(), value.clone());
        }

        builder = builder.loki(LokiConfig {
            loki_url: loki_url.clone(),
            labels,
            extra_fields: HashMap::new(),
        });
    }

    builder.build()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing with optional Loki support
    let tracing_config = build_tracing_config(&args);
    let loki_task = pluto_tracing::init(&tracing_config)?;

    // Spawn Loki background task if configured
    if let Some(task) = loki_task {
        tokio::spawn(task);
        tracing::info!("Loki logging enabled");
    }

    // Load existing key or create a new one
    let key = match k1::load_priv_key(&args.data_dir) {
        Ok(key) => {
            tracing::info!(
                "Loaded existing private key from {}",
                args.data_dir.display()
            );
            key
        }
        Err(err) => {
            tracing::error!(
                "Failed to load private key from {}",
                args.data_dir.display()
            );
            anyhow::bail!("Failed to load private key: {err}")
        }
    };

    let enr = pluto_eth2util::enr::Record::new(
        key.clone(),
        vec![
            pluto_eth2util::enr::with_ip_impl(Ipv4Addr::from([0, 0, 0, 0])),
            pluto_eth2util::enr::with_tcp_impl(args.port),
            pluto_eth2util::enr::with_udp_impl(args.port),
        ],
    )?;

    tracing::info!("ENR: {}", enr);

    // Run the metrics exporter
    let bind_address = SocketAddr::from(([0, 0, 0, 0], args.metrics_port));

    // Load cluster lock from data_dir/cluster-lock.json
    let lock_path = args.data_dir.join("cluster-lock.json");
    let lock: Option<Lock> = if lock_path.exists() {
        let lock_json = fs::read_to_string(&lock_path)?;
        let lock: Lock = serde_json::from_str(&lock_json)?;
        tracing::info!(
            "Loaded cluster lock from {}: {} peers, lock_hash: {}",
            lock_path.display(),
            lock.operators.len(),
            hex::encode(&lock.lock_hash)
        );
        Some(lock)
    } else {
        tracing::warn!(
            "No lock file found at {}, using default values",
            lock_path.display()
        );
        None
    };

    let lock_hash = lock
        .as_ref()
        .map(|l| l.lock_hash.clone())
        .unwrap_or(vec![0x00, 0x00, 0x00, 0x00]);
    let peers = lock
        .as_ref()
        .map(|l| l.peer_ids())
        .transpose()?
        .unwrap_or_default();

    // Create local peer info
    let (git_hash, _) = git_commit();
    let local_info = LocalPeerInfo::new(
        VERSION.to_string(),
        lock_hash.clone(),
        &git_hash,
        false,
        &args.nickname,
    );

    let interval = Duration::from_secs(args.interval);

    // Build the node
    // No known cluster peers in this example
    let known_peers: Vec<libp2p::PeerId> = vec![];
    let mut node = Node::new(
        P2PConfig::default(),
        key,
        NodeType::TCP,
        false,
        known_peers,
        PlutoBehaviour::builder(),
        |_global_context, keypair, relay_client| {
            let peer_id = keypair.public().to_peer_id();
            CombinedBehaviour {
                peer_info: Behaviour::new(
                    peer_id,
                    Config::new(local_info.clone())
                        .with_peers(peers.clone())
                        .with_interval(interval),
                ),
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                    .expect("Failed to create mDNS behaviour"),
                relay: relay_client,
            }
        },
    )?;

    let local_peer_id = *node.local_peer_id();
    tracing::info!("Local peer id: {local_peer_id}");
    tracing::info!("mDNS auto-discovery enabled");

    let cluster_peer = peer_name(&local_peer_id);

    let cluster_name = lock.as_ref().map(|l| l.name.clone()).unwrap_or_default();

    // Setup metrics exporter with real data
    // cluster_hash uses first 7 hex chars (or less if shorter)
    let cluster_hash_hex7 = {
        let h = hex::encode(&lock_hash);
        if h.len() <= 7 { h } else { h[..7].to_string() }
    };
    let metrics_collection = MetricsCollection::default().with_labels([
        ("charon_version", VERSION.to_string()),
        ("cluster_hash", cluster_hash_hex7),
        ("cluster_name", cluster_name),
        ("cluster_network", "mainnet".to_string()),
        ("cluster_peer", cluster_peer),
        ("nickname", args.nickname.clone()),
    ]);

    let exporter = MetricsExporter::new(metrics_collection.collect().into())
        .bind(bind_address)
        .await
        .expect("Failed to bind metrics exporter");

    tokio::spawn(async move {
        exporter
            .start()
            .await
            .expect("Failed to start metrics exporter");
    });

    // Listen on the specified port
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?;
    node.listen_on(listen_addr)?;

    // Dial the specified addresses
    for dial_addr in &args.dial {
        tracing::info!("Dialing {dial_addr}");
        node.dial(dial_addr.clone())?;
    }

    tracing::info!(
        "Peerinfo example started with nickname '{}', interval {}s",
        args.nickname,
        args.interval
    );
    tracing::info!("Press Ctrl+C to exit");

    // Main event loop
    loop {
        tokio::select! {
            event = node.select_next_some() => handle_event(event, &mut node),
            _ = signal::ctrl_c() => {
                tracing::info!("Received Ctrl+C, shutting down...");
                break;
            }
        }
    }

    Ok(())
}
