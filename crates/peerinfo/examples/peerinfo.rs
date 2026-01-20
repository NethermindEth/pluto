//! Peerinfo example
//!
//! This example demonstrates the peerinfo protocol by creating two nodes
//! that exchange peer information with each other using mDNS auto-discovery.
//!
//! Run with:
//! ```sh
//! cargo run --example peerinfo -p charon-peerinfo
//! ```
//!
//! Run two instances on different ports - they will auto-discover each other:
//!
//! Terminal 1: `cargo run --example peerinfo -p charon-peerinfo -- --port 4001`
//! Terminal 2: `cargo run --example peerinfo -p charon-peerinfo -- --port 4002`
#![allow(missing_docs)]
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use charon_p2p::{
    config::P2PConfig,
    k1::{self, key_path},
    p2p::{Node, NodeType},
};
use charon_peerinfo::{Behaviour, Config, Event, LocalPeerInfo};
use clap::Parser;
use k256::SecretKey;
use libp2p::{
    Multiaddr, Swarm,
    futures::StreamExt,
    identify, mdns, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use tokio::signal;
use tracing_subscriber::EnvFilter;
use vise::MetricsCollection;
use vise_exporter::MetricsExporter;

/// Command line arguments
#[derive(Debug, Parser)]
#[command(name = "peerinfo-example")]
#[command(about = "Demonstrates the peerinfo protocol with mDNS discovery")]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// The port to listen on
    #[arg(short, long, default_value = "4001")]
    pub port: u16,

    /// Optional addresses to dial
    #[arg(short, long)]
    pub dial: Vec<Multiaddr>,

    /// Nickname for this node
    #[arg(short, long, default_value = "example-node")]
    pub nickname: String,

    /// Peer info exchange interval in seconds
    #[arg(short, long, default_value = "5")]
    pub interval: u64,

    /// Data directory for storing the private key
    #[arg(long, default_value = ".charon-example")]
    pub data_dir: PathBuf,

    /// Metrics port to bind to
    #[arg(long, default_value = "9465")]
    pub metrics_port: u16,
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Initialize the node with a private key
    Init {
        /// Data directory for storing the private key
        #[arg(long, default_value = ".charon-example")]
        data_dir: PathBuf,

        /// Private key as a hex string
        #[arg(long)]
        private_key: String,
    },
}

/// Combined behaviour with peerinfo, identify, ping, and mdns
#[derive(NetworkBehaviour)]
pub struct CombinedBehaviour {
    pub peer_info: Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub relay: relay::client::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub type CombinedEvent = CombinedBehaviourEvent;

fn handle_event(event: SwarmEvent<CombinedEvent>, swarm: &mut Swarm<CombinedBehaviour>) {
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
        SwarmEvent::Behaviour(CombinedEvent::PeerInfo(Event::Received { peer, info, .. })) => {
            tracing::info!(
                "Received PeerInfo from {peer}:\n\
                 │  Version: {}\n\
                 │  Git Hash: {}\n\
                 │  Nickname: {}\n\
                 │  Builder API: {}\n\
                 │  Lock Hash: {:?}",
                info.charon_version,
                info.git_hash,
                info.nickname,
                info.builder_api_enabled,
                hex::encode(&info.lock_hash),
            );
        }
        SwarmEvent::Behaviour(CombinedEvent::PeerInfo(Event::Error { peer, error, .. })) => {
            tracing::warn!("PeerInfo error with {peer}: {error}");
        }
        SwarmEvent::Behaviour(CombinedEvent::Identify(identify::Event::Received {
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
        SwarmEvent::Behaviour(CombinedEvent::Ping(ping::Event { peer, result, .. })) => {
            match result {
                Ok(rtt) => tracing::debug!("Ping to {peer}: {rtt:?}"),
                Err(e) => tracing::debug!("Ping to {peer} failed: {e}"),
            }
        }
        SwarmEvent::Behaviour(CombinedEvent::Mdns(mdns::Event::Discovered(peers))) => {
            for (peer_id, addr) in peers {
                tracing::info!("🔍 mDNS discovered peer {peer_id} at {addr}");
                if let Err(e) = swarm.dial(addr) {
                    tracing::warn!("Failed to dial discovered peer: {e}");
                }
            }
        }
        SwarmEvent::Behaviour(CombinedEvent::Mdns(mdns::Event::Expired(peers))) => {
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

fn init_node(data_dir: &PathBuf, private_key: &str) -> anyhow::Result<()> {
    // Decode the hex string
    let key_bytes = hex::decode(private_key.trim().trim_start_matches("0x"))?;

    // Parse the secret key
    let key = SecretKey::from_slice(&key_bytes)?;

    // Create the data directory
    std::fs::create_dir_all(data_dir)?;

    // Save the key
    let key_file = key_path(data_dir);
    std::fs::write(&key_file, hex::encode(key.to_bytes()))?;

    tracing::info!(
        "Initialized node with private key in {}",
        key_file.display()
    );

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("debug".parse()?))
        .init();

    let args = Args::parse();

    // Handle init subcommand
    if let Some(Command::Init {
        data_dir,
        private_key,
    }) = args.command
    {
        return init_node(&data_dir, &private_key);
    }

    // Run the metrics exporter
    let bind_address = SocketAddr::from(([0, 0, 0, 0], args.metrics_port));

    let exporter = MetricsExporter::new(
        MetricsCollection::default()
            .with_prefix("pluto")
            .collect()
            .into(),
    )
    .bind(bind_address)
    .await
    .expect("Failed to bind metrics exporter");

    tokio::spawn(async move {
        exporter
            .start()
            .await
            .expect("Failed to start metrics exporter");
    });

    // Load existing key or create a new one
    let key = match k1::load_priv_key(&args.data_dir) {
        Ok(key) => {
            tracing::info!(
                "Loaded existing private key from {}",
                args.data_dir.display()
            );
            key
        }
        Err(_) => {
            tracing::info!("Creating new private key in {}", args.data_dir.display());
            k1::new_saved_priv_key(&args.data_dir)?
        }
    };
    let enr = charon_eth2::enr::Record::new(
        key.clone(),
        vec![
            charon_eth2::enr::with_ip_impl(Ipv4Addr::from([0, 0, 0, 0])),
            charon_eth2::enr::with_tcp_impl(args.port),
            charon_eth2::enr::with_udp_impl(args.port),
        ],
    )?;

    tracing::info!("ENR: {}", enr);

    // Create local peer info
    let local_info = LocalPeerInfo::new(
        "v1.0.0",
        vec![0x00, 0x00, 0x00, 0x00],
        "abc1234",
        false,
        &args.nickname,
    );

    let Node { mut swarm } = Node::new(
        P2PConfig::default(),
        key,
        false,
        NodeType::TCP,
        |key, relay_client| CombinedBehaviour {
            peer_info: Behaviour::new(
                Config::new(local_info.clone()).with_interval(Duration::from_secs(args.interval)),
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/peerinfo-example/1.0.0".to_string(),
                key.public(),
            )),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(15))
                    .with_timeout(Duration::from_secs(10)),
            ),
            mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                .expect("Failed to create mDNS behaviour"),
            relay: relay_client,
        },
    )?;

    let local_peer_id = *swarm.local_peer_id();
    tracing::info!("Local peer id: {local_peer_id}");
    tracing::info!("mDNS auto-discovery enabled");

    // Listen on the specified port
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?;
    swarm.listen_on(listen_addr)?;

    // Dial the specified addresses if provided
    for dial_addr in &args.dial {
        tracing::info!("Dialing {dial_addr}");
        swarm.dial(dial_addr.clone())?;
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
            event = swarm.select_next_some() => handle_event(event, &mut swarm),
            _ = signal::ctrl_c() => {
                tracing::info!("Received Ctrl+C, shutting down...");
                break;
            }
        }
    }

    Ok(())
}
