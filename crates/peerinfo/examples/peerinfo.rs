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
use std::time::Duration;

use charon_peerinfo::{Behaviour, Config, Event, LocalPeerInfo};
use clap::Parser;
use libp2p::{
    Multiaddr, Swarm, SwarmBuilder,
    futures::StreamExt,
    identify, mdns, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tokio::signal;
use tracing_subscriber::EnvFilter;

/// Command line arguments
#[derive(Debug, Parser)]
#[command(name = "peerinfo-example")]
#[command(about = "Demonstrates the peerinfo protocol with mDNS discovery")]
pub struct Args {
    /// The port to listen on
    #[arg(short, long, default_value = "4001")]
    pub port: u16,

    /// Optional address to dial
    #[arg(short, long)]
    pub dial: Option<Multiaddr>,

    /// Nickname for this node
    #[arg(short, long, default_value = "example-node")]
    pub nickname: String,

    /// Peer info exchange interval in seconds
    #[arg(short, long, default_value = "5")]
    pub interval: u64,
}

/// Combined behaviour with peerinfo, identify, ping, and mdns
#[derive(NetworkBehaviour)]
pub struct CombinedBehaviour {
    pub peer_info: Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub type CombinedEvent = CombinedBehaviourEvent;

fn build_swarm(peerinfo_config: Config) -> anyhow::Result<Swarm<CombinedBehaviour>> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            Ok(CombinedBehaviour {
                peer_info: Behaviour::new(peerinfo_config),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/peerinfo-example/1.0.0".to_string(),
                    key.public(),
                )),
                ping: ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(15))
                        .with_timeout(Duration::from_secs(10)),
                ),
                mdns: mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?,
            })
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    Ok(swarm)
}

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
                "📥 Received PeerInfo from {peer}:\n\
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("debug".parse()?))
        .init();

    let args = Args::parse();

    // Create local peer info
    let local_info = LocalPeerInfo::new(
        "v1.0.0",                     // charon_version
        vec![0xDE, 0xAD, 0xBE, 0xEF], // lock_hash (example)
        "abc1234",                    // git_hash
        false,                        // builder_api_enabled
        &args.nickname,               // nickname
    );

    // Create peerinfo config with custom interval for demonstration
    let peerinfo_config = Config::new(local_info)
        .with_interval(Duration::from_secs(args.interval))
        .with_timeout(Duration::from_secs(10));

    let mut swarm = build_swarm(peerinfo_config)?;

    let local_peer_id = *swarm.local_peer_id();
    tracing::info!("Local peer id: {local_peer_id}");
    tracing::info!("mDNS auto-discovery enabled");

    // Listen on the specified port
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?;
    swarm.listen_on(listen_addr)?;

    // Dial the specified address if provided
    if let Some(dial_addr) = &args.dial {
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
