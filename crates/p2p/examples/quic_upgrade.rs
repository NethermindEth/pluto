//! QUIC Upgrade Example
//!
//! This example demonstrates the QUIC upgrade behaviour that automatically
//! upgrades TCP connections to QUIC when both peers support it.
//!
//! # Running the Example
//!
//! Run two instances in separate terminals:
//!
//! ```bash
//! # Terminal 1: Start the first node (note the peer ID printed)
//! cargo run -p pluto-p2p --example quic_upgrade -- --port 9000
//! # Output: Started node with peer ID: 16Uiu2HAmXXX...
//!
//! # Terminal 2: Start the second node with the first node's peer ID as known peer
//! cargo run -p pluto-p2p --example quic_upgrade -- --port 9001 \
//!     --dial /ip4/127.0.0.1/tcp/9000 \
//!     --peer 16Uiu2HAmXXX...
//! ```
//!
//! # What Happens
//!
//! 1. Node 2 connects to Node 1 via TCP
//! 2. Both nodes exchange identify information (including their QUIC addresses)
//! 3. The peer addresses are stored in the peer store
//! 4. The QUIC upgrade behaviour detects the TCP connection to a known peer
//! 5. After ~1 minute, it attempts to dial the peer's QUIC address
//! 6. On success: the redundant TCP connection is closed
//! 7. On failure: exponential backoff is applied before retrying
//!
//! # Note
//!
//! The QUIC upgrade behaviour only upgrades connections to "known peers"
//! (cluster members). In production, these are configured at startup.
//! For this example, use `--peer` to specify the peer ID to upgrade.
//!
//! # Expected Output
//!
//! ```text
//! [CONNECTED] 16Uiu2HAm... via TCP at /ip4/127.0.0.1/tcp/9000
//! [IDENTIFY] Received from 16Uiu2HAm...
//!   Agent: quic-upgrade-example/1.0.0
//!   Addresses:
//!     - [TCP] /ip4/127.0.0.1/tcp/9000
//!     - [QUIC] /ip4/127.0.0.1/udp/9000/quic-v1
//! ... (after ~1 minute) ...
//! [CONNECTED] 16Uiu2HAm... via QUIC at /ip4/127.0.0.1/udp/9000/quic-v1
//! [QUIC UPGRADE] Successfully upgraded connection to 16Uiu2HAm...!
//! [DISCONNECTED] 16Uiu2HAm... TCP connection closed (remaining: 1)
//! ```

use std::str::FromStr;

use anyhow::Result;
use clap::Parser;
use k256::elliptic_curve::rand_core::OsRng;
use libp2p::{Multiaddr, PeerId, futures::StreamExt, relay, swarm::SwarmEvent};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    quic_upgrade::QuicUpgradeEvent,
};
use tokio::signal;

/// Command line arguments.
#[derive(Debug, Parser)]
#[command(name = "quic_upgrade")]
#[command(about = "Demonstrates QUIC upgrade behaviour")]
pub struct Args {
    /// The port to listen on (both TCP and UDP/QUIC).
    #[arg(short, long, default_value = "9000")]
    pub port: u16,

    /// Address to dial (e.g., /ip4/127.0.0.1/tcp/9000).
    #[arg(short, long)]
    pub dial: Option<Multiaddr>,

    /// Known peer ID(s) to attempt QUIC upgrade for.
    /// The upgrade behaviour only upgrades connections to known peers.
    #[arg(long)]
    pub peer: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key = k256::SecretKey::random(&mut OsRng);

    // Create a config with the specified port
    // Note: P2PConfig requires a specific IP (not 0.0.0.0), so we use 127.0.0.1 for
    // local testing
    let config = P2PConfig {
        tcp_addrs: vec![format!("127.0.0.1:{}", args.port)],
        udp_addrs: vec![format!("127.0.0.1:{}", args.port)],
        ..Default::default()
    };

    // Parse known peer IDs from command line
    let known_peers: Vec<PeerId> = args
        .peer
        .iter()
        .filter_map(|s| PeerId::from_str(s).ok())
        .collect();

    if !known_peers.is_empty() {
        println!("Known peers for QUIC upgrade: {:?}", known_peers);
    }

    let mut node = Node::new(
        config,
        key,
        NodeType::QUIC, // Enable QUIC transport
        false,          // Don't filter private addresses (for local testing)
        P2PContext::new(known_peers),
        |builder, _keypair, relay_client| {
            builder
                .with_user_agent("quic-upgrade-example/1.0.0")
                .with_quic_enabled(true) // Enable QUIC upgrade behaviour
                .with_inner(relay_client)
        },
    )?;

    println!("Started node with peer ID: {}", node.local_peer_id());
    println!("Listening on TCP and QUIC port: {}", args.port);

    // Dial the remote peer if specified
    if let Some(dial_addr) = &args.dial {
        println!("Dialing remote peer via TCP: {dial_addr}");
        node.dial(dial_addr.clone())?;
    }

    println!("\nWaiting for events... (Ctrl+C to quit)");
    if args.peer.is_empty() {
        println!("Note: No --peer specified. QUIC upgrade only works for known peers.");
        println!("      Copy this node's peer ID and pass it to the other node with --peer\n");
    } else {
        println!("QUIC upgrade will be attempted ~1 minute after TCP connection is established.\n");
    }

    // Event loop
    loop {
        tokio::select! {
            event = node.select_next_some() => {
                handle_event(event);
            }
            _ = signal::ctrl_c() => {
                println!("\nReceived Ctrl+C, shutting down...");
                break;
            }
        }
    }

    Ok(())
}

fn handle_event(event: SwarmEvent<PlutoBehaviourEvent<relay::client::Behaviour>>) {
    match event {
        // New listen address
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("[LISTEN] {address}");
        }

        // Connection established
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            let addr = match &endpoint {
                libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
            };
            let transport = if addr.to_string().contains("quic") {
                "QUIC"
            } else {
                "TCP"
            };
            println!("[CONNECTED] {peer_id} via {transport} at {addr}");
        }

        // Connection closed
        SwarmEvent::ConnectionClosed {
            peer_id,
            endpoint,
            num_established,
            ..
        } => {
            let addr = match &endpoint {
                libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
            };
            let transport = if addr.to_string().contains("quic") {
                "QUIC"
            } else {
                "TCP"
            };
            println!(
                "[DISCONNECTED] {peer_id} {transport} connection closed (remaining: {num_established})"
            );
        }

        // QUIC upgrade events
        SwarmEvent::Behaviour(PlutoBehaviourEvent::QuicUpgrade(event)) => match event {
            QuicUpgradeEvent::Upgraded { peer } => {
                println!("[QUIC UPGRADE] Successfully upgraded connection to {peer}!");
            }
            QuicUpgradeEvent::UpgradeFailed { peer, reason } => {
                println!("[QUIC UPGRADE FAILED] {peer}: {reason}");
            }
        },

        // Identify received - shows peer's addresses including QUIC
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(
            libp2p::identify::Event::Received { peer_id, info, .. },
        )) => {
            println!("[IDENTIFY] Received from {peer_id}");
            println!("  Agent: {}", info.agent_version);
            println!("  Addresses:");
            for addr in &info.listen_addrs {
                let transport = if addr.to_string().contains("quic") {
                    "QUIC"
                } else if addr.to_string().contains("tcp") {
                    "TCP"
                } else {
                    "other"
                };
                println!("    - [{transport}] {addr}");
            }
        }

        // Ping events
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(event)) => {
            if let Ok(rtt) = event.result {
                println!("[PING] {} RTT: {:?}", event.peer, rtt);
            }
        }

        // Connection errors
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            println!("[ERROR] Outgoing connection to {peer_id:?}: {error}");
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            println!("[ERROR] Incoming connection: {error}");
        }

        // Ignore other events
        _ => {}
    }
}
