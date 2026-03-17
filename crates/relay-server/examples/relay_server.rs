#![allow(missing_docs)]
//! Relay server example demonstrating a standalone libp2p relay node.
//!
//! This example shows how to run a relay server that allows peers to:
//! - Make relay reservations to be reachable when behind NAT/firewalls
//! - Create relay circuits to connect to other peers through the relay
//! - Query relay multiaddrs via HTTP endpoint
//!
//! ## What is a Relay Server?
//!
//! A relay server acts as an intermediary for P2P connections when direct
//! connections are not possible due to NAT, firewalls, or network topology.
//! Peers can:
//! 1. Reserve a slot on the relay (relay reservation)
//! 2. Be reached by other peers through the relay (relay circuit)
//!
//! ## Usage
//!
//! Run the relay server with default settings:
//! ```bash
//! cargo run --example relay_server
//! ```
//!
//! The server will:
//! - Generate a random keypair for the relay's peer identity
//! - Listen on a random available TCP port (0.0.0.0:0)
//! - Serve relay multiaddrs via HTTP on port 8888
//! - Accept up to 100 relay connections
//! - Allow up to 10 reservations per peer
//!
//! ## Configuration
//!
//! The example uses:
//! - `max_conns`: Maximum concurrent relay connections (100)
//! - `max_res_per_peer`: Maximum reservations per peer (10)
//! - `http_addr`: HTTP server address for ENR queries (0.0.0.0:8888)
//! - Random TCP port (0) to let the OS choose an available port
//!
//! ## Querying Relay Addresses
//!
//! Once running, query the relay's multiaddrs:
//! ```bash
//! curl http://localhost:8888
//! ```
//!
//! This returns the relay's multiaddrs that clients can use to connect.

use k256::SecretKey;
use pluto_p2p::config::P2PConfig;
use pluto_relay_server::{config::Config, p2p::run_relay_p2p_node};
use pluto_tracing::TracingConfig;
use rand::rngs::OsRng;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tokio::main]
async fn main() {
    pluto_tracing::init(&TracingConfig::default()).expect("Failed to initialize tracing");

    let config = Config::builder()
        .p2p_config(
            P2PConfig::builder()
                .with_tcp_addrs(vec!["0.0.0.0:0".to_string()])
                .build(),
        )
        .max_conns(100)
        .max_res_per_peer(10)
        .http_addr("0.0.0.0:8888".to_string())
        .build();

    let key = SecretKey::random(&mut OsRng);

    let ct = CancellationToken::new();

    tokio::select! {
        result = run_relay_p2p_node(&config, key, ct.child_token()) => {
            result.expect("Failed to run relay P2P node");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received, shutting down gracefully...");
            ct.cancel();

        }
    }

    info!("Shutdown complete");
}
