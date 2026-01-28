#![allow(missing_docs)]
use std::str::FromStr;

use charon_p2p::config::P2PConfig;
use charon_relay_server::{config::Config, p2p::run_relay_p2p_node};
use k256::SecretKey;
use libp2p::multiaddr;
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
                .with_tcp_addrs(vec![
                    multiaddr::Multiaddr::from_str("/ip4/0.0.0.0/tcp/0")
                        .expect("Failed to parse multiaddress")
                        .to_string(),
                ])
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
