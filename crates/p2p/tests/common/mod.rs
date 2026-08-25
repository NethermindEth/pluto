//! Shared fixtures for the `pluto-p2p` integration tests.

use std::time::Duration;

use futures::StreamExt as _;
use k256::SecretKey;
use libp2p::{Multiaddr, PeerId, relay, swarm::SwarmEvent};
use pluto_p2p::{
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use tokio::{task::JoinHandle, time::timeout};

/// How long any single step of an integration test may take before it is
/// treated as hung.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Starts an in-process relay server on loopback TCP and drives it in the
/// background. Returns its peer id, listen address, and swarm task handle —
/// abort the handle to stop the relay.
pub async fn spawn_relay_server(key: SecretKey) -> (PeerId, Multiaddr, JoinHandle<()>) {
    let peer_id = peer_id_from_key(key.public_key()).expect("relay peer id");

    let mut node = Node::new_server(
        P2PConfig::default(),
        key,
        NodeType::TCP,
        false,
        // Relay servers don't track cluster peers - they serve all connections.
        P2PContext::default(),
        None,
        |builder, keypair| {
            builder.with_inner(relay::Behaviour::new(
                keypair.public().to_peer_id(),
                relay::Config {
                    // Room for a circuit to carry a real payload; the default
                    // is 128 KiB.
                    max_circuit_bytes: 32 << 20,
                    // Keep the defaults: an exhaustive literal drops the
                    // per-peer and per-IP rate limiters.
                    ..relay::Config::default()
                },
            ))
        },
    )
    .expect("build relay server node");

    node.listen_on(
        "/ip4/127.0.0.1/tcp/0"
            .parse::<Multiaddr>()
            .expect("parse relay listen multiaddr"),
    )
    .expect("relay listen_on");

    let addr = timeout(TEST_TIMEOUT, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("timed out waiting for the relay listen address");

    // Without a reachable advertised address, reservations are rejected
    // client-side with `NoAddressesInReservation`.
    node.add_external_address(addr.clone());

    let handle = tokio::spawn(async move {
        loop {
            node.select_next_some().await;
        }
    });

    (peer_id, addr, handle)
}
