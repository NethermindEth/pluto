//! What a node advertises, seen through identify as a peer receives it.
//!
//! A node configured to listen on port 0 must advertise the kernel-assigned
//! port, never the configured 0, with its external IP on that same port; and a
//! relay circuit listener must not leak the relay's port into that set.

mod common;

use common::TEST_TIMEOUT;
use futures::StreamExt as _;
use libp2p::{Multiaddr, identify, multiaddr::Protocol, relay, swarm::SwarmEvent};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer, utils,
};
use pluto_testutil::random;
use tokio::time;

type ClientNode = Node<relay::client::Behaviour>;

const EXTERNAL_IP: &str = "1.2.3.4";

fn tcp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

/// Drives `node` until it has reported both a direct and a relayed listen
/// address, and returns the direct one.
async fn direct_listen_addr(node: &mut ClientNode) -> Multiaddr {
    time::timeout(TEST_TIMEOUT, async {
        let mut direct = None;
        let mut relayed = false;
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
                if utils::is_relay_addr(&address) {
                    relayed = true;
                } else {
                    direct = Some(address);
                }
                if relayed && let Some(addr) = &direct {
                    return addr.clone();
                }
            }
        }
    })
    .await
    .expect("timed out waiting for the listen addresses")
}

#[tokio::test]
async fn advertises_own_bound_ports_only() {
    let (relay_peer, relay_addr, relay_handle) =
        common::spawn_relay_server(random::generate_insecure_k1_key(20)).await;

    let key_a = random::generate_insecure_k1_key(21);
    let key_b = random::generate_insecure_k1_key(22);
    let peer_a = peer::peer_id_from_key(key_a.public_key()).expect("peer id A");
    let peer_b = peer::peer_id_from_key(key_b.public_key()).expect("peer id B");

    // A listens on a kernel-assigned TCP port, reserves a relay circuit, and
    // has an external IP override.
    let mut node_a: ClientNode = Node::new(
        P2PConfig::builder()
            .with_tcp_addrs(vec!["127.0.0.1:0".to_owned()])
            .with_external_ip(EXTERNAL_IP.to_owned())
            .build(),
        key_a,
        NodeType::TCP,
        false,
        P2PContext::new(vec![peer_b, relay_peer]),
        |builder, _keypair, relay_client| builder.with_inner(relay_client),
    )
    .expect("build node A");
    node_a
        .listen_on(
            relay_addr
                .with(Protocol::P2p(relay_peer))
                .with(Protocol::P2pCircuit),
        )
        .expect("A listen_on circuit");

    let mut node_b: ClientNode = Node::new(
        P2PConfig::default(),
        key_b,
        NodeType::TCP,
        false,
        P2PContext::new(vec![peer_a]),
        |builder, _keypair, relay_client| builder.with_inner(relay_client),
    )
    .expect("build node B");

    let bound = direct_listen_addr(&mut node_a).await;
    let bound_port = tcp_port(&bound).expect("bound TCP port");
    assert!(bound_port != 0, "kernel must have assigned a port");

    node_b.dial(bound).expect("dial A");

    // Drive both until B has A's identify payload.
    let advertised = time::timeout(TEST_TIMEOUT, async {
        loop {
            tokio::select! {
                _ = node_a.select_next_some() => {}
                event = node_b.select_next_some() => {
                    if let SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) = event
                        && peer_id == peer_a
                    {
                        return info.listen_addrs;
                    }
                }
            }
        }
    })
    .await
    .expect("timed out waiting for A's identify");

    relay_handle.abort();

    let external: Multiaddr = format!("/ip4/{EXTERNAL_IP}/tcp/{bound_port}")
        .parse()
        .expect("external multiaddr");
    assert!(
        advertised.contains(&external),
        "external address {external} missing from {advertised:?}",
    );

    assert!(
        advertised
            .iter()
            .filter(|addr| !utils::is_relay_addr(addr))
            .all(|addr| tcp_port(addr) == Some(bound_port)),
        "advertised addresses on a port other than {bound_port}: {advertised:?}",
    );
}
