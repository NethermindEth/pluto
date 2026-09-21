//! What a node advertises, seen through identify as a peer receives it.
//!
//! A node configured to listen on port 0 must advertise the kernel-assigned
//! port of each transport it installs, never the configured 0, with its
//! external IP on those same ports; and a relay circuit listener must not leak
//! the relay's port into that set.

mod common;

use common::TEST_TIMEOUT;
use futures::StreamExt as _;
use libp2p::{Multiaddr, identify, multiaddr::Protocol, relay, swarm::SwarmEvent};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer,
    utils::{self, TransportProtocol},
};
use pluto_testutil::random;
use tokio::time;

type ClientNode = Node<relay::client::Behaviour>;

const EXTERNAL_IP: &str = "1.2.3.4";

/// Drives `node` until it has reported `want` direct listen addresses and a
/// relayed one, and returns the direct ones.
async fn direct_listen_addrs(node: &mut ClientNode, want: usize) -> Vec<Multiaddr> {
    time::timeout(TEST_TIMEOUT, async {
        let mut direct = Vec::with_capacity(want);
        let mut relayed = false;
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
                if utils::is_relay_addr(&address) {
                    relayed = true;
                } else {
                    direct.push(address);
                }
                if relayed && direct.len() == want {
                    return direct;
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

    // A listens on a kernel-assigned port per transport, reserves a relay
    // circuit, and has an external IP override.
    let mut node_a: ClientNode = Node::new(
        P2PConfig::builder()
            .with_tcp_addrs(vec!["127.0.0.1:0".to_owned()])
            .with_udp_addrs(vec!["127.0.0.1:0".to_owned()])
            .with_external_ip(EXTERNAL_IP.to_owned())
            .build(),
        key_a,
        NodeType::QUIC,
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

    let bound = direct_listen_addrs(&mut node_a, 2).await;
    let tcp_addr = bound
        .iter()
        .find(|addr| utils::is_tcp_addr(addr))
        .cloned()
        .expect("A must bind a TCP listener");
    let tcp_port = utils::addr_port(&tcp_addr, TransportProtocol::Tcp).expect("bound TCP port");
    let quic_port = bound
        .iter()
        .find_map(|addr| utils::addr_port(addr, TransportProtocol::Quic))
        .expect("A must bind a QUIC listener");
    assert!(
        tcp_port != 0 && quic_port != 0,
        "the kernel must have assigned both ports"
    );

    node_b.dial(tcp_addr).expect("dial A");

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

    let external_tcp: Multiaddr = format!("/ip4/{EXTERNAL_IP}/tcp/{tcp_port}")
        .parse()
        .expect("external TCP multiaddr");
    let external_quic: Multiaddr = format!("/ip4/{EXTERNAL_IP}/udp/{quic_port}/quic-v1")
        .parse()
        .expect("external QUIC multiaddr");
    assert!(
        advertised.contains(&external_tcp),
        "external address {external_tcp} missing from {advertised:?}",
    );
    assert!(
        advertised.contains(&external_quic),
        "external address {external_quic} missing from {advertised:?}",
    );

    let own_port = |addr: &Multiaddr| {
        utils::addr_port(addr, TransportProtocol::Tcp).is_none_or(|port| port == tcp_port)
            && utils::addr_port(addr, TransportProtocol::Quic).is_none_or(|port| port == quic_port)
    };
    assert!(
        advertised
            .iter()
            .filter(|addr| !utils::is_relay_addr(addr))
            .all(own_port),
        "advertised addresses on a port other than {tcp_port}/{quic_port}: {advertised:?}",
    );
}
