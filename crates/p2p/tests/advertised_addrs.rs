//! A node configured to listen on port 0 must advertise the ports the kernel
//! assigned, never the configured 0, and must advertise its external IP on
//! those same ports.
//!
//! Checked through identify as received by a peer, which is the only view
//! other nodes ever get of what this node advertises.

use std::time::Duration;

use futures::StreamExt as _;
use libp2p::{Multiaddr, identify, multiaddr::Protocol, relay, swarm::SwarmEvent};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::time::timeout;

type ClientNode = Node<relay::client::Behaviour>;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const EXTERNAL_IP: &str = "1.2.3.4";

fn tcp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

async fn first_listen_addr(node: &mut ClientNode) -> Multiaddr {
    timeout(TEST_TIMEOUT, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("timed out waiting for a listen address")
}

#[tokio::test]
async fn advertises_bound_ports_not_configured_port_zero() {
    let key_a = generate_insecure_k1_key(21);
    let key_b = generate_insecure_k1_key(22);
    let peer_a = peer_id_from_key(key_a.public_key()).expect("peer id A");
    let peer_b = peer_id_from_key(key_b.public_key()).expect("peer id B");

    // A listens on a kernel-assigned port and has an external IP override.
    let mut node_a: ClientNode = Node::new(
        P2PConfig::builder()
            .with_tcp_addrs(vec!["127.0.0.1:0".to_owned()])
            .with_external_ip(EXTERNAL_IP.to_owned())
            .build(),
        key_a,
        NodeType::TCP,
        false,
        P2PContext::new(vec![peer_b]),
        |builder, _keypair, relay_client| builder.with_inner(relay_client),
    )
    .expect("build node A");

    let mut node_b: ClientNode = Node::new(
        P2PConfig::default(),
        key_b,
        NodeType::TCP,
        false,
        P2PContext::new(vec![peer_a]),
        |builder, _keypair, relay_client| builder.with_inner(relay_client),
    )
    .expect("build node B");

    let bound = first_listen_addr(&mut node_a).await;
    let bound_port = tcp_port(&bound).expect("bound TCP port");
    assert!(bound_port != 0, "kernel must have assigned a port");

    node_b.dial(bound.clone()).expect("dial A");

    // Drive both until B has A's identify payload.
    let advertised = timeout(TEST_TIMEOUT, async {
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

    let external: Multiaddr = format!("/ip4/{EXTERNAL_IP}/tcp/{bound_port}")
        .parse()
        .expect("external multiaddr");

    assert!(
        advertised.contains(&bound),
        "bound address {bound} missing from {advertised:?}",
    );
    assert!(
        advertised.contains(&external),
        "external address {external} missing from {advertised:?}",
    );
    assert!(
        advertised.iter().all(|addr| tcp_port(addr) != Some(0)),
        "port 0 must never be advertised: {advertised:?}",
    );
}
