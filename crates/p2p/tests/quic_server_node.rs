//! End-to-end coverage for a *server* node built with [`NodeType::QUIC`].
//!
//! Every [`Node::new_server`] call in the repo passes [`NodeType::TCP`] except
//! the production relay in `pluto-relay-server`, so the QUIC server path — the
//! one that actually ships — is otherwise untested. These tests drive it
//! directly: they assert the node installs *both* transports and binds a
//! listener for each configured address, that a [`NodeType::TCP`] server binds
//! only TCP even when UDP addresses are configured, and that a real client can
//! complete a QUIC handshake against the QUIC server.

use std::time::Duration;

use futures::StreamExt as _;
use libp2p::{Multiaddr, multiaddr::Protocol, relay, swarm::SwarmEvent};
use pluto_p2p::{
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A relay server node — the shape `pluto-relay-server` builds in production.
type ServerNode = Node<relay::Behaviour>;

/// Loopback config with one TCP and one UDP address, both on kernel-assigned
/// ports.
fn loopback_config() -> P2PConfig {
    P2PConfig::builder()
        .with_tcp_addrs(vec!["127.0.0.1:0".to_owned()])
        .with_udp_addrs(vec!["127.0.0.1:0".to_owned()])
        .build()
}

/// Builds a relay server node of `node_type` on [`loopback_config`].
fn build_server(key: k256::SecretKey, node_type: NodeType) -> ServerNode {
    Node::new_server(
        loopback_config(),
        key,
        node_type,
        // Keep loopback addresses: the tests connect over 127.0.0.1.
        false,
        // Relay servers don't track cluster peers - they serve all connections.
        P2PContext::default(),
        None,
        |builder, keypair| {
            builder.with_inner(relay::Behaviour::new(
                keypair.public().to_peer_id(),
                relay::Config::default(),
            ))
        },
    )
    .expect("build relay server node")
}

fn is_quic(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::QuicV1))
}

fn is_tcp(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
}

/// Drives `node` until it has reported `want` listen addresses.
async fn listen_addrs(node: &mut ServerNode, want: usize) -> Vec<Multiaddr> {
    let wait = async {
        let mut addrs = Vec::with_capacity(want);
        while addrs.len() < want {
            if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
                addrs.push(address);
            }
        }
        addrs
    };

    timeout(TEST_TIMEOUT, wait)
        .await
        .expect("timed out waiting for the listen addresses")
}

#[tokio::test]
async fn quic_server_binds_tcp_and_quic_listeners() {
    let mut node = build_server(generate_insecure_k1_key(1), NodeType::QUIC);

    // `listen_on` binds before it returns, so the listener count is already
    // final here: one per configured address of every installed transport.
    assert_eq!(
        node.listener_ids().len(),
        2,
        "a QUIC server must bind both its TCP and its UDP address",
    );

    let addrs = listen_addrs(&mut node, 2).await;

    assert!(
        addrs.iter().any(is_tcp),
        "no TCP listen address among {addrs:?}",
    );
    assert!(
        addrs.iter().any(is_quic),
        "no QUIC listen address among {addrs:?}",
    );
}

#[tokio::test]
async fn tcp_server_binds_no_quic_listener() {
    let mut node = build_server(generate_insecure_k1_key(2), NodeType::TCP);

    assert_eq!(
        node.listener_ids().len(),
        1,
        "a TCP server must ignore its configured UDP address",
    );

    let addrs = listen_addrs(&mut node, 1).await;

    assert!(
        !addrs.iter().any(is_quic),
        "a TCP server must not listen on QUIC, got {addrs:?}",
    );
}

#[tokio::test]
async fn client_connects_to_quic_server_over_quic() {
    let server_key = generate_insecure_k1_key(3);
    let client_key = generate_insecure_k1_key(4);

    let server_peer = peer_id_from_key(server_key.public_key()).expect("derive server peer id");
    let client_peer = peer_id_from_key(client_key.public_key()).expect("derive client peer id");

    let mut server = build_server(server_key, NodeType::QUIC);
    let mut client: Node<relay::client::Behaviour> = Node::new(
        P2PConfig::default(),
        client_key,
        NodeType::QUIC,
        false,
        P2PContext::new(vec![server_peer]),
        |builder, _keypair, relay_client| builder.with_inner(relay_client),
    )
    .expect("build production client node");

    let quic_addr = listen_addrs(&mut server, 2)
        .await
        .into_iter()
        .find(is_quic)
        .expect("server must expose a QUIC listen address");

    client.dial(quic_addr.clone()).expect("client dial server");

    // Drive both swarms until the client reports the connection. Only an
    // established connection proves the QUIC transport is really installed on
    // the *server*: the dial address is QUIC-only, so a TCP-only server would
    // never complete the handshake.
    let drive = async {
        loop {
            tokio::select! {
                event = server.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        assert!(
                            peer_id == client_peer,
                            "server connected to unexpected peer {peer_id}",
                        );
                    }
                }
                event = client.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } = event {
                        assert!(
                            peer_id == server_peer,
                            "client connected to unexpected peer {peer_id}",
                        );
                        assert!(
                            is_quic(endpoint.get_remote_address()),
                            "connection was not negotiated over QUIC: {endpoint:?}",
                        );
                        return;
                    }
                }
            }
        }
    };

    timeout(TEST_TIMEOUT, drive)
        .await
        .expect("timed out before the client connected over QUIC");
}
