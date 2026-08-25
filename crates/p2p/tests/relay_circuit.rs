//! End-to-end test for relayed connectivity through an in-process relay.
//!
//! Two Pluto client nodes that never dial each other directly instead connect
//! through a third Pluto node running the libp2p relay *server* behaviour:
//!
//! 1. the relay node ([`Node::new_server`] + [`relay::Behaviour`]) listens on
//!    loopback TCP;
//! 2. a *listener* client ([`Node::new`], relay client inner) reserves a slot
//!    on the relay by listening on the relay's `/p2p-circuit` address;
//! 3. a *dialer* client dials the listener through that circuit address and the
//!    two establish a relayed connection.
//!
//! This exercises the production [`Node`] plumbing for both the relay server
//! and relay client paths over real sockets — the relay reservation and circuit
//! hop, not just a direct dial.

mod common;

use futures::StreamExt as _;
use libp2p::{PeerId, multiaddr::Protocol, relay, swarm::SwarmEvent};
use pluto_p2p::{
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
    utils::is_relay_addr,
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::time::timeout;

use common::{TEST_TIMEOUT, spawn_relay_server};

#[tokio::test]
async fn two_nodes_connect_through_relay_circuit() {
    let listener_key = generate_insecure_k1_key(2);
    let dialer_key = generate_insecure_k1_key(3);

    let listener_peer = peer_id_from_key(listener_key.public_key()).expect("listener peer id");
    let dialer_peer = peer_id_from_key(dialer_key.public_key()).expect("dialer peer id");

    let (relay_peer, relay_addr, relay_handle) =
        spawn_relay_server(generate_insecure_k1_key(1)).await;

    // Full relay address including its peer id, plus the circuit suffix.
    let relay_with_id = relay_addr.with(Protocol::P2p(relay_peer));
    let circuit_base = relay_with_id.clone().with(Protocol::P2pCircuit);

    // --- Two client nodes. ---
    let make_client = |key, known: PeerId| -> Node<relay::client::Behaviour> {
        Node::new(
            P2PConfig::default(),
            key,
            NodeType::TCP,
            false,
            P2PContext::new(vec![known, relay_peer]),
            |builder, _keypair, relay_client| builder.with_inner(relay_client),
        )
        .expect("build relay client node")
    };

    let mut listener = make_client(listener_key, dialer_peer);
    let mut dialer = make_client(dialer_key, listener_peer);

    // The listener reserves a relay slot by listening on the circuit address.
    listener
        .listen_on(circuit_base.clone())
        .expect("listener listen_on circuit");

    // Drive the listener until the reservation is confirmed (a relayed listen
    // address appears).
    timeout(TEST_TIMEOUT, async {
        loop {
            let event = listener.select_next_some().await;
            if matches!(event, SwarmEvent::NewListenAddr { ref address, .. } if is_relay_addr(address))
            {
                return;
            }
        }
    })
    .await
    .expect("timed out waiting for the listener's relay reservation");

    // The dialer reaches the listener purely through the relay circuit.
    let dial_target = circuit_base.with(Protocol::P2p(listener_peer));
    dialer
        .dial(dial_target)
        .expect("dialer dial listener via circuit");

    // Both ends must observe a connection to *each other* (connections to the
    // relay peer don't count).
    let mut listener_linked = false;
    let mut dialer_linked = false;

    timeout(TEST_TIMEOUT, async {
        loop {
            tokio::select! {
                event = listener.select_next_some() => {
                    if matches!(event, SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == dialer_peer) {
                        listener_linked = true;
                    }
                }
                event = dialer.select_next_some() => {
                    if matches!(event, SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == listener_peer) {
                        dialer_linked = true;
                    }
                }
            }

            if listener_linked && dialer_linked {
                break;
            }
        }
    })
    .await
    .expect("timed out establishing the relayed connection");

    assert!(
        listener_linked,
        "listener never saw the dialer over the relay"
    );
    assert!(
        dialer_linked,
        "dialer never reached the listener over the relay"
    );

    relay_handle.abort();
}
