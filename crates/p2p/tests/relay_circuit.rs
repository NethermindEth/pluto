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

use std::{fmt::Debug, time::Duration};

use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol, relay, swarm::SwarmEvent};
use pluto_p2p::{
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::time::timeout;
use tracing_subscriber::EnvFilter;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns true if `addr` is a relayed (`/p2p-circuit`) address.
fn is_circuit_addr(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|proto| matches!(proto, Protocol::P2pCircuit))
}

/// Installs a test tracing subscriber. Defaults to `warn` so reservation and
/// circuit failures surface even without `RUST_LOG`; set e.g.
/// `RUST_LOG=libp2p=debug,pluto_p2p=debug` for full transport tracing.
fn init_logs() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

/// Logs swarm events instead of silently dropping them: failures at `warn`, the
/// rest at `trace`. A rejected reservation or failed circuit dial then shows up
/// in the logs rather than as a bare timeout.
fn note_swarm_event<E: Debug>(label: &str, event: &SwarmEvent<E>) {
    use SwarmEvent::*;
    match event {
        OutgoingConnectionError { peer_id, error, .. } => {
            tracing::warn!(node = label, ?peer_id, %error, "outgoing connection error");
        }
        IncomingConnectionError { error, .. } => {
            tracing::warn!(node = label, %error, "incoming connection error");
        }
        ListenerError { error, .. } => {
            tracing::warn!(node = label, %error, "listener error");
        }
        ListenerClosed {
            reason: Err(error), ..
        } => {
            tracing::warn!(node = label, %error, "listener closed with error");
        }
        _ => tracing::trace!(node = label, ?event, "swarm event"),
    }
}

#[tokio::test]
async fn two_nodes_connect_through_relay_circuit() {
    init_logs();

    let relay_key = generate_insecure_k1_key(1);
    let listener_key = generate_insecure_k1_key(2);
    let dialer_key = generate_insecure_k1_key(3);

    let relay_peer = peer_id_from_key(relay_key.public_key()).expect("relay peer id");
    let listener_peer = peer_id_from_key(listener_key.public_key()).expect("listener peer id");
    let dialer_peer = peer_id_from_key(dialer_key.public_key()).expect("dialer peer id");

    // --- Relay server node. ---
    let relay_config = relay::Config {
        max_reservations: 16,
        max_reservations_per_peer: 4,
        reservation_duration: Duration::from_secs(3600),
        reservation_rate_limiters: vec![],
        max_circuits: 16,
        max_circuits_per_peer: 4,
        max_circuit_duration: Duration::from_secs(120),
        max_circuit_bytes: 32 * 1024 * 1024,
        circuit_src_rate_limiters: vec![],
    };
    let mut relay_node = Node::new_server(
        P2PConfig::default(),
        relay_key,
        NodeType::TCP,
        false,
        P2PContext::default(),
        None,
        move |builder, keypair| {
            let behaviour = relay::Behaviour::new(keypair.public().to_peer_id(), relay_config);
            builder.with_inner(behaviour)
        },
    )
    .expect("build relay server node");

    let relay_listen = "/ip4/127.0.0.1/tcp/0"
        .parse::<Multiaddr>()
        .expect("parse relay listen multiaddr");
    relay_node
        .listen_on(relay_listen)
        .expect("relay listen_on");

    // Wait for the relay's concrete TCP address, then keep the relay driven in
    // the background so it can service reservations and circuits.
    let relay_addr = timeout(TEST_TIMEOUT, async {
        loop {
            let event = relay_node.select_next_some().await;
            note_swarm_event("relay", &event);
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return address;
            }
        }
    })
    .await
    .expect("timed out waiting for the relay listen address");

    // The relay must advertise a reachable address, otherwise reservations are
    // rejected client-side with `NoAddressesInReservation`.
    relay_node.add_external_address(relay_addr.clone());

    let relay_handle = tokio::spawn(async move {
        loop {
            let event = relay_node.select_next_some().await;
            note_swarm_event("relay", &event);
        }
    });

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
            note_swarm_event("listener", &event);
            if matches!(event, SwarmEvent::NewListenAddr { ref address, .. } if is_circuit_addr(address))
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
                    note_swarm_event("listener", &event);
                    if matches!(event, SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == dialer_peer) {
                        listener_linked = true;
                    }
                }
                event = dialer.select_next_some() => {
                    note_swarm_event("dialer", &event);
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
