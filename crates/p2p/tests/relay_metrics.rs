//! End-to-end check of relay connectivity metrics on the production path: a
//! real [`Node`] whose [`RelayManager`] reserves a circuit on an in-process
//! relay server over loopback TCP.
//!
//! The `relay::manager` unit tests drive the behaviour's `FromSwarm` handlers
//! directly; this test exercises the whole swarm plumbing the live cluster
//! runs, which is where both metric bugs showed up on the Charon dashboard:
//!
//! 1. `p2p_relay_connections` had no writer at all, so "Connected Relays"
//!    (`sum(p2p_relay_connections) by (peer) > 0`) was blank;
//! 2. the relay server — an ordinary transport peer, so libp2p's ping behaviour
//!    pings it — leaked into the per-peer `p2p_ping_*` series and appeared as a
//!    phantom cluster peer on `max(p2p_ping_success) by (peer)`.

mod common;

use futures::StreamExt as _;
use libp2p::{
    PeerId, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    metrics::P2P_METRICS,
    name::peer_name,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::{AddrInfo, MutablePeer, Peer},
    relay::{RelayManager, RelayManagerEvent},
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::time::timeout;
use vise::Gauge;

use common::{TEST_TIMEOUT, spawn_relay_server};

/// Client behaviour mirroring the app wiring: the relay client transport plus
/// the [`RelayManager`] that keeps the reservation alive. Ping is not listed
/// here because it lives in the outer `PlutoBehaviour`, as it does in the app.
#[derive(NetworkBehaviour)]
struct ClientBehaviour {
    relay: relay::client::Behaviour,
    relay_manager: RelayManager,
}

#[tokio::test]
async fn relay_reservation_sets_relay_connections_and_emits_no_ping_metrics() {
    let (relay_peer, relay_addr, relay_handle) =
        spawn_relay_server(generate_insecure_k1_key(11)).await;
    let relay_label = peer_name(&relay_peer);

    let relay_mutable = MutablePeer::new(Peer::new_relay_peer(&AddrInfo {
        id: relay_peer,
        addrs: vec![relay_addr],
    }));

    // The relay is deliberately absent from the known-peer set: the app builds
    // `P2PContext` from cluster peers only, handing relays to the conn gater
    // and the relay manager instead (`app/src/node/behaviour.rs`).
    let mut client: Node<ClientBehaviour> = Node::new(
        P2PConfig::default(),
        generate_insecure_k1_key(12),
        NodeType::TCP,
        false,
        P2PContext::new(Vec::<PeerId>::new()),
        move |builder, _keypair, relay_client| {
            let p2p_context = builder.p2p_context();
            builder.with_inner(ClientBehaviour {
                relay: relay_client,
                relay_manager: RelayManager::new(vec![relay_mutable], p2p_context),
            })
        },
    )
    .expect("build relay client node");

    // Drive the client until it holds a reservation *and* has pinged the relay.
    // The manager dials the relay and listens on its circuit address on its
    // own, and libp2p pings a fresh connection immediately, so both usually
    // land in the same handful of events. Metrics are recorded in
    // `Node::handle_event` before an event is yielded, so by the time these
    // are observed the gauge write and the ping gate have already run.
    let mut reserved = false;
    let mut pinged = false;
    timeout(TEST_TIMEOUT, async {
        while !(reserved && pinged) {
            match client.select_next_some().await {
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                    ClientBehaviourEvent::RelayManager(RelayManagerEvent::RelayReserved(peer)),
                )) if peer == relay_peer => reserved = true,
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event { peer, .. }))
                    if peer == relay_peer =>
                {
                    pinged = true;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for the relay reservation and a ping of the relay");

    assert_eq!(
        P2P_METRICS
            .relay_connections
            .get(&relay_label)
            .map(Gauge::get),
        Some(1),
        "a held reservation must show up as p2p_relay_connections{{peer}}=1"
    );

    // Read with `contains` rather than indexing so these assertions don't
    // create the very series they are checking for.
    assert!(
        !P2P_METRICS.ping_success.contains(&relay_label),
        "the relay must not appear in p2p_ping_success"
    );
    assert!(
        !P2P_METRICS.ping_latency_secs.contains(&relay_label),
        "the relay must not appear in p2p_ping_latency_secs"
    );
    assert!(
        !P2P_METRICS.ping_error_total.contains(&relay_label),
        "the relay must not appear in p2p_ping_error_total"
    );

    relay_handle.abort();
}
