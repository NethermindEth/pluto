//! End-to-end check of relay connectivity metrics on the production path: a
//! real [`Node`] whose [`RelayManager`] reserves a circuit on an in-process
//! relay server over loopback TCP. The `relay::manager` unit tests drive the
//! `FromSwarm` handlers directly; this one exercises the full swarm plumbing,
//! where both metric bugs showed up.

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

/// Mirrors the app wiring: relay client transport plus the [`RelayManager`].
/// Ping lives in the outer `PlutoBehaviour`, as it does in the app.
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
    // `P2PContext` from cluster peers only.
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
    // `Node::handle_event` records metrics before yielding an event, so both
    // writes have run by the time these are observed.
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

    // `contains` rather than indexing, so the assertions don't create the very
    // series they check for.
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
