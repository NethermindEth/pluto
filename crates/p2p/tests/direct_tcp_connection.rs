//! End-to-end test for two real Pluto nodes connecting directly over TCP.
//!
//! Unlike `dkg::frostp2p_integ_test` (which uses `Node::new_server` with a
//! custom test behaviour), this drives the full *production* client stack built
//! by [`Node::new`]: the composed [`PlutoBehaviour`] with its connection
//! logger, gater, identify, ping, autonat and QUIC-upgrade sub-behaviours, plus
//! the libp2p relay *client* behaviour as the inner behaviour.
//!
//! The test asserts that two nodes, given only a listen address, establish a
//! bidirectional connection and actually run the identify and ping protocols
//! over it — proving the real behaviour stack negotiates and stays live.
//!
//! [`PlutoBehaviour`]: pluto_p2p::behaviours::pluto::PlutoBehaviour

use std::time::Duration;

use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, identify, ping, relay, swarm::SwarmEvent};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::time::timeout;

/// A client node whose inner behaviour is the libp2p relay client — the same
/// shape `Node::new` produces in production.
type ClientNode = Node<relay::client::Behaviour>;
/// Swarm event type yielded by [`ClientNode`].
type ClientEvent = SwarmEvent<PlutoBehaviourEvent<relay::client::Behaviour>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// What we expect to observe on a single node over the connection's lifetime.
#[derive(Default)]
struct Observed {
    connected: bool,
    identified: bool,
    pinged: bool,
}

impl Observed {
    fn complete(&self) -> bool {
        self.connected && self.identified && self.pinged
    }
}

/// Builds a production client node listening on nothing yet, tracking
/// `known_peer` in its [`P2PContext`].
fn build_client_node(key: k256::SecretKey, known_peer: PeerId) -> ClientNode {
    let p2p_context = P2PContext::new(vec![known_peer]);
    Node::new(
        P2PConfig::default(),
        key,
        NodeType::TCP,
        // Keep loopback addresses: the test connects over 127.0.0.1.
        false,
        p2p_context,
        |builder, _keypair, relay_client| builder.with_inner(relay_client),
    )
    .expect("build production client node")
}

/// Drives `node` until it reports a `NewListenAddr`, returning that address.
async fn first_listen_addr(node: &mut ClientNode) -> Multiaddr {
    let wait = async {
        loop {
            let event = node.select_next_some().await;
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return address;
            }
        }
    };

    timeout(TEST_TIMEOUT, wait)
        .await
        .expect("timed out waiting for a listen address")
}

/// Folds a single swarm event into `observed`, checking the peer identity on
/// connection.
fn record_event(event: ClientEvent, expected_peer: &PeerId, observed: &mut Observed) {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            assert!(
                peer_id == *expected_peer,
                "connected to unexpected peer {peer_id}, wanted {expected_peer}",
            );
            observed.connected = true;
        }
        // Only a `Received` proves the peers actually exchanged identify
        // payloads, not merely that we sent ours.
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            ..
        })) => {
            assert!(
                peer_id == *expected_peer,
                "identify from unexpected peer {peer_id}, wanted {expected_peer}",
            );
            observed.identified = true;
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event { peer, result, .. })) => {
            assert!(
                peer == *expected_peer,
                "ping involving unexpected peer {peer}, wanted {expected_peer}",
            );
            // A measured RTT means the ping round-trip actually completed.
            if result.is_ok() {
                observed.pinged = true;
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn two_nodes_connect_identify_and_ping_over_tcp() {
    let key_a = generate_insecure_k1_key(1);
    let key_b = generate_insecure_k1_key(2);

    let peer_a = peer_id_from_key(key_a.public_key()).expect("derive peer id A");
    let peer_b = peer_id_from_key(key_b.public_key()).expect("derive peer id B");
    assert!(peer_a != peer_b, "test keys must yield distinct peer ids");

    let mut node_a = build_client_node(key_a, peer_b);
    let mut node_b = build_client_node(key_b, peer_a);

    assert!(
        node_a.local_peer_id() == &peer_a,
        "node A reported an unexpected local peer id",
    );
    assert!(
        node_b.local_peer_id() == &peer_b,
        "node B reported an unexpected local peer id",
    );

    // Node A listens; node B dials the resulting address.
    let listen = "/ip4/127.0.0.1/tcp/0"
        .parse::<Multiaddr>()
        .expect("parse loopback listen multiaddr");
    node_a.listen_on(listen).expect("node A listen_on");

    let dial_target = first_listen_addr(&mut node_a).await;
    node_b.dial(dial_target).expect("node B dial node A");

    // Drive both nodes until each has connected, exchanged identify, and
    // completed a ping with the other.
    let mut observed_a = Observed::default();
    let mut observed_b = Observed::default();

    let drive = async {
        loop {
            tokio::select! {
                event = node_a.select_next_some() => {
                    record_event(event, &peer_b, &mut observed_a);
                }
                event = node_b.select_next_some() => {
                    record_event(event, &peer_a, &mut observed_b);
                }
            }

            if observed_a.complete() && observed_b.complete() {
                break;
            }
        }
    };

    timeout(TEST_TIMEOUT, drive)
        .await
        .expect("timed out before both nodes connected, identified and pinged");
}
