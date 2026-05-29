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

use std::{fmt::Debug, time::Duration};

use anyhow::{Context as _, ensure};
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
use tracing_subscriber::EnvFilter;

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

/// Installs a test tracing subscriber. Defaults to `warn` so connection and
/// listener errors surface even without `RUST_LOG`; set e.g.
/// `RUST_LOG=libp2p=debug,pluto_p2p=debug` for full transport tracing.
fn init_logs() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

/// Logs swarm events instead of silently dropping them: failures at `warn`, the
/// rest at `trace`. Surfaces the real cause of a hang instead of a bare
/// timeout.
fn note_swarm_event<E: Debug>(event: &SwarmEvent<E>) {
    use SwarmEvent::*;
    match event {
        OutgoingConnectionError { peer_id, error, .. } => {
            tracing::warn!(?peer_id, %error, "outgoing connection error");
        }
        IncomingConnectionError { error, .. } => {
            tracing::warn!(%error, "incoming connection error");
        }
        ListenerError { error, .. } => {
            tracing::warn!(%error, "listener error");
        }
        ListenerClosed {
            reason: Err(error), ..
        } => {
            tracing::warn!(%error, "listener closed with error");
        }
        _ => tracing::trace!(?event, "swarm event"),
    }
}

/// Builds a production client node listening on nothing yet, tracking
/// `known_peer` in its [`P2PContext`].
fn build_client_node(key: k256::SecretKey, known_peer: PeerId) -> anyhow::Result<ClientNode> {
    let p2p_context = P2PContext::new(vec![known_peer]);
    let node = Node::new(
        P2PConfig::default(),
        key,
        NodeType::TCP,
        // Keep loopback addresses: the test connects over 127.0.0.1.
        false,
        p2p_context,
        |builder, _keypair, relay_client| builder.with_inner(relay_client),
    )
    .context("build production client node")?;

    Ok(node)
}

/// Drives `node` until it reports a `NewListenAddr`, returning that address.
async fn first_listen_addr(node: &mut ClientNode) -> anyhow::Result<Multiaddr> {
    let wait = async {
        loop {
            let event = node.select_next_some().await;
            note_swarm_event(&event);
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                return address;
            }
        }
    };

    let address = timeout(TEST_TIMEOUT, wait)
        .await
        .context("timed out waiting for a listen address")?;

    Ok(address)
}

/// Folds a single swarm event into `observed`, checking the peer identity on
/// connection.
fn record_event(
    event: ClientEvent,
    expected_peer: &PeerId,
    observed: &mut Observed,
) -> anyhow::Result<()> {
    note_swarm_event(&event);
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            ensure!(
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
            ensure!(
                peer_id == *expected_peer,
                "identify from unexpected peer {peer_id}, wanted {expected_peer}",
            );
            observed.identified = true;
        }
        SwarmEvent::Behaviour(PlutoBehaviourEvent::Ping(ping::Event { peer, result, .. })) => {
            ensure!(
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

    Ok(())
}

#[tokio::test]
async fn two_nodes_connect_identify_and_ping_over_tcp() -> anyhow::Result<()> {
    init_logs();

    let key_a = generate_insecure_k1_key(1);
    let key_b = generate_insecure_k1_key(2);

    let peer_a = peer_id_from_key(key_a.public_key()).context("derive peer id A")?;
    let peer_b = peer_id_from_key(key_b.public_key()).context("derive peer id B")?;
    ensure!(peer_a != peer_b, "test keys must yield distinct peer ids");

    let mut node_a = build_client_node(key_a, peer_b)?;
    let mut node_b = build_client_node(key_b, peer_a)?;

    ensure!(
        node_a.local_peer_id() == &peer_a,
        "node A reported an unexpected local peer id",
    );
    ensure!(
        node_b.local_peer_id() == &peer_b,
        "node B reported an unexpected local peer id",
    );

    // Node A listens; node B dials the resulting address.
    let listen = "/ip4/127.0.0.1/tcp/0"
        .parse::<Multiaddr>()
        .context("parse loopback listen multiaddr")?;
    node_a.listen_on(listen).context("node A listen_on")?;

    let dial_target = first_listen_addr(&mut node_a).await?;
    node_b.dial(dial_target).context("node B dial node A")?;

    // Drive both nodes until each has connected, exchanged identify, and
    // completed a ping with the other.
    let mut observed_a = Observed::default();
    let mut observed_b = Observed::default();

    let drive = async {
        loop {
            tokio::select! {
                event = node_a.select_next_some() => {
                    record_event(event, &peer_b, &mut observed_a)?;
                }
                event = node_b.select_next_some() => {
                    record_event(event, &peer_a, &mut observed_b)?;
                }
            }

            if observed_a.complete() && observed_b.complete() {
                break;
            }
        }

        anyhow::Ok(())
    };

    timeout(TEST_TIMEOUT, drive)
        .await
        .context("timed out before both nodes connected, identified and pinged")??;

    Ok(())
}
