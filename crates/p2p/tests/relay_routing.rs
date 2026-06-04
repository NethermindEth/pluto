//! End-to-end test that two isolated nodes connect through a Pluto relay.
//!
//! A Pluto relay server runs on loopback TCP. Node A reserves a circuit on the
//! relay; node B is told only A's `/p2p-circuit` address (it never learns A's
//! direct address), so the only way it can reach A is via the relay. The test
//! asserts the relay routes the circuit (`CircuitReqAccepted` for B → A) and
//! that B actually establishes a connection to A over it — i.e. the noise
//! handshake bytes flowed through the relay. This proves the relay carries real
//! peer-to-peer traffic, not just that its HTTP endpoint answers.

use std::time::Duration;

use anyhow::{Context as _, Result};
use k256::{SecretKey, elliptic_curve::rand_core::OsRng};
use libp2p::{
    Multiaddr, PeerId,
    futures::StreamExt,
    multiaddr::Protocol,
    relay,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
};
use tokio::{
    spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

/// Overall test deadline for any single await.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimal client behaviour: just the relay client needed for circuit routing.
#[derive(NetworkBehaviour)]
struct RelayClientBehaviour {
    relay: relay::client::Behaviour,
}

/// Relay-side events the test cares about.
enum RelayEvent {
    /// A peer's reservation was accepted.
    Reservation(PeerId),
    /// A circuit was accepted, routing `src` to `dst`.
    Circuit { src: PeerId, dst: PeerId },
}

/// Drives the relay server: reports its first listen address, accepted
/// reservations, and accepted circuits.
fn spawn_relay(
    mut relay_node: Node<relay::Behaviour>,
    listen_tx: oneshot::Sender<Multiaddr>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    mut stop_rx: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    spawn(async move {
        let mut listen_tx = Some(listen_tx);
        loop {
            tokio::select! {
                event = relay_node.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if let Some(tx) = listen_tx.take() {
                            tx.send(address).ok();
                        }
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        relay::Event::ReservationReqAccepted { src_peer_id, .. },
                    )) => {
                        event_tx.send(RelayEvent::Reservation(src_peer_id)).ok();
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                        relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id },
                    )) => {
                        event_tx
                            .send(RelayEvent::Circuit {
                                src: src_peer_id,
                                dst: dst_peer_id,
                            })
                            .ok();
                    }
                    _ => {}
                },
                _ = &mut stop_rx => break,
            }
        }
    })
}

/// Drives the destination node: dials the relay, then reserves a circuit once
/// the relay connection is established.
fn spawn_reserving_node(
    mut node: Node<RelayClientBehaviour>,
    relay_addr: Multiaddr,
    circuit_addr: Multiaddr,
    mut stop_rx: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    spawn(async move {
        node.dial(relay_addr).ok();
        let mut reserved = false;
        loop {
            tokio::select! {
                event = node.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event
                        && !reserved
                    {
                        reserved = true;
                        node.listen_on(circuit_addr.clone()).ok();
                    }
                }
                _ = &mut stop_rx => break,
            }
        }
    })
}

/// Drives the source node: dials the destination's circuit address and reports
/// the peer id of every connection it establishes.
fn spawn_dialing_node(
    mut node: Node<RelayClientBehaviour>,
    dst_addr: Multiaddr,
    established_tx: mpsc::UnboundedSender<PeerId>,
    mut stop_rx: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    spawn(async move {
        node.dial(dst_addr).ok();
        loop {
            tokio::select! {
                event = node.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        established_tx.send(peer_id).ok();
                    }
                }
                _ = &mut stop_rx => break,
            }
        }
    })
}

/// Builds the relay server node listening on a loopback TCP port.
fn build_relay() -> Result<Node<relay::Behaviour>> {
    let key = SecretKey::random(&mut OsRng);
    let cfg = P2PConfig::builder()
        .with_tcp_addrs(vec!["127.0.0.1:0".to_string()])
        .build();
    let node = Node::<relay::Behaviour>::new_server(
        cfg,
        key,
        NodeType::TCP,
        false,
        P2PContext::default(),
        None,
        |builder, keypair| {
            builder.with_inner(relay::Behaviour::new(
                keypair.public().to_peer_id(),
                relay::Config::default(),
            ))
        },
    )?;
    Ok(node)
}

/// Builds a relay client node.
fn build_client() -> Result<Node<RelayClientBehaviour>> {
    let key = SecretKey::random(&mut OsRng);
    let node = Node::<RelayClientBehaviour>::new(
        P2PConfig::default(),
        key,
        NodeType::TCP,
        false,
        P2PContext::default(),
        |builder, _keypair, relay_client| {
            builder.with_inner(RelayClientBehaviour {
                relay: relay_client,
            })
        },
    )?;
    Ok(node)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn isolated_nodes_connect_through_relay() -> Result<()> {
    let relay_node = build_relay()?;
    let relay_peer_id = *relay_node.local_peer_id();

    let (listen_tx, listen_rx) = oneshot::channel::<Multiaddr>();
    let (relay_event_tx, mut relay_event_rx) = mpsc::unbounded_channel::<RelayEvent>();
    let (relay_stop_tx, relay_stop_rx) = oneshot::channel::<()>();
    let relay_task = spawn_relay(relay_node, listen_tx, relay_event_tx, relay_stop_rx);

    let relay_listen_addr = timeout(TEST_TIMEOUT, listen_rx)
        .await
        .context("timed out waiting for relay listen address")?
        .context("relay listen channel closed")?;
    let relay_addr = relay_listen_addr.with(Protocol::P2p(relay_peer_id));
    let circuit_listen_addr = relay_addr.clone().with(Protocol::P2pCircuit);

    // Destination node A reserves a circuit on the relay.
    let dst_node = build_client()?;
    let dst_peer_id = *dst_node.local_peer_id();
    let (dst_stop_tx, dst_stop_rx) = oneshot::channel::<()>();
    let dst_task = spawn_reserving_node(
        dst_node,
        relay_addr.clone(),
        circuit_listen_addr,
        dst_stop_rx,
    );

    // Wait until A's reservation is in place before B tries to reach it.
    timeout(TEST_TIMEOUT, async {
        while let Some(event) = relay_event_rx.recv().await {
            if let RelayEvent::Reservation(peer) = event
                && peer == dst_peer_id
            {
                return Ok(());
            }
        }
        anyhow::bail!("relay event channel closed before reservation");
    })
    .await
    .context("timed out waiting for destination reservation")??;

    // Source node B is told ONLY A's circuit address, so it must use the relay.
    let dst_circuit_addr = relay_addr
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(dst_peer_id));
    let src_node = build_client()?;
    let src_peer_id = *src_node.local_peer_id();
    let (established_tx, mut established_rx) = mpsc::unbounded_channel::<PeerId>();
    let (src_stop_tx, src_stop_rx) = oneshot::channel::<()>();
    let src_task = spawn_dialing_node(src_node, dst_circuit_addr, established_tx, src_stop_rx);

    // Expect the relay to route B → A, and B to establish the relayed connection.
    timeout(TEST_TIMEOUT, async {
        let mut circuit_routed = false;
        let mut connected_to_dst = false;
        while !(circuit_routed && connected_to_dst) {
            tokio::select! {
                Some(event) = relay_event_rx.recv() => {
                    if let RelayEvent::Circuit { src, dst } = event
                        && src == src_peer_id
                        && dst == dst_peer_id
                    {
                        circuit_routed = true;
                    }
                }
                Some(peer) = established_rx.recv() => {
                    if peer == dst_peer_id {
                        connected_to_dst = true;
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("timed out waiting for relayed connection")??;

    // Reaching here means both conditions held: the relay accepted the B → A
    // circuit and B established the relayed connection to A.

    // Shutdown.
    src_stop_tx.send(()).ok();
    src_task.await.context("source task panicked")?;
    dst_stop_tx.send(()).ok();
    dst_task.await.context("destination task panicked")?;
    relay_stop_tx.send(()).ok();
    relay_task.await.context("relay task panicked")?;

    Ok(())
}
