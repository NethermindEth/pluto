//! End-to-end test for relay reservations over a real libp2p network.
//!
//! Starts a Pluto relay server (`Node<relay::Behaviour>`) on loopback TCP and a
//! handful of relay clients (`Node` with relay-client support). Each client
//! dials the relay and listens on its `/p2p-circuit` address, which requests a
//! reservation. The test asserts the relay accepts a reservation from every
//! client. This goes beyond the relay-server HTTP `/enr` test: it exercises the
//! actual libp2p circuit-reservation protocol end to end.

use std::{collections::HashSet, time::Duration};

use anyhow::{Context as _, Result, ensure};
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

/// Number of relay clients that reserve a circuit.
const CLIENTS: usize = 3;
/// Overall test deadline for any single await.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimal client behaviour: just the relay client needed to reserve a circuit.
#[derive(NetworkBehaviour)]
struct RelayClientBehaviour {
    relay: relay::client::Behaviour,
}

/// Drives the relay server: reports its first listen address and the peer id of
/// every accepted reservation.
fn spawn_relay(
    mut relay_node: Node<relay::Behaviour>,
    listen_tx: oneshot::Sender<Multiaddr>,
    reservation_tx: mpsc::UnboundedSender<PeerId>,
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
                        reservation_tx.send(src_peer_id).ok();
                    }
                    _ => {}
                },
                _ = &mut stop_rx => break,
            }
        }
    })
}

/// Drives one relay client: dials the relay, then reserves a circuit once the
/// relay connection is established.
fn spawn_client(
    mut client: Node<RelayClientBehaviour>,
    relay_addr: Multiaddr,
    circuit_addr: Multiaddr,
    mut stop_rx: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    spawn(async move {
        client.dial(relay_addr).ok();
        let mut reserved = false;
        loop {
            tokio::select! {
                event = client.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event
                        && !reserved
                    {
                        reserved = true;
                        client.listen_on(circuit_addr.clone()).ok();
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
async fn relay_accepts_client_reservations() -> Result<()> {
    let relay_node = build_relay()?;
    let relay_peer_id = *relay_node.local_peer_id();

    let (listen_tx, listen_rx) = oneshot::channel::<Multiaddr>();
    let (reservation_tx, mut reservation_rx) = mpsc::unbounded_channel::<PeerId>();
    let (relay_stop_tx, relay_stop_rx) = oneshot::channel::<()>();
    let relay_task = spawn_relay(relay_node, listen_tx, reservation_tx, relay_stop_rx);

    let relay_listen_addr = timeout(TEST_TIMEOUT, listen_rx)
        .await
        .context("timed out waiting for relay listen address")?
        .context("relay listen channel closed")?;
    let relay_addr = relay_listen_addr.with(Protocol::P2p(relay_peer_id));
    let circuit_addr = relay_addr.clone().with(Protocol::P2pCircuit);

    let mut client_ids = HashSet::<PeerId>::new();
    let mut client_tasks = Vec::with_capacity(CLIENTS);
    let mut client_stops = Vec::with_capacity(CLIENTS);
    for _ in 0..CLIENTS {
        let client = build_client()?;
        client_ids.insert(*client.local_peer_id());
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let task = spawn_client(client, relay_addr.clone(), circuit_addr.clone(), stop_rx);
        client_tasks.push(task);
        client_stops.push(stop_tx);
    }

    // Every client must obtain an accepted reservation on the relay.
    let mut reserved = HashSet::<PeerId>::new();
    while !client_ids.is_subset(&reserved) {
        let src = timeout(TEST_TIMEOUT, reservation_rx.recv())
            .await
            .context("timed out waiting for relay reservations")?
            .context("reservation channel closed prematurely")?;
        reserved.insert(src);
    }
    ensure!(
        client_ids.is_subset(&reserved),
        "not all clients reserved: clients={client_ids:?}, reserved={reserved:?}",
    );

    for stop in client_stops {
        stop.send(()).ok();
    }
    for task in client_tasks {
        task.await.context("client task panicked")?;
    }
    relay_stop_tx.send(()).ok();
    relay_task.await.context("relay task panicked")?;
    Ok(())
}
