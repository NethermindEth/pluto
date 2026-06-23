//! End-to-end test for the peerinfo protocol over a real libp2p network.
//!
//! Spawns a small cluster of swarms that each run only the peerinfo
//! [`Behaviour`], connects them in a full mesh over loopback TCP, and asserts
//! that every node receives the peer info (version, lock hash, nickname) of
//! every other node across a live connection. This goes beyond the in-crate
//! protobuf round-trip unit tests: it proves the information actually travels a
//! negotiated libp2p stream and surfaces as a behaviour event.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, futures::StreamExt, identity::Keypair, noise,
    swarm::SwarmEvent, tcp, yamux,
};
use pluto_peerinfo::{Behaviour, Config, Event, LocalPeerInfo};
use tokio::{
    spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

/// Number of nodes in the test cluster.
const NODES: usize = 4;
/// Peer info exchange interval; short so the first exchange happens promptly.
const INTERVAL: Duration = Duration::from_millis(50);
/// Per-connection request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Keep idle connections alive long enough for the periodic exchange to run.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Overall test deadline for any single await.
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Cluster-wide version string shared by every node.
const CLUSTER_VERSION: &str = "v1.2.3";
/// Cluster-wide git hash shared by every node.
const CLUSTER_GIT_HASH: &str = "abc1234";
/// Cluster-wide lock hash shared by every node.
const CLUSTER_LOCK_HASH: [u8; 32] = [0xab; 32];

/// Nickname advertised by node `idx`; the only per-node-distinct field, used to
/// confirm that received info came from the expected sender.
fn nickname_of(idx: usize) -> String {
    format!("node-{idx}")
}

/// Peer info received by one node from one peer, flattened to the fields under
/// test so the test does not depend on the generated protobuf type.
struct ReceivedInfo {
    receiver: usize,
    sender: PeerId,
    nickname: String,
    version: String,
    lock_hash: Vec<u8>,
}

/// Handle to a spawned node: the dial queue, the stop signal, and the task.
struct NodeHandle {
    dial_tx: mpsc::UnboundedSender<Multiaddr>,
    stop_tx: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// Builds a swarm running only the peerinfo behaviour and starts listening on a
/// loopback TCP port.
fn build_swarm(keypair: Keypair, idx: usize) -> Result<Swarm<Behaviour>> {
    let local_info = LocalPeerInfo::new(
        CLUSTER_VERSION,
        CLUSTER_LOCK_HASH.to_vec(),
        CLUSTER_GIT_HASH,
        false,
        nickname_of(idx),
    );
    let config = Config::new(local_info)
        .with_interval(INTERVAL)
        .with_timeout(REQUEST_TIMEOUT);
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .context("failed to build tcp transport")?
        .with_behaviour(|key| Behaviour::new(key.public().to_peer_id(), config))
        .context("failed to build peerinfo behaviour")?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build();
    let listen_addr = "/ip4/127.0.0.1/tcp/0"
        .parse::<Multiaddr>()
        .context("failed to parse listen multiaddr")?;
    swarm
        .listen_on(listen_addr)
        .context("failed to start listening")?;
    Ok(swarm)
}

/// Spawns the swarm event loop for one node.
fn spawn_node(
    mut swarm: Swarm<Behaviour>,
    idx: usize,
    listen_tx: mpsc::UnboundedSender<(usize, Multiaddr)>,
    received_tx: mpsc::UnboundedSender<ReceivedInfo>,
) -> NodeHandle {
    let (dial_tx, mut dial_rx) = mpsc::unbounded_channel::<Multiaddr>();
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let task = spawn(async move {
        loop {
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        listen_tx.send((idx, address)).ok();
                    }
                    SwarmEvent::Behaviour(Event::Received { peer, info, .. }) => {
                        let received = ReceivedInfo {
                            receiver: idx,
                            sender: peer,
                            nickname: info.nickname,
                            version: info.pluto_version,
                            lock_hash: info.lock_hash.to_vec(),
                        };
                        received_tx.send(received).ok();
                    }
                    _ => {}
                },
                addr = dial_rx.recv() => {
                    if let Some(addr) = addr {
                        swarm.dial(addr).ok();
                    }
                }
                _ = &mut stop_rx => break,
            }
        }
    });
    NodeHandle {
        dial_tx,
        stop_tx,
        task,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connected_nodes_exchange_peer_info() -> Result<()> {
    let keypairs = (0..NODES)
        .map(|_| Keypair::generate_ed25519())
        .collect::<Vec<_>>();
    let peer_ids = keypairs
        .iter()
        .map(|k| k.public().to_peer_id())
        .collect::<Vec<_>>();
    let index_of = peer_ids
        .iter()
        .enumerate()
        .map(|(idx, peer)| (*peer, idx))
        .collect::<HashMap<PeerId, usize>>();

    let (listen_tx, mut listen_rx) = mpsc::unbounded_channel::<(usize, Multiaddr)>();
    let (received_tx, mut received_rx) = mpsc::unbounded_channel::<ReceivedInfo>();

    let mut handles = Vec::with_capacity(NODES);
    for (idx, keypair) in keypairs.into_iter().enumerate() {
        let swarm = build_swarm(keypair, idx)?;
        let handle = spawn_node(swarm, idx, listen_tx.clone(), received_tx.clone());
        handles.push(handle);
    }
    drop(listen_tx);
    drop(received_tx);

    // Collect one listen address per node before dialing.
    let mut addrs = vec![None::<Multiaddr>; NODES];
    let mut listening = 0usize;
    while listening < NODES {
        let next = timeout(TEST_TIMEOUT, listen_rx.recv())
            .await
            .context("timed out waiting for listen addresses")?
            .context("listen channel closed before all nodes listened")?;
        let (idx, address) = next;
        if addrs[idx].is_none() {
            addrs[idx] = Some(address);
            listening += 1;
        }
    }
    let addrs = addrs
        .into_iter()
        .enumerate()
        .map(|(idx, addr)| addr.with_context(|| format!("missing listen addr for node {idx}")))
        .collect::<Result<Vec<Multiaddr>>>()?;

    // Connect the cluster in a full mesh; one connection per pair is enough, as
    // both ends run the periodic exchange over it.
    for (i, handle) in handles.iter().enumerate() {
        for addr in addrs.iter().skip(i + 1) {
            handle
                .dial_tx
                .send(addr.clone())
                .context("failed to queue dial")?;
        }
    }

    // Collect exchanges until every ordered (receiver, sender) pair is covered.
    let expected_pairs = NODES * (NODES - 1);
    let mut latest = HashMap::<(usize, usize), ReceivedInfo>::new();
    let mut seen = HashSet::<(usize, usize)>::new();
    while seen.len() < expected_pairs {
        let received = timeout(TEST_TIMEOUT, received_rx.recv())
            .await
            .context("timed out waiting for peer info exchange")?
            .context("received channel closed prematurely")?;
        let sender = *index_of
            .get(&received.sender)
            .context("received info from an unknown peer")?;
        let key = (received.receiver, sender);
        seen.insert(key);
        latest.insert(key, received);
    }

    // Every node must have received the correct info from every other node.
    for receiver in 0..NODES {
        for sender in 0..NODES {
            if receiver == sender {
                continue;
            }
            let info = latest
                .get(&(receiver, sender))
                .with_context(|| format!("node {receiver} never received info from {sender}"))?;
            let want_nickname = nickname_of(sender);
            ensure!(
                info.nickname == want_nickname,
                "node {receiver} got nickname {:?} from node {sender}, want {want_nickname:?}",
                info.nickname,
            );
            ensure!(
                info.version == CLUSTER_VERSION,
                "node {receiver} got version {:?} from node {sender}, want {CLUSTER_VERSION:?}",
                info.version,
            );
            ensure!(
                info.lock_hash == CLUSTER_LOCK_HASH,
                "node {receiver} got unexpected lock hash from node {sender}",
            );
        }
    }

    for handle in handles {
        let NodeHandle {
            dial_tx,
            stop_tx,
            task,
        } = handle;
        drop(dial_tx);
        stop_tx.send(()).ok();
        task.await.context("node task panicked")?;
    }
    Ok(())
}
