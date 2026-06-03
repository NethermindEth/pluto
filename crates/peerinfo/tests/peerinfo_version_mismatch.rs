//! End-to-end test for peerinfo version-compatibility handling over libp2p.
//!
//! Two nodes connect over loopback TCP: one advertises a supported version, the
//! other an unsupported one. The test asserts the implemented
//! (Charon-equivalent) behaviour: peerinfo is informational, so a version
//! mismatch does **not** tear down the connection or abort the exchange —
//! instead the offending peer is flagged via the `version_support` gauge (0 =
//! incompatible, 1 = compatible), and the exchange still completes in both
//! directions without panicking.

use std::{collections::HashSet, time::Duration};

use anyhow::{Context as _, Result, ensure};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, futures::StreamExt, identity::Keypair, noise,
    swarm::SwarmEvent, tcp, yamux,
};
use pluto_p2p::name::peer_name;
use pluto_peerinfo::{Behaviour, Config, Event, LocalPeerInfo, metrics::PEERINFO_METRICS};
use tokio::{
    spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

/// A version whose minor matches the supported set (compatible).
const COMPATIBLE_VERSION: &str = "v1.5.0";
/// A version older than the supported set with no matching minor
/// (incompatible).
const INCOMPATIBLE_VERSION: &str = "v0.9.0";
/// Git hash matching the protocol's `^[0-9a-f]{7}$` validation regex.
const GIT_HASH: &str = "abc1234";
/// Cluster-wide lock hash shared by both nodes.
const LOCK_HASH: [u8; 32] = [0xab; 32];
/// Gauge value meaning "peer version supported".
const SUPPORTED: i64 = 1;
/// Gauge value meaning "peer version unsupported".
const UNSUPPORTED: i64 = 0;

/// Peer info exchange interval; short so the first exchange happens promptly.
const INTERVAL: Duration = Duration::from_millis(50);
/// Per-connection request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Keep idle connections alive long enough for the periodic exchange to run.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Overall test deadline for any single await.
const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Handle to a spawned node.
struct NodeHandle {
    dial_tx: mpsc::UnboundedSender<Multiaddr>,
    stop_tx: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// Builds a swarm running only the peerinfo behaviour, advertising `version`,
/// and starts listening on a loopback TCP port.
fn build_swarm(keypair: Keypair, version: &str, nickname: &str) -> Result<Swarm<Behaviour>> {
    let local_info = LocalPeerInfo::new(version, LOCK_HASH.to_vec(), GIT_HASH, false, nickname);
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

/// Spawns the swarm event loop, reporting its listen address and the index of
/// every peer it successfully exchanges info with.
fn spawn_node(
    mut swarm: Swarm<Behaviour>,
    idx: usize,
    listen_tx: mpsc::UnboundedSender<(usize, Multiaddr)>,
    received_tx: mpsc::UnboundedSender<(usize, PeerId)>,
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
                    SwarmEvent::Behaviour(Event::Received { peer, .. }) => {
                        received_tx.send((idx, peer)).ok();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incompatible_version_peer_is_flagged_without_dropping_exchange() -> Result<()> {
    let compatible_key = Keypair::generate_ed25519();
    let incompatible_key = Keypair::generate_ed25519();
    let compatible_id = compatible_key.public().to_peer_id();
    let incompatible_id = incompatible_key.public().to_peer_id();

    let (listen_tx, mut listen_rx) = mpsc::unbounded_channel::<(usize, Multiaddr)>();
    let (received_tx, mut received_rx) = mpsc::unbounded_channel::<(usize, PeerId)>();

    // Node 0 advertises a supported version, node 1 an unsupported one.
    let compatible_swarm = build_swarm(compatible_key, COMPATIBLE_VERSION, "compatible")?;
    let incompatible_swarm = build_swarm(incompatible_key, INCOMPATIBLE_VERSION, "incompatible")?;
    let node0 = spawn_node(compatible_swarm, 0, listen_tx.clone(), received_tx.clone());
    let node1 = spawn_node(
        incompatible_swarm,
        1,
        listen_tx.clone(),
        received_tx.clone(),
    );
    drop(listen_tx);
    drop(received_tx);

    // Collect both listen addresses.
    let mut addrs = [None::<Multiaddr>, None::<Multiaddr>];
    while addrs.iter().any(Option::is_none) {
        let (idx, address) = timeout(TEST_TIMEOUT, listen_rx.recv())
            .await
            .context("timed out waiting for listen addresses")?
            .context("listen channel closed before both nodes listened")?;
        if addrs[idx].is_none() {
            addrs[idx] = Some(address);
        }
    }
    let node1_addr = addrs[1].clone().context("missing listen addr for node 1")?;

    // One connection is enough; both ends run the periodic exchange over it.
    node0
        .dial_tx
        .send(node1_addr)
        .context("failed to queue dial")?;

    // Wait until each node has validated the other (both exchange directions).
    let mut seen = HashSet::<(usize, usize)>::new();
    while seen.len() < 2 {
        let (receiver, sender) = timeout(TEST_TIMEOUT, received_rx.recv())
            .await
            .context("timed out waiting for peer info exchange")?
            .context("received channel closed prematurely")?;
        let sender_idx = if sender == compatible_id {
            0
        } else if sender == incompatible_id {
            1
        } else {
            anyhow::bail!("received info from an unknown peer");
        };
        seen.insert((receiver, sender_idx));
    }

    // The exchange completed in both directions despite the mismatch: the
    // connection was neither rejected nor torn down (no crash, no panic).
    ensure!(
        seen.contains(&(0, 1)) && seen.contains(&(1, 0)),
        "expected a completed exchange in both directions, saw {seen:?}",
    );

    // The compatibility verdict is recorded on the per-peer gauge.
    let incompatible_support = PEERINFO_METRICS.version_support[&peer_name(&incompatible_id)].get();
    let compatible_support = PEERINFO_METRICS.version_support[&peer_name(&compatible_id)].get();
    ensure!(
        incompatible_support == UNSUPPORTED,
        "unsupported peer should be flagged 0, got {incompatible_support}",
    );
    ensure!(
        compatible_support == SUPPORTED,
        "supported peer should be flagged 1, got {compatible_support}",
    );

    for handle in [node0, node1] {
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
