use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use anyhow::Context as _;
use futures::StreamExt as _;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::Index};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use pluto_testutil::random::generate_insecure_k1_key;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::{
    bcast,
    frost::run_frost_parallel,
    frostp2p::{FrostP2P, FrostP2PBehaviour, FrostP2PEvent, new_frost_p2p},
    share::Share,
};

const NODES: usize = 4;
const THRESHOLD: usize = 3;
const NUM_VALIDATORS: usize = 2;
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "TestBehaviourEvent")]
struct TestBehaviour {
    bcast: bcast::Behaviour,
    frost: FrostP2PBehaviour,
}

#[derive(Debug)]
enum TestBehaviourEvent {
    Bcast,
    Frost(FrostP2PEvent),
}

impl From<bcast::Event> for TestBehaviourEvent {
    fn from(_event: bcast::Event) -> Self {
        Self::Bcast
    }
}

impl From<FrostP2PEvent> for TestBehaviourEvent {
    fn from(event: FrostP2PEvent) -> Self {
        Self::Frost(event)
    }
}

struct LocalNode {
    transport: FrostP2P,
    node: Node<TestBehaviour>,
}

struct RunningNode {
    transport: FrostP2P,
    dial_tx: mpsc::UnboundedSender<Vec<Multiaddr>>,
    stop_tx: oneshot::Sender<()>,
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
}

#[derive(Default)]
struct FrostEventCounts {
    direct_sent: usize,
    direct_received: usize,
    round1_started: usize,
    round1_bcast_started: usize,
    round1_bcast_completed: usize,
    round1_direct_started: usize,
    round1_completed: usize,
    round2_started: usize,
    round2_bcast_started: usize,
    round2_bcast_completed: usize,
    round2_completed: usize,
    protocol_completed: usize,
}

impl FrostEventCounts {
    fn bump(count: &mut usize, label: &'static str) {
        *count = count.checked_add(1).expect(label);
    }

    fn is_complete(&self, expected_direct_events: usize) -> bool {
        self.direct_sent >= expected_direct_events
            && self.direct_received >= expected_direct_events
            && self.round1_started >= NODES
            && self.round1_bcast_started >= NODES
            && self.round1_bcast_completed >= NODES
            && self.round1_direct_started >= NODES
            && self.round1_completed >= NODES
            && self.round2_started >= NODES
            && self.round2_bcast_started >= NODES
            && self.round2_bcast_completed >= NODES
            && self.round2_completed >= NODES
            && self.protocol_completed >= NODES
    }

    fn record(
        &mut self,
        node_index: usize,
        event: FrostP2PEvent,
        expected_peer_count: usize,
    ) -> anyhow::Result<()> {
        match event {
            FrostP2PEvent::RoundStarted { round: 1 } => {
                Self::bump(&mut self.round1_started, "round 1 started count overflow");
            }
            FrostP2PEvent::RoundStarted { round: 2 } => {
                Self::bump(&mut self.round2_started, "round 2 started count overflow");
            }
            FrostP2PEvent::BroadcastStarted { round: 1 } => {
                Self::bump(
                    &mut self.round1_bcast_started,
                    "round 1 broadcast started count overflow",
                );
            }
            FrostP2PEvent::BroadcastStarted { round: 2 } => {
                Self::bump(
                    &mut self.round2_bcast_started,
                    "round 2 broadcast started count overflow",
                );
            }
            FrostP2PEvent::BroadcastCompleted { round: 1 } => {
                Self::bump(
                    &mut self.round1_bcast_completed,
                    "round 1 broadcast completed count overflow",
                );
            }
            FrostP2PEvent::BroadcastCompleted { round: 2 } => {
                Self::bump(
                    &mut self.round2_bcast_completed,
                    "round 2 broadcast completed count overflow",
                );
            }
            FrostP2PEvent::DirectSendStarted { peer_count } => {
                assert_eq!(peer_count, expected_peer_count);
                Self::bump(
                    &mut self.round1_direct_started,
                    "round 1 direct started count overflow",
                );
            }
            FrostP2PEvent::DirectSent { .. } => {
                Self::bump(&mut self.direct_sent, "direct sent count overflow");
            }
            FrostP2PEvent::DirectReceived { .. } => {
                Self::bump(&mut self.direct_received, "direct received count overflow");
            }
            FrostP2PEvent::RoundCompleted { round: 1 } => {
                Self::bump(
                    &mut self.round1_completed,
                    "round 1 completed count overflow",
                );
            }
            FrostP2PEvent::RoundCompleted { round: 2 } => {
                Self::bump(
                    &mut self.round2_completed,
                    "round 2 completed count overflow",
                );
            }
            FrostP2PEvent::ProtocolCompleted => {
                Self::bump(
                    &mut self.protocol_completed,
                    "protocol completed count overflow",
                );
            }
            FrostP2PEvent::DirectSendFailed { peer_id, error } => {
                anyhow::bail!("unexpected FROST P2P failure for {peer_id}: {error}");
            }
            FrostP2PEvent::BroadcastFailed { round, error } => {
                anyhow::bail!("unexpected FROST round {round} broadcast failure: {error}");
            }
            FrostP2PEvent::RoundStarted { round }
            | FrostP2PEvent::BroadcastStarted { round }
            | FrostP2PEvent::BroadcastCompleted { round }
            | FrostP2PEvent::RoundCompleted { round } => {
                anyhow::bail!("unexpected FROST round event from node {node_index}: {round}");
            }
        }

        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frost_p2p_full_dkg_round_trip() -> anyhow::Result<()> {
    let keys = (0..NODES)
        .map(|index| {
            generate_insecure_k1_key(u8::try_from(index).expect("test index should fit u8"))
        })
        .collect::<Vec<_>>();
    let peer_ids = keys
        .iter()
        .map(|key| peer_id_from_key(key.public_key()))
        .collect::<Result<Vec<_>, _>>()?;
    let peer_share_indices = peer_ids
        .iter()
        .enumerate()
        .map(|(index, peer_id)| {
            (
                *peer_id,
                u32::try_from(
                    index
                        .checked_add(1)
                        .expect("test share index should not overflow"),
                )
                .expect("test share index should fit u32"),
            )
        })
        .collect::<HashMap<_, _>>();

    let local_nodes = build_local_nodes(keys, &peer_ids, &peer_share_indices).await?;
    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();
    let (listen_tx, mut listen_rx) = mpsc::unbounded_channel();
    let (frost_event_tx, mut frost_event_rx) = mpsc::unbounded_channel();
    let running = spawn_nodes(local_nodes, conn_tx, listen_tx, frost_event_tx)?;

    let listen_addrs = wait_for_listen_addrs(&mut listen_rx).await?;
    send_dial_targets(&running, &listen_addrs)?;
    wait_for_connections(&mut conn_rx, &peer_ids).await?;

    let cancellation = CancellationToken::new();
    let node_shares = run_dkg(running, &mut frost_event_rx, cancellation.clone()).await?;
    cancellation.cancel();

    verify_returned_shares(&node_shares);

    Ok(())
}

async fn build_local_nodes(
    keys: Vec<k256::SecretKey>,
    peer_ids: &[PeerId],
    peer_share_indices: &HashMap<PeerId, u32>,
) -> anyhow::Result<Vec<LocalNode>> {
    let mut nodes = Vec::with_capacity(NODES);

    for (index, key) in keys.into_iter().enumerate() {
        let local_share_idx = u32::try_from(
            index
                .checked_add(1)
                .expect("test share index should not overflow"),
        )
        .expect("test share index should fit u32");
        let p2p_context = P2PContext::new(peer_ids.to_vec());
        let (bcast, bcast_comp) =
            bcast::Behaviour::new(peer_ids.to_vec(), p2p_context.clone(), key.clone());
        let (frost, mut frost_handle) = FrostP2PBehaviour::new(
            p2p_context.clone(),
            peer_ids.iter().copied(),
            peer_share_indices.clone(),
            local_share_idx,
            NUM_VALIDATORS,
        );
        let transport = new_frost_p2p(
            bcast_comp,
            &mut frost_handle,
            peer_share_indices,
            local_share_idx,
            THRESHOLD,
            NUM_VALIDATORS,
        )
        .await?;
        let behaviour = TestBehaviour { bcast, frost };
        let node = Node::new_server(
            P2PConfig::default(),
            key,
            NodeType::TCP,
            false,
            p2p_context,
            None,
            move |builder, _keypair| builder.with_inner(behaviour),
        )?;

        nodes.push(LocalNode { transport, node });
    }

    Ok(nodes)
}

fn spawn_nodes(
    nodes: Vec<LocalNode>,
    conn_tx: mpsc::UnboundedSender<(usize, PeerId)>,
    listen_tx: mpsc::UnboundedSender<(usize, Multiaddr)>,
    frost_event_tx: mpsc::UnboundedSender<(usize, FrostP2PEvent)>,
) -> anyhow::Result<Vec<RunningNode>> {
    let mut running = Vec::with_capacity(nodes.len());

    for (index, local) in nodes.into_iter().enumerate() {
        let transport = local.transport;
        let mut node = local.node;
        let conn_tx = conn_tx.clone();
        let listen_tx = listen_tx.clone();
        let frost_event_tx = frost_event_tx.clone();
        let (dial_tx, mut dial_rx) = mpsc::unbounded_channel::<Vec<Multiaddr>>();
        let (stop_tx, mut stop_rx) = oneshot::channel();

        let join = tokio::spawn(async move {
            node.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;

            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    Some(targets) = dial_rx.recv() => {
                        for target in targets {
                            node.dial(target)?;
                        }
                    }
                    event = node.select_next_some() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                let _ = listen_tx.send((index, address));
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                let _ = conn_tx.send((index, peer_id));
                            }
                            SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(
                                TestBehaviourEvent::Frost(event),
                            )) => {
                                let _ = frost_event_tx.send((index, event));
                            }
                            _ => {}
                        }
                    }
                }
            }

            anyhow::Ok(())
        });

        running.push(RunningNode {
            transport,
            dial_tx,
            stop_tx,
            join,
        });
    }

    Ok(running)
}

async fn wait_for_listen_addrs(
    listen_rx: &mut mpsc::UnboundedReceiver<(usize, Multiaddr)>,
) -> anyhow::Result<Vec<Multiaddr>> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mut addrs = vec![None; NODES];
        while addrs.iter().any(Option::is_none) {
            let (index, addr) = listen_rx
                .recv()
                .await
                .context("listen address channel closed")?;
            if index < NODES && addrs[index].is_none() {
                addrs[index] = Some(addr);
            }
        }

        addrs
            .into_iter()
            .map(|addr| addr.context("missing listen address"))
            .collect()
    })
    .await
    .context("timed out waiting for listen addresses")?
}

fn send_dial_targets(running: &[RunningNode], listen_addrs: &[Multiaddr]) -> anyhow::Result<()> {
    for (index, node) in running.iter().enumerate() {
        let targets = listen_addrs
            .iter()
            .enumerate()
            .filter(|(other, _)| *other > index)
            .map(|(_, addr)| addr.clone())
            .collect::<Vec<_>>();
        node.dial_tx
            .send(targets)
            .context("dial target channel closed")?;
    }

    Ok(())
}

async fn wait_for_connections(
    conn_rx: &mut mpsc::UnboundedReceiver<(usize, PeerId)>,
    expected_peers: &[PeerId],
) -> anyhow::Result<()> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mut seen = vec![HashSet::<PeerId>::new(); NODES];
        while seen
            .iter()
            .any(|peers| peers.len() < NODES.saturating_sub(1))
        {
            let (index, peer_id) = conn_rx
                .recv()
                .await
                .context("connection event channel closed")?;
            if index < NODES && expected_peers.contains(&peer_id) {
                seen[index].insert(peer_id);
            }
        }

        anyhow::Ok(())
    })
    .await
    .context("timed out waiting for libp2p connections")?
}

async fn run_dkg(
    running: Vec<RunningNode>,
    frost_event_rx: &mut mpsc::UnboundedReceiver<(usize, FrostP2PEvent)>,
    cancellation: CancellationToken,
) -> anyhow::Result<Vec<Vec<Share>>> {
    let mut dkg_tasks = Vec::with_capacity(running.len());
    let mut swarm_tasks = Vec::with_capacity(running.len());

    for (index, node) in running.into_iter().enumerate() {
        let cancellation = cancellation.clone();
        let share_idx = u32::try_from(
            index
                .checked_add(1)
                .expect("test share index should not overflow"),
        )
        .expect("test share index should fit u32");
        let mut transport = node.transport;
        dkg_tasks.push(tokio::spawn(async move {
            run_frost_parallel(
                cancellation,
                &mut transport,
                u32::try_from(NUM_VALIDATORS).expect("NUM_VALIDATORS should fit u32"),
                u32::try_from(NODES).expect("NODES should fit u32"),
                u32::try_from(THRESHOLD).expect("THRESHOLD should fit u32"),
                share_idx,
                "0",
            )
            .await
        }));
        swarm_tasks.push((node.stop_tx, node.join));
    }

    let shares = tokio::time::timeout(TEST_TIMEOUT, async {
        let mut node_shares = Vec::with_capacity(dkg_tasks.len());
        for task in dkg_tasks {
            node_shares.push(task.await.context("DKG task panicked")??);
        }
        anyhow::Ok(node_shares)
    })
    .await
    .context("timed out waiting for FROST DKG")??;

    wait_for_frost_p2p_events(frost_event_rx).await?;

    for (stop_tx, join) in swarm_tasks {
        let _ = stop_tx.send(());
        join.await.context("swarm task panicked")??;
    }

    Ok(shares)
}

async fn wait_for_frost_p2p_events(
    frost_event_rx: &mut mpsc::UnboundedReceiver<(usize, FrostP2PEvent)>,
) -> anyhow::Result<()> {
    let expected_direct_events = NODES
        .checked_mul(NODES.saturating_sub(1))
        .context("expected FROST event count overflow")?;

    tokio::time::timeout(TEST_TIMEOUT, async {
        let mut counts = FrostEventCounts::default();
        let expected_peer_count = NODES.saturating_sub(1);

        while !counts.is_complete(expected_direct_events) {
            let (node_index, event) = frost_event_rx
                .recv()
                .await
                .context("frost p2p event channel closed")?;
            counts.record(node_index, event, expected_peer_count)?;
        }

        anyhow::Ok(())
    })
    .await
    .context("timed out waiting for FROST P2P events")?
}

fn verify_returned_shares(node_shares: &[Vec<Share>]) {
    let msg = b"frost p2p full dkg round trip";
    assert_eq!(node_shares.len(), NODES);

    for shares in node_shares {
        assert_eq!(shares.len(), NUM_VALIDATORS);
    }

    for val_idx in 0..NUM_VALIDATORS {
        let pub_key = node_shares[0][val_idx].pub_key;
        let mut partials = HashMap::new();

        for (node_idx, shares) in node_shares.iter().enumerate() {
            assert_eq!(shares[val_idx].pub_key, pub_key);
            let mut share_ids = shares[val_idx]
                .public_shares
                .keys()
                .copied()
                .collect::<Vec<_>>();
            share_ids.sort_unstable();
            assert_eq!(share_ids, vec![1, 2, 3, 4]);

            if node_idx < THRESHOLD {
                let share_id = Index::try_from(
                    node_idx
                        .checked_add(1)
                        .expect("share index should not overflow"),
                )
                .expect("share index should fit Index");
                let sig = BlstImpl
                    .sign(&shares[val_idx].secret_share, msg)
                    .expect("partial signature should succeed");
                partials.insert(share_id, sig);
            }
        }

        let sig = BlstImpl
            .threshold_aggregate(&partials)
            .expect("threshold aggregation should succeed");
        BlstImpl
            .verify(&pub_key, msg, &sig)
            .expect("aggregated signature should verify");
    }
}
