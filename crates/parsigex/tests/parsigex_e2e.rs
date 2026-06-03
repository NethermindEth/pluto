//! End-to-end partial signature exchange test.
//!
//! Four nodes connect over real (loopback TCP) libp2p, each signs a shared
//! message with its own threshold-BLS share, and broadcasts the partial
//! signature through the ParSigEx protocol. One node then aggregates the
//! threshold of partials it received *over the network* and verifies the
//! result against the group public key.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, swarm::SwarmEvent};
use pluto_core::{
    signeddata::SignedRandao,
    types::{Duty, DutyType, ParSignedDataSet, PubKey, SlotNumber},
};
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PrivateKey, PublicKey, Signature},
};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use pluto_parsigex::{self as parsigex, DutyGater, Event, Handle, Verifier};
use pluto_testutil::random::{generate_insecure_k1_key, generate_test_bls_key};
use tokio::{
    spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const NODES: usize = 4;
const THRESHOLD: usize = 3;
const EPOCH: u64 = 1;
const SLOT: u64 = 32;
const MSG: &[u8] = b"pluto parsigex e2e partial signature";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Threshold key material dealt for the test cluster.
struct ClusterKey {
    group_pub: PublicKey,
    group_pub_core: PubKey,
    shares: HashMap<u64, PrivateKey>,
}

impl ClusterKey {
    /// Deals a fresh group key into [`NODES`] shares with a [`THRESHOLD`].
    fn deal() -> Result<Self> {
        let secret = generate_test_bls_key(42);
        let group_pub = BlstImpl
            .secret_to_public_key(&secret)
            .context("failed to derive group public key")?;
        let total = u64::try_from(NODES).context("node count should fit u64")?;
        let threshold = u64::try_from(THRESHOLD).context("threshold should fit u64")?;
        let shares = BlstImpl
            .threshold_split(&secret, total, threshold)
            .context("failed to split group secret into shares")?;
        let group_pub_core = PubKey::new(group_pub);

        Ok(Self {
            group_pub,
            group_pub_core,
            shares,
        })
    }
}

/// A built node together with everything needed to drive and verify it.
struct NodeBundle {
    node: Node<parsigex::Behaviour>,
    handle: Handle,
    share_idx: u64,
    share_priv: PrivateKey,
}

/// A spawned node: its swarm runs on a task; control happens over channels.
struct RunningNode {
    handle: Handle,
    share_idx: u64,
    share_priv: PrivateKey,
    dial_tx: mpsc::UnboundedSender<Vec<Multiaddr>>,
    stop_tx: oneshot::Sender<()>,
    join: JoinHandle<Result<()>>,
}

/// A partial signature observed on the wire: (receiving node, share,
/// signature).
type ReceivedPartial = (usize, u64, Signature);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parsigex_threshold_round_trip() -> Result<()> {
    let mut harness = Harness::start()?;
    harness.connect().await?;
    let broadcasts = harness.broadcast_all()?;

    // Node 0 holds share 1; it must collect the threshold of *other* nodes'
    // partials purely from the network before it can aggregate.
    let received = harness.collect_partials(0).await?;
    ensure!(
        received.len() == THRESHOLD,
        "node 0 should receive exactly {THRESHOLD} partials, got {}",
        received.len()
    );
    ensure!(
        !received.contains_key(&1),
        "node 0 must not receive its own share (index 1)"
    );

    harness.aggregate_and_verify(&received)?;
    await_broadcasts(broadcasts).await?;
    harness.shutdown().await
}

/// Owns a running parsigex cluster and drives the end-to-end flow.
struct Harness {
    cluster: ClusterKey,
    peer_ids: Vec<PeerId>,
    running: Vec<RunningNode>,
    conn_rx: mpsc::UnboundedReceiver<(usize, PeerId)>,
    listen_rx: mpsc::UnboundedReceiver<(usize, Multiaddr)>,
    recv_rx: mpsc::UnboundedReceiver<ReceivedPartial>,
}

impl Harness {
    /// Deals a key, builds [`NODES`] nodes and starts their swarm loops.
    fn start() -> Result<Self> {
        let cluster = ClusterKey::deal()?;
        let (bundles, peer_ids) = NodeBuilder::new(&cluster)?.build_all()?;

        let (conn_tx, conn_rx) = mpsc::unbounded_channel();
        let (listen_tx, listen_rx) = mpsc::unbounded_channel();
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let sinks = EventSinks {
            conn_tx,
            listen_tx,
            recv_tx,
        };
        let running = spawn_nodes(bundles, &sinks);

        Ok(Self {
            cluster,
            peer_ids,
            running,
            conn_rx,
            listen_rx,
            recv_rx,
        })
    }

    /// Connects every node to every peer over a full mesh.
    async fn connect(&mut self) -> Result<()> {
        let listen_addrs = with_timeout(
            self.recv_listen_addrs(),
            "timed out waiting for listen addresses",
        )
        .await?;
        self.dial_full_mesh(&listen_addrs)?;
        with_timeout(
            self.recv_connections(),
            "timed out waiting for libp2p connections",
        )
        .await
    }

    /// Drains listen-address events until every node has reported one.
    async fn recv_listen_addrs(&mut self) -> Result<Vec<Multiaddr>> {
        let mut addrs = vec![None; NODES];
        while addrs.iter().any(Option::is_none) {
            let (index, addr) = self
                .listen_rx
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
    }

    /// Dials a full mesh: each node dials every peer with a higher index.
    fn dial_full_mesh(&self, listen_addrs: &[Multiaddr]) -> Result<()> {
        for (index, node) in self.running.iter().enumerate() {
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

    /// Drains connection events until every node has connected to all peers.
    async fn recv_connections(&mut self) -> Result<()> {
        let mut seen = vec![HashSet::<PeerId>::new(); NODES];
        while seen
            .iter()
            .any(|peers| peers.len() < NODES.saturating_sub(1))
        {
            let (index, peer_id) = self
                .conn_rx
                .recv()
                .await
                .context("connection event channel closed")?;
            if index < NODES && self.peer_ids.contains(&peer_id) {
                seen[index].insert(peer_id);
            }
        }

        Ok(())
    }

    /// Each node signs [`MSG`] with its share and broadcasts it via ParSigEx.
    fn broadcast_all(&self) -> Result<Vec<JoinHandle<parsigex::Result<u64>>>> {
        let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Randao);
        let mut tasks = Vec::with_capacity(self.running.len());

        for node in &self.running {
            let signature = BlstImpl
                .sign(&node.share_priv, MSG)
                .context("failed to sign with share")?;
            let partial = SignedRandao::new_partial(EPOCH, signature, node.share_idx);
            let mut data_set = ParSignedDataSet::new();
            data_set.insert(self.cluster.group_pub_core, partial);

            let task = broadcast_partial(node.handle.clone(), duty.clone(), data_set);
            tasks.push(spawn(task));
        }

        Ok(tasks)
    }

    /// Collects partials addressed to `receiver` until the threshold is met.
    async fn collect_partials(&mut self, receiver: usize) -> Result<HashMap<u64, Signature>> {
        with_timeout(
            self.recv_threshold_partials(receiver),
            "timed out collecting partial signatures",
        )
        .await
    }

    /// Drains received partials addressed to `receiver` until the threshold is
    /// met.
    async fn recv_threshold_partials(
        &mut self,
        receiver: usize,
    ) -> Result<HashMap<u64, Signature>> {
        let mut partials = HashMap::new();
        while partials.len() < THRESHOLD {
            let (index, share_idx, signature) = self
                .recv_rx
                .recv()
                .await
                .context("received partial channel closed")?;
            if index == receiver {
                partials.insert(share_idx, signature);
            }
        }

        Ok(partials)
    }

    /// Aggregates `partials` and verifies the result against the group key.
    fn aggregate_and_verify(&self, partials: &HashMap<u64, Signature>) -> Result<()> {
        let group_sig = BlstImpl
            .threshold_aggregate(partials)
            .context("threshold aggregation of received partials failed")?;
        BlstImpl
            .verify(&self.cluster.group_pub, MSG, &group_sig)
            .context("aggregated signature did not verify against the group public key")
    }

    /// Stops every node and waits for its swarm task to finish.
    async fn shutdown(self) -> Result<()> {
        for node in self.running {
            node.stop_tx
                .send(())
                .ok()
                .context("failed to signal node to stop")?;
            node.join.await.context("swarm task panicked")??;
        }

        Ok(())
    }
}

/// Awaits `future`, mapping an elapsed [`TEST_TIMEOUT`] to `msg`.
async fn with_timeout<F, T>(future: F, msg: &'static str) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    timeout(TEST_TIMEOUT, future).await.context(msg)?
}

/// Builds [`NODES`] parsigex nodes over loopback TCP that share one cluster
/// key.
struct NodeBuilder<'a> {
    cluster: &'a ClusterKey,
    keys: Vec<k256::SecretKey>,
    peer_ids: Vec<PeerId>,
}

impl<'a> NodeBuilder<'a> {
    /// Generates node identities for a [`NODES`]-sized cluster.
    fn new(cluster: &'a ClusterKey) -> Result<Self> {
        let keys = (0..NODES)
            .map(|index| generate_insecure_k1_key(u8::try_from(index).expect("node index fits u8")))
            .collect::<Vec<_>>();
        let peer_ids = keys
            .iter()
            .map(|key| peer_id_from_key(key.public_key()))
            .collect::<Result<Vec<_>, _>>()
            .context("failed to derive peer IDs")?;

        Ok(Self {
            cluster,
            keys,
            peer_ids,
        })
    }

    /// Builds the node at `index`, holding share `index + 1`.
    fn build_node(&self, index: usize, key: k256::SecretKey) -> Result<NodeBundle> {
        let peer_id = self.peer_ids[index];
        let p2p_context = P2PContext::new(self.peer_ids.clone());

        let verifier: Verifier = Arc::new(|_duty, _pubkey, _data| Box::pin(async { Ok(()) }));
        let duty_gater: DutyGater = Arc::new(|duty: &Duty| duty.duty_type != DutyType::Unknown);
        let config = parsigex::Config::new(peer_id, p2p_context.clone(), verifier, duty_gater)
            .with_timeout(Duration::from_secs(10));
        let (behaviour, handle) = parsigex::Behaviour::new(config);

        let node = Node::new_server(
            P2PConfig::default(),
            key,
            NodeType::TCP,
            false,
            p2p_context,
            None,
            move |builder, _keypair| builder.with_inner(behaviour),
        )
        .context("failed to build node")?;

        let one_based = index.checked_add(1).context("share index overflow")?;
        let share_idx = u64::try_from(one_based).context("share index fits u64")?;
        let share_priv = *self
            .cluster
            .shares
            .get(&share_idx)
            .with_context(|| format!("missing share for index {share_idx}"))?;

        Ok(NodeBundle {
            node,
            handle,
            share_idx,
            share_priv,
        })
    }

    /// Builds every node, returning the bundles and the cluster peer IDs.
    fn build_all(self) -> Result<(Vec<NodeBundle>, Vec<PeerId>)> {
        let mut bundles = Vec::with_capacity(self.keys.len());
        for (index, key) in self.keys.iter().cloned().enumerate() {
            bundles.push(self.build_node(index, key)?);
        }

        Ok((bundles, self.peer_ids))
    }
}

/// Event sinks every node's swarm loop forwards into.
#[derive(Clone)]
struct EventSinks {
    conn_tx: mpsc::UnboundedSender<(usize, PeerId)>,
    listen_tx: mpsc::UnboundedSender<(usize, Multiaddr)>,
    recv_tx: mpsc::UnboundedSender<ReceivedPartial>,
}

/// Spawns each node's swarm loop, forwarding listen/connection/receive events.
fn spawn_nodes(bundles: Vec<NodeBundle>, sinks: &EventSinks) -> Vec<RunningNode> {
    let mut running = Vec::with_capacity(bundles.len());

    for (index, bundle) in bundles.into_iter().enumerate() {
        let (dial_tx, dial_rx) = mpsc::unbounded_channel::<Vec<Multiaddr>>();
        let (stop_tx, stop_rx) = oneshot::channel();
        let join = spawn(run_swarm(
            bundle.node,
            index,
            sinks.clone(),
            dial_rx,
            stop_rx,
        ));

        running.push(RunningNode {
            handle: bundle.handle,
            share_idx: bundle.share_idx,
            share_priv: bundle.share_priv,
            dial_tx,
            stop_tx,
            join,
        });
    }

    running
}

/// Drives one node's swarm until stopped, dialing on request and forwarding
/// listen, connection and received-partial events to `sinks`.
async fn run_swarm(
    mut node: Node<parsigex::Behaviour>,
    index: usize,
    sinks: EventSinks,
    mut dial_rx: mpsc::UnboundedReceiver<Vec<Multiaddr>>,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<()> {
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
                        let _ = sinks.listen_tx.send((index, address));
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        let _ = sinks.conn_tx.send((index, peer_id));
                    }
                    SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(Event::Received {
                        data_set,
                        ..
                    })) => {
                        for data in data_set.inner().values() {
                            if let Ok(signature) = data.signed_data.signature() {
                                let _ = sinks.recv_tx.send((index, data.share_idx, signature));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Broadcasts one partial signature set through ParSigEx and waits for the
/// terminal outcome.
async fn broadcast_partial(
    handle: Handle,
    duty: Duty,
    data_set: ParSignedDataSet,
) -> parsigex::Result<u64> {
    handle.broadcast_and_wait(duty, data_set).await
}

/// Waits for every broadcast task to report a successful ParSigEx send.
async fn await_broadcasts(tasks: Vec<JoinHandle<parsigex::Result<u64>>>) -> Result<()> {
    for (idx, task) in tasks.into_iter().enumerate() {
        let result = timeout(TEST_TIMEOUT, task)
            .await
            .with_context(|| format!("broadcast task {idx} timed out"))?
            .with_context(|| format!("broadcast task {idx} panicked"))?;
        result.with_context(|| format!("node {idx} broadcast failed"))?;
    }

    Ok(())
}
