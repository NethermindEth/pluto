//! End-to-end test that ParSigEx rejects a cryptographically invalid partial.
//!
//! Two nodes connect over real (loopback TCP) libp2p. A real threshold-BLS key
//! is dealt; the receiver runs a genuine verifier that checks each received
//! partial signature against the signer's public share. The sender broadcasts
//! one valid partial (correctly signed over the agreed message) and one invalid
//! partial (a well-formed BLS signature over a *different* message). The test
//! asserts the receiver surfaces the valid one as `Received` and rejects the
//! invalid one as `Error` (`InvalidPartialSignature`) — it is never delivered.
//!
//! This exercises the real ParSigEx verify-and-reject path (`do_recv` →
//! `Failure::InvalidPartialSignature`), not a no-op verifier, so it proves
//! Byzantine protection against forged partials at the exchange layer.

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, ensure};
use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, swarm::SwarmEvent};
use pluto_core::{
    signeddata::SignedRandao,
    types::{Duty, DutyType, ParSignedData, ParSignedDataSet, PubKey, SlotNumber},
};
use pluto_crypto::{
    blst_impl::BlstImpl,
    tbls::Tbls,
    types::{PrivateKey, PublicKey},
};
use pluto_p2p::{
    behaviours::pluto::PlutoBehaviourEvent,
    config::P2PConfig,
    p2p::{Node, NodeType},
    p2p_context::P2PContext,
    peer::peer_id_from_key,
};
use pluto_parsigex::{self as parsigex, DutyGater, Event, Failure, Handle, Verifier, VerifyError};
use pluto_testutil::random::{generate_insecure_k1_key, generate_test_bls_key};
use tokio::{
    spawn,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const NODES: usize = 2;
const THRESHOLD: usize = 2;
const RECEIVER: usize = 0;
const SENDER: usize = 1;
/// The sender is node index 1, so it holds the 1-based share index 2.
const SENDER_SHARE: u64 = 2;
const EPOCH: u64 = 1;
const SLOT: u64 = 32;
/// The message the cluster agrees to sign for this duty.
const MSG: &[u8] = b"pluto parsigex agreed signing root";
/// A different message; a partial over this must be rejected for the duty.
const WRONG_MSG: &[u8] = b"pluto parsigex tampered signing root";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Threshold key material dealt for the test cluster.
struct ClusterKey {
    group_pub_core: PubKey,
    shares: HashMap<u64, PrivateKey>,
    public_shares: HashMap<u64, PublicKey>,
}

impl ClusterKey {
    fn deal() -> Result<Self> {
        let secret = generate_test_bls_key(42);
        let group_pub = BlstImpl
            .secret_to_public_key(&secret)
            .context("failed to derive group public key")?;
        let total = u64::try_from(NODES).context("node count fits u64")?;
        let threshold = u64::try_from(THRESHOLD).context("threshold fits u64")?;
        let shares = BlstImpl
            .threshold_split(&secret, total, threshold)
            .context("failed to split group secret into shares")?;

        let mut public_shares = HashMap::with_capacity(shares.len());
        for (share_idx, share_priv) in &shares {
            let share_pub = BlstImpl
                .secret_to_public_key(share_priv)
                .context("failed to derive public share")?;
            public_shares.insert(*share_idx, share_pub);
        }

        Ok(Self {
            group_pub_core: PubKey::new(group_pub),
            shares,
            public_shares,
        })
    }
}

/// An event observed on a node's swarm loop.
enum Observed {
    Received { node: usize, share_idx: u64 },
    Rejected { node: usize, error: Failure },
}

/// A spawned node: its swarm runs on a task; control happens over channels.
struct RunningNode {
    handle: Handle,
    dial_tx: mpsc::UnboundedSender<Vec<Multiaddr>>,
    stop_tx: oneshot::Sender<()>,
    join: JoinHandle<Result<()>>,
}

/// Sinks the swarm loop forwards events into.
#[derive(Clone)]
struct EventSinks {
    listen_tx: mpsc::UnboundedSender<(usize, Multiaddr)>,
    conn_tx: mpsc::UnboundedSender<(usize, PeerId)>,
    observed_tx: mpsc::UnboundedSender<Observed>,
}

/// A verifier that always accepts (for the sender, which never receives here).
fn accept_all_verifier() -> Verifier {
    Arc::new(|_duty, _pubkey, _data| Box::pin(async { Ok(()) }))
}

/// A verifier that checks each partial against its public share over [`MSG`].
fn share_verifier(public_shares: HashMap<u64, PublicKey>) -> Verifier {
    let public_shares = Arc::new(public_shares);
    Arc::new(move |_duty, _pubkey, data: ParSignedData| {
        let public_shares = public_shares.clone();
        Box::pin(async move {
            let signature = data
                .signed_data
                .signature()
                .map_err(|e| VerifyError::Other(e.to_string()))?;
            let public_share = public_shares
                .get(&data.share_idx)
                .ok_or(VerifyError::InvalidShareIndex)?;
            BlstImpl
                .verify(public_share, MSG, &signature)
                .map_err(|e| VerifyError::Other(e.to_string()))?;
            Ok(())
        })
    })
}

/// Builds the parsigex node at `index` with the given verifier.
fn build_node(
    index: usize,
    key: k256::SecretKey,
    peer_ids: &[PeerId],
    verifier: Verifier,
) -> Result<(Node<parsigex::Behaviour>, Handle)> {
    let peer_id = peer_ids[index];
    let p2p_context = P2PContext::new(peer_ids.to_vec());
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

    Ok((node, handle))
}

/// Drives one node's swarm until stopped, forwarding events into `sinks`.
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
            event = node.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    sinks.listen_tx.send((index, address)).ok();
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    sinks.conn_tx.send((index, peer_id)).ok();
                }
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(Event::Received {
                    data_set,
                    ..
                })) => {
                    for data in data_set.inner().values() {
                        sinks
                            .observed_tx
                            .send(Observed::Received {
                                node: index,
                                share_idx: data.share_idx,
                            })
                            .ok();
                    }
                }
                SwarmEvent::Behaviour(PlutoBehaviourEvent::Inner(Event::Error { error, .. })) => {
                    sinks
                        .observed_tx
                        .send(Observed::Rejected { node: index, error })
                        .ok();
                }
                _ => {}
            },
        }
    }
    Ok(())
}

/// Builds a partial signature set: `share` signs `message`, tagged `share_idx`.
fn partial_set(
    cluster: &ClusterKey,
    share: &PrivateKey,
    share_idx: u64,
    message: &[u8],
) -> Result<ParSignedDataSet> {
    let signature = BlstImpl
        .sign(share, message)
        .context("failed to sign with share")?;
    let partial = SignedRandao::new_partial(EPOCH, signature, share_idx);
    let mut data_set = ParSignedDataSet::new();
    data_set.insert(cluster.group_pub_core, partial);
    Ok(data_set)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parsigex_rejects_invalid_partial_signature() -> Result<()> {
    let cluster = ClusterKey::deal()?;
    let sender_share = *cluster
        .shares
        .get(&SENDER_SHARE)
        .context("missing sender share")?;

    let keys = (0..NODES)
        .map(|index| generate_insecure_k1_key(u8::try_from(index).expect("node index fits u8")))
        .collect::<Vec<_>>();
    let peer_ids = keys
        .iter()
        .map(|key| peer_id_from_key(key.public_key()))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to derive peer IDs")?;

    let (listen_tx, mut listen_rx) = mpsc::unbounded_channel::<(usize, Multiaddr)>();
    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<(usize, PeerId)>();
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel::<Observed>();
    let sinks = EventSinks {
        listen_tx,
        conn_tx,
        observed_tx,
    };

    let verifiers = [
        share_verifier(cluster.public_shares.clone()),
        accept_all_verifier(),
    ];
    let mut running = Vec::with_capacity(NODES);
    for (index, (key, verifier)) in keys.into_iter().zip(verifiers).enumerate() {
        let (node, handle) = build_node(index, key, &peer_ids, verifier)?;
        let (dial_tx, dial_rx) = mpsc::unbounded_channel::<Vec<Multiaddr>>();
        let (stop_tx, stop_rx) = oneshot::channel();
        let join = spawn(run_swarm(node, index, sinks.clone(), dial_rx, stop_rx));
        running.push(RunningNode {
            handle,
            dial_tx,
            stop_tx,
            join,
        });
    }

    // Collect both listen addresses, then connect the two nodes.
    let mut addrs = [None::<Multiaddr>, None::<Multiaddr>];
    while addrs.iter().any(Option::is_none) {
        let (index, address) = timeout(TEST_TIMEOUT, listen_rx.recv())
            .await
            .context("timed out waiting for listen addresses")?
            .context("listen channel closed")?;
        if addrs[index].is_none() {
            addrs[index] = Some(address);
        }
    }
    let sender_addr = addrs[SENDER]
        .clone()
        .context("missing sender listen addr")?;
    running[RECEIVER]
        .dial_tx
        .send(vec![sender_addr])
        .context("failed to queue dial")?;

    let mut connected = [false, false];
    while !connected.iter().all(|c| *c) {
        let (index, _peer) = timeout(TEST_TIMEOUT, conn_rx.recv())
            .await
            .context("timed out waiting for connections")?
            .context("connection channel closed")?;
        connected[index] = true;
    }

    let duty = Duty::new(SlotNumber::new(SLOT), DutyType::Randao);

    // 1. A valid partial must be received.
    let valid = partial_set(&cluster, &sender_share, SENDER_SHARE, MSG)?;
    running[SENDER]
        .handle
        .broadcast_and_wait(duty.clone(), valid)
        .await
        .context("failed to broadcast valid partial")?;
    let first = timeout(TEST_TIMEOUT, observed_rx.recv())
        .await
        .context("timed out waiting for the valid partial")?
        .context("observed channel closed")?;
    match first {
        Observed::Received { node, share_idx } => {
            ensure!(node == RECEIVER, "valid partial observed on node {node}");
            ensure!(
                share_idx == SENDER_SHARE,
                "valid partial had share index {share_idx}, want {SENDER_SHARE}",
            );
        }
        Observed::Rejected { error, .. } => {
            anyhow::bail!("valid partial was rejected: {error}");
        }
    }

    // 2. An invalid partial (signed over a different message) must be rejected.
    let invalid = partial_set(&cluster, &sender_share, SENDER_SHARE, WRONG_MSG)?;
    running[SENDER]
        .handle
        .broadcast_and_wait(duty.clone(), invalid)
        .await
        .context("failed to broadcast invalid partial")?;
    let second = timeout(TEST_TIMEOUT, observed_rx.recv())
        .await
        .context("timed out waiting for the invalid partial outcome")?
        .context("observed channel closed")?;
    match second {
        Observed::Rejected { node, error } => {
            ensure!(node == RECEIVER, "rejection observed on node {node}");
            ensure!(
                matches!(error, Failure::InvalidPartialSignature(_)),
                "invalid partial rejected for the wrong reason: {error}",
            );
        }
        Observed::Received { share_idx, .. } => {
            anyhow::bail!("invalid partial (share {share_idx}) was accepted, not rejected");
        }
    }

    for node in running {
        node.stop_tx
            .send(())
            .ok()
            .context("failed to signal node to stop")?;
        node.join.await.context("swarm task panicked")??;
    }
    Ok(())
}
