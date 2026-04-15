//! Handles broadcasting of K1 signatures over the lock hash via the bcast
//! protocol.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use k256::SecretKey;
use libp2p::PeerId;
use pluto_p2p::peer::Peer;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::{
    bcast::{self, Component},
    dkgpb::v1::nodesigs::MsgNodeSig,
};

/// The message ID used for node signature broadcasts.
const NODE_SIG_MSG_ID: &str = "/charon/dkg/node_sig";

/// Error returned by [`NodeSigBcast`] operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Signing the lock hash with the local K1 key failed.
    #[error("k1 lock hash signature: {0}")]
    Sign(#[from] pluto_k1util::K1UtilError),

    /// Broadcasting or registering the broadcast message failed.
    #[error("k1 lock hash signature broadcast: {0}")]
    Broadcast(#[from] bcast::Error),

    /// The exchange was cancelled before all signatures were collected.
    #[error("cancelled")]
    Cancelled,

    /// The local node index cannot be represented as a u32.
    #[error("node index {0} exceeds u32 range")]
    NodeIndexOutOfRange(usize),
}

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Handles broadcasting of K1 signatures over the lock hash via the bcast
/// protocol.
pub struct NodeSigBcast {
    sigs: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    bcast: Component,
    node_idx: usize,
    lock_hash_tx: watch::Sender<Option<Vec<u8>>>,
}

impl NodeSigBcast {
    /// Returns a new instance, registering bcast handlers on `bcast_comp`.
    pub async fn new(peers: Vec<Peer>, node_idx: usize, bcast_comp: Component) -> Result<Self> {
        let sigs = Arc::new(Mutex::new(vec![None::<Vec<u8>>; peers.len()]));
        let (lock_hash_tx, lock_hash_rx) = watch::channel(None::<Vec<u8>>);

        let sigs_cb = Arc::clone(&sigs);
        let peers = Arc::new(peers);

        bcast_comp
            .register_message::<MsgNodeSig>(
                NODE_SIG_MSG_ID,
                Box::new(|_peer_id, _msg| Ok(())),
                Box::new(move |peer_id, _msg_id, msg| {
                    let peers = Arc::clone(&peers);
                    let lock_hash_rx = lock_hash_rx.clone();
                    let sigs = Arc::clone(&sigs_cb);
                    Box::pin(async move {
                        receive(peer_id, msg, node_idx, &peers, lock_hash_rx, &sigs).await
                    })
                }),
            )
            .await?;

        Ok(Self {
            sigs,
            bcast: bcast_comp,
            node_idx,
            lock_hash_tx,
        })
    }

    /// Exchanges K1 signatures over the lock hash with all peers.
    ///
    /// Signs `lock_hash` with `key`, broadcasts the signature to all peers, and
    /// polls until every peer's signature has been received and verified.
    /// Returns all collected signatures ordered by peer index.
    pub async fn exchange(
        self,
        key: &SecretKey,
        lock_hash: impl AsRef<[u8]>,
        token: CancellationToken,
    ) -> Result<Vec<Vec<u8>>> {
        let lock_hash = lock_hash.as_ref();

        let local_sig = pluto_k1util::sign(key, lock_hash)?.to_vec();

        // Make the lock hash available to incoming callbacks before broadcasting.
        // Only fails if all receivers are dropped, which cannot happen here.
        let _ = self.lock_hash_tx.send(Some(lock_hash.to_vec()));

        let peer_index =
            u32::try_from(self.node_idx).map_err(|_| Error::NodeIndexOutOfRange(self.node_idx))?;

        let bcast_data = MsgNodeSig {
            signature: local_sig.clone().into(),
            peer_index,
        };

        tracing::debug!("Exchanging node signatures");

        self.bcast.broadcast(NODE_SIG_MSG_ID, &bcast_data).await?;

        {
            let mut sigs = self.sigs.lock().unwrap_or_else(|e| e.into_inner());
            sigs[self.node_idx] = Some(local_sig);
        }

        let mut ticker = tokio::time::interval(Duration::from_millis(100));

        loop {
            tokio::select! {
                () = token.cancelled() => return Err(Error::Cancelled),
                _ = ticker.tick() => {
                    if let Some(all) = all_sigs(&self.sigs.lock().unwrap_or_else(|e| e.into_inner())) {
                        return Ok(all);
                    }
                }
            }
        }
    }
}

/// Returns a copy of all signatures if every slot is filled, otherwise `None`.
fn all_sigs(sigs: &[Option<Vec<u8>>]) -> Option<Vec<Vec<u8>>> {
    sigs.iter().cloned().collect()
}

/// Validates and stores an incoming node signature message.
///
/// Waits for the lock hash to become available via the watch channel before
/// verifying the signature.
async fn receive(
    peer_id: PeerId,
    msg: MsgNodeSig,
    node_idx: usize,
    peers: &[Peer],
    lock_hash_rx: watch::Receiver<Option<Vec<u8>>>,
    sigs: &Mutex<Vec<Option<Vec<u8>>>>,
) -> bcast::Result<()> {
    let peer_idx = usize::try_from(msg.peer_index).expect("peer_index out of usize range");

    if peer_idx == node_idx || peer_idx >= peers.len() {
        return Err(bcast::Error::InvalidPeerIndex(peer_id));
    }

    let pubkey = peers[peer_idx].public_key()?;

    let lock_hash = {
        let mut rx = lock_hash_rx.clone();
        let guard = rx
            .wait_for(|v| v.is_some())
            .await
            .map_err(|_| bcast::Error::MissingField("lock_hash"))?;
        guard
            .clone()
            .ok_or(bcast::Error::MissingField("lock_hash"))?
    };

    if !pluto_k1util::verify_65(&pubkey, &lock_hash, msg.signature.as_ref())? {
        return Err(bcast::Error::InvalidSignature(peer_id));
    }

    sigs.lock().unwrap_or_else(|e| e.into_inner())[peer_idx] = Some(msg.signature.to_vec());

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::TcpListener};

    use anyhow::Context as _;
    use futures::StreamExt as _;
    use libp2p::{Multiaddr, swarm::SwarmEvent};
    use pluto_p2p::{
        config::P2PConfig,
        p2p::{Node, NodeType},
        p2p_context::P2PContext,
        peer::{Peer, peer_id_from_key},
    };
    use pluto_testutil::random::generate_insecure_k1_key;
    use test_case::test_case;
    use tokio::{
        sync::{mpsc, oneshot, watch},
        task::JoinSet,
    };

    use crate::bcast::Behaviour;

    use super::*;

    fn make_peer(seed: u8, index: usize) -> (SecretKey, Peer) {
        let key = generate_insecure_k1_key(seed);
        let id = peer_id_from_key(key.public_key()).unwrap();
        let peer = Peer {
            id,
            addresses: vec![],
            index,
            name: format!("peer-{seed}"),
        };
        (key, peer)
    }

    #[test]
    fn all_sigs_returns_none_when_slot_empty() {
        assert!(all_sigs(&[None, Some(vec![1]), Some(vec![2])]).is_none());
        assert!(all_sigs(&[Some(vec![1]), None, Some(vec![2])]).is_none());
    }

    #[test]
    fn all_sigs_returns_vec_when_all_filled() {
        let result = all_sigs(&[Some(vec![1u8]), Some(vec![2u8])]).unwrap();
        assert_eq!(result, vec![vec![1u8], vec![2u8]]);
    }

    #[test]
    fn all_sigs_empty_input() {
        assert_eq!(all_sigs(&[]), Some(vec![]));
    }

    // Ports TestSigsCallbacks from charon/dkg/nodesigs_internal_test.go.
    // n=10 peers; peer_index 11 = n+1, 10 = n.
    #[test_case( 0, Some(vec![0u8; 32]), 65, "invalid peer index" ; "wrong_peer_index_equal_to_ours")]
    #[test_case(11, Some(vec![0u8; 32]), 65, "invalid peer index" ; "wrong_peer_index_more_than_operators")]
    #[test_case(10, Some(vec![0u8; 32]), 65, "invalid peer index" ; "wrong_peer_index_exactly_at_len")]
    #[test_case( 1, None,                65, "missing protobuf field: lock_hash" ; "missing_lock_hash")]
    #[test_case( 1, Some(vec![42u8; 32]), 65, "The signature recovery id byte 42 is invalid" ; "signature_verification_failed")]
    #[test_case( 1, Some(vec![42u8; 32]),  2, "The signature length is invalid: expected 65, actual 2" ; "malformed_signature")]
    #[tokio::test]
    async fn sigs_callbacks(
        peer_index: u32,
        lock_hash: Option<Vec<u8>>,
        sig_len: usize,
        expected_msg: &str,
    ) {
        const N: usize = 10;
        let peers: Vec<Peer> = (0..N)
            .map(|i| make_peer(u8::try_from(i).expect("The number fits into u8"), i).1)
            .collect();
        let (_, rx) = watch::channel(lock_hash);
        let sigs = Mutex::new(vec![None::<Vec<u8>>; N]);

        let msg = MsgNodeSig {
            signature: vec![42u8; sig_len].into(),
            peer_index,
        };

        let err = receive(peers[0].id, msg, 0, &peers, rx, &sigs)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(expected_msg),
            "expected '{expected_msg}' in '{err}'"
        );
    }

    #[tokio::test]
    async fn sigs_callbacks_ok() {
        let (_, peer0) = make_peer(0, 0);
        let (key1, peer1) = make_peer(1, 1);
        let peers = vec![peer0, peer1.clone()];
        let lock_hash = vec![42u8; 32];
        let (_, rx) = watch::channel(Some(lock_hash.clone()));
        let sigs = Mutex::new(vec![None::<Vec<u8>>; 2]);

        let sig = pluto_k1util::sign(&key1, &lock_hash).unwrap();
        let msg = MsgNodeSig {
            signature: sig.to_vec().into(),
            peer_index: 1,
        };

        receive(peer1.id, msg, 0, &peers, rx, &sigs).await.unwrap();

        let guard = sigs.lock().unwrap();
        assert_eq!(guard[1], Some(sig.to_vec()));
    }

    struct TestNode {
        node: Node<Behaviour>,
        addr: Multiaddr,
    }

    struct RunningNode {
        stop_tx: oneshot::Sender<()>,
        join: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    fn available_tcp_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    async fn wait_for_all_connections(
        conn_rx: &mut mpsc::UnboundedReceiver<(usize, PeerId)>,
        n: usize,
    ) -> anyhow::Result<()> {
        let mut seen = vec![HashSet::<PeerId>::new(); n];
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if seen.iter().all(|peers| peers.len() == n.saturating_sub(1)) {
                    return Ok(());
                }
                let (index, peer_id) = conn_rx.recv().await.context("connection channel closed")?;
                seen[index].insert(peer_id);
            }
        })
        .await
        .context("timed out waiting for connections")?
    }

    async fn spawn_swarm_tasks(
        mut nodes: Vec<TestNode>,
        conn_tx: mpsc::UnboundedSender<(usize, PeerId)>,
    ) -> anyhow::Result<Vec<RunningNode>> {
        for node in &mut nodes {
            node.node.listen_on(node.addr.clone())?;
        }

        let dial_targets: Vec<Vec<Multiaddr>> = (0..nodes.len())
            .map(|index| {
                nodes
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other > index)
                    .map(|(_, n)| n.addr.clone())
                    .collect()
            })
            .collect();

        let mut running = Vec::with_capacity(nodes.len());
        for (index, (test_node, targets)) in nodes.into_iter().zip(dial_targets).enumerate() {
            let mut node = test_node.node;
            let conn_tx = conn_tx.clone();
            let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

            let join = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                for target in targets {
                    node.dial(target)?;
                }
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        event = node.select_next_some() => {
                            if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                                let _ = conn_tx.send((index, peer_id));
                            }
                        }
                    }
                }
                Ok(())
            });

            running.push(RunningNode { stop_tx, join });
        }

        Ok(running)
    }

    async fn shutdown_swarm_tasks(tasks: Vec<RunningNode>) -> anyhow::Result<()> {
        for task in tasks {
            let _ = task.stop_tx.send(());
            task.join.await??;
        }
        Ok(())
    }

    // Ports `TestSigsExchange` from charon/dkg/nodesigs_internal_test.go.
    #[tokio::test]
    async fn test_sigs_exchange() -> anyhow::Result<()> {
        const N: usize = 7;

        let keys: Vec<SecretKey> = (0..N)
            .map(|i| generate_insecure_k1_key(u8::try_from(i).expect("N fits in u8")))
            .collect();
        let peer_ids: Vec<PeerId> = keys
            .iter()
            .map(|k| peer_id_from_key(k.public_key()))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let cluster_peers: Vec<Peer> = peer_ids
            .iter()
            .enumerate()
            .map(|(i, &id)| Peer {
                id,
                addresses: vec![],
                index: i,
                name: format!("peer-{i}"),
            })
            .collect();

        let ports = (0..N)
            .map(|_| available_tcp_port())
            .collect::<anyhow::Result<Vec<_>>>()?;

        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();

        let mut test_nodes = Vec::with_capacity(N);
        let mut nsig_list = Vec::with_capacity(N);

        for (index, key) in keys.iter().enumerate() {
            let p2p_context = P2PContext::new(peer_ids.clone());
            let (behaviour, component) =
                Behaviour::new(peer_ids.clone(), p2p_context.clone(), key.clone());
            let nsig = NodeSigBcast::new(cluster_peers.clone(), index, component).await?;
            nsig_list.push(nsig);

            let node = Node::new_server(
                P2PConfig::default(),
                key.clone(),
                NodeType::TCP,
                false,
                peer_ids.clone(),
                move |builder, _| builder.with_p2p_context(p2p_context).with_inner(behaviour),
            )?;

            let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", ports[index]).parse()?;
            test_nodes.push(TestNode { node, addr });
        }

        let running = spawn_swarm_tasks(test_nodes, conn_tx).await?;
        wait_for_all_connections(&mut conn_rx, N).await?;

        let lock_hash = [42u8; 32];
        let token = CancellationToken::new();
        let mut handles = JoinSet::new();

        for (i, nsig) in nsig_list.into_iter().enumerate() {
            let key = keys[i].clone();
            let token = token.clone();
            handles.spawn(async move { nsig.exchange(&key, lock_hash, token).await });
        }

        let results = tokio::time::timeout(Duration::from_secs(45), async {
            let mut results = Vec::with_capacity(N);
            while let Some(res) = handles.join_next().await {
                results.push(res??);
            }
            anyhow::Ok(results)
        })
        .await
        .context("exchange timed out")??;

        assert_eq!(results.len(), N);
        let first = &results[0];
        assert_eq!(first.len(), N);
        for sig in first {
            assert!(!sig.is_empty());
        }
        for result in &results[1..] {
            assert_eq!(result, first, "all nodes must collect identical signatures");
        }

        token.cancel();
        shutdown_swarm_tasks(running).await?;

        Ok(())
    }
}
