//! DKG partial-signature exchanger.
//!
//! # Design
//!
//! The [`Exchanger`] coordinates partial-signature exchange during the DKG
//! ceremony.  It wraps the [`pluto_parsigex`] network layer to broadcast and
//! receive partial signatures, accumulates them in an in-memory store, and
//! notifies callers when all peers have contributed their share for every
//! distributed validator (DV).
//!
//! ## Sig types
//!
//! DKG reuses the `parsigex` wire protocol but encodes the exchange round in
//! the `Duty.slot` field, with `DutyType::Signature` for all rounds.
//!
//! | Constant                 | Slot  | Purpose                                      |
//! |--------------------------|-------|----------------------------------------------|
//! | [`SIG_LOCK`]             | 101   | Lock-hash partial signatures                 |
//! | [`SIG_VALIDATOR_REG`]    | 102   | Validator-registration partial signatures    |
//! | [`SIG_DEPOSIT_DATA`]     | 200+N | Deposit-data partial sigs (one per amount N) |
//!
//! These slot values are part of the wire protocol and **must not change**.
//!
//! ## Architecture
//!
//! ```text
//! exchange(sig_type, set)
//!   │
//!   ├─► store_set(slot, set) ──► entries[(slot,pk)] ──► threshold? ──► sig_type_data[slot][pk]
//!   │                                                                        │
//!   ├─► handle.broadcast(duty, set) ──► parsigex swarm                 notify.notify_waiters()
//!   │                                         │                              │
//!   │                              subscriber(duty, set)                     │
//!   │                                   │                                    │
//!   │                              store_set(slot, set) ─────────────────────┘
//!   │
//!   └─► loop { check sig_type_data[slot].len() == expected_dvs; notify.notified().await }
//! ```

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use libp2p::PeerId;
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use pluto_core::{
    deadline::Deadliner,
    parsigdb::memory::{MemDB, internal_subscriber, threshold_subscriber},
    types::{Duty, DutyType, ParSignedData, ParSignedDataSet, PubKey, SlotNumber},
};
use pluto_parsigex::{Handle, ReceivedSub, received_subscriber};

/// Numeric identifier for a DKG signature exchange round, encoded as
/// `Duty.slot`.
pub type SigType = u64;

/// Slot value for lock-hash signature exchange.
/// Must not change — part of the wire protocol.
pub const SIG_LOCK: SigType = 101;

/// Slot value for validator-registration signature exchange.
/// Must not change — part of the wire protocol.
pub const SIG_VALIDATOR_REG: SigType = 102;

/// Base slot value for deposit-data signature exchange.
/// Partial deposits use `SIG_DEPOSIT_DATA + N` for each distinct amount N.
/// Must not change — part of the wire protocol.
pub const SIG_DEPOSIT_DATA: SigType = 200;

/// Accumulated partial-signature data keyed first by sig type (slot) then by
/// public key.
///
/// Matches Go's `sigTypeStore
/// map[sigType]map[core.PubKey][]core.ParSignedData`.
pub type SigTypeStore = HashMap<SigType, HashMap<PubKey, Vec<ParSignedData>>>;

/// Shared store of threshold-reached partial signatures with a wakeup notifier.
///
/// `exchange()` sleeps on `notify` and checks `inner` on each wake-up.
#[derive(Debug, Clone)]
pub struct DataByPubkey {
    /// Accumulated data once threshold is reached for each (sig_type, pubkey)
    /// pair.
    pub inner: Arc<Mutex<SigTypeStore>>,
    /// Notified whenever new data is merged into `inner`.
    pub notify: Arc<Notify>,
}

impl Default for DataByPubkey {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            notify: Arc::new(Notify::new()),
        }
    }
}

type DutyGaterFn = Arc<dyn Fn(&Duty) -> bool + Send + Sync + 'static>;

/// Errors returned by exchanger operations.
#[derive(Debug, thiserror::Error)]
pub enum ExchangerError {
    /// The cancellation token was triggered while waiting.
    #[error("exchanger cancelled")]
    Cancelled,
    /// Received a threshold callback for an unrecognised sig type.
    #[error("unrecognised sig type {0}")]
    UnrecognisedSigType(SigType),
    /// The underlying partial-signature database returned an error.
    #[error("sigdb: {0}")]
    SigDB(#[from] pluto_core::parsigdb::memory::MemDBError),
}

/// Coordinates partial-signature exchange between DKG participants.
pub struct Exchanger {
    /// Broadcast handle for the parsigex swarm.
    pub handle: Handle,
    /// In-memory partial-signature database.
    pub sigdb: Arc<Mutex<MemDB>>,
    /// Set of recognised sig types for this exchanger instance.
    pub sig_types: HashSet<SigType>,
    /// Threshold-reached data used by `exchange()` to detect completion.
    pub sig_data: DataByPubkey,
    /// Gate function; returns true for duties this exchanger should process.
    pub duty_gater_fn: DutyGaterFn,
    /// Cancellation token forwarded to internal components.
    pub ct: CancellationToken,
}

/// Deadliner that never expires any duty, used during DKG where slot-based
/// expiry does not apply.
struct NoopDeadliner;

#[async_trait]
impl Deadliner for NoopDeadliner {
    async fn add(&self, _duty: Duty) -> bool {
        true
    }

    fn c(&self) -> Option<tokio::sync::mpsc::Receiver<Duty>> {
        None
    }
}

impl Exchanger {
    /// Creates a new exchanger and wires up the three core subscriptions:
    ///
    /// 1. `sigdb.subscribe_internal` → `handle.broadcast` (send own sigs to
    ///    peers)
    /// 2. `sigdb.subscribe_threshold` → `push_psigs` (accumulate and notify)
    /// 3. `handle.subscribe` → `sigdb.store_external` (store received peer
    ///    sigs)
    pub async fn new(
        ct: CancellationToken,
        handle: Handle,
        peers: Vec<PeerId>,
        sig_types: Vec<SigType>,
    ) -> Self {
        // Partial signature roots not known yet, so skip verification in parsigex,
        // rather verify before we aggregate.
        let st: HashSet<SigType> = sig_types.iter().copied().collect();

        let duty_gater_fn: DutyGaterFn = {
            let st = st.clone();
            Arc::new(move |duty: &Duty| {
                if duty.duty_type != DutyType::Signature {
                    return false;
                }

                if st.contains(&SIG_DEPOSIT_DATA) && duty.slot.inner() >= SIG_DEPOSIT_DATA {
                    return true;
                }

                st.contains(&duty.slot.inner())
            })
        };

        // threshold is len(peers) to wait until we get all the partial sigs from all
        // the peers per DV
        let threshold = u64::try_from(peers.len()).expect("usize fits in u64");
        let sigdb = Arc::new(Mutex::new(MemDB::new(
            ct.clone(),
            threshold,
            Arc::new(NoopDeadliner),
        )));
        let sig_data = DataByPubkey::default();

        // Wiring core workflow components

        {
            let handle_clone = handle.clone();
            let sub = internal_subscriber(move |duty, set| {
                let handle = handle_clone.clone();
                async move {
                    if let Err(e) = handle.broadcast(duty, set).await {
                        warn!(error = %e, "Failed to broadcast partial signatures during DKG");
                    }
                    Ok(())
                }
            });
            sigdb.lock().await.subscribe_internal(sub).await;
        }

        {
            let duty_gater = duty_gater_fn.clone();
            let sig_data_clone = sig_data.clone();
            let sub = threshold_subscriber(move |duty, set| {
                let duty_gater = duty_gater.clone();
                let sig_data = sig_data_clone.clone();
                async move {
                    if let Err(e) = push_psigs(&duty_gater, &sig_data, duty, set).await {
                        warn!(error = %e, "push_psigs failed");
                    }
                    Ok(())
                }
            });
            sigdb.lock().await.subscribe_threshold(sub).await;
        }

        {
            let sigdb_clone = Arc::clone(&sigdb);
            let sub: ReceivedSub = received_subscriber(move |duty, set| {
                let sigdb = sigdb_clone.clone();
                async move {
                    if let Err(e) = sigdb.lock().await.store_external(&duty, &set).await {
                        warn!(error = %e, "Failed to store external partial signatures");
                    }
                }
            });
            handle.subscribe(sub).await;
        }

        Exchanger {
            handle,
            sigdb,
            sig_types: st,
            sig_data,
            duty_gater_fn,
            ct,
        }
    }

    /// Exchanges partial signatures of the given sig type among DKG
    /// participants.
    ///
    /// Stores the local node's partial signatures, broadcasts them to peers,
    /// then waits until every peer has contributed their share for every DV
    /// in `set`. Returns a map of public key → all partial signatures (one
    /// per participant).
    pub async fn exchange(
        &self,
        sig_type: SigType,
        set: ParSignedDataSet,
    ) -> Result<HashMap<PubKey, Vec<ParSignedData>>, ExchangerError> {
        // Start the process by storing current peer's ParSignedDataSet
        let duty = Duty::new_signature_duty(SlotNumber::new(sig_type));

        {
            let sigdb = self.sigdb.lock().await;
            sigdb.store_internal(&duty, &set).await?;
        }

        let expected_dvs = set.inner().len();

        loop {
            // Create the notified() future before checking state so we cannot
            // miss a notification that fires between the check and the await.
            let notified = self.sig_data.notify.notified();

            {
                let inner = self.sig_data.inner.lock().await;
                if let Some(data) = inner.get(&sig_type) {
                    // We are done when we have ParSignedData of all the DVs from each peer
                    if data.len() == expected_dvs {
                        return Ok(data.clone());
                    }
                }
            }

            tokio::select! {
                biased;
                _ = self.ct.cancelled() => return Err(ExchangerError::Cancelled),
                _ = notified => {}
            }
        }
    }
}

/// Writes partial signature data obtained from peers into the sig data store.
async fn push_psigs(
    duty_gater_fn: &DutyGaterFn,
    sig_data: &DataByPubkey,
    duty: Duty,
    set: HashMap<PubKey, Vec<ParSignedData>>,
) -> Result<(), ExchangerError> {
    let sig_type = duty.slot.inner();

    if !duty_gater_fn(&duty) {
        return Err(ExchangerError::UnrecognisedSigType(sig_type));
    }

    {
        let mut inner = sig_data.inner.lock().await;
        let entry = inner.entry(sig_type).or_insert_with(HashMap::new);
        for (pk, psigs) in set {
            entry.insert(pk, psigs);
        }
    }

    sig_data.notify.notify_waiters();

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::TcpListener, sync::Arc, time::Duration};

    use anyhow::Context as _;
    use futures::StreamExt as _;
    use libp2p::{Multiaddr, swarm::SwarmEvent};
    use pluto_core::types::{DutyType, ParSignedData, ParSignedDataSet, PubKey, Signature};
    use pluto_p2p::{
        config::P2PConfig,
        p2p::{Node, NodeType},
        p2p_context::P2PContext,
        peer::peer_id_from_key,
    };
    use pluto_parsigex::{Behaviour as ParsexBehaviour, Config as ParsexConfig};
    use pluto_testutil::random::generate_insecure_k1_key;
    use rand::{Rng as _, RngCore as _};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::{Exchanger, SIG_DEPOSIT_DATA, SIG_LOCK, SIG_VALIDATOR_REG, SigTypeStore};

    fn available_tcp_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    async fn wait_for_connections(
        conn_rx: &mut mpsc::UnboundedReceiver<libp2p::PeerId>,
        expected_count: usize,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut seen = std::collections::HashSet::new();
            while seen.len() < expected_count {
                let peer_id = conn_rx
                    .recv()
                    .await
                    .context("connection event channel closed")?;
                seen.insert(peer_id);
            }
            anyhow::Ok(())
        })
        .await
        .context("timed out waiting for libp2p connections")?
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exchanger() -> anyhow::Result<()> {
        const DVS: usize = 3;
        const NODES: usize = 4;

        let sig_types = vec![SIG_LOCK, SIG_VALIDATOR_REG, SIG_DEPOSIT_DATA];

        // Create pubkeys for each DV
        let pubkeys: Vec<PubKey> = (0..DVS)
            .map(|_| {
                let mut bytes = [0u8; 48];
                rand::thread_rng().fill_bytes(&mut bytes);
                PubKey::from(bytes)
            })
            .collect();

        // Build expected_data: for each pubkey, partial sigs from all NODES
        let mut expected_data: HashMap<PubKey, Vec<ParSignedData>> = HashMap::new();
        for pk in &pubkeys {
            let psigs: Vec<ParSignedData> = (0..NODES)
                .map(|j| {
                    let mut bytes = [0u8; 96];
                    rand::thread_rng().fill(&mut bytes[..]);
                    Signature::new_partial(Signature::new(bytes), (j + 1) as u64)
                })
                .collect();
            expected_data.insert(*pk, psigs);
        }

        // Build data_to_be_sent: for each node index, its ParSignedDataSet
        let mut data_to_be_sent: Vec<ParSignedDataSet> = vec![ParSignedDataSet::new(); NODES];
        for (pk, psigs) in &expected_data {
            for psig in psigs {
                let node_idx = usize::try_from(psig.share_idx - 1).expect("share_idx fits usize");
                data_to_be_sent[node_idx].insert(*pk, psig.clone());
            }
        }

        // Create keys and peer_ids
        let keys: Vec<_> = (0..u8::try_from(NODES).expect("NODES fits u8"))
            .map(generate_insecure_k1_key)
            .collect();
        let peer_ids: Vec<libp2p::PeerId> = keys
            .iter()
            .map(|k| peer_id_from_key(k.public_key()))
            .collect::<Result<_, _>>()?;
        let ports: Vec<u16> = (0..NODES)
            .map(|_| available_tcp_port())
            .collect::<anyhow::Result<_>>()?;

        // Create nodes and collect handles
        let mut nodes = Vec::with_capacity(NODES);
        let mut handles = Vec::with_capacity(NODES);

        for (i, key) in keys.into_iter().enumerate() {
            let p2p_context = P2PContext::new(peer_ids.clone());

            let verifier: pluto_parsigex::Verifier =
                Arc::new(|_duty, _pk, _psig| Box::pin(async { Ok(()) }));
            let duty_gater: pluto_parsigex::DutyGater =
                Arc::new(|duty: &pluto_core::types::Duty| duty.duty_type == DutyType::Signature);

            let config = ParsexConfig::new(peer_ids[i], p2p_context.clone(), verifier, duty_gater);
            let (behaviour, handle) = ParsexBehaviour::new(config);

            let node = Node::new_server(
                P2PConfig::default(),
                key,
                NodeType::TCP,
                false,
                p2p_context,
                None,
                move |builder, _key| builder.with_inner(behaviour),
            )?;

            handles.push(handle);
            nodes.push(node);
        }

        // Listen on assigned ports
        for (i, node) in nodes.iter_mut().enumerate() {
            let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", ports[i]).parse()?;
            node.listen_on(addr)?;
        }

        // Spawn swarm event loops; each node dials all nodes with higher index
        let mut conn_rxs: Vec<mpsc::UnboundedReceiver<libp2p::PeerId>> = Vec::with_capacity(NODES);

        for (i, mut node) in nodes.into_iter().enumerate() {
            let (conn_tx, conn_rx) = mpsc::unbounded_channel::<libp2p::PeerId>();
            conn_rxs.push(conn_rx);

            let dial_targets: Vec<Multiaddr> = (i + 1..NODES)
                .map(|j| {
                    format!("/ip4/127.0.0.1/tcp/{}", ports[j])
                        .parse::<Multiaddr>()
                        .expect("valid multiaddr")
                })
                .collect();

            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                for target in dial_targets {
                    let _ = node.dial(target);
                }
                loop {
                    let event = node.select_next_some().await;
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        let _ = conn_tx.send(peer_id);
                    }
                }
            });
        }

        // Wait for each node to see all NODES-1 peers connected
        for conn_rx in &mut conn_rxs {
            wait_for_connections(conn_rx, NODES - 1).await?;
        }

        // Create one Exchanger per node
        let ct = CancellationToken::new();
        let mut exchangers: Vec<Arc<Exchanger>> = Vec::with_capacity(NODES);
        for handle in handles {
            let ex = Exchanger::new(ct.clone(), handle, peer_ids.clone(), sig_types.clone()).await;
            exchangers.push(Arc::new(ex));
        }

        // Run concurrent exchanges: for each (node, sig_type) pair, spawn a task
        let mut join_set = tokio::task::JoinSet::new();
        for (node_idx, ex) in exchangers.iter().enumerate() {
            for &sig_type in &sig_types {
                let ex = Arc::clone(ex);
                let set = data_to_be_sent[node_idx].clone();
                join_set.spawn(async move {
                    let data = ex.exchange(sig_type, set).await.expect("exchange failed");
                    (sig_type, data)
                });
            }
        }

        // Collect results into actual: one entry per sig_type (last writer wins,
        // all nodes return equivalent data for each sig_type)
        let actual: SigTypeStore = join_set.join_all().await.into_iter().collect();

        // Assert all expected sig types arrived (matches the Go test assertions).
        // The Go reflect.DeepEqual is intentionally discarded there — we only
        // verify presence, DV count, and share count per DV.
        for &sig_type in &sig_types {
            let data = actual
                .get(&sig_type)
                .with_context(|| format!("missing sig_type {sig_type} from received data"))?;
            assert_eq!(data.len(), DVS, "sig_type {sig_type}: wrong DV count");
            for (pk, psigs) in data {
                let mut got: Vec<u64> = psigs.iter().map(|p| p.share_idx).collect();
                got.sort_unstable();
                let mut want: Vec<u64> = (1..=NODES as u64).collect();
                want.sort_unstable();
                assert_eq!(
                    got, want,
                    "sig_type {sig_type} pk {pk}: wrong share indices"
                );
            }
        }
        assert_eq!(actual.len(), sig_types.len());

        Ok(())
    }
}
