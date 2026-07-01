use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use libp2p::{Multiaddr, PeerId, swarm::ConnectionId};
use tracing::error;

/// Maximum number of inactive peers retained in the [`PeerStore`].
///
/// Disconnected, non-cluster peers are evicted oldest-first once this many are
/// stored, bounding memory growth from connection churn by remote peers.
const MAX_INACTIVE_PEERS: usize = 1024;

/// Maximum number of listen addresses stored per peer (from the identify
/// protocol). `listen_addrs` is attacker-controlled in both content and
/// length; legitimate cluster peers advertise only a handful of addresses, so
/// this cap drops nothing real while bounding per-peer memory. Excess
/// addresses beyond the cap are discarded (the first `MAX_PEER_ADDRESSES` are
/// kept).
pub(crate) const MAX_PEER_ADDRESSES: usize = 32;

/// Global context shared across P2P components.
///
/// This struct provides thread-safe access to shared state including:
/// - Known cluster peer IDs (immutable after construction)
/// - Runtime peer connection state (mutable via `PeerStore`)
#[derive(Debug, Clone, Default)]
pub struct P2PContext {
    /// Local peer ID for this node, once known.
    local_peer_id: Arc<OnceLock<PeerId>>,
    /// Known cluster peer IDs. These are the peers that are part of the
    /// cluster and should be tracked with peer metrics (as opposed to
    /// relay metrics for unknown peers).
    known_peers: Arc<HashSet<PeerId>>,
    /// Peer store for tracking active/inactive peer connections.
    peer_store: Arc<RwLock<PeerStore>>,
}

impl P2PContext {
    /// Creates a new global context with the given known peers.
    pub fn new(known_peers: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            local_peer_id: Arc::default(),
            known_peers: Arc::new(known_peers.into_iter().collect()),
            peer_store: Arc::default(),
        }
    }

    /// Sets the local peer ID for this node.
    pub fn set_local_peer_id(&self, peer_id: PeerId) {
        if let Err(existing_peer_id) = self.local_peer_id.set(peer_id)
            && existing_peer_id != peer_id
        {
            error!(
                existing_peer_id = %existing_peer_id,
                new_peer_id = %peer_id,
                "ignoring attempt to reset local peer id"
            );
        }
    }

    /// Returns the local peer ID for this node, if known.
    pub fn local_peer_id(&self) -> Option<PeerId> {
        self.local_peer_id.get().copied()
    }

    /// Returns true if the peer is a known cluster peer.
    pub fn is_known_peer(&self, peer: &PeerId) -> bool {
        self.known_peers.contains(peer)
    }

    /// Returns the known peer IDs.
    pub fn known_peers(&self) -> &HashSet<PeerId> {
        &self.known_peers
    }

    /// Returns a read lock on the peer store.
    pub fn peer_store_lock(&self) -> RwLockReadGuard<'_, PeerStore> {
        self.peer_store.read().expect("Failed to read peer store")
    }

    /// Returns a write lock on the peer store.
    pub fn peer_store_write_lock(&self) -> RwLockWriteGuard<'_, PeerStore> {
        self.peer_store.write().expect("Failed to write peer store")
    }
}

/// Peer connection information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Peer {
    /// Peer ID.
    pub id: PeerId,

    /// Connection ID.
    pub connection_id: ConnectionId,

    /// Remote address of the connection.
    pub remote_addr: Multiaddr,
}

/// Peer store.
#[derive(Debug, Clone, Default)]
pub struct PeerStore {
    /// Active peers.
    active_peers: HashSet<Peer>,

    /// Inactive peers.
    inactive_peers: HashSet<Peer>,

    /// Insertion order of `inactive_peers`, oldest at the front. Used to evict
    /// the oldest entries once `MAX_INACTIVE_PEERS` is exceeded. Membership is
    /// kept consistent with `inactive_peers`.
    inactive_order: VecDeque<Peer>,

    /// Known addresses for each peer (populated from identify protocol).
    peer_addresses: HashMap<PeerId, Vec<Multiaddr>>,
}

impl PeerStore {
    /// Adds a peer to the peer store.
    pub fn add_peer(&mut self, peer: Peer) {
        if self.inactive_peers.remove(&peer) {
            self.inactive_order.retain(|p| p != &peer);
        }
        self.active_peers.insert(peer);
    }

    /// Marks a peer connection as inactive.
    ///
    /// `known_peers` is the set of cluster peer IDs; entries whose peer ID is
    /// in this set are never evicted by the `MAX_INACTIVE_PEERS` cap.
    pub fn remove_peer(&mut self, peer: Peer, known_peers: &HashSet<PeerId>) {
        self.active_peers.remove(&peer);

        // Avoid duplicate ordering entries if the same Peer is removed twice.
        if self.inactive_peers.insert(peer.clone()) {
            self.inactive_order.push_back(peer);
        }

        self.evict_inactive(known_peers);
    }

    /// Evicts oldest inactive, non-known peers until `inactive_peers` is within
    /// `MAX_INACTIVE_PEERS`. Known cluster peers are re-queued (kept) so they
    /// are never dropped. Bounded: each call scans at most
    /// `inactive_order.len()` entries.
    fn evict_inactive(&mut self, known_peers: &HashSet<PeerId>) {
        // Bound the number of scan iterations to the current queue length so a
        // queue made entirely of known peers cannot loop forever.
        let mut scanned = 0usize;
        let max_scan = self.inactive_order.len();
        while self.inactive_peers.len() > MAX_INACTIVE_PEERS && scanned < max_scan {
            scanned = scanned.saturating_add(1);
            let Some(candidate) = self.inactive_order.pop_front() else {
                break;
            };
            if known_peers.contains(&candidate.id) {
                // Never evict known cluster peers; keep them, re-queue at back.
                self.inactive_order.push_back(candidate);
                continue;
            }
            self.inactive_peers.remove(&candidate);
        }
    }

    /// Returns the active peers.
    pub fn peers<T: FromIterator<Peer>>(&self) -> T {
        self.active_peers.iter().cloned().collect()
    }

    /// Returns the inactive peers.
    pub fn inactive_peers<T: FromIterator<Peer>>(&self) -> T {
        self.inactive_peers.iter().cloned().collect()
    }

    /// Returns all peers.
    pub fn all_peers<T: FromIterator<Peer>>(&self) -> T {
        self.active_peers
            .iter()
            .chain(self.inactive_peers.iter())
            .cloned()
            .collect()
    }

    /// Returns the number of active peers.
    pub fn active_count(&self) -> usize {
        self.active_peers.len()
    }

    /// Returns the number of inactive peers.
    pub fn inactive_count(&self) -> usize {
        self.inactive_peers.len()
    }

    /// Returns all active connections to a specific peer.
    pub fn connections_to_peer(&self, peer_id: &PeerId) -> Vec<&Peer> {
        self.active_peers
            .iter()
            .filter(|p| &p.id == peer_id)
            .collect()
    }

    /// Sets the known addresses for a peer (from identify protocol).
    ///
    /// The address list is truncated to [`MAX_PEER_ADDRESSES`] before storing,
    /// because `addrs` is attacker-controlled and otherwise unbounded.
    pub fn set_peer_addresses(&mut self, peer_id: PeerId, mut addrs: Vec<Multiaddr>) {
        if addrs.len() > MAX_PEER_ADDRESSES {
            addrs.truncate(MAX_PEER_ADDRESSES);
        }
        self.peer_addresses.insert(peer_id, addrs);
    }

    /// Returns the known addresses for a peer.
    pub fn peer_addresses(&self, peer_id: &PeerId) -> Option<&Vec<Multiaddr>> {
        self.peer_addresses.get(peer_id)
    }

    /// Removes the stored addresses for a peer. Returns the removed addresses,
    /// if any.
    pub fn remove_peer_addresses(&mut self, peer_id: &PeerId) -> Option<Vec<Multiaddr>> {
        self.peer_addresses.remove(peer_id)
    }

    /// Number of peers with stored addresses. Test/diagnostic helper.
    #[cfg(test)]
    pub(crate) fn peer_addresses_count(&self) -> usize {
        self.peer_addresses.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(n: usize) -> Peer {
        Peer {
            id: PeerId::random(),
            connection_id: ConnectionId::new_unchecked(n),
            remote_addr: "/ip4/127.0.0.1/tcp/9000".parse().unwrap(),
        }
    }

    #[test]
    fn inactive_peers_evicts_oldest_beyond_cap() {
        let mut store = PeerStore::default();
        let known = HashSet::new();

        let peers: Vec<Peer> = (0..(MAX_INACTIVE_PEERS + 10)).map(test_peer).collect();
        for peer in &peers {
            store.remove_peer(peer.clone(), &known);
        }

        assert_eq!(store.inactive_count(), MAX_INACTIVE_PEERS);
        // Ordering queue membership stays consistent with the set.
        assert_eq!(store.inactive_order.len(), store.inactive_count());

        let all: Vec<Peer> = store.all_peers();
        // The 10 oldest are evicted, the most recent are retained.
        for old in &peers[..10] {
            assert!(!all.contains(old), "oldest peer should have been evicted");
        }
        for recent in &peers[peers.len() - 10..] {
            assert!(all.contains(recent), "recent peer should be retained");
        }
    }

    #[test]
    fn known_peers_are_not_evicted() {
        let mut store = PeerStore::default();
        let known_peer = test_peer(0);
        let known: HashSet<PeerId> = std::iter::once(known_peer.id).collect();

        // Insert the known peer first (oldest), then flood with non-known peers.
        store.remove_peer(known_peer.clone(), &known);
        for n in 1..=(MAX_INACTIVE_PEERS + 5) {
            store.remove_peer(test_peer(n), &known);
        }

        let all: Vec<Peer> = store.all_peers();
        assert!(
            all.contains(&known_peer),
            "known peer must never be evicted"
        );
    }

    #[test]
    fn add_peer_then_remove_keeps_order_consistent() {
        let mut store = PeerStore::default();
        let known = HashSet::new();
        let peer = test_peer(1);

        // Inactive, then re-activated: must be removed from the inactive set and
        // the ordering queue so it is not double-counted when it goes inactive again.
        store.remove_peer(peer.clone(), &known);
        assert_eq!(store.inactive_count(), 1);
        store.add_peer(peer.clone());
        assert_eq!(store.inactive_count(), 0);
        assert_eq!(store.inactive_order.len(), 0);

        store.remove_peer(peer.clone(), &known);
        assert_eq!(store.inactive_count(), 1);
        assert_eq!(store.inactive_order.len(), 1);
    }

    #[test]
    fn set_peer_addresses_truncates_to_cap() {
        let mut store = PeerStore::default();
        let peer = PeerId::random();
        let addrs: Vec<Multiaddr> = (0..(MAX_PEER_ADDRESSES + 50))
            .map(|i| {
                format!("/ip4/127.0.0.1/tcp/{}", 9000usize.saturating_add(i))
                    .parse()
                    .unwrap()
            })
            .collect();

        store.set_peer_addresses(peer, addrs.clone());

        let stored = store.peer_addresses(&peer).unwrap();
        assert_eq!(stored.len(), MAX_PEER_ADDRESSES);
        // truncate keeps the prefix
        assert_eq!(stored.as_slice(), &addrs[..MAX_PEER_ADDRESSES]);
    }

    #[test]
    fn set_peer_addresses_keeps_under_cap() {
        let mut store = PeerStore::default();
        let peer = PeerId::random();
        let addrs: Vec<Multiaddr> = (0..3)
            .map(|i| {
                format!("/ip4/127.0.0.1/tcp/{}", 9000usize.saturating_add(i))
                    .parse()
                    .unwrap()
            })
            .collect();

        store.set_peer_addresses(peer, addrs.clone());
        assert_eq!(store.peer_addresses(&peer), Some(&addrs));
    }

    #[test]
    fn remove_peer_addresses_removes_entry() {
        let mut store = PeerStore::default();
        let peer = PeerId::random();
        let addrs: Vec<Multiaddr> = vec!["/ip4/127.0.0.1/tcp/9000".parse().unwrap()];

        store.set_peer_addresses(peer, addrs.clone());
        assert_eq!(store.peer_addresses_count(), 1);

        assert_eq!(store.remove_peer_addresses(&peer), Some(addrs));
        assert!(store.peer_addresses(&peer).is_none());
        assert_eq!(store.remove_peer_addresses(&peer), None);
    }
}
