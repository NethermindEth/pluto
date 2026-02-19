use std::{
    collections::HashSet,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use libp2p::{PeerId, swarm::ConnectionId};

/// Global context shared across P2P components.
///
/// This struct provides thread-safe access to shared state including:
/// - Known cluster peer IDs (immutable after construction)
/// - Runtime peer connection state (mutable via `PeerStore`)
#[derive(Debug, Clone, Default)]
pub struct GlobalContext {
    /// Known cluster peer IDs. These are the peers that are part of the
    /// cluster and should be tracked with peer metrics (as opposed to
    /// relay metrics for unknown peers).
    known_peers: Arc<Vec<PeerId>>,
    /// Peer store for tracking active/inactive peer connections.
    peer_store: Arc<RwLock<PeerStore>>,
}

impl GlobalContext {
    /// Creates a new global context with the given known peers.
    pub fn new(known_peers: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            known_peers: Arc::new(known_peers.into_iter().collect()),
            peer_store: Arc::default(),
        }
    }

    /// Returns true if the peer is a known cluster peer.
    pub fn is_known_peer(&self, peer: &PeerId) -> bool {
        self.known_peers.contains(peer)
    }

    /// Returns the known peer IDs.
    pub fn known_peers(&self) -> &[PeerId] {
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

/// Peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Peer {
    /// Peer ID.
    pub id: PeerId,

    /// Connection ID.
    pub connection_id: ConnectionId,
}

/// Peer store.
#[derive(Debug, Clone, Default)]
pub struct PeerStore {
    /// Active peers.
    active_peers: HashSet<Peer>,

    /// Inactive peers.
    inactive_peers: HashSet<Peer>,
}

impl PeerStore {
    /// Adds a peer to the peer store.
    pub fn add_peer(&mut self, peer: Peer) {
        self.inactive_peers.remove(&peer);
        self.active_peers.insert(peer);
    }

    /// Removes a peer from the peer store.
    pub fn remove_peer(&mut self, peer: Peer) {
        self.active_peers.remove(&peer);
        self.inactive_peers.insert(peer.clone());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_peer_id() -> PeerId {
        PeerId::random()
    }

    fn make_peer(id: PeerId, conn_id: usize) -> Peer {
        Peer {
            id,
            connection_id: ConnectionId::new_unchecked(conn_id),
        }
    }

    // =========================================================================
    // PeerStore tests
    // =========================================================================

    #[test]
    fn test_peer_store_default_is_empty() {
        let store = PeerStore::default();

        assert_eq!(store.active_count(), 0);
        assert_eq!(store.inactive_count(), 0);

        let all: Vec<Peer> = store.all_peers();
        assert!(all.is_empty());
    }

    #[test]
    fn test_add_peer() {
        let mut store = PeerStore::default();
        let peer = make_peer(random_peer_id(), 1);

        store.add_peer(peer.clone());

        assert_eq!(store.active_count(), 1);
        assert_eq!(store.inactive_count(), 0);

        let active: Vec<Peer> = store.peers();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], peer);
    }

    #[test]
    fn test_add_same_peer_twice_is_idempotent() {
        let mut store = PeerStore::default();
        let peer = make_peer(random_peer_id(), 1);

        store.add_peer(peer.clone());
        store.add_peer(peer.clone());

        assert_eq!(store.active_count(), 1);
        assert_eq!(store.inactive_count(), 0);
    }

    #[test]
    fn test_add_multiple_peers() {
        let mut store = PeerStore::default();
        let peer1 = make_peer(random_peer_id(), 1);
        let peer2 = make_peer(random_peer_id(), 2);
        let peer3 = make_peer(random_peer_id(), 3);

        store.add_peer(peer1);
        store.add_peer(peer2);
        store.add_peer(peer3);

        assert_eq!(store.active_count(), 3);
        assert_eq!(store.inactive_count(), 0);
    }

    #[test]
    fn test_same_peer_id_different_connection_ids_are_distinct() {
        let mut store = PeerStore::default();
        let peer_id = random_peer_id();
        let peer_conn1 = make_peer(peer_id, 1);
        let peer_conn2 = make_peer(peer_id, 2);

        store.add_peer(peer_conn1);
        store.add_peer(peer_conn2);

        // Both should be tracked as separate connections
        assert_eq!(store.active_count(), 2);
    }

    #[test]
    fn test_remove_peer_moves_to_inactive() {
        let mut store = PeerStore::default();
        let peer = make_peer(random_peer_id(), 1);

        store.add_peer(peer.clone());
        assert_eq!(store.active_count(), 1);
        assert_eq!(store.inactive_count(), 0);

        store.remove_peer(peer.clone());

        assert_eq!(store.active_count(), 0);
        assert_eq!(store.inactive_count(), 1);

        let inactive: Vec<Peer> = store.inactive_peers();
        assert_eq!(inactive.len(), 1);
        assert_eq!(inactive[0], peer);
    }

    #[test]
    fn test_remove_nonexistent_peer_adds_to_inactive() {
        let mut store = PeerStore::default();
        let peer = make_peer(random_peer_id(), 1);

        // Remove a peer that was never added
        store.remove_peer(peer.clone());

        // It should still appear in inactive peers
        assert_eq!(store.active_count(), 0);
        assert_eq!(store.inactive_count(), 1);
    }

    #[test]
    fn test_read_inactive_peer_moves_to_active() {
        let mut store = PeerStore::default();
        let peer = make_peer(random_peer_id(), 1);

        // Add -> Remove -> Re-add
        store.add_peer(peer.clone());
        store.remove_peer(peer.clone());
        assert_eq!(store.inactive_count(), 1);

        store.add_peer(peer.clone());

        assert_eq!(store.active_count(), 1);
        assert_eq!(store.inactive_count(), 0);
    }

    #[test]
    fn test_all_peers_combines_active_and_inactive() {
        let mut store = PeerStore::default();
        let peer1 = make_peer(random_peer_id(), 1);
        let peer2 = make_peer(random_peer_id(), 2);

        store.add_peer(peer1.clone());
        store.add_peer(peer2.clone());
        store.remove_peer(peer1.clone());

        assert_eq!(store.active_count(), 1);
        assert_eq!(store.inactive_count(), 1);

        let all: Vec<Peer> = store.all_peers();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_peers_as_hashset() {
        let mut store = PeerStore::default();
        let peer1 = make_peer(random_peer_id(), 1);
        let peer2 = make_peer(random_peer_id(), 2);

        store.add_peer(peer1.clone());
        store.add_peer(peer2.clone());

        let active: HashSet<Peer> = store.peers();
        assert!(active.contains(&peer1));
        assert!(active.contains(&peer2));
    }

    // =========================================================================
    // Peer equality tests
    // =========================================================================

    #[test]
    fn test_peer_equality() {
        let peer_id = random_peer_id();
        let peer1 = make_peer(peer_id, 1);
        let peer2 = make_peer(peer_id, 1);
        let peer3 = make_peer(peer_id, 2);

        assert_eq!(peer1, peer2);
        assert_ne!(peer1, peer3);
    }

    #[test]
    fn test_peer_hash_consistency() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };

        let peer_id = random_peer_id();
        let peer1 = make_peer(peer_id, 1);
        let peer2 = make_peer(peer_id, 1);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        peer1.hash(&mut hasher1);
        peer2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    // =========================================================================
    // GlobalContext tests
    // =========================================================================

    #[test]
    fn test_global_context_default() {
        let ctx = GlobalContext::default();
        let store = ctx.peer_store_lock();

        assert_eq!(store.active_count(), 0);
        assert_eq!(store.inactive_count(), 0);
        assert!(ctx.known_peers().is_empty());
    }

    #[test]
    fn test_global_context_new_with_known_peers() {
        let peer1 = random_peer_id();
        let peer2 = random_peer_id();

        let ctx = GlobalContext::new([peer1, peer2]);

        assert_eq!(ctx.known_peers().len(), 2);
        assert!(ctx.is_known_peer(&peer1));
        assert!(ctx.is_known_peer(&peer2));
    }

    #[test]
    fn test_global_context_is_known_peer() {
        let known = random_peer_id();
        let unknown = random_peer_id();

        let ctx = GlobalContext::new([known]);

        assert!(ctx.is_known_peer(&known));
        assert!(!ctx.is_known_peer(&unknown));
    }

    #[test]
    fn test_global_context_known_peers_immutable_across_clones() {
        let peer = random_peer_id();
        let ctx1 = GlobalContext::new([peer]);
        let ctx2 = ctx1.clone();

        // Both clones see the same known peers
        assert!(ctx1.is_known_peer(&peer));
        assert!(ctx2.is_known_peer(&peer));
        assert_eq!(ctx1.known_peers().len(), ctx2.known_peers().len());
    }

    #[test]
    fn test_global_context_write_then_read() {
        let ctx = GlobalContext::default();
        let peer = make_peer(random_peer_id(), 1);

        {
            let mut store = ctx.peer_store_write_lock();
            store.add_peer(peer.clone());
        }

        {
            let store = ctx.peer_store_lock();
            assert_eq!(store.active_count(), 1);
        }
    }

    #[test]
    fn test_global_context_clone_shares_state() {
        let ctx1 = GlobalContext::default();
        let ctx2 = ctx1.clone();
        let peer = make_peer(random_peer_id(), 1);

        // Write through ctx1
        {
            let mut store = ctx1.peer_store_write_lock();
            store.add_peer(peer.clone());
        }

        // Read through ctx2 - should see the same state
        {
            let store = ctx2.peer_store_lock();
            assert_eq!(store.active_count(), 1);
        }
    }

    #[test]
    fn test_global_context_multiple_readers() {
        let ctx = GlobalContext::default();
        let peer = make_peer(random_peer_id(), 1);

        {
            let mut store = ctx.peer_store_write_lock();
            store.add_peer(peer);
        }

        // Multiple simultaneous read locks should work
        let guard1 = ctx.peer_store_lock();
        let guard2 = ctx.peer_store_lock();

        assert_eq!(guard1.active_count(), 1);
        assert_eq!(guard2.active_count(), 1);
    }

    // =========================================================================
    // Thread safety tests
    // =========================================================================

    #[test]
    fn test_concurrent_writes() {
        use std::thread;

        let ctx = GlobalContext::default();
        let mut handles = vec![];

        for i in 0..10 {
            let ctx_clone = ctx.clone();
            let handle = thread::spawn(move || {
                let peer = make_peer(random_peer_id(), i);
                let mut store = ctx_clone.peer_store_write_lock();
                store.add_peer(peer);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        let store = ctx.peer_store_lock();
        assert_eq!(store.active_count(), 10);
    }

    #[test]
    fn test_concurrent_reads_and_writes() {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            thread,
        };

        let ctx = GlobalContext::default();
        let read_count = Arc::new(AtomicUsize::new(0));

        // First add some peers
        for i in 0..5 {
            let peer = make_peer(random_peer_id(), i);
            ctx.peer_store_write_lock().add_peer(peer);
        }

        let mut handles = vec![];

        // Spawn readers
        for _ in 0..5 {
            let ctx_clone = ctx.clone();
            let read_count_clone = read_count.clone();
            let handle = thread::spawn(move || {
                let store = ctx_clone.peer_store_lock();
                let count = store.active_count();
                read_count_clone.fetch_add(count, Ordering::SeqCst);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Each reader should have seen at least 5 peers
        assert!(read_count.load(Ordering::SeqCst) >= 25);
    }
}
