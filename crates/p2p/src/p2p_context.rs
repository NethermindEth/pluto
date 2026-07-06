use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use libp2p::{Multiaddr, PeerId, swarm::ConnectionId};
use tracing::error;

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

    /// Known addresses for each peer (populated from identify protocol).
    peer_addresses: HashMap<PeerId, Vec<Multiaddr>>,
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

    /// Returns whether there is any active connection to the given peer.
    ///
    /// Equivalent to `!connections_to_peer(peer_id).is_empty()` but does not
    /// allocate, since it short-circuits on the first match.
    pub fn has_connection(&self, peer_id: &PeerId) -> bool {
        self.active_peers.iter().any(|p| &p.id == peer_id)
    }

    /// Returns all active connections to a specific peer.
    pub fn connections_to_peer(&self, peer_id: &PeerId) -> Vec<&Peer> {
        self.active_peers
            .iter()
            .filter(|p| &p.id == peer_id)
            .collect()
    }

    /// Sets the known addresses for a peer (from identify protocol).
    pub fn set_peer_addresses(&mut self, peer_id: PeerId, addrs: Vec<Multiaddr>) {
        self.peer_addresses.insert(peer_id, addrs);
    }

    /// Returns the known addresses for a peer.
    pub fn peer_addresses(&self, peer_id: &PeerId) -> Option<&Vec<Multiaddr>> {
        self.peer_addresses.get(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: PeerId, connection_id: usize) -> Peer {
        Peer {
            id,
            connection_id: ConnectionId::new_unchecked(connection_id),
            remote_addr: Multiaddr::empty(),
        }
    }

    #[test]
    fn has_connection_empty_store_is_false() {
        let store = PeerStore::default();
        assert!(!store.has_connection(&PeerId::random()));
    }

    #[test]
    fn has_connection_reflects_added_peer() {
        let a = PeerId::random();
        let b = PeerId::random();
        let mut store = PeerStore::default();
        store.add_peer(peer(a, 1));

        assert!(store.has_connection(&a));
        assert!(!store.has_connection(&b));
    }

    #[test]
    fn has_connection_true_with_multiple_connections() {
        let a = PeerId::random();
        let mut store = PeerStore::default();
        store.add_peer(peer(a, 1));
        store.add_peer(peer(a, 2));

        assert!(store.has_connection(&a));
    }

    #[test]
    fn has_connection_matches_connections_to_peer() {
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let mut store = PeerStore::default();
        store.add_peer(peer(a, 1));
        store.add_peer(peer(b, 1));

        for id in [a, b, c] {
            assert_eq!(
                store.has_connection(&id),
                !store.connections_to_peer(&id).is_empty()
            );
        }
    }

    #[test]
    fn has_connection_false_after_remove() {
        let a = PeerId::random();
        let mut store = PeerStore::default();
        let conn = peer(a, 1);
        store.add_peer(conn.clone());
        assert!(store.has_connection(&a));

        store.remove_peer(conn);
        assert!(!store.has_connection(&a));
    }
}
