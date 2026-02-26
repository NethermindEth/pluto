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
pub struct P2PContext {
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
            known_peers: Arc::new(known_peers.into_iter().collect()),
            peer_store: Arc::default(),
        }
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
