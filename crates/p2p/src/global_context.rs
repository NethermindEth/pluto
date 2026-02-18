use std::{
    collections::HashSet,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use libp2p::{PeerId, swarm::ConnectionId};

/// Global context.
#[derive(Debug, Clone, Default)]
pub struct GlobalContext {
    /// Peer store.
    peer_store: Arc<RwLock<PeerStore>>,
}

impl GlobalContext {
    /// Returns a read lock on the peer store.
    pub fn peer_store_lock<'a>(&'a self) -> RwLockReadGuard<'a, PeerStore> {
        self.peer_store.read().expect("Failed to read peer store")
    }

    /// Returns a write lock on the peer store.
    pub fn peer_store_write_lock<'a>(&'a self) -> RwLockWriteGuard<'a, PeerStore> {
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
}
