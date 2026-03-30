use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use libp2p::{Multiaddr, PeerId, swarm::ConnectionId};

/// Global context shared across P2P components.
///
/// This struct provides thread-safe access to shared state including:
/// - Known cluster peer IDs (immutable after construction)
/// - Runtime peer connection state (mutable via `PeerStore`)
#[derive(Debug, Clone, Default)]
pub struct P2PContext {
    /// Local peer ID for this node, once known.
    local_peer_id: Arc<RwLock<Option<PeerId>>>,
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
        *self
            .local_peer_id
            .write()
            .expect("Failed to write local peer id") = Some(peer_id);
    }

    /// Returns the local peer ID for this node, if known.
    pub fn local_peer_id(&self) -> Option<PeerId> {
        *self
            .local_peer_id
            .read()
            .expect("Failed to read local peer id")
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
