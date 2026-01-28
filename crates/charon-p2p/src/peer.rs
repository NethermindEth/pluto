//! # Charon P2P Peer
//!
//! Peer-related types and utilities.

use std::sync::{Arc, Mutex};

use k256::{PublicKey as K256PublicKey, SecretKey};
use libp2p::{Multiaddr, PeerId, identity::PublicKey as Libp2pPublicKey};
use pluto_eth2util::enr::Record;

use crate::name::peer_name;

/// Peer error.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// Failed to parse public key.
    #[error("Failed to parse public key")]
    FailedToParsePublicKey(#[from] libp2p::identity::ParseError),

    /// Failed to decode protobuf-encoded public key.
    #[error("Failed to decode protobuf-encoded public key")]
    FailedToDecodeProtobuf(#[from] libp2p::identity::DecodingError),

    /// Public key is not a secp256k1 key.
    #[error("Public key is not a secp256k1 key")]
    NotSecp256k1Key(#[from] libp2p::identity::OtherVariantError),

    /// Failed to parse secp256k1 public key.
    #[error("Failed to parse secp256k1 public key: {0}")]
    FailedToParseSecp256k1PublicKey(#[from] k256::elliptic_curve::Error),

    /// Missing public key in ENR.
    #[error("Missing public key in ENR")]
    MissingPublicKeyInEnr,

    /// Failed to convert the public key.
    #[error("Failed to convert the public key: {0}")]
    FailedToConvertPublicKey(#[from] pluto_k1util::K1UtilError),

    /// Unknown public key.
    #[error(
        "Unknown private key provided, it doesn't match any public key encoded inside the operator ENRs"
    )]
    UnknownPublicKey,
}

type Result<T> = std::result::Result<T, PeerError>;

/// Peer address information (peer ID and multiaddresses).
#[derive(Clone, Debug)]
pub struct AddrInfo {
    /// Peer ID.
    pub id: PeerId,

    /// Multiaddresses of the peer.
    pub addrs: Vec<Multiaddr>,
}

/// Peer represents a peer in the libp2p network, either a charon node or a
/// relay.
#[derive(Clone, Debug)]
pub struct Peer {
    /// LibP2P peer identity.
    pub id: PeerId,

    /// List of libp2p multiaddresses of the peer.
    pub addresses: Vec<Multiaddr>,

    /// Index is the order of this node in the cluster.
    /// This is only applicable to charon nodes, not relays.
    pub index: usize,

    /// Represents a human friendly name for the peer.
    pub name: String,
}

impl Peer {
    /// Creates a new relay peer from address information.
    pub fn new_relay_peer(info: &AddrInfo) -> Peer {
        Peer {
            id: info.id,
            addresses: info.addrs.clone(),
            index: 0,
            name: peer_name(&info.id),
        }
    }

    /// Creates a Peer from a ENR.
    pub fn from_enr(enr: &Record, index: usize) -> Result<Peer> {
        let id = peer_id_from_key(enr.public_key.ok_or(PeerError::MissingPublicKeyInEnr)?)?;

        Ok(Peer {
            id,
            index,
            name: peer_name(&id),
            addresses: vec![],
        })
    }

    /// Returns share index of this Peer. ShareIdx is 1-indexed while peer index
    /// is 0-indexed.
    pub fn share_idx(&self) -> usize {
        self.index.wrapping_add(1)
    }

    /// Returns the public key of the peer.
    pub fn public_key(&self) -> Result<K256PublicKey> {
        peer_id_to_public_key(&self.id)
    }

    /// Returns the libp2p peer address info (peer ID and multiaddrs).
    pub fn addr_info(&self) -> AddrInfo {
        AddrInfo {
            id: self.id,
            addrs: self.addresses.clone(),
        }
    }
}

/// Mutable peer error.
#[derive(Debug, thiserror::Error)]
pub enum MutablePeerError {
    /// Failed to lock the mutable peer.
    #[error("Failed to lock the mutable peer")]
    PoisonError,
}

/// MutablePeer is a mutable peer that can be updated.
#[derive(Debug, Clone)]
pub struct MutablePeer {
    /// Inner state of the mutable peer.
    inner: Arc<Mutex<MutablePeerInner>>,
}

/// Subscriber is a function that is called when the peer is updated.
pub type Subscriber = Box<dyn Fn(&Peer) + Send + Sync + 'static>;

/// MutablePeerInner is the inner state of a MutablePeer.
pub struct MutablePeerInner {
    /// Peer.
    peer: Option<Peer>,

    /// Subscribers.
    subs: Vec<Subscriber>,
}

impl std::fmt::Debug for MutablePeerInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutablePeerInner")
            .field("peer", &self.peer)
            .field("subs", &format!("[{} subscribers]", self.subs.len()))
            .finish()
    }
}

type MutablePeerResult<T> = std::result::Result<T, MutablePeerError>;

impl MutablePeer {
    /// Creates a new mutable peer with an initial value.
    pub fn new(peer: Peer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MutablePeerInner {
                peer: Some(peer),
                subs: Vec::new(),
            })),
        }
    }

    /// Updates the mutable peer and calls all subscribers.
    pub fn set(&self, peer: Peer) -> MutablePeerResult<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| MutablePeerError::PoisonError)?;
        inner.peer = Some(peer.clone());
        inner.subs.iter().for_each(|sub| sub(&peer.clone()));
        Ok(())
    }

    /// Returns the current peer or None if not available.
    pub fn peer(&self) -> MutablePeerResult<Option<Peer>> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| MutablePeerError::PoisonError)?;
        Ok(inner.peer.clone())
    }

    /// Registers a function that is called when the peer is updated.
    pub fn subscribe(&self, sub: Subscriber) -> MutablePeerResult<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| MutablePeerError::PoisonError)?;
        inner.subs.push(sub);
        Ok(())
    }
}

/// Converts a PeerId to a K256PublicKey.
/// Only works for secp256k1 keys.
pub fn peer_id_to_public_key(peer_id: &PeerId) -> Result<K256PublicKey> {
    let libp2p_pk = peer_id_to_libp2p_pk(peer_id)?;
    pluto_k1util::public_key_from_libp2p(&libp2p_pk).map_err(Into::into)
}

/// Extracts the libp2p PublicKey from a PeerId.
pub fn peer_id_to_libp2p_pk(peer_id: &PeerId) -> Result<Libp2pPublicKey> {
    Libp2pPublicKey::try_decode_protobuf(peer_id.as_ref().digest()).map_err(Into::into)
}

/// Converts a K256PublicKey to a libp2p PublicKey.
fn k256_pk_to_libp2p_pk(pk: &K256PublicKey) -> Result<Libp2pPublicKey> {
    let sec1_bytes = pk.to_sec1_bytes();
    let secp_key = libp2p::identity::secp256k1::PublicKey::try_from_bytes(&sec1_bytes)?;
    Ok(Libp2pPublicKey::from(secp_key))
}

/// Converts a K256PublicKey to a PeerId.
pub fn peer_id_from_key(key: K256PublicKey) -> Result<PeerId> {
    let libp2p_pk = k256_pk_to_libp2p_pk(&key)?;
    Ok(PeerId::from_public_key(&libp2p_pk))
}

/// `verify_p2p_key` returns an error if the p2p key doesn't match any lock
/// operator ENR.
pub fn verify_p2p_key(peers: &[Peer], key: &SecretKey) -> Result<()> {
    let want = key.public_key();

    for peer in peers {
        let pub_key = peer_id_to_libp2p_pk(&peer.id)?;

        let got = pluto_k1util::public_key_from_libp2p(&pub_key)?;

        if got == want {
            return Ok(());
        }
    }

    Err(PeerError::UnknownPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_testutil::random::generate_insecure_k1_key;

    #[test]
    fn test_new_peer() {
        let p2p_key = generate_insecure_k1_key(1);

        let record = Record::new(p2p_key, vec![]).unwrap();

        let peer = Peer::from_enr(&record, 0).unwrap();

        assert_eq!(
            peer.id.to_string(),
            "16Uiu2HAkzdQ5Y9SYT91K1ue5SxXwgmajXntfScGnLYeip5hHyWmT"
        );
    }

    #[test]
    #[ignore]
    fn test_new_tcp_host() {
        todo!("add this test after implementing p2p.NewNode function");
    }

    #[test]
    #[ignore]
    fn test_verify_p2p_key() {
        todo!("add this test after implementing cluster.NewForT function");
    }

    #[test]
    #[ignore]
    fn test_peer_id_key() {
        todo!("add this test after implementing peer_id_key function");
    }
}
