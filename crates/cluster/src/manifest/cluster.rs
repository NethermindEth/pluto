//! Cluster manifest helper functions for peer and validator operations.

use crate::{
    definition::NodeIdx,
    manifestpb::v1::{Cluster, Validator},
};
use pluto_p2p::peer::Peer;

use super::Result;

/// Returns the cluster operators as a slice of p2p peers.
pub fn cluster_peers(_cluster: &Cluster) -> Result<Vec<Peer>> {
    unimplemented!("cluster_peers")
}

/// Returns the operators p2p peer IDs.
pub fn cluster_peer_ids(_cluster: &Cluster) -> Result<Vec<String>> {
    unimplemented!("cluster_peer_ids")
}

/// Returns the node index for the peer in the cluster.
pub fn cluster_node_idx(_cluster: &Cluster, _peer_id: &str) -> Result<NodeIdx> {
    unimplemented!("cluster_node_idx")
}

/// Returns the validator BLS group public key.
pub fn validator_public_key(_validator: &Validator) -> Result<Vec<u8>> {
    unimplemented!("validator_public_key")
}

/// Returns the validator hex group public key.
pub fn validator_public_key_hex(_validator: &Validator) -> String {
    unimplemented!("validator_public_key_hex")
}

/// Returns the validator's peerIdx'th BLS public share.
pub fn validator_public_share(_validator: &Validator, _peer_idx: usize) -> Result<Vec<u8>> {
    unimplemented!("validator_public_share")
}
