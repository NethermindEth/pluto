//! Node approval mutation implementation.

use crate::manifestpb::v1::{Cluster, SignedMutation};

use super::Result;

/// Signs a node approval mutation.
pub fn sign_node_approval(
    _parent: &[u8],
    _secret: &k256::ecdsa::SigningKey,
) -> Result<SignedMutation> {
    unimplemented!("sign_node_approval")
}

/// Creates a new node approvals composite mutation.
pub fn new_node_approvals_composite(_approvals: Vec<SignedMutation>) -> Result<SignedMutation> {
    unimplemented!("new_node_approvals_composite")
}

/// Verifies a node approval mutation.
pub(crate) fn verify_node_approval(_signed: &SignedMutation) -> Result<()> {
    unimplemented!("verify_node_approval")
}

/// Transforms a cluster with a node approvals composite mutation.
pub(crate) fn transform_node_approvals(
    _cluster: &Cluster,
    _signed: &SignedMutation,
) -> Result<Cluster> {
    unimplemented!("transform_node_approvals")
}
