//! Add validators mutation implementation.

use crate::manifestpb::v1::{Cluster, SignedMutation, Validator};

use super::Result;

/// Creates a new gen validators mutation.
pub fn new_gen_validators(_parent: &[u8], _validators: Vec<Validator>) -> Result<SignedMutation> {
    unimplemented!("new_gen_validators")
}

/// Verifies a gen validators mutation.
#[allow(dead_code)]
pub(crate) fn verify_gen_validators(_signed: &SignedMutation) -> Result<()> {
    unimplemented!("verify_gen_validators")
}

/// Transforms a cluster with a gen validators mutation.
pub(crate) fn transform_gen_validators(
    _cluster: &Cluster,
    _signed: &SignedMutation,
) -> Result<Cluster> {
    unimplemented!("transform_gen_validators")
}

/// Creates a new add validators composite mutation.
pub fn new_add_validators(
    _gen_validators: &SignedMutation,
    _node_approvals: &SignedMutation,
) -> Result<SignedMutation> {
    unimplemented!("new_add_validators")
}

/// Transforms a cluster with an add validators composite mutation.
pub(crate) fn transform_add_validators(
    _cluster: &Cluster,
    _signed: &SignedMutation,
) -> Result<Cluster> {
    unimplemented!("transform_add_validators")
}
