//! Legacy lock mutation implementation.

use crate::{
    lock::Lock,
    manifestpb::v1::{Cluster, SignedMutation, SignedMutationList},
};

use super::Result;

/// Creates a new raw legacy lock mutation from JSON bytes.
pub fn new_raw_legacy_lock(_json_bytes: &[u8]) -> Result<SignedMutation> {
    unimplemented!("new_raw_legacy_lock")
}

/// Creates a new legacy lock mutation for testing.
pub fn new_legacy_lock_for_tests(_lock: &Lock) -> Result<SignedMutation> {
    unimplemented!("new_legacy_lock_for_tests")
}

/// Creates a new DAG from a legacy lock for testing.
pub fn new_dag_from_lock_for_tests(_lock: &Lock) -> Result<SignedMutationList> {
    unimplemented!("new_dag_from_lock_for_tests")
}

/// Creates a new cluster from a legacy lock for testing.
pub fn new_cluster_from_lock_for_tests(_lock: &Lock) -> Result<Cluster> {
    unimplemented!("new_cluster_from_lock_for_tests")
}

/// Verifies a legacy lock mutation.
#[allow(dead_code)]
pub(crate) fn verify_legacy_lock(_signed: &SignedMutation) -> Result<()> {
    unimplemented!("verify_legacy_lock")
}

/// Transforms a cluster with a legacy lock mutation.
pub(crate) fn transform_legacy_lock(
    _cluster: &Cluster,
    _signed: &SignedMutation,
) -> Result<Cluster> {
    unimplemented!("transform_legacy_lock")
}

/// Checks if a protobuf message is zero/empty.
#[allow(dead_code)]
pub(crate) fn is_zero_proto<T>(_msg: &T) -> bool
where
    T: prost::Message + Default,
{
    unimplemented!("is_zero_proto")
}
