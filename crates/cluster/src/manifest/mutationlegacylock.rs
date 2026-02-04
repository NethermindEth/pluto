use crate::{
    lock::Lock,
    manifestpb::v1::{Cluster, LegacyLock, Mutation, SignedMutation, SignedMutationList},
};

use super::{ManifestError, Result, types::MutationType};

impl ::prost::Name for LegacyLock {
    const NAME: &'static str = "LegacyLock";
    const PACKAGE: &'static str = "cluster.manifestpb.v1";

    fn type_url() -> ::prost::alloc::string::String {
        format!(
            "type.googleapis.com/{}",
            <Self as ::prost::Name>::full_name()
        )
    }
}

/// Creates a new raw legacy lock mutation from JSON bytes.
pub fn new_raw_legacy_lock(json_bytes: &[u8]) -> Result<SignedMutation> {
    // Verify that the bytes are a valid lock by deserializing
    let _: Lock = serde_json::from_slice(json_bytes)
        .map_err(|e| ManifestError::InvalidMutation(format!("unmarshal lock: {}", e)))?;

    let legacy_lock = LegacyLock {
        json: json_bytes.to_vec().into(),
    };

    let lock_any = prost_types::Any::from_msg(&legacy_lock)
        .map_err(|e| ManifestError::InvalidMutation(format!("lock to any: {e}")))?;

    let zero_parent = vec![0u8; 32];

    Ok(SignedMutation {
        mutation: Some(Mutation {
            parent: zero_parent.into(),
            r#type: MutationType::LegacyLock.as_str().to_string(),
            data: Some(lock_any),
        }),
        signer: Default::default(),
        signature: Default::default(),
    })
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
