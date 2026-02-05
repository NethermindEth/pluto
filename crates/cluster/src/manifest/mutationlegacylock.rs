use prost::Message as _;

use crate::{
    lock::Lock,
    manifestpb::v1::{Cluster, LegacyLock, Mutation, Operator, SignedMutation},
};

use super::{
    error::{ManifestError, Result},
    helpers::{extract_mutation, validator_to_proto, verify_empty_sig},
    types::MutationType,
};

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

/// Verifies a legacy lock mutation.
pub fn verify_legacy_lock(signed: &SignedMutation) -> Result<()> {
    let mutation = extract_mutation(signed, MutationType::LegacyLock)?;

    verify_empty_sig(signed)?;

    let data = mutation
        .data
        .as_ref()
        .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

    let legacy_lock = LegacyLock::decode(&*data.value)
        .map_err(|_| ManifestError::InvalidMutation("mutation data to legacy lock".to_string()))?;

    let _lock: Lock = serde_json::from_slice(&legacy_lock.json)
        .map_err(|e| ManifestError::InvalidMutation(format!("unmarshal lock: {}", e)))?;

    Ok(())
}

/// Transforms a cluster with a legacy lock mutation.
pub(crate) fn transform_legacy_lock(cluster: &Cluster, signed: &SignedMutation) -> Result<Cluster> {
    if !is_zero_proto(cluster) {
        return Err(ManifestError::InvalidMutation(
            "legacy lock not first mutation".to_string(),
        ));
    }

    verify_legacy_lock(signed)?;

    let mutation = signed
        .mutation
        .as_ref()
        .ok_or(ManifestError::InvalidSignedMutation)?;

    let data = mutation
        .data
        .as_ref()
        .ok_or_else(|| ManifestError::InvalidMutation("data is nil".to_string()))?;

    let legacy_lock = LegacyLock::decode(&*data.value)
        .map_err(|_| ManifestError::InvalidMutation("mutation data to legacy lock".to_string()))?;

    let lock: Lock = serde_json::from_slice(&legacy_lock.json)
        .map_err(|e| ManifestError::InvalidMutation(format!("unmarshal lock: {}", e)))?;

    // Build operators
    let mut ops = Vec::new();
    for operator in &lock.operators {
        ops.push(Operator {
            address: operator.address.clone(),
            enr: operator.enr.clone(),
        });
    }

    // Check validator addresses length matches validators length
    if lock.validator_addresses.len() != lock.distributed_validators.len() {
        return Err(ManifestError::InvalidMutation(
            "validator addresses and validators length mismatch".to_string(),
        ));
    }

    // Build validators
    let mut vals = Vec::new();
    for (i, validator) in lock.distributed_validators.iter().enumerate() {
        let val = validator_to_proto(validator, &lock.validator_addresses[i])?;
        vals.push(val);
    }

    Ok(Cluster {
        name: lock.name.clone(),
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        threshold: lock.threshold as i32,
        dkg_algorithm: lock.dkg_algorithm.clone(),
        fork_version: lock.fork_version.clone().into(),
        consensus_protocol: lock.consensus_protocol.clone(),
        #[allow(clippy::cast_possible_truncation)]
        target_gas_limit: lock.target_gas_limit as u32,
        compounding: lock.compounding,
        validators: vals,
        operators: ops,
        // These will be set by materialise
        initial_mutation_hash: Default::default(),
        latest_mutation_hash: Default::default(),
    })
}

/// Checks if a protobuf message is zero/empty.
pub(crate) fn is_zero_proto<T>(msg: &T) -> bool
where
    T: prost::Message + Default + PartialEq,
{
    *msg == T::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{manifest::materialise::materialise, manifestpb::v1::SignedMutationList};

    #[test]
    fn is_zero_proto_test() {
        let cluster = Cluster::default();
        assert!(is_zero_proto(&cluster));
    }

    #[test]
    fn legacy_lock_not_first_mutation() {
        let cluster = Cluster {
            name: "foo".to_string(),
            ..Default::default()
        };

        let result = transform_legacy_lock(&cluster, &SignedMutation::default());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ManifestError::InvalidMutation(_)
        ));
    }

    #[test]
    fn load_legacy_lock_from_testdata() {
        let lock_json = include_str!("../testdata/cluster_lock_v1_8_0.json");
        let lock: Lock = serde_json::from_str(lock_json).unwrap();

        // Test creating legacy lock mutation using official method
        let json_bytes = serde_json::to_vec(&lock).unwrap();
        let signed = new_raw_legacy_lock(&json_bytes).unwrap();
        assert!(signed.mutation.is_some());

        let mutation = signed.mutation.as_ref().unwrap();
        assert_eq!(mutation.r#type, MutationType::LegacyLock.as_str());
        assert!(signed.signer.is_empty());
        assert!(signed.signature.is_empty());

        // Test transform
        let cluster = transform_legacy_lock(&Cluster::default(), &signed).unwrap();
        assert_eq!(cluster.name, lock.name);
        assert_eq!(cluster.threshold, i32::try_from(lock.threshold).unwrap());
        assert_eq!(cluster.operators.len(), lock.operators.len());
        assert_eq!(cluster.validators.len(), lock.distributed_validators.len());
    }

    #[test]
    fn new_dag_from_lock() {
        let lock_json = include_str!("../testdata/cluster_lock_v1_8_0.json");
        let lock: Lock = serde_json::from_str(lock_json).unwrap();

        let json_bytes = serde_json::to_vec(&lock).unwrap();
        let signed = new_raw_legacy_lock(&json_bytes).unwrap();
        let dag = SignedMutationList {
            mutations: vec![signed],
        };
        assert_eq!(dag.mutations.len(), 1);
    }

    #[test]
    fn new_cluster_from_lock() {
        let lock_json = include_str!("../testdata/cluster_lock_v1_8_0.json");
        let lock: Lock = serde_json::from_str(lock_json).unwrap();

        let json_bytes = serde_json::to_vec(&lock).unwrap();
        let signed = new_raw_legacy_lock(&json_bytes).unwrap();
        let cluster = materialise(&SignedMutationList {
            mutations: vec![signed],
        })
        .unwrap();
        assert_eq!(cluster.name, lock.name);
        assert!(!cluster.initial_mutation_hash.is_empty());
        assert!(!cluster.latest_mutation_hash.is_empty());
        // For a single mutation, initial and latest should be the same
        assert_eq!(cluster.initial_mutation_hash, cluster.latest_mutation_hash);
    }
}
