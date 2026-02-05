use crate::manifestpb::v1::{Cluster, SignedMutationList};

use super::error::{ManifestError, Result};

/// Transforms a raw DAG and returns the resulting cluster manifest.
pub fn materialise(raw_dag: &SignedMutationList) -> Result<Cluster> {
    if raw_dag.mutations.is_empty() {
        return Err(ManifestError::EmptyDAG);
    }

    let mut cluster = Cluster::default();

    for signed in &raw_dag.mutations {
        cluster = signed.transform(&cluster)?;
    }

    // initial_mutation_hash is the hash of the first mutation
    cluster.initial_mutation_hash = raw_dag
        .mutations
        .first()
        .ok_or(ManifestError::EmptyDAG)?
        .hash()?
        .into();

    // latest_mutation_hash is the hash of the last mutation
    cluster.latest_mutation_hash = raw_dag
        .mutations
        .last()
        .ok_or(ManifestError::EmptyDAG)?
        .hash()?
        .into();

    Ok(cluster)
}
