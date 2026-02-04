//! Cluster manifest materialisation.

use crate::manifestpb::v1::{Cluster, SignedMutationList};

use super::{ManifestError, Result, types};

/// Transforms a raw DAG and returns the resulting cluster manifest.
///
/// Applies each mutation in order to build up the final cluster state.
/// Sets `initial_mutation_hash` from the first mutation and
/// `latest_mutation_hash` from the last mutation.
///
/// Returns an error if the DAG is empty or any transformation fails.
pub fn materialise(raw_dag: &SignedMutationList) -> Result<Cluster> {
    if raw_dag.mutations.is_empty() {
        return Err(ManifestError::EmptyDAG);
    }

    let mut cluster = Cluster::default();

    for signed in &raw_dag.mutations {
        cluster = types::transform(&cluster, signed)?;
    }

    // initial_mutation_hash is the hash of the first mutation
    // SAFETY: We already checked that mutations is not empty above
    cluster.initial_mutation_hash =
        types::hash(raw_dag.mutations.first().ok_or(ManifestError::EmptyDAG)?)?.into();

    // LatestMutationHash is the hash of the last mutation
    // SAFETY: We already checked that mutations is not empty above
    cluster.latest_mutation_hash =
        types::hash(raw_dag.mutations.last().ok_or(ManifestError::EmptyDAG)?)?.into();

    Ok(cluster)
}
