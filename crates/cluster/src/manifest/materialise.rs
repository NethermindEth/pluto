//! Cluster manifest materialisation.

use crate::manifestpb::v1::{Cluster, SignedMutationList};

use super::Result;

/// Transforms a raw DAG and returns the resulting cluster manifest.
///
/// Applies each mutation in order to build up the final cluster state.
/// Sets `initial_mutation_hash` from the first mutation and
/// `latest_mutation_hash` from the last mutation.
///
/// Returns an error if the DAG is empty or any transformation fails.
pub fn materialise(_raw_dag: &SignedMutationList) -> Result<Cluster> {
    unimplemented!("materialise")
}
