//! Cluster manifest loading from disk.

use std::path::Path;

use crate::{
    lock::Lock,
    manifestpb::v1::{Cluster, SignedMutationList},
};

use super::{ManifestError, Result};

/// Loads the current cluster state from disk.
///
/// Reads either from cluster manifest or legacy lock file.
/// If both files are provided, both files are read and:
/// - If cluster hashes don't match, an error is returned
/// - If cluster hashes match, the cluster loaded from the manifest file is returned
///
/// Returns an error if the cluster can't be loaded from either file.
pub fn load_cluster<P1, P2, F>(
    _manifest_file: P1,
    _legacy_lock_file: P2,
    _lock_callback: Option<F>,
) -> Result<Cluster>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
    F: FnOnce(Lock) -> Result<()>,
{
    unimplemented!("load_cluster")
}

/// Loads the raw cluster DAG from disk.
///
/// Reads either from cluster manifest or legacy lock file.
/// If both files are provided, both files are read and:
/// - If cluster hashes don't match, an error is returned
/// - If cluster hashes match, the DAG loaded from the manifest file is returned
///
/// Returns an error if the DAG can't be loaded from either file.
pub fn load_dag<P1, P2, F>(
    _manifest_file: P1,
    _legacy_lock_file: P2,
    _lock_callback: Option<F>,
) -> Result<SignedMutationList>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
    F: FnOnce(Lock) -> Result<()>,
{
    unimplemented!("load_dag")
}

/// Loads the raw DAG from cluster manifest file on disk.
pub(crate) fn load_dag_from_manifest<P: AsRef<Path>>(_filename: P) -> Result<SignedMutationList> {
    unimplemented!("load_dag_from_manifest")
}

/// Loads the raw DAG from legacy lock file on disk.
pub(crate) fn load_dag_from_legacy_lock<P: AsRef<Path>, F: FnOnce(Lock) -> Result<()>>(
    _filename: P,
    _lock_callback: Option<F>,
) -> Result<SignedMutationList> {
    unimplemented!("load_dag_from_legacy_lock")
}

/// Verifies that cluster hashes match between manifest and legacy DAG.
pub(crate) fn cluster_hashes_match(
    _dag_manifest: &SignedMutationList,
    _dag_legacy: &SignedMutationList,
) -> Result<()> {
    unimplemented!("cluster_hashes_match")
}
