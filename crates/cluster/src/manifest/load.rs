//! Cluster manifest loading from disk.

use std::path::Path;

use prost::Message as _;

use crate::{
    lock::Lock,
    manifestpb::v1::{Cluster, SignedMutationList},
};

use super::{
    ManifestError, Result, materialise::materialise, mutationlegacylock::new_raw_legacy_lock, types,
};

/// Returns the current cluster state from disk by reading either from cluster
/// manifest or legacy lock file.
///
///  If both files are provided, both files are
/// read and:
/// - If cluster hashes don't match, an error is returned
/// - If cluster hashes match, the cluster loaded from the manifest file is
///   returned.
///
/// Returns an error if the cluster can't be loaded from either file.
pub fn load_cluster<F>(
    manifest_file: impl AsRef<Path>,
    legacy_lock_file: impl AsRef<Path>,
    lock_callback: Option<F>,
) -> Result<Cluster>
where
    F: FnOnce(Lock) -> Result<()>,
{
    let dag = load_dag(manifest_file, legacy_lock_file, lock_callback)?;
    materialise(&dag)
}

/// Returns the raw cluster DAG from disk by reading either from cluster
/// manifest or legacy lock file.
///
/// If both files are provided, both files are
/// read and:
/// - If cluster hashes don't match, an error is returned
/// - If cluster hashes match, the DAG loaded from the manifest file is returned
///
/// Returns an error if the DAG can't be loaded from either file.
pub fn load_dag<F>(
    manifest_file: impl AsRef<Path>,
    legacy_lock_file: impl AsRef<Path>,
    lock_callback: Option<F>,
) -> Result<SignedMutationList>
where
    F: FnOnce(Lock) -> Result<()>,
{
    let manifest_result = load_dag_from_manifest(&manifest_file);
    let legacy_result = load_dag_from_legacy_lock(&legacy_lock_file, lock_callback);

    match (manifest_result, legacy_result) {
        // Both files loaded successfully, check if cluster hashes match
        (Ok(dag_manifest), Ok(dag_legacy)) => {
            cluster_hashes_match(&dag_manifest, &dag_legacy)?;
            Ok(dag_manifest.clone())
        }
        // Only manifest loaded successfully
        (Ok(dag_manifest), Err(_)) => Ok(dag_manifest),
        // Only legacy lock loaded successfully
        (Err(_), Ok(dag_legacy)) => Ok(dag_legacy),
        // Both failed
        (Err(err_manifest), Err(err_legacy)) => {
            // Check if both files don't exist
            let manifest_not_found = matches!(&err_manifest, ManifestError::Io(e) if e.kind() == std::io::ErrorKind::NotFound);
            let legacy_not_found = matches!(&err_legacy, ManifestError::Io(e) if e.kind() == std::io::ErrorKind::NotFound);

            if manifest_not_found && legacy_not_found {
                return Err(ManifestError::NoFileFound {
                    lock_file: legacy_lock_file.as_ref().display().to_string(),
                    manifest_file: manifest_file.as_ref().display().to_string(),
                });
            }

            // Return legacy lock error if it exists but failed to load
            if !legacy_not_found {
                return Err(ManifestError::InvalidMutation(format!(
                    "couldn't load cluster from legacy lock file: {}",
                    err_legacy
                )));
            }

            // Otherwise return manifest error
            Err(ManifestError::InvalidMutation(format!(
                "couldn't load cluster from manifest file: {}",
                err_manifest
            )))
        }
    }
}

/// Loads the raw DAG from cluster manifest file on disk.
pub(crate) fn load_dag_from_manifest(filename: impl AsRef<Path>) -> Result<SignedMutationList> {
    let bytes = std::fs::read(filename.as_ref())?;
    let raw_dag = SignedMutationList::decode(&*bytes)?;
    Ok(raw_dag)
}

/// Loads the raw DAG from legacy lock file on disk.
pub(crate) fn load_dag_from_legacy_lock<F: FnOnce(Lock) -> Result<()>>(
    filename: impl AsRef<Path>,
    lock_callback: Option<F>,
) -> Result<SignedMutationList> {
    let bytes = std::fs::read(filename)?;

    let lock: Lock = serde_json::from_slice(&bytes)?;

    if let Some(callback) = lock_callback {
        callback(lock)?;
    }

    let legacy = new_raw_legacy_lock(&bytes)?;

    Ok(SignedMutationList {
        mutations: vec![legacy],
    })
}

/// Verifies that cluster hashes match between manifest and legacy DAG.
pub(crate) fn cluster_hashes_match(
    dag_manifest: &SignedMutationList,
    dag_legacy: &SignedMutationList,
) -> Result<()> {
    let hash_manifest = types::hash(
        dag_manifest
            .mutations
            .first()
            .ok_or(ManifestError::EmptyDAG)?,
    )?;

    let hash_legacy = types::hash(
        dag_legacy
            .mutations
            .first()
            .ok_or(ManifestError::EmptyDAG)?,
    )?;

    if hash_manifest != hash_legacy {
        return Err(ManifestError::ClusterHashMismatch {
            manifest_hash: hex::encode(&hash_manifest),
            legacy_hash: hex::encode(&hash_legacy),
        });
    }

    Ok(())
}
