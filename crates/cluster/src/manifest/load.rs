use std::path::Path;

use prost::Message as _;

use crate::{
    lock::Lock,
    manifestpb::v1::{Cluster, SignedMutationList},
};

use super::{
    ManifestError, Result, materialise::materialise, mutationlegacylock::new_raw_legacy_lock,
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
    let hash_manifest = dag_manifest
        .mutations
        .first()
        .ok_or(ManifestError::EmptyDAG)?
        .hash()?;

    let hash_legacy = dag_legacy
        .mutations
        .first()
        .ok_or(ManifestError::EmptyDAG)?
        .hash()?;

    if hash_manifest != hash_legacy {
        return Err(ManifestError::ClusterHashMismatch {
            manifest_hash: hex::encode(&hash_manifest),
            legacy_hash: hex::encode(&hash_legacy),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lock::Lock,
        manifest::{materialise::materialise, mutationlegacylock::new_raw_legacy_lock},
    };
    use std::{fs, path::PathBuf};
    use test_case::test_case;

    fn testdata_path(filename: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("testdata")
            .join(filename)
    }

    fn manifest_testdata_path(filename: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("manifest")
            .join("testdata")
            .join(filename)
    }

    #[test_case("", "", Some(ManifestError::NoFileFound { lock_file: String::new(), manifest_file: String::new() }) ; "no_files")]
    #[test_case("manifest", "", None ; "only_manifest")]
    #[test_case("", "lock.json", None ; "only_legacy_lock")]
    #[test_case("manifest", "lock.json", None ; "both_files")]
    #[test_case("manifest", "lock2.json", Some(ManifestError::ClusterHashMismatch { manifest_hash: String::new(), legacy_hash: String::new() }) ; "mismatching_cluster_hashes")]
    fn load_manifest(
        manifest_file: &str,
        legacy_lock_file: &str,
        expected_error: Option<ManifestError>,
    ) {
        // Setup: Load legacy lock and create manifest file (shared across all tests)
        let lock_path = manifest_testdata_path("lock.json");
        let lock_bytes = fs::read(&lock_path).unwrap();
        let lock: Lock = serde_json::from_slice(&lock_bytes).unwrap();

        let json_bytes = serde_json::to_vec(&lock).unwrap();
        let legacy_lock = new_raw_legacy_lock(&json_bytes).unwrap();
        let dag = SignedMutationList {
            mutations: vec![legacy_lock],
        };
        let expected_cluster = materialise(&dag).unwrap();

        // Write manifest file to temp directory
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("cluster-manifest.pb");
        let manifest_bytes = dag.encode_to_vec();
        fs::write(&manifest_path, manifest_bytes).unwrap();

        // Map test parameters to actual paths
        let lock_file_path = if !legacy_lock_file.is_empty() {
            Some(manifest_testdata_path(legacy_lock_file))
        } else {
            None
        };

        let manifest_arg = if manifest_file == "manifest" {
            manifest_path.to_str().unwrap()
        } else {
            manifest_file
        };
        let lock_arg = lock_file_path
            .as_ref()
            .map(|p| p.to_str().unwrap())
            .unwrap_or("");

        // Load raw cluster DAG from disk
        let result = load_dag(
            manifest_arg,
            lock_arg,
            Option::<fn(Lock) -> Result<()>>::None,
        );

        if let Some(expected_err) = expected_error {
            assert!(result.is_err());
            let err = result.unwrap_err();
            match expected_err {
                ManifestError::NoFileFound { .. } => {
                    assert!(matches!(err, ManifestError::NoFileFound { .. }));
                }
                ManifestError::ClusterHashMismatch { .. } => {
                    assert!(matches!(err, ManifestError::ClusterHashMismatch { .. }));
                }
                _ => panic!("Unexpected error type"),
            }
        } else {
            let loaded_dag = result.unwrap();

            // The only mutation is the `legacy_lock` mutation
            assert_eq!(loaded_dag.mutations.len(), 1);

            let cluster_from_dag = materialise(&loaded_dag).unwrap();
            let loaded_cluster = load_cluster(
                manifest_arg,
                lock_arg,
                Option::<fn(Lock) -> Result<()>>::None,
            )
            .unwrap();
            assert_eq!(expected_cluster, loaded_cluster);
            assert_eq!(expected_cluster, cluster_from_dag);
        }
    }

    #[test]
    #[ignore] // TODO: lock3.json has null values that aren't compatible with Lock struct deserialization
    fn load_modified_legacy_lock() {
        // This test ensures the hard-coded hash is used for legacy locks,
        // even if the lock file was modified and run with --no-verify
        let lock3_path = manifest_testdata_path("lock3.json");
        let cluster =
            load_cluster("", &lock3_path, Option::<fn(Lock) -> Result<()>>::None).unwrap();

        let hash_hex = hex::encode(&cluster.initial_mutation_hash);
        // Verify the hash starts with expected prefix
        assert_eq!(&hash_hex[..9], "4073fe542");
    }

    // Parametrized test across all supported versions
    #[test_case("v1.0.0")]
    #[test_case("v1.1.0")]
    #[test_case("v1.2.0")]
    #[test_case("v1.3.0")]
    #[test_case("v1.4.0")]
    #[test_case("v1.5.0")]
    #[test_case("v1.6.0")]
    #[test_case("v1.7.0")]
    #[test_case("v1.8.0")]
    #[test_case("v1.9.0")]
    #[test_case("v1.10.0")]
    fn load_legacy_version(version: &str) {
        // Load the lock file for this version
        let filename = format!("cluster_lock_{}.json", version.replace('.', "_"));
        let lock_path = testdata_path(&filename);

        let lock_bytes = fs::read(&lock_path).unwrap();
        let lock: Lock = serde_json::from_slice(&lock_bytes).unwrap();

        // Create temp file for the lock
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_lock_path = temp_dir.path().join("lock.json");
        fs::write(&temp_lock_path, &lock_bytes).unwrap();

        // Load cluster from the lock file
        let cluster =
            load_cluster("", &temp_lock_path, Option::<fn(Lock) -> Result<()>>::None).unwrap();

        // Verify loaded cluster properties match the lock
        assert_eq!(
            cluster.initial_mutation_hash, lock.lock_hash,
            "initial mutation hash should match lock hash"
        );
        assert_eq!(
            cluster.latest_mutation_hash, lock.lock_hash,
            "latest mutation hash should match lock hash"
        );
        assert_eq!(cluster.name, lock.name);
        #[allow(clippy::cast_possible_truncation)]
        {
            assert_eq!(cluster.threshold, lock.threshold as i32);
        }
        assert_eq!(cluster.dkg_algorithm, lock.dkg_algorithm);
        assert_eq!(cluster.fork_version.as_ref(), lock.fork_version.as_slice());
        assert_eq!(cluster.validators.len(), lock.distributed_validators.len());
        assert_eq!(cluster.operators.len(), lock.operators.len());

        // Verify validators
        for (i, validator) in cluster.validators.iter().enumerate() {
            assert_eq!(
                validator.public_key.as_ref(),
                lock.distributed_validators[i].pub_key.as_slice()
            );
            assert_eq!(
                validator.pub_shares.len(),
                lock.distributed_validators[i].pub_shares.len()
            );
            assert_eq!(
                validator.fee_recipient_address,
                lock.validator_addresses[i].fee_recipient_address
            );
            assert_eq!(
                validator.withdrawal_address,
                lock.validator_addresses[i].withdrawal_address
            );
        }

        // Verify operators
        for (i, operator) in cluster.operators.iter().enumerate() {
            assert_eq!(operator.address, lock.operators[i].address);
            assert_eq!(operator.enr, lock.operators[i].enr);
        }
    }
}
