//! Loading and verification of a cluster [`Lock`] from disk.
//!
//! Mirrors Charon's `cluster.LoadClusterLock` (`cluster/load.go`), which
//! replaced the manifest-DAG loading path when the cluster manifest was
//! removed (Charon #4130). Charon v1.7.1 obtained the cluster by materialising
//! a manifest DAG; this function reads and verifies the cluster lock file
//! directly.

use std::path::Path;

use pluto_eth1wrap::{EthClient, EthClientError};
use tracing::warn;

use crate::lock::{Lock, LockError};

/// Errors returned by [`load_cluster_lock`].
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The cluster-lock file could not be read from disk.
    #[error("read cluster-lock.json {path}: {source}")]
    Read {
        /// Path that failed to read.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The cluster-lock file could not be JSON-decoded.
    #[error("unmarshal cluster-lock.json: {0}")]
    Parse(#[source] serde_json::Error),

    /// Cluster-lock hash verification failed. Re-run with `no_verify` to bypass
    /// this check at your own risk.
    #[error(
        "verify cluster lock hashes (run with no_verify to bypass verification at your own risk): {0}"
    )]
    VerifyHashes(#[source] LockError),

    /// Cluster-lock signature verification failed. Re-run with `no_verify` to
    /// bypass this check at your own risk.
    #[error(
        "verify cluster lock signatures (run with no_verify to bypass verification at your own risk): {0}"
    )]
    VerifySignatures(#[source] LockError),

    /// The execution-layer client could not be constructed.
    #[error("build execution-layer client: {0}")]
    Eth1(#[source] EthClientError),
}

/// Reads the cluster lock file at `lock_file_path`, JSON-decodes it into a
/// [`Lock`], and verifies its hashes and signatures.
///
/// When `no_verify` is set, verification failures are logged as warnings
/// instead of being returned as errors (mirrors Charon's `--no-verify`): both
/// [`Lock::verify_hashes`] and [`Lock::verify_signatures`] still run.
///
/// `eth1` backs EIP-1271 smart-contract operator-signature verification. Pass a
/// no-op client (from `EthClient::new("")`) to skip only the contract-based
/// checks; BLS-aggregate and node signatures are still verified.
///
/// Mirrors Charon's `cluster.LoadClusterLock`.
pub async fn load_cluster_lock(
    lock_file_path: impl AsRef<Path>,
    no_verify: bool,
    eth1: &EthClient,
) -> Result<Lock, LoadError> {
    let path = lock_file_path.as_ref();

    let contents = tokio::fs::read_to_string(path)
        .await
        .map_err(|source| LoadError::Read {
            path: path.display().to_string(),
            source,
        })?;

    let lock: Lock = serde_json::from_str(&contents).map_err(LoadError::Parse)?;

    match lock.verify_hashes() {
        Ok(()) => {}
        Err(err) if no_verify => {
            warn!(%err, "Ignoring failed cluster lock hashes verification due to no_verify flag");
        }
        Err(err) => return Err(LoadError::VerifyHashes(err)),
    }

    match lock.verify_signatures(eth1).await {
        Ok(()) => {}
        Err(err) if no_verify => {
            warn!(%err, "Ignoring failed cluster lock signatures verification due to no_verify flag");
        }
        Err(err) => return Err(LoadError::VerifySignatures(err)),
    }

    Ok(lock)
}

/// Reads and verifies the cluster lock at `lock_file_path` with a default no-op
/// execution-layer client (no configured endpoint) and verification enabled.
///
/// Convenient for standalone tools that only need a verified lock and have no
/// execution-layer endpoint to inject. EIP-1271 smart-contract operator
/// signatures are skipped; BLS-aggregate and node signatures are still
/// verified.
///
/// Mirrors Charon's `cluster.LoadClusterLockAndVerify`.
pub async fn load_cluster_lock_and_verify(
    lock_file_path: impl AsRef<Path>,
) -> Result<Lock, LoadError> {
    let eth1 = EthClient::new("").await.map_err(LoadError::Eth1)?;

    load_cluster_lock(lock_file_path, false, &eth1).await
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    const LOCK_V1_10_0: &str = include_str!("testdata/cluster_lock_v1_10_0.json");

    /// A no-op execution-layer client: BLS-aggregate and node signatures are
    /// still verified, only EIP-1271 contract-based operator signatures are
    /// skipped.
    async fn noop_eth1() -> EthClient {
        EthClient::new("").await.expect("noop eth1 client")
    }

    /// Writes `contents` to a temporary file that `load_cluster_lock` can read
    /// by path.
    fn write_lock(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create temp lock file");
        file.write_all(contents.as_bytes())
            .expect("write temp lock file");
        file.flush().expect("flush temp lock file");
        file
    }

    /// Ports Charon's `TestLoadClusterLock`: the lock is read and parsed and
    /// its fields are populated (verification skipped via `no_verify`).
    #[tokio::test]
    async fn load_cluster_lock_reads_and_parses() {
        let file = write_lock(LOCK_V1_10_0);
        let eth1 = noop_eth1().await;

        let lock = load_cluster_lock(file.path(), true, &eth1)
            .await
            .expect("load lock");

        assert_eq!(lock.definition.name, "test definition");
        assert_eq!(lock.definition.version, "v1.10.0");
        assert_eq!(lock.threshold, 3);
        assert_eq!(lock.distributed_validators.len(), 2);
        assert_eq!(lock.node_signatures.len(), 2);
        assert_eq!(
            lock.lock_hash,
            hex::decode("015036f659bd05894dfb531bf0ab3fdb32a05584ec037fc8262843d14e1aae60")
                .unwrap()
        );
        // Verify first operator
        assert_eq!(
            lock.operators[0].address.to_uppercase(),
            "0x094279db1944ebd7a19d0f7bbacbe0255aa5b7d4".to_uppercase()
        );
        assert_eq!(
            lock.operators[0].enr.to_uppercase(),
            "enr://b0223beea5f4f74391f445d15afd4294040374f6924b98cbf8713f8d962d7c8d".to_uppercase()
        );
        // Verify first distributed validator
        assert_eq!(
            lock.distributed_validators[0].public_key_hex().unwrap().to_uppercase(),
            "0x1814be823350eab13935f31d84484517e924aef78ae151c00755925836b7075885650c30ec29a3703934bf50a28da102".to_uppercase()
        );
        assert_eq!(lock.distributed_validators[0].pub_shares.len(), 2);
    }

    /// With verification enabled, a corrupted lock hash is rejected.
    #[tokio::test]
    async fn load_cluster_lock_rejects_tampered_hash() {
        let mut lock: Lock = serde_json::from_str(LOCK_V1_10_0).unwrap();
        lock.lock_hash[0] ^= 0xff;
        let file = write_lock(&serde_json::to_string(&lock).unwrap());
        let eth1 = noop_eth1().await;

        let err = load_cluster_lock(file.path(), false, &eth1)
            .await
            .expect_err("tampered hash must fail verification");

        assert!(matches!(err, LoadError::VerifyHashes(_)), "got {err:?}");
    }

    /// With `no_verify`, the same corrupted lock is loaded regardless (the
    /// verification failure is downgraded to a warning).
    #[tokio::test]
    async fn load_cluster_lock_no_verify_ignores_tampered_hash() {
        let mut lock: Lock = serde_json::from_str(LOCK_V1_10_0).unwrap();
        lock.lock_hash[0] ^= 0xff;
        let file = write_lock(&serde_json::to_string(&lock).unwrap());
        let eth1 = noop_eth1().await;

        let loaded = load_cluster_lock(file.path(), true, &eth1)
            .await
            .expect("no_verify should ignore verification failures");

        assert_eq!(loaded.definition.version, "v1.10.0");
    }

    /// A missing file surfaces a read error rather than a parse/verify error.
    #[tokio::test]
    async fn load_cluster_lock_missing_file() {
        let eth1 = noop_eth1().await;

        let err = load_cluster_lock("/nonexistent/cluster-lock.json", false, &eth1)
            .await
            .expect_err("missing file must fail");

        assert!(matches!(err, LoadError::Read { .. }), "got {err:?}");
    }

    /// Malformed JSON surfaces a parse error.
    #[tokio::test]
    async fn load_cluster_lock_malformed_json() {
        let file = write_lock("{ not valid json");
        let eth1 = noop_eth1().await;

        let err = load_cluster_lock(file.path(), false, &eth1)
            .await
            .expect_err("malformed json must fail");

        assert!(matches!(err, LoadError::Parse(_)), "got {err:?}");
    }

    /// A freshly generated, self-consistent lock verifies end-to-end with
    /// `no_verify=false` against a no-op execution-layer client.
    #[tokio::test]
    async fn load_cluster_lock_verifies_generated_lock() {
        let (lock, ..) = crate::test_cluster::new_for_test(1, 2, 3, 1);
        let file = write_lock(&serde_json::to_string(&lock).expect("serialize generated lock"));
        let eth1 = noop_eth1().await;

        let loaded = load_cluster_lock(file.path(), false, &eth1)
            .await
            .expect("generated lock should verify");

        assert_eq!(loaded.lock_hash, lock.lock_hash);
    }

    /// The convenience wrapper reads and verifies a self-consistent lock using
    /// its built-in no-op execution-layer client.
    #[tokio::test]
    async fn load_cluster_lock_and_verify_generated_lock() {
        let (lock, ..) = crate::test_cluster::new_for_test(1, 2, 3, 1);
        let file = write_lock(&serde_json::to_string(&lock).expect("serialize generated lock"));

        let loaded = load_cluster_lock_and_verify(file.path())
            .await
            .expect("generated lock should verify");

        assert_eq!(loaded.lock_hash, lock.lock_hash);
    }
}
