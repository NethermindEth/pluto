//! # Charon P2P K1

use std::path::{Path, PathBuf};

use charon_k1util as k1util;
use k256::{SecretKey, elliptic_curve::rand_core::OsRng};
use rand::RngCore;

const KEY_FILE_NAME: &str = "charon-enr-private-key";
const KEY_BACKUP_DIR: &str = "charon-enr-private-key-backups";

type Result<T> = std::result::Result<T, K1Error>;

/// An error that can occur when loading a private key.
#[derive(Debug, thiserror::Error)]
pub enum K1Error {
    /// K1 utility error.
    #[error("K1 utility error: {0}")]
    K1UtilError(#[from] k1util::K1UtilError),

    /// IOError.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Returns the charon-enr-private-key path relative to the data dir.
pub fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(KEY_FILE_NAME)
}

/// Loads the private key from the data dir.
pub fn load_priv_key(data_dir: &Path) -> Result<SecretKey> {
    k1util::load(&key_path(data_dir)).map_err(K1Error::K1UtilError)
}

/// Generates a new private key and saves it to the data dir.
pub fn new_saved_priv_key(data_dir: &Path) -> Result<SecretKey> {
    backup_priv_key(data_dir)?;

    std::fs::create_dir_all(data_dir)?;

    let key = SecretKey::random(&mut OsRng);

    k1util::save(&key, &key_path(data_dir)).map_err(K1Error::K1UtilError)?;

    Ok(key)
}

/// Backs up the private key to the backup directory.
///
/// The backup directory is created if it doesn't exist.
fn backup_priv_key(data_dir: &Path) -> Result<()> {
    let key_path = key_path(data_dir);

    if !key_path.exists() {
        // Nothing to backup
        return Ok(());
    }

    let current_time = chrono::Utc::now();
    let nonce = OsRng.next_u64();
    let backup_path = data_dir.join(KEY_BACKUP_DIR).join(format!(
        "{}_{}",
        current_time.format("%Y-%m-%d_%H-%M-%S_%f"),
        nonce
    ));
    std::fs::create_dir_all(
        backup_path
            .parent()
            .expect("Backup path parent should exist"),
    )
    .map_err(K1Error::IoError)?;
    if backup_path.is_dir() {
        panic!("Backup path is a directory: {:?}", backup_path);
    }
    std::fs::copy(key_path, backup_path).map_err(K1Error::IoError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::rand_core::OsRng;
    use std::{collections::HashSet, fs};
    use tempfile::TempDir;

    fn setup_temp_dir() -> TempDir {
        tempfile::tempdir().expect("Failed to create temp dir")
    }

    fn create_test_key_file(data_dir: &Path) -> Result<SecretKey> {
        let key = SecretKey::random(&mut OsRng);
        k1util::save(&key, &key_path(data_dir))?;
        Ok(key)
    }

    #[test]
    fn test_key_path() {
        let data_dir = Path::new("/test/data");
        let path = key_path(data_dir);
        assert_eq!(path, PathBuf::from("/test/data/charon-enr-private-key"));
    }

    #[test]
    fn test_new_saved_priv_key_creates_key() -> Result<()> {
        let temp_dir = setup_temp_dir();
        let data_dir = temp_dir.path();

        let key = new_saved_priv_key(data_dir)?;

        let key_file = key_path(data_dir);
        assert!(key_file.exists());

        let loaded_key = load_priv_key(data_dir)?;
        assert_eq!(key.to_bytes(), loaded_key.to_bytes());

        Ok(())
    }

    #[test]
    fn test_new_saved_priv_key_creates_data_dir() -> Result<()> {
        let temp_dir = setup_temp_dir();
        let data_dir = temp_dir.path().join("new_dir");

        assert!(!data_dir.exists());

        new_saved_priv_key(&data_dir)?;

        assert!(data_dir.exists());
        assert!(data_dir.is_dir());

        assert!(key_path(&data_dir).exists());

        Ok(())
    }

    #[test]
    fn test_load_priv_key_success() -> Result<()> {
        let temp_dir = setup_temp_dir();
        let data_dir = temp_dir.path();

        let original_key = create_test_key_file(data_dir)?;

        let loaded_key = load_priv_key(data_dir)?;

        assert_eq!(original_key.to_bytes(), loaded_key.to_bytes());

        Ok(())
    }

    #[test]
    fn test_load_priv_key_file_not_found() {
        let temp_dir = setup_temp_dir();
        let data_dir = temp_dir.path();

        let result = load_priv_key(data_dir);

        assert!(result.is_err());
        assert!(matches!(result, Err(K1Error::K1UtilError(_))));
    }

    #[test]
    fn test_backup_priv_key_creates_backup() -> Result<()> {
        let temp_dir = setup_temp_dir();
        let data_dir = temp_dir.path();

        create_test_key_file(data_dir)?;

        backup_priv_key(data_dir)?;

        let backup_dir = data_dir.join(KEY_BACKUP_DIR);
        assert!(backup_dir.exists());
        assert!(backup_dir.is_dir());

        let entries: Vec<_> = fs::read_dir(&backup_dir)?.filter_map(|e| e.ok()).collect();
        assert_eq!(entries.len(), 1);

        Ok(())
    }

    #[test]
    fn test_new_saved_priv_key_with_existing_key() -> Result<()> {
        let temp_dir = setup_temp_dir();
        let data_dir = temp_dir.path();

        let first_key = new_saved_priv_key(data_dir)?;

        let second_key = new_saved_priv_key(data_dir)?;

        assert_ne!(first_key.to_bytes(), second_key.to_bytes());

        let loaded_key = load_priv_key(data_dir)?;
        assert_eq!(second_key.to_bytes(), loaded_key.to_bytes());

        let backup_dir = data_dir.join(KEY_BACKUP_DIR);
        assert!(backup_dir.exists());

        let entries: Vec<_> = fs::read_dir(&backup_dir)?.filter_map(|e| e.ok()).collect();
        assert_eq!(entries.len(), 1);

        Ok(())
    }

    #[test]
    fn test_backup_uniqueness() -> Result<()> {
        const NUM_BACKUPS: usize = 5;

        let temp_dir = setup_temp_dir();
        let data_dir = temp_dir.path();

        create_test_key_file(data_dir)?;

        for _ in 0..NUM_BACKUPS {
            backup_priv_key(data_dir)?;
        }

        let backup_dir = data_dir.join(KEY_BACKUP_DIR);
        let entries: Vec<_> = fs::read_dir(&backup_dir)?.filter_map(|e| e.ok()).collect();
        let backup_names: HashSet<_> = entries.iter().map(|e| e.file_name()).collect();

        assert_eq!(
            backup_names.len(),
            NUM_BACKUPS,
            "Should have 5 unique backup names"
        );

        Ok(())
    }
}
