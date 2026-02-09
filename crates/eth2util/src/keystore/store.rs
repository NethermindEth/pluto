//! Core keystore functionality for EIP-2335 compatible keystore files.
// Package keystore provides functions to store and load private keys
// to/from EIP 2335 (https://eips.ethereum.org/EIPS/eip-2335) compatible Keystore files. Passwords are
// expected/created in files with same identical names as the keystores, except
// with txt extension.

use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::PrivateKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    eip2335::{CryptoSection, EIP2335_KEYSTORE_VERSION, encrypt_eip2335},
    error::{KeystoreError, Result},
};

/// Insecure PBKDF2 iteration count (2^4 = 16) for fast test encryption.
const INSECURE_PBKDF2_C: u32 = 16;

/// EIP-2334 derivation path for Ethereum 2.0 validators.
const EIP2334_PATH: &str = "m/12381/3600/0/0/0";

/// Syntactic sugar to highlight the security implications of insecure keys.
pub struct ConfirmInsecure;

/// Confirms the use of insecure keys for testing purposes.
pub static CONFIRM_INSECURE_KEYS: ConfirmInsecure = ConfirmInsecure;

/// Stores the secrets in `dir/keystore-insecure-%d.json` EIP-2335 keystore
/// files with new random passwords stored in `dir/keystore-insecure-%d.txt`.
///
/// The keystores are insecure and should only be used for testing large
/// validator sets as it speeds up encryption and decryption at the cost of
/// security.
pub async fn store_keys_insecure(
    secrets: &[PrivateKey],
    dir: &str,
    _confirm: &ConfirmInsecure,
) -> Result<()> {
    store_keys_internal(secrets, dir, "keystore-insecure-", Some(INSECURE_PBKDF2_C)).await
}

/// Stores the secrets in `dir/keystore-%d.json` EIP-2335 keystore files
/// with new random passwords stored in `dir/keystore-%d.txt`.
///
/// Note: this doesn't ensure the folder `dir` exists.
pub async fn store_keys(secrets: &[PrivateKey], dir: &str) -> Result<()> {
    store_keys_internal(secrets, dir, "keystore-", None).await
}

/// Internal implementation for storing keystore files concurrently.
async fn store_keys_internal(
    secrets: &[PrivateKey],
    dir: &str,
    filename_prefix: &str,
    pbkdf2_c: Option<u32>,
) -> Result<()> {
    check_dir(dir).await?;

    let mut set = tokio::task::JoinSet::new();

    for (i, secret) in secrets.iter().enumerate() {
        let secret = *secret;
        let dir = dir.to_string();
        let prefix = filename_prefix.to_string();

        set.spawn(async move {
            let filename = format!("{}/{}{}.json", dir, prefix, i);
            let password = random_hex32()?;
            let store = encrypt(&secret, &password, pbkdf2_c)?;
            let b = serialize_keystore(&store)?;

            // Write keystore file with 0o444 permissions (read-only for all).
            write_file(&filename, b.as_bytes(), 0o444).await?;

            store_password(&filename, &password).await?;

            Ok::<(), KeystoreError>(())
        });
    }

    while let Some(res) = set.join_next().await {
        res??;
    }

    Ok(())
}

/// Keystore JSON file representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    /// The encrypted crypto section.
    pub crypto: CryptoSection,
    /// Optional description to help identify the keystore.
    #[serde(default)]
    pub description: String,
    /// Hex-encoded BLS public key.
    #[serde(default)]
    pub pubkey: String,
    /// EIP-2334 derivation path.
    #[serde(default)]
    pub path: String,
    /// UUID identifying this keystore.
    #[serde(rename = "uuid")]
    pub id: String,
    /// Keystore version (must be 4).
    pub version: u32,
}

/// Encrypts a secret as an EIP-2335 keystore using PBKDF2 cipher.
pub fn encrypt(secret: &PrivateKey, password: &str, pbkdf2_c: Option<u32>) -> Result<Keystore> {
    let tbls = BlstImpl;
    let pub_key = tbls
        .secret_to_public_key(secret)
        .map_err(|e| KeystoreError::Encrypt(format!("marshal pubkey: {e}")))?;

    let crypto = encrypt_eip2335(secret.as_slice(), password, pbkdf2_c)?;

    Ok(Keystore {
        crypto,
        description: String::new(),
        pubkey: hex::encode(pub_key),
        path: EIP2334_PATH.to_string(),
        id: generate_uuid(),
        version: EIP2335_KEYSTORE_VERSION,
    })
}

/// Decrypts a keystore and returns the private key.
pub fn decrypt(store: &Keystore, password: &str) -> Result<PrivateKey> {
    let secret_bytes = super::eip2335::decrypt_eip2335(&store.crypto, password)?;

    let len = secret_bytes.len();
    let secret: PrivateKey =
        secret_bytes
            .try_into()
            .map_err(|_| KeystoreError::InvalidKeyLength {
                expected: 32,
                actual: len,
            })?;

    Ok(secret)
}

/// Generates a random UUID in uppercase hex format.
///
/// Format: `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
fn generate_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    Uuid::from_bytes(bytes).to_string().to_uppercase()
}

/// Loads a keystore password from the keystore's associated password file.
pub(crate) async fn load_password(key_file: impl AsRef<str>) -> Result<String> {
    if matches!(
        tokio::fs::metadata(key_file.as_ref()).await,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    ) {
        return Err(KeystoreError::PasswordNotFound {
            path: key_file.as_ref().to_string(),
        });
    }

    let password_file = key_file.as_ref().replacen(".json", ".txt", 1);
    let b = tokio::fs::read_to_string(&password_file).await?;

    Ok(b)
}

/// Stores a password to the keystore's associated password file.
pub async fn store_password(key_file: &str, password: &str) -> Result<()> {
    let password_file = key_file.replacen(".json", ".txt", 1);
    // Write password file with 0o400 permissions (read-only for owner).
    write_file(&password_file, password.as_bytes(), 0o400).await
}

/// Returns a random 32-character hex string using crypto-secure RNG.
pub fn random_hex32() -> Result<String> {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    Ok(hex::encode(b))
}

/// Checks if `dir` exists and is a directory.
pub async fn check_dir(dir: &str) -> Result<()> {
    let metadata = tokio::fs::metadata(dir).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            KeystoreError::DirNotExist {
                path: dir.to_string(),
            }
        } else {
            KeystoreError::Io(e)
        }
    })?;

    if !metadata.is_dir() {
        return Err(KeystoreError::NotADirectory {
            path: dir.to_string(),
        });
    }

    Ok(())
}

/// Serializes a keystore to JSON with 1-space indentation
fn serialize_keystore(store: &Keystore) -> Result<String> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    store.serialize(&mut ser)?;

    String::from_utf8(buf).map_err(|e| KeystoreError::Encrypt(format!("utf8 error: {e}")))
}

/// Writes `data` to `path` with the given unix mode bits.
async fn write_file(path: &str, data: &[u8], mode: u32) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .await?;
    file.write_all(data).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::PrivateKey};
    use tempfile::TempDir;

    use super::*;
    use crate::keystore::load::load_files_unordered;

    /// Generates a random BLS secret key for testing.
    fn generate_secret_key() -> PrivateKey {
        let tbls = BlstImpl;
        tbls.generate_secret_key(rand::thread_rng()).unwrap()
    }

    #[tokio::test]
    async fn store_load_insecure() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        let mut secrets = Vec::new();
        for _ in 0..2 {
            secrets.push(generate_secret_key());
        }

        store_keys_insecure(&secrets, &dir_path, &CONFIRM_INSECURE_KEYS)
            .await
            .unwrap();

        let key_files = load_files_unordered(&dir_path).await.unwrap();

        let actual = key_files.sequenced_keys().unwrap();

        assert_eq!(secrets, actual);
    }

    #[tokio::test]
    async fn store_load_secure() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        let mut secrets = Vec::new();
        for _ in 0..3 {
            secrets.push(generate_secret_key());
        }

        store_keys(&secrets, &dir_path).await.unwrap();

        let key_files = load_files_unordered(&dir_path).await.unwrap();

        let actual = key_files.sequenced_keys().unwrap();

        assert_eq!(secrets, actual);
    }

    #[tokio::test]
    async fn check_dir_test() {
        let err = store_keys(&[], "foo").await.unwrap_err();
        assert!(matches!(err, KeystoreError::DirNotExist { .. }));

        let testdata_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/keystore/testdata/keystore-scrypt.json")
            .to_string_lossy()
            .to_string();

        let err = store_keys(&[], &testdata_path).await.unwrap_err();
        assert!(matches!(err, KeystoreError::NotADirectory { .. }));
    }
}
