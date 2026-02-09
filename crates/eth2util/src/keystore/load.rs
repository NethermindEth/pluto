use std::collections::HashMap;

use pluto_crypto::types::PrivateKey;
use regex::Regex;

use super::{
    error::{KeystoreError, Result},
    store::Keystore,
};

/// Wraps a list of key files with convenience functions.
#[derive(Debug)]
pub struct KeyFiles(Vec<KeyFile>);

impl KeyFiles {
    /// Returns the private keys of the files.
    pub fn keys(&self) -> Vec<PrivateKey> {
        self.0.iter().map(|kf| kf.private_key).collect()
    }

    /// Returns the private keys in strict sequential file index order from 0 to
    /// N.
    ///
    /// If the indexes are unknown or not sequential or there are duplicates,
    /// an error is returned.
    pub fn sequenced_keys(&self) -> Result<Vec<PrivateKey>> {
        let len = self.len();
        let mut resp = vec![PrivateKey::default(); len];
        let zero = PrivateKey::default();

        for kf in &self.0 {
            if !kf.has_index() {
                return Err(KeystoreError::UnknownIndex {
                    filename: kf.filename.clone(),
                });
            }

            let idx = usize::try_from(kf.file_index)
                .ok()
                .filter(|&i| i < len)
                .ok_or_else(|| KeystoreError::OutOfSequence {
                    index: kf.file_index,
                    filename: kf.filename.clone(),
                })?;

            if resp[idx] != zero {
                return Err(KeystoreError::DuplicateIndex {
                    index: kf.file_index,
                    filename: kf.filename.clone(),
                });
            }

            resp[idx] = kf.private_key;
        }

        Ok(resp)
    }

    /// Returns the number of key files.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Represents the result of decrypting a keystore file.
#[derive(Debug, Clone)]
pub struct KeyFile {
    /// The decrypted private key.
    pub private_key: PrivateKey,
    /// The filename of the keystore file.
    pub filename: String,
    /// The index extracted from the filename, or -1 if not present.
    pub file_index: i64,
}

impl KeyFile {
    /// Returns true if the keystore file has a valid index.
    pub fn has_index(&self) -> bool {
        self.file_index != -1
    }
}

/// Returns all decrypted keystore files stored in `dir/keystore-*.json`
/// EIP-2335 keystore files using passwords stored in `dir/keystore-*.txt`.
///
/// The resulting keystore files are in random order.
pub async fn load_files_unordered(dir: &str) -> Result<KeyFiles> {
    let mut read_dir = tokio::fs::read_dir(dir).await?;
    let mut set = tokio::task::JoinSet::new();

    while let Some(entry) = read_dir.next_entry().await? {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if !name.starts_with("keystore-") || !name.ends_with(".json") {
            continue;
        }

        let filename = path.to_string_lossy().to_string();

        set.spawn(async move {
            let b = tokio::fs::read_to_string(&filename).await?;
            let store: Keystore = serde_json::from_str(&b)?;

            let password_file = filename.replacen(".json", ".txt", 1);
            let password = tokio::fs::read_to_string(&password_file)
                .await
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        KeystoreError::PasswordNotFound {
                            path: password_file.clone(),
                        }
                    } else {
                        KeystoreError::Io(e)
                    }
                })?;

            let private_key = super::store::decrypt(&store, &password)?;
            let file_index = extract_file_index(&filename)?;

            Ok::<KeyFile, KeystoreError>(KeyFile {
                private_key,
                filename,
                file_index,
            })
        });
    }

    if set.is_empty() {
        return Err(KeystoreError::NoKeysFound);
    }

    let mut key_files = Vec::new();
    while let Some(res) = set.join_next().await {
        key_files.push(res??);
    }

    Ok(KeyFiles(key_files))
}

/// Loads keystore files recursively from the given directory.
///
/// Works like [`load_files_unordered`] but recursively searches for keystore
/// files in the given directory. It tries matching the found password files to
/// decrypted keystore files.
pub async fn load_files_recursively(dir: &str) -> Result<KeyFiles> {
    // Step 1: Walk the directory recursively to find all .json and .txt files.
    let dir = dir.to_string();
    let (json_files, txt_files) = tokio::task::spawn_blocking(move || {
        let mut json_files = Vec::new();
        let mut txt_files = Vec::new();

        for entry in walkdir::WalkDir::new(&dir) {
            let entry = entry
                .map_err(|e| KeystoreError::WalkDir(format!("failed to walk directory: {e}")))?;

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path().to_string_lossy().to_string();
            match std::path::Path::new(&path)
                .extension()
                .and_then(|e| e.to_str())
            {
                Some("json") => json_files.push(path),
                Some("txt") => txt_files.push(path),
                _ => {}
            }
        }

        Ok::<_, KeystoreError>((json_files, txt_files))
    })
    .await
    .map_err(|e| KeystoreError::WalkDir(format!("walk directory failed: {e}")))??;

    // Step 2: Decode the keystore files
    let mut keystores_map: HashMap<String, Keystore> = HashMap::new();
    let mut valid_files = Vec::new();

    for filepath in &json_files {
        let b = tokio::fs::read_to_string(filepath).await?;

        let Ok(store) = serde_json::from_str::<Keystore>(&b) else {
            continue;
        };

        keystores_map.insert(filepath.clone(), store);
        valid_files.push(filepath.clone());
    }

    // Step 3: Load all passwords from .txt files
    let mut passwords_map: HashMap<String, String> = HashMap::new();
    for filepath in &txt_files {
        let b = tokio::fs::read_to_string(filepath).await?;
        passwords_map.insert(filepath.clone(), b);
    }

    // Step 4: Decrypt keystores concurrently.
    let mut set = tokio::task::JoinSet::new();
    let passwords_map = std::sync::Arc::new(passwords_map);

    for filepath in valid_files {
        let store =
            keystores_map
                .get(&filepath)
                .cloned()
                .ok_or(KeystoreError::KeystoreNotFound {
                    path: filepath.clone(),
                })?;

        let password_file = filepath.replacen(".json", ".txt", 1);
        let passwords = std::sync::Arc::clone(&passwords_map);

        set.spawn(async move {
            // First try the password file that matches the keystore file.
            let mut err = None;

            if let Some(password) = passwords.get(&password_file) {
                match super::store::decrypt(&store, password) {
                    Ok(secret) => return Ok((filepath, secret)),
                    Err(e) => err = Some(e),
                }
            }

            // If no matching password or decryption failed, try all passwords.
            for password in passwords.values() {
                match super::store::decrypt(&store, password) {
                    Ok(secret) => return Ok((filepath, secret)),
                    Err(e) => err = Some(e),
                }
            }

            Err(err.unwrap_or(KeystoreError::Decrypt(
                "no matching password found".to_string(),
            )))
        });
    }

    let mut results = Vec::new();
    while let Some(res) = set.join_next().await {
        results.push(res??);
    }

    // Assign sequential indices after collection since completion order is
    // non-deterministic.
    let key_files = results
        .into_iter()
        .enumerate()
        .map(|(i, (filename, private_key))| KeyFile {
            private_key,
            filename,
            file_index: i64::try_from(i).unwrap_or(-1) + 1,
        })
        .collect();

    Ok(KeyFiles(key_files))
}

/// Regex for matching keystore filenames like `keystore-0.json` or
/// `keystore-insecure-42.json`.
static KEYSTORE_FILE_INDEX_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"keystore-(?:insecure-)?([0-9]+)\.json").expect("invalid regex")
});

/// Extracts the index from a keystore filename, or returns -1 if no index is
/// present.
pub fn extract_file_index(filename: &str) -> Result<i64> {
    if !KEYSTORE_FILE_INDEX_RE.is_match(filename) {
        return Ok(-1);
    }

    let captures = KEYSTORE_FILE_INDEX_RE
        .captures(filename)
        .ok_or(KeystoreError::UnexpectedRegex)?;

    let idx_str = captures
        .get(1)
        .ok_or(KeystoreError::UnexpectedRegex)?
        .as_str();

    let idx: i64 = idx_str
        .parse()
        .map_err(|_| KeystoreError::UnexpectedRegex)?;

    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: @iamquang95 use test-cases
    #[test]
    fn extract_index_standard() {
        assert_eq!(extract_file_index("keystore-0.json").unwrap(), 0);
        assert_eq!(extract_file_index("keystore-1.json").unwrap(), 1);
        assert_eq!(extract_file_index("keystore-42.json").unwrap(), 42);
    }

    #[test]
    fn extract_index_insecure() {
        assert_eq!(extract_file_index("keystore-insecure-0.json").unwrap(), 0);
        assert_eq!(extract_file_index("keystore-insecure-5.json").unwrap(), 5);
    }

    #[test]
    fn extract_index_no_match() {
        assert_eq!(extract_file_index("keystore-foo.json").unwrap(), -1);
        assert_eq!(extract_file_index("keystore-bar-1.json").unwrap(), -1);
        assert_eq!(extract_file_index("other.json").unwrap(), -1);
    }

    #[test]
    fn extract_index_with_path() {
        assert_eq!(extract_file_index("/tmp/dir/keystore-3.json").unwrap(), 3);
        assert_eq!(
            extract_file_index("/tmp/dir/keystore-insecure-7.json").unwrap(),
            7
        );
    }
}
