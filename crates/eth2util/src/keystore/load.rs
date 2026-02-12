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
        self.iter().map(|kf| kf.private_key).collect()
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

        for kf in self.iter() {
            let idx = kf.file_index.ok_or_else(|| KeystoreError::UnknownIndex {
                filename: kf.filename.clone(),
            })?;

            if idx >= len {
                return Err(KeystoreError::OutOfSequence {
                    index: idx,
                    filename: kf.filename.clone(),
                });
            }

            if resp[idx] != zero {
                return Err(KeystoreError::DuplicateIndex {
                    index: idx,
                    filename: kf.filename.clone(),
                });
            }

            resp[idx] = kf.private_key;
        }

        Ok(resp)
    }
}

impl std::ops::Deref for KeyFiles {
    type Target = [KeyFile];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Represents the result of decrypting a keystore file.
#[derive(Debug, Clone)]
pub struct KeyFile {
    /// The decrypted private key.
    pub private_key: PrivateKey,
    /// The filename of the keystore file.
    pub filename: String,
    /// The index extracted from the filename, or None if not present.
    pub file_index: Option<usize>,
}

/// Returns all decrypted keystore files stored in `dir/keystore-*.json`
/// EIP-2335 keystore files using passwords stored in `dir/keystore-*.txt`.
///
/// The resulting keystore files are in random order.
pub async fn load_files_unordered(dir: impl AsRef<str>) -> Result<KeyFiles> {
    let mut read_dir = tokio::fs::read_dir(dir.as_ref()).await?;
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

            let password = super::store::load_password(&filename).await?;
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
pub async fn load_files_recursively(dir: impl AsRef<str>) -> Result<KeyFiles> {
    // Step 1: Walk the directory recursively to find all .json and .txt files.
    let dir = dir.as_ref().to_string();
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
            file_index: Some(i.saturating_add(1)),
        })
        .collect();

    Ok(KeyFiles(key_files))
}

/// Regex for matching keystore filenames like `keystore-0.json` or
/// `keystore-insecure-42.json`.
static KEYSTORE_FILE_INDEX_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"keystore-(?:insecure-)?([0-9]+)\.json").expect("invalid regex")
});

/// Extracts the index from a keystore filename, or returns None if no index is
/// present.
pub fn extract_file_index(filename: impl AsRef<str>) -> Result<Option<usize>> {
    if !KEYSTORE_FILE_INDEX_RE.is_match(filename.as_ref()) {
        return Ok(None);
    }

    let captures = KEYSTORE_FILE_INDEX_RE
        .captures(filename.as_ref())
        .ok_or(KeystoreError::UnexpectedRegex)?;

    let idx_str = captures
        .get(1)
        .ok_or(KeystoreError::UnexpectedRegex)?
        .as_str();

    let idx: usize = idx_str
        .parse()
        .map_err(|_| KeystoreError::UnexpectedRegex)?;

    Ok(Some(idx))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::PrivateKey};
    use tempfile::TempDir;
    use test_case::test_case;

    use super::*;
    use crate::keystore::store::{CONFIRM_INSECURE_KEYS, store_keys_insecure};

    /// Generates a random BLS secret key for testing.
    fn generate_secret_key() -> PrivateKey {
        let tbls = BlstImpl;
        tbls.generate_secret_key(rand::thread_rng()).unwrap()
    }

    /// Helper: generates a new key, stores it insecurely, then renames the
    /// files to the target filename. Returns the generated key.
    async fn store_new_key_for_test(target: &str) -> PrivateKey {
        let secret = generate_secret_key();
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        store_keys_insecure(&[secret], &dir_path, &CONFIRM_INSECURE_KEYS)
            .await
            .unwrap();

        let src_json = format!("{}/keystore-insecure-0.json", dir_path);
        let src_txt = format!("{}/keystore-insecure-0.txt", dir_path);
        let target_txt = target.replacen(".json", ".txt", 1);

        std::fs::rename(&src_json, target).unwrap();
        std::fs::rename(&src_txt, &target_txt).unwrap();

        secret
    }

    #[test_case("keystore-0.json", 0 ; "standard_0")]
    #[test_case("keystore-1.json", 1 ; "standard_1")]
    #[test_case("keystore-42.json", 42 ; "standard_42")]
    fn extract_index_standard(filename: &str, expected: usize) {
        assert_eq!(extract_file_index(filename).unwrap(), Some(expected));
    }

    #[test_case("keystore-insecure-0.json", 0 ; "insecure_0")]
    #[test_case("keystore-insecure-5.json", 5 ; "insecure_5")]
    fn extract_index_insecure(filename: &str, expected: usize) {
        assert_eq!(extract_file_index(filename).unwrap(), Some(expected));
    }

    #[test_case("keystore-foo.json" ; "foo")]
    #[test_case("keystore-bar-1.json" ; "bar_1")]
    #[test_case("other.json" ; "other")]
    fn extract_index_no_match(filename: &str) {
        assert_eq!(extract_file_index(filename).unwrap(), None);
    }

    #[test_case("/tmp/dir/keystore-3.json", 3 ; "with_path_3")]
    #[test_case("/tmp/dir/keystore-insecure-7.json", 7 ; "with_path_insecure_7")]
    fn extract_index_with_path(filename: &str, expected: usize) {
        assert_eq!(extract_file_index(filename).unwrap(), Some(expected));
    }

    #[tokio::test]
    async fn load_empty() {
        let result = load_files_unordered(".").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn load_scrypt() {
        let testdata_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/keystore/testdata")
            .to_string_lossy()
            .to_string();

        let keyfiles = load_files_unordered(&testdata_dir).await.unwrap();

        assert_eq!(keyfiles.len(), 1);

        let hex_key = hex::encode(keyfiles[0].private_key);
        assert_eq!(
            hex_key,
            "10b16fc552aa607fa1399027f7b86ab789077e470b5653b338693dc2dde02468"
        );
    }

    #[tokio::test]
    async fn load_non_charon_names() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        let mut filenames = [
            "keystore-bar-1".to_string(),
            "keystore-bar-2".to_string(),
            "keystore-bar-10".to_string(),
            "keystore-foo".to_string(),
        ];
        filenames.sort();

        let mut secrets = Vec::new();
        let mut expect = std::collections::HashSet::new();

        for _ in 0..filenames.len() {
            let secret = generate_secret_key();
            secrets.push(secret);
            expect.insert(secret);
        }

        store_keys_insecure(&secrets, &dir_path, &CONFIRM_INSECURE_KEYS)
            .await
            .unwrap();

        // Rename according to filenames slice
        for (idx, name) in filenames.iter().enumerate() {
            let old_json = format!("{}/keystore-insecure-{}.json", dir_path, idx);
            let new_json = format!("{}/{}.json", dir_path, name);
            std::fs::rename(&old_json, &new_json).unwrap();

            let old_txt = format!("{}/keystore-insecure-{}.txt", dir_path, idx);
            let new_txt = format!("{}/{}.txt", dir_path, name);
            std::fs::rename(&old_txt, &new_txt).unwrap();
        }

        let key_files = load_files_unordered(&dir_path).await.unwrap();

        assert_eq!(key_files.len(), expect.len());

        for key_file in key_files.iter() {
            assert!(expect.contains(&key_file.private_key));
        }
    }

    #[tokio::test]
    async fn load_non_sequential_idx() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        let mut secrets = Vec::new();
        for _ in 0..2 {
            secrets.push(generate_secret_key());
        }

        store_keys_insecure(&secrets, &dir_path, &CONFIRM_INSECURE_KEYS)
            .await
            .unwrap();

        let old_path = format!("{}/keystore-insecure-1.json", dir_path);
        let new_path = format!("{}/keystore-insecure-42.json", dir_path);
        std::fs::rename(&old_path, &new_path).unwrap();

        let old_path = format!("{}/keystore-insecure-1.txt", dir_path);
        let new_path = format!("{}/keystore-insecure-42.txt", dir_path);
        std::fs::rename(&old_path, &new_path).unwrap();

        let key_files = load_files_unordered(&dir_path).await.unwrap();

        let result = key_files.sequenced_keys();
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("out of sequence keystore index"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn load_sequential_non_charon_names() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        let mut filenames = [
            "keystore-bar-1".to_string(),
            "keystore-bar-2".to_string(),
            "keystore-bar-10".to_string(),
            "keystore-foo".to_string(),
        ];
        filenames.sort();

        let mut secrets = Vec::new();
        for _ in 0..filenames.len() {
            secrets.push(generate_secret_key());
        }

        store_keys_insecure(&secrets, &dir_path, &CONFIRM_INSECURE_KEYS)
            .await
            .unwrap();

        // Rename according to filenames slice
        for (idx, name) in filenames.iter().enumerate() {
            let old_json = format!("{}/keystore-insecure-{}.json", dir_path, idx);
            let new_json = format!("{}/{}.json", dir_path, name);
            std::fs::rename(&old_json, &new_json).unwrap();

            let old_txt = format!("{}/keystore-insecure-{}.txt", dir_path, idx);
            let new_txt = format!("{}/{}.txt", dir_path, name);
            std::fs::rename(&old_txt, &new_txt).unwrap();
        }

        let key_files = load_files_unordered(&dir_path).await.unwrap();

        let result = key_files.sequenced_keys();
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown keystore index, filename not 'keystore-%d.json'"),
            "unexpected error: {}",
            err
        );
    }

    /// Table-driven test for sequenced keys.
    #[test_case(&["0"], true ; "happy_1")]
    #[test_case(&["0", "1"], true ; "happy_2")]
    #[test_case(&["0", "1", "2", "3"], true ; "happy_4")]
    #[test_case(&["1", "2", "3"], false ; "missing_0")]
    #[test_case(&["0", "1", "3"], false ; "missing_2")]
    #[test_case(&["0", "17"], false ; "missing_range")]
    #[test_case(&["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19"], true ; "happy_20")]
    #[test_case(&["0", "1", "foo"], false ; "single_non_numeric")]
    #[test_case(&["foo", "bar02", "qux-01"], false ; "all_non_numeric")]
    #[tokio::test]
    async fn sequenced_keys(suffixes: &[&str], should_succeed: bool) {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        let mut expected = Vec::new();

        for suffix in suffixes {
            let target = format!("{}/keystore-{}.json", dir_path, suffix);
            let secret = store_new_key_for_test(&target).await;
            expected.push(secret);
        }

        let key_files = load_files_unordered(&dir_path).await.unwrap();

        let result = key_files.sequenced_keys();
        if !should_succeed {
            assert!(result.is_err(), "test should have failed");
            return;
        }

        let actual = result.expect("test should have succeeded");
        assert_eq!(expected, actual, "keys mismatch");
    }

    #[tokio::test]
    async fn load_files_recursively_test() {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        // Create a nested directory structure with keystore files
        let nested_dir = format!("{}/nested", dir_path);
        std::fs::create_dir(&nested_dir).unwrap();

        // Store keys in root & nested directories
        let pk1 = store_new_key_for_test(&format!("{}/keystore-alpha.json", dir_path)).await;
        let pk2 = store_new_key_for_test(&format!("{}/keystore-bravo.json", nested_dir)).await;

        let key_files = load_files_recursively(&dir_path).await.unwrap();

        assert_eq!(key_files.len(), 2);

        // Check if both keys are loaded correctly
        for kf in key_files.iter() {
            let is_pk1 = kf.private_key == pk1;
            let is_pk2 = kf.private_key == pk2;
            assert!(is_pk1 || is_pk2, "Loaded key does not match expected keys");
        }

        assert_ne!(key_files[0].private_key, key_files[1].private_key);
        assert_ne!(key_files[0].file_index, key_files[1].file_index);

        // Sub-test: shuffle password files
        let alpha_password =
            std::fs::read_to_string(format!("{}/keystore-alpha.txt", dir_path)).unwrap();
        let bravo_password =
            std::fs::read_to_string(format!("{}/keystore-bravo.txt", nested_dir)).unwrap();

        std::fs::remove_file(format!("{}/keystore-alpha.txt", dir_path)).unwrap();
        std::fs::remove_file(format!("{}/keystore-bravo.txt", nested_dir)).unwrap();

        // Write swapped passwords
        std::fs::write(format!("{}/keystore-alpha.txt", dir_path), &bravo_password).unwrap();
        std::fs::write(
            format!("{}/keystore-bravo.txt", nested_dir),
            &alpha_password,
        )
        .unwrap();

        let key_files = load_files_recursively(&dir_path).await.unwrap();

        assert_eq!(key_files.len(), 2);
    }
}
