// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business
// Source License 1.1

//! Tests for keystore module. Translated from Go keystore_test.go.

use std::path::PathBuf;

use pluto_crypto::{blst_impl::BlstImpl, tbls::Tbls, types::PrivateKey};
use tempfile::TempDir;

use super::*;

/// Generates a random BLS secret key for testing.
fn generate_secret_key() -> PrivateKey {
    let tbls = BlstImpl;
    tbls.generate_secret_key(rand::thread_rng()).unwrap()
}

/// Helper: generates a new key, stores it insecurely, then renames the files
/// to the target filename. Returns the generated key.
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

#[tokio::test]
async fn store_load() {
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
async fn store_load_non_charon_names() {
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
async fn store_load_keys_all() {
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
async fn store_load_non_sequential_idx() {
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
async fn store_load_sequential_non_charon_names() {
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

/// Table-driven test for sequenced keys.
#[tokio::test]
async fn sequenced_keys() {
    struct TestCase {
        name: &'static str,
        suffixes: Vec<&'static str>,
        ok: bool,
    }

    let tests = vec![
        TestCase {
            name: "happy 1",
            suffixes: vec!["0"],
            ok: true,
        },
        TestCase {
            name: "happy 2",
            suffixes: vec!["0", "1"],
            ok: true,
        },
        TestCase {
            name: "happy 4",
            suffixes: vec!["0", "1", "2", "3"],
            ok: true,
        },
        TestCase {
            name: "missing 0",
            suffixes: vec!["1", "2", "3"],
            ok: false,
        },
        TestCase {
            name: "missing 2",
            suffixes: vec!["0", "1", "3"],
            ok: false,
        },
        TestCase {
            name: "missing range",
            suffixes: vec!["0", "17"],
            ok: false,
        },
        TestCase {
            name: "happy 20",
            suffixes: vec![
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
                "15", "16", "17", "18", "19",
            ],
            ok: true,
        },
        TestCase {
            name: "single non-numeric",
            suffixes: vec!["0", "1", "foo"],
            ok: false,
        },
        TestCase {
            name: "all non-numeric",
            suffixes: vec!["foo", "bar02", "qux-01"],
            ok: false,
        },
    ];

    for test in tests {
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        let mut expected = Vec::new();

        for suffix in &test.suffixes {
            let target = format!("{}/keystore-{}.json", dir_path, suffix);
            let secret = store_new_key_for_test(&target).await;
            expected.push(secret);
        }

        let key_files = load_files_unordered(&dir_path).await.unwrap();

        let result = key_files.sequenced_keys();
        if !test.ok {
            assert!(result.is_err(), "test '{}' should have failed", test.name);
            continue;
        }

        let actual = result.unwrap_or_else(|e| panic!("test '{}' failed: {}", test.name, e));
        assert_eq!(expected, actual, "test '{}' keys mismatch", test.name);
    }
}

#[tokio::test]
async fn test_load_files_recursively() {
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

#[tokio::test]
async fn test_check_dir() {
    let err = store_keys(&[], "foo").await.unwrap_err();
    assert!(
        err.to_string().contains("not exist"),
        "unexpected error: {}",
        err
    );

    let testdata_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/keystore/testdata/keystore-scrypt.json")
        .to_string_lossy()
        .to_string();

    let err = store_keys(&[], &testdata_path).await.unwrap_err();
    assert!(
        err.to_string().contains("not a directory"),
        "unexpected error: {}",
        err
    );
}
