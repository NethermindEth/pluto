// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business
// Source License 1.1

//! Error types for keystore operations.

/// Error type for keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Keystore directory does not exist.
    #[error("keystore dir does not exist: {path}")]
    DirNotExist {
        /// Path that was checked.
        path: String,
    },

    /// Path is not a directory.
    #[error("keystore dir is not a directory: {path}")]
    NotADirectory {
        /// Path that was checked.
        path: String,
    },

    /// No keystore files found in directory.
    #[error("no keys found")]
    NoKeysFound,

    /// Keystore password file not found.
    #[error("keystore password file not found {path}")]
    PasswordNotFound {
        /// Password file path.
        path: String,
    },

    /// Out of sequence keystore index.
    #[error("out of sequence keystore index {index} in file {filename}")]
    OutOfSequence {
        /// The index found.
        index: i64,
        /// The filename.
        filename: String,
    },

    /// Duplicate keystore index.
    #[error("duplicate keystore index {index} in file {filename}")]
    DuplicateIndex {
        /// The duplicated index.
        index: i64,
        /// The filename.
        filename: String,
    },

    /// Unknown keystore index.
    #[error("unknown keystore index, filename not 'keystore-%d.json': {filename}")]
    UnknownIndex {
        /// The filename.
        filename: String,
    },

    /// Encryption error.
    #[error("encryption error: {0}")]
    Encrypt(String),

    /// Decryption error.
    #[error("decryption error: {0}")]
    Decrypt(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex decode error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Unsupported KDF function.
    #[error("unsupported KDF: {0}")]
    UnsupportedKdf(String),

    /// Checksum verification failed.
    #[error("decrypt keystore: checksum verification failed")]
    InvalidChecksum,

    /// Invalid decrypted key length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(#[from] pluto_crypto::types::Error),

    /// Glob pattern error.
    #[error("glob pattern error: {0}")]
    GlobPattern(#[from] glob::PatternError),

    /// Scrypt params error.
    #[error("scrypt params error: {0}")]
    ScryptParams(String),

    /// Task join error.
    #[error("task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    /// Walk directory error.
    #[error("walk directory error: {0}")]
    WalkDir(String),

    /// Keystore not found during recursive load.
    #[error("keystore not found: {path}")]
    KeystoreNotFound {
        /// The path that was looked up.
        path: String,
    },

    /// Unexpected regex error when extracting keystore file index.
    #[error("unexpected regex error")]
    UnexpectedRegex,
}

pub(crate) type Result<T> = std::result::Result<T, KeystoreError>;
