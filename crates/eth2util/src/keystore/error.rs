use std::path::PathBuf;

use pluto_crypto::types::PRIVATE_KEY_LENGTH;

/// Error type for keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Keystore directory does not exist.
    #[error("keystore dir does not exist: {}", path.display())]
    DirNotExist {
        /// Path that was checked.
        path: PathBuf,
    },

    /// Path is not a directory.
    #[error("keystore dir is not a directory: {}", path.display())]
    NotADirectory {
        /// Path that was checked.
        path: PathBuf,
    },

    /// No keystore files found in directory.
    #[error("no keys found")]
    NoKeysFound,

    /// Keystore password file not found.
    #[error("keystore password file not found {}", path.display())]
    PasswordNotFound {
        /// Password file path.
        path: PathBuf,
    },

    /// Out of sequence keystore index.
    #[error("out of sequence keystore index {index} in file {filename}")]
    OutOfSequence {
        /// The index found.
        index: usize,
        /// The filename.
        filename: String,
    },

    /// Duplicate keystore index.
    #[error("duplicate keystore index {index} in file {filename}")]
    DuplicateIndex {
        /// The duplicated index.
        index: usize,
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

    /// Invalid PBKDF2 parameters.
    #[error("invalid pbkdf2 param")]
    InvalidPbkdf2Param,

    /// Invalid scrypt parameters.
    #[error("invalid scrypt param")]
    InvalidScryptParam,

    /// Invalid salt length.
    #[error("invalid salt length")]
    InvalidSaltLength,

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
    #[error("invalid key length: expected {PRIVATE_KEY_LENGTH}, got {actual}")]
    InvalidKeyLength {
        /// Actual byte length.
        actual: usize,
    },

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(#[from] pluto_crypto::types::Error),

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
    #[error("keystore not found: {}", path.display())]
    KeystoreNotFound {
        /// The path that was looked up.
        path: PathBuf,
    },

    /// Unexpected regex error when extracting keystore file index.
    #[error("unexpected regex error")]
    UnexpectedRegex,
}

pub(crate) type Result<T> = std::result::Result<T, KeystoreError>;
