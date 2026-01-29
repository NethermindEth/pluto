//! Error types for the Pluto CLI.

use std::path::PathBuf;
use thiserror::Error;

/// Result type for CLI operations.
pub type Result<T> = std::result::Result<T, CliError>;

/// Errors that can occur in the Pluto CLI.
#[derive(Error, Debug)]
pub(crate) enum CliError {
    /// Private key file not found.
    #[error(
        "Private key not found. If this is your first time running this client, create one with `pluto create enr`."
    )]
    PrivateKeyNotFound {
        /// Path where the ENR private key was expected.
        enr_path: PathBuf,
    },

    /// Private key already exists.
    #[error("charon-enr-private-key already exists")]
    PrivateKeyAlreadyExists {
        /// Path where the ENR private key exists.
        enr_path: PathBuf,
    },

    /// Failed to load private key.
    #[error("Failed to load private key: {0}")]
    KeyLoadError(#[from] pluto_p2p::k1::K1Error),

    /// ENR generation failed.
    #[error("ENR generation failed: {0}")]
    EnrError(#[from] pluto_eth2util::enr::RecordError),

    /// IO error occurred.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
