//! Error types for the Pluto CLI.

use std::path::PathBuf;
use thiserror::Error;

/// Result type for CLI operations.
pub type Result<T> = std::result::Result<T, CliError>;

/// Errors that can occur in the Pluto CLI.
#[derive(Error, Debug)]
pub enum CliError {
    /// Private key file not found.
    #[error(
        "private key not found. If this is your first time running this client, create one with `pluto create enr`."
    )]
    PrivateKeyNotFound {
        /// Path where the ENR private key was expected.
        enr_path: PathBuf,
    },

    /// Failed to load private key.
    #[error("Failed to load private key: {0}")]
    KeyLoadError(String),

    /// ENR generation failed.
    #[error("ENR generation failed: {0}")]
    EnrError(#[from] charon_eth2::enr::RecordError),

    /// IO error occurred.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
