//! Error types for the Pluto CLI.

use std::{
    path::PathBuf,
    process::{ExitCode, Termination},
};

use thiserror::Error;

/// Result type for CLI operations.
pub type Result<T> = std::result::Result<T, CliError>;

pub struct ExitResult(pub Result<()>);

impl Termination for ExitResult {
    fn report(self) -> ExitCode {
        match self.0 {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Error: {}", err);
                ExitCode::FAILURE
            }
        }
    }
}

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
    #[error("IO error: {source}")]
    Io {
        source: std::io::Error,
        context: String,
    },

    /// JSON serialization/deserialization error.
    #[error("JSON error: {source}")]
    Json {
        source: serde_json::Error,
        context: String,
    },

    /// K1 utility error.
    #[error("K1 utility error: {0}")]
    K1Util(#[from] pluto_k1util::K1UtilError),

    /// Obol API error.
    #[error("Obol API error: {0}")]
    ObolApi(#[from] pluto_app::obolapi::ObolApiError),

    /// SSZ hasher error.
    #[error("Hasher error: {0}")]
    HasherError(#[from] pluto_cluster::ssz_hasher::HasherError),

    /// HTTP request error.
    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Test timeout or interrupted.
    #[error("timeout/interrupted")]
    _TimeoutInterrupted,

    /// Test case not supported.
    #[error("test case not supported")]
    _TestCaseNotSupported,

    /// Generic error with message.
    #[error("{0}")]
    Other(String),
}

// Implement From<std::io::Error> for backwards compatibility
impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::Io {
            source: err,
            context: String::new(),
        }
    }
}

// Implement From<serde_json::Error> for convenience
impl From<serde_json::Error> for CliError {
    fn from(err: serde_json::Error) -> Self {
        CliError::Json {
            source: err,
            context: String::new(),
        }
    }
}
