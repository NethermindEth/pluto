//! Module-wide error type for the validator mock.
//!
//! Mirrors the structure of `pluto_eth2util::signing::SigningError`: a single
//! `thiserror::Error` enum that the public API returns. Phase-2/3 submodules
//! add new variants as their failure modes appear.

use pluto_eth2api::EthBeaconNodeApiClientError;
use pluto_eth2util::{eth2exp::Eth2ExpError, helpers::HelperError, signing::SigningError};

/// Result alias used by the validator mock.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the validator mock.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Beacon-node API call failed.
    #[error(transparent)]
    BeaconNode(#[from] EthBeaconNodeApiClientError),

    /// Signing-helper failure (resolving domains, hashing roots, etc.).
    #[error(transparent)]
    Signing(#[from] SigningError),

    /// Helper utility (slot/epoch arithmetic against the spec) failure.
    #[error(transparent)]
    Helper(#[from] HelperError),

    /// Aggregator-selection helper failure.
    #[error(transparent)]
    Eth2Exp(#[from] Eth2ExpError),

    /// HTTP error from raw POST submissions (attestation /
    /// aggregate-and-proof).
    #[error("submit {endpoint}: {source}")]
    Submit {
        /// Path of the failed POST.
        endpoint: &'static str,
        /// Underlying HTTP error.
        #[source]
        source: reqwest::Error,
    },

    /// Beacon node returned a non-success status for a raw POST submission.
    /// Surfaces the response body so beacon-node validation errors (e.g.
    /// 400 "invalid signature on attestation 0") are visible — mirroring the
    /// diagnostic richness of Go's typed `eth2Cl.SubmitAttestations` error.
    #[error("submit {endpoint}: {status}: {body}")]
    SubmitStatus {
        /// Path of the failed POST.
        endpoint: &'static str,
        /// HTTP status code returned by the beacon node.
        status: reqwest::StatusCode,
        /// Response body (truncated to a sensible length).
        body: String,
    },

    /// Local signer could not produce a signature for the requested pubkey.
    #[error(transparent)]
    Sign(#[from] SignError),

    /// Hash-tree-root computation failed.
    #[error("hash tree root: {0}")]
    HashTreeRoot(String),

    /// Beacon response was malformed or missing data.
    #[error("malformed beacon response: {0}")]
    Malformed(String),

    /// Required validator index missing from the active set.
    #[error("missing validator index {0}")]
    MissingValidatorIndex(u64),

    /// Builder/proposal/block variant not supported.
    #[error("unsupported variant: {0}")]
    UnsupportedVariant(&'static str),
}

/// Signer-specific errors. Wrapped into [`Error::Sign`] when surfaced from the
/// validator-mock public API.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// No private key is registered for the requested public key.
    #[error("no secret found for pubkey")]
    UnknownPubkey,

    /// Underlying BLS error.
    #[error(transparent)]
    Bls(#[from] pluto_crypto::types::Error),
}
