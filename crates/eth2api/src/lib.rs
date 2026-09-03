//! # Eth2Api
//!
//! Client for an Ethereum beacon node. Its external API follows the official
//! [Ethereum beacon APIs specification](https://ethereum.github.io/beacon-APIs/).
//! Every failure is an [`EthBeaconNodeApiClientError`] variant.

/// HTTP client for a single beacon node.
pub mod client;

/// Client-level Beacon API types: request options, response envelopes and
/// error bodies.
pub mod types;

pub use client::*;
pub use types::*;

/// Error type of the client.
pub mod error;

pub use error::{EthBeaconNodeApiClientError, PayloadError};

/// Prometheus metrics for beacon node requests.
pub mod metrics;

pub use metrics::instrument;

/// Ethereum 2.0 consensus layer specification types.
pub mod spec;

/// API v1 types from the Ethereum beacon chain and builder API specifications.
pub mod v1;

/// Versioned wrappers for signeddata-related payloads.
pub mod versioned;

/// Cache of Validators retrieved from the Beacon node.
pub mod valcache;

#[cfg(test)]
pub(crate) mod test_fixtures;

#[cfg(test)]
#[cfg(feature = "integration")]
mod integration;
