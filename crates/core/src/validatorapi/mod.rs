//! Validator-facing HTTP API.
//!
//! Serves the subset of beacon-API endpoints related to distributed
//! validation and reverse-proxies the rest to the upstream beacon node.

pub mod component;
pub mod error;
pub mod handler;
pub mod metrics;
pub mod router;
pub mod types;
pub mod validator_cache;

#[cfg(test)]
pub mod testutils;

pub use component::Component;
pub use error::ApiError;
pub use handler::Handler;
pub use router::new_router;
pub use validator_cache::{CachedValidatorsError, CachedValidatorsProvider};
