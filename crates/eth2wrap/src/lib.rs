//! Beacon-node client wrappers.
//!
//! Mirrors Charon's `app/eth2wrap` package: utilities layered on top of the
//! raw beacon-node API client, including the per-epoch validator cache and
//! the [`CachedValidatorsProvider`] interface that downstream components
//! consume.

/// Cache of validators retrieved from the beacon node.
pub mod valcache;

pub use valcache::{
    ActiveValidators, CachedValidatorsError, CachedValidatorsProvider, CompleteValidators,
    ValidatorCache, ValidatorCacheError,
};
