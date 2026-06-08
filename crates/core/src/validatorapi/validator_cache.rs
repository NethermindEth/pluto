//! Cluster-wide active-validators lookup consumed by submit handlers.
//!
//! Mirrors Charon's `app/eth2wrap.CachedValidatorsProvider` interface:
//! submit handlers that have to translate a validator-client-supplied
//! `validator_index` into the cluster's DV root public key consult this
//! trait. Defined here in `pluto-core` so the validator API does not need
//! to depend on the application crate that owns the concrete per-epoch
//! cache implementation.

use std::collections::HashMap;

use async_trait::async_trait;
use pluto_eth2api::spec::phase0::{BLSPubKey, ValidatorIndex};

/// Boxed error returned by [`CachedValidatorsProvider`] methods. Kept
/// opaque so the trait does not bind callers to any single backing
/// implementation's error type.
pub type CachedValidatorsError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Provides the cluster's currently active validators, indexed by
/// validator index. Mirrors Go's `eth2Cl.ActiveValidators(ctx)`, which is
/// itself backed by `app/eth2wrap`'s per-epoch validator cache; the
/// validator-API [`Component`](super::Component) calls through this trait
/// so the cache is the single source of truth across duty handlers
/// without `pluto-core` depending on the cache crate.
///
/// Implementations may populate the underlying cache on demand — callers
/// must not assume the call is non-blocking.
#[async_trait]
pub trait CachedValidatorsProvider: Send + Sync {
    /// Returns the `validator_index -> DV root BLS public key` map.
    async fn active_validators(
        &self,
    ) -> Result<HashMap<ValidatorIndex, BLSPubKey>, CachedValidatorsError>;
}
