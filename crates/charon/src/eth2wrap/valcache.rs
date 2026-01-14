#![allow(missing_docs)]

use crate::eth2wrap::client::{BeaconClient, ValidatorIndex};
use alloy::primitives::map::HashMap;
use charon_core::types::PubKey;
// TODO: Should we use Tokio's Mutex instead?
use std::sync::{Arc, Mutex};

type Result<T> = std::result::Result<T, ValidatorCacheError>;

#[derive(Debug, thiserror::Error)]
pub enum ValidatorCacheError {
    /// Failed to lock the Beacon Client.
    #[error("Failed to lock the Beacon Client")]
    PoisonError,
}

#[derive(Debug, Clone, Default)]
pub struct ActiveValidators(HashMap<ValidatorIndex, PubKey>);

impl std::ops::Deref for ActiveValidators {
    type Target = HashMap<ValidatorIndex, PubKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompleteValidators(HashMap<ValidatorIndex, PubKey>);

impl std::ops::Deref for CompleteValidators {
    type Target = HashMap<ValidatorIndex, PubKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ActiveValidators {
    pub fn indices(&self) -> impl Iterator<Item = ValidatorIndex> {
        self.0.keys().copied()
    }

    pub fn pubkeys(&self) -> impl Iterator<Item = &PubKey> {
        self.0.values()
    }
}

trait CachedValidatorsProvider {
    fn active_validators(&self) -> Result<ActiveValidators>;
    fn complete_validators(&self) -> Result<CompleteValidators>;
}

/// A cache for active validators.
#[derive(Clone)]
pub struct ValidatorCache(Arc<Mutex<ValidatorCacheInner>>);

struct ValidatorCacheInner {
    eth2_cl: BeaconClient,
    pubkeys: Vec<PubKey>,
    active: Option<ActiveValidators>,
    complete: Option<CompleteValidators>,
}

impl ValidatorCache {
    pub fn new(eth2_cl: BeaconClient, pubkeys: Vec<PubKey>) -> Self {
        Self(Arc::new(Mutex::new(ValidatorCacheInner {
            eth2_cl,
            pubkeys,
            active: None,
            complete: None,
        })))
    }

    /// Trims the cache. This should be called on epoch boundary.
    pub fn trim(&mut self) -> Result<()> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| ValidatorCacheError::PoisonError)?;

        inner.active = None;
        inner.complete = None;
        Ok(())
    }

    // Returns the cached active validators and true if they are available.
    fn active_cached() -> Result<ActiveValidators> {
        todo!();
    }

    /// Returns the cached complete validators and true if they are available.
    fn cached() {
        todo!();
    }

    /// Returns the cached active validators, cached complete validators
    /// response, or fetches them if not available populating the cache.
    pub async fn get_by_head(&self) -> Result<(ActiveValidators, CompleteValidators)> {
        let inner = self
            .0
            .lock()
            .map_err(|_| ValidatorCacheError::PoisonError)?;

        if let (Some(active), Some(complete)) = (&inner.active, &inner.complete) {
            return Ok((active.clone(), complete.clone()));
        };

        todo!();
    }
}
