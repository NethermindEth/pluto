#![allow(missing_docs)]

use crate::eth2wrap::eth2api::{
    EthBeaconNodeApiClientError, Validator, ValidatorIndex, ValidatorStatusExt,
};
use charon_core::types::PubKey;
use eth2api::{
    EthBeaconNodeApiClient, GetStateValidatorsRequest, GetStateValidatorsRequestPath,
    GetStateValidatorsRequestQuery, GetStateValidatorsResponse, GetStateValidatorsResponseResponse,
};
use std::{
    collections::HashMap,
    // TODO: Should we use Tokio's Mutex instead?
    sync::{Arc, Mutex},
};

type Result<T> = std::result::Result<T, ValidatorCacheError>;

#[derive(Debug, thiserror::Error)]
pub enum ValidatorCacheError {
    /// Failed to lock the Beacon Client.
    #[error("Failed to lock the Beacon Client")]
    PoisonError,

    #[error("Beacon client error: {0}")]
    BeaconClientError(#[from] EthBeaconNodeApiClientError),
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
pub struct CompleteValidators(HashMap<ValidatorIndex, Validator>);

impl std::ops::Deref for CompleteValidators {
    type Target = HashMap<ValidatorIndex, Validator>;

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
    eth2_cl: EthBeaconNodeApiClient,
    pubkeys: Vec<PubKey>,
    active: Option<ActiveValidators>,
    complete: Option<CompleteValidators>,
}

impl ValidatorCache {
    pub fn new(eth2_cl: EthBeaconNodeApiClient, pubkeys: Vec<PubKey>) -> Self {
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

    /// Returns the cached active validators, cached complete validators
    /// response, or fetches them if not available populating the cache.
    pub async fn get_by_head(&self) -> Result<(ActiveValidators, CompleteValidators)> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| ValidatorCacheError::PoisonError)?;

        if let (Some(active), Some(complete)) = (&inner.active, &inner.complete) {
            return Ok((active.clone(), complete.clone()));
        };

        let opts = GetStateValidatorsRequest {
            path: GetStateValidatorsRequestPath {
                state_id: "head".into(),
            },
            query: GetStateValidatorsRequestQuery {
                id: Some(inner.pubkeys.iter().map(|pk| pk.to_string()).collect()),
                ..Default::default()
            },
        };

        let response = inner
            .eth2_cl
            .get_state_validators(opts)
            .await
            .map_err(|e| EthBeaconNodeApiClientError::RequestError(e))
            .and_then(|response| match response {
                GetStateValidatorsResponse::Ok(response) => Ok(response),
                _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
            })?;

        let (active_validators, complete_validators) = validators_from_response(response)?;

        inner.active = Some(active_validators.clone());
        inner.complete = Some(complete_validators.clone());

        return Ok((active_validators, complete_validators));
    }

    /// Fetches active and complete validator by slot populating the cache.
    /// If it fails to fetch by slot, it falls back to head state and retries to
    /// fetch by slot next slot.
    ///
    /// It returns a boolean indicating whether the data was actually refreshed
    /// by slot.
    pub async fn get_by_slot(
        &self,
        slot: u64,
    ) -> Result<(ActiveValidators, CompleteValidators, bool)> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| ValidatorCacheError::PoisonError)?;

        let mut opts = GetStateValidatorsRequest {
            path: GetStateValidatorsRequestPath {
                state_id: slot.to_string(),
            },
            query: GetStateValidatorsRequestQuery {
                id: Some(inner.pubkeys.iter().map(|pk| pk.to_string()).collect()),
                ..Default::default()
            },
        };
        let (response, refreshed_by_slot) =
            match inner.eth2_cl.get_state_validators(opts.clone()).await {
                Ok(GetStateValidatorsResponse::Ok(response)) => (response, true),
                _ => {
                    // Failed to fetch by slot, fall back to head state
                    opts.path.state_id = "head".into();

                    let response = inner
                        .eth2_cl
                        .get_state_validators(opts)
                        .await
                        .map_err(|e| EthBeaconNodeApiClientError::RequestError(e))
                        .and_then(|response| match response {
                            GetStateValidatorsResponse::Ok(response) => Ok(response),
                            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
                        })?;

                    (response, false)
                }
            };

        let (active_validators, complete_validators) = validators_from_response(response)?;

        inner.active = Some(active_validators.clone());
        inner.complete = Some(complete_validators.clone());

        return Ok((active_validators, complete_validators, refreshed_by_slot));
    }
}

fn validators_from_response(
    response: GetStateValidatorsResponseResponse,
) -> Result<(ActiveValidators, CompleteValidators)> {
    let all_validators = response
        .data
        .into_iter()
        .map(|datum| {
            let index = datum
                .index
                .parse()
                .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)?;
            let validator = datum.try_into()?;

            Ok((index, validator))
        })
        .collect::<Result<HashMap<ValidatorIndex, Validator>>>()?;

    let active_validators = all_validators
        .iter()
        .filter(|(_, validator)| validator.status.is_active())
        .map(|(index, validator)| {
            let index = *index;
            let pubkey = PubKey::try_from(validator.validator.pubkey.as_str())
                .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)?;

            Ok((index, pubkey))
        })
        .collect::<Result<HashMap<ValidatorIndex, PubKey>>>()?;

    Ok((
        ActiveValidators(active_validators),
        CompleteValidators(all_validators),
    ))
}
