use crate::eth2wrap::eth2api::{EthBeaconNodeApiClientError, ValidatorIndex, ValidatorStatusExt};
use charon_core::types::PubKey;
use eth2api::{
    EthBeaconNodeApiClient, GetStateValidatorsResponseResponse,
    GetStateValidatorsResponseResponseDatum, PostStateValidatorsRequest,
    PostStateValidatorsRequestPath, PostStateValidatorsResponse, ValidatorRequestBody,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

type Result<T> = std::result::Result<T, ValidatorCacheError>;

/// Errors that can occur when interacting with the validator cache.
#[derive(Debug, thiserror::Error)]
pub enum ValidatorCacheError {
    /// Failed to lock the cache state.
    #[error("Failed to lock the cache state")]
    PoisonError,

    /// Beacon client API error.
    #[error("Beacon client error: {0}")]
    BeaconClientError(#[from] EthBeaconNodeApiClientError),
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for ValidatorCacheError {
    fn from(_: PoisonError<MutexGuard<'_, T>>) -> Self {
        Self::PoisonError
    }
}

/// Active validators as [`PubKey`] indexed by their validator index.
#[derive(Debug, Clone, Default)]
pub struct ActiveValidators(HashMap<ValidatorIndex, PubKey>);

impl std::ops::Deref for ActiveValidators {
    type Target = HashMap<ValidatorIndex, PubKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Complete response of the Beacon node validators endpoint.
#[derive(Debug, Clone, Default)]
pub struct CompleteValidators(HashMap<ValidatorIndex, GetStateValidatorsResponseResponseDatum>);

impl std::ops::Deref for CompleteValidators {
    type Target = HashMap<ValidatorIndex, GetStateValidatorsResponseResponseDatum>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ActiveValidators {
    /// An [`Iterator`] of active validator indices.
    pub fn indices(&self) -> impl Iterator<Item = ValidatorIndex> + '_ {
        self.0.keys().copied()
    }

    /// An [`Iterator`] of active validator public keys.
    pub fn pubkeys(&self) -> impl Iterator<Item = &PubKey> + '_ {
        self.0.values()
    }
}

/// A provider of cached validator information for the current epoch,
/// including both active validators and complete validator data.
pub trait CachedValidatorsProvider {
    /// Get the cached active validators.
    fn active_validators(&self) -> Result<ActiveValidators>;

    /// Get all the cached validators.
    fn complete_validators(&self) -> Result<CompleteValidators>;
}

/// A cache for active validators.
#[derive(Clone)]
pub struct ValidatorCache(Arc<ValidatorCacheInner>);

struct ValidatorCacheInner {
    eth2_cl: EthBeaconNodeApiClient,
    pubkeys: Vec<PubKey>,
    state: Mutex<ValidatorCacheState>,
}

struct ValidatorCacheState {
    active: Option<ActiveValidators>,
    complete: Option<CompleteValidators>,
}

impl ValidatorCache {
    /// Creates a new, empty validator cache.
    pub fn new(eth2_cl: EthBeaconNodeApiClient, pubkeys: Vec<PubKey>) -> Self {
        Self(Arc::new(ValidatorCacheInner {
            eth2_cl,
            pubkeys,
            state: Mutex::new(ValidatorCacheState {
                active: None,
                complete: None,
            }),
        }))
    }

    /// Clears the cache. This should be called on epoch boundary.
    pub fn trim(&self) -> Result<()> {
        let mut state = self.0.state.lock()?;

        state.active = None;
        state.complete = None;

        Ok(())
    }

    /// Returns the cached active validators and complete validators response,
    /// or fetches them if not available populating the cache.
    pub async fn get_by_head(&self) -> Result<(ActiveValidators, CompleteValidators)> {
        {
            // Limit the scope of the lock
            let state = self
                .0
                .state
                .lock()
                .map_err(|_| ValidatorCacheError::PoisonError)?;

            if let (Some(active), Some(complete)) = (&state.active, &state.complete) {
                return Ok((active.clone(), complete.clone()));
            };
        }

        let request = PostStateValidatorsRequest {
            path: PostStateValidatorsRequestPath {
                state_id: "head".into(),
            },
            body: ValidatorRequestBody {
                ids: Some(self.0.pubkeys.iter().map(|pk| pk.to_string()).collect()),
                ..Default::default()
            },
        };

        let response = self
            .0
            .eth2_cl
            .post_state_validators(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)
            .and_then(|response| match response {
                PostStateValidatorsResponse::Ok(response) => Ok(response),
                _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
            })?;

        let (active_validators, complete_validators) = validators_from_response(response)?;

        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| ValidatorCacheError::PoisonError)?;

        state.active = Some(active_validators.clone());
        state.complete = Some(complete_validators.clone());

        Ok((active_validators, complete_validators))
    }

    /// Fetches active and complete validators response by slot populating the
    /// cache. If it fails to fetch by slot, it falls back to head state.
    ///
    /// Returns a tuple containing the active validators, complete validators
    /// response, and a boolean indicating whether the data was fetched by
    /// slot (`true`) or fell back to head (`false`).
    pub async fn get_by_slot(
        &self,
        slot: u64,
    ) -> Result<(ActiveValidators, CompleteValidators, bool)> {
        let mut request = PostStateValidatorsRequest {
            path: PostStateValidatorsRequestPath {
                state_id: slot.to_string(),
            },
            body: ValidatorRequestBody {
                ids: Some(self.0.pubkeys.iter().map(|pk| pk.to_string()).collect()),
                ..Default::default()
            },
        };

        let (response, refreshed_by_slot) =
            match self.0.eth2_cl.post_state_validators(request.clone()).await {
                Ok(PostStateValidatorsResponse::Ok(response)) => (response, true),
                _ => {
                    // Failed to fetch by slot, fall back to head state
                    request.path.state_id = "head".into();

                    let response = self
                        .0
                        .eth2_cl
                        .post_state_validators(request)
                        .await
                        .map_err(EthBeaconNodeApiClientError::RequestError)
                        .and_then(|response| match response {
                            PostStateValidatorsResponse::Ok(response) => Ok(response),
                            _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
                        })?;

                    (response, false)
                }
            };

        let (active_validators, complete_validators) = validators_from_response(response)?;

        let mut state = self.0.state.lock()?;

        state.active = Some(active_validators.clone());
        state.complete = Some(complete_validators.clone());

        Ok((active_validators, complete_validators, refreshed_by_slot))
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

            Ok((index, datum))
        })
        .collect::<Result<HashMap<ValidatorIndex, GetStateValidatorsResponseResponseDatum>>>()?;

    let active_validators = all_validators
        .iter()
        .filter(|(_, v)| v.status.is_active())
        .map(|(&index, v)| {
            let pubkey = v
                .validator
                .pubkey
                .as_str()
                .try_into()
                .map_err(|_| EthBeaconNodeApiClientError::UnexpectedType)?;

            Ok((index, pubkey))
        })
        .collect::<Result<HashMap<ValidatorIndex, PubKey>>>()?;

    Ok((
        ActiveValidators(active_validators),
        CompleteValidators(all_validators),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth2api::{
        BlindedBlock400Response, GetStateValidatorsResponseResponseDatum,
        ValidatorResponseValidator, ValidatorStatus,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    #[tokio::test]
    async fn get_by_head_returns_cached_values_when_cache_is_populated() {
        let pubkey1 = test_pubkey(1);
        let validator = test_validator_datum(1, &pubkey1, ValidatorStatus::ActiveOngoing);
        let eth2_cl = EthBeaconNodeApiClient::with_base_url("http://0.0.0.0")
            .expect("Failed to create client");
        let cache = ValidatorCache::new(eth2_cl, vec![pubkey1.clone()]);
        {
            // Manually populate the cache with test data
            let mut state = cache.0.state.lock().unwrap();

            let mut active_map = HashMap::new();
            active_map.insert(1, pubkey1);

            let mut complete_map = HashMap::new();
            complete_map.insert(1, validator.clone());

            state.active = Some(ActiveValidators(active_map));
            state.complete = Some(CompleteValidators(complete_map));
        };

        let (active, complete) = cache
            .get_by_head()
            .await
            .expect("`get_by_head` succeeds when cache is populated");

        // Verify the returned active validators
        {
            assert_eq!(active.len(), 1);
            assert!(active.contains_key(&1));
            assert_eq!(active.get(&1), Some(&pubkey1));
        }

        // Verify the returned complete validators
        {
            assert_eq!(complete.len(), 1);
            assert!(complete.contains_key(&1));
            assert_eq!(complete.get(&1), Some(&validator));
        }
    }

    #[tokio::test]
    async fn get_by_head_returns_error_when_request_fails() {
        // Create a mock server that returns a 404 error
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(404).set_body_json(not_found_response_body()))
            .expect(1)
            .mount(&mock_server)
            .await;
        let eth2_cl = EthBeaconNodeApiClient::with_base_url(mock_server.uri())
            .expect("Failed to create client");
        let cache = ValidatorCache::new(eth2_cl, vec![test_pubkey(1)]);

        // Verify cache is initially empty
        {
            let state = cache.0.state.lock().unwrap();
            assert!(state.active.is_none());
            assert!(state.complete.is_none());
        }

        let result = cache.get_by_head().await;
        assert!(result.is_err());

        // Verify cache remains empty after failed request
        {
            let state = cache.0.state.lock().unwrap();
            assert!(state.active.is_none());
            assert!(state.complete.is_none());
        }
    }

    fn test_pubkey(seed: u8) -> PubKey {
        let mut bytes = [0u8; 48];
        bytes[0] = seed;
        PubKey::new(bytes)
    }

    fn test_validator_datum(
        index: u64,
        pubkey: &PubKey,
        status: ValidatorStatus,
    ) -> GetStateValidatorsResponseResponseDatum {
        // NOTE: these values are placeholders intended for testing only
        GetStateValidatorsResponseResponseDatum {
            index: index.to_string(),
            balance: "32000000000".to_string(),
            status,
            validator: ValidatorResponseValidator {
                pubkey: pubkey.to_string(),
                withdrawal_credentials:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                effective_balance: "32000000000".to_string(),
                slashed: false,
                activation_eligibility_epoch: "0".to_string(),
                activation_epoch: "0".to_string(),
                exit_epoch: "18446744073709551615".to_string(),
                withdrawable_epoch: "18446744073709551615".to_string(),
            },
        }
    }

    fn not_found_response_body() -> BlindedBlock400Response {
        BlindedBlock400Response {
            code: 404.0,
            message: "State not found".to_string(),
            stacktraces: None,
        }
    }
}
