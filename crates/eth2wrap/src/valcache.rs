use async_trait::async_trait;
use pluto_eth2api::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError, GetStateValidatorsResponseResponse,
    GetStateValidatorsResponseResponseDatum, PostStateValidatorsRequest,
    PostStateValidatorsRequestPath, PostStateValidatorsResponse, ValidatorRequestBody,
    spec::phase0::{BLSPubKey, ValidatorIndex},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

type Result<T> = std::result::Result<T, ValidatorCacheError>;

/// Errors that can occur when interacting with the validator cache.
#[derive(Debug, thiserror::Error)]
pub enum ValidatorCacheError {
    /// Beacon Node API client error.
    #[error("Beacon Node API client error: {0}")]
    EthBeaconNodeApiClientError(#[from] EthBeaconNodeApiClientError),
    /// Pubkey string returned by the beacon node could not be decoded.
    #[error("invalid pubkey hex returned by beacon node")]
    InvalidPubkeyHex,
}

/// Active validators as [`BLSPubKey`] indexed by their validator index.
///
/// Mirrors Charon's `app/eth2wrap.ActiveValidators` — the on-the-wire pubkey
/// representation, before any conversion into a Pluto-specific wrapper type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ActiveValidators(HashMap<ValidatorIndex, BLSPubKey>);

impl std::ops::Deref for ActiveValidators {
    type Target = HashMap<ValidatorIndex, BLSPubKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<HashMap<ValidatorIndex, BLSPubKey>> for ActiveValidators {
    fn from(value: HashMap<ValidatorIndex, BLSPubKey>) -> Self {
        Self(value)
    }
}

impl From<ActiveValidators> for HashMap<ValidatorIndex, BLSPubKey> {
    fn from(value: ActiveValidators) -> Self {
        value.0
    }
}

/// Complete response of the Beacon node validators endpoint.
#[derive(Debug, Clone, Default, PartialEq)]
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
    pub fn pubkeys(&self) -> impl Iterator<Item = &BLSPubKey> + '_ {
        self.0.values()
    }
}

/// Boxed error returned by [`CachedValidatorsProvider`] methods. Kept
/// opaque so the trait does not bind callers to any single backing
/// implementation's error type.
pub type CachedValidatorsError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A provider of cached validator information for the current epoch.
///
/// Mirrors Charon's `eth2wrap.CachedValidatorsProvider` — the validator-API
/// component fetches the cluster's active validators through this interface
/// rather than going directly to the beacon node, so it benefits from
/// per-epoch caching and so the cache is the single source of truth across
/// duty handlers.
#[async_trait]
pub trait CachedValidatorsProvider: Send + Sync {
    /// Returns the cluster's currently active validators, indexed by
    /// validator index. The implementation may populate the cache on demand
    /// — callers should not assume the call is non-blocking.
    async fn active_validators(
        &self,
    ) -> std::result::Result<ActiveValidators, CachedValidatorsError>;
}

/// A cache for active validators.
#[derive(Clone)]
pub struct ValidatorCache(Arc<RwLock<ValidatorCacheInner>>);

struct ValidatorCacheInner {
    eth2_cl: EthBeaconNodeApiClient,
    pubkeys: Vec<BLSPubKey>,
    active: Option<ActiveValidators>,
    complete: Option<CompleteValidators>,
}

impl ValidatorCache {
    /// Creates a new, empty validator cache.
    pub fn new(eth2_cl: EthBeaconNodeApiClient, pubkeys: Vec<BLSPubKey>) -> Self {
        Self(Arc::new(RwLock::new(ValidatorCacheInner {
            eth2_cl,
            pubkeys,
            active: None,
            complete: None,
        })))
    }

    /// Clears the cache. This should be called on epoch boundary.
    pub async fn trim(&self) {
        let mut inner = self.0.write().await;

        inner.active = None;
        inner.complete = None;
    }

    /// Returns the cached active validators and complete validators response,
    /// or fetches them if not available populating the cache.
    pub async fn get_by_head(&self) -> Result<(ActiveValidators, CompleteValidators)> {
        let mut inner = self.0.write().await;

        if let (Some(active), Some(complete)) = (&inner.active, &inner.complete) {
            return Ok((active.clone(), complete.clone()));
        };

        let request = PostStateValidatorsRequest {
            path: PostStateValidatorsRequestPath {
                state_id: "head".into(),
            },
            body: ValidatorRequestBody {
                ids: Some(inner.pubkeys.iter().map(pubkey_to_hex).collect()),
                ..Default::default()
            },
        };

        let response = inner
            .eth2_cl
            .post_state_validators(request)
            .await
            .map_err(EthBeaconNodeApiClientError::RequestError)
            .and_then(|response| match response {
                PostStateValidatorsResponse::Ok(response) => Ok(response),
                _ => Err(EthBeaconNodeApiClientError::UnexpectedResponse),
            })?;

        let (active_validators, complete_validators) = validators_from_response(response)?;

        inner.active = Some(active_validators.clone());
        inner.complete = Some(complete_validators.clone());

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
        let mut inner = self.0.write().await;

        let mut request = PostStateValidatorsRequest {
            path: PostStateValidatorsRequestPath {
                state_id: slot.to_string(),
            },
            body: ValidatorRequestBody {
                ids: Some(inner.pubkeys.iter().map(pubkey_to_hex).collect()),
                ..Default::default()
            },
        };

        let (response, refreshed_by_slot) =
            match inner.eth2_cl.post_state_validators(request.clone()).await {
                Ok(PostStateValidatorsResponse::Ok(response)) => (response, true),
                _ => {
                    // Failed to fetch by slot, fall back to head state
                    request.path.state_id = "head".into();

                    let response = inner
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

        inner.active = Some(active_validators.clone());
        inner.complete = Some(complete_validators.clone());

        Ok((active_validators, complete_validators, refreshed_by_slot))
    }
}

#[async_trait]
impl CachedValidatorsProvider for ValidatorCache {
    async fn active_validators(
        &self,
    ) -> std::result::Result<ActiveValidators, CachedValidatorsError> {
        let (active, _) = self.get_by_head().await?;
        Ok(active)
    }
}

fn pubkey_to_hex(pk: &BLSPubKey) -> String {
    format!("0x{}", hex::encode(pk))
}

fn parse_pubkey_hex(s: &str) -> Result<BLSPubKey> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|_| ValidatorCacheError::InvalidPubkeyHex)?;
    BLSPubKey::try_from(bytes.as_slice()).map_err(|_| ValidatorCacheError::InvalidPubkeyHex)
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
        .map(|(&index, v)| Ok((index, parse_pubkey_hex(v.validator.pubkey.as_str())?)))
        .collect::<Result<HashMap<ValidatorIndex, BLSPubKey>>>()?;

    Ok((
        ActiveValidators(active_validators),
        CompleteValidators(all_validators),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluto_eth2api::{
        BlindedBlock400Response, GetStateValidatorsResponseResponseDatum,
        ValidatorResponseValidator, ValidatorStatus,
    };
    use pluto_testutil::BeaconMock;
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    #[tokio::test]
    async fn get_by_head_successful_fetch() {
        // Create a set of validators with different statuses (some active, some not)
        let pubkeys = (0..10u8).map(test_pubkey).collect::<Vec<BLSPubKey>>();
        let datums = [
            test_validator_datum(0, &pubkeys[0], ValidatorStatus::PendingInitialized), /* not active */
            test_validator_datum(1, &pubkeys[1], ValidatorStatus::PendingQueued), /* not active */
            test_validator_datum(2, &pubkeys[2], ValidatorStatus::ActiveOngoing), /* active */
            test_validator_datum(3, &pubkeys[3], ValidatorStatus::ActiveExiting), /* active */
            test_validator_datum(4, &pubkeys[4], ValidatorStatus::ActiveSlashed), /* active */
            test_validator_datum(5, &pubkeys[5], ValidatorStatus::ExitedUnslashed), /* not active */
            test_validator_datum(6, &pubkeys[6], ValidatorStatus::ExitedSlashed), // not active
            test_validator_datum(7, &pubkeys[7], ValidatorStatus::WithdrawalPossible), /* not active */
            test_validator_datum(8, &pubkeys[8], ValidatorStatus::WithdrawalDone), /* not active */
            test_validator_datum(9, &pubkeys[9], ValidatorStatus::ActiveOngoing),  /* active */
        ];

        let expected_complete = datums
            .iter()
            .map(|datum| {
                let index = datum.index.parse().unwrap();
                (index, datum.clone())
            })
            .collect::<HashMap<ValidatorIndex, GetStateValidatorsResponseResponseDatum>>();

        let expected_active = expected_complete
            .iter()
            .filter(|(_, datum)| datum.status.is_active())
            .map(|(&index, datum)| {
                let pubkey = parse_pubkey_hex(datum.validator.pubkey.as_str()).unwrap();
                (index, pubkey)
            })
            .collect::<HashMap<ValidatorIndex, BLSPubKey>>();

        // Create a mock server that tracks request count
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("should create beacon mock");
        post_state_validators_success("head", datums.to_vec())
            .expect(2) // Should be called exactly twice (once before trim, once after)
            .mount(mock.server())
            .await;

        // Create a cache.
        let cache = ValidatorCache::new(mock.client().clone(), pubkeys);

        // Check cache is populated.
        let (actual_active, actual_complete) =
            cache.get_by_head().await.expect("`get_by_head` succeeds");
        assert_eq!(actual_active.0, expected_active);
        assert_eq!(actual_complete.0, expected_complete);

        // Check cache is used (no additional request).
        let (actual_active, actual_complete) =
            cache.get_by_head().await.expect("`get_by_head` succeeds");
        assert_eq!(actual_active.0, expected_active);
        assert_eq!(actual_complete.0, expected_complete);

        // Trim cache.
        cache.trim().await;

        // Check cache is populated again.
        let (actual_active, actual_complete) =
            cache.get_by_head().await.expect("`get_by_head` succeeds");
        assert_eq!(actual_active.0, expected_active);
        assert_eq!(actual_complete.0, expected_complete);

        // Check cache is used again (no additional request).
        let (actual_active, actual_complete) =
            cache.get_by_head().await.expect("`get_by_head` succeeds");
        assert_eq!(actual_active.0, expected_active);
        assert_eq!(actual_complete.0, expected_complete);
    }

    #[tokio::test]
    async fn get_by_head_fail_fetch() {
        // Create a mock server that returns a 404 error
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("should create beacon mock");

        post_state_validators_not_found("head")
            .expect(1)
            .mount(mock.server())
            .await;
        let cache = ValidatorCache::new(mock.client().clone(), vec![test_pubkey(1)]);

        // Verify cache is initially empty
        {
            let inner = cache.0.write().await;
            assert!(inner.active.is_none());
            assert!(inner.complete.is_none());
        }

        let result = cache.get_by_head().await;
        assert!(result.is_err());

        // Verify cache remains empty after failed request
        {
            let inner = cache.0.write().await;
            assert!(inner.active.is_none());
            assert!(inner.complete.is_none());
        }
    }

    #[tokio::test]
    async fn get_by_slot_successful_fetch() {
        // Create two validator pubkeys
        let pubkeys = vec![test_pubkey(0), test_pubkey(1)];

        // Set up mock server with different responses based on slot
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("should create beacon mock");

        post_state_validators_success(
            "1",
            vec![
                test_validator_datum(0, &pubkeys[0], ValidatorStatus::PendingQueued),
                test_validator_datum(1, &pubkeys[1], ValidatorStatus::ActiveOngoing),
            ],
        )
        .mount(mock.server())
        .await;

        post_state_validators_success(
            "2",
            vec![
                test_validator_datum(0, &pubkeys[0], ValidatorStatus::ActiveOngoing),
                test_validator_datum(1, &pubkeys[1], ValidatorStatus::ActiveOngoing),
            ],
        )
        .mount(mock.server())
        .await;

        post_state_validators_success(
            "11",
            vec![
                test_validator_datum(0, &pubkeys[0], ValidatorStatus::PendingQueued),
                test_validator_datum(1, &pubkeys[1], ValidatorStatus::PendingQueued),
            ],
        )
        .mount(mock.server())
        .await;

        post_state_validators_not_found("3")
            .mount(mock.server())
            .await;
        post_state_validators_not_found("head")
            .mount(mock.server())
            .await;

        // Create a cache.
        let cache = ValidatorCache::new(mock.client().clone(), pubkeys.clone());

        // Test slot 1: 1 active validator (index 1), 2 complete, refreshed_by_slot=true
        let (active, complete, refreshed_by_slot) = cache
            .get_by_slot(1)
            .await
            .expect("`get_by_slot(1)` succeeds");
        assert_eq!(active.len(), 1);
        assert_eq!(active.get(&1), Some(&pubkeys[1]));
        assert_eq!(complete.len(), 2);
        assert!(refreshed_by_slot);

        // Test slot 2: 2 active validators, 2 complete, refreshed_by_slot=true
        let (active, complete, refreshed_by_slot) = cache
            .get_by_slot(2)
            .await
            .expect("`get_by_slot(2)` succeeds");
        assert_eq!(active.len(), 2);
        assert_eq!(complete.len(), 2);
        assert!(refreshed_by_slot);

        // Test slot 11: 0 active validators, 2 complete, refreshed_by_slot=true
        let (active, complete, refreshed_by_slot) = cache
            .get_by_slot(11)
            .await
            .expect("`get_by_slot(11)` succeeds");
        assert!(active.is_empty());
        assert_eq!(complete.len(), 2);
        assert!(refreshed_by_slot);

        // Test slot 3: error (both slot and head fallback fail),
        // refreshed_by_slot=false
        let result = cache.get_by_slot(3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_by_slot_fallback_to_head() {
        // Create two validator pubkeys
        let pubkeys = vec![test_pubkey(0), test_pubkey(1)];

        // Set up mock server: slot requests fail, but head succeeds
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("should create beacon mock");

        post_state_validators_not_found("1")
            .mount(mock.server())
            .await;

        post_state_validators_success(
            "head",
            vec![
                test_validator_datum(0, &pubkeys[0], ValidatorStatus::ActiveOngoing),
                test_validator_datum(1, &pubkeys[1], ValidatorStatus::ActiveOngoing),
            ],
        )
        .mount(mock.server())
        .await;

        let cache = ValidatorCache::new(mock.client().clone(), pubkeys);

        // Test slot 1: fails, falls back to head, returns 2 active, 2 complete,
        // refreshed_by_slot=false
        let (active, complete, refreshed_by_slot) = cache
            .get_by_slot(1)
            .await
            .expect("`get_by_slot(1)` succeeds via head fallback");
        assert_eq!(active.len(), 2);
        assert_eq!(complete.len(), 2);
        assert!(!refreshed_by_slot);
    }

    /// The trait impl funnels through `get_by_head`, so two consecutive
    /// `active_validators` calls hit the upstream once and reuse the cached
    /// value on the second call.
    #[tokio::test]
    async fn cached_validators_provider_uses_cache() {
        let pubkeys = vec![test_pubkey(0), test_pubkey(1)];
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("should create beacon mock");

        post_state_validators_success(
            "head",
            vec![
                test_validator_datum(0, &pubkeys[0], ValidatorStatus::ActiveOngoing),
                test_validator_datum(1, &pubkeys[1], ValidatorStatus::PendingQueued),
            ],
        )
        .expect(1)
        .mount(mock.server())
        .await;

        let cache = ValidatorCache::new(mock.client().clone(), pubkeys.clone());

        let first = CachedValidatorsProvider::active_validators(&cache)
            .await
            .expect("active_validators succeeds");
        assert_eq!(first.len(), 1);
        assert_eq!(first.get(&0), Some(&pubkeys[0]));

        let second = CachedValidatorsProvider::active_validators(&cache)
            .await
            .expect("active_validators succeeds");
        assert_eq!(first, second);
    }

    fn test_pubkey(seed: u8) -> BLSPubKey {
        let mut bytes = [0u8; 48];
        bytes[0] = seed;
        bytes
    }

    fn test_validator_datum(
        index: u64,
        pubkey: &BLSPubKey,
        status: ValidatorStatus,
    ) -> GetStateValidatorsResponseResponseDatum {
        // NOTE: these values are placeholders intended for testing only
        GetStateValidatorsResponseResponseDatum {
            index: index.to_string(),
            balance: "32000000000".to_string(),
            status,
            validator: ValidatorResponseValidator {
                pubkey: pubkey_to_hex(pubkey),
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

    fn post_state_validators_success(
        state_id: impl AsRef<str>,
        validators: Vec<GetStateValidatorsResponseResponseDatum>,
    ) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!(
                "/eth/v1/beacon/states/{}/validators",
                state_id.as_ref()
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                GetStateValidatorsResponseResponse {
                    execution_optimistic: false,
                    finalized: true,
                    data: validators,
                },
            ))
    }

    fn post_state_validators_not_found(state_id: impl AsRef<str>) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!(
                "/eth/v1/beacon/states/{}/validators",
                state_id.as_ref()
            )))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(BlindedBlock400Response {
                    code: 404.0,
                    message: "State not found".to_string(),
                    stacktraces: None,
                }),
            )
    }
}
