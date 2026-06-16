use crate::{
    EthBeaconNodeApiClient,
    valcache::{ActiveValidators, CompleteValidators, ValidatorCache, ValidatorCacheError},
};
use std::sync::Arc;
use tokio::sync::RwLock;

type Result<T> = std::result::Result<T, BeaconNodeClientError>;

/// Errors returned by [`BeaconNodeClient`].
#[derive(Debug, thiserror::Error)]
pub enum BeaconNodeClientError {
    /// Validator cache failed.
    #[error(transparent)]
    ValidatorCache(#[from] ValidatorCacheError),
}

/// Beacon node client with Charon/Pluto convenience state layered on top of the
/// generated Beacon API client.
#[derive(Clone)]
pub struct BeaconNodeClient {
    api: EthBeaconNodeApiClient,
    // TODO: Find the concrete usages of the `validator_cache` and consider if we can make it
    // immutable, that is, set it once at construction and not have to deal with the possibility of
    // it being unset later.
    validator_cache: Arc<RwLock<ValidatorCache>>,
}

impl BeaconNodeClient {
    /// Creates a new beacon node client.
    pub fn new(api: EthBeaconNodeApiClient) -> Self {
        Self {
            api: api.clone(),
            validator_cache: Arc::new(RwLock::new(ValidatorCache::new(api, Vec::new()))),
        }
    }

    /// Returns the generated Beacon API client.
    pub fn api(&self) -> &EthBeaconNodeApiClient {
        &self.api
    }

    /// Sets the validator cache used by cached validator methods.
    pub async fn set_validator_cache(&self, validator_cache: ValidatorCache) {
        *self.validator_cache.write().await = validator_cache;
    }

    /// Returns active validators for `head`.
    pub async fn active_validators(&self) -> Result<ActiveValidators> {
        let (active, _) = self.validator_cache().await.get_by_head().await?;
        Ok(active)
    }

    /// Returns complete validators for `head`.
    pub async fn complete_validators(&self) -> Result<CompleteValidators> {
        let (_, complete) = self.validator_cache().await.get_by_head().await?;
        Ok(complete)
    }

    /// Get the validator cache.
    pub async fn validator_cache(&self) -> ValidatorCache {
        self.validator_cache.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GetStateValidatorsResponseResponse, GetStateValidatorsResponseResponseDatum,
        ValidatorResponseValidator, ValidatorStatus, spec::phase0::BLSPubKey,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const EFFECTIVE_BALANCE: &str = "32000000000";
    const ZERO_EPOCH: &str = "0";
    const FAR_FUTURE_EPOCH: &str = "18446744073709551615";
    const ZERO_WITHDRAWAL_CREDENTIALS: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    #[tokio::test]
    async fn active_and_complete_validators_share_cache() {
        let pubkeys = vec![test_pubkey(1), test_pubkey(2)];
        let mock = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                GetStateValidatorsResponseResponse {
                    execution_optimistic: false,
                    finalized: true,
                    data: vec![
                        test_validator_datum(10, &pubkeys[0], ValidatorStatus::ActiveOngoing),
                        test_validator_datum(11, &pubkeys[1], ValidatorStatus::PendingQueued),
                    ],
                },
            ))
            .expect(1)
            .mount(&mock)
            .await;

        let client = BeaconNodeClient::new(test_client(&mock));
        client
            .set_validator_cache(ValidatorCache::new(client.api().clone(), pubkeys))
            .await;

        let active = client.active_validators().await.unwrap();
        let complete = client.complete_validators().await.unwrap();

        assert_eq!(active.len(), 1);
        assert_eq!(complete.len(), 2);
    }

    fn test_client(server: &MockServer) -> EthBeaconNodeApiClient {
        EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid mock server URL")
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
        GetStateValidatorsResponseResponseDatum {
            index: index.to_string(),
            balance: EFFECTIVE_BALANCE.to_string(),
            status,
            validator: ValidatorResponseValidator {
                pubkey: format!("0x{}", hex::encode(pubkey)),
                withdrawal_credentials: ZERO_WITHDRAWAL_CREDENTIALS.to_string(),
                effective_balance: EFFECTIVE_BALANCE.to_string(),
                slashed: false,
                activation_eligibility_epoch: ZERO_EPOCH.to_string(),
                activation_epoch: ZERO_EPOCH.to_string(),
                exit_epoch: FAR_FUTURE_EPOCH.to_string(),
                withdrawable_epoch: FAR_FUTURE_EPOCH.to_string(),
            },
        }
    }
}
