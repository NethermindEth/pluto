use crate::{
    ConsensusVersion, EthBeaconNodeApiClient, EthBeaconNodeApiClientError,
    confcache::ConfigCache,
    extensions::{
        self, ForkSchedule, GenesisInfo, compute_builder_domain, domain_from_config,
        fork_schedule_from_spec, resolve_domain_type,
    },
    spec::phase0,
    valcache::{ActiveValidators, CompleteValidators, ValidatorCache, ValidatorCacheError},
};
use chrono::{DateTime, Utc};
use std::{collections::HashMap, fmt, sync::Arc, time::Duration};
use tokio::sync::RwLock;

type Result<T> = std::result::Result<T, BeaconNodeClientError>;
type ConfigResult<T> = std::result::Result<T, EthBeaconNodeApiClientError>;

/// Errors returned by [`BeaconNodeClient`].
#[derive(Debug, thiserror::Error)]
pub enum BeaconNodeClientError {
    /// Validator cache failed.
    #[error(transparent)]
    ValidatorCache(#[from] ValidatorCacheError),
}

/// Shared state behind every [`BeaconNodeClient`] clone.
struct Inner {
    api: EthBeaconNodeApiClient,
    config: ConfigCache,
    // TODO: Find the concrete usages of the `validator_cache` and consider if we can make it
    // immutable, that is, set it once at construction and not have to deal with the possibility of
    // it being unset later.
    validator_cache: RwLock<ValidatorCache>,
}

/// Beacon node client layering a per-epoch validator cache and the static
/// chain-config cache (backing signing-domain resolution) over the generated
/// API client. Clones share one `Arc`.
#[derive(Clone)]
pub struct BeaconNodeClient(Arc<Inner>);

impl fmt::Debug for BeaconNodeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeaconNodeClient")
            .field("base_url", &self.0.api.base_url.as_str())
            .finish_non_exhaustive()
    }
}

impl BeaconNodeClient {
    /// Creates a new beacon node client.
    pub fn new(api: EthBeaconNodeApiClient) -> Self {
        Self(Arc::new(Inner {
            config: ConfigCache::default(),
            validator_cache: RwLock::new(ValidatorCache::new(api.clone(), Vec::new())),
            api,
        }))
    }

    /// Returns the generated Beacon API client.
    pub fn api(&self) -> &EthBeaconNodeApiClient {
        &self.0.api
    }

    /// Warms the static-config cache (spec, genesis, fork schedule). Called
    /// at startup, before duty scheduling, failing fast.
    pub async fn warm(&self) -> ConfigResult<()> {
        tokio::try_join!(self.spec(), self.genesis(), self.fork_schedule())?;
        Ok(())
    }

    /// Returns the chain spec as a JSON object (cached).
    pub async fn spec(&self) -> ConfigResult<Arc<serde_json::Value>> {
        self.0.config.spec(&self.0.api).await
    }

    /// Returns the parsed genesis data (cached).
    pub(crate) async fn genesis(&self) -> ConfigResult<Arc<GenesisInfo>> {
        self.0.config.genesis(&self.0.api).await
    }

    /// Returns the parsed fork-schedule entries, in server order (cached).
    pub(crate) async fn fork_schedule(&self) -> ConfigResult<Arc<Vec<ForkSchedule>>> {
        self.0.config.fork_schedule(&self.0.api).await
    }

    /// Returns the genesis time (cached).
    pub async fn genesis_time(&self) -> ConfigResult<DateTime<Utc>> {
        Ok(self.genesis().await?.time)
    }

    /// Returns the slot duration and slots per epoch (cached).
    pub async fn slots_config(&self) -> ConfigResult<(Duration, u64)> {
        let spec = self.spec().await?;
        extensions::slots_config_from_spec(&spec)
    }

    /// Returns the spec-derived fork schedule for all known forks (cached).
    pub async fn fork_config(&self) -> ConfigResult<HashMap<ConsensusVersion, ForkSchedule>> {
        let spec = self.spec().await?;
        fork_schedule_from_spec(&spec)
    }

    /// Returns the domain type with the provided config/spec key (cached).
    pub async fn domain_type(&self, spec_key: &str) -> ConfigResult<phase0::DomainType> {
        let spec = self.spec().await?;
        resolve_domain_type(&spec, spec_key)
    }

    /// Returns the genesis (builder) domain for the provided domain type
    /// (cached).
    pub async fn genesis_domain(
        &self,
        domain_type: phase0::DomainType,
    ) -> ConfigResult<phase0::Domain> {
        let genesis = self.genesis().await?;

        Ok(compute_builder_domain(domain_type, genesis.fork_version))
    }

    /// Returns the resolved beacon domain for the provided domain type and
    /// epoch (cached); see [`domain_from_config`] for the derivation rules.
    pub async fn domain(
        &self,
        domain_type: phase0::DomainType,
        epoch: phase0::Epoch,
    ) -> ConfigResult<phase0::Domain> {
        let spec = self.spec().await?;
        let genesis = self.genesis().await?;
        let schedule = self.fork_schedule().await?;

        domain_from_config(&spec, &genesis, &schedule, domain_type, epoch)
    }

    /// Sets the validator cache used by cached validator methods.
    pub async fn set_validator_cache(&self, validator_cache: ValidatorCache) {
        *self.0.validator_cache.write().await = validator_cache;
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
        self.0.validator_cache.read().await.clone()
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
