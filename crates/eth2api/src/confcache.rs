//! Cache of static beacon-node chain config (spec, genesis, fork schedule),
//! so signing-domain resolution does not hit the beacon node per operation.
//! The generated [`EthBeaconNodeApiClient`] cannot hold state, so the cache
//! lives in [`BeaconNodeClient`](crate::BeaconNodeClient), which exposes the
//! derived lookups over this module's mechanism.

use crate::{
    EthBeaconNodeApiClient, EthBeaconNodeApiClientError,
    extensions::{ForkSchedule, GenesisInfo, parse_fork_schedule, parse_genesis},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

type Result<T> = std::result::Result<T, EthBeaconNodeApiClientError>;

/// How long a cached value is served before re-fetching, so fork-schedule
/// changes (e.g. a beacon-node upgrade) are picked up within minutes.
const STATIC_CONFIG_TTL: Duration = Duration::from_secs(5 * 60);

/// One cached config value and its fetch time.
#[derive(Debug)]
struct ConfigEntry<T> {
    value: RwLock<Option<(Arc<T>, Instant)>>,
}

impl<T> Default for ConfigEntry<T> {
    fn default() -> Self {
        Self {
            value: RwLock::new(None),
        }
    }
}

impl<T> ConfigEntry<T> {
    /// Returns the cached value, fetching when absent or older than `ttl`.
    /// The fetch runs under the write lock, so concurrent cold callers
    /// coalesce into one request; failures are never cached.
    async fn get_or_fetch<F, Fut>(&self, ttl: Duration, fetch: F) -> Result<Arc<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        {
            let cached = self.value.read().await;
            if let Some((value, fetched_at)) = &*cached
                && fetched_at.elapsed() < ttl
            {
                return Ok(Arc::clone(value));
            }
        }

        let mut cached = self.value.write().await;
        // Re-check: a caller holding the write lock before us may have
        // filled the entry while we were blocked acquiring it.
        if let Some((value, fetched_at)) = &*cached
            && fetched_at.elapsed() < ttl
        {
            return Ok(Arc::clone(value));
        }

        let value = Arc::new(fetch().await?);
        *cached = Some((Arc::clone(&value), Instant::now()));

        Ok(value)
    }
}

/// The cached static beacon-node config: spec, genesis, and fork schedule.
/// The owning client passes its API handle into the fetching getters.
#[derive(Debug, Default)]
pub(crate) struct ConfigCache {
    spec: ConfigEntry<serde_json::Value>,
    genesis: ConfigEntry<GenesisInfo>,
    fork_schedule: ConfigEntry<Vec<ForkSchedule>>,
}

impl ConfigCache {
    /// Returns the chain spec as a JSON object.
    pub(crate) async fn spec(
        &self,
        api: &EthBeaconNodeApiClient,
    ) -> Result<Arc<serde_json::Value>> {
        self.spec
            .get_or_fetch(STATIC_CONFIG_TTL, || api.fetch_spec_data())
            .await
    }

    /// Returns the parsed genesis data (parsed at fetch time, so malformed
    /// responses are never cached).
    pub(crate) async fn genesis(&self, api: &EthBeaconNodeApiClient) -> Result<Arc<GenesisInfo>> {
        self.genesis
            .get_or_fetch(STATIC_CONFIG_TTL, || async {
                parse_genesis(&api.fetch_genesis_data().await?)
            })
            .await
    }

    /// Returns the parsed fork-schedule entries, in server order.
    pub(crate) async fn fork_schedule(
        &self,
        api: &EthBeaconNodeApiClient,
    ) -> Result<Arc<Vec<ForkSchedule>>> {
        self.fork_schedule
            .get_or_fetch(STATIC_CONFIG_TTL, || async {
                parse_fork_schedule(&api.fetch_fork_schedule_data().await?)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BeaconNodeClient;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const SPEC_PATH: &str = "/eth/v1/config/spec";
    const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";
    const FORK_SCHEDULE_PATH: &str = "/eth/v1/config/fork_schedule";

    fn spec_body() -> serde_json::Value {
        json!({ "data": {
            "SECONDS_PER_SLOT": "12",
            "SLOTS_PER_EPOCH": "32",
            "DOMAIN_BEACON_ATTESTER": "0x01000000",
            "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
            "ALTAIR_FORK_VERSION": "0x01000000",
            "ALTAIR_FORK_EPOCH": "10",
            "BELLATRIX_FORK_VERSION": "0x02000000",
            "BELLATRIX_FORK_EPOCH": "20",
            "CAPELLA_FORK_VERSION": "0x03000000",
            "CAPELLA_FORK_EPOCH": "30",
            "DENEB_FORK_VERSION": "0x04000000",
            "DENEB_FORK_EPOCH": "40",
            "ELECTRA_FORK_VERSION": "0x05000000",
            "ELECTRA_FORK_EPOCH": "50",
            "FULU_FORK_VERSION": "0x06000000",
            "FULU_FORK_EPOCH": "60",
        }})
    }

    fn genesis_body() -> serde_json::Value {
        json!({ "data": {
            "genesis_time": "1606824023",
            "genesis_validators_root":
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            "genesis_fork_version": "0x00000000",
        }})
    }

    fn fork_schedule_body() -> serde_json::Value {
        json!({ "data": [
            {
                "previous_version": "0x00000000",
                "current_version": "0x00000000",
                "epoch": "0"
            },
            {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "10"
            },
        ]})
    }

    async fn mount_config(server: &MockServer, expect: u64) {
        Mock::given(method("GET"))
            .and(path(SPEC_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(spec_body()))
            .expect(expect)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(GENESIS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(genesis_body()))
            .expect(expect)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(FORK_SCHEDULE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(fork_schedule_body()))
            .expect(expect)
            .mount(server)
            .await;
    }

    fn client_over(server: &MockServer) -> BeaconNodeClient {
        BeaconNodeClient::new(
            EthBeaconNodeApiClient::with_base_url(server.uri()).expect("valid mock server URL"),
        )
    }

    #[tokio::test]
    async fn repeated_lookups_fetch_each_endpoint_once() {
        let server = MockServer::start().await;
        mount_config(&server, 1).await;
        let client = client_over(&server);

        client.warm().await.unwrap();

        // Every lookup after warm() is served from cache (`.expect(1)` mocks).
        let attester = client.domain_type("DOMAIN_BEACON_ATTESTER").await.unwrap();
        let first = client.domain(attester, 20).await.unwrap();
        let second = client.domain(attester, 20).await.unwrap();
        assert_eq!(first, second);
        client.genesis_domain(attester).await.unwrap();
        assert_eq!(
            client.slots_config().await.unwrap(),
            (Duration::from_secs(12), 32)
        );
        client.fork_config().await.unwrap();
        client.genesis_time().await.unwrap();

        // Fork version at epoch 20 comes from the second schedule entry.
        assert_eq!(first[..4], [0x01, 0x00, 0x00, 0x00]);
    }

    #[tokio::test]
    async fn concurrent_cold_lookups_coalesce_into_one_fetch() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(SPEC_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(spec_body())
                    // Force overlap with the first in-flight fetch.
                    .set_delay(Duration::from_millis(100)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = client_over(&server);

        // Spawn all tasks before awaiting any (a lazy `map` would run them
        // sequentially) so they race on the cold entry.
        let lookups: Vec<_> = (0..16)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(async move { client.spec().await })
            })
            .collect();
        for lookup in lookups {
            lookup.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn fetch_failures_are_not_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(GENESIS_PATH))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let client = client_over(&server);
        client.genesis().await.unwrap_err();

        // Not cached: the next lookup after recovery succeeds.
        Mock::given(method("GET"))
            .and(path(GENESIS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(genesis_body()))
            .expect(1)
            .mount(&server)
            .await;
        client.genesis().await.unwrap();
    }

    /// An empty fork schedule is a fetch failure: cached, it would break all
    /// non-builder domain resolution until TTL expiry.
    #[tokio::test]
    async fn empty_fork_schedule_is_rejected_and_not_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(FORK_SCHEDULE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
            .expect(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let client = client_over(&server);
        client.fork_schedule().await.unwrap_err();

        // Not cached: the next lookup after recovery succeeds.
        Mock::given(method("GET"))
            .and(path(FORK_SCHEDULE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(fork_schedule_body()))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(client.fork_schedule().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn expired_values_are_refetched() {
        let entry = ConfigEntry::<u8>::default();
        let fetches = AtomicUsize::new(0);

        for _ in 0..2 {
            entry
                .get_or_fetch(Duration::ZERO, || async {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                })
                .await
                .unwrap();
        }

        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }
}
