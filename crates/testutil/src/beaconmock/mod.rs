//! Beacon node API mocks for tests.
//!
//! `BeaconMock` owns the backing `wiremock::MockServer`, so keep the mock alive
//! for as long as clients use `BeaconMock::client()`.

mod attestation;
mod defaults;
mod fuzzer;
mod gorand;
mod headproducer;
mod options;
mod proposal;
mod state;

use std::{sync::Arc, time::Duration};

use bon::bon;
use chrono::{DateTime, Utc};
use pluto_eth2api::{EthBeaconNodeApiClient, spec::phase0::Root};
use serde_json::Value;
use wiremock::MockServer;

use defaults::{default_genesis, default_genesis_time, default_spec, mount_defaults};
use fuzzer::mount_fuzzer;
use headproducer::HeadProducer;
use options::{
    mount_endpoint_override, mount_no_attester_duties, mount_no_proposer_duties,
    mount_no_sync_committee_duties,
};
use state::{hex_0x, set_object_field, write_lock};

pub use state::{MockState, Validator, ValidatorSet};

/// Errors returned while configuring `BeaconMock`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The generated beacon API client could not be created for the mock URL.
    #[error("create beacon node api client: {0}")]
    Client(#[source] anyhow::Error),
}

/// Result type for beacon mock setup.
pub type Result<T> = std::result::Result<T, Error>;

/// Wire-level beacon node mock with a generated client pre-dialed to the
/// server.
#[derive(Debug)]
pub struct BeaconMock {
    server: MockServer,
    client: EthBeaconNodeApiClient,
    state: Arc<MockState>,
    // Held to keep the slot ticker alive; dropped with `BeaconMock`.
    _head_producer: HeadProducer,
}

impl Drop for BeaconMock {
    fn drop(&mut self) {
        // The pooled port may be reused by the next test's server; don't
        // leak this mock's cached chain config to it.
        pluto_eth2api::purge_chain_config_cache(&self.client.base_url);
    }
}

#[bon]
impl BeaconMock {
    /// Builds a beacon mock with charon-compatible defaults, overriding any
    /// provided fields.
    #[builder]
    pub async fn new(
        validator_set: Option<ValidatorSet>,
        slot_duration: Option<Duration>,
        slots_per_epoch: Option<u64>,
        genesis_time: Option<DateTime<Utc>>,
        genesis_validators_root: Option<Root>,
        spec: Option<Value>,
        deterministic_attester_duties: Option<u64>,
        deterministic_proposer_duties: Option<u64>,
        fuzzer: Option<bool>,
        #[builder(default)] endpoint_overrides: Vec<(String, Value)>,
        fork_version: Option<[u8; 4]>,
        sync_committee_size: Option<u64>,
        sync_committee_subnet_count: Option<u64>,
        #[builder(default)] no_proposer_duties: bool,
        #[builder(default)] no_attester_duties: bool,
        #[builder(default)] no_sync_committee_duties: bool,
        deterministic_sync_comm_duties: Option<(u64, u64)>,
    ) -> Result<Self> {
        let mut spec = spec.unwrap_or_else(default_spec);
        let mut genesis = default_genesis();
        let validator_set = validator_set.unwrap_or_default();

        let effective_slot_duration = slot_duration.unwrap_or(Duration::from_secs(12));
        let effective_genesis_time = genesis_time.unwrap_or_else(default_genesis_time);

        if let Some(slot_duration) = slot_duration {
            // `SECONDS_PER_SLOT` truncates to whole seconds, but the head ticker
            // runs at the exact `slot_duration`. Clocks derived from
            // `SECONDS_PER_SLOT` only stay aligned when callers pass whole
            // seconds (the simnet path does, via `normalize_simnet_slot_duration`).
            set_object_field(
                &mut spec,
                "SECONDS_PER_SLOT",
                slot_duration.as_secs().to_string(),
            );
        }

        if let Some(slots_per_epoch) = slots_per_epoch {
            set_object_field(&mut spec, "SLOTS_PER_EPOCH", slots_per_epoch.to_string());
        }

        if let Some(genesis_time) = genesis_time {
            let timestamp = genesis_time.timestamp().to_string();
            set_object_field(&mut genesis, "genesis_time", timestamp.clone());
            set_object_field(&mut spec, "MIN_GENESIS_TIME", timestamp);
        }

        if let Some(genesis_validators_root) = genesis_validators_root {
            set_object_field(
                &mut genesis,
                "genesis_validators_root",
                hex_0x(genesis_validators_root),
            );
        }

        if let Some(fork_version) = fork_version {
            let formatted = hex_0x(fork_version);
            set_object_field(&mut spec, "GENESIS_FORK_VERSION", formatted.clone());
            set_object_field(&mut genesis, "genesis_fork_version", formatted);
        }

        if let Some(size) = sync_committee_size {
            set_object_field(&mut spec, "SYNC_COMMITTEE_SIZE", size.to_string());
        }

        if let Some(count) = sync_committee_subnet_count {
            set_object_field(&mut spec, "SYNC_COMMITTEE_SUBNET_COUNT", count.to_string());
        }

        if let Some((n, _)) = deterministic_sync_comm_duties {
            set_object_field(&mut spec, "EPOCHS_PER_SYNC_COMMITTEE_PERIOD", n.to_string());
        }

        let state = Arc::new(MockState::new(spec, genesis, validator_set));
        *write_lock(&state.deterministic_attester_duties) = deterministic_attester_duties;
        *write_lock(&state.deterministic_proposer_duties) = deterministic_proposer_duties;
        *write_lock(&state.deterministic_sync_comm_duties) = deterministic_sync_comm_duties;

        let server = MockServer::start().await;

        // Higher priority (lower number) mounts must register before the defaults
        // so wiremock falls back to the default routes when no override matches.
        for (endpoint, value) in endpoint_overrides {
            mount_endpoint_override(&server, endpoint, value).await;
        }
        if no_proposer_duties {
            mount_no_proposer_duties(&server).await;
        }
        if no_attester_duties {
            mount_no_attester_duties(&server).await;
        }
        if no_sync_committee_duties {
            mount_no_sync_committee_duties(&server).await;
        }

        mount_defaults(&server, Arc::clone(&state)).await;
        attestation::mount(&server, Arc::clone(&state)).await;
        proposal::mount(&server, Arc::clone(&state)).await;

        let head_producer =
            HeadProducer::spawn(&server, effective_genesis_time, effective_slot_duration).await;

        if fuzzer.unwrap_or(false) {
            mount_fuzzer(&server).await;
        }

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).map_err(Error::Client)?;
        // Wiremock pools listeners, so this port may have served an earlier
        // test; drop any chain config cached for it.
        pluto_eth2api::purge_chain_config_cache(&client.base_url);

        Ok(Self {
            server,
            client,
            state,
            _head_producer: head_producer,
        })
    }

    /// Returns the generated beacon node API client connected to this mock.
    #[must_use]
    pub fn client(&self) -> &EthBeaconNodeApiClient {
        &self.client
    }

    /// Returns the backing mock server for mounting test-specific endpoints.
    #[must_use]
    pub fn server(&self) -> &MockServer {
        &self.server
    }

    /// Returns the mock server base URI.
    #[must_use]
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Returns shared state used by the mounted HTTP handlers.
    #[must_use]
    pub fn state(&self) -> Arc<MockState> {
        Arc::clone(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike, Utc};
    use serde_json::json;

    const ATTESTER_DUTIES_GOLDEN: &str =
        include_str!("testdata/TestDeterministicAttesterDuties.golden");
    const PROPOSER_DUTIES_GOLDEN: &str =
        include_str!("testdata/TestDeterministicProposerDuties.golden");
    const ATTESTATION_STORE_GOLDEN: &str = include_str!("testdata/TestAttestationStore.golden");

    async fn get_json(url: &str) -> Value {
        let resp = reqwest::get(url).await.expect("send");
        assert_eq!(resp.status(), 200, "GET {url} returned {}", resp.status());
        resp.json().await.expect("json")
    }

    async fn post_json(url: &str, body: &Value) -> Value {
        let resp = reqwest::Client::new()
            .post(url)
            .json(body)
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), 200, "POST {url} returned {}", resp.status());
        resp.json().await.expect("json")
    }

    /// Asserts that `actual` equals the JSON in `golden`.
    fn assert_golden_json(actual: &Value, golden: &str) {
        let expected: Value = serde_json::from_str(golden).expect("parse golden");
        assert_eq!(actual, &expected, "actual JSON does not match golden");
    }

    /// Validator set A, deterministic factor 1, epoch 1, validator index 2 —
    /// response must match the shared golden fixture.
    #[tokio::test]
    async fn deterministic_attester_duties() {
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_attester_duties(1)
            .build()
            .await
            .expect("build mock");

        let url = format!("{}/eth/v1/validator/duties/attester/1", mock.uri());
        let body = post_json(&url, &json!(["2"])).await;
        assert_golden_json(&body["data"], ATTESTER_DUTIES_GOLDEN);
    }

    /// Validator set A, deterministic factor 1, epoch 1. The mock ignores the
    /// indices filter and assigns all active validators round-robin — response
    /// must match the shared golden fixture.
    #[tokio::test]
    async fn deterministic_proposer_duties() {
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_proposer_duties(1)
            .build()
            .await
            .expect("build mock");

        let url = format!("{}/eth/v1/validator/duties/proposer/1", mock.uri());
        let body = get_json(&url).await;
        assert_golden_json(&body["data"], PROPOSER_DUTIES_GOLDEN);
    }

    /// Proposer duties must skip non-active validators in the set (the
    /// deterministic assignment iterates active validators only).
    #[tokio::test]
    async fn proposer_duties_skip_inactive_validators() {
        use pluto_eth2api::{ValidatorResponseValidator, ValidatorStatus};

        let mut set = ValidatorSet::validator_set_a();
        set.insert(Validator {
            index: 4,
            balance: 4,
            status: ValidatorStatus::WithdrawalDone,
            validator: ValidatorResponseValidator {
                activation_eligibility_epoch: "4".into(),
                activation_epoch: "5".into(),
                effective_balance: "4".into(),
                exit_epoch: "0".into(),
                pubkey: format!("0x{}", "01".repeat(48)),
                slashed: false,
                withdrawable_epoch: "0".into(),
                withdrawal_credentials: format!("0x{}", "00".repeat(32)),
            },
        });

        let mock = BeaconMock::builder()
            .validator_set(set)
            .deterministic_proposer_duties(1)
            .build()
            .await
            .expect("build mock");

        let url = format!("{}/eth/v1/validator/duties/proposer/1", mock.uri());
        let body = get_json(&url).await;
        let indices: Vec<&str> = body["data"]
            .as_array()
            .expect("duties array")
            .iter()
            .filter_map(|duty| duty["validator_index"].as_str())
            .collect();
        assert_eq!(
            indices,
            ["1", "2", "3"],
            "inactive validator (index 4) must be skipped"
        );
    }

    /// Golden assertion on `AttestationData` for slot=1, committee_index=2.
    /// Encodes the `previous_epoch = epoch - 1` wraparound at epoch 0
    /// (source.epoch = u64::MAX).
    #[tokio::test]
    async fn attestation_data_matches_golden() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let url = format!(
            "{}/eth/v1/validator/attestation_data?slot=1&committee_index=2",
            mock.uri()
        );
        let body = get_json(&url).await;
        assert_golden_json(&body["data"], ATTESTATION_STORE_GOLDEN);
    }

    /// Default mock serves genesis/spec/deposit-contract/syncing/version with
    /// the expected baseline values.
    #[tokio::test]
    async fn static_endpoints() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let base = mock.uri();

        let genesis = get_json(&format!("{base}/eth/v1/beacon/genesis")).await;
        let expected = Utc.with_ymd_and_hms(2022, 3, 1, 0, 0, 0).unwrap();
        assert_eq!(
            genesis["data"]["genesis_time"],
            expected.timestamp().to_string()
        );

        let spec = get_json(&format!("{base}/eth/v1/config/spec")).await;
        assert_eq!(spec["data"]["ALTAIR_FORK_EPOCH"], "0");
        assert_eq!(spec["data"]["DENEB_FORK_EPOCH"], "0");
        assert_eq!(spec["data"]["ELECTRA_FORK_EPOCH"], "2048");
        assert_eq!(spec["data"]["SLOTS_PER_EPOCH"], "16");

        let deposit = get_json(&format!("{base}/eth/v1/config/deposit_contract")).await;
        assert_eq!(deposit["data"]["chain_id"], "17000");

        let syncing = get_json(&format!("{base}/eth/v1/node/syncing")).await;
        assert_eq!(syncing["data"]["is_syncing"], false);

        let version = get_json(&format!("{base}/eth/v1/node/version")).await;
        assert_eq!(
            version["data"]["version"],
            "teku/v25.9.3/linux-x86_64/-ubuntu-openjdk64bitservervm-java-21"
        );
    }

    /// A builder-provided genesis time flows through to the
    /// `/eth/v1/beacon/genesis` endpoint.
    #[tokio::test]
    async fn genesis_time_override() {
        let t0 = Utc::now().with_nanosecond(0).expect("truncate nanoseconds");
        let mock = BeaconMock::builder()
            .genesis_time(t0)
            .build()
            .await
            .expect("build mock");

        let body = get_json(&format!("{}/eth/v1/beacon/genesis", mock.uri())).await;
        assert_eq!(
            body["data"]["genesis_time"],
            t0.timestamp().to_string(),
            "genesis_time override should be served verbatim"
        );
    }

    /// A builder-set slots_per_epoch is reflected in the spec endpoint.
    #[tokio::test]
    async fn slots_per_epoch_override() {
        let mock = BeaconMock::builder()
            .slots_per_epoch(5)
            .build()
            .await
            .expect("build mock");

        let body = get_json(&format!("{}/eth/v1/config/spec", mock.uri())).await;
        assert_eq!(body["data"]["SLOTS_PER_EPOCH"], "5");
    }

    /// A builder-set slot_duration is reflected as SECONDS_PER_SLOT in the spec
    /// endpoint.
    #[tokio::test]
    async fn slot_duration_override() {
        let mock = BeaconMock::builder()
            .slot_duration(Duration::from_secs(1))
            .build()
            .await
            .expect("build mock");

        let body = get_json(&format!("{}/eth/v1/config/spec", mock.uri())).await;
        assert_eq!(body["data"]["SECONDS_PER_SLOT"], "1");
    }

    /// With no builder options, the spec reports the simnet defaults and
    /// genesis time matches the 2022-03-01 baseline.
    #[tokio::test]
    async fn default_overrides() {
        let mock = BeaconMock::builder().build().await.expect("build mock");
        let base = mock.uri();

        let spec = get_json(&format!("{base}/eth/v1/config/spec")).await;
        assert_eq!(spec["data"]["CONFIG_NAME"], "charon-simnet");
        assert_eq!(spec["data"]["SLOTS_PER_EPOCH"], "16");

        let genesis = get_json(&format!("{base}/eth/v1/beacon/genesis")).await;
        let expected = Utc.with_ymd_and_hms(2022, 3, 1, 0, 0, 0).unwrap();
        assert_eq!(
            genesis["data"]["genesis_time"],
            expected.timestamp().to_string()
        );
    }

    /// Regression for the simnet duty-flow blocker: validators are resolved via
    /// POST `/eth/v1/beacon/states/{id}/validators` — by the core scheduler's
    /// `ValidatorCache` and by the validator mock's `active_validators` (which
    /// fronts every attester/proposer/sync-committee duty). The mock must serve
    /// POST, not just the literal-`head` GET, or no validator is ever seen and
    /// no duty flows.
    #[tokio::test]
    async fn post_state_validators_resolves_seeded_set() {
        use pluto_eth2api::valcache::ValidatorCache;

        let mut pk_a = [0u8; 48];
        pk_a[0] = 0xaa;
        let mut pk_b = [0u8; 48];
        pk_b[0] = 0xbb;

        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::mock_dvs([pk_a, pk_b]))
            .build()
            .await
            .expect("build mock");

        // Core-scheduler path: `get_by_head` → `post_state_validators` (POST).
        let cache = ValidatorCache::new(mock.client().clone(), Vec::new());
        let (active, _complete) = cache
            .get_by_head()
            .await
            .expect("valcache resolves validators via POST");
        assert_eq!(active.pubkeys().count(), 2, "both seeded validators active");

        // Validator-mock path: same POST endpoint, distinct caller.
        let vmock_active = crate::validatormock::active_validators(mock.client())
            .await
            .expect("vmock active_validators resolves via POST");
        assert_eq!(vmock_active.len(), 2);
    }

    /// The core fetcher fetches proposer data via `produce_block_v3` → GET
    /// `/eth/v3/validator/blocks/{slot}`; without a mount it gets
    /// `UnexpectedResponse` and the proposer duty never decides. Assert the
    /// mock serves an `Ok` produce-block response the client parses.
    #[tokio::test]
    async fn produce_block_v3_serves_ok_proposal() {
        use pluto_eth2api::{ProduceBlockV3Request, ProduceBlockV3Response};

        let mock = BeaconMock::builder().build().await.expect("build mock");
        let request = ProduceBlockV3Request::builder()
            .slot("1".to_string())
            .randao_reveal(format!("0x{}", "00".repeat(96)))
            .graffiti(format!("0x{}", "00".repeat(32)))
            .builder_boost_factor("0".to_string())
            .build()
            .expect("build produce-block request");

        let resp = mock
            .client()
            .produce_block_v3(request)
            .await
            .expect("produce_block_v3 request succeeds");
        assert!(
            matches!(resp, ProduceBlockV3Response::Ok(_)),
            "expected an Ok produce-block response (not UnexpectedResponse)"
        );
    }
}
