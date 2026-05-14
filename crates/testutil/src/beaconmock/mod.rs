//! Beacon node API mocks for tests.
//!
//! `BeaconMock` owns the backing `wiremock::MockServer`, so keep the mock alive
//! for as long as clients use `BeaconMock::client()`.

mod attestation;
mod defaults;
mod fuzzer;
mod headproducer;
mod options;
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

#[bon]
impl BeaconMock {
    /// Builds a beacon mock with Charon-compatible defaults, overriding any
    /// provided fields.
    #[allow(clippy::too_many_arguments)]
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

        let head_producer =
            HeadProducer::spawn(&server, effective_genesis_time, effective_slot_duration).await;

        if fuzzer.unwrap_or(false) {
            mount_fuzzer(&server).await;
        }

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).map_err(Error::Client)?;

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
