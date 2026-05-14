//! Beacon node API mocks for tests.
//!
//! `BeaconMock` owns the backing `wiremock::MockServer`, so keep the mock alive
//! for as long as clients use `BeaconMock::client()`.

mod defaults;
mod state;

use std::{sync::Arc, time::Duration};

use bon::bon;
use chrono::{DateTime, Utc};
use pluto_eth2api::{EthBeaconNodeApiClient, spec::phase0::Root};
use serde_json::Value;
use wiremock::MockServer;

use defaults::{default_genesis, default_spec, mount_defaults};
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
}

#[bon]
impl BeaconMock {
    /// Builds a beacon mock with Charon-compatible defaults, overriding any
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
    ) -> Result<Self> {
        let mut spec = spec.unwrap_or_else(default_spec);
        let mut genesis = default_genesis();
        let validator_set = validator_set.unwrap_or_default();

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

        let state = Arc::new(MockState::new(spec, genesis, validator_set));
        *write_lock(&state.deterministic_attester_duties) = deterministic_attester_duties;
        *write_lock(&state.deterministic_proposer_duties) = deterministic_proposer_duties;

        let server = MockServer::start().await;
        mount_defaults(&server, Arc::clone(&state)).await;

        let client = EthBeaconNodeApiClient::with_base_url(server.uri()).map_err(Error::Client)?;

        Ok(Self {
            server,
            client,
            state,
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
