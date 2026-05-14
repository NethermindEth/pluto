//! Beacon node API mocks for tests.
//!
//! `BeaconMock` owns the backing `wiremock::MockServer`, so keep the mock alive
//! for as long as clients use `BeaconMock::client()`.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use bon::bon;
use chrono::{DateTime, TimeZone, Utc};
use pluto_eth2api::{
    EthBeaconNodeApiClient, ValidatorResponseValidator, ValidatorStatus,
    spec::phase0::{BLSPubKey, Epoch, Root, ValidatorIndex},
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, path_regex},
};

const ZERO_ROOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const DEFAULT_GENESIS_VALIDATORS_ROOT: &str =
    "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1";
const DEFAULT_GENESIS_FORK_VERSION: &str = "0x01017000";
const DEFAULT_WITHDRAWAL_CREDENTIALS: &str =
    "0x3132333435363738393031323334353637383930313233343536373839303132";
const DEFAULT_MOCK_PRIORITY: u8 = 255;

/// Errors returned while configuring `BeaconMock`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The generated beacon API client could not be created for the mock URL.
    #[error("create beacon node api client: {0}")]
    Client(#[source] anyhow::Error),
}

/// Result type for beacon mock setup.
pub type Result<T> = std::result::Result<T, Error>;

/// Minimal validator representation used by the beacon mock.
#[derive(Debug, Clone, PartialEq)]
pub struct Validator {
    /// Validator index in the beacon registry.
    pub index: ValidatorIndex,
    /// Current balance in gwei.
    pub balance: u64,
    /// Current validator status.
    pub status: ValidatorStatus,
    /// Validator details returned by the beacon API.
    pub validator: ValidatorResponseValidator,
}

impl Validator {
    /// Creates an active validator with the provided index and public key.
    #[must_use]
    pub fn active(index: ValidatorIndex, pubkey: BLSPubKey) -> Self {
        let pubkey = hex_0x(pubkey);

        Self {
            index,
            balance: index,
            status: ValidatorStatus::ActiveOngoing,
            validator: ValidatorResponseValidator {
                activation_eligibility_epoch: index.to_string(),
                activation_epoch: index.checked_add(1).unwrap_or(index).to_string(),
                effective_balance: index.to_string(),
                exit_epoch: u64::MAX.to_string(),
                pubkey,
                slashed: false,
                withdrawable_epoch: u64::MAX.to_string(),
                withdrawal_credentials: DEFAULT_WITHDRAWAL_CREDENTIALS.to_string(),
            },
        }
    }
}

/// Validator set used to seed validator and duty endpoints.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValidatorSet(BTreeMap<ValidatorIndex, Validator>);

impl ValidatorSet {
    /// Returns the small deterministic validator set from Charon's Go
    /// beaconmock.
    #[must_use]
    pub fn validator_set_a() -> Self {
        [
            (
                1,
                "0x914cff835a769156ba43ad50b931083c2dadd94e8359ce394bc7a3e06424d0214922ddf15f81640530b9c25c0bc0d490",
            ),
            (
                2,
                "0x8dae41352b69f2b3a1c0b05330c1bf65f03730c520273028864b11fcb94d8ce8f26d64f979a0ee3025467f45fd2241ea",
            ),
            (
                3,
                "0x8ee91545183c8c2db86633626f5074fd8ef93c4c9b7a2879ad1768f600c5b5906c3af20d47de42c3b032956fa8db1a76",
            ),
        ]
        .into_iter()
        .filter_map(|(index, pubkey)| {
            parse_pubkey(pubkey).map(|pubkey| (index, Validator::active(index, pubkey)))
        })
        .collect()
    }

    /// Inserts or replaces a validator.
    pub fn insert(&mut self, validator: Validator) {
        self.0.insert(validator.index, validator);
    }

    /// Returns all validators in index order.
    #[must_use]
    pub fn validators(&self) -> Vec<Validator> {
        self.0.values().cloned().collect()
    }

    /// Returns the validator for an index.
    #[must_use]
    pub fn by_index(&self, index: ValidatorIndex) -> Option<Validator> {
        self.0.get(&index).cloned()
    }

    /// Returns true if the set contains no validators.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<(ValidatorIndex, Validator)> for ValidatorSet {
    fn from_iter<T: IntoIterator<Item = (ValidatorIndex, Validator)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Shared mock state used by mounted HTTP handlers.
#[derive(Debug)]
pub struct MockState {
    spec: RwLock<Value>,
    genesis: RwLock<Value>,
    validator_set: RwLock<ValidatorSet>,
    deterministic_attester_duties: RwLock<Option<u64>>,
    deterministic_proposer_duties: RwLock<Option<u64>>,
}

impl MockState {
    fn new(spec: Value, genesis: Value, validator_set: ValidatorSet) -> Self {
        Self {
            spec: RwLock::new(spec),
            genesis: RwLock::new(genesis),
            validator_set: RwLock::new(validator_set),
            deterministic_attester_duties: RwLock::new(None),
            deterministic_proposer_duties: RwLock::new(None),
        }
    }

    /// Returns a clone of the spec map served by `/eth/v1/config/spec`.
    #[must_use]
    pub fn spec(&self) -> Value {
        read_lock(&self.spec).clone()
    }

    /// Replaces one spec key.
    pub fn set_spec_field(&self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        if let Some(spec) = write_lock(&self.spec).as_object_mut() {
            spec.insert(key, value);
        }
    }

    /// Returns a clone of the genesis data served by `/eth/v1/beacon/genesis`.
    #[must_use]
    pub fn genesis(&self) -> Value {
        read_lock(&self.genesis).clone()
    }

    /// Replaces one genesis field.
    pub fn set_genesis_field(&self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        if let Some(genesis) = write_lock(&self.genesis).as_object_mut() {
            genesis.insert(key, value);
        }
    }

    /// Replaces the validator set served by validator-related endpoints.
    pub fn set_validator_set(&self, validator_set: ValidatorSet) {
        *write_lock(&self.validator_set) = validator_set;
    }
}

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

async fn mount_defaults(server: &MockServer, state: Arc<MockState>) {
    Mock::given(method("GET"))
        .and(path("/up"))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(DEFAULT_MOCK_PRIORITY)
        .mount(server)
        .await;

    mount_json(server, "GET", "/eth/v1/config/spec", {
        let state = Arc::clone(&state);
        move |_| json!({ "data": state.spec() })
    })
    .await;

    mount_json(server, "GET", "/eth/v1/beacon/genesis", {
        let state = Arc::clone(&state);
        move |_| json!({ "data": state.genesis() })
    })
    .await;

    mount_json(server, "GET", "/eth/v1/config/fork_schedule", |_| {
        json!({
            "data": [
                { "previous_version": "0x01017000", "current_version": "0x01017000", "epoch": "0" },
                { "previous_version": "0x01017000", "current_version": "0x02017000", "epoch": "0" },
                { "previous_version": "0x02017000", "current_version": "0x03017000", "epoch": "0" },
                { "previous_version": "0x03017000", "current_version": "0x04017000", "epoch": "0" },
                { "previous_version": "0x04017000", "current_version": "0x05017000", "epoch": "0" }
            ]
        })
    })
    .await;

    mount_json(
        server,
        "GET",
        "/eth/v1/node/version",
        |_| json!({ "data": { "version": "charon/static_beacon_mock" } }),
    )
    .await;

    mount_json(server, "GET", "/eth/v1/node/syncing", |_| {
        json!({
            "data": {
                "head_slot": "1",
                "sync_distance": "0",
                "is_syncing": false,
                "is_optimistic": false,
                "el_offline": false
            }
        })
    })
    .await;

    mount_json(server, "GET", "/eth/v1/beacon/headers/head", |_| {
        json!({
            "data": {
                "root": ZERO_ROOT,
                "canonical": true,
                "header": {
                    "message": {
                        "slot": "1",
                        "proposer_index": "0",
                        "parent_root": ZERO_ROOT,
                        "state_root": ZERO_ROOT,
                        "body_root": ZERO_ROOT
                    },
                    "signature": format!("0x{}", "00".repeat(96))
                }
            },
            "execution_optimistic": false,
            "finalized": false
        })
    })
    .await;

    mount_json(server, "GET", "/eth/v1/config/deposit_contract", |_| {
        json!({
            "data": {
                "chain_id": "17000",
                "address": "0x4242424242424242424242424242424242424242"
            }
        })
    })
    .await;

    mount_status(
        server,
        "POST",
        "/eth/v1/validator/sync_committee_subscriptions",
        200,
    )
    .await;
    mount_status(
        server,
        "POST",
        "/eth/v1/validator/beacon_committee_subscriptions",
        200,
    )
    .await;
    mount_status(
        server,
        "POST",
        "/eth/v1/validator/prepare_beacon_proposer",
        200,
    )
    .await;

    mount_json_with_status(
        server,
        "GET",
        "/eth/v2/validator/aggregate_attestation",
        400,
        |_| {
            json!({
                "code": 403,
                "message": "Beacon node was not assigned to aggregate on that subnet."
            })
        },
    )
    .await;

    mount_json(server, "GET", "/eth/v1/beacon/states/head/validators", {
        let state = Arc::clone(&state);
        move |_| validators_response(&state)
    })
    .await;

    mount_json(
        server,
        "POST",
        r"^/eth/v1/validator/duties/attester/[0-9]+$",
        {
            let state = Arc::clone(&state);
            move |request| attester_duties_response(&state, request)
        },
    )
    .await;

    mount_json(
        server,
        "GET",
        r"^/eth/v1/validator/duties/proposer/[0-9]+$",
        {
            let state = Arc::clone(&state);
            move |request| proposer_duties_response(&state, request)
        },
    )
    .await;
}

async fn mount_json<F>(server: &MockServer, http_method: &'static str, endpoint: &'static str, f: F)
where
    F: Send + Sync + 'static + Fn(&Request) -> Value,
{
    mount_json_with_status(server, http_method, endpoint, 200, f).await;
}

async fn mount_json_with_status<F>(
    server: &MockServer,
    http_method: &'static str,
    endpoint: &'static str,
    status: u16,
    f: F,
) where
    F: Send + Sync + 'static + Fn(&Request) -> Value,
{
    let route = Mock::given(method(http_method));
    let route = if endpoint.starts_with('^') {
        route.and(path_regex(endpoint))
    } else {
        route.and(path(endpoint))
    };

    route
        .respond_with(move |request: &Request| {
            ResponseTemplate::new(status).set_body_json(f(request))
        })
        .with_priority(DEFAULT_MOCK_PRIORITY)
        .mount(server)
        .await;
}

async fn mount_status(
    server: &MockServer,
    http_method: &'static str,
    endpoint: &'static str,
    status: u16,
) {
    Mock::given(method(http_method))
        .and(path(endpoint))
        .respond_with(ResponseTemplate::new(status))
        .with_priority(DEFAULT_MOCK_PRIORITY)
        .mount(server)
        .await;
}

fn validators_response(state: &MockState) -> Value {
    let data: Vec<Value> = read_lock(&state.validator_set)
        .validators()
        .into_iter()
        .map(|validator| {
            json!({
                "index": validator.index.to_string(),
                "balance": validator.balance.to_string(),
                "status": validator.status,
                "validator": validator.validator,
            })
        })
        .collect();

    json!({
        "data": data,
        "execution_optimistic": false,
        "finalized": false
    })
}

fn attester_duties_response(state: &MockState, request: &Request) -> Value {
    let Some(factor) = *read_lock(&state.deterministic_attester_duties) else {
        return duties_response(Vec::new());
    };

    let epoch = epoch_from_path(request.url.path());
    let mut indices = indices_from_body(request);
    indices.sort_unstable();

    let validator_set = read_lock(&state.validator_set).clone();
    let slots_per_epoch = slots_per_epoch(state);
    let committee_length = factor.max(1);
    let validator_committee_index = committee_length.saturating_sub(1);

    let data = indices
        .into_iter()
        .enumerate()
        .filter_map(|(position, index)| {
            let validator = validator_set.by_index(index)?;
            let position = u64::try_from(position).ok()?;
            let slot_offset = position.checked_mul(factor)?.checked_rem(slots_per_epoch)?;
            let slot = slots_per_epoch
                .checked_mul(epoch)?
                .checked_add(slot_offset)?;

            Some(json!({
                "pubkey": validator.validator.pubkey,
                "slot": slot.to_string(),
                "validator_index": index.to_string(),
                "committee_index": index.to_string(),
                "committee_length": committee_length.to_string(),
                "committees_at_slot": slots_per_epoch.to_string(),
                "validator_committee_index": validator_committee_index.to_string(),
            }))
        })
        .collect();

    duties_response(data)
}

fn proposer_duties_response(state: &MockState, request: &Request) -> Value {
    let Some(factor) = *read_lock(&state.deterministic_proposer_duties) else {
        return duties_response(Vec::new());
    };

    let epoch = epoch_from_path(request.url.path());
    let slots_per_epoch = slots_per_epoch(state);
    let validators = read_lock(&state.validator_set).validators();
    let mut assigned_slots = BTreeMap::new();
    let mut data = Vec::new();

    for (position, validator) in validators.into_iter().enumerate() {
        let Ok(position) = u64::try_from(position) else {
            continue;
        };
        let Some(slot_offset) = position
            .checked_mul(factor)
            .and_then(|offset| offset.checked_rem(slots_per_epoch))
        else {
            continue;
        };
        if assigned_slots.contains_key(&slot_offset) {
            break;
        }

        assigned_slots.insert(slot_offset, ());

        let Some(slot) = slots_per_epoch
            .checked_mul(epoch)
            .and_then(|base| base.checked_add(slot_offset))
        else {
            continue;
        };

        data.push(json!({
            "pubkey": validator.validator.pubkey,
            "slot": slot.to_string(),
            "validator_index": validator.index.to_string(),
        }));

        if factor == 0 {
            break;
        }
    }

    duties_response(data)
}

fn duties_response(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "dependent_root": ZERO_ROOT,
        "execution_optimistic": false
    })
}

fn indices_from_body(request: &Request) -> Vec<ValidatorIndex> {
    serde_json::from_slice::<Vec<String>>(&request.body)
        .map(|indices| {
            indices
                .into_iter()
                .filter_map(|index| index.parse::<ValidatorIndex>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn epoch_from_path(path: &str) -> Epoch {
    path.rsplit('/')
        .next()
        .and_then(|epoch| epoch.parse::<Epoch>().ok())
        .unwrap_or_default()
}

fn slots_per_epoch(state: &MockState) -> u64 {
    read_lock(&state.spec)
        .get("SLOTS_PER_EPOCH")
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
        .filter(|slots| *slots > 0)
        .unwrap_or(16)
}

fn default_spec() -> Value {
    json!({
        "CONFIG_NAME": "charon-simnet",
        "SLOTS_PER_EPOCH": "16",
        "SECONDS_PER_SLOT": "12",
        "MIN_GENESIS_TIME": default_genesis_time().timestamp().to_string(),
        "GENESIS_FORK_VERSION": DEFAULT_GENESIS_FORK_VERSION,
        "ALTAIR_FORK_VERSION": "0x20000910",
        "ALTAIR_FORK_EPOCH": "0",
        "BELLATRIX_FORK_VERSION": "0x30000910",
        "BELLATRIX_FORK_EPOCH": "0",
        "CAPELLA_FORK_VERSION": "0x40000910",
        "CAPELLA_FORK_EPOCH": "0",
        "DENEB_FORK_VERSION": "0x50000910",
        "DENEB_FORK_EPOCH": "0",
        "ELECTRA_FORK_VERSION": "0x60000910",
        "ELECTRA_FORK_EPOCH": "2048",
        "FULU_FORK_VERSION": "0x70000910",
        "FULU_FORK_EPOCH": u64::MAX.to_string(),
        "DOMAIN_BEACON_PROPOSER": "0x00000000",
        "DOMAIN_BEACON_ATTESTER": "0x01000000",
        "DOMAIN_RANDAO": "0x02000000",
        "DOMAIN_DEPOSIT": "0x03000000",
        "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
        "DOMAIN_SELECTION_PROOF": "0x05000000",
        "DOMAIN_AGGREGATE_AND_PROOF": "0x06000000",
        "DOMAIN_SYNC_COMMITTEE": "0x07000000",
        "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF": "0x08000000",
        "DOMAIN_CONTRIBUTION_AND_PROOF": "0x09000000",
        "DOMAIN_APPLICATION_BUILDER": "0x00000001",
        "TARGET_AGGREGATORS_PER_COMMITTEE": "16",
        "SYNC_COMMITTEE_SIZE": "512",
        "SYNC_COMMITTEE_SUBNET_COUNT": "4",
        "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE": "16",
        "EPOCHS_PER_SYNC_COMMITTEE_PERIOD": "256"
    })
}

fn default_genesis() -> Value {
    json!({
        "genesis_time": default_genesis_time().timestamp().to_string(),
        "genesis_validators_root": DEFAULT_GENESIS_VALIDATORS_ROOT,
        "genesis_fork_version": DEFAULT_GENESIS_FORK_VERSION,
    })
}

fn default_genesis_time() -> DateTime<Utc> {
    match Utc.with_ymd_and_hms(2022, 3, 1, 0, 0, 0).single() {
        Some(time) => time,
        None => Utc::now(),
    }
}

fn set_object_field(target: &mut Value, key: &'static str, value: impl Into<Value>) {
    if let Some(target) = target.as_object_mut() {
        target.insert(key.to_string(), value.into());
    }
}

fn hex_0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

fn parse_pubkey(pubkey: &str) -> Option<BLSPubKey> {
    let pubkey = pubkey.strip_prefix("0x").unwrap_or(pubkey);
    let bytes = hex::decode(pubkey).ok()?;
    bytes.try_into().ok()
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
