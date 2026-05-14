//! Default spec/genesis and mount logic for the beacon mock HTTP handlers.

use std::{collections::BTreeMap, sync::Arc};

use chrono::{DateTime, TimeZone, Utc};
use pluto_eth2api::spec::phase0::{Epoch, ValidatorIndex};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use super::state::{MockState, read_lock};

pub(crate) const ZERO_ROOT: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";
pub(crate) const DEFAULT_GENESIS_VALIDATORS_ROOT: &str =
    "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1";
pub(crate) const DEFAULT_GENESIS_FORK_VERSION: &str = "0x01017000";
pub(crate) const DEFAULT_MOCK_PRIORITY: u8 = 255;

pub(crate) async fn mount_defaults(server: &MockServer, state: Arc<MockState>) {
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

pub(crate) async fn mount_json<F>(
    server: &MockServer,
    http_method: &'static str,
    endpoint: &'static str,
    f: F,
) where
    F: Send + Sync + 'static + Fn(&Request) -> Value,
{
    mount_json_with_status(server, http_method, endpoint, 200, f).await;
}

pub(crate) async fn mount_json_with_status<F>(
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

pub(crate) async fn mount_status(
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

pub(crate) fn default_spec() -> Value {
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

pub(crate) fn default_genesis() -> Value {
    json!({
        "genesis_time": default_genesis_time().timestamp().to_string(),
        "genesis_validators_root": DEFAULT_GENESIS_VALIDATORS_ROOT,
        "genesis_fork_version": DEFAULT_GENESIS_FORK_VERSION,
    })
}

pub(crate) fn default_genesis_time() -> DateTime<Utc> {
    match Utc.with_ymd_and_hms(2022, 3, 1, 0, 0, 0).single() {
        Some(time) => time,
        None => Utc::now(),
    }
}
