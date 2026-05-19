//! Default spec/genesis and mount logic for the beacon mock HTTP handlers.

use std::{collections::BTreeMap, sync::Arc};

use chrono::{DateTime, TimeZone, Utc};
use pluto_eth2api::spec::phase0::{Epoch, ValidatorIndex};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use super::state::{MockState, last_path_segment_u64, read_lock};

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

    mount_response(
        server,
        "POST",
        r"^/eth/v1/validator/duties/attester/[0-9]+$",
        {
            let state = Arc::clone(&state);
            move |request| attester_duties_response(&state, request)
        },
    )
    .await;

    mount_response(
        server,
        "GET",
        r"^/eth/v1/validator/duties/proposer/[0-9]+$",
        {
            let state = Arc::clone(&state);
            move |request| proposer_duties_response(&state, request)
        },
    )
    .await;

    mount_json(server, "GET", r"^/eth/v2/beacon/blocks/[^/]+$", |_| {
        bellatrix_signed_block_response()
    })
    .await;

    mount_json(server, "POST", r"^/eth/v1/validator/duties/sync/[0-9]+$", {
        let state = Arc::clone(&state);
        move |request| sync_committee_duties_response(&state, request)
    })
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

/// Mounts a handler that returns a `ResponseTemplate` directly, used by
/// handlers that need to vary the HTTP status (e.g. 500 on spec lookup
/// failure, matching Charon's `SlotsPerEpochFunc` error propagation).
pub(crate) async fn mount_response<F>(
    server: &MockServer,
    http_method: &'static str,
    endpoint: &'static str,
    f: F,
) where
    F: Send + Sync + 'static + Fn(&Request) -> ResponseTemplate,
{
    let route = Mock::given(method(http_method));
    let route = if endpoint.starts_with('^') {
        route.and(path_regex(endpoint))
    } else {
        route.and(path(endpoint))
    };

    route
        .respond_with(move |request: &Request| f(request))
        .with_priority(DEFAULT_MOCK_PRIORITY)
        .mount(server)
        .await;
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

fn attester_duties_response(state: &MockState, request: &Request) -> ResponseTemplate {
    let Some(factor) = *read_lock(&state.deterministic_attester_duties) else {
        return ResponseTemplate::new(200).set_body_json(duties_response(Vec::new()));
    };

    let epoch = epoch_from_path(request.url.path());
    let mut indices = indices_from_body(request);
    indices.sort_unstable();

    let validator_set = read_lock(&state.validator_set).clone();
    let slots_per_epoch = match slots_per_epoch(state) {
        Ok(value) => value,
        Err(message) => return error_response(500, message),
    };
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

    ResponseTemplate::new(200).set_body_json(duties_response(data))
}

fn proposer_duties_response(state: &MockState, request: &Request) -> ResponseTemplate {
    let Some(factor) = *read_lock(&state.deterministic_proposer_duties) else {
        return ResponseTemplate::new(200).set_body_json(duties_response(Vec::new()));
    };

    let epoch = epoch_from_path(request.url.path());
    let slots_per_epoch = match slots_per_epoch(state) {
        Ok(value) => value,
        Err(message) => return error_response(500, message),
    };
    // Mirrors Charon's `WithDeterministicProposerDuties`, which iterates over
    // `mock.ActiveValidators(ctx)` — only validators with an Active* status
    // are eligible to propose.
    let validators: Vec<_> = read_lock(&state.validator_set)
        .validators()
        .into_iter()
        .filter(|validator| validator.status.is_active())
        .collect();
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

    ResponseTemplate::new(200).set_body_json(duties_response(data))
}

fn bellatrix_signed_block_response() -> Value {
    use crate::random::{random_eth2_signature, random_root, random_slot, random_v_idx};

    let zero_sig = format!("0x{}", "00".repeat(96));
    let zero_bytes32 = format!("0x{}", "00".repeat(32));
    let zero_bytes20 = format!("0x{}", "00".repeat(20));
    let zero_logs_bloom = format!("0x{}", "00".repeat(256));
    let sync_committee_bits = format!("0x{}", "00".repeat(64));

    let body = json!({
        "randao_reveal": random_eth2_signature(),
        "eth1_data": {
            "deposit_root": random_root(),
            "deposit_count": "0",
            "block_hash": zero_bytes32,
        },
        "graffiti": zero_bytes32,
        "proposer_slashings": [],
        "attester_slashings": [],
        "attestations": [],
        "deposits": [],
        "voluntary_exits": [],
        "sync_aggregate": {
            "sync_committee_bits": sync_committee_bits,
            "sync_committee_signature": zero_sig,
        },
        "execution_payload": {
            "parent_hash": zero_bytes32,
            "fee_recipient": zero_bytes20,
            "state_root": zero_bytes32,
            "receipts_root": zero_bytes32,
            "logs_bloom": zero_logs_bloom,
            "prev_randao": zero_bytes32,
            "block_number": "0",
            "gas_limit": "0",
            "gas_used": "0",
            "timestamp": "0",
            "extra_data": "0x",
            "base_fee_per_gas": "0",
            "block_hash": zero_bytes32,
            "transactions": [],
        }
    });

    json!({
        "version": "bellatrix",
        "data": {
            "message": {
                "slot": random_slot().to_string(),
                "proposer_index": random_v_idx().to_string(),
                "parent_root": random_root(),
                "state_root": random_root(),
                "body": body,
            },
            "signature": random_eth2_signature(),
        }
    })
}

fn duties_response(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "dependent_root": ZERO_ROOT,
        "execution_optimistic": false
    })
}

fn sync_committee_duties_response(state: &MockState, request: &Request) -> Value {
    let Some((n, k)) = *read_lock(&state.deterministic_sync_comm_duties) else {
        return sync_duties_response(Vec::new());
    };

    let epoch = epoch_from_path(request.url.path());
    let Some(remainder) = epoch.checked_rem(k) else {
        return sync_duties_response(Vec::new());
    };
    if remainder >= n {
        return sync_duties_response(Vec::new());
    }

    let indices = indices_from_body(request);
    let validator_set = read_lock(&state.validator_set).clone();

    let data = indices
        .into_iter()
        .enumerate()
        .filter_map(|(position, index)| {
            let validator = validator_set.by_index(index)?;
            Some(json!({
                "pubkey": validator.validator.pubkey,
                "validator_index": index.to_string(),
                "validator_sync_committee_indices": [position.to_string()],
            }))
        })
        .collect();

    sync_duties_response(data)
}

fn sync_duties_response(data: Vec<Value>) -> Value {
    json!({
        "data": data,
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
    last_path_segment_u64(path)
}

/// Reads `SLOTS_PER_EPOCH` from the spec, mirroring Charon's
/// `SlotsPerEpochFunc` (testutil/beaconmock/options.go) which surfaces an
/// error when the key is missing or not a positive integer instead of
/// silently defaulting.
pub(crate) fn slots_per_epoch(state: &MockState) -> Result<u64, &'static str> {
    read_lock(&state.spec)
        .get("SLOTS_PER_EPOCH")
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
        .filter(|slots| *slots > 0)
        .ok_or("failed to lookup or invalid SLOTS_PER_EPOCH from spec")
}

pub(crate) fn error_response(status: u16, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(json!({
        "code": status,
        "message": message,
    }))
}

/// Embedded beacon-node snapshot used as the baseline for default responses.
///
/// Generated by `scripts/gen_static_beaconmock.sh` against a Holesky beacon
/// node. Validated at compile time by `build.rs`.
pub(crate) const STATIC_JSON: &str = include_str!("static.json");

fn static_endpoint_data(endpoint: &str) -> serde_json::Map<String, Value> {
    let snapshot: Value =
        serde_json::from_str(STATIC_JSON).expect("static.json validated by build.rs");
    snapshot
        .get(endpoint)
        .and_then(|entry| entry.get("data"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

pub(crate) fn default_spec() -> Value {
    // Start from the Holesky snapshot baseline (~80 mainnet keys) and overlay
    // the Charon-simnet overrides used by tests.
    let mut spec = static_endpoint_data("/eth/v1/config/spec");

    let overrides: &[(&str, &str)] = &[
        ("CONFIG_NAME", "charon-simnet"),
        ("SLOTS_PER_EPOCH", "16"),
        ("SECONDS_PER_SLOT", "12"),
        ("GENESIS_FORK_VERSION", DEFAULT_GENESIS_FORK_VERSION),
        ("ALTAIR_FORK_VERSION", "0x20000910"),
        ("ALTAIR_FORK_EPOCH", "0"),
        ("BELLATRIX_FORK_VERSION", "0x30000910"),
        ("BELLATRIX_FORK_EPOCH", "0"),
        ("CAPELLA_FORK_VERSION", "0x40000910"),
        ("CAPELLA_FORK_EPOCH", "0"),
        ("DENEB_FORK_VERSION", "0x50000910"),
        ("DENEB_FORK_EPOCH", "0"),
        ("ELECTRA_FORK_VERSION", "0x60000910"),
        ("ELECTRA_FORK_EPOCH", "2048"),
        ("FULU_FORK_VERSION", "0x70000910"),
        ("DOMAIN_BEACON_PROPOSER", "0x00000000"),
        ("DOMAIN_BEACON_ATTESTER", "0x01000000"),
        ("DOMAIN_RANDAO", "0x02000000"),
        ("DOMAIN_DEPOSIT", "0x03000000"),
        ("DOMAIN_VOLUNTARY_EXIT", "0x04000000"),
        ("DOMAIN_SELECTION_PROOF", "0x05000000"),
        ("DOMAIN_AGGREGATE_AND_PROOF", "0x06000000"),
        ("DOMAIN_SYNC_COMMITTEE", "0x07000000"),
        ("DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF", "0x08000000"),
        ("DOMAIN_CONTRIBUTION_AND_PROOF", "0x09000000"),
        ("DOMAIN_APPLICATION_BUILDER", "0x00000001"),
        ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "256"),
    ];
    for (key, value) in overrides {
        spec.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    spec.insert(
        "MIN_GENESIS_TIME".to_string(),
        Value::String(default_genesis_time().timestamp().to_string()),
    );
    spec.insert(
        "FULU_FORK_EPOCH".to_string(),
        Value::String(u64::MAX.to_string()),
    );

    Value::Object(spec)
}

pub(crate) fn default_genesis() -> Value {
    json!({
        "genesis_time": default_genesis_time().timestamp().to_string(),
        "genesis_validators_root": DEFAULT_GENESIS_VALIDATORS_ROOT,
        "genesis_fork_version": DEFAULT_GENESIS_FORK_VERSION,
    })
}

pub(crate) fn default_genesis_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2022, 3, 1, 0, 0, 0)
        .single()
        .expect("2022-03-01T00:00:00Z is an unambiguous UTC instant")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beaconmock::BeaconMock;

    #[test]
    fn default_spec_contains_load_bearing_keys() {
        let spec = default_spec();
        for key in [
            "MAX_VALIDATORS_PER_COMMITTEE",
            "EPOCHS_PER_HISTORICAL_VECTOR",
            "MIN_PER_EPOCH_CHURN_LIMIT",
            "MAX_EFFECTIVE_BALANCE",
            "MAX_EFFECTIVE_BALANCE_ELECTRA",
            "DEPOSIT_CHAIN_ID",
            "PRESET_BASE",
            "MAX_COMMITTEES_PER_SLOT",
        ] {
            assert!(
                spec.get(key).is_some(),
                "default_spec is missing load-bearing key {key}"
            );
        }
    }

    #[tokio::test]
    async fn bellatrix_signed_block_endpoint_returns_versioned_block() {
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("build beacon mock");

        let base = mock.uri();
        let http = reqwest::Client::new();

        // The `block_id` segment is opaque to the mock; "head" exercises the
        // path_regex match.
        let resp = http
            .get(format!("{base}/eth/v2/beacon/blocks/head"))
            .send()
            .await
            .expect("blocks request");
        assert_eq!(resp.status(), 200, "blocks endpoint should succeed");

        let body: Value = resp.json().await.expect("blocks json");
        assert_eq!(
            body.get("version").and_then(Value::as_str),
            Some("bellatrix"),
            "version field should be bellatrix"
        );
        assert!(
            body.get("data").and_then(Value::as_object).is_some(),
            "data field should be a JSON object"
        );

        // Same endpoint should also match a numeric block_id.
        let resp = http
            .get(format!("{base}/eth/v2/beacon/blocks/123"))
            .send()
            .await
            .expect("blocks request (numeric)");
        assert_eq!(resp.status(), 200);
    }
}
