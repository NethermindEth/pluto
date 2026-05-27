//! Optional fuzz handlers that override default beacon endpoints with random
//! JSON responses.
//!
//! Mirrors `WithBeaconMockFuzzer` from Charon's Go beaconmock
//! (`testutil/beaconmock/beaconmock_fuzz.go`). Pluto's mock is HTTP-only, so
//! instead of swapping out function dispatch fields we mount higher-priority
//! wiremock routes that produce randomly-generated, schema-shaped JSON for the
//! same set of endpoints consumed by Charon during fuzz testing.
//!
//! Mounted routes use a numerically lower priority than `mount_defaults` so
//! they take precedence when both are registered on the same `MockServer`.

use rand::{Rng, seq::SliceRandom};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use super::state::last_path_segment_u64;
use crate::random::{
    random_bit_list, random_eth2_signature, random_phase0_attestation, random_root,
};

/// Priority for fuzzer routes; must be numerically lower (= higher priority)
/// than `defaults::DEFAULT_MOCK_PRIORITY` so it overrides default mounts.
const FUZZ_MOCK_PRIORITY: u8 = 10;

/// Mounts random-response handlers for the endpoints fuzzed in the Go
/// `WithBeaconMockFuzzer` option.
///
/// The mounted handlers return JSON-shaped responses with random values. Tests
/// should not rely on any specific field values.
pub(super) async fn mount_fuzzer(server: &MockServer) {
    mount_fuzz_json(
        server,
        "GET",
        "/eth/v2/validator/aggregate_attestation",
        |_| aggregate_attestation_response(),
    )
    .await;

    mount_fuzz_json(server, "GET", "/eth/v1/validator/attestation_data", |_| {
        attestation_data_response()
    })
    .await;

    // Both v2 and v3 endpoints for block production exist in Charon's flows.
    mount_fuzz_json(
        server,
        "GET",
        r"^/eth/v2/validator/blocks/[0-9]+$",
        |request| proposal_response(slot_from_path(request.url.path())),
    )
    .await;

    mount_fuzz_json(
        server,
        "GET",
        r"^/eth/v3/validator/blocks/[0-9]+$",
        |request| proposal_response(slot_from_path(request.url.path())),
    )
    .await;

    mount_fuzz_json(server, "GET", r"^/eth/v2/beacon/blocks/.+$", |_| {
        signed_beacon_block_response()
    })
    .await;

    mount_fuzz_json(
        server,
        "GET",
        "/eth/v1/beacon/states/head/validators",
        |_| validators_response(),
    )
    .await;

    mount_fuzz_json(
        server,
        "POST",
        r"^/eth/v1/validator/duties/attester/[0-9]+$",
        |request| attester_duties_response(epoch_from_path(request.url.path())),
    )
    .await;

    mount_fuzz_json(
        server,
        "GET",
        r"^/eth/v1/validator/duties/proposer/[0-9]+$",
        |request| proposer_duties_response(epoch_from_path(request.url.path())),
    )
    .await;

    mount_fuzz_json(
        server,
        "POST",
        r"^/eth/v1/validator/duties/sync/[0-9]+$",
        |request| sync_committee_duties_response(epoch_from_path(request.url.path())),
    )
    .await;
}

async fn mount_fuzz_json<F>(
    server: &MockServer,
    http_method: &'static str,
    endpoint: &'static str,
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
        .respond_with(move |request: &Request| ResponseTemplate::new(200).set_body_json(f(request)))
        .with_priority(FUZZ_MOCK_PRIORITY)
        .mount(server)
        .await;
}

fn aggregate_attestation_response() -> Value {
    json!({
        "version": "deneb",
        "data": random_phase0_attestation(),
    })
}

fn attestation_data_response() -> Value {
    let mut rng = rand::thread_rng();
    json!({
        "data": {
            "slot": rng.r#gen::<u64>().to_string(),
            "index": rng.r#gen::<u64>().to_string(),
            "beacon_block_root": random_root(),
            "source": random_checkpoint(),
            "target": random_checkpoint(),
        }
    })
}

fn proposal_response(slot: u64) -> Value {
    json!({
        "version": "deneb",
        "execution_payload_blinded": false,
        "execution_payload_value": "0",
        "consensus_block_value": "0",
        "data": {
            "block": random_beacon_block(slot),
            "kzg_proofs": [],
            "blobs": [],
        }
    })
}

fn signed_beacon_block_response() -> Value {
    let mut rng = rand::thread_rng();
    let slot = rng.r#gen::<u64>();
    json!({
        "version": "deneb",
        "execution_optimistic": false,
        "finalized": false,
        "data": {
            "message": random_beacon_block(slot),
            "signature": random_eth2_signature(),
        }
    })
}

fn validators_response() -> Value {
    let mut rng = rand::thread_rng();
    let count = rng.gen_range(0..=4u64);
    let data: Vec<Value> = (0..count)
        .map(|index| {
            json!({
                "index": index.to_string(),
                "balance": rng.r#gen::<u64>().to_string(),
                "status": random_validator_status(&mut rng),
                "validator": {
                    "pubkey": format!("0x{}", hex::encode([rng.r#gen::<u8>(); 48])),
                    "withdrawal_credentials": random_root(),
                    "effective_balance": rng.r#gen::<u64>().to_string(),
                    "slashed": rng.r#gen::<bool>(),
                    "activation_eligibility_epoch": rng.r#gen::<u64>().to_string(),
                    "activation_epoch": rng.r#gen::<u64>().to_string(),
                    "exit_epoch": rng.r#gen::<u64>().to_string(),
                    "withdrawable_epoch": rng.r#gen::<u64>().to_string(),
                }
            })
        })
        .collect();

    json!({
        "data": data,
        "execution_optimistic": false,
        "finalized": false,
    })
}

fn attester_duties_response(epoch: u64) -> Value {
    let mut rng = rand::thread_rng();
    let slots_per_epoch = 16u64;
    let count = rng.gen_range(0..=4u64);
    let data: Vec<Value> = (0..count)
        .map(|i| {
            let slot_offset = rng.gen_range(0..slots_per_epoch);
            let slot = epoch
                .saturating_mul(slots_per_epoch)
                .saturating_add(slot_offset);
            json!({
                "pubkey": format!("0x{}", hex::encode([rng.r#gen::<u8>(); 48])),
                "validator_index": i.to_string(),
                "committee_index": rng.r#gen::<u64>().to_string(),
                "committee_length": rng.r#gen::<u64>().to_string(),
                "committees_at_slot": slots_per_epoch.to_string(),
                "validator_committee_index": rng.r#gen::<u64>().to_string(),
                "slot": slot.to_string(),
            })
        })
        .collect();

    json!({
        "data": data,
        "dependent_root": random_root(),
        "execution_optimistic": false,
    })
}

fn proposer_duties_response(epoch: u64) -> Value {
    let mut rng = rand::thread_rng();
    let slots_per_epoch = 16u64;
    let count = rng.gen_range(0..=4u64);
    let data: Vec<Value> = (0..count)
        .map(|i| {
            let slot_offset = rng.gen_range(0..slots_per_epoch);
            let slot = epoch
                .saturating_mul(slots_per_epoch)
                .saturating_add(slot_offset);
            json!({
                "pubkey": format!("0x{}", hex::encode([rng.r#gen::<u8>(); 48])),
                "validator_index": i.to_string(),
                "slot": slot.to_string(),
            })
        })
        .collect();

    json!({
        "data": data,
        "dependent_root": random_root(),
        "execution_optimistic": false,
    })
}

fn sync_committee_duties_response(_epoch: u64) -> Value {
    let mut rng = rand::thread_rng();
    let count = rng.gen_range(0..=4u64);
    let data: Vec<Value> = (0..count)
        .map(|i| {
            let subnet_count = rng.gen_range(0..=4u64);
            let subnets: Vec<String> = (0..subnet_count).map(|s| s.to_string()).collect();
            json!({
                "pubkey": format!("0x{}", hex::encode([rng.r#gen::<u8>(); 48])),
                "validator_index": i.to_string(),
                "validator_sync_committee_indices": subnets,
            })
        })
        .collect();

    json!({
        "data": data,
        "execution_optimistic": false,
    })
}

fn random_checkpoint() -> Value {
    let mut rng = rand::thread_rng();
    json!({
        "epoch": rng.r#gen::<u64>().to_string(),
        "root": random_root(),
    })
}

fn random_validator_status(rng: &mut impl Rng) -> &'static str {
    const STATUSES: &[&str] = &[
        "pending_initialized",
        "pending_queued",
        "active_ongoing",
        "active_exiting",
        "active_slashed",
        "exited_unslashed",
        "exited_slashed",
        "withdrawal_possible",
        "withdrawal_done",
    ];
    STATUSES
        .choose(rng)
        .copied()
        .expect("STATUSES is a non-empty constant slice")
}

fn random_beacon_block(slot: u64) -> Value {
    let mut rng = rand::thread_rng();
    json!({
        "slot": slot.to_string(),
        "proposer_index": rng.r#gen::<u64>().to_string(),
        "parent_root": random_root(),
        "state_root": random_root(),
        "body": random_beacon_block_body(),
    })
}

fn random_beacon_block_body() -> Value {
    json!({
        "randao_reveal": random_eth2_signature(),
        "eth1_data": {
            "deposit_root": random_root(),
            "deposit_count": rand::thread_rng().r#gen::<u64>().to_string(),
            "block_hash": random_root(),
        },
        "graffiti": random_root(),
        "proposer_slashings": [],
        "attester_slashings": [],
        "attestations": [random_phase0_attestation()],
        "deposits": [],
        "voluntary_exits": [],
        "sync_aggregate": {
            "sync_committee_bits": random_bit_list(0),
            "sync_committee_signature": random_eth2_signature(),
        },
        "execution_payload": {
            "parent_hash": random_root(),
            "fee_recipient": format!("0x{}", hex::encode([0u8; 20])),
            "state_root": random_root(),
            "receipts_root": random_root(),
            "logs_bloom": format!("0x{}", hex::encode([0u8; 256])),
            "prev_randao": random_root(),
            "block_number": "0",
            "gas_limit": "0",
            "gas_used": "0",
            "timestamp": "0",
            "extra_data": "0x",
            "base_fee_per_gas": "0",
            "block_hash": random_root(),
            "transactions": [],
            "withdrawals": [],
            "blob_gas_used": "0",
            "excess_blob_gas": "0",
        },
        "bls_to_execution_changes": [],
        "blob_kzg_commitments": [],
    })
}

fn slot_from_path(path: &str) -> u64 {
    last_path_segment_u64(path)
}

fn epoch_from_path(path: &str) -> u64 {
    last_path_segment_u64(path)
}

#[cfg(test)]
mod tests {
    use crate::beaconmock::BeaconMock;
    use reqwest::{Client, Method, StatusCode};
    use serde_json::Value;

    struct Endpoint {
        method: Method,
        path: &'static str,
        body: Option<&'static str>,
    }

    #[tokio::test]
    async fn fuzzer_returns_random_json_for_each_endpoint() {
        let mock = BeaconMock::builder()
            .fuzzer(true)
            .build()
            .await
            .expect("build beacon mock");

        let base = mock.uri();
        let http = Client::new();

        let endpoints = [
            Endpoint {
                method: Method::GET,
                path: "/eth/v2/validator/aggregate_attestation?slot=1&attestation_data_root=0x0000000000000000000000000000000000000000000000000000000000000000",
                body: None,
            },
            Endpoint {
                method: Method::GET,
                path: "/eth/v1/validator/attestation_data?slot=1&committee_index=0",
                body: None,
            },
            Endpoint {
                method: Method::GET,
                path: "/eth/v2/validator/blocks/123",
                body: None,
            },
            Endpoint {
                method: Method::GET,
                path: "/eth/v3/validator/blocks/123",
                body: None,
            },
            Endpoint {
                method: Method::GET,
                path: "/eth/v2/beacon/blocks/head",
                body: None,
            },
            Endpoint {
                method: Method::GET,
                path: "/eth/v1/beacon/states/head/validators",
                body: None,
            },
            Endpoint {
                method: Method::POST,
                path: "/eth/v1/validator/duties/attester/7",
                body: Some(r#"["0","1"]"#),
            },
            Endpoint {
                method: Method::GET,
                path: "/eth/v1/validator/duties/proposer/7",
                body: None,
            },
            Endpoint {
                method: Method::POST,
                path: "/eth/v1/validator/duties/sync/7",
                body: Some(r#"["0","1"]"#),
            },
        ];

        for endpoint in endpoints {
            let url = format!("{base}{}", endpoint.path);
            let mut req = http.request(endpoint.method.clone(), &url);
            if let Some(body) = endpoint.body {
                req = req
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body);
            }

            let resp = req
                .send()
                .await
                .unwrap_or_else(|err| panic!("request to {url} failed: {err}"));

            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "fuzzed endpoint {url} should return 200",
            );

            // Response must be JSON-parseable.
            let body: Value = resp
                .json()
                .await
                .unwrap_or_else(|err| panic!("response from {url} not JSON: {err}"));
            assert!(
                body.get("data").is_some(),
                "fuzzed endpoint {url} should return a `data` field; got {body}",
            );
        }
    }
}
