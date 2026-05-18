//! Builder option helpers (mount handlers + tests).
//!
//! Wiring lives in [`super`]; this module only owns the mock-mount helpers
//! used by those options and the unit tests that exercise them.

use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use super::defaults::ZERO_ROOT;

/// Priority for builder-driven overrides. Lower numeric priority wins in
/// `wiremock`, so this sits above [`super::defaults::DEFAULT_MOCK_PRIORITY`]
/// (255) and below any test-supplied overrides mounted directly via
/// [`BeaconMock::server`](super::BeaconMock::server).
pub(crate) const OVERRIDE_PRIORITY: u8 = 50;

/// Mounts a static JSON override for `endpoint` returning `value`.
///
/// `endpoint` may be either a plain path or a regex prefixed with `^`.
pub(crate) async fn mount_endpoint_override(server: &MockServer, endpoint: String, value: Value) {
    // Both GET and POST share the route since callers may override either.
    for http_method in ["GET", "POST"] {
        let template = ResponseTemplate::new(200).set_body_json(value.clone());

        let route = Mock::given(method(http_method));
        let route = if endpoint.starts_with('^') {
            route.and(path_regex(endpoint.clone()))
        } else {
            route.and(path(endpoint.clone()))
        };

        route
            .respond_with(template)
            .with_priority(OVERRIDE_PRIORITY)
            .mount(server)
            .await;
    }
}

fn empty_duties_body() -> Value {
    json!({
        "data": [],
        "dependent_root": ZERO_ROOT,
        "execution_optimistic": false,
    })
}

fn empty_sync_duties_body() -> Value {
    json!({
        "data": [],
        "execution_optimistic": false,
    })
}

/// Mounts an empty-list override for the proposer duties endpoint.
pub(crate) async fn mount_no_proposer_duties(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/eth/v1/validator/duties/proposer/[0-9]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_duties_body()))
        .with_priority(OVERRIDE_PRIORITY)
        .mount(server)
        .await;
}

/// Mounts an empty-list override for the attester duties endpoint.
pub(crate) async fn mount_no_attester_duties(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/attester/[0-9]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_duties_body()))
        .with_priority(OVERRIDE_PRIORITY)
        .mount(server)
        .await;
}

/// Mounts an empty-list override for the sync-committee duties endpoint.
pub(crate) async fn mount_no_sync_committee_duties(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex(r"^/eth/v1/validator/duties/sync/[0-9]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_sync_duties_body()))
        .with_priority(OVERRIDE_PRIORITY)
        .mount(server)
        .await;
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::beaconmock::{BeaconMock, ValidatorSet};

    async fn get_json(uri: &str, path: &str) -> Value {
        let url = format!("{uri}{path}");
        reqwest::get(&url)
            .await
            .expect("request")
            .json::<Value>()
            .await
            .expect("decode json")
    }

    async fn post_json(uri: &str, path: &str, body: &Value) -> Value {
        let url = format!("{uri}{path}");
        reqwest::Client::new()
            .post(&url)
            .json(body)
            .send()
            .await
            .expect("request")
            .json::<Value>()
            .await
            .expect("decode json")
    }

    #[tokio::test]
    async fn endpoint_override_returns_custom_value() {
        let override_body = json!({ "data": "custom" });
        let mock = BeaconMock::builder()
            .endpoint_overrides(vec![(
                "/eth/v1/node/version".to_string(),
                override_body.clone(),
            )])
            .build()
            .await
            .expect("build mock");

        let got = get_json(&mock.uri(), "/eth/v1/node/version").await;
        assert_eq!(got, override_body);
    }

    #[tokio::test]
    async fn endpoint_override_supports_multiple_entries() {
        let a = json!({ "data": { "id": "a" } });
        let b = json!({ "data": { "id": "b" } });
        let mock = BeaconMock::builder()
            .endpoint_overrides(vec![
                ("/eth/v1/node/version".to_string(), a.clone()),
                ("/eth/v1/beacon/headers/head".to_string(), b.clone()),
            ])
            .build()
            .await
            .expect("build mock");

        assert_eq!(get_json(&mock.uri(), "/eth/v1/node/version").await, a);
        assert_eq!(
            get_json(&mock.uri(), "/eth/v1/beacon/headers/head").await,
            b
        );
    }

    #[tokio::test]
    async fn fork_version_overrides_spec_and_genesis() {
        let mock = BeaconMock::builder()
            .fork_version([0xaa, 0xbb, 0xcc, 0xdd])
            .build()
            .await
            .expect("build mock");

        let spec = get_json(&mock.uri(), "/eth/v1/config/spec").await;
        let genesis = get_json(&mock.uri(), "/eth/v1/beacon/genesis").await;

        assert_eq!(
            spec["data"]["GENESIS_FORK_VERSION"].as_str(),
            Some("0xaabbccdd"),
        );
        assert_eq!(
            genesis["data"]["genesis_fork_version"].as_str(),
            Some("0xaabbccdd"),
        );
    }

    #[tokio::test]
    async fn sync_committee_size_overrides_spec() {
        let mock = BeaconMock::builder()
            .sync_committee_size(32)
            .build()
            .await
            .expect("build mock");

        let spec = get_json(&mock.uri(), "/eth/v1/config/spec").await;
        assert_eq!(spec["data"]["SYNC_COMMITTEE_SIZE"].as_str(), Some("32"));
    }

    #[tokio::test]
    async fn sync_committee_subnet_count_overrides_spec() {
        let mock = BeaconMock::builder()
            .sync_committee_subnet_count(8)
            .build()
            .await
            .expect("build mock");

        let spec = get_json(&mock.uri(), "/eth/v1/config/spec").await;
        assert_eq!(
            spec["data"]["SYNC_COMMITTEE_SUBNET_COUNT"].as_str(),
            Some("8"),
        );
    }

    #[tokio::test]
    async fn no_proposer_duties_returns_empty_list() {
        // Set deterministic proposer duties first, then assert no_proposer_duties
        // wins.
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_proposer_duties(1)
            .no_proposer_duties(true)
            .build()
            .await
            .expect("build mock");

        let body = get_json(&mock.uri(), "/eth/v1/validator/duties/proposer/3").await;
        assert!(body["data"].as_array().unwrap().is_empty());
        assert_eq!(body["dependent_root"].as_str(), Some(super::ZERO_ROOT));
        assert_eq!(body["execution_optimistic"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn no_attester_duties_returns_empty_list() {
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_attester_duties(1)
            .no_attester_duties(true)
            .build()
            .await
            .expect("build mock");

        let body = post_json(
            &mock.uri(),
            "/eth/v1/validator/duties/attester/0",
            &json!(["1", "2"]),
        )
        .await;
        assert!(body["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_sync_committee_duties_returns_empty_list() {
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_sync_comm_duties((4, 8))
            .no_sync_committee_duties(true)
            .build()
            .await
            .expect("build mock");

        let body = post_json(
            &mock.uri(),
            "/eth/v1/validator/duties/sync/0",
            &json!(["1", "2"]),
        )
        .await;
        assert!(body["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deterministic_sync_comm_duties_within_window() {
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_sync_comm_duties((2, 8))
            .build()
            .await
            .expect("build mock");

        // epoch=0, 0%8=0 <2 → duties returned for the requested indices.
        let body = post_json(
            &mock.uri(),
            "/eth/v1/validator/duties/sync/0",
            &json!(["1", "2"]),
        )
        .await;
        let data = body["data"].as_array().expect("data array");
        assert_eq!(data.len(), 2);
        assert_eq!(data[0]["validator_index"].as_str(), Some("1"));
        assert_eq!(
            data[0]["validator_sync_committee_indices"]
                .as_array()
                .unwrap(),
            &vec![json!("0")],
        );
        assert_eq!(data[1]["validator_index"].as_str(), Some("2"));
        assert_eq!(
            data[1]["validator_sync_committee_indices"]
                .as_array()
                .unwrap(),
            &vec![json!("1")],
        );

        // Spec EPOCHS_PER_SYNC_COMMITTEE_PERIOD reflects n=2.
        let spec = get_json(&mock.uri(), "/eth/v1/config/spec").await;
        assert_eq!(
            spec["data"]["EPOCHS_PER_SYNC_COMMITTEE_PERIOD"].as_str(),
            Some("2"),
        );
    }

    #[tokio::test]
    async fn deterministic_sync_comm_duties_outside_window() {
        let mock = BeaconMock::builder()
            .validator_set(ValidatorSet::validator_set_a())
            .deterministic_sync_comm_duties((2, 8))
            .build()
            .await
            .expect("build mock");

        // epoch=2, 2%8=2 >=2 → no duties.
        let body = post_json(
            &mock.uri(),
            "/eth/v1/validator/duties/sync/2",
            &json!(["1", "2"]),
        )
        .await;
        assert!(body["data"].as_array().unwrap().is_empty());
    }
}
