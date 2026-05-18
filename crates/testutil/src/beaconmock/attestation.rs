//! Attestation data store and HTTP endpoints used by `BeaconMock`.
//!
//! Mirrors Charon's Go `attestationStore` (testutil/beaconmock/attestation.go):
//! generates deterministic `AttestationData` for a `(slot, committee_index)`
//! pair, keyed by the SSZ hash-tree-root of the generated data, and serves it
//! back through the `aggregate_attestation` endpoint when queried by root.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use pluto_eth2api::spec::phase0::{AttestationData, Checkpoint, Epoch, Root, Slot};
use serde_json::{Value, json};
use tree_hash::TreeHash;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

use super::{
    defaults::{error_response, slots_per_epoch},
    state::{MockState, hex_0x, read_lock, write_lock},
};

/// Priority used by attestation routes; lower than the default fallback so
/// these handlers override the static 400 mounted in `defaults.rs`.
const ATTESTATION_PRIORITY: u8 = 100;

/// Number of slots after which previously generated entries are pruned.
const PRUNE_AFTER_SLOTS: u64 = 32;

/// Tracks attestation data generated on demand and indexed by SSZ hash root.
///
/// Mirrors Charon's `attestationStore`.
#[derive(Debug, Default)]
pub(crate) struct AttestationStore {
    entries: RwLock<BTreeMap<Root, AttestationData>>,
}

impl AttestationStore {
    /// Generates a deterministic `AttestationData` for the requested
    /// `(slot, committee_index)`, stores it keyed by its SSZ hash-tree-root,
    /// and returns the data alongside the computed root.
    pub(crate) fn new_attestation_data(
        &self,
        slot: Slot,
        committee_index: u64,
        slots_per_epoch: u64,
    ) -> (AttestationData, Root) {
        let epoch = epoch_from_slot(slot, slots_per_epoch);
        let data = build_attestation_data(epoch, slot, committee_index);
        let root = data.tree_hash_root().0;
        self.set_data(data.clone(), root);
        (data, root)
    }

    /// Returns a previously generated `AttestationData` for `root`, if any.
    pub(crate) fn get_by_root(&self, root: &Root) -> Option<AttestationData> {
        read_lock(&self.entries).get(root).cloned()
    }

    fn set_data(&self, data: AttestationData, root: Root) {
        let mut entries = write_lock(&self.entries);
        // Drop entries older than `PRUNE_AFTER_SLOTS` relative to the new data.
        entries.retain(|_, old| old.slot.saturating_add(PRUNE_AFTER_SLOTS) >= data.slot);
        entries.insert(root, data);
    }
}

/// Computes the epoch for `slot` given `slots_per_epoch`, mirroring
/// `eth2util.EpochFromSlot` in Charon's Go code.
fn epoch_from_slot(slot: Slot, slots_per_epoch: u64) -> Epoch {
    slot.checked_div(slots_per_epoch).unwrap_or(0)
}

/// Returns the SSZ hash root of a slot number (little-endian u64, right padded
/// to 32 bytes), matching `eth2util.SlotHashRoot` in Charon's Go code.
fn slot_hash_root(num: u64) -> Root {
    num.tree_hash_root().0
}

fn build_attestation_data(epoch: Epoch, slot: Slot, committee_index: u64) -> AttestationData {
    // Match Go: at epoch 0, previous_epoch wraps to u64::MAX (see
    // charon/testutil/beaconmock/attestation.go `newAttestationData`).
    let previous_epoch = epoch.wrapping_sub(1);
    AttestationData {
        slot,
        index: committee_index,
        beacon_block_root: slot_hash_root(slot),
        source: Checkpoint {
            epoch: previous_epoch,
            root: slot_hash_root(previous_epoch),
        },
        target: Checkpoint {
            epoch,
            root: slot_hash_root(epoch),
        },
    }
}

/// Mounts the attestation-data and aggregate-attestation handlers on `server`.
///
/// These routes use a higher priority than `mount_defaults`, so a successful
/// lookup overrides the static 400 served by the default
/// `aggregate_attestation` route; unknown roots fall through to the default
/// 400 response.
pub(crate) async fn mount(server: &MockServer, state: Arc<MockState>) {
    mount_response_with_priority(
        server,
        "GET",
        "/eth/v1/validator/attestation_data",
        ATTESTATION_PRIORITY,
        {
            let state = Arc::clone(&state);
            move |request| attestation_data_response(&state, request)
        },
    )
    .await;

    Mock::given(method("GET"))
        .and(path("/eth/v2/validator/aggregate_attestation"))
        .and(query_param_present("attestation_data_root"))
        .respond_with({
            let state = Arc::clone(&state);
            move |request: &Request| aggregate_attestation_response(&state, request)
        })
        .with_priority(ATTESTATION_PRIORITY)
        .mount(server)
        .await;
}

fn attestation_data_response(state: &MockState, request: &Request) -> ResponseTemplate {
    let slot = query_value(request, "slot")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let committee_index = query_value(request, "committee_index")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);

    let slots_per_epoch = match slots_per_epoch(state) {
        Ok(value) => value,
        Err(message) => return error_response(500, message),
    };

    let (data, _root) =
        state
            .attestation_store
            .new_attestation_data(slot, committee_index, slots_per_epoch);

    ResponseTemplate::new(200).set_body_json(json!({ "data": attestation_data_json(&data) }))
}

fn aggregate_attestation_response(state: &MockState, request: &Request) -> ResponseTemplate {
    let root_param = query_value(request, "attestation_data_root").unwrap_or_default();
    let Some(root) = parse_root(&root_param) else {
        return ResponseTemplate::new(400).set_body_json(unknown_root_body());
    };

    let Some(data) = state.attestation_store.get_by_root(&root) else {
        return ResponseTemplate::new(400).set_body_json(unknown_root_body());
    };

    ResponseTemplate::new(200).set_body_json(aggregate_attestation_body(&data))
}

fn aggregate_attestation_body(data: &AttestationData) -> Value {
    // Charon's defaultMock returns a Fulu (Electra-shaped) attestation with a
    // single committee bit set, an empty aggregation bitlist and a zeroed
    // signature.
    let mut committee_bits = [0u8; 8];
    committee_bits[0] = 0x01;

    json!({
        "version": "fulu",
        "data": {
            "aggregation_bits": "0x01",
            "data": attestation_data_json(data),
            "signature": format!("0x{}", "00".repeat(96)),
            "committee_bits": hex_0x(committee_bits),
        }
    })
}

fn attestation_data_json(data: &AttestationData) -> Value {
    json!({
        "slot": data.slot.to_string(),
        "index": data.index.to_string(),
        "beacon_block_root": hex_0x(data.beacon_block_root),
        "source": {
            "epoch": data.source.epoch.to_string(),
            "root": hex_0x(data.source.root),
        },
        "target": {
            "epoch": data.target.epoch.to_string(),
            "root": hex_0x(data.target.root),
        }
    })
}

fn unknown_root_body() -> Value {
    json!({
        "code": 400,
        "message": "unknown aggregate attestation root"
    })
}

fn parse_root(value: &str) -> Option<Root> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(stripped).ok()?;
    bytes.try_into().ok()
}

fn query_value(request: &Request, key: &str) -> Option<String> {
    request
        .url
        .query_pairs()
        .find_map(|(k, v)| (k == key).then(|| v.into_owned()))
}

fn query_param_present(key: &'static str) -> impl wiremock::Match {
    QueryParamPresent { key }
}

struct QueryParamPresent {
    key: &'static str,
}

impl wiremock::Match for QueryParamPresent {
    fn matches(&self, request: &Request) -> bool {
        request.url.query_pairs().any(|(k, _)| k == self.key)
    }
}

async fn mount_response_with_priority<F>(
    server: &MockServer,
    http_method: &'static str,
    endpoint: &'static str,
    priority: u8,
    f: F,
) where
    F: Send + Sync + 'static + Fn(&Request) -> ResponseTemplate,
{
    Mock::given(method(http_method))
        .and(path(endpoint))
        .respond_with(move |request: &Request| f(request))
        .with_priority(priority)
        .mount(server)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beaconmock::BeaconMock;
    use pluto_eth2api::spec::phase0::AttestationData;

    #[tokio::test]
    async fn attestation_round_trip() {
        let mock = BeaconMock::builder()
            .build()
            .await
            .expect("build beacon mock");

        let base = mock.uri();
        let http = reqwest::Client::new();

        // 1. Fetch attestation data for slot=10, committee_index=2.
        let resp = http
            .get(format!(
                "{base}/eth/v1/validator/attestation_data?slot=10&committee_index=2"
            ))
            .send()
            .await
            .expect("attestation_data request");
        assert_eq!(resp.status(), 200, "attestation_data should succeed");
        let body: Value = resp.json().await.expect("attestation_data json");
        let data_json = body.get("data").expect("data field").clone();
        let data: AttestationData =
            serde_json::from_value(data_json).expect("deserialize attestation data");

        assert_eq!(data.slot, 10);
        assert_eq!(data.index, 2);

        // 2. Compute the SSZ HTR of the returned data.
        let root = data.tree_hash_root().0;
        let root_hex = format!("0x{}", hex::encode(root));

        // 3. Fetch aggregate_attestation for the matching root.
        let resp = http
            .get(format!(
                "{base}/eth/v2/validator/aggregate_attestation?slot=10&attestation_data_root={root_hex}"
            ))
            .send()
            .await
            .expect("aggregate_attestation request");
        assert_eq!(resp.status(), 200, "aggregate_attestation should match");
        let body: Value = resp.json().await.expect("aggregate_attestation json");
        assert_eq!(body.get("version").and_then(Value::as_str), Some("fulu"));
        let returned = body
            .get("data")
            .and_then(|d| d.get("data"))
            .cloned()
            .expect("nested data");
        let returned: AttestationData =
            serde_json::from_value(returned).expect("deserialize aggregated data");
        assert_eq!(returned, data, "returned data should match generated data");

        // 4. Unknown root falls through to 400.
        let zero_root = format!("0x{}", "00".repeat(32));
        let resp = http
            .get(format!(
                "{base}/eth/v2/validator/aggregate_attestation?slot=10&attestation_data_root={zero_root}"
            ))
            .send()
            .await
            .expect("aggregate_attestation unknown root request");
        assert_eq!(
            resp.status(),
            400,
            "aggregate_attestation should 400 on unknown root"
        );
    }

    #[test]
    fn slot_hash_root_matches_charon() {
        // Mirrors charon/eth2util/hash_test.go: SSZ hash of slot 2 is the
        // little-endian uint64 right-padded to 32 bytes.
        assert_eq!(
            hex::encode(slot_hash_root(2)),
            "0200000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn epoch_from_slot_handles_zero() {
        assert_eq!(epoch_from_slot(10, 0), 0);
        assert_eq!(epoch_from_slot(0, 16), 0);
        assert_eq!(epoch_from_slot(32, 16), 2);
    }

    #[test]
    fn store_prunes_old_entries() {
        let store = AttestationStore::default();
        let (_, root_old) = store.new_attestation_data(1, 0, 16);
        let (_, root_recent) = store.new_attestation_data(100, 0, 16);

        assert!(
            store.get_by_root(&root_old).is_none(),
            "entries older than 32 slots should be pruned"
        );
        assert!(store.get_by_root(&root_recent).is_some());
    }
}
