//! Build script: validate `beaconmock/static.json` at compile time.
//!
//! Catches regressions in the embedded beacon-node snapshot (malformed JSON,
//! missing endpoints, missing spec keys) before the test crate runs, and
//! triggers a rebuild whenever the snapshot changes.

use std::path::Path;

const STATIC_JSON: &str = "src/beaconmock/static.json";

/// Endpoints that must be present in `static.json`. Mirrors `gen_static.sh`.
const REQUIRED_ENDPOINTS: &[&str] = &[
    "/eth/v1/beacon/genesis",
    "/eth/v1/config/deposit_contract",
    "/eth/v1/config/fork_schedule",
    "/eth/v1/node/version",
    "/eth/v1/config/spec",
    "/eth/v2/beacon/blocks/0",
];

/// Spec keys the mock relies on. Real beacon clients read more, but these are
/// the minimum the Rust port references directly.
const REQUIRED_SPEC_KEYS: &[&str] = &[
    "SLOTS_PER_EPOCH",
    "SECONDS_PER_SLOT",
    "GENESIS_FORK_VERSION",
    "ALTAIR_FORK_EPOCH",
    "BELLATRIX_FORK_EPOCH",
    "CAPELLA_FORK_EPOCH",
    "DENEB_FORK_EPOCH",
    "ELECTRA_FORK_EPOCH",
    "MAX_VALIDATORS_PER_COMMITTEE",
    "TARGET_AGGREGATORS_PER_COMMITTEE",
    "SYNC_COMMITTEE_SIZE",
    "EPOCHS_PER_SYNC_COMMITTEE_PERIOD",
];

fn main() {
    let path = Path::new(STATIC_JSON);
    println!("cargo:rerun-if-changed={}", path.display());

    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));

    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("{} is not valid JSON: {err}", path.display()));

    let endpoints = parsed
        .as_object()
        .unwrap_or_else(|| panic!("{} top-level value must be a JSON object", path.display()));

    for required in REQUIRED_ENDPOINTS {
        let entry = endpoints
            .get(*required)
            .unwrap_or_else(|| panic!("{} missing required endpoint {required}", path.display()));
        // Each entry is either a beacon-node response body (with `data`) or an
        // error envelope (`code` + `message`, e.g. 404 for blocks/0).
        if entry.get("data").is_none() && entry.get("code").is_none() {
            panic!(
                "{} endpoint {required} must contain either `data` or an error envelope",
                path.display()
            );
        }
    }

    let spec = endpoints
        .get("/eth/v1/config/spec")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .unwrap_or_else(|| {
            panic!(
                "{} `/eth/v1/config/spec` -> `data` must be a JSON object",
                path.display()
            )
        });

    for key in REQUIRED_SPEC_KEYS {
        if !spec.contains_key(*key) {
            panic!("{} spec is missing required key {key}", path.display());
        }
    }
}
