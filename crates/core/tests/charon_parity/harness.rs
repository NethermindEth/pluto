//! Driver for the Charon-parity fixture-replay harness.
//!
//! - [`load_all`] walks the testdata directory and parses every `*.json`
//!   fixture.
//! - [`build_component`] wires a [`Component`] from a fixture's [`Setup`] block
//!   — a `BeaconMock` plus a never-expiring [`MemDB`].
//! - [`dispatch`] routes a fixture's [`Request`] to the matching `Handler`
//!   method. For [`Status::Unimplemented`] fixtures with complex payload types
//!   it substitutes a hardcoded stub value, so the fixture JSON can stay
//!   minimal — the stub handler panics before reading the value anyway. For
//!   [`Status::Implemented`] / [`Status::Partial`] the JSON is parsed strictly.
//! - [`compare_ok`] / [`compare_err`] deep-diff actual vs expected.
//! - [`is_unimplemented_panic`] inspects a caught panic payload and confirms it
//!   came from an `unimplemented!()` macro.
//! - [`ParitySummary`] tallies how many fixtures passed / are still pending /
//!   are flagged partial.

use std::{collections::HashMap, fmt, fs, path::Path, sync::Arc};

use chrono::{DateTime, Utc};
use futures::FutureExt;
use pluto_core::{
    deadline::{DeadlineCalculator, DeadlinerTask, Result as DeadlineResult},
    dutydb::MemDB,
    types::Duty,
    validatorapi::{
        component::Component,
        error::ApiError,
        handler::Handler,
        types::{
            AggregateAttestationOpts, AttestationDataOpts, AttesterDutiesOpts, ProposalOpts,
            ProposerDutiesOpts, SignedVoluntaryExit, SyncCommitteeContributionOpts,
            SyncCommitteeDutiesOpts, ValidatorsOpts, VersionedSignedBlindedProposal,
            VersionedSignedProposal,
        },
    },
};
use pluto_eth2api::{EthBeaconNodeApiClient, spec::phase0::BLSPubKey};
use pluto_testutil::{BeaconMock, ValidatorSet};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::fixture::{Endpoint, Expected, Fixture, Request, Setup, Status};

/// Recursively loads every `*.json` fixture under `root`.
pub fn load_all(root: &Path) -> Vec<(std::path::PathBuf, Fixture)> {
    let mut out = vec![];
    walk(root, &mut out);
    out.sort_by(|(a, _), (b, _)| a.cmp(b));
    out
}

fn walk(dir: &Path, out: &mut Vec<(std::path::PathBuf, Fixture)>) {
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(err) => panic!("read_dir {}: {err}", dir.display()),
    };
    for entry in read {
        let entry = entry.expect("readdir entry");
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let fixture: Fixture = serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
        if fixture.endpoint != fixture.request.endpoint() {
            panic!(
                "{}: endpoint `{}` does not match request kind `{}`",
                path.display(),
                fixture.endpoint.as_str(),
                fixture.request.endpoint().as_str(),
            );
        }
        if fixture.status == Status::Implemented && fixture.expected.is_none() {
            panic!(
                "{}: status=implemented requires an `expected` block",
                path.display()
            );
        }
        out.push((path, fixture));
    }
}

/// Schedules every duty with `MAX_UTC`, so duties stay `Scheduled` but
/// never naturally expire. Mirrors the `FarFutureCalculator` used in
/// `validatorapi::component` tests; copied locally because it is not
/// pub-exported.
struct FarFutureCalculator;

impl DeadlineCalculator for FarFutureCalculator {
    fn deadline(&self, _: &Duty) -> DeadlineResult<Option<DateTime<Utc>>> {
        Ok(Some(DateTime::<Utc>::MAX_UTC))
    }
}

/// Wires a `Component` from the fixture's `Setup`. The held `_mock`
/// and `_cancel` keep the upstream mock server + deadliner background
/// task alive for the full dispatch; they are dropped at the end of
/// `evaluate`.
pub struct BuiltComponent {
    pub component: Component,
    pub _mock: BeaconMock,
    pub _cancel: CancellationToken,
}

pub async fn build_component(setup: &Setup) -> BuiltComponent {
    let mock = build_mock(setup).await;
    let cancel = CancellationToken::new();
    let (deadliner, _deadliner_rx) =
        DeadlinerTask::start(cancel.clone(), "charon-parity", FarFutureCalculator);
    let (_evict_tx, evict_rx) = mpsc::channel(1);
    let dutydb = Arc::new(MemDB::new(deadliner, evict_rx, &cancel));
    let eth2_cl = Arc::new(
        EthBeaconNodeApiClient::with_base_url(mock.uri())
            .expect("build EthBeaconNodeApiClient from mock URI"),
    );

    // V1 leaves `pub_share_by_pubkey` empty because none of the
    // currently-implemented handlers on `main` invoke partial-signature
    // verification. Submit handlers will need to populate this once they
    // graduate from `unimplemented!()`.
    let pub_share_by_pubkey: HashMap<BLSPubKey, BLSPubKey> = HashMap::new();

    let component = Component::new(
        eth2_cl,
        dutydb,
        setup.share_idx,
        pub_share_by_pubkey,
        setup.builder_enabled,
    );

    BuiltComponent {
        component,
        _mock: mock,
        _cancel: cancel,
    }
}

async fn build_mock(setup: &Setup) -> BeaconMock {
    let m = &setup.beacon_mock;
    // `bon`'s typestate setters can each be called at most once, so
    // route every conditional through the `maybe_*` variant which takes
    // `Option<T>` and is a no-op when the option is `None`.
    BeaconMock::builder()
        .maybe_validator_set(m.use_validator_set_a.then(ValidatorSet::validator_set_a))
        .maybe_deterministic_proposer_duties(m.deterministic_proposer_duties)
        .maybe_deterministic_attester_duties(m.deterministic_attester_duties)
        .build()
        .await
        .expect("build beacon mock")
}

/// Either a JSON-serialised success body or a structured error summary.
#[derive(Debug)]
pub enum Outcome {
    Ok(serde_json::Value),
    Err { status_code: u16, message: String },
}

/// Routes a fixture to the matching Handler trait method. V1 builds
/// every input value from a hardcoded stub helper — the fixture's
/// `request` field only tags the endpoint. Implemented handlers
/// (`node_version`, `proposer_duties`, …) see fixed inputs;
/// unimplemented handlers panic before reading anything. A V2
/// follow-up can move to per-fixture parameterised inputs once the
/// placeholder types in `validatorapi::types` derive `Deserialize`.
///
/// Any panic (including `unimplemented!()`) propagates out — the
/// caller catches it with `FutureExt::catch_unwind`.
pub async fn dispatch(component: &Component, request: &Request, _status: Status) -> Outcome {
    match request.kind {
        Endpoint::NodeVersion => unwrap_eth(component.node_version().await, |r| {
            serde_json::to_value(&r).expect("serialize NodeVersionResponse")
        }),
        Endpoint::ProposerDuties => unwrap_eth(
            component.proposer_duties(stub_proposer_duties_opts()).await,
            |r| serde_json::to_value(&r).expect("serialize ProposerDutiesResponse"),
        ),
        Endpoint::AttesterDuties => unwrap_eth(
            component.attester_duties(stub_attester_duties_opts()).await,
            |r| serde_json::to_value(&r).expect("serialize AttesterDutiesResponse"),
        ),
        Endpoint::SyncCommitteeDuties => unwrap_eth(
            component
                .sync_committee_duties(stub_sync_committee_duties_opts())
                .await,
            |r| serde_json::to_value(&r).expect("serialize SyncCommitteeDutiesResponse"),
        ),
        Endpoint::AttestationData => unwrap_eth(
            component
                .attestation_data(stub_attestation_data_opts())
                .await,
            |r| serde_json::to_value(&r.data).expect("serialize AttestationData"),
        ),
        Endpoint::SubmitAttestations => unwrap_unit(component.submit_attestations(vec![]).await),
        Endpoint::Proposal => unwrap_eth(
            component.proposal(stub_proposal_opts()).await,
            // EthResponse<VersionedProposal> doesn't derive Serialize
            // on `main`; reconstruct the wire shape by hand. The
            // handler is a stub on main, so this path mostly exercises
            // the unimplemented-panic branch.
            |r| {
                serde_json::json!({
                    "execution_optimistic": r.execution_optimistic,
                    "finalized": r.finalized,
                    "dependent_root": r.dependent_root,
                })
            },
        ),
        Endpoint::SubmitProposal => {
            unwrap_unit(component.submit_proposal(stub_signed_proposal()).await)
        }
        Endpoint::SubmitBlindedProposal => unwrap_unit(
            component
                .submit_blinded_proposal(stub_signed_blinded_proposal())
                .await,
        ),
        Endpoint::AggregateAttestation => unwrap_eth(
            component
                .aggregate_attestation(stub_aggregate_attestation_opts())
                .await,
            |_| serde_json::Value::Null,
        ),
        Endpoint::SubmitAggregateAttestations => {
            unwrap_unit(component.submit_aggregate_attestations(vec![]).await)
        }
        Endpoint::BeaconCommitteeSelections => {
            unwrap_eth(component.beacon_committee_selections(vec![]).await, |_| {
                serde_json::Value::Null
            })
        }
        Endpoint::SyncCommitteeSelections => {
            unwrap_eth(component.sync_committee_selections(vec![]).await, |_| {
                serde_json::Value::Null
            })
        }
        Endpoint::Validators => {
            unwrap_eth(component.validators(stub_validators_opts()).await, |_| {
                serde_json::Value::Null
            })
        }
        Endpoint::SubmitValidatorRegistrations => {
            unwrap_unit(component.submit_validator_registrations(vec![]).await)
        }
        Endpoint::SubmitVoluntaryExit => {
            unwrap_unit(component.submit_voluntary_exit(stub_voluntary_exit()).await)
        }
        Endpoint::SyncCommitteeContribution => unwrap_eth(
            component
                .sync_committee_contribution(stub_sync_committee_contribution_opts())
                .await,
            |_| serde_json::Value::Null,
        ),
        Endpoint::SubmitSyncCommitteeContributions => {
            unwrap_unit(component.submit_sync_committee_contributions(vec![]).await)
        }
        Endpoint::SubmitSyncCommitteeMessages => {
            unwrap_unit(component.submit_sync_committee_messages(vec![]).await)
        }
    }
}

fn unwrap_eth<T>(
    result: Result<T, ApiError>,
    to_json: impl FnOnce(T) -> serde_json::Value,
) -> Outcome {
    match result {
        Ok(v) => Outcome::Ok(to_json(v)),
        Err(err) => api_error_to_outcome(err),
    }
}

fn unwrap_unit(result: Result<(), ApiError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Ok(serde_json::Value::Null),
        Err(err) => api_error_to_outcome(err),
    }
}

fn api_error_to_outcome(err: ApiError) -> Outcome {
    Outcome::Err {
        status_code: err.status_code.as_u16(),
        message: err.message.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Stub builders for the Unimplemented dispatch path.
//
// These return the bare-minimum value the handler's input type accepts.
// The matching handler is currently `unimplemented!()` and panics before
// reading the value, so contents are irrelevant — they just need to
// typecheck.
// ---------------------------------------------------------------------------

fn stub_proposer_duties_opts() -> ProposerDutiesOpts {
    ProposerDutiesOpts { epoch: 0 }
}

fn stub_attester_duties_opts() -> AttesterDutiesOpts {
    AttesterDutiesOpts {
        epoch: 0,
        indices: vec![],
    }
}

fn stub_sync_committee_duties_opts() -> SyncCommitteeDutiesOpts {
    SyncCommitteeDutiesOpts {
        epoch: 0,
        indices: vec![],
    }
}

fn stub_attestation_data_opts() -> AttestationDataOpts {
    AttestationDataOpts {
        slot: 0,
        committee_index: 0,
    }
}

fn stub_proposal_opts() -> ProposalOpts {
    ProposalOpts {
        slot: 0,
        randao_reveal: [0; 96],
        graffiti: [0; 32],
        builder_boost_factor: None,
    }
}

fn stub_aggregate_attestation_opts() -> AggregateAttestationOpts {
    AggregateAttestationOpts {
        slot: 0,
        attestation_data_root: [0; 32],
        committee_index: 0,
    }
}

fn stub_validators_opts() -> ValidatorsOpts {
    ValidatorsOpts {
        state: "head".to_string(),
        pubkeys: vec![],
        indices: vec![],
    }
}

fn stub_sync_committee_contribution_opts() -> SyncCommitteeContributionOpts {
    SyncCommitteeContributionOpts {
        slot: 0,
        subcommittee_index: 0,
        beacon_block_root: [0; 32],
    }
}

// `SignedVoluntaryExit`, `VersionedSignedProposal`, and
// `VersionedSignedBlindedProposal` are placeholder `{}` structs on
// `main`; PR #461 replaces them with `signeddata::*` / `versioned::*`
// re-exports. Construct via literal — when those re-exports land, this
// V1 harness will fail to compile and the porter will need to update
// the stubs to construct real values.
fn stub_voluntary_exit() -> SignedVoluntaryExit {
    SignedVoluntaryExit {}
}

fn stub_signed_proposal() -> VersionedSignedProposal {
    VersionedSignedProposal {}
}

fn stub_signed_blinded_proposal() -> VersionedSignedBlindedProposal {
    VersionedSignedBlindedProposal {}
}

/// Deep-diff `actual` against the expected fixture body. Returns
/// `Ok(())` on match, `Err(diff_string)` on mismatch.
pub fn compare_ok(actual: &serde_json::Value, expected: &serde_json::Value) -> Result<(), String> {
    if actual == expected {
        return Ok(());
    }
    let actual_pretty =
        serde_json::to_string_pretty(actual).expect("serialise actual JSON for diff");
    let expected_pretty =
        serde_json::to_string_pretty(expected).expect("serialise expected JSON for diff");
    Err(format!(
        "json mismatch:\n--- expected ---\n{expected_pretty}\n--- actual ---\n{actual_pretty}",
    ))
}

/// Returns `Ok(())` if the structured error matches the expected
/// status + (optional) message envelope.
pub fn compare_err(
    actual_status: u16,
    actual_message: &str,
    expected: &Expected,
) -> Result<(), String> {
    let Expected::Err {
        status_code,
        message,
    } = expected
    else {
        return Err(format!(
            "actual was Err({actual_status}, {actual_message:?}) but expected `ok` body"
        ));
    };
    if *status_code != actual_status {
        return Err(format!(
            "status_code mismatch: expected {status_code}, got {actual_status} (message: {actual_message:?})",
        ));
    }
    if let Some(expected_msg) = message
        && expected_msg != actual_message
    {
        return Err(format!(
            "message mismatch: expected {expected_msg:?}, got {actual_message:?}",
        ));
    }
    Ok(())
}

/// Inspects a caught panic payload to decide whether it came from an
/// `unimplemented!()` macro. The std macro formats with
/// `"not yet implemented: <msg>"`, and Pluto's stubs use messages like
/// `"submit_attestations not yet ported"` — either pattern counts.
pub fn is_unimplemented_panic(payload: &(dyn std::any::Any + Send)) -> Option<String> {
    let msg = payload
        .downcast_ref::<&'static str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())?;
    if msg.starts_with("not yet implemented")
        || msg.contains("not yet ported")
        || msg.contains("not yet stubbed")
    {
        Some(msg)
    } else {
        None
    }
}

/// Tally of fixture outcomes for the test's stdout summary.
#[derive(Debug, Default)]
pub struct ParitySummary {
    pub implemented_pass: usize,
    pub pending: usize,
    pub partial: usize,
    pub failures: Vec<String>,
}

impl ParitySummary {
    pub fn record_pass(&mut self) {
        self.implemented_pass = self.implemented_pass.saturating_add(1);
    }

    pub fn record_pending(&mut self) {
        self.pending = self.pending.saturating_add(1);
    }

    pub fn record_partial(&mut self) {
        self.partial = self.partial.saturating_add(1);
    }

    pub fn record_failure(&mut self, name: &str, detail: impl Into<String>) {
        self.failures.push(format!("[{name}] {}", detail.into()));
    }

    pub fn total(&self) -> usize {
        self.implemented_pass
            .saturating_add(self.pending)
            .saturating_add(self.partial)
            .saturating_add(self.failures.len())
    }
}

impl fmt::Display for ParitySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\nCharon-parity summary ({} fixtures):", self.total())?;
        writeln!(f, "  implemented passing: {}", self.implemented_pass)?;
        writeln!(f, "  pending (unimplemented stubs): {}", self.pending)?;
        writeln!(f, "  partial (known divergences): {}", self.partial)?;
        writeln!(f, "  failed: {}", self.failures.len())?;
        Ok(())
    }
}

/// Drives one fixture and folds the outcome into `summary`. Returns
/// `Err(detail)` mirroring the summary's failure list, so the caller
/// can surface per-fixture errors if it chooses to.
pub async fn evaluate(
    path: &Path,
    fixture: &Fixture,
    summary: &mut ParitySummary,
) -> Result<(), String> {
    let built = build_component(&fixture.setup).await;
    let status = fixture.status;
    let dispatch_future = async {
        let component = &built.component;
        dispatch(component, &fixture.request, status).await
    };
    let outcome = std::panic::AssertUnwindSafe(dispatch_future)
        .catch_unwind()
        .await;

    let result = match (fixture.status, outcome) {
        (Status::Implemented, Ok(Outcome::Ok(actual))) => {
            let expected = fixture
                .expected
                .as_ref()
                .expect("implemented status requires expected (checked at load)");
            match expected {
                Expected::Ok { body } => match compare_ok(&actual, body) {
                    Ok(()) => {
                        summary.record_pass();
                        Ok(())
                    }
                    Err(diff) => {
                        summary.record_failure(&fixture.name, diff.clone());
                        Err(diff)
                    }
                },
                Expected::Err { .. } => {
                    let diff = format!("expected Err response, got Ok: {actual}");
                    summary.record_failure(&fixture.name, diff.clone());
                    Err(diff)
                }
            }
        }
        (
            Status::Implemented,
            Ok(Outcome::Err {
                status_code,
                message,
            }),
        ) => {
            let expected = fixture
                .expected
                .as_ref()
                .expect("implemented status requires expected (checked at load)");
            match compare_err(status_code, &message, expected) {
                Ok(()) => {
                    summary.record_pass();
                    Ok(())
                }
                Err(diff) => {
                    summary.record_failure(&fixture.name, diff.clone());
                    Err(diff)
                }
            }
        }
        (Status::Implemented, Err(panic)) => {
            let detail = format_panic("unexpected panic in implemented handler", &*panic);
            summary.record_failure(&fixture.name, detail.clone());
            Err(detail)
        }
        (Status::Unimplemented, Ok(outcome)) => {
            let detail = format!(
                "graduation candidate: {} no longer panics — returned {outcome:?}. Promote fixture to status:implemented and fill in `expected`.",
                fixture.endpoint.as_str()
            );
            summary.record_failure(&fixture.name, detail.clone());
            Err(detail)
        }
        (Status::Unimplemented, Err(panic)) => match is_unimplemented_panic(&*panic) {
            Some(_) => {
                summary.record_pending();
                Ok(())
            }
            None => {
                let detail = format_panic("non-unimplemented panic in stub", &*panic);
                summary.record_failure(&fixture.name, detail.clone());
                Err(detail)
            }
        },
        (Status::Partial, _) => {
            summary.record_partial();
            Ok(())
        }
    };

    result.map_err(|err| format!("{} ({})\n{}", fixture.name, path.display(), err))
}

fn format_panic(prefix: &str, payload: &(dyn std::any::Any + Send)) -> String {
    let msg = payload
        .downcast_ref::<&'static str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic payload>".to_string());
    format!("{prefix}: {msg}")
}
