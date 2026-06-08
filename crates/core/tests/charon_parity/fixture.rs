//! Serde types for the Charon-parity fixture-replay harness.
//!
//! See `crates/core/testdata/charon-parity/README.md` for the wire
//! format and porting status semantics.

use serde::Deserialize;

/// One fixture: a single `(handler, scenario)` test case.
#[derive(Debug, Clone, Deserialize)]
pub struct Fixture {
    /// Stable identifier of the scenario, e.g. `"node_version_basic"`.
    pub name: String,

    /// Which [`Handler`](pluto_core::validatorapi::handler::Handler) method
    /// to drive. Tag for the [`Request`] dispatch enum.
    pub endpoint: Endpoint,

    /// Porting state of this handler. Drives whether a successful call,
    /// a panic, or a divergence is treated as pass or fail.
    pub status: Status,

    /// Citation: Charon source file:line for the Go reference.
    /// Surfaced in fixture-author tooling; the harness itself doesn't
    /// read it, but the field is required so fixtures stay self-documenting.
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "documentation field; read by tooling, not by the harness"
    )]
    pub go_source: Option<String>,

    /// Citation: Charon test file:case for the expected-behaviour anchor.
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "documentation field; read by tooling, not by the harness"
    )]
    pub go_test: Option<String>,

    /// State seeded into the `Component` before the dispatch runs.
    #[serde(default)]
    pub setup: Setup,

    /// Inbound request payload routed to the handler.
    pub request: Request,

    /// Expected response. Omitted when [`Status::Unimplemented`].
    #[serde(default)]
    pub expected: Option<Expected>,

    /// Free-form notes that survive into the failure output.
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "documentation field; surfaced manually on diff inspection"
    )]
    pub notes: Option<String>,
}

/// Which Handler trait method this fixture drives. The variant name
/// maps 1:1 to the trait method name.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    NodeVersion,
    ProposerDuties,
    AttesterDuties,
    SyncCommitteeDuties,
    AttestationData,
    SubmitAttestations,
    Proposal,
    SubmitProposal,
    SubmitBlindedProposal,
    AggregateAttestation,
    SubmitAggregateAttestations,
    BeaconCommitteeSelections,
    SyncCommitteeSelections,
    Validators,
    SubmitValidatorRegistrations,
    SubmitVoluntaryExit,
    SyncCommitteeContribution,
    SubmitSyncCommitteeContributions,
    SubmitSyncCommitteeMessages,
}

impl Endpoint {
    /// Returns the snake-case method name. Used in failure messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodeVersion => "node_version",
            Self::ProposerDuties => "proposer_duties",
            Self::AttesterDuties => "attester_duties",
            Self::SyncCommitteeDuties => "sync_committee_duties",
            Self::AttestationData => "attestation_data",
            Self::SubmitAttestations => "submit_attestations",
            Self::Proposal => "proposal",
            Self::SubmitProposal => "submit_proposal",
            Self::SubmitBlindedProposal => "submit_blinded_proposal",
            Self::AggregateAttestation => "aggregate_attestation",
            Self::SubmitAggregateAttestations => "submit_aggregate_attestations",
            Self::BeaconCommitteeSelections => "beacon_committee_selections",
            Self::SyncCommitteeSelections => "sync_committee_selections",
            Self::Validators => "validators",
            Self::SubmitValidatorRegistrations => "submit_validator_registrations",
            Self::SubmitVoluntaryExit => "submit_voluntary_exit",
            Self::SyncCommitteeContribution => "sync_committee_contribution",
            Self::SubmitSyncCommitteeContributions => "submit_sync_committee_contributions",
            Self::SubmitSyncCommitteeMessages => "submit_sync_committee_messages",
        }
    }
}

/// Porting state of the handler under test.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Handler is wired. Expect [`Expected`] to match the returned value
    /// exactly.
    Implemented,
    /// Handler is still an `unimplemented!()` stub. Expect a panic whose
    /// payload mentions "not yet" (the Pluto convention). Any other
    /// outcome — Ok return or a different panic — is a hard failure that
    /// signals the fixture needs graduation to [`Self::Implemented`].
    Unimplemented,
    /// Handler is wired but currently diverges from Charon in a known
    /// way. Logged in the summary; does not fail the run. Use sparingly,
    /// always with a `notes` field explaining the divergence.
    Partial,
}

/// State seeded into the `Component` before the handler runs.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Setup {
    /// Configures the upstream beacon mock. When unset, the mock is
    /// built with `BeaconMock::builder().build()` defaults (Charon's
    /// Charon-compatible spec).
    #[serde(default)]
    pub beacon_mock: BeaconMockSetup,

    /// Threshold BLS share index assigned to the simulated node. Default
    /// is `1`.
    #[serde(default = "default_share_idx")]
    pub share_idx: u64,

    /// Whether builder mode is enabled on the Component. Default `false`.
    #[serde(default)]
    pub builder_enabled: bool,
}

fn default_share_idx() -> u64 {
    1
}

/// BeaconMock configuration knobs. Only the most common knobs are
/// exposed in the fixture wire format; grow this as fixtures need more.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BeaconMockSetup {
    /// Seeds the mock to serve deterministic proposer duties for the
    /// builtin `validator_set_a`. The value is the `factor` Charon's
    /// `WithDeterministicProposerDuties` takes.
    #[serde(default)]
    pub deterministic_proposer_duties: Option<u64>,

    /// Seeds deterministic attester duties for `validator_set_a`. See
    /// `pluto_testutil::beaconmock::BeaconMock`.
    #[serde(default)]
    pub deterministic_attester_duties: Option<u64>,

    /// When set, registers the builtin `validator_set_a` so endpoints
    /// that introspect the active set (proposer duties, attester duties)
    /// have something to return.
    #[serde(default)]
    pub use_validator_set_a: bool,
}

/// Tags the Handler method to dispatch. V1 of the harness always uses
/// a hardcoded stub value for the handler's input (see the `stub_*`
/// helpers in `harness.rs`), so any per-endpoint payload fields in the
/// fixture JSON (`opts`, `proposal`, `attestations`, …) are accepted
/// for documentation but ignored at runtime. A V2 follow-up can grow
/// this struct into typed variants once the placeholder types in
/// `validatorapi::types` derive `Deserialize`.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub kind: Endpoint,
}

impl Request {
    /// The endpoint tag this request targets. Used to cross-check the
    /// fixture's `endpoint` field against the request `kind`.
    pub fn endpoint(&self) -> Endpoint {
        self.kind
    }
}

/// Expected outcome of the handler call. Used only when
/// [`Status::Implemented`].
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expected {
    /// Handler is expected to return `Ok(payload)`. The harness
    /// serialises the actual response and deep-compares against `body`.
    Ok { body: serde_json::Value },
    /// Handler is expected to return `Err(ApiError)`. Compares
    /// `status_code` and the `{code, message}` envelope; source-chain
    /// strings are intentionally ignored to keep fixtures portable
    /// across Rust toolchain versions.
    Err {
        status_code: u16,
        #[serde(default)]
        message: Option<String>,
    },
}
