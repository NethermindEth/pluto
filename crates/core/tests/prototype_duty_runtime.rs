//! PROTOTYPE (not yet runnable): validator duty execution over the full
//! runtime pipeline.
//!
//! Forward specifications, all `#[ignore]`d so they never run in CI. They pin
//! the most important runtime proofs and the single blocker.
//!
//! ## The blocker
//!
//! There is no `pluto run` command (`crates/cli/src/cli.rs` exposes only `Enr`,
//! `Create`, `Version`, `Relay`, `Dkg`, `Alpha`). The duty pipeline cannot be
//! assembled or exercised until it exists.
//!
//! ## What already exists (the building blocks)
//!
//! - `DutyDB` (`crates/core/src/dutydb/memory.rs`)
//! - `ValidatorAPI` component (`crates/core/src/validatorapi/component.rs`) —
//!   but its submit handlers are dead-code, awaiting the runtime
//! - `ParSigEx` (`crates/parsigex/`), `ParSigDB`
//!   (`crates/core/src/parsigdb/memory.rs`), `SigAgg`
//!   (`crates/core/src/sigagg.rs`), `AggSigDB`
//!   (`crates/core/src/aggsigdb/memory.rs`)
//! - `Tracker` and `Deadliner` (`crates/core/src/{tracker,deadline}/`)
//! - QBFT state machine (`crates/core/src/qbft/`) and libp2p transport (#448)
//! - `BeaconMock` and `ValidatorMock` (`crates/testutil/src/{beaconmock,
//!   validatormock}/`) — the simnet doubles are ready
//!
//! ## What is missing (the gap)
//!
//! The runtime glue that wires the blocks into a pipeline: a **scheduler**
//! (duty poller), a **fetcher** (unsigned duty data), a **consensus runner**
//! (spawns `qbft::run()` over the transport), a **broadcaster** (submits
//! aggregated signatures), and the ValidatorAPI **submit handlers**. None of
//! these exist.
//!
//! ## Target pipeline (each test, once `pluto run` exists)
//!
//! scheduler → fetch unsigned duty → QBFT consensus over the `UnsignedDataSet`
//! → store in `DutyDB` → VC signs → ParSigEx exchange → ParSigDB threshold
//! match → SigAgg aggregate → broadcast to the beacon node.

/// Full attestation duty over the pipeline on a small simnet cluster:
/// scheduler → consensus → VC sign → parsig → aggregate → submit, asserting one
/// aggregated attestation is submitted per validator/slot.
#[test]
#[ignore = "blocked on `pluto run`: no scheduler/fetcher/consensus-runner/broadcaster pipeline"]
fn prototype_test_attestation_duty_full_pipeline() {
    unimplemented!("specification only — needs the assembled duty runtime (see module docs)");
}

/// Block proposal duty over the pipeline, asserting exactly one valid block is
/// produced and broadcast per validator/slot.
#[test]
#[ignore = "blocked on `pluto run`: no proposer pipeline / broadcaster"]
fn prototype_test_block_proposal_duty_produces_one_block() {
    unimplemented!("specification only — needs the assembled duty runtime (see module docs)");
}

/// Multi-slot simnet with `BeaconMock` + `ValidatorMock` and 3-4 nodes,
/// asserting attester and proposer duties pass across several slots (parity
/// with Charon's `TestSimnetDuties`).
#[test]
#[ignore = "blocked on `pluto run`: simnet doubles exist but nothing drives the pipeline"]
fn prototype_test_multi_slot_simnet_duties() {
    unimplemented!("specification only — needs the assembled duty runtime (see module docs)");
}
