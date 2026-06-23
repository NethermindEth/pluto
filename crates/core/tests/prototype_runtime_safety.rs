//! PROTOTYPE (not yet runnable): runtime safety / anti-slashing guarantees.
//!
//! Forward specifications, all `#[ignore]`d so they never run in CI. These are
//! the safety properties a distributed validator exists to provide; none can be
//! exercised yet.
//!
//! ## The blocker(s)
//!
//! - No `pluto run` command / assembled duty runtime (see
//!   `prototype_duty_runtime.rs`). Without scheduler → consensus → VC sign →
//!   parsig → aggregate → broadcast, none of these scenarios can be reproduced.
//! - No **slashing-protection database**. There is no persistent record of what
//!   a validator has already signed anywhere in the tree (the `*_slashings`
//!   symbols in `crates/core/src/{signeddata,dutydb}` are block-body fields,
//!   not slashing protection). The surround/double-vote-across-restart case
//!   additionally needs this DB to be built.
//! - `privkeylock` itself exists (`crates/app/src/privkeylock.rs`); only the
//!   run-level enforcement test is missing.
//!
//! ## Why consensus alone is not enough
//!
//! Threshold aggregation is only safe if every node signs the *same* data.
//! Consensus over the `UnsignedDataSet` plus `DutyDB` persistence plus slashing
//! protection together prevent a malicious beacon node or a compromised VC from
//! inducing a double vote / double proposal. Each test below pins one such
//! guarantee.

/// A malicious beacon node serves conflicting attestation data to different
/// nodes; the cluster must sign one root or nothing — never two.
#[test]
#[ignore = "blocked on `pluto run`: no consensus-backed duty pipeline to defend"]
fn prototype_test_malicious_bn_conflicting_attestation_data() {
    unimplemented!("specification only — needs the assembled duty runtime + consensus");
}

/// A malicious beacon node attempts to induce a double block proposal; at most
/// one block signature must be produced/broadcast per validator/slot.
#[test]
#[ignore = "blocked on `pluto run`: no proposer pipeline to defend"]
fn prototype_test_malicious_bn_double_proposal_is_prevented() {
    unimplemented!("specification only — needs the assembled duty runtime");
}

/// A compromised validator client submits a partial that does not match the
/// consensus-decided duty; it must be rejected, never exchanged or aggregated.
#[test]
#[ignore = "blocked on `pluto run`: no consensus/DutyDB cross-check on submitted partials"]
fn prototype_test_compromised_vc_submission_is_rejected() {
    unimplemented!("specification only — needs the assembled duty runtime + DutyDB cross-check");
}

/// Network partition 2/2: with no majority, neither side may sign or broadcast
/// (safety over liveness).
#[test]
#[ignore = "blocked on `pluto run`: no runtime to partition"]
fn prototype_test_network_partition_2_2_signs_nothing() {
    unimplemented!("specification only — needs the assembled duty runtime");
}

/// Network partition 3/1: the majority side continues; the isolated minority
/// cannot reach threshold and must not sign.
#[test]
#[ignore = "blocked on `pluto run`: no runtime to partition"]
fn prototype_test_network_partition_3_1_majority_continues_minority_safe() {
    unimplemented!("specification only — needs the assembled duty runtime");
}

/// A surround/double vote attempted across a restart must be blocked by
/// persistent slashing history.
#[test]
#[ignore = "blocked on `pluto run` AND a slashing-protection DB (neither exists)"]
fn prototype_test_surround_vote_blocked_across_restart() {
    unimplemented!("specification only — needs the duty runtime and a persistent slashing DB");
}

/// A second runtime started on the same validator keys must not be able to
/// start/sign (`privkeylock` enforcement at the run level).
#[test]
#[ignore = "blocked on `pluto run`: privkeylock primitive exists, run-level enforcement does not"]
fn prototype_test_privkeylock_blocks_second_runtime() {
    unimplemented!("specification only — needs `pluto run` to enforce privkeylock at startup");
}
