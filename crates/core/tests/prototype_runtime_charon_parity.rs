//! PROTOTYPE (not yet runnable): mixed Pluto + Charon runtime interoperability.
//!
//! Forward specifications, all `#[ignore]`d so they never run in CI. These
//! prove real interoperability: a cluster of mixed Charon and Pluto nodes
//! executing live validator duties together, not just exchanging static files.
//!
//! ## The blocker
//!
//! No `pluto run` command / assembled duty runtime (see
//! `prototype_duty_runtime.rs`). Static-artifact Charon parity is already
//! covered — Charon-created locks parse and verify in Pluto
//! (`crates/cluster/src/lock.rs`, V1.0-V1.10 fixtures) and a mixed 2 Charon +
//! 2 Pluto DKG ceremony runs in CI (`.github/workflows/dkg-runner.yml`). What
//! cannot be reproduced is a mixed cluster running the *runtime*: agreeing on
//! duty data over QBFT, exchanging partials over ParSigEx, and aggregating —
//! across both implementations.
//!
//! ## Target scenarios (once `pluto run` exists)
//!
//! Wire-level parity of QBFT (`/charon/consensus/...`) and ParSigEx
//! (`/charon/parsigex/2.0.0`) must let Charon and Pluto nodes participate in
//! the same consensus game and partial-signature exchange, then all agree on
//! the duty hash and produce a valid aggregated signature.

/// Mixed runtime, 3 Charon + 1 Pluto: duties pass and all nodes agree on the
/// duty hash (minimum real interoperability).
#[test]
#[ignore = "blocked on `pluto run`: no runtime for a mixed cluster to execute duties"]
fn prototype_test_mixed_runtime_three_charon_one_pluto() {
    unimplemented!("specification only — needs `pluto run` + QBFT/ParSigEx wire parity");
}

/// Mixed runtime, 2 Charon + 2 Pluto: attestation and proposer duties pass
/// (stronger parity).
#[test]
#[ignore = "blocked on `pluto run`: no runtime for a mixed cluster to execute duties"]
fn prototype_test_mixed_runtime_two_charon_two_pluto() {
    unimplemented!("specification only — needs `pluto run` + QBFT/ParSigEx wire parity");
}
