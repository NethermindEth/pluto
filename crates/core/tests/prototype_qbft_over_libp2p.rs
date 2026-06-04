//! PROTOTYPE (not yet runnable): QBFT consensus over a real libp2p network.
//!
//! This file is a forward specification, not a working test. It documents the
//! end-to-end QBFT scenario we want to prove and the single piece of production
//! code that is missing to make it real. The test is `#[ignore]`d so it never
//! runs in CI; it exists to pin the target and give the future test a home.
//!
//! ## What already exists
//!
//! - The QBFT state machine: `pluto_core::qbft::run()`
//!   (`crates/core/src/qbft/mod.rs:327`). Multi-node consensus reaching a
//!   single decided value — including degraded and adversarial cases — is
//!   already covered against an **in-memory** transport with a fake clock in
//!   `crates/core/src/qbft/internal_test.rs` (`happy`, `stagger_start`,
//!   `dropped_messages`, `fuzzed`, `chain_split`).
//! - The libp2p QBFT transport and sniffer landed in #448:
//!   `crates/core/src/consensus/qbft/transport.rs` and `.../sniffer.rs`. Both
//!   carry `#![allow(dead_code)]` with `TODO: Remove once the consensus runner
//!   wires this transport.`
//! - The per-instance plumbing: `pluto_core::consensus::instance::InstanceIo`
//!   (`maybe_start()`, `take_recv_rx()`, …) buffers inbound messages until a
//!   runner starts.
//!
//! ## What is missing (the only gap)
//!
//! A **consensus runner**: the glue that, for one duty/instance, adapts the
//! libp2p `consensus::qbft::transport` to the state machine's abstract
//! `qbft::Transport<T>`, drains `InstanceIo` once `maybe_start()` returns true,
//! and drives `qbft::run()` — pumping messages between the swarm and the state
//! machine. Nothing spawns `qbft::run()` over the network today, so this test
//! cannot be written yet. This is the highest-leverage runtime work available
//! before `pluto run`.
//!
//! ## Target scenario (to assert once the runner exists)
//!
//! 1. Start N (e.g. 4) Pluto nodes, each running the consensus runner over the
//!    libp2p transport, connected in a full mesh over loopback TCP.
//! 2. Feed each honest node the same proposed value for one instance.
//! 3. Assert every honest node decides, and they all decide the **same** value
//!    in the same instance — proving wire serialization + transport + runner
//!    interoperate, not just the in-memory state machine.
//!
//! Follow-on variants (own prototypes/commits later): one crashed node with the
//! remaining majority still deciding, and a Byzantine proposer that must never
//! cause two honest nodes to decide different values.

/// Forward spec for QBFT reaching a single decision across nodes over libp2p.
///
/// Ignored and intentionally not implemented: it requires a consensus runner
/// that wires `consensus::qbft::transport` + `consensus::instance::InstanceIo`
/// into `qbft::run()`. See the module docs above.
#[test]
#[ignore = "blocked: no consensus runner wires the libp2p QBFT transport into qbft::run()"]
fn prototype_test_qbft_reaches_single_decision_over_libp2p() {
    unimplemented!(
        "specification only — implement once a consensus runner drives qbft::run() over the \
         consensus::qbft libp2p transport (see module docs)"
    );
}
