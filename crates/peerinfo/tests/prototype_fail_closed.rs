//! PROTOTYPE (not yet runnable): fail-closed handling of incompatible peers.
//!
//! Forward specification, `#[ignore]`d so it never runs in CI.
//!
//! ## Context
//!
//! peerinfo version/lock-hash mismatch is **informational by design** (Charon
//! parity): the node flags the peer via the `version_support` gauge and logs,
//! but does not drop the connection. That implemented behaviour is already
//! covered by the real test
//! `crates/peerinfo/tests/peerinfo_version_mismatch.rs`
//! (`incompatible_version_peer_is_flagged_without_dropping_exchange`).
//!
//! ## What is missing (the gap)
//!
//! The actual fail-closed enforcement — refusing to admit a peer that is not a
//! member of the cluster — is not wired. `PlutoBehaviour` carries a
//! `ConnGater` (`crates/p2p/src/behaviours/pluto.rs`), but "by default an open
//! gater is used that allows all connections"; nothing constructs a gater that
//! denies peers whose ID is absent from the cluster lock, and no policy turns a
//! peerinfo incompatibility verdict into a disconnect. Wiring that policy is a
//! runtime concern (blocked on the assembled node / `pluto run`).
//!
//! ## Target scenario (to assert once enforcement exists)
//!
//! 1. Start a node configured with a cluster-membership gater.
//! 2. Have a peer whose ID is not in the cluster lock attempt to connect.
//! 3. Assert the connection is denied (gater rejects it) and the node keeps
//!    running — it never treats the stranger as a cluster peer, without
//!    crashing.

/// Forward spec for refusing a non-cluster / incompatible peer. Ignored and
/// intentionally unimplemented: needs a cluster-membership gater policy wired
/// into the runtime (see module docs).
#[test]
#[ignore = "blocked: no gater policy denies non-cluster peers; peerinfo mismatch is informational only"]
fn prototype_test_incompatible_peer_connection_is_refused() {
    unimplemented!(
        "specification only — implement once a cluster-membership ConnGater (or a peerinfo \
         verdict-to-disconnect policy) is wired into the runtime (see module docs)"
    );
}
