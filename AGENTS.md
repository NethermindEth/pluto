# AGENTS.md — Pluto (Rust) Porting & Review Guide

## Scope

Pluto is an alternative implementation of [Charon](https://github.com/ObolNetwork/charon/), a distributed validator middleware client for Ethereum Staking. It enables a group of independent operators to safely run a single validator by coordinating duties across multiple nodes.

Pluto, like Charon, is used by stakers to distribute the responsibility of running Ethereum Validators across a number of different instances and client implementations.

## Project Structure

Workspace layout (high level):

```text
pluto/
  Cargo.toml               # Workspace members, shared deps, lints
  crates/                  # Workspace crates (Rust source lives here)
    app/                   # Application crate
    build-proto/           # Protobuf/build-time code generation
    cli/                   # `pluto` CLI binary and command wiring
    cluster/               # Cluster types and helpers
    consensus/             # QBFT consensus protocol implementation
    core/                  # Core domain logic
    crypto/                # Cryptographic primitives and helpers
    dkg/                   # Distributed key generation logic
    eth1wrap/              # Execution-layer (eth1) client wrapper
    eth2api/               # Beacon-node API client types/helpers
    eth2util/              # Ethereum consensus utility code
    featureset/            # Feature flag management
    frost/                 # FROST threshold signature implementation
    infosync/              # Peer info synchronisation protocol
    k1util/                # Secp256k1 utilities
    p2p/                   # P2P networking (libp2p)
    parsigex/              # Partial-signature exchange protocol
    peerinfo/              # Peer info utilities
    priority/              # Priority queue / duty prioritisation
    relay-server/          # Relay server implementation
    ssz/                   # SSZ serialisation helpers
    testutil/              # Test helpers/fixtures (workspace-internal)
    tracing/               # Observability/tracing utilities
  scripts/                 # Helper shell scripts (cluster comparison, DKG runner, etc.)
  test-infra/              # Docker-compose and local infra for integration testing/observability
  third_party/             # Vendored third-party code (e.g. patched libp2p multistream-select)
  deny.toml                # `cargo deny` policy
  rust-toolchain.toml      # Rust toolchain pin
  rustfmt.toml             # Formatting rules
  clippy.toml              # Clippy configuration
```

## Golden Rules

- NEVER IMPLEMENT WITHOUT AN APPROVED PLAN
- ALWAYS READ THE GO SOURCE — NEVER GUESS BEHAVIOR
- ASK QUESTION IF UNDERSPECIFY

- Default to **functional equivalence** with the Go implementation.

## Tooling / Quality Gates

Environment:

- Recommended dev setup: `nix develop` (see `pluto/CONTRIBUTING.md`).
- Rust toolchain is pinned in `pluto/rust-toolchain.toml`.

Commands (run from `pluto/`):

```bash
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check --hide-inclusion-graph
```