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
    core/                  # Core domain logic
    crypto/                # Cryptographic primitives and helpers
    dkg/                   # Distributed key generation logic
    eth2api/               # Beacon-node API client types/helpers
    eth2util/              # Ethereum consensus utility code
    k1util/                # Secp256k1 utilities
    p2p/                   # P2P networking (libp2p)
    peerinfo/              # Peer info utilities
    relay-server/          # Relay server implementation
    test-compose/          # Docker-compose smoke-test harness (test infrastructure, not shipped)
    testutil/              # Test helpers/fixtures (workspace-internal)
    tracing/               # Observability/tracing utilities
  test-infra/              # Docker-compose and local infra for integration testing/observability
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

### Error types

A `thiserror` type with an unnamed `#[from]` field carries `#[pluto_stacktrace::located]` as its outermost attribute, so the raise location and a stack trace are captured on conversion.

- The field's type becomes `pluto_stacktrace::LocatedError<T>`: build it with `.into()` and match through it with `**`.
- `Display` is the plain `thiserror` message; the location and the trace are reachable only through `Debug`.
- The attribute rejects a type with no unnamed `#[from]` field.
- Write the conversion as `?`, a closure (`.map_err(|e| e.into())`), or an explicit `.into()`; passing `Into::into` or `Type::from` as a function value captures the location of a `core` shim.
- `error!` renders an error with `?err` where it is dropped and with `%err` where it is propagated, so a trace is printed once.

## Tooling / Quality Gates

Environment:

- Recommended dev setup: `nix develop` (see `pluto/CONTRIBUTING.md`).
- Rust toolchain is pinned in `pluto/rust-toolchain.toml`.

Commands (run from `pluto/`):

```bash
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --features pluto-eth2api/integration
# Smoke tests are opt-in (--features smoke); see crates/test-compose/README.md.
cargo deny check --hide-inclusion-graph
```