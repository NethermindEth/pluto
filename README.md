# Pluto
[![Docs](https://github.com/NethermindEth/pluto/actions/workflows/docs.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/docs.yml)
[![Lint](https://github.com/NethermindEth/pluto/actions/workflows/linter.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/linter.yml)
[![Build](https://github.com/NethermindEth/pluto/actions/workflows/test.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/test.yml)
[![Dependencies](https://github.com/NethermindEth/pluto/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/dependency-audit.yml)
![Coverage](https://github.com/NethermindEth/pluto/wiki/coverage.svg)

![Rust](https://img.shields.io/badge/rust-1.95-orange.svg)
[![License](https://img.shields.io/badge/License-BUSL_1.1-blue.svg)](https://spdx.org/licenses/BUSL-1.1.html)

Pluto is an alternative implementation of [Charon](https://github.com/ObolNetwork/charon/), a distributed validator middleware client for Ethereum Staking. It enables a group of independent operators to safely run a single validator by coordinating duties across multiple nodes.

Pluto, like Charon, is used by stakers to distribute the responsibility of running Ethereum Validators across a number of different instances and client implementations.

See the official docs at https://docs.obol.org/ for introductions and key concepts.

## Documentation

The [Obol Docs](https://docs.obol.org/) website is the best place to get started.
The important sections are [intro](https://docs.obol.org/learn/charon),
[key concepts](https://docs.obol.org/docs/int/key-concepts) and [charon](https://docs.obol.org/docs/charon/intro).

## Version compatibility

Pluto tracks [Charon](https://github.com/ObolNetwork/charon/) parity: the workspace version reflects the Charon release that Pluto aims to be compatible with.

Following [semver](https://semver.org), two given versions of Pluto are:
 - **compatible** if their `MAJOR` number is the same, `MINOR` and `PATCH` numbers differ
 - **incompatible** if their `MAJOR` number differs

Reasons for a new `MAJOR` release include a new Ethereum hardfork, removal of an old hardfork, or breaking changes to the internal P2P network or consensus mechanism.

The `pluto dkg` subcommand is **more restrictive**: all peers must run matching `MAJOR` and `MINOR` versions for the DKG ceremony; patch versions may differ, though running the latest patch is recommended.

## Build / Run / Test

**Docker (pre-built image):**
```sh
docker pull nethermindeth/pluto:latest
docker run --rm nethermindeth/pluto:latest --help
```

**Build from source:**
```sh
cargo build --release --workspace
```

**Run tests:**
```sh
cargo test --workspace --all-features   # requires a running Docker daemon
```

**Local cluster with test-infra:**
```sh
cd test-infra
docker compose up
```

## Examples

Examples are located in crate-specific example folders:

- [Relay Server](crates/relay-server/examples/relay_server.rs)
- [Peerinfo](crates/peerinfo/examples/peerinfo.rs)
- [P2P](crates/p2p/examples/p2p.rs)
- [P2P Bootnode](crates/p2p/examples/bootnode.rs)
- [Quic Upgrade](crates/p2p/examples/quic_upgrade.rs)
- [Metrics](crates/p2p/examples/metrics.rs)
- [Tracing](crates/tracing/examples/basic.rs)
- [Consensus (QBFT)](crates/consensus/examples/qbft.rs)
- [DKG Broadcast](crates/dkg/examples/bcast.rs)
- [DKG Sync](crates/dkg/examples/sync.rs)
- [Parsigex](crates/parsigex/examples/parsigex.rs)

## License

Business Source License 1.1 — see [LICENSE](./LICENSE) for details.

## Would like to contribute?

See [Contributing](./CONTRIBUTING.md).
