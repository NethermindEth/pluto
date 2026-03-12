# Pluto
[![Docs](https://github.com/NethermindEth/pluto/actions/workflows/docs.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/docs.yml)
[![Lint](https://github.com/NethermindEth/pluto/actions/workflows/linter.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/linter.yml)
[![Build](https://github.com/NethermindEth/pluto/actions/workflows/test.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/test.yml)
[![Dependencies](https://github.com/NethermindEth/pluto/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/NethermindEth/pluto/actions/workflows/dependency-audit.yml)
![Coverage](https://github.com/NethermindEth/pluto/wiki/coverage.svg)

![Rust](https://img.shields.io/badge/rust-1.89-orange.svg)
[![License](https://img.shields.io/badge/License-BUSL_1.1-blue.svg)](https://spdx.org/licenses/BUSL-1.1.html)

Pluto is an alternative implementation of [Charon](https://github.com/ObolNetwork/charon/), a distributed validator middleware client for Ethereum Staking. It enables a group of independent operators to safely run a single validator by coordinating duties across multiple nodes.

Pluto, like Charon, is used by stakers to distribute the responsibility of running Ethereum Validators across a number of different instances and client implementations.

See the official docs at https://docs.obol.org/ for introductions and key concepts.

## Documentation

The [Obol Docs](https://docs.obol.org/) website is the best place to get started.
The important sections are [intro](https://docs.obol.org/learn/charon),
[key concepts](https://docs.obol.org/docs/int/key-concepts) and [charon](https://docs.obol.org/docs/charon/intro).

## Version compatibility

Considering [semver](https://semver.org) as the project's versioning scheme, two given versions of Charon are:
 - **compatible** if their `MAJOR` number is the same, `MINOR` and `PATCH` numbers differ
 - **incompatible** if their `MAJOR` number differs

There are several reasons to justify a new `MAJOR` release, for example:
 - a new Ethereum hardfork
 - an old Ethereum hardfork is removed due to network inactivity
 - modifications to the internal P2P network or consensus mechanism requiring deep changes to the codebase

The `charon dkg` subcommand **is more restrictive** than this general compatibility promise; all peers should use matching `MAJOR` and `MINOR` versions of Charon for the DKG process, patch versions may differ though it is recommended to use the latest patch of any version.

## Examples

Examples are located in crate-specific example folders:

- [Relay Server](crates/relay-server/examples/relay_server.rs)
- [Peerinfo](crates/peerinfo/examples/peerinfo.rs)
- [P2P](crates/p2p/examples/p2p.rs)
- [Quic Upgrade](crates/p2p/examples/quic_upgrade.rs)
- [Metrics](crates/p2p/examples/metrics.rs)
- [Tracing](crates/tracing/examples/basic.rs)

## License

Business Source License 1.1 — see [LICENSE](./LICENSE) for details.

## Would like to contribute?

See [Contributing](./CONTRIBUTING.md).
