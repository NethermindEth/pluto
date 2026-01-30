# `pluto` CLI (Rust)

This crate builds the `pluto` binary (`pluto-cli`).

Pluto enables the operation of Ethereum validators in a fault tolerant manner by splitting the validating keys across a group of trusted parties using threshold cryptography.

## Commands (current)

### `pluto enr`

Prints an Ethereum Node Record (ENR) from this client's charon-enr-private-key. This serves as a public key that identifies this client to its peers.

- **Flags**
  - `--data-dir <PATH>`: The directory where pluto will store all its internal data.
  - `--verbose`: Prints the expanded form of ENR.

### `pluto create`

Create artifacts for a distributed validator cluster. These commands can be used to facilitate the creation of a distributed validator cluster between a group of operators by performing a distributed key generation ceremony, or they can be used to create a local cluster for single operator use cases.

#### `pluto create enr`

Create an Ethereum Node Record (ENR) private key to identify this charon client

- **Flags**
  - `--data-dir <PATH>`: The directory where pluto will store all its internal data.

### `pluto version`

Output version info

- **Flags**
  - `--verbose`: Includes detailed module version info and supported protocols.

## Rust vs Go command parity

Go source of truth: `charon/cmd/cmd.go` (root command wiring).

| Command | Go `charon` | Rust `pluto` | Notes |
| --- | ---: | ---: | --- |
| `version` | ✅ | ✅ | |
| `enr` | ✅ | ✅ | |
| `run` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `relay` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `dkg` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `create` | ✅ | ✅ (partial) | Rust has `create enr` only. |
| `create dkg` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `create cluster` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `combine` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha add-validators` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha test` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha test all` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha test peers` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha test beacon` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha test validator` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha test mev` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `alpha test infra` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `exit` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `exit active-validator-list` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `exit sign` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `exit broadcast` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `exit fetch` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `exit delete` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `unsafe` | ✅ | ❌ | Not implemented in Rust CLI yet. |
| `unsafe run` | ✅ | ❌ | Not implemented in Rust CLI yet. |
