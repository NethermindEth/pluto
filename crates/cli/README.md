# `pluto` CLI

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

## Example

### Create and read ENR

Create an ENR key, then print the ENR.

```bash
# 1) Generate and store the ENR private key.
#    This writes: <DATA_DIR>/charon-enr-private-key
pluto create enr --data-dir ./pluto-data

# 2) Print the ENR from the stored key.
pluto enr --data-dir ./pluto-data

# 3) Print the ENR + decoded fields (pubkey/signature).
pluto enr --data-dir ./pluto-data --verbose
```

## Pluto vs Charon command parity

Charon source of truth: `charon/cmd/cmd.go` (root command wiring).

| Command | `charon` | `pluto` | Notes |
| --- | ---: | ---: | --- |
| `version` | ✅ | ✅ | |
| `enr` | ✅ | ✅ | |
| `run` | ✅ | ❌ | Not implemented (`charon/cmd/run.go`) |
| `relay` | ✅ | ❌ | Not implemented (`charon/cmd/relay.go`) |
| `dkg` | ✅ | ❌ | Not implemented (`charon/cmd/dkg.go`) |
| `create` | ✅ | ✅ | |
| `create dkg` | ✅ | ✅ | |
| `create enr` | ✅ | ✅ | |
| `create cluster` | ✅ | ✅ | |
| `combine` | ✅ | ❌ | Not implemented (`charon/cmd/combine.go`) |
| `alpha` | ✅ | ❌ | Not implemented (`charon/cmd/alpha.go`) |
| `alpha add-validators` | ✅ | ❌ | Not implemented (`charon/cmd/addvalidators.go`) |
| `alpha test` | ✅ | ❌ | Not implemented (`charon/cmd/test.go`) |
| `alpha test all` | ✅ | ❌ | Not implemented (`charon/cmd/testall.go`) |
| `alpha test peers` | ✅ | ❌ | Not implemented (`charon/cmd/testpeers.go`) |
| `alpha test beacon` | ✅ | ❌ | Not implemented (`charon/cmd/testbeacon.go`) |
| `alpha test validator` | ✅ | ❌ | Not implemented (`charon/cmd/testvalidator.go`) |
| `alpha test mev` | ✅ | ❌ | Not implemented (`charon/cmd/testmev.go`) |
| `alpha test infra` | ✅ | ❌ | Not implemented (`charon/cmd/testinfra.go`) |
| `exit` | ✅ | ❌ | Not implemented (`charon/cmd/exit.go`) |
| `exit active-validator-list` | ✅ | ❌ | Not implemented (`charon/cmd/exit_list.go`) |
| `exit sign` | ✅ | ❌ | Not implemented (`charon/cmd/exit_sign.go`) |
| `exit broadcast` | ✅ | ❌ | Not implemented (`charon/cmd/exit_broadcast.go`) |
| `exit fetch` | ✅ | ❌ | Not implemented (`charon/cmd/exit_fetch.go`) |
| `exit delete` | ✅ | ❌ | Not implemented (`charon/cmd/exit_delete.go`) |
| `unsafe` | ✅ | ❌ | Not implemented (`charon/cmd/unsafe.go`) |
| `unsafe run` | ✅ | ❌ | Not implemented (`charon/cmd/run.go`) |
