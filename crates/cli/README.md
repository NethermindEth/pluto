# `pluto` CLI

This crate builds the `pluto` binary (`pluto-cli`).

Pluto enables the operation of Ethereum validators in a fault tolerant manner by splitting the validating keys across a group of trusted parties using threshold cryptography.

## Commands (current)

Most flags below also read a `CHARON_*` environment variable (for example `--beacon-node-endpoints` reads `CHARON_BEACON_NODE_ENDPOINTS`), mirroring charon's environment surface. A variable that is set but empty is treated as unset. Run `pluto <COMMAND> --help` for the authoritative list — flags with a binding show an `[env: ...]` line.

Some flags are accepted for charon compatibility but are not yet wired up. They are marked below as **[IGNORED]** (parsed, then dropped — `pluto run` logs a warning for most of them) or **[UNSUPPORTED]** (setting the flag makes the command exit at startup with an error).

### `pluto run`

Starts the long-running Pluto middleware process to perform distributed validator duties.

- **Cluster and key flags**
  - `--private-key-file <PATH>`: The path to the pluto enr private key file. (default: `.charon/charon-enr-private-key`)
  - `--private-key-file-lock`: Enables private key locking to prevent multiple instances using the same key.
  - `--lock-file <PATH>`: The path to the cluster lock file defining the distributed validator cluster. (default: `.charon/cluster-lock.json`)
  - `--manifest-file <PATH>`: **[IGNORED]** Cluster manifest support was removed (charon #4130); the flag is accepted but the file is never read and the lock file is authoritative. (default: `.charon/cluster-manifest.pb`)
  - `--no-verify`: Disables cluster definition and lock file verification.
  - `--nickname <NAME>`: Human friendly peer nickname. Maximum 32 characters.
- **Beacon node and validator client flags**
  - `--beacon-node-endpoints <URLS>`: Comma separated list of one or more beacon node endpoint URLs.
  - `--fallback-beacon-node-endpoints <URLS>`: **[IGNORED]** Fallback support is not yet implemented; no failover occurs.
  - `--beacon-node-timeout <DURATION>`: Timeout for the HTTP requests Pluto makes to the configured beacon nodes. (default: `2s`)
  - `--beacon-node-submit-timeout <DURATION>`: Timeout for the submission-related HTTP requests. (default: `2s`)
  - `--beacon-node-headers <HEADERS>`: **[UNSUPPORTED]** Comma separated list of headers formatted as `header=value`.
  - `--validator-api-address <ADDR>`: Listening address (ip and port) for validator-facing traffic proxying the beacon-node API. (default: `127.0.0.1:3600`)
  - `--vc-tls-cert-file <PATH>`: **[UNSUPPORTED]** The path to the TLS certificate file used by pluto for the validator client API endpoint.
  - `--vc-tls-key-file <PATH>`: **[UNSUPPORTED]** The path to the TLS private key file associated with the provided TLS certificate.
  - `--execution-client-rpc-endpoint <URL>`: The address of the execution engine JSON-RPC API.
- **Duty flags**
  - `--builder-api`: Enables the builder api. Will only produce builder blocks. Must also be enabled on the validator client. Cannot be combined with the simnet mock flags.
  - `--synthetic-block-proposals`: **[UNSUPPORTED]** Enables additional synthetic block proposal duties. Used for testing of rare duties.
  - `--graffiti <GRAFFITI>`: Comma-separated list or single graffiti string to include in block proposals. Maximum 28 bytes per graffiti.
  - `--graffiti-disable-client-append`: Disables appending the `OB<CL_TYPE>` suffix to graffiti. Raises the limit to 32 bytes.
  - `--consensus-protocol <NAME>`: **[UNSUPPORTED]** Preferred consensus protocol name for the node. Selected automatically when not specified.
  - `--feature-set <SET>`: Minimum feature set to enable by default: `alpha`, `beta`, or `stable`. (default: `stable`)
  - `--feature-set-enable <FEATURES>`: Comma-separated list of features to enable, overriding the default minimum feature set.
  - `--feature-set-disable <FEATURES>`: Comma-separated list of features to disable, overriding the default minimum feature set.
- **Monitoring and tracing flags**
  - `--monitoring-address <ADDR>`: Listening address (ip and port) for the monitoring API (prometheus). (default: `127.0.0.1:3620`)
  - `--debug-address <ADDR>`: **[IGNORED]** No debug listener is started yet.
  - `--otlp-address <ADDR>`, `--otlp-headers <HEADERS>`, `--otlp-insecure`, `--otlp-service-name <NAME>`: **[IGNORED]** OTLP tracing is not yet wired up.
  - `--jaeger-address <ADDR>`, `--jaeger-service <NAME>`: **[IGNORED]** Retained for flag compatibility with charon.
  - `--proc-directory <PATH>`: **[IGNORED]** Stack-component detection is not yet implemented.
- **Simnet flags** (local testing)
  - `--simnet-beacon-mock`: Enables an internal mock beacon node for running a simnet.
  - `--simnet-validator-mock`: Enables an internal mock validator client. Requires `--simnet-beacon-mock`.
  - `--simnet-validator-keys-dir <PATH>`: The directory containing the simnet validator key shares. (default: `.charon/validator_keys`)
  - `--simnet-slot-duration <DURATION>`: Configures slot duration in simnet beacon mock. (default: `1s`)
  - `--simnet-beacon-mock-fuzz`: Configures simnet beaconmock to return fuzzed responses.
- **Custom testnet flags**
  - `--testnet-name <NAME>`: Name of the custom test network.
  - `--testnet-fork-version <HEX>`: Genesis fork version in hex of the custom test network.
  - `--testnet-chain-id <ID>`: Chain ID of the custom test network.
  - `--testnet-genesis-timestamp <TIMESTAMP>`: Genesis timestamp of the custom test network.
  - `--testnet-capella-hard-fork <VERSION>`: Capella hard fork version of the custom test network.
  - The custom network is only registered when the testnet flags are fully specified; a partial set is silently ignored and pluto falls back to the built-in network registry.
- Plus the [common P2P flags](#common-p2p-flags) and [common logging flags](#common-logging-flags).

### `pluto relay`

Starts a libp2p circuit relay that charon clients can use to discover and connect to their peers.

- **Flags**
  - `--data-dir <PATH>`: The directory where pluto will store all its internal data. (default: `.charon`)
  - `--http-address <ADDR>`: Listening address (ip and port) for the relay http server serving runtime ENR. (default: `127.0.0.1:3640`)
  - `--auto-p2pkey`: Automatically generate and persist a p2p key if one does not exist. Always on: it defaults to true and cannot be switched off on the command line (`--auto-p2pkey=false` is rejected); set `CHARON_AUTO_P2PKEY=false` to require an existing key.
  - `--p2p-relay-loglevel <LEVEL>`: **[IGNORED]** Parsed but never applied.
  - `--p2p-max-reservations <N>`: Updates max circuit reservations per peer (each valid for 1 hour). (default: `512`)
  - `--p2p-max-connections <N>`: Currently applied as the relay's total reservation limit; it does not cap inbound connections. (default: `16384`)
  - `--p2p-advertise-private-addresses`: Enable advertising of libp2p auto-detected private addresses.
  - `--monitoring-address <ADDR>`: Listening address (ip and port) for the monitoring API (prometheus).
  - `--debug-address <ADDR>`: **[IGNORED]** Parsed but no debug listener is started (no warning is emitted).
- Plus the [common P2P flags](#common-p2p-flags) and [common logging flags](#common-logging-flags). Note that `--p2p-relays` is accepted but unused by the relay itself.

### `pluto dkg`

Participate in a distributed key generation ceremony for a specific cluster definition that creates distributed validator key shares and a final cluster lock configuration. All other cluster operators should run this command at the same time.

- **Flags**
  - `--data-dir <PATH>`: The directory where charon will store all its internal data. (default: `.charon`)
  - `--definition-file <PATH|URL>`: The path to the cluster definition file or an HTTP URL. (default: `.charon/cluster-definition.json`)
  - `--no-verify`: Disables cluster definition and lock file verification.
  - `--timeout <DURATION>`: Timeout for the DKG process, should be increased if DKG times out. (default: `1m0s`)
  - `--shutdown-delay <DURATION>`: Graceful shutdown delay. (default: `1s`)
  - `--keymanager-address <URL>`: The keymanager URL to import validator keyshares.
  - `--keymanager-auth-token <TOKEN>`: Authentication bearer token to interact with the keymanager API. Provide the api-token only, without the `Bearer` prefix.
  - `--execution-client-rpc-endpoint <URL>`: The address of the execution engine JSON-RPC API.
  - `--publish`: Publish the created cluster to a remote API.
  - `--publish-address <URL>`: The URL to publish the cluster to. (default: `https://api.obol.tech/v1`)
  - `--publish-timeout <DURATION>`: Timeout for publishing a cluster; increase for clusters with more than 200 validators. (default: `30s`)
  - `--zipped`: Create a tar archive compressed with gzip of the target directory after creation.
- Plus the [common P2P flags](#common-p2p-flags) and the [common logging flags](#common-logging-flags).

### `pluto enr`

Prints an Ethereum Node Record (ENR) from this client's charon-enr-private-key. This serves as a public key that identifies this client to its peers.

- **Flags**
  - `--data-dir <PATH>`: The directory where pluto will store all its internal data. (default: `.charon`)
  - `--verbose`: Prints the expanded form of ENR.

### `pluto create`

Create artifacts for a distributed validator cluster. These commands can be used to facilitate the creation of a distributed validator cluster between a group of operators by performing a distributed key generation ceremony, or they can be used to create a local cluster for single operator use cases.

#### `pluto create enr`

Create an Ethereum Node Record (ENR) private key to identify this charon client

- **Flags**
  - `--data-dir <PATH>`: The directory where pluto will store all its internal data. (default: `.charon`)

#### `pluto create dkg`

Create a cluster definition file for a new Distributed Key Generation ceremony.

- **Flags**
  - `--output-dir <PATH>`: The folder to write the output `cluster-definition.json` file to. (default: `.charon`)
  - `--name <NAME>`: Optional cosmetic cluster name.
  - `--num-validators <N>`: The number of distributed validators the cluster will manage (32ETH+ staked for each). (default: `1`)
  - `-t, --threshold <N>`: Optional override of threshold required for signature reconstruction. Defaults to `ceil(n*2/3)` if zero. Non-default values decrease security. An explicit value is validated against the `--operator-enrs` count, so it can only be used with that flag. (default: `0`)
  - `--operator-enrs <ENRS>`: Comma-separated list of each operator's Charon ENR address. Mutually exclusive with `--operator-addresses`; required unless that flag is used.
  - `--operator-addresses <ADDRS>`: Comma-separated list of each operator's Ethereum address. Only usable together with `--publish`; mutually exclusive with `--operator-enrs`.
  - `--fee-recipient-addresses <ADDRS>`: Comma separated list of Ethereum addresses of the fee recipient for each validator. Provide either a single address or one per validator.
  - `--withdrawal-addresses <ADDRS>`: Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards. Provide either a single address or one per validator.
  - `--network <NETWORK>`: Ethereum network to create validators for. Accepted: `mainnet`, `prater` (alias for `goerli`), `goerli`, `sepolia`, `holesky`, `hoodi`, `gnosis`, `chiado` — the `--help` text lists only a subset. (default: `mainnet`)
  - `--dkg-algorithm <ALGO>`: DKG algorithm to use; `default` or `frost`. (default: `default`)
  - `--deposit-amounts <AMOUNTS>`: List of partial deposit amounts (integers) in ETH. Values must sum up to at least 32ETH.
  - `--consensus-protocol <NAME>`: Preferred consensus protocol name for the cluster. Selected automatically when not specified.
  - `--target-gas-limit <N>`: Preferred target gas limit for transactions. (default: `60000000`)
  - `--compounding`: Enable compounding rewards for validators by using `0x02` withdrawal credentials.
  - `--execution-client-rpc-endpoint <URL>`: The address of the execution engine JSON-RPC API.
  - `--publish`: Creates an invitation to the DKG ceremony on the DV Launchpad. Terms and conditions apply.
  - `--publish-address <URL>`: The URL to publish the cluster to. (default: `https://api.obol.tech/v1`)

#### `pluto create cluster`

Creates a local charon cluster configuration including validator keys, charon p2p keys, `cluster-lock.json` and `deposit-data.json` file(s).

- **Flags**
  - `--cluster-dir <PATH>`: The target folder to create the cluster in. (default: `./`)
  - `--definition-file <PATH|URL>`: Optional path to a cluster definition file or an HTTP URL. Overrides the other cluster configuration flags, but requires `--execution-client-rpc-endpoint` to be set.
  - `--name <NAME>`: The cluster name.
  - `--nodes <N>`: The number of charon nodes in the cluster. Minimum is 3. (default: `0`)
  - `--num-validators <N>`: The number of distributed validators needed in the cluster. (default: `0`)
  - `--threshold <N>`: Optional override of threshold required for signature reconstruction. Defaults to `ceil(n*2/3)` if zero. Non-default values decrease security.
  - `--network <NETWORK>`: Ethereum network to create validators for. One of `mainnet`, `prater`, `goerli`, `sepolia`, `hoodi`, `holesky`, `gnosis`, `chiado`.
  - `--fee-recipient-addresses <ADDRS>`: Comma separated list of Ethereum addresses of the fee recipient for each validator. Provide either a single address or one per validator.
  - `--withdrawal-addresses <ADDRS>`: Comma separated list of Ethereum addresses to receive the returned stake and accrued rewards. Provide either a single address or one per validator.
  - `--deposit-amounts <AMOUNTS>`: List of partial deposit amounts (integers) in ETH. Values must sum up to at least 32ETH.
  - `--compounding`: Enable compounding rewards for validators by using `0x02` withdrawal credentials.
  - `--target-gas-limit <N>`: Preferred target gas limit for transactions. (default: `60000000`)
  - `--consensus-protocol <NAME>`: Preferred consensus protocol name for the cluster. Selected automatically when not specified.
  - `--execution-client-rpc-endpoint <URL>`: The address of the execution engine JSON-RPC API.
  - `--split-existing-keys`: Split an existing validator's private key into a set of distributed validator private key shares. Does not re-create deposit data for this key. Requires `--split-keys-dir`; cannot be combined with `--num-validators`.
  - `--split-keys-dir <PATH>`: Directory containing keys to split. Expects keys in `keystore-*.json` and passwords in `keystore-*.txt`. Only takes effect together with `--split-existing-keys`; on its own it is silently ignored.
  - `--insecure-keys`: Generates insecure keystore files. This should never be used. Note the mainnet/gnosis rejection is only enforced when `--definition-file` is used; the flags-only path performs no network check.
  - `--keymanager-addresses <URLS>`: Comma separated list of keymanager URLs to import validator key shares to. One address is required per node in the cluster.
  - `--keymanager-auth-tokens <TOKENS>`: Authentication bearer tokens to interact with the keymanager URLs. Provide the api-tokens only, without the `Bearer` prefix.
  - `--publish`: Publish lock file to obol-api.
  - `--publish-address <URL>`: The URL to publish the lock file to. (default: `https://api.obol.tech/v1`)
  - `--testnet-name <NAME>`, `--testnet-fork-version <HEX>`, `--testnet-chain-id <ID>`, `--testnet-genesis-timestamp <TIMESTAMP>`: Custom test network parameters.
  - `--zipped`: Create a tar archive compressed with gzip of the cluster directory after creation.

### `pluto alpha test`

Test subcommands provide a test suite to evaluate the current cluster setup. The full validator stack can be tested — charon peers, consensus layer, validator client, MEV — and the current machine's infra can be examined as well.

All `alpha test` subcommands share these flags:

- `--test-cases <NAMES>`: Comma-separated list of test names to execute. The available names differ per subcommand and are listed in that subcommand's `--help`.
- `--timeout <DURATION>`: Execution timeout for all tests. (default: `1h`)
- `--quiet`: Do not print test results to stdout. Requires `--output-json` (errors otherwise).
- `--output-json <PATH>`: File path to which output can be written in JSON format.
- `--publish`: Publish test result file to obol-api.
- `--publish-address <URL>`: The URL to publish the test result file to. (default: `https://api.obol.tech/v1`)
- `--publish-private-key-file <PATH>`: The path to the charon enr private key file, used for signing the publish request. (default: `.charon/charon-enr-private-key`)

#### `pluto alpha test peers`

Run multiple tests towards peer nodes. Available tests: `Ping`, `PingMeasure`, `PingLoad`, `DirectConn`, `Libp2pTCPPortOpen`, `PingRelay`, `PingMeasureRelay`. Note that `Libp2pTCPPortOpen` runs by default and fails unless `--p2p-tcp-address` is set.

Exactly one of `--enrs`, `--lock-file` or `--definition-file` must be provided; they are mutually exclusive.

- `--enrs <ENRS>`: Comma-separated list of each peer ENR address.
- `--lock-file <PATH>`: The path to the cluster lock file defining the distributed validator cluster.
- `--definition-file <PATH|URL>`: The path to the cluster definition file or an HTTP URL.
- `--private-key-file <PATH>`: The path to the charon enr private key file. (default: `.charon/charon-enr-private-key`)
- `--keep-alive <DURATION>`: Time to keep the TCP node alive after test completion, so the connection is open for other peers to test against. (default: `30m`)
- `--load-test-duration <DURATION>`: Time to keep running the load tests. For each second a new continuous ping instance is spawned. (default: `30s`)
- `--direct-connection-timeout <DURATION>`: Time to keep trying to establish a direct connection to the peer. (default: `2m`)
- Plus the [common P2P flags](#common-p2p-flags).

#### `pluto alpha test beacon`

Run multiple tests towards beacon nodes. Available tests: `Ping`, `PingMeasure`, `Version`, `Synced`, `PeerCount`, `PingLoad`, `Simulate1`, `Simulate10`, `Simulate100`, `Simulate500`, `Simulate1000`, `SimulateCustom`. The `PingLoad` and `Simulate*` tests only run when `--load-test` is set and are silently skipped otherwise; `SimulateCustom` additionally requires `--simulation-custom` greater than 0.

- `--endpoints <URLS>`: **[REQUIRED]** Comma separated list of one or more beacon node endpoint URLs.
- `--load-test`: Enable load test.
- `--load-test-duration <DURATION>`: Time to keep running the load tests. (default: `5s`)
- `--simulation-duration-in-slots <N>`: Time to keep running the simulation in slots. (default: `32`)
- `--simulation-file-dir <PATH>`: Directory to write simulation result JSON files. (default: `./`)
- `--simulation-verbose`: Show results for each request and each validator.
- `--simulation-custom <N>`: Run custom simulation with the specified amount of validators. (default: `0`)

#### `pluto alpha test validator`

Run multiple tests towards the validator client. Available tests: `Ping`, `PingMeasure`, `PingLoad`.

- `--validator-api-address <ADDR>`: Listening address (ip and port) for validator-facing traffic proxying the beacon-node API. (default: `127.0.0.1:3600`)
- `--load-test-duration <DURATION>`: Time to keep running the load tests. (default: `5s`)

#### `pluto alpha test mev`

Run multiple tests towards MEV relays. Available tests: `Ping`, `PingMeasure`, `CreateBlock`. The `CreateBlock` test only runs when `--load-test` is set and is silently skipped otherwise.

- `--endpoints <URLS>`: **[REQUIRED]** Comma separated list of one or more MEV relay endpoint URLs.
- `--beacon-node-endpoint <URL>`: Beacon node endpoint URL used for the block creation test. Required with `--load-test` — and only allowed then; the command aborts if it is set without `--load-test`.
- `--load-test`: Enable load test.
- `--number-of-payloads <N>`: Increases the accuracy of the load test by asking for multiple payloads. Increases test duration. (default: `1`)

#### `pluto alpha test infra`

Run multiple hardware and internet connectivity tests. Available tests: `DiskWriteSpeed`, `DiskWriteIOPS`, `DiskReadSpeed`, `DiskReadIOPS`, `AvailableMemory`, `TotalMemory`, `InternetLatency`, `InternetDownloadSpeed`, `InternetUploadSpeed`.

- `--disk-io-test-file-dir <PATH>`: Directory at which disk performance will be measured. Defaults to the current user's home directory.
- `--disk-io-block-size-kb <KB>`: The block size in kilobytes used for I/O units, for both reads and writes. (default: `4096`)
- `--internet-test-servers-only <NAMES>`: List of specific server names to include for the internet tests; the best performing one is chosen. Servers are chosen automatically when not provided.
- `--internet-test-servers-exclude <NAMES>`: List of server names to exclude from the tests.

#### `pluto alpha test all`

Runs every test category. **Not yet functional**, for two independent reasons:

- `TestAllArgs` flattens `TestConfigArgs` once directly and again through each of the five per-category arg structs, so clap sees six copies of `--output-json` and friends. In debug builds this trips a clap debug assertion and the command panics before parsing any argument — including `pluto alpha test all --help`.
- The runner itself is a stub: `unimplemented!()` at `crates/cli/src/commands/test/all.rs:45`.

### `pluto version`

Output version info

- **Flags**
  - `--verbose`: Includes detailed module version info and supported protocols.

### `pluto unsafe run` (hidden)

Hidden group of subcommands that includes both normal and test flags. It is intended for internal testing of the Pluto client and should be used with caution. `unsafe run` accepts every [`pluto run`](#pluto-run) flag plus:

- `--p2p-fuzz`: **[UNSUPPORTED]** Enables fuzzing of P2P messages; currently rejected at startup.

### Common P2P flags

Shared by `run`, `relay`, `dkg` and `alpha test peers`.

- `--p2p-relays <RELAYS>`: Comma-separated list of libp2p relay URLs or multiaddrs. Defaults to five public relays operated by Nethermind and Obol (see `crates/p2p/src/config.rs`), which `run`, `dkg` and `alpha test peers` dial unless overridden. Unused by `pluto relay` itself.
- `--p2p-external-ip <IP>`: The IP address advertised by libp2p. This may be used to advertise an external IP.
- `--p2p-external-hostname <HOST>`: The DNS hostname advertised by libp2p. This may be used to advertise an external DNS.
- `--p2p-tcp-address <ADDRS>`: Comma-separated list of listening TCP addresses (ip and port) for libp2p traffic. The empty default does not bind to a local port and therefore only supports outgoing connections.
- `--p2p-udp-address <ADDRS>`: Comma-separated list of listening UDP addresses (ip and port) for libp2p traffic. Same empty-default behaviour as the TCP flag.
- `--p2p-disable-reuseport`: **[IGNORED]** Stored in the p2p config but never applied by any command — TCP port reuse stays enabled (charon applies `tcp.DisableReuseport()`).

### Common logging flags

Global: accepted by every command, and parsed identically before or after the subcommand (`pluto --log-level=debug run` and `pluto run --log-level=debug` are equivalent).

All log output goes to stderr, leaving each command's stdout free for its own data.

`RUST_LOG` is not consulted; `--log-level` (or its default) always decides the filter.

- `--log-format <FORMAT>`: **[IGNORED]** Accepted but not yet applied — output is always console-formatted. (default: `console`)
- `--log-level <LEVEL>`: Log level; `debug`, `info`, `warn` or `error`. (default: `info`)
- `--log-color <COLOR>`: Log color; `auto`, `force` or `disable`. `auto` means "unless `NO_COLOR` is set", not TTY detection. (default: `auto`)
- `--log-output-path <PATH>`: **[IGNORED]** Accepted but not yet applied — no log file is written.
- `--loki-addresses <ADDRS>`: Enables sending of logfmt structured logs to a Loki log aggregation server, in addition to normal stderr logs. Only the first address is used; extra entries are ignored with a warning (charon fans out to every address).
- `--loki-service <NAME>`: Service label sent with logs to Loki. (default: `pluto`)

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
| `run` | ✅ | ✅ | |
| `relay` | ✅ | ✅ | |
| `dkg` | ✅ | ✅ | |
| `create` | ✅ | ✅ | |
| `create dkg` | ✅ | ✅ | |
| `create enr` | ✅ | ✅ | |
| `create cluster` | ✅ | ✅ | |
| `combine` | ✅ | ❌ | Not implemented (`charon/cmd/combine.go`) |
| `alpha` | ✅ | ✅ | |
| `alpha add-validators` | ✅ | ❌ | Not implemented (`charon/cmd/addvalidators.go`) |
| `alpha test` | ✅ | ✅ | |
| `alpha test all` | ✅ | 🚧 | Registered but non-functional: panics on duplicate flattened args in debug builds, and the runner is `unimplemented!()` (`crates/cli/src/commands/test/all.rs:45`) |
| `alpha test peers` | ✅ | ✅ | |
| `alpha test beacon` | ✅ | ✅ | |
| `alpha test validator` | ✅ | ✅ | |
| `alpha test mev` | ✅ | ✅ | |
| `alpha test infra` | ✅ | ✅ | |
| `exit` | ✅ | ❌ | Not implemented (`charon/cmd/exit.go`) |
| `exit active-validator-list` | ✅ | ❌ | Not implemented (`charon/cmd/exit_list.go`) |
| `exit sign` | ✅ | ❌ | Not implemented (`charon/cmd/exit_sign.go`) |
| `exit broadcast` | ✅ | ❌ | Not implemented (`charon/cmd/exit_broadcast.go`) |
| `exit fetch` | ✅ | ❌ | Not implemented (`charon/cmd/exit_fetch.go`) |
| `exit delete` | ✅ | ❌ | Not implemented (`charon/cmd/exit_delete.go`) |
| `unsafe` | ✅ | ✅ | |
| `unsafe run` | ✅ | ✅ | |
