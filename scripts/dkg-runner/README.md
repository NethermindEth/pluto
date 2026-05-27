# DKG Runner

Shell scripts for running a complete DKG ceremony with a configurable mix of Pluto and Charon nodes.

## Prerequisites

- Pluto binary built (used for `create dkg` and for any Pluto nodes in the ceremony): `cargo build -p pluto-cli`
- `charon` binary on your `$PATH` and `curl` installed (required when `RUN_SMOKE_VERIFY` is enabled; this is the default)
- Relay server reachable (default: `https://0.relay.obol.tech`)

## Quick start

```bash
# From repo root — 2 Pluto + 2 Charon (defaults)
./scripts/dkg-runner/run.sh

# All Charon, 4 nodes (works today; Pluto DKG not yet ready)
PLUTO_NODES=0 CHARON_NODES=4 ./scripts/dkg-runner/run.sh

# All Pluto, 4 nodes
PLUTO_NODES=4 CHARON_NODES=0 ./scripts/dkg-runner/run.sh

# 1 Pluto + 3 Charon
NODES=4 THRESHOLD=3 PLUTO_NODES=1 CHARON_NODES=3 ./scripts/dkg-runner/run.sh

# Run a single node manually after setup
./scripts/dkg-runner/setup.sh
./scripts/dkg-runner/run-node.sh 0 charon
./scripts/dkg-runner/run-node.sh 1 pluto

# Release binary, custom relay, longer timeout
PLUTO_BIN=./target/release/pluto \
RELAY_URL=https://0.relay.obol.tech \
TIMEOUT=300 \
./scripts/dkg-runner/run.sh

# Keep nodes running after a successful ceremony for inspection
KEEP_NODES=1 ./scripts/dkg-runner/run.sh

# CI invocation: quiet logging, all-Charon, fail fast on timeout
CI=true PLUTO_NODES=0 CHARON_NODES=4 TIMEOUT=180 \
    ./scripts/dkg-runner/run.sh

# Run multiple times back-to-back
for i in $(seq 1 5); do ./scripts/dkg-runner/run.sh; done
```

## Configuration

All variables are optional. Set them in the environment before calling any script.

| Variable | Default | Description |
|----------|---------|-------------|
| `NODES` | `4` | Total node count |
| `THRESHOLD` | `3` | Min shares required to reconstruct the key |
| `PLUTO_NODES` | `2` | How many slots use the Pluto binary (fills slots 0…N-1) |
| `CHARON_NODES` | `2` | How many slots use the Charon binary (fills remaining slots) |
| `RELAY_URL` | `https://0.relay.obol.tech` | Relay ENR endpoint passed to the DKG nodes |
| `NETWORK` | `holesky` | Ethereum network for the cluster definition |
| `FEE_RECIPIENT` | `0xDeaDBeef…` | Fee recipient address for the cluster |
| `WITHDRAWAL_ADDR` | `0xDeaDBeef…` | Withdrawal address for the cluster |
| `TIMEOUT` | `120` | Seconds to wait before declaring the ceremony failed |
| `SHUTDOWN_DELAY` | `120s` | Graceful shutdown delay passed to each node via `--shutdown-delay` |
| `NODE_EXIT_TIMEOUT` | `180` | Seconds to wait for node processes to exit cleanly after artifacts appear |
| `PLUTO_BIN` | `./target/debug/pluto` | Path to the Pluto binary (only required when `PLUTO_NODES > 0`) |
| `CHARON_BIN` | `charon` | Path to the Charon binary |
| `RUN_SMOKE_VERIFY` | `1` | Smoke-start the collected node dirs with `charon run` after output collection |
| `SMOKE_SECONDS` | `8` | Seconds to wait for smoke validator APIs to become ready |
| `SMOKE_PORT_BASE` | `19000` | First local port used by smoke verification |
| `WORK_DIR` | `/tmp/dkg-run` | Scratch directory — wiped at the start of every run |
| `KEEP_NODES` | `0` | Leave node processes running after a successful ceremony when set to `1`/`true`/`yes`/`on` |
| `CI` | _(unset)_ | When truthy, suppresses per-node tee to stdout; logs go to `WORK_DIR/node-*/node.log` only |

`PLUTO_NODES + CHARON_NODES` must equal `NODES`.

## What happens during a run

| Phase | Script | Action |
|-------|--------|--------|
| 1 | `setup.sh` | Wipes `WORK_DIR`, creates `node-0/`…`node-N/` data dirs, generates a p2p key + ENR for each node (`pluto create enr` / `charon create enr`), then runs `pluto create dkg --operator-enrs=…` |
| 2 | `start-nodes.sh` | Starts Pluto nodes (slots 0…PLUTO_NODES-1) and Charon nodes (remaining slots) as background processes, each in its own process group; logs to `node-N/node.log` |
| 3 | `monitor.sh` | Waits for `cluster-lock.json` and at least one keystore to appear in every node's data dir; exits 0 on completion, 1 on timeout (with the tail of each `node.log` dumped to stderr) |
| 4 | `wait-node-exits.sh` | Waits for each node process to exit with status `0` unless `KEEP_NODES` is enabled |
| 5 | `collect.sh` | Copies keystores and `cluster-lock.json` to `WORK_DIR/output/`; prints a summary |
| 6 | `ci/verify-output-semantic.sh` | Validates the collected output is internally consistent across nodes |
| 7 | `ci/verify-run-smoke.sh` | Starts the collected node dirs with `charon run` and checks every validator API reaches readiness |

On success, outputs are under `$WORK_DIR/output/`. On failure or timeout, partial outputs are still collected and `WORK_DIR` is preserved for inspection. `run.sh` never deletes `WORK_DIR`; use `./scripts/dkg-runner/reset.sh` when you're done.

If `KEEP_NODES` is enabled, successful runs leave the node processes running.

Ctrl-C at any point kills all node process groups cleanly via the SIGINT trap; `WORK_DIR` is preserved.

## Scripts

| Script | Description |
|--------|-------------|
| `run.sh` | Main entry point — runs all phases in order |
| `setup.sh` | Creates the cluster definition and data directories |
| `start-nodes.sh` | Launches node processes in the background (each in its own process group) |
| `run-node.sh` | Runs a single node in the foreground: `run-node.sh <index> <pluto\|charon>` |
| `monitor.sh` | Waits for ceremony completion or timeout |
| `wait-node-exits.sh` | Waits for all node processes to report clean exit codes |
| `collect.sh` | Gathers keystores and lock file into `output/` |
| `ci/verify-output-semantic.sh` | Checks that the collected outputs match the ceremony config and share consistent contents |
| `ci/verify-run-smoke.sh` | Smoke-starts the collected node dirs with `charon run` |
| `ci/verify-output.sh` | Legacy file-presence check for `cluster-lock.json` and keystores |
| `ci/install-charon.sh` | Downloads and installs a Charon release binary |
| `reset.sh` | Kills all nodes and removes `WORK_DIR` (the explicit cleanup tool) |
| `config.sh` | Shared env-var defaults sourced by every script |
| `lib.sh` | Shared helpers (logging, binary checks, process-group kill) |

Each script is independently runnable if you need to step through phases manually:

```bash
# Step through manually
./scripts/dkg-runner/setup.sh
./scripts/dkg-runner/start-nodes.sh
./scripts/dkg-runner/run-node.sh 0 pluto
./scripts/dkg-runner/monitor.sh
./scripts/dkg-runner/collect.sh
./scripts/dkg-runner/ci/verify-output-semantic.sh
./scripts/dkg-runner/ci/verify-run-smoke.sh
./scripts/dkg-runner/reset.sh
```

## Logs

Each node writes to `$WORK_DIR/node-N/node.log`. To tail all logs live in a second terminal:

```bash
tail -f /tmp/dkg-run/node-*/node.log
```

## CI

The runner is non-interactive when `CI=true` (or any truthy value) is set:

- Per-node stdout/stderr is written to `node-*/node.log` only — not duplicated to the controlling terminal.
- On timeout, the tail of every `node.log` is dumped to stderr automatically.
- `WORK_DIR` is preserved on every exit path, so you can upload it as a build artifact.
- Exit codes: `0` success, `1` failure/timeout, `130` interrupted.

A typical GitHub Actions step:

```yaml
- name: Run DKG ceremony
  env:
    CI: "true"
    PLUTO_NODES: 2
    CHARON_NODES: 2
    TIMEOUT: 180
  run: ./scripts/dkg-runner/run.sh

- name: Upload DKG work dir on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: dkg-run
    path: /tmp/dkg-run
```

## Troubleshooting

**`PLUTO_NODES + CHARON_NODES must equal NODES`** — check your env vars add up.

**`cluster-definition.json not found`** — `pluto create dkg` may have written the file under a different path. Check `$WORK_DIR` manually.

**Ceremony times out** — increase `TIMEOUT`, check relay connectivity, and read the per-node log tails that `monitor.sh` prints to stderr on timeout. Full logs remain at `$WORK_DIR/node-*/node.log`.

**Pluto binary not found** — build first with `cargo build -p pluto-cli`, or set `PLUTO_BIN` to the correct path. `PLUTO_BIN` is always required because setup uses `pluto create dkg`.

**Smoke verification fails immediately** — install `charon` and `curl`, or set `RUN_SMOKE_VERIFY=0` if you only want the ceremony run and output collection.
