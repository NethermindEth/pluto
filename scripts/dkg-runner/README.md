# DKG Runner

Shell scripts for running a complete DKG ceremony with a configurable mix of Pluto and Charon nodes.

## Prerequisites

- `charon` binary on your `$PATH` (used for `create dkg`)
- Pluto binary built: `cargo build -p pluto-cli`
- Relay server reachable (default: `https://relay.obol.tech`)

## Quick start

```bash
# From repo root — 2 Pluto + 2 Charon, tmux split-pane view (recommended)
./scripts/dkg-runner/tmux-run.sh

# Same, but plain terminal (no tmux required)
./scripts/dkg-runner/run.sh

# All Pluto, 4 nodes
PLUTO_NODES=4 CHARON_NODES=0 ./scripts/dkg-runner/run.sh

# All Charon, 4 nodes
PLUTO_NODES=0 CHARON_NODES=4 ./scripts/dkg-runner/run.sh

# 1 Pluto + 3 Charon
NODES=4 THRESHOLD=3 PLUTO_NODES=1 CHARON_NODES=3 ./scripts/dkg-runner/run.sh

# Release binary, custom relay, longer timeout
PLUTO_BIN=./target/release/pluto \
RELAY_URL=https://relay.obol.tech \
TIMEOUT=300 \
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
| `RELAY_URL` | `https://relay.obol.tech` | Relay ENR endpoint passed to `charon create dkg` |
| `NETWORK` | `holesky` | Ethereum network for the cluster definition |
| `FEE_RECIPIENT` | `0xDeaDBeef…` | Fee recipient address for the cluster |
| `WITHDRAWAL_ADDR` | `0xDeaDBeef…` | Withdrawal address for the cluster |
| `TIMEOUT` | `120` | Seconds to wait before declaring the ceremony failed |
| `PLUTO_BIN` | `./target/debug/pluto` | Path to the Pluto binary |
| `CHARON_BIN` | `charon` | Path to the Charon binary |
| `WORK_DIR` | `/tmp/dkg-run` | Scratch directory — wiped at the start of every run |

`PLUTO_NODES + CHARON_NODES` must equal `NODES`.

## What happens during a run

| Phase | Script | Action |
|-------|--------|--------|
| 1 | `setup.sh` | Wipes `WORK_DIR`, creates `node-0/`…`node-N/` data dirs, generates a p2p key + ENR for each node (`pluto create enr` / `charon create enr`), then runs `charon create dkg --operator-enrs=…` |
| 2 | `start-nodes.sh` | Starts Pluto nodes (slots 0…PLUTO_NODES-1) and Charon nodes (remaining slots) as background processes; logs to `node-N/node.log` |
| 3 | `monitor.sh` | Polls logs for completion signals; prints live progress; exits 0 when all nodes complete, 1 on timeout |
| 4 | *(inline)* | Sends SIGTERM to all node processes |
| 5 | `collect.sh` | Copies keystores and `cluster-lock.json` to `WORK_DIR/output/`; prints a summary |

On success, outputs are under `$WORK_DIR/output/`. On failure or timeout, partial outputs are collected before cleanup.

Ctrl-C at any point kills all nodes cleanly via a SIGINT trap.

## Scripts

| Script | Description |
|--------|-------------|
| `tmux-run.sh` | Like `run.sh` but opens a tmux session: top pane = monitor, bottom row = one log pane per node |
| `run.sh` | Main entry point — runs all phases in order (plain terminal) |
| `setup.sh` | Creates the cluster definition and data directories |
| `start-nodes.sh` | Launches node processes in the background |
| `monitor.sh` | Waits for ceremony completion or timeout |
| `collect.sh` | Gathers keystores and lock file into `output/` |
| `reset.sh` | Kills all nodes and removes `WORK_DIR` |
| `config.sh` | Shared env-var defaults sourced by every script |

Each script is independently runnable if you need to step through phases manually:

```bash
# Step through manually
./scripts/dkg-runner/setup.sh
./scripts/dkg-runner/start-nodes.sh
./scripts/dkg-runner/monitor.sh
./scripts/dkg-runner/collect.sh
./scripts/dkg-runner/reset.sh
```

## Logs

Each node writes to `$WORK_DIR/node-N/node.log`. To tail all logs live in a second terminal:

```bash
tail -f /tmp/dkg-run/node-*/node.log
```

## Troubleshooting

**`PLUTO_NODES + CHARON_NODES must equal NODES`** — check your env vars add up.

**`cluster-definition.json not found`** — `charon create dkg` may have written the file under a different path. Check `$WORK_DIR/.charon/` manually.

**Ceremony times out** — increase `TIMEOUT`, check relay connectivity, and inspect `$WORK_DIR/node-*/node.log` for errors.

**Pluto binary not found** — build first with `cargo build -p pluto-cli`, or set `PLUTO_BIN` to the correct path.
