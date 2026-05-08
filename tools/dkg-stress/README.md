# dkg-stress

Stress runner for DKG ceremonies. Wraps `scripts/dkg-runner/run.sh` to execute
N ceremonies (sequentially or in parallel), with a live ratatui UI for
inspecting in-flight progress and per-node logs.

This crate lives outside the main Pluto workspace (`exclude` entry in the root
`Cargo.toml`) so it has its own dependency graph and `Cargo.lock`. Build and
run it locally — it isn't part of `cargo build --workspace`.

## Build

```bash
cd tools/dkg-stress
cargo build --release
```

The binary lands at `tools/dkg-stress/target/release/dkg-stress`.

`run.sh`'s prerequisites still apply: `charon` on `$PATH` (or via `CHARON_BIN`),
`pluto` built (only if `PLUTO_NODES > 0`), and a reachable relay. See
`scripts/dkg-runner/README.md` for the per-ceremony setup.

## Quick start

```bash
# 50 ceremonies, 4 in flight at a time, 5-minute timeout per run.
CHARON_BIN=~/projects/charon/charon RUNS=50 WORKERS=4 TIMEOUT=300 \
    ./tools/dkg-stress/target/release/dkg-stress

# Same thing with flags rather than env vars.
./tools/dkg-stress/target/release/dkg-stress \
    --runs 50 --workers 4

# Sequential smoke test, all-Pluto, keep all artifacts for inspection.
PLUTO_NODES=4 CHARON_NODES=0 \
    ./tools/dkg-stress/target/release/dkg-stress \
    --runs 5 --keep-passed

# Append-only mode (CI, log capture, redirected output).
./tools/dkg-stress/target/release/dkg-stress --runs 10 --no-tui
```

## Configuration

Every option supports both a CLI flag and an environment variable. Flags win
when both are set; otherwise env vars; otherwise defaults.

### Stress-runner options

| Flag | Env var | Default | Description |
|---|---|---|---|
| `-n`, `--runs` | `RUNS` | `10` | Total ceremonies to run |
| `-w`, `--workers` | `WORKERS` | `1` | Concurrent ceremonies |
| `--work-dir` | `STRESS_WORK_DIR` | `/tmp/dkg-stress` | Base directory; each run uses `run-NNNN/` |
| `--run-script` | `DKG_RUN_SCRIPT` | `../../scripts/dkg-runner/run.sh` (relative to crate) | Path to `run.sh` |
| `--keep-passed` | `KEEP_PASSED` | off | Keep `node-*/` dirs of passed runs (default trims them) |
| `--no-tui` | `NO_TUI` | off | Disable ratatui UI; emit per-run log lines |
| `--tick-ms` | `TICK_MS` | `250` | UI redraw interval |

### Per-ceremony options (forwarded to `run.sh` via env)

These are inherited from the calling environment unchanged — see
`scripts/dkg-runner/run.sh --help` for the authoritative list:

`NODES`, `THRESHOLD`, `PLUTO_NODES`, `CHARON_NODES`, `RELAY_URL`, `NETWORK`,
`FEE_RECIPIENT`, `WITHDRAWAL_ADDR`, `TIMEOUT`, `NODE_EXIT_TIMEOUT`,
`SHUTDOWN_DELAY`, `PLUTO_BIN`, `CHARON_BIN`.

`WORK_DIR` is overridden per run and is **not** forwarded — each ceremony gets
its own isolated work dir under `STRESS_WORK_DIR`. `CI` is forced to `true`
when `WORKERS > 1` so per-node logs don't tee to the controlling terminal
(unless you explicitly export `CI` yourself).

## TUI

```
┌─ DKG stress test ────────────────────────────────────────────────┐
│ runs=50 workers=4 work_dir=/tmp/dkg-stress                       │
│ j/k=run · J/K=±10 · Home/End · Tab/h/l=log · PgUp/PgDn=scroll …  │
├─────────────────┬────────────────────────────────────────────────┤
│ runs            │ run-0017 — running                             │
│  run-0001 PASS  │ run.log │ node-0 │ node-1 │ node-2 │ node-3    │
│  run-0002 PASS  │ ─────────────────────────────────────────────  │
│  run-0003 FAIL  │ 2026-05-08T... INFO pluto::dkg starting        │
│ ▶run-0017 run.. │ ...                                            │
│  run-0018 pend  │                                                │
├─────────────────┴────────────────────────────────────────────────┤
│ PASS 16  FAIL 1  run 4  pend 29   (17/50 done)  follow=auto …    │
└──────────────────────────────────────────────────────────────────┘
```

Each in-flight run's row mutates `pending → running Ns → PASS/FAIL Ns` in
place. The detail pane on the right tails the selected log file (last
~256 KB), parsing ANSI escape codes so the colored Pluto/Charon log output
renders correctly.

### Keybindings

**Run selection (left pane)**

| Key | Action |
|---|---|
| `j` `k` `↓` `↑` | Move selection by 1 |
| `J` `K` | Move selection by 10 |
| `Home` `End` | First / last run |
| `a` | Re-engage auto-follow (selection tracks the latest active run) |

**Log navigation (right pane)**

| Key | Action |
|---|---|
| `Tab` `Shift-Tab` `h` `l` `←` `→` | Cycle log file (`run.log`, `node-0`, `node-1`, …) |
| `PgUp` `PgDn` | Scroll log by ~20 lines |
| `Ctrl-u` `Ctrl-d` | Scroll log by ~10 lines (vim half-page) |
| `Ctrl-b` `Ctrl-f` | Scroll log by ~20 lines (vim full-page) |
| `g` | Jump to top of buffer |
| `G` | Jump to tail (resume live updates) |

**Other**

| Key | Action |
|---|---|
| `q` `Esc` `Ctrl-C` | Graceful shutdown — SIGTERMs in-flight ceremonies, finalises the summary |

Once you scroll up or move the selection, the footer shows `follow=manual`
(selection pinned) and/or `log=+N (G to follow)` (log offset). Press `a` to
return to auto-follow, `G` to snap the log back to its tail.

## Output

For each invocation, `dkg-stress` writes:

```
${STRESS_WORK_DIR}/
├── summary.tsv                  # one row per completed run
├── run-0001/
│   ├── run.log                  # full stdout/stderr of this run.sh invocation
│   ├── node-0/node.log          # per-node logs (passed runs trim these by default)
│   ├── node-1/node.log
│   └── …
├── run-0002/
└── …
```

`summary.tsv` columns: `run_id`, `status` (`pass`/`fail`), `duration_s`,
`start_time` (ISO-8601 UTC), `work_dir`. New rows are appended atomically as
ceremonies complete.

When `--keep-passed` is off (the default), `node-*/` subdirs of passed runs
are deleted to keep disk usage bounded. `run.log` and the cluster lock files
are always preserved. Failed runs are kept in full.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All ceremonies passed |
| `1` | One or more failed; details in the final summary and `summary.tsv` |
| `2` | Configuration error (bad flag, missing `run.sh`, etc.) |
| `130` | Interrupted (SIGINT/SIGTERM/SIGHUP); in-flight ceremonies are SIGTERM'd, partial summary preserved |

## Graceful shutdown

`q`, `Esc`, and `Ctrl-C` from the TUI, plus external `SIGINT` / `SIGTERM` /
`SIGHUP`, all flow through the same path:

1. Set the shared stop flag — workers stop dispatching new runs.
2. SIGTERM every in-flight `run.sh` process group, so each ceremony's
   `_on_signal` trap fires and shuts the four nodes down cleanly.
3. Wait up to 5 s for clean exits, then SIGKILL stragglers.
4. Restore the terminal, finalise `summary.tsv`, print aggregate stats.

No orphan processes; partial runs are recorded as `fail` with their actual
runtime, un-started runs as "skipped".

## Troubleshooting

**"could not find run.sh"** — pass `--run-script` or set `DKG_RUN_SCRIPT`. The
default lookup walks two directories up from the binary's manifest dir, so it
only auto-resolves when running from a checkout.

**TUI is garbled / shows raw escape codes** — pluto/charon logs are now
parsed with `ansi-to-tui`. If you still see escapes, the file likely contains
non-SGR control sequences; switch tabs or hit `g` to refresh.

**Scrolling does nothing** — make sure you're hitting the log pane keys
(`PgUp`/`PgDn`, `Ctrl-u`/`Ctrl-d`), not the run-selection keys (`j`/`k`).
The detail title shows `[+N lines]` once you've scrolled. Bear in mind the
buffer is the last 256 KB of the file — extremely long ceremonies will only
let you scroll back through that window.

**"all failed" with no obvious cause** — open one of the failed runs in the
TUI, cycle through `run.log` (orchestration output) and each `node-N/node.log`
to find the first error. If `KEEP_PASSED` was off and you want artifacts of
all runs, re-run with `--keep-passed`.

**Workers wedged after Ctrl-C** — should not happen; check
`pgrep -fl run.sh`. If anything sticks around, file an issue with the
`/tmp/dkg-stress/run-NNNN/` directory contents.
