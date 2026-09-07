# Pluto Compose

> A docker-compose test harness for standing up insecure local pluto/charon clusters, used by the smoke integration tests.

This is adapted from charon's [testutil/compose](https://github.com/ObolNetwork/charon/tree/main/testutil/compose)
(pinned at `v1.7.1`, the pluto parity reference) and extended with one extra axis: each node
in the cluster can run either **charon** or **pluto**, so clusters of N charon + M pluto nodes
can be composed for cross-implementation testing.

The harness generates `docker-compose.yml` files that stand up a full cluster (keygen +
run) against a mock beacon node. It is driven programmatically by the integration tests
in `tests/smoke.rs` — there is no standalone CLI. Cluster generation happens in
three stages, exposed as crate functions and pinned by the golden tests in `testdata/`:

1. **define** (`define`): writes a `docker-compose.yml` that runs `create dkg` when keygen==dkg.
2. **lock** (`lock`): writes a `docker-compose.yml` that runs `create cluster` or `dkg`.
3. **run** (`run`): writes a `docker-compose.yml` that runs the cluster.

`auto` (see `src/auto.rs`) chains define → lock → run and runs `docker compose up`; it is
what the tests call after writing a config with `write_config`.

This crate is test infrastructure: nothing in it ships in the `pluto` binary.

## Node implementations

Each node runs either charon or pluto, assigned round-robin from a scenario's `node_impls`
config (empty defaults to all charon):

- Charon nodes run `obolnetwork/charon:{tag}` (smoke pins `v1.7.1`; the default config
uses `latest`). Set the tag to `local` to build from `CHARON_REPO`.
- Pluto nodes run `pluto:{tag}` (default `local`), built automatically from the repo
root `Dockerfile` during the define step. This requires the `PLUTO_REPO` env var
pointing at the pluto repo.
- `key_gen_impl` selects which implementation runs the single-container keygen steps
(`create cluster` / `create dkg`); it defaults to node0's implementation.
- The relay always runs the charon node-base image.

Pluto accepts `CHARON_*` env vars and charon-compatible flags by design (CLI parity),
so the generated docker-compose.yml services are identical for both implementations
apart from the image — no per-implementation command construction. All node roles are
supported for both implementations: keygen (`create cluster`, `create dkg`, `dkg`) and
run. Env parity includes charon's empty-value semantics: a `CHARON_*` variable that is
set but empty counts as unset, as Viper does, so an empty placeholder falls back to the
flag default instead of being parsed as `""`.

Implementation names are validated when configs are written and loaded; anything
other than `charon` or `pluto` is rejected.

## Smoke tests

`tests/smoke.rs` mirrors charon's compose smoke tests: each scenario generates
and runs a full cluster with a mock beacon node (simnet), while a Prometheus container
evaluates the generated alert rules (see `write_alert_rules` in `src/define.rs`). A scenario
fails if any alert fires.

Alert semantics: collection starts once Prometheus answers its rules API. For the
next 60 seconds (the warmup window) exactly three known cold-start transients are
tolerated and must self-resolve — `Error Log Rate` (one consensus-timeout error per
node at the first epoch boundary, before the validator mock submits duties),
`Warn Log Rate` (charon's app-start warning burst), and `Broadcast Duty Rate` (no
duties broadcast before the p2p mesh forms). Any other alert fires the scenario
immediately, warmup or not, and so does anything still firing after the warmup.

Prerequisites: a running Docker daemon and the workspace build prerequisites (see
`CONTRIBUTING.md`; the test binary links `pluto-testutil`, which needs `protoc` and
`oas3-gen` like the rest of the workspace). The first run builds `pluto:local` from
`PLUTO_REPO` (a few minutes) and pulls `obolnetwork/charon:v1.7.1` — both happen
automatically, no manual build needed.

The scenarios are `#[ignore]`d tests named `scenario_<name>`, so they only run when
asked for:

```
# Pluto scenarios only (builds pluto:local from PLUTO_REPO; relay and
# pluto_keygen_create runtime nodes pull obolnetwork/charon:v1.7.1):
PLUTO_REPO=$(git rev-parse --show-toplevel) cargo test -p pluto-test-compose --test smoke -- \
  --ignored --nocapture --exact \
  scenario_pluto_keygen_create scenario_all_pluto scenario_mixed_2_charon_2_pluto scenario_pluto_dkg

# Full matrix (pluto + charon-only scenarios):
PLUTO_REPO=$(git rev-parse --show-toplevel) cargo test -p pluto-test-compose --test smoke -- --ignored --nocapture

# The CI matrix: everything but the resource-heavy very_large scenario:
PLUTO_REPO=$(git rev-parse --show-toplevel) cargo test -p pluto-test-compose --test smoke -- \
  --ignored --nocapture --skip scenario_very_large

# Keep docker-compose logs per scenario (<dir>/<scenario>.log):
SMOKE_LOG_DIR=. cargo test -p pluto-test-compose --test smoke -- --ignored --nocapture
```

Without `--exact`, a name is a substring filter (`dkg` selects `pluto_dkg` too).
Environment variables read by the suite:

| Variable | Effect |
|----------|--------|
| `PLUTO_REPO` | pluto checkout to build `pluto:local` from; scenarios that run pluto (`pluto_keygen_create`, `all_pluto`, `mixed_2_charon_2_pluto`, `pluto_dkg`) skip when it is unset |
| `SMOKE_SUDO_PERMS=1` | fix root-owned artefacts with `sudo chown`/`chmod` after each step (containers run as root); needed where the caller must clean the compose dir up afterwards, e.g. CI |
| `SMOKE_LOG_DIR=<dir>` | write each scenario's `docker compose up` output to `<dir>/<scenario>.log` instead of stdout |
| `SMOKE_EXTERNAL_RELAY=<url>` | route the cluster through an external relay instead of the compose one |

There is no global timeout to set: each scenario is bounded by its own 2–3 minute alert
window plus image builds, and libtest has no overall deadline. Scenarios run one at a
time whatever `--test-threads` says, because clusters competing for CPU and memory
produce duty timeouts a sequential run never sees. `.github/workflows/smoke-tests.yml`
runs the CI matrix on manual dispatch and bounds the run with its step timeout.

All smoke scenarios run the mock validator client. Real VCs cannot pass the alert
gate against charon v1.7.1's beaconmock: it reports `head_slot: "1"` from
`/eth/v1/node/syncing`, so e.g. lighthouse permanently treats the beacon node as
unsynced and performs no duties, starving the cluster below its signing threshold.
(Upstream charon runs lighthouse in these scenarios but its alert collector matches
a Prometheus state that never occurs, so nothing was ever gated.) The real-VC compose
service definitions remain in the harness (`static/`), but the tests always run the
mock VC.

### Alert criteria vs. charon

Adapted from charon's `testutil/compose` alert rules, but the gate is corrected and the
criteria calibrated to actually fire: charon's collector matches Prometheus alert state
`"active"`, which is never emitted (only `inactive` / `pending` / `firing`), so upstream
nothing is ever gated. This harness matches `"firing"`, so several rules necessarily differ:

| Rule | Charon v1.7.1 | Pluto | Change & why |
|------|---------------|-------|--------------|
| `Pluto Down` | `up == 0` | `up == 0` | identical |
| `Validator API Error Rate` | `increase(…{endpoint!="proxy"}[30s]) > 1` | same | identical |
| `Proxy API Error Rate` | `increase(…{endpoint="proxy"}[30s]) > 5` | same | identical |
| `Warn Log Rate` | `increase(app_log_warn_total[30s]) > 2` | same + `{topic!~"vmock\|tracker"}` | exclude charon mock-noise topics (vmock has no builder-registration handler; the beacon mock never includes broadcasts on-chain) |
| `Error Log Rate` | `app_log_error_total > 0` | `increase(app_log_error_total[30s]) > 0` | windowed — an absolute counter can't recover from the inherent cold-start consensus timeout (mock-VC startup delay → no randao); a window + warmup can |
| `Broadcast Duty Rate` | `increase(core_bcast_broadcast_total[30s]) < 0.5` | `(sum by (job) (increase(…{job=~"node[0-9]+"}[30s])) or on (job) max by (job) (0 * up)) < 0.5` | per-node sum + absent-series fallback, so a node emitting *no* broadcast series fails (charon's per-series form missed it) |
| `Outstanding Duty Rate` | `core_bcast_broadcast_total − core_scheduler_duty_total > 50` | *removed* | dead rule — a duty is broadcast at most as often as scheduled, so it can never be positive |
| _gate (alert state)_ | `"active"` — never emitted | `"firing"` + readiness wait + 60s warmup allowlist | charon's gate is vacuous; pluto's enforces |

Scenarios that intentionally degrade the cluster tune the gate via config, not the code:

| Config knob | Effect | Used by |
|-------------|--------|---------|
| `alert_exclude_jobs` | exempt a node from the per-node rules (never from `Pluto Down`) | `1_of_4_down`, `1_of_3_down` |
| `alert_disable_rules` | drop an entire rule | `1_of_3_down` (disables the error-rate gates — a downed round-1 leader makes every third proposer duty unrecoverable on the mock) |

## Versioning

Charon is pinned to the pluto parity reference (`v1.7.1`) through the docker image tag
the smoke tests use: `CHARON_IMAGE_TAG` in `src/smoke.rs`. Bump it deliberately alongside
the parity target, not to track charon main.
