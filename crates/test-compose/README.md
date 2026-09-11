# Pluto Compose

Docker-compose smoke-test harness for pluto and charon clusters, adapted from
charon's `testutil/compose`. Test infrastructure: nothing here ships in the
`pluto` binary.

A cluster is produced in steps (`define` → `lock` → `run`), each
rewriting `docker-compose.yml` from `config.json`. `auto` chains the steps
against a docker daemon, brings the cluster up and watches Prometheus for
alerts. Nodes are charon or pluto per `node_impls`; key generation follows
`key_gen_impl`.

## Smoke tests

`tests/smoke.rs` holds one `#[ignore]`d test per scenario, named
`scenario_<name>`. Each stands up a cluster for two minutes and fails on any
firing alert. Prerequisites: docker with compose v2, and `oas3-gen` from
`CONTRIBUTING.md` (the harness links `pluto-eth2util`, whose API types are
generated at build time).

```bash
# one or more scenarios
cargo test -p pluto-test-compose --test smoke -- --ignored --nocapture --exact scenario_default_alpha scenario_pluto_dkg
# the CI matrix (very_large needs a big machine)
cargo test -p pluto-test-compose --test smoke -- --ignored --nocapture --test-threads=1 --skip scenario_very_large
# keep per-scenario logs
SMOKE_LOG_DIR=. cargo test -p pluto-test-compose --test smoke -- --ignored --nocapture --exact scenario_default_alpha
```

| Variable | Effect |
|---|---|
| `PLUTO_REPO` | Repository root the `pluto:local` image is built from (default: this workspace). |
| `SMOKE_SUDO_PERMS` | Set to `1` when containers run as root, so the harness can `sudo chown` its artefacts. |
| `SMOKE_LOG_DIR` | Write `<dir>/<scenario>.log` with the `docker compose up` output. |
| `SMOKE_EXTERNAL_RELAY` | Use this relay URL instead of the in-cluster relay. |

The CI workflow (`.github/workflows/smoke-tests.yml`) is manual-only and runs
the same command.

## Alert criteria vs. charon

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

The charon image tag is `CHARON_IMAGE_TAG` in `src/smoke.rs`.
