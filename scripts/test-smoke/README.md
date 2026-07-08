# test-smoke

Boot a distributed-validator cluster of `run --simnet-*` nodes, hold it for a
window, and **fail if it's unhealthy** — a bash + docker **adaptation** of charon's
compose smoke test, swappable charon↔pluto per node. It is not a byte-faithful port;
see [Deviations](#deviations-from-charons-testsmoke).

## Quick start

```bash
cd scripts/test-smoke
./run.sh                                        # all-charon, default scenario (~90s)
NODE0_IMAGE=nethermindeth/pluto:main ./run.sh   # swap node0 to pluto
SCENARIO=node_down ./run.sh                     # run a specific scenario (see below)
```

A healthy run ends with **`[PASS] …`** (exit 0); any failing gate ends with
**`[FAIL] …`** (exit 1) and leaves `smoke-logs.txt` in this directory for debugging.
Requires docker (+ `docker compose`), `python3`, and `curl`.

---

## Summary

| | |
|---|---|
| **Nodes** | A **charon and/or pluto** cluster — each node's image is chosen via `NODE{N}_IMAGE`. All-charon today (charon is the parity reference); swap nodes to pluto as `pluto run` lands, or run a mixed cluster. |
| **Adapts** | charon **v1.7.1**'s compose smoke *methodology* — `testutil/compose/smoke/smoke_test.go` (`TestSmoke`) + `compose.Auto`, with the alert oracle `testutil/compose/static/prometheus/rules.yml`. Adapted for a self-contained validator-mock cluster (see Deviations). |
| **Proves** | *operational health* — a real containerized cluster stays **alert-free** over a window and **survives a node loss**. |
| **How** | docker-compose brings up the cluster + Prometheus; a bash loop applies charon's two smoke oracles — **container survival** (`--abort-on-container-exit`) and the **alert API** (fail-closed if unpollable) — plus a positive **broadcast-liveness** gate. |
| **Why bash+docker** | It's black-box orchestration (charon's own harness just shells out to `docker compose` + `curl`), and it's the only layer that exercises the real **docker image** + monitoring stack. |

### Deviations from charon's TestSmoke

Honest scope — this is an *adaptation*, not a faithful reproduction:

| Deviation | charon TestSmoke | here | Why |
|---|---|---|---|
| Validator client | real VC mix `[lighthouse, lighthouse, mock]` | all `--simnet-validator-mock` | self-contained/fast; real VCs are a deferred nightly lane |
| `Warn Log Rate`, `Broadcast Duty Rate` | fatal | reported-but-ignored | benign vmock artifacts, not cluster faults (`IGNORE_ALERTS=""` re-enables) |
| `Error Log Rate` | monotonic `>0` | error **growth** during the window | tolerates the transient cold-start consensus timeout without masking steady-state errors |
| Default scenario | runs alpha/beta/stable tiers | `default_stable` (others via `SCENARIO=`) | one scenario per run |
| Cluster size | scenarios span N=3/4/10 + DKG | fixed N=4 | a static compose can't vary node count |
| `node_down` oracle | full alert oracle @1s | **liveness/chaos** check @1s (survivor errors **reported, not gated**) | charon's real-VC survivors stay clean at 1s; vmock survivors permanently-fail node0's duties, and 6s starves the broadcast window — so full-oracle node-loss is the real-VC lane |

Kept faithful: the up→keygen→run→scrape flow; both of charon's oracles for the steady
scenarios — **container survival** (`docker compose up --abort-on-container-exit`) and
**poll alerts→fail on firing** (fail-closed if unpollable) against `rules.yml` (charon's
rule **expressions** verbatim, names rebranded); and `node_down`'s isolation *mechanism*
(node0 given no relay → cannot communicate, at charon's default 1s). `node_down`'s
*oracle* is the one thing vmock can't match — see the deviation row above.

---

## Setup

`run.sh` → `docker compose up` starts these services in dependency order:

| Service | Image | Role |
|---|---|---|
| `init` | busybox | `chmod` the shared volumes (docker volumes are root-owned; the node images run as non-root) |
| `setup` | `SETUP_IMAGE` | `create cluster` (insecure keys) → per-node `cluster-lock.json` + enr key + validator keys |
| `fix-perms` | busybox | make the keys writable for whatever uid the node images use |
| `relay` | `RELAY_IMAGE` | libp2p relay |
| `node0..3` | `NODE{N}_IMAGE` | `run --simnet-beacon-mock --simnet-validator-mock …` (each: own beacon mock + built-in validator mock; the 4 run real QBFT + threshold signing over the relay) |
| `prometheus` | prom/prometheus | scrape each node's `:3620`, evaluate the alert rules |

- **Oracle:** `../../test-infra/rules.yml`, mounted read-only — charon's compose
  alert rules with **identical expressions** (`expr`/`for`/`severity` verbatim); only
  the group/alert names and descriptions are rebranded charon→Pluto.
- **Verdict** (all must hold): wait for the expected nodes `readyz==1` → warmup +
  baseline error/broadcast counters → hold `MEASURE_SECONDS` polling `/api/v1/alerts`,
  then check, in order:
  1. **container survival** — no long-running container (relay, prometheus, and **all**
     nodes, including an isolated node0) exited (adapts `--abort-on-container-exit`);
  2. **alert API pollable** — fail **closed** if it never answered or died mid-run;
  3. **broadcast liveness** — **every** node's `core_bcast_broadcast_total` grew, so one
     silently-idle node can't hide behind the others (duties are flowing on each node);
  4. **alert oracle** — no firing alert (`Error Log Rate` as window-growth). `node_down`
     replaces this step with a liveness pass that **reports** survivor errors instead of
     gating on them — see notes.

  All counter reads for the verdict fail **closed** (a failed Prometheus query is a
  failure, not a silent 0). On exit: write `smoke-logs.txt` and `down -v`.

### Configuration

| Env | Default | Purpose |
|---|---|---|
| `NODE{0..3}_IMAGE` | `obolnetwork/charon:v1.7.1` | per-node image (swap to pluto) |
| `SETUP_IMAGE`, `RELAY_IMAGE` | `obolnetwork/charon:v1.7.1` | keygen / relay image |
| `SCENARIO` | `default_stable` | scenario to run (see below) |
| `NETWORK` | `hoodi` | cluster network |
| `FEATURE_SET` | `stable` | `--feature-set` |
| `SYNTHETIC_PROPOSALS` | `true` | `--synthetic-block-proposals` |
| `BUILDER_API` | `false` | `--builder-api` |
| `SLOT_DURATION` | `1s` | `--simnet-slot-duration` |
| `MEASURE_SECONDS` | `60` | hold-window length (charon default; keep ≥45s so the `increase[30s]`+`for:15s` rules can fire) |
| `WARMUP_SECONDS` | `10` | settle past cold-start before baselining errors |
| `READY_TIMEOUT` | `30` | wait-for-ready timeout (~10s observed) |
| `READY_NODES` | `4` | nodes that must be ready (`node_down` uses 3) |
| `IGNORE_ALERTS` | `Warn Log Rate,Broadcast Duty Rate` | alerts reported, not fatal |
| `PROMETHEUS_VERSION` | `v2.55.1` | pinned Prometheus image tag |
| `PROM_PORT` | `9090` | host port for Prometheus |

---

## What is covered

### Scenarios

| `SCENARIO` | Effect | Verdict |
|---|---|---|
| `default_stable` *(default)* | baseline, `--feature-set=stable` | no fatal alert |
| `default_alpha` | `--feature-set=alpha` | no fatal alert |
| `builder` | `--builder-api=true` | no fatal alert |
| `no_synthetic` | `--synthetic-block-proposals=false`, **6s slots** | no fatal alert |
| `node_down` | node0 given **no relay** (up-but-mute), 1s (charon `1_of_4_down`) | **liveness/chaos**: 3 survivors up + quorum + broadcasting, node0 no crash; survivor errors **reported** |

### Alert oracle

The verdict is charon's 7 compose rules. Five **gate** (fatal); two are benign on
a validator-mock cluster and are **reported-but-ignored** by default:

| Alert | Role |
|---|---|
| `Pluto Down` (`up==0`) | gate |
| `Error Log Rate` | gate — measured as error **growth during the window**, not the monotonic alert (see cold-start note) |
| `Validator API Error Rate` | gate |
| `Proxy API Error Rate` | gate |
| `Outstanding Duty Rate` | gate |
| `Warn Log Rate` | ignored (mock logs benign `unexpected duty` warnings) |
| `Broadcast Duty Rate` | ignored as an alert (mock submits only the epoch-aligned attester → sparse); its "is duty output flowing" intent is kept via the **per-node broadcast-liveness** gate below |

Set `IGNORE_ALERTS=""` to enforce all seven (e.g. a future real-VC run).

**Beyond the alert rules**, the verdict always also gates on **container survival**
(charon's `--abort-on-container-exit`) and **per-node broadcast liveness** (a positive
"every node is producing output" check the "no alert fired" oracle can't provide) —
these apply even when `IGNORE_ALERTS` silences an alert.

### Scenario notes

- **Cold-start:** simnet genesis is a past timestamp, so duties fire immediately —
  before the p2p mesh finishes forming. A node can then hit a one-time
  `consensus timeout` ERROR at startup. Since `Error Log Rate` is monotonic
  (`app_log_error_total > 0`), that would flake the smoke; so the harness warms up
  (`WARMUP_SECONDS`), baselines the error counter, and fails only on error **growth
  during the measured window** — a cold-start blip is tolerated, steady-state errors
  are not.
- **`node_down`** uses charon's `1_of_4_down` isolation: node0 is given **no relay**
  (`NODE0_RELAY=""` → `--p2p-relays=`) so it stays **up but can't reach peers** (charon
  zeroes node0's p2p env for the same effect). It's dropped from the readiness/error/
  broadcast aggregates (`EXCLUDE_INSTANCE`, `READY_NODES=3`) but **not** from
  container-survival — a node0 that *crashes* (e.g. a pluto panic) still fails.
  charon enforces its full alert oracle here, and its **real-VC** survivors stay clean at
  1s; this **vmock** cluster's survivors can't — they permanently-fail the ~¼ of duties
  node0 led (proposer/sync_contribution can't round-change within a 1s deadline), and 6s
  slots make duties too sparse for the broadcast gate. So `node_down` is scoped as a
  **liveness/chaos check** (survivors up + quorum + broadcasting, no crash) that
  **reports** the survivor errors rather than gating on them; enforcing the full oracle
  under a node loss is the deferred **real-VC lane** (see Deviations).
- **`no_synthetic`** runs at **6s slots**: with synthetic proposals off the real
  proposer-consensus path runs, and at 1s slots it hits a cold-start consensus
  timeout that trips `Error Log Rate`; 6s clears it.

### Not covered

- **Real validator clients** (Lighthouse/Teku) — every node uses the built-in
  `--simnet-validator-mock`, so the real VC↔validator-API surface isn't exercised.
- **Variable cluster size** (3- or 10-node) and the **DKG keygen** path — the
  compose is fixed at 4 nodes with centralized keygen.
