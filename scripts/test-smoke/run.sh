#!/usr/bin/env bash
# TestSmoke analog (bash + docker): boot a 4-node `run --simnet-*` cluster + Prometheus
# (loading test-infra/rules.yml), wait until the expected nodes are ready, hold for a
# window, and FAIL if the cluster is unhealthy. Adapts charon's compose smoke (see
# README for deviations). charon's smoke has TWO oracles and this mirrors both:
#   1. container survival — `docker compose up --abort-on-container-exit`: no long-running
#      container may crash for the duration (here: checked after the window via `dc ps`).
#   2. alerts (when monitoring is on) — poll the alert API; fail on any firing alert,
#      and FAIL CLOSED if the API can't be polled.
# On top of those we add a positive liveness gate (duties are actually being broadcast)
# and treat Error Log Rate as window-growth (see below).
#
# Flow: parse scenario -> docker compose up -> wait Prometheus -> wait nodes ready ->
#       warmup+baseline -> poll alerts for a window -> verdict -> teardown.
#
# All-charon by default; swap nodes to pluto via env:
#   NODE0_IMAGE=nethermindeth/pluto:main ./run.sh
# Tunables: NODE{0..3}_IMAGE, SETUP_IMAGE, RELAY_IMAGE, PROMETHEUS_VERSION, NETWORK,
#           FEATURE_SET, SYNTHETIC_PROPOSALS, BUILDER_API, SLOT_DURATION,
#           MEASURE_SECONDS, WARMUP_SECONDS, READY_TIMEOUT, READY_NODES,
#           IGNORE_ALERTS, PROM_PORT.

# -e: abort on any unhandled command failure; -u: error on use of an unset variable;
# -o pipefail: a pipeline fails if ANY stage fails (not just the last one).
set -euo pipefail

# Run from this script's own dir so the RELATIVE paths inside docker-compose.yml
# (e.g. ../../test-infra/rules.yml) resolve no matter where the script is called from.
cd "$(dirname "$0")"

# ${VAR:-default} means "use $VAR if the caller exported it, else this default".
READY_TIMEOUT=${READY_TIMEOUT:-30}          # max seconds to wait for nodes to be ready (~10s observed)
MEASURE_SECONDS=${MEASURE_SECONDS:-60}      # hold window (charon default; keep >=45s so increase[30s]+for:15s rules can fire)
WARMUP_SECONDS=${WARMUP_SECONDS:-10}        # settle past cold-start before baselining errors/broadcasts (see below)
READY_NODES=${READY_NODES:-4}               # how many nodes must be ready (node_down lowers this to 3)
PROM="http://localhost:${PROM_PORT:-9090}"  # Prometheus HTTP API base (host-exposed port)

# Alerts that are NOISE on a `--simnet-validator-mock` cluster (not cluster faults),
# reported but not fatal. charon's rules.yml is calibrated for its real-VC TestSmoke;
# the simnet validatormock produces benign "unexpected duty" (builder_registration)
# warnings -> Warn Log Rate, and only submits the epoch-aligned attester (16 slots/
# epoch) -> sparse per-duty broadcasts -> Broadcast Duty Rate. The "is the cluster
# producing duty output" intent of Broadcast Duty Rate is NOT lost: it's replaced by a
# positive broadcast-GROWTH gate (below) that's robust to vmock sparsity. Set
# IGNORE_ALERTS="" for a real-VC tier where these alerts become meaningful again.
IGNORE_ALERTS=${IGNORE_ALERTS:-"Warn Log Rate,Broadcast Duty Rate"}

# --- small helpers -------------------------------------------------------------
log()  { printf '[smoke] %s\n' "$*"; }   # progress line
fail() { printf '[FAIL] %s\n' "$*"; }    # failure line (caller still does an explicit exit 1)
pass() { printf '[PASS] %s\n' "$*"; }    # success line
dc()   { docker compose "$@"; }          # shorthand; runs in this dir, which holds docker-compose.yml

# Runs on ANY exit (success, failure, or a set -e abort): save all container logs for
# debugging, then remove containers + volumes so the next run starts from clean state.
# The `|| true` keeps teardown from itself tripping set -e.
collect_and_down() {
  dc logs --no-color >smoke-logs.txt 2>&1 || true
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}
trap collect_and_down EXIT

# promsum QUERY -> the summed value of a PromQL query, or 0 on any error/empty result.
# Bash cannot parse JSON, so we pipe Prometheus's JSON response through python. The
# trailing `|| echo 0` guards the case where curl fails (e.g. Prometheus not up yet).
# NOTE: 0-on-error is safe HERE because promsum only gates readiness (0 ready -> the
# wait loop times out -> fail) and baselines counters; the alert VERDICT uses
# firing_alerts, which instead fails closed (below).
promsum() {
  curl -sf "$PROM/api/v1/query" --data-urlencode "query=$1" 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    # result is a list of {"metric":..., "value":[timestamp, "val"]}; sum the values.
    r = d.get("data", {}).get("result", []) if d.get("status") == "success" else []
    print(sum(float(s["value"][1]) for s in r))
except Exception:
    print(0)
' 2>/dev/null || echo 0
}

# promq QUERY -> summed value on success, or the literal "ERR" if the query can't be run
# or returns a non-success body. VERDICT counters (error/broadcast growth) use this
# instead of promsum: promsum returns 0 on failure (fail OPEN — a failed final query would
# hide new errors as "0 growth"), whereas an ERR here makes the verdict fail CLOSED.
promq() {
  local body
  body=$(curl -sf "$PROM/api/v1/query" --data-urlencode "query=$1" 2>/dev/null) || { printf 'ERR'; return; }
  printf '%s' "$body" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    if d.get("status") != "success":
        print("ERR"); sys.exit(0)
    print(sum(float(s["value"][1]) for s in d.get("data", {}).get("result", [])))
except Exception:
    print("ERR")
'
}

# firing_alerts -> newline-separated names of currently-firing alerts (empty if none),
# or the literal "__POLL_ERR__" if the alert API can't be reached or returns a
# non-success body. The caller FAILS CLOSED on __POLL_ERR__: a dead Prometheus must not
# read as "no alerts = healthy". Alerts whose instance starts with $EXCLUDE_INSTANCE are
# dropped, so a fault scenario judges only the survivors.
firing_alerts() {
  local body
  body=$(curl -sf "$PROM/api/v1/alerts" 2>/dev/null) || { printf '__POLL_ERR__'; return; }
  printf '%s' "$body" | EXCLUDE_INSTANCE="${EXCLUDE_INSTANCE:-}" python3 -c '
import sys, json, os
ex = os.environ.get("EXCLUDE_INSTANCE", "")
try:
    d = json.load(sys.stdin)
    if d.get("status") != "success":
        print("__POLL_ERR__"); sys.exit(0)
    names = set()                        # a set de-dupes: one name even if it fires on several nodes
    for a in d.get("data", {}).get("alerts", []):
        if a.get("state") != "firing":   # skip "pending" (still inside the rule for: window)
            continue
        if ex and a.get("labels", {}).get("instance", "").startswith(ex):
            continue                     # skip the excluded node (fault scenario)
        names.add(a["labels"].get("alertname", "?"))
    print("\n".join(sorted(names)))
except Exception:
    print("__POLL_ERR__")
'
}

# ge A B -> succeeds (exit 0) iff A >= B; gt A B -> iff A > B. awk because bash arithmetic
# can't compare floats and Prometheus returns values like "4.0". `!` flips awk's exit code
# so a true comparison becomes shell-success.
ge() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a>=b)}'; }
gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a>b)}'; }

# containers_ok -> succeeds iff every long-running service is still running (adapts
# charon's `docker compose up --abort-on-container-exit`: a crashed node/relay/prometheus
# is a failure the alert oracle can miss — un-scraped services, or a crash in the last
# seconds before an alert would fire). ALL nodes are checked, INCLUDING node_down's
# isolated node0: charon's --abort-on-container-exit does not exempt it, so a pluto node0
# that panics must fail even while it's the "down" node (it should stay up-but-mute, not
# crash). One-shot services (init, setup, fix-perms) are expected to have exited, so
# they're not checked. Sets EXITED on failure.
EXITED=""
containers_ok() {
  local running svc miss=""
  running=$(dc ps --services --status running 2>/dev/null || true)
  for svc in relay prometheus node0 node1 node2 node3; do
    printf '%s\n' "$running" | grep -qx "$svc" || miss="$miss $svc"
  done
  EXITED="$miss"
  [ -z "$miss" ]
}

# --- scenario selection --------------------------------------------------------
# Each scenario sets env that docker-compose interpolates into the node flags (exported
# BEFORE `up`). (N=3 / N=10 / dkg would need a variable node count — out of scope for a
# static compose.)
SCENARIO=${SCENARIO:-default_stable}
case "$SCENARIO" in
  default_stable) ;;                                                        # baseline defaults
  default_alpha)  export FEATURE_SET=${FEATURE_SET:-alpha} ;;               # --feature-set=alpha
  builder)        export BUILDER_API=${BUILDER_API:-true} ;;                # --builder-api=true
  no_synthetic)   export SYNTHETIC_PROPOSALS=${SYNTHETIC_PROPOSALS:-false} SLOT_DURATION=${SLOT_DURATION:-6s} ;; # real proposer-consensus path; 6s slots avoid the cold-start timeout
  # node_down = charon's 1_of_4_down isolation: node0 given NO relay (empty NODE0_RELAY ->
  # compose renders `--p2p-relays=`) so it stays UP but can't discover peers (charon zeroes
  # node0's p2p env for the same effect), at charon's default 1s. HONEST SCOPE: charon
  # enforces its FULL alert oracle here (Alerting is hardcoded true) and its real-VC
  # survivors stay clean at 1s — but this VMOCK cluster's survivors permanently-fail the
  # ~1/4 of duties node0 would have led (proposer/sync_contribution can't round-change in a
  # 1s deadline), and at 6s duties are too sparse for the broadcast-liveness window. So the
  # vmock node_down is a LIVENESS / CHAOS check: it gates on container-survival (incl node0)
  # + quorum + broadcasting, and REPORTS the survivor consensus errors (surfaced, not
  # hidden) rather than gating on them. Full alert-oracle enforcement under a node loss is
  # the deferred real-VC lane. EXCLUDE_INSTANCE drops node0 from readiness/error/broadcast
  # AGGREGATES (not container-survival — node0 must not crash); READY_NODES drops to 3.
  node_down)      export NODE0_RELAY="" EXCLUDE_INSTANCE=node0; READY_NODES=3 ;;
  *) echo "unknown SCENARIO='$SCENARIO' (default_stable|default_alpha|builder|no_synthetic|node_down)" >&2; exit 2 ;;
esac
log "scenario: $SCENARIO"

# PromQL label filter that drops the excluded (isolated) node from cluster aggregates,
# so readiness/error/broadcast are all judged over the survivors only (else an isolated
# node0 that still reported ready or held a nonzero counter would skew them).
excl=""
[ -n "${EXCLUDE_INSTANCE:-}" ] && excl="{instance!~\"${EXCLUDE_INSTANCE}.*\"}"
ready_query="count(app_monitoring_readyz${excl}==1)"
err_query="sum(app_log_error_total${excl})"
# Per-node liveness: sum each instance's broadcasts across duty types, then take the MIN
# across instances. Checked > 0 at verdict so one silently-idle node can't hide behind the
# others' growth (charon's Broadcast Duty Rate rule is per-series too). increase() over the
# measure window means no separate baseline is needed.
bcast_query="min(sum by (instance) (increase(core_bcast_broadcast_total${excl}[${MEASURE_SECONDS}s])))"

# --- bring up the cluster ------------------------------------------------------
log "clean start + bring up cluster (setup -> relay -> 4x run -> prometheus)"
dc down -v --remove-orphans >/dev/null 2>&1 || true   # wipe any leftover state from a prior run
dc up -d --remove-orphans                             # -d = detached; compose depends_on handles ordering

# Wait for Prometheus to answer before we query it. $SECONDS is a bash built-in that
# counts seconds since the shell started; t0 snapshots it so (SECONDS - t0) = elapsed.
log "waiting for prometheus"
t0=$SECONDS
until curl -sf "$PROM/-/ready" >/dev/null 2>&1; do
  [ $((SECONDS - t0)) -ge 60 ] && { fail "prometheus not ready in 60s"; exit 1; }  # give up after 60s
  sleep 2
done

# Wait until the expected number of nodes report ready. app_monitoring_readyz==1 means
# "ready", so the PromQL count(...) is how many nodes match; loop until it hits
# READY_NODES (4 normally; 3 for node_down, where node0 is excluded from the count).
log "waiting for ${READY_NODES} nodes /readyz==1 (timeout ${READY_TIMEOUT}s)"
t0=$SECONDS
while :; do                                            # `while :` loops forever until an inner break
  ready=$(promsum "$ready_query")
  ge "$ready" "$READY_NODES" && break                  # expected nodes ready -> stop waiting
  if [ $((SECONDS - t0)) -ge "$READY_TIMEOUT" ]; then
    fail "only ${ready}/${READY_NODES} nodes ready after ${READY_TIMEOUT}s (see smoke-logs.txt)"
    exit 1
  fi
  sleep 3
done
log "${READY_NODES} nodes ready after $((SECONDS - t0))s"

# Duties fire at genesis (a PAST timestamp), so a node elected leader for an early slot
# may start consensus before the p2p mesh finishes forming -> a one-time cold-start
# "consensus timeout" ERROR. It's transient (the cluster recovers), but charon's Error
# Log Rate rule is monotonic (app_log_error_total > 0) and would trip forever. So we
# settle past cold-start, then BASELINE the error + broadcast counters here; the verdict
# judges only their GROWTH during the measured window.
[ "$WARMUP_SECONDS" -gt 0 ] && { log "warmup ${WARMUP_SECONDS}s (let cold-start settle)"; sleep "$WARMUP_SECONDS"; }
err_start=$(promq "$err_query")
if [ "$err_start" = ERR ]; then fail "error-counter baseline query failed (Prometheus unreachable?)"; exit 1; fi
# (broadcast liveness needs no baseline — bcast_query uses increase() over the window.)

# --- measure window ------------------------------------------------------------
# Poll firing alerts every 5s for the whole window and accumulate the distinct names.
# `end` is the wall-clock second to stop at; `seen` is the running sorted-unique union.
# Track poll outcomes so we can FAIL CLOSED if the alert API stops answering mid-run.
log "measuring ${MEASURE_SECONDS}s — polling alert oracle (rules.yml)"
end=$((SECONDS + MEASURE_SECONDS))
seen=""; polled_ok=0; poll_err=0
while [ "$SECONDS" -lt "$end" ]; do
  a=$(firing_alerts)
  if [ "$a" = "__POLL_ERR__" ]; then                   # alert API unreachable / bad response
    poll_err=$((poll_err + 1))
  else
    polled_ok=$((polled_ok + 1))
    # append this poll's alerts, strip blank lines, keep the union sorted + de-duped
    [ -n "$a" ] && seen=$(printf '%s\n%s' "$seen" "$a" | sed '/^$/d' | sort -u)
  fi
  sleep 5
done

echo
log "===== container states ====="
dc ps || true                                          # show which containers are up/exited (debugging aid)
echo

# --- verdict -------------------------------------------------------------------
# 1) CONTAINER SURVIVAL (charon's --abort-on-container-exit). A crashed survivor/relay/
#    prometheus is a hard failure the alert oracle can miss.
if ! containers_ok; then
  fail "long-running containers exited during the run (crash/OOM):${EXITED}"
  fail "logs: scripts/test-smoke/smoke-logs.txt"
  exit 1
fi

# 2) FAIL CLOSED on a broken monitor: if the alert API never answered, or stopped
#    answering mid-run, an empty alert set means "we couldn't see", NOT "healthy" (charon
#    does the same — compose.Auto errors when alerts can't be polled).
if [ "$polled_ok" -eq 0 ]; then
  fail "alert API never returned a valid response — cannot trust the verdict (Prometheus down?)"
  exit 1
fi
if [ "$poll_err" -gt 0 ]; then
  fail "alert API unreachable on ${poll_err}/$((polled_ok + poll_err)) polls — monitoring stack unhealthy"
  exit 1
fi

# 3) POSITIVE LIVENESS (per node): EVERY non-excluded node must broadcast duties during
#    the window. bcast_query is the MIN across instances of each instance's total (summed
#    over duty types) increase — so one silently-idle node can't hide behind the others'
#    growth (the "no alert fired" oracle's blind spot for an idle-but-up node). Replaces
#    the intent of the ignored, vmock-noisy Broadcast Duty Rate alert.
bcast_min=$(promq "$bcast_query")
if [ "$bcast_min" = ERR ]; then fail "broadcast query failed — cannot verify liveness"; exit 1; fi
if ! gt "$bcast_min" 0; then
  fail "a node broadcast no duties during the window — not every node is producing output (min per-node increase=${bcast_min})"
  fail "logs: scripts/test-smoke/smoke-logs.txt"
  exit 1
fi

# node_down is a LIVENESS / CHAOS check, not the full alert oracle (see the scenario
# comment): its vmock survivors log EXPECTED consensus-timeout errors under the node loss
# at 1s, which charon's real-VC 1_of_4_down does not. Container-survival (incl node0),
# quorum, and broadcast-liveness are gated above. SURFACE the survivor errors/alerts
# (never hide them) but don't fail on them here — full-oracle enforcement is the deferred
# real-VC lane.
if [ "$SCENARIO" = node_down ]; then
  errd=$(promq "$err_query")
  if [ "$errd" != ERR ] && gt "$errd" "$err_start"; then
    log "survivors logged errors under the node loss (EXPECTED on the vmock tier; informational, NOT gated): baseline=${err_start} now=${errd}"
  fi
  if [ -n "$seen" ]; then
    log "alerts firing on survivors (informational for node_down; full oracle = real-VC lane):"
    printf '%s\n' "$seen" | sed 's/^/       ~ /'
  fi
  pass "node_down: 3 survivors up + quorum ready + broadcasting, node0 up-but-isolated, no container crash — cluster survived node0 loss (liveness/chaos check)"
  exit 0
fi

# 4) ALERT ORACLE (non-fault scenarios). `Error Log Rate` is judged by a window-delta
#    (below), not the monotonic alert, so a one-time cold-start error doesn't fail a
#    healthy cluster. The rest are partitioned into fatal vs ignored (vmock noise).
#    Membership trick: wrap the ignore-list and each name in commas so ",A,B," contains
#    ",A," exactly (whole-name).
fatal="" ignored=""
while IFS= read -r a; do                               # read `seen` one line at a time
  [ -z "$a" ] && continue
  [ "$a" = "Error Log Rate" ] && continue              # handled by the error-growth check below
  if printf '%s' ",$IGNORE_ALERTS," | grep -qF ",$a,"; then
    ignored=$(printf '%s\n%s' "$ignored" "$a" | sed '/^$/d')
  else
    fatal=$(printf '%s\n%s' "$fatal" "$a" | sed '/^$/d')
  fi
done <<EOF
$seen
EOF

# Fatal only if the error counter GREW since err_start (errors during the window, not the
# pre-baseline cold-start blip). promq (not promsum) so a failed query fails CLOSED rather
# than reading as 0 = "no new errors" and hiding a real regression.
err_end=$(promq "$err_query")
if [ "$err_end" = ERR ]; then fail "error-counter verdict query failed — cannot verify Error Log Rate"; exit 1; fi
if gt "$err_end" "$err_start"; then
  fatal=$(printf '%s\n%s' "$fatal" "Error Log Rate (new errors during the window)" | sed '/^$/d')
fi

if [ -n "$ignored" ]; then
  log "ignored (vmock noise, not cluster faults):"
  printf '%s\n' "$ignored" | sed 's/^/       ~ /'
fi

# Any non-ignored firing alert = unhealthy cluster = fail.
if [ -n "$fatal" ]; then
  fail "alerts fired during the window (unhealthy cluster):"
  printf '%s\n' "$fatal" | sed 's/^/       - /'
  fail "logs: scripts/test-smoke/smoke-logs.txt"
  exit 1
fi
pass "no fatal alerts over ${MEASURE_SECONDS}s — ${READY_NODES} nodes healthy + broadcasting (TestSmoke analog OK)"
