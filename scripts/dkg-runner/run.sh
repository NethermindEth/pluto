#!/usr/bin/env bash
# run.sh — Orchestrates a complete DKG ceremony with Pluto and/or Charon nodes.
#
# Usage:
#   ./run.sh [--help]
#
# Environment variables (all optional; defaults shown):
#   NODES=4              Total number of nodes in the ceremony.
#   THRESHOLD=3          Signing threshold (min shares required to reconstruct).
#   PLUTO_NODES=2        How many of the NODES slots use the Pluto binary.
#   CHARON_NODES=2       How many of the NODES slots use the Charon binary.
#   RELAY_URL=https://pluto-relay-0.ovh.dev-nethermind.xyz
#                        Relay ENR endpoint used by the DKG nodes.
#   TIMEOUT=120          Seconds to wait for all nodes before aborting.
#   SHUTDOWN_DELAY=120s Graceful shutdown delay passed to each node.
#   NODE_EXIT_TIMEOUT=180
#                        Seconds to wait for nodes to exit after completion.
#   PLUTO_BIN=./target/debug/pluto
#                        Path to the Pluto binary.
#   CHARON_BIN=charon    Path to the Charon binary.
#   WORK_DIR=/tmp/dkg-run
#                        Scratch directory for the run (wiped on every call).
#   KEEP_NODES=0         Leave nodes running after a successful ceremony when
#                        set to 1/true/yes/on.
#   RUN_SMOKE_VERIFY=1   Smoke-start generated node dirs with charon run after
#                        successful output collection.
#   SMOKE_SECONDS=8      Seconds to wait for smoke validator APIs to become ready.
#   SMOKE_PORT_BASE=19000
#                        First local port used by runtime smoke verification.
#   NETWORK=holesky      Ethereum network for the cluster definition.
#   FEE_RECIPIENT=0xDeaD...
#                        Fee recipient address passed to pluto create dkg.
#   WITHDRAWAL_ADDR=0xDeaD...
#                        Withdrawal address passed to pluto create dkg.
#   CI=                  When truthy (1/true/yes/on), suppress per-node tee
#                        to stdout; logs land only in WORK_DIR/node-*/node.log.
#
# Exit codes:
#   0   — ceremony completed; outputs collected under WORK_DIR/output.
#   1   — ceremony failed or timed out; WORK_DIR is preserved for debugging.
#   130 — interrupted (SIGINT/SIGTERM); WORK_DIR is preserved.
#
# WORK_DIR is never deleted by run.sh.  Use ./reset.sh when you're done.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="run"

# ── Argument handling ────────────────────────────────────────────────────────

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    grep '^#' "${BASH_SOURCE[0]}" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
fi

# ── Validation ───────────────────────────────────────────────────────────────

if (( PLUTO_NODES + CHARON_NODES != NODES )); then
    log_err "PLUTO_NODES (${PLUTO_NODES}) + CHARON_NODES (${CHARON_NODES}) must equal NODES (${NODES})"
    exit 1
fi

if (( THRESHOLD > NODES )); then
    log_err "THRESHOLD (${THRESHOLD}) cannot exceed NODES (${NODES})"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    log_err "jq is required for semantic output verification"
    exit 1
fi

if ! type -t compgen >/dev/null 2>&1; then
    log_err "compgen builtin is required (bash must be built with programmable completion)"
    exit 1
fi

if is_truthy "${RUN_SMOKE_VERIFY}" && ! command -v curl >/dev/null 2>&1; then
    log_err "curl is required for runtime smoke verification"
    exit 1
fi

# ── Cleanup helpers ──────────────────────────────────────────────────────────

PID_FILE="${WORK_DIR}/pids"

_kill_nodes() {
    kill_pgids "${PID_FILE}" 5
}

_on_signal() {
    log_warn "Caught signal — killing nodes (work dir preserved at ${WORK_DIR})"
    _kill_nodes || true
    exit 130
}

trap '_on_signal' INT TERM

# ── Main flow ────────────────────────────────────────────────────────────────

log_info "=============================================="
log_info "DKG runner starting"
log_info "  NODES        = ${NODES}"
log_info "  THRESHOLD    = ${THRESHOLD}"
log_info "  PLUTO_NODES  = ${PLUTO_NODES}"
log_info "  CHARON_NODES = ${CHARON_NODES}"
log_info "  RELAY_URL    = ${RELAY_URL}"
log_info "  NETWORK      = ${NETWORK}"
log_info "  TIMEOUT      = ${TIMEOUT}s"
log_info "  SHUTDOWN_DELAY = ${SHUTDOWN_DELAY}"
log_info "  NODE_EXIT_TIMEOUT = ${NODE_EXIT_TIMEOUT}s"
log_info "  PLUTO_BIN    = ${PLUTO_BIN}"
log_info "  CHARON_BIN   = ${CHARON_BIN}"
log_info "  WORK_DIR     = ${WORK_DIR}"
log_info "  KEEP_NODES   = ${KEEP_NODES}"
log_info "  RUN_SMOKE_VERIFY = ${RUN_SMOKE_VERIFY}"
log_info "  SMOKE_PORT_BASE = ${SMOKE_PORT_BASE}"
log_info "  CI           = ${CI:-}"
log_info "=============================================="

log_info "--- Phase 1: Setup ---"
"${SCRIPT_DIR}/setup.sh"

log_info "--- Phase 2: Start nodes ---"
"${SCRIPT_DIR}/start-nodes.sh"

log_info "--- Phase 3: Monitor ---"
monitor_exit=0
"${SCRIPT_DIR}/monitor.sh" || monitor_exit=$?

if (( monitor_exit != 0 )); then
    log_err "DKG ceremony did not complete within ${TIMEOUT}s."
    log_info "Killing nodes and collecting partial outputs..."
    _kill_nodes || true
    "${SCRIPT_DIR}/collect.sh" || true
    log_info "Work dir preserved at ${WORK_DIR}. Run ${SCRIPT_DIR}/reset.sh to remove it."
    trap - INT TERM
    exit 1
fi

if is_truthy "${KEEP_NODES}"; then
    log_info "--- Phase 4: Keep nodes running (ceremony complete) ---"
else
    log_info "--- Phase 4: Wait for clean node exits ---"
    wait_exit=0
    "${SCRIPT_DIR}/wait-node-exits.sh" || wait_exit=$?
    if (( wait_exit != 0 )); then
        log_err "One or more nodes exited unsuccessfully after producing artifacts."
        _kill_nodes || true
        "${SCRIPT_DIR}/collect.sh" || true
        log_info "Work dir preserved at ${WORK_DIR}. Run ${SCRIPT_DIR}/reset.sh to remove it."
        trap - INT TERM
        exit 1
    fi
fi

log_info "--- Phase 5: Collect outputs ---"
"${SCRIPT_DIR}/collect.sh"

log_info "--- Phase 6: Verify semantic outputs ---"
"${SCRIPT_DIR}/ci/verify-output-semantic.sh"

if is_truthy "${RUN_SMOKE_VERIFY}"; then
    log_info "--- Phase 7: Smoke-start runtime outputs ---"
    "${SCRIPT_DIR}/ci/verify-run-smoke.sh"
fi

log_info "=============================================="
log_info "DKG ceremony completed successfully."
log_info "Outputs available in: ${WORK_DIR}/output"
log_info "Run ${SCRIPT_DIR}/reset.sh to clean up."
if is_truthy "${KEEP_NODES}"; then
    log_info "Node processes were left running."
fi
log_info "=============================================="

trap - INT TERM
exit 0
