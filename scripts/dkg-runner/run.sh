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
#   RELAY_URL=https://relay.obol.tech
#                        Relay ENR endpoint used by charon create dkg.
#   TIMEOUT=120          Seconds to wait for all nodes before aborting.
#   PLUTO_BIN=./target/debug/pluto
#                        Path to the Pluto binary.
#   CHARON_BIN=charon    Path to the Charon binary.
#   WORK_DIR=/tmp/dkg-run
#                        Scratch directory for the run (wiped on every call).
#   KEEP_NODES=0         Leave nodes running after a successful ceremony when
#                        set to 1/true/yes.
#   NETWORK=holesky      Ethereum network for the cluster definition.
#   FEE_RECIPIENT=0xDeaD...
#                        Fee recipient address passed to charon create dkg.
#   WITHDRAWAL_ADDR=0xDeaD...
#                        Withdrawal address passed to charon create dkg.
#
# Exit codes:
#   0 — ceremony completed successfully; outputs collected under WORK_DIR/output
#   1 — ceremony failed or timed out; WORK_DIR has been cleaned up

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

# ── Argument handling ────────────────────────────────────────────────────────

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    grep '^#' "${BASH_SOURCE[0]}" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
fi

# ── Validation ───────────────────────────────────────────────────────────────

if (( PLUTO_NODES + CHARON_NODES != NODES )); then
    echo "[run] ERROR: PLUTO_NODES (${PLUTO_NODES}) + CHARON_NODES (${CHARON_NODES}) must equal NODES (${NODES})" >&2
    exit 1
fi

if (( THRESHOLD > NODES )); then
    echo "[run] ERROR: THRESHOLD (${THRESHOLD}) cannot exceed NODES (${NODES})" >&2
    exit 1
fi

# ── Cleanup handler ──────────────────────────────────────────────────────────

_cleanup() {
    local exit_code=$?
    echo ""
    echo "[run] Caught signal or error — cleaning up..."
    # reset.sh will kill processes and remove WORK_DIR.
    "${SCRIPT_DIR}/reset.sh" || true
    exit $(( exit_code == 0 ? 1 : exit_code ))
}

# Trap Ctrl-C (SIGINT), SIGTERM, and unexpected exits.
trap '_cleanup' INT TERM

# ── Main flow ────────────────────────────────────────────────────────────────

should_keep_nodes() {
    case "${KEEP_NODES}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

echo "[run] =============================================="
echo "[run] DKG runner starting"
echo "[run]   NODES        = ${NODES}"
echo "[run]   THRESHOLD    = ${THRESHOLD}"
echo "[run]   PLUTO_NODES  = ${PLUTO_NODES}"
echo "[run]   CHARON_NODES = ${CHARON_NODES}"
echo "[run]   RELAY_URL    = ${RELAY_URL}"
echo "[run]   NETWORK      = ${NETWORK}"
echo "[run]   TIMEOUT      = ${TIMEOUT}s"
echo "[run]   PLUTO_BIN    = ${PLUTO_BIN}"
echo "[run]   CHARON_BIN   = ${CHARON_BIN}"
echo "[run]   WORK_DIR     = ${WORK_DIR}"
echo "[run]   KEEP_NODES   = ${KEEP_NODES}"
echo "[run] =============================================="

echo "[run] --- Phase 1: Setup ---"
"${SCRIPT_DIR}/setup.sh"

echo "[run] --- Phase 2: Start nodes ---"
"${SCRIPT_DIR}/start-nodes.sh"

echo "[run] --- Phase 3: Monitor ---"
monitor_exit=0
"${SCRIPT_DIR}/monitor.sh" || monitor_exit=$?

if (( monitor_exit != 0 )); then
    echo "[run] ERROR: DKG ceremony did not complete within ${TIMEOUT}s." >&2
    echo "[run] Collecting partial outputs before cleanup..."
    "${SCRIPT_DIR}/collect.sh" || true
    echo "[run] Calling reset to kill nodes and clean up."
    "${SCRIPT_DIR}/reset.sh" || true
    # Disarm the EXIT trap so we don't double-cleanup.
    trap - INT TERM
    exit 1
fi

if should_keep_nodes; then
    echo "[run] --- Phase 4: Keep nodes running (ceremony complete) ---"
else
    echo "[run] --- Phase 4: Kill nodes (ceremony complete) ---"
    # Kill all nodes cleanly.  Nodes may already have exited on their own after
    # completing the ceremony, so we suppress errors here.
    PID_FILE="${WORK_DIR}/pids"
    if [[ -f "${PID_FILE}" ]]; then
        while IFS= read -r pid; do
            [[ -z "${pid}" ]] && continue
            if kill -0 "${pid}" 2>/dev/null; then
                kill -TERM "${pid}" 2>/dev/null || true
            fi
        done < "${PID_FILE}"
    fi
fi

echo "[run] --- Phase 5: Collect outputs ---"
"${SCRIPT_DIR}/collect.sh"

echo "[run] =============================================="
echo "[run] DKG ceremony completed successfully."
echo "[run] Outputs available in: ${WORK_DIR}/output"
if should_keep_nodes; then
    echo "[run] Node processes were left running. Use ./scripts/dkg-runner/reset.sh to stop them."
fi
echo "[run] =============================================="

# Disarm the trap before a clean exit.
trap - INT TERM
exit 0
