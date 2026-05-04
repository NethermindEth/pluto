#!/usr/bin/env bash
# start-nodes.sh — Launches Pluto and Charon DKG nodes as background processes.
#
# Usage: ./start-nodes.sh
#
# Slots 0 .. PLUTO_NODES-1   are started with the Pluto binary.
# Slots PLUTO_NODES .. NODES-1 are started with the Charon binary.
# Each node runs in its own process group; PGIDs are appended to ${WORK_DIR}/pids
# so reset.sh / run.sh can signal the whole tree on cleanup.
#
# Behaviour with CI=true: logs go to ${WORK_DIR}/node-N/node.log only (no tee
# to stdout).  Without CI, output is also tee'd to the controlling terminal.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="start-nodes"

DEF_FILE="${WORK_DIR}/cluster-definition.json"
PID_FILE="${WORK_DIR}/pids"

# ── Pre-flight ───────────────────────────────────────────────────────────────
require_bin "charon" "${CHARON_BIN}" || exit 1
if (( PLUTO_NODES > 0 )); then
    require_bin "pluto" "${PLUTO_BIN}" || exit 1
fi

if [[ ! -f "${DEF_FILE}" ]]; then
    log_err "cluster-definition.json not found at ${DEF_FILE}"
    log_err "Run setup.sh first."
    exit 1
fi

# Enable job control so each backgrounded job runs in its own process group.
# With monitor mode on, $! is the leader's PID and equals the new PGID, which
# lets us signal the whole tree (including any descendants the binary spawns)
# via `kill -- -PGID` in reset.sh / run.sh.
set -m

: > "${PID_FILE}"

start_node() {
    local index="${1}"
    local bin="${2}"
    local label="${3}"
    local data_dir="${WORK_DIR}/node-${index}"
    local log_file="${data_dir}/node.log"

    mkdir -p "${data_dir}"
    log_info "Starting ${label} node ${index} (bin: ${bin})"

    if is_ci; then
        # Quiet path for CI: write to log file only.
        "${bin}" dkg \
            --definition-file="${DEF_FILE}" \
            --data-dir="${data_dir}" \
            --p2p-relays="${RELAY_URL}" \
            > "${log_file}" 2>&1 &
    else
        # Interactive path: tee to log file and the terminal.
        "${bin}" dkg \
            --definition-file="${DEF_FILE}" \
            --data-dir="${data_dir}" \
            --p2p-relays="${RELAY_URL}" \
            > >(tee "${log_file}") 2>&1 &
    fi

    echo "$!" >> "${PID_FILE}"
}

for (( i = 0; i < PLUTO_NODES; i++ )); do
    start_node "${i}" "${PLUTO_BIN}" "pluto"
done

for (( i = PLUTO_NODES; i < NODES; i++ )); do
    start_node "${i}" "${CHARON_BIN}" "charon"
done

log_info "All ${NODES} nodes started. PGIDs written to ${PID_FILE}"
