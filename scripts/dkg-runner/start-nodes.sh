#!/usr/bin/env bash
# start-nodes.sh — Launches Pluto and Charon DKG nodes as background processes.
#
# Usage: ./start-nodes.sh
#
# Slots 0 .. PLUTO_NODES-1  are started with the Pluto binary.
# Slots PLUTO_NODES .. NODES-1 are started with the Charon binary.
# All PIDs are appended to ${WORK_DIR}/pids.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

DEF_FILE="${WORK_DIR}/cluster-definition.json"
PID_FILE="${WORK_DIR}/pids"

if [[ ! -f "${DEF_FILE}" ]]; then
    echo "[start-nodes] ERROR: cluster-definition.json not found at ${DEF_FILE}" >&2
    echo "[start-nodes] Run setup.sh first." >&2
    exit 1
fi

# Truncate / create the PID file.
: > "${PID_FILE}"

start_node() {
    local index="${1}"
    local bin="${2}"
    local label="${3}"
    local data_dir="${WORK_DIR}/node-${index}"
    local log_file="${data_dir}/node.log"

    mkdir -p "${data_dir}"

    echo "[start-nodes] Starting ${label} node ${index} (bin: ${bin})"

    # Use process substitution so that $! captures the binary's PID rather than
    # tee's.  With `cmd > >(tee file) 2>&1 &`, the backgrounded job IS cmd and
    # tee runs inside the substitution as a child of the shell, so $! is cmd's PID.
    "${bin}" dkg \
        --definition-file="${DEF_FILE}" \
        --data-dir="${data_dir}" \
        --p2p-relays="${RELAY_URL}" \
        > >(tee "${log_file}") 2>&1 &
    echo "$!" >> "${PID_FILE}"
}

# Start Pluto nodes (slots 0 .. PLUTO_NODES-1)
for (( i = 0; i < PLUTO_NODES; i++ )); do
    start_node "${i}" "${PLUTO_BIN}" "pluto"
done

# Start Charon nodes (slots PLUTO_NODES .. NODES-1)
for (( i = PLUTO_NODES; i < NODES; i++ )); do
    start_node "${i}" "${CHARON_BIN}" "charon"
done

echo "[start-nodes] All ${NODES} nodes started. PIDs written to ${PID_FILE}"
