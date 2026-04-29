#!/usr/bin/env bash
# run-node.sh — Runs a single DKG node in the foreground.
#
# Usage:
#   ./run-node.sh <node-index> <pluto|charon>
#   ./run-node.sh 0 charon
#   ./run-node.sh 1 pluto
#
# Prerequisite:
#   setup.sh must already have created WORK_DIR/cluster-definition.json and the
#   per-node data directories / ENR keys.
#
# Environment variables (all optional; defaults shown):
#   Same as config.sh, notably:
#   PLUTO_BIN=./target/debug/pluto
#   CHARON_BIN=charon
#   WORK_DIR=/tmp/dkg-run
#   RELAY_URL=https://0.relay.obol.tech

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    grep '^#' "${BASH_SOURCE[0]}" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
fi

if [[ $# -ne 2 ]]; then
    echo "[run-node] ERROR: expected exactly 2 arguments: <node-index> <pluto|charon>" >&2
    exit 1
fi

NODE_INDEX="${1}"
NODE_KIND="${2}"
DEF_FILE="${WORK_DIR}/cluster-definition.json"
DATA_DIR="${WORK_DIR}/node-${NODE_INDEX}"
LOG_FILE="${DATA_DIR}/node.log"

if ! [[ "${NODE_INDEX}" =~ ^[0-9]+$ ]]; then
    echo "[run-node] ERROR: node-index must be a non-negative integer" >&2
    exit 1
fi

if (( NODE_INDEX < 0 || NODE_INDEX >= NODES )); then
    echo "[run-node] ERROR: node-index (${NODE_INDEX}) must be in range 0..$(( NODES - 1 ))" >&2
    exit 1
fi

if [[ ! -f "${DEF_FILE}" ]]; then
    echo "[run-node] ERROR: cluster-definition.json not found at ${DEF_FILE}" >&2
    if find "${WORK_DIR}" -maxdepth 1 -type d -name 'node-*' 2>/dev/null | grep -q .; then
        echo "[run-node] setup appears incomplete or interrupted." >&2
        echo "[run-node] setup.sh must finish all ENR generation and print 'Done. Definition file: ...' before run-node.sh can be used." >&2
    else
        echo "[run-node] Run ./scripts/dkg-runner/setup.sh first." >&2
    fi
    exit 1
fi

if [[ ! -d "${DATA_DIR}" ]]; then
    echo "[run-node] ERROR: node data directory not found at ${DATA_DIR}" >&2
    echo "[run-node] Run ./scripts/dkg-runner/setup.sh first." >&2
    exit 1
fi

case "${NODE_KIND}" in
    pluto)
        BIN="${PLUTO_BIN}"
        ;;
    charon)
        BIN="${CHARON_BIN}"
        ;;
    *)
        echo "[run-node] ERROR: node kind must be 'pluto' or 'charon'" >&2
        exit 1
        ;;
esac

mkdir -p "${DATA_DIR}"

echo "[run-node] =============================================="
echo "[run-node] Starting single DKG node"
echo "[run-node]   NODE_INDEX = ${NODE_INDEX}"
echo "[run-node]   NODE_KIND  = ${NODE_KIND}"
echo "[run-node]   BIN        = ${BIN}"
echo "[run-node]   DEF_FILE   = ${DEF_FILE}"
echo "[run-node]   DATA_DIR   = ${DATA_DIR}"
echo "[run-node]   LOG_FILE   = ${LOG_FILE}"
echo "[run-node] =============================================="

exec "${BIN}" dkg \
    --definition-file="${DEF_FILE}" \
    --data-dir="${DATA_DIR}" \
    --p2p-relays="${RELAY_URL}" \
    2>&1 | tee "${LOG_FILE}"
