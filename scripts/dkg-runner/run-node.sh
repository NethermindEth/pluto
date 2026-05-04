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
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="run-node"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    grep '^#' "${BASH_SOURCE[0]}" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
fi

if [[ $# -ne 2 ]]; then
    log_err "expected exactly 2 arguments: <node-index> <pluto|charon>"
    exit 1
fi

NODE_INDEX="${1}"
NODE_KIND="${2}"
DEF_FILE="${WORK_DIR}/cluster-definition.json"
DATA_DIR="${WORK_DIR}/node-${NODE_INDEX}"
LOG_FILE="${DATA_DIR}/node.log"

if ! [[ "${NODE_INDEX}" =~ ^[0-9]+$ ]]; then
    log_err "node-index must be a non-negative integer"
    exit 1
fi

if (( NODE_INDEX < 0 || NODE_INDEX >= NODES )); then
    log_err "node-index (${NODE_INDEX}) must be in range 0..$(( NODES - 1 ))"
    exit 1
fi

if [[ ! -f "${DEF_FILE}" ]]; then
    log_err "cluster-definition.json not found at ${DEF_FILE}"
    if find "${WORK_DIR}" -maxdepth 1 -type d -name 'node-*' 2>/dev/null | grep -q .; then
        log_err "setup appears incomplete or interrupted."
        log_err "setup.sh must finish all ENR generation before run-node.sh can be used."
    else
        log_err "Run ./scripts/dkg-runner/setup.sh first."
    fi
    exit 1
fi

if [[ ! -d "${DATA_DIR}" ]]; then
    log_err "node data directory not found at ${DATA_DIR}"
    log_err "Run ./scripts/dkg-runner/setup.sh first."
    exit 1
fi

case "${NODE_KIND}" in
    pluto)  BIN="${PLUTO_BIN}" ;;
    charon) BIN="${CHARON_BIN}" ;;
    *)
        log_err "node kind must be 'pluto' or 'charon'"
        exit 1
        ;;
esac

require_bin "${NODE_KIND}" "${BIN}" || exit 1

log_info "=============================================="
log_info "Starting single DKG node"
log_info "  NODE_INDEX = ${NODE_INDEX}"
log_info "  NODE_KIND  = ${NODE_KIND}"
log_info "  BIN        = ${BIN}"
log_info "  DEF_FILE   = ${DEF_FILE}"
log_info "  DATA_DIR   = ${DATA_DIR}"
log_info "  LOG_FILE   = ${LOG_FILE}"
log_info "=============================================="

"${BIN}" dkg \
    --definition-file="${DEF_FILE}" \
    --data-dir="${DATA_DIR}" \
    --p2p-relays="${RELAY_URL}" \
    2>&1 | tee "${LOG_FILE}"
