#!/usr/bin/env bash
# reset.sh — Kills all running node process groups and removes WORK_DIR.
#
# Usage: ./reset.sh
#
# Reads PGIDs from ${WORK_DIR}/pids and signals the whole process group of each
# node (SIGTERM, then SIGKILL after a short grace period).  Finally removes
# WORK_DIR.  This is the explicit cleanup tool — run.sh does not call it on
# failure, so partial outputs are preserved for debugging until you ask for
# them to be wiped.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="reset"

PID_FILE="${WORK_DIR}/pids"
GRACE_PERIOD=5

if [[ -f "${PID_FILE}" ]]; then
    log_info "Stopping node process groups listed in ${PID_FILE}"
    kill_pgids "${PID_FILE}" "${GRACE_PERIOD}"
else
    log_info "No PID file at ${PID_FILE} — nothing to kill"
fi

if [[ -d "${WORK_DIR}" ]]; then
    log_info "Removing work directory: ${WORK_DIR}"
    rm -rf "${WORK_DIR}"
fi
log_info "Done."
