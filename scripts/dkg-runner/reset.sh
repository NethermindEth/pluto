#!/usr/bin/env bash
# reset.sh — Kills all running node processes and removes WORK_DIR.
#
# Usage: ./reset.sh
#
# Reads PIDs from ${WORK_DIR}/pids and sends SIGTERM (then SIGKILL after a
# short grace period) to each process group.  Finally removes WORK_DIR.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

PID_FILE="${WORK_DIR}/pids"
GRACE_PERIOD=5  # seconds before escalating to SIGKILL

if [[ -f "${PID_FILE}" ]]; then
    echo "[reset] Stopping node processes listed in ${PID_FILE}"
    while IFS= read -r pid; do
        [[ -z "${pid}" ]] && continue

        if kill -0 "${pid}" 2>/dev/null; then
            echo "[reset]   SIGTERM -> PID ${pid}"
            kill -TERM "${pid}" 2>/dev/null || true
        else
            echo "[reset]   PID ${pid} is not running (skipping)"
        fi
    done < "${PID_FILE}"

    # Wait for processes to exit gracefully.
    sleep "${GRACE_PERIOD}"

    # Escalate to SIGKILL for any survivors.
    while IFS= read -r pid; do
        [[ -z "${pid}" ]] && continue

        if kill -0 "${pid}" 2>/dev/null; then
            echo "[reset]   SIGKILL -> PID ${pid} (did not exit in time)"
            kill -KILL "${pid}" 2>/dev/null || true
        fi
    done < "${PID_FILE}"
else
    echo "[reset] No PID file found at ${PID_FILE} — nothing to kill"
fi

echo "[reset] Removing work directory: ${WORK_DIR}"
rm -rf "${WORK_DIR}"
echo "[reset] Done."
