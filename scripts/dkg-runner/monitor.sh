#!/usr/bin/env bash
# monitor.sh — Polls node logs for DKG ceremony completion.
#
# Usage: ./monitor.sh
#
# Exit codes:
#   0 — all nodes reported completion within TIMEOUT seconds
#   1 — timed out before all nodes completed
#
# Compatible with bash 3.2+ (macOS default shell).
# Uses per-node sentinel files instead of associative arrays.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

# Sentinel directory — one file per completed node.
DONE_DIR="${WORK_DIR}/.done"
mkdir -p "${DONE_DIR}"

# Patterns that indicate a node finished successfully.
COMPLETION_PATTERN='[Dd][Kk][Gg].*[Cc]omplete\|[Ss]hare.*[Cc]reated\|[Kk]eyshare\|[Cc]eremony.*[Cc]omplete\|[Kk]ey.*[Ss]hares.*[Ss]aved\|wrote.*keystore'

# Patterns that indicate trouble (printed as warnings; we do not exit on them).
ERROR_PATTERN='ERRO\|FATAL\|panic'

POLL_INTERVAL=3  # seconds between scans

echo "[monitor] Waiting for ${NODES} nodes to complete (timeout: ${TIMEOUT}s)"

start_time="${SECONDS}"

while true; do
    elapsed=$(( SECONDS - start_time ))

    if (( elapsed >= TIMEOUT )); then
        done_count=$(ls -1 "${DONE_DIR}" 2>/dev/null | wc -l | tr -d ' ')
        echo "[monitor] TIMEOUT after ${elapsed}s — ${done_count}/${NODES} nodes completed." >&2
        exit 1
    fi

    for i in $(seq 0 $(( NODES - 1 ))); do
        sentinel="${DONE_DIR}/node-${i}"
        node_dir="${WORK_DIR}/node-${i}"
        log="${node_dir}/node.log"

        # Already done — skip.
        [[ -f "${sentinel}" ]] && continue
        [[ -f "${log}" ]] || continue

        if grep -q "${COMPLETION_PATTERN}" "${log}" 2>/dev/null; then
            touch "${sentinel}"
            done_count=$(ls -1 "${DONE_DIR}" 2>/dev/null | wc -l | tr -d ' ')
            echo "[monitor] Node ${i} completed (${done_count}/${NODES})"
        fi

        # Print error lines as warnings (non-fatal).
        grep "${ERROR_PATTERN}" "${log}" 2>/dev/null | tail -3 | while IFS= read -r line; do
            echo "[monitor] WARN [node-${i}]: ${line}"
        done || true
    done

    done_count=$(ls -1 "${DONE_DIR}" 2>/dev/null | wc -l | tr -d ' ')
    if (( done_count >= NODES )); then
        echo "[monitor] All ${NODES} nodes completed successfully."
        exit 0
    fi

    echo "[monitor] ${done_count}/${NODES} nodes done (${elapsed}s elapsed)"
    sleep "${POLL_INTERVAL}"
done
