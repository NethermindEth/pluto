#!/usr/bin/env bash
# monitor.sh — Waits for cluster-lock.json to appear in every node's data dir.
#
# Usage: ./monitor.sh
#
# Completion is detected by the existence of the canonical DKG output
# (cluster-lock.json) in each node's data directory — the artifact that
# collect.sh ultimately copies out.  This is independent of log formatting
# and survives differences between Charon and Pluto.
#
# Exit codes:
#   0 — every node produced cluster-lock.json before TIMEOUT.
#   1 — timed out; the tail of each node log is dumped to stderr for CI debug.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="monitor"

POLL_INTERVAL=2
TAIL_LINES=30

log_info "Waiting for ${NODES} nodes (timeout: ${TIMEOUT}s)"
log_info "Completion = cluster-lock.json AND keystore-*.json present in ${WORK_DIR}/node-*/"

# A node is done when both cluster-lock.json and at least one keystore are
# present. Pluto writes keystores under validator_keys/, Charon writes them
# flat in the data dir — accept either layout.
node_done() {
    local node_dir="${1}"
    [[ -f "${node_dir}/cluster-lock.json" ]] || return 1
    compgen -G "${node_dir}/validator_keys/keystore-*.json" > /dev/null 2>&1 \
        || compgen -G "${node_dir}/keystore-*.json" > /dev/null 2>&1
}

start_time="${SECONDS}"
last_count=-1

while true; do
    elapsed=$(( SECONDS - start_time ))
    done_count=0
    for (( i = 0; i < NODES; i++ )); do
        if node_done "${WORK_DIR}/node-${i}"; then
            done_count=$(( done_count + 1 ))
        fi
    done

    if (( done_count >= NODES )); then
        log_info "All ${NODES} nodes completed (${elapsed}s)"
        exit 0
    fi

    if (( elapsed >= TIMEOUT )); then
        log_err "TIMEOUT after ${elapsed}s — ${done_count}/${NODES} nodes completed"
        for (( i = 0; i < NODES; i++ )); do
            log_path="${WORK_DIR}/node-${i}/node.log"
            if [[ -f "${log_path}" ]]; then
                printf '\n[monitor] === tail -n %d node-%d/node.log ===\n' \
                    "${TAIL_LINES}" "${i}" >&2
                tail -n "${TAIL_LINES}" "${log_path}" >&2 || true
            else
                printf '\n[monitor] === node-%d/node.log: missing ===\n' "${i}" >&2
            fi
        done
        exit 1
    fi

    # Only print progress when the count changes — keeps CI logs tidy.
    if (( done_count != last_count )); then
        log_info "${done_count}/${NODES} nodes done (${elapsed}s elapsed)"
        last_count="${done_count}"
    fi
    sleep "${POLL_INTERVAL}"
done
