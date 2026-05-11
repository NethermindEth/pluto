#!/usr/bin/env bash
# wait-node-exits.sh — waits for every DKG node to report a clean exit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="wait-node-exits"

log_tail() {
    local index="${1}"
    local log_file="${WORK_DIR}/node-${index}/node.log"
    if [[ -f "${log_file}" ]]; then
        log_err "Last log lines for node-${index}:"
        tail -40 "${log_file}" >&2 || true
    else
        log_err "No log file for node-${index}: ${log_file}"
    fi
}

node_exit_code() {
    local index="${1}"
    local exit_file="${WORK_DIR}/node-${index}/exit-code"
    [[ -f "${exit_file}" ]] || return 1
    cat "${exit_file}"
}

log_info "Waiting for ${NODES} node exit codes (timeout: ${NODE_EXIT_TIMEOUT}s)"

start_time=$(date +%s)
while true; do
    done_count=0
    for (( i = 0; i < NODES; i++ )); do
        if [[ -f "${WORK_DIR}/node-${i}/exit-code" ]]; then
            done_count=$(( done_count + 1 ))
            code=$(node_exit_code "${i}")
            if [[ "${code}" != "0" ]]; then
                log_err "node-${i} exited with status ${code}"
                log_tail "${i}"
                exit 1
            fi
        fi
    done

    if (( done_count == NODES )); then
        break
    fi

    elapsed=$(( $(date +%s) - start_time ))
    if (( elapsed >= NODE_EXIT_TIMEOUT )); then
        log_err "TIMEOUT after ${elapsed}s — ${done_count}/${NODES} nodes exited"
        for (( i = 0; i < NODES; i++ )); do
            [[ -f "${WORK_DIR}/node-${i}/exit-code" ]] || log_tail "${i}"
        done
        exit 1
    fi

    sleep 1
done

failed=0
for (( i = 0; i < NODES; i++ )); do
    code=$(node_exit_code "${i}")
    if [[ "${code}" != "0" ]]; then
        log_err "node-${i} exited with status ${code}"
        log_tail "${i}"
        failed=1
    fi
done

if (( failed != 0 )); then
    exit 1
fi

log_info "All ${NODES} nodes exited cleanly."
