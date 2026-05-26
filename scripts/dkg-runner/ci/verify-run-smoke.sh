#!/usr/bin/env bash
# verify-run-smoke.sh — smoke-start collected DKG node dirs with `charon run`.
#
# Env:
#   WORK_DIR       scratch directory used by run.sh (default: /tmp/dkg-run)
#   NODES          total node count (default: 4)
#   CHARON_BIN     charon binary path/name (default: charon)
#   SMOKE_SECONDS  seconds allowed for monitoring endpoints to become ready
#                  (default: 8)
#   SMOKE_PORT_BASE
#                  first local port used by this check (default: 19000)
#
# This verifies the generated full node data dirs are loadable by a later
# Charon/Pluto-style runtime: cluster lock, p2p key, validator keystores, and
# passwords are all usable enough for the process to start.
#
# It does not prove real beacon duties. It uses Charon simnet mocks and kills
# the processes after every validator API reaches readiness.

set -euo pipefail

WORK_DIR="${WORK_DIR:-/tmp/dkg-run}"
NODES="${NODES:-4}"
CHARON_BIN="${CHARON_BIN:-charon}"
SMOKE_SECONDS="${SMOKE_SECONDS:-8}"
SMOKE_PORT_BASE="${SMOKE_PORT_BASE:-19000}"
SMOKE_DIR="${WORK_DIR}/run-smoke"

fail() {
    echo "::error::$*" >&2
    exit 1
}

log() {
    echo "[run-smoke] $*"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || [[ -x "$1" ]] || fail "missing required command: $1"
}

detect_keys_dir() {
    local node_dir="$1"
    shopt -s nullglob
    local flat_keys=("${node_dir}"/keystore-*.json)
    local nested_keys=("${node_dir}"/validator_keys/keystore-*.json)
    shopt -u nullglob

    if (( ${#flat_keys[@]} > 0 && ${#nested_keys[@]} > 0 )); then
        fail "mixed flat and validator_keys keystore layouts in ${node_dir}"
    fi

    if (( ${#nested_keys[@]} > 0 )); then
        printf '%s/validator_keys' "${node_dir}"
    else
        printf '%s' "${node_dir}"
    fi
}

tail_log() {
    local index="$1"
    local log_file="${SMOKE_DIR}/node-${index}.log"
    echo "::error::node-${index} smoke log tail:" >&2
    tail -80 "${log_file}" >&2 || true
}

kill_nodes() {
    for pid in "${pids[@]:-}"; do
        kill "${pid}" >/dev/null 2>&1 || true
    done
    for pid in "${pids[@]:-}"; do
        wait "${pid}" >/dev/null 2>&1 || true
    done
}

require_cmd "${CHARON_BIN}"
require_cmd curl
rm -rf "${SMOKE_DIR}"
mkdir -p "${SMOKE_DIR}"

pids=()
validator_urls=()
trap 'kill_nodes' EXIT INT TERM

for (( i = 0; i < NODES; i++ )); do
    node_dir="${WORK_DIR}/node-${i}"
    lock_file="${node_dir}/cluster-lock.json"
    key_file="${node_dir}/charon-enr-private-key"
    keys_dir="$(detect_keys_dir "${node_dir}")"
    log_file="${SMOKE_DIR}/node-${i}.log"

    [[ -d "${node_dir}" ]] || fail "node-${i}: missing data dir ${node_dir}"
    [[ -s "${lock_file}" ]] || fail "node-${i}: missing cluster-lock.json"
    [[ -s "${key_file}" ]] || fail "node-${i}: missing charon-enr-private-key"
    shopt -s nullglob
    keystores=("${keys_dir}"/keystore-*.json)
    shopt -u nullglob
    (( ${#keystores[@]} > 0 )) || fail "node-${i}: missing keystore json files in ${keys_dir}"

    for keystore in "${keystores[@]}"; do
        password="${keystore%.json}.txt"
        [[ -s "${password}" ]] || fail "node-${i}: missing password file for ${keystore}"
    done

    validator_port=$((SMOKE_PORT_BASE + i))
    monitoring_port=$((SMOKE_PORT_BASE + 100 + i))
    validator_urls+=("http://127.0.0.1:${validator_port}/eth/v1/node/version")

    log "starting node-${i}"
    "${CHARON_BIN}" run \
        --simnet-beacon-mock \
        --simnet-validator-mock \
        --lock-file="${lock_file}" \
        --private-key-file="${key_file}" \
        --simnet-validator-keys-dir="${keys_dir}" \
        --validator-api-address="127.0.0.1:${validator_port}" \
        --monitoring-address="127.0.0.1:${monitoring_port}" \
        --p2p-relays="" \
        --log-level=info \
        >"${log_file}" 2>&1 &
    pids+=("$!")
done

deadline=$((SECONDS + SMOKE_SECONDS))
ready=()
for (( i = 0; i < NODES; i++ )); do
    ready[i]=0
done

while (( SECONDS < deadline )); do
    all_ready=1
    for (( i = 0; i < NODES; i++ )); do
        pid="${pids[$i]}"
        if ! kill -0 "${pid}" >/dev/null 2>&1; then
            tail_log "${i}"
            fail "node-${i}: exited before validator API became ready"
        fi

        if (( ready[i] == 0 )); then
            if curl -fsS "${validator_urls[$i]}" >/dev/null 2>&1; then
                ready[i]=1
                log "node-${i} validator API ready"
            else
                all_ready=0
            fi
        fi
    done

    (( all_ready == 1 )) && break
    sleep 1
done

for (( i = 0; i < NODES; i++ )); do
    if (( ready[i] == 0 )); then
        tail_log "${i}"
        fail "node-${i}: validator API not ready after ${SMOKE_SECONDS}s"
    fi
done

log "all ${NODES} nodes reached validator API readiness"
