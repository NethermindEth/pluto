#!/usr/bin/env bash
# collect.sh — Gathers keystore and cluster-lock files from node directories.
#
# Usage: ./collect.sh
#
# Copies keystore-*.json and cluster-lock.json from each node data directory
# into ${WORK_DIR}/output/, then prints a summary of which nodes produced
# outputs and which did not.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="collect"

OUTPUT_DIR="${WORK_DIR}/output"
mkdir -p "${OUTPUT_DIR}"

log_info "Collecting outputs into ${OUTPUT_DIR}"

nodes_with_keystores=()
nodes_without_keystores=()
nodes_with_lock=()
nodes_without_lock=()

for (( i = 0; i < NODES; i++ )); do
    node_dir="${WORK_DIR}/node-${i}"
    node_label="node-${i}"
    node_out="${OUTPUT_DIR}/${node_label}"
    mkdir -p "${node_out}"

    # Pluto writes keystores under validator_keys/, Charon writes them flat
    # in the data dir.  Handle both layouts.
    keystore_count=0

    if compgen -G "${node_dir}/validator_keys/keystore-*.json" > /dev/null 2>&1; then
        cp "${node_dir}"/validator_keys/keystore-*.json "${node_out}/"
        keystore_count=$(ls "${node_dir}"/validator_keys/keystore-*.json 2>/dev/null | wc -l | tr -d ' ')
    fi

    if compgen -G "${node_dir}/keystore-*.json" > /dev/null 2>&1; then
        cp "${node_dir}"/keystore-*.json "${node_out}/"
        keystore_count=$(( keystore_count + $(ls "${node_dir}"/keystore-*.json 2>/dev/null | wc -l | tr -d ' ') ))
    fi

    if (( keystore_count > 0 )); then
        nodes_with_keystores+=("${node_label} (${keystore_count} keystore(s))")
    else
        nodes_without_keystores+=("${node_label}")
    fi

    if [[ -f "${node_dir}/cluster-lock.json" ]]; then
        cp "${node_dir}/cluster-lock.json" "${node_out}/cluster-lock.json"
        nodes_with_lock+=("${node_label}")
    else
        nodes_without_lock+=("${node_label}")
    fi
done

# `${arr[@]+"${arr[@]}"}` is the canonical guard for safely expanding an array
# under `set -u` when it might be empty.

echo ""
log_info "=== Summary ==="
log_info "Nodes WITH keystores (${#nodes_with_keystores[@]}):"
for entry in ${nodes_with_keystores[@]+"${nodes_with_keystores[@]}"}; do
    log_info "            ${entry}"
done

if (( ${#nodes_without_keystores[@]} > 0 )); then
    log_info "Nodes WITHOUT keystores (${#nodes_without_keystores[@]}):"
    for entry in "${nodes_without_keystores[@]}"; do
        log_info "            ${entry}"
    done
fi

log_info "Nodes WITH cluster-lock (${#nodes_with_lock[@]}):"
for entry in ${nodes_with_lock[@]+"${nodes_with_lock[@]}"}; do
    log_info "            ${entry}"
done

if (( ${#nodes_without_lock[@]} > 0 )); then
    log_info "Nodes WITHOUT cluster-lock (${#nodes_without_lock[@]}):"
    for entry in "${nodes_without_lock[@]}"; do
        log_info "            ${entry}"
    done
fi

log_info "Output directory: ${OUTPUT_DIR}"
