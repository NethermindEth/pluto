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

OUTPUT_DIR="${WORK_DIR}/output"
mkdir -p "${OUTPUT_DIR}"

echo "[collect] Collecting outputs into ${OUTPUT_DIR}"

nodes_with_keystores=()
nodes_without_keystores=()
nodes_with_lock=()
nodes_without_lock=()

for i in $(seq 0 $(( NODES - 1 ))); do
    node_dir="${WORK_DIR}/node-${i}"
    node_label="node-${i}"
    node_out="${OUTPUT_DIR}/${node_label}"
    mkdir -p "${node_out}"

    # Collect keystore files.
    # Pluto writes them to validator_keys/keystore-*.json inside the data dir.
    # Charon writes them directly to the data dir as keystore-*.json.
    keystore_count=0

    # Check Pluto-style location first.
    if compgen -G "${node_dir}/validator_keys/keystore-*.json" > /dev/null 2>&1; then
        cp "${node_dir}"/validator_keys/keystore-*.json "${node_out}/"
        keystore_count=$(ls "${node_dir}"/validator_keys/keystore-*.json 2>/dev/null | wc -l | tr -d ' ')
    fi

    # Also check Charon-style location (top-level of data dir).
    if compgen -G "${node_dir}/keystore-*.json" > /dev/null 2>&1; then
        cp "${node_dir}"/keystore-*.json "${node_out}/"
        keystore_count=$(( keystore_count + $(ls "${node_dir}"/keystore-*.json 2>/dev/null | wc -l | tr -d ' ') ))
    fi

    if (( keystore_count > 0 )); then
        nodes_with_keystores+=("${node_label} (${keystore_count} keystore(s))")
    else
        nodes_without_keystores+=("${node_label}")
    fi

    # Collect cluster-lock.json.
    if [[ -f "${node_dir}/cluster-lock.json" ]]; then
        cp "${node_dir}/cluster-lock.json" "${node_out}/cluster-lock.json"
        nodes_with_lock+=("${node_label}")
    else
        nodes_without_lock+=("${node_label}")
    fi
done

echo ""
echo "[collect] === Summary ==="

echo "[collect] Nodes WITH keystores (${#nodes_with_keystores[@]}):"
for entry in "${nodes_with_keystores[@]+"${nodes_with_keystores[@]}"}"; do
    echo "            ${entry}"
done

if (( ${#nodes_without_keystores[@]} > 0 )); then
    echo "[collect] Nodes WITHOUT keystores (${#nodes_without_keystores[@]}):"
    for entry in "${nodes_without_keystores[@]}"; do
        echo "            ${entry}"
    done
fi

echo "[collect] Nodes WITH cluster-lock (${#nodes_with_lock[@]}):"
for entry in "${nodes_with_lock[@]+"${nodes_with_lock[@]}"}"; do
    echo "            ${entry}"
done

if (( ${#nodes_without_lock[@]} > 0 )); then
    echo "[collect] Nodes WITHOUT cluster-lock (${#nodes_without_lock[@]}):"
    for entry in "${nodes_without_lock[@]}"; do
        echo "            ${entry}"
    done
fi

echo "[collect] Output directory: ${OUTPUT_DIR}"
