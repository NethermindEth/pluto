#!/usr/bin/env bash
# verify-output.sh — Verifies that a DKG ceremony produced all expected files.
#
# Usage:
#   ./verify-output.sh
#
# Env:
#   WORK_DIR — scratch directory used by run.sh (default: /tmp/dkg-run).
#   NODES    — total number of nodes in the ceremony  (default: 4).
#
# Checks, for each node-${i} under ${WORK_DIR}/output:
#   - cluster-lock.json exists and is non-empty
#   - at least one keystore-*.json exists
#
# Exits 0 if every node passes, 1 otherwise. Failures are reported to stderr
# using the GitHub Actions ::error:: annotation format.

set -euo pipefail

WORK_DIR="${WORK_DIR:-/tmp/dkg-run}"
NODES="${NODES:-4}"
OUTPUT_DIR="${WORK_DIR}/output"

if [[ ! -d "${OUTPUT_DIR}" ]]; then
    echo "::error::output directory not found: ${OUTPUT_DIR}" >&2
    exit 1
fi

failures=0
for (( i = 0; i < NODES; i++ )); do
    node_dir="${OUTPUT_DIR}/node-${i}"

    if [[ ! -s "${node_dir}/cluster-lock.json" ]]; then
        echo "::error::node-${i}: missing or empty cluster-lock.json" >&2
        failures=$(( failures + 1 ))
    fi

    if ! compgen -G "${node_dir}/keystore-*.json" > /dev/null; then
        echo "::error::node-${i}: no keystore-*.json files" >&2
        failures=$(( failures + 1 ))
    fi
done

if (( failures > 0 )); then
    echo "::error::${failures} verification check(s) failed" >&2
    exit 1
fi

echo "All ${NODES} nodes produced cluster-lock.json and at least one keystore."
