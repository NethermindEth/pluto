#!/usr/bin/env bash
# setup.sh — Initialises WORK_DIR, generates per-node keys/ENRs, then creates
#             the cluster-definition.json via `charon create dkg`.
#
# Usage: ./setup.sh
#
# Reads configuration from config.sh (or the current environment).
# Safe to call multiple times: WORK_DIR is wiped and recreated on every call.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

echo "[setup] Removing old work directory (if any): ${WORK_DIR}"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

echo "[setup] Creating per-node data directories and generating ENRs"

enrs=()

# ── Pluto nodes (slots 0 .. PLUTO_NODES-1) ───────────────────────────────────
for i in $(seq 0 $(( PLUTO_NODES - 1 ))); do
    data_dir="${WORK_DIR}/node-${i}"
    mkdir -p "${data_dir}"

    echo "[setup]   Generating ENR for pluto node ${i} in ${data_dir}"
    # `pluto create enr` prints the ENR on a line starting with "enr:"
    enr=$("${PLUTO_BIN}" create enr --data-dir="${data_dir}" 2>&1 \
          | grep -E '^enr:' | head -1)
    if [[ -z "${enr}" ]]; then
        echo "[setup] ERROR: failed to capture ENR for pluto node ${i}" >&2
        exit 1
    fi
    echo "[setup]   pluto node ${i}: ${enr}"
    enrs+=("${enr}")
done

# ── Charon nodes (slots PLUTO_NODES .. NODES-1) ───────────────────────────────
for i in $(seq "${PLUTO_NODES}" $(( NODES - 1 ))); do
    data_dir="${WORK_DIR}/node-${i}"
    mkdir -p "${data_dir}"

    echo "[setup]   Generating ENR for charon node ${i} in ${data_dir}"
    # `charon create enr` prints the ENR on a line starting with "enr:"
    enr=$("${CHARON_BIN}" create enr --data-dir="${data_dir}" 2>&1 \
          | grep -E '^enr:' | head -1)
    if [[ -z "${enr}" ]]; then
        echo "[setup] ERROR: failed to capture ENR for charon node ${i}" >&2
        exit 1
    fi
    echo "[setup]   charon node ${i}: ${enr}"
    enrs+=("${enr}")
done

# ── Build comma-separated ENR list ───────────────────────────────────────────
IFS=',' enr_list="${enrs[*]}"
echo "[setup] Collected ${#enrs[@]} ENRs"

# ── Create cluster definition ─────────────────────────────────────────────────
# `charon create dkg --output-dir=DIR` writes cluster-definition.json directly
# into DIR (not into DIR/.charon/).
CHARON_DEF_FILE="${WORK_DIR}/cluster-definition.json"

echo "[setup] Running: ${CHARON_BIN} create dkg"
"${CHARON_BIN}" create dkg \
    --operator-enrs="${enr_list}" \
    --threshold="${THRESHOLD}" \
    --fee-recipient-addresses="${FEE_RECIPIENT}" \
    --withdrawal-addresses="${WITHDRAWAL_ADDR}" \
    --network="${NETWORK}" \
    --name=test-dkg \
    --output-dir="${WORK_DIR}"

if [[ ! -f "${CHARON_DEF_FILE}" ]]; then
    echo "[setup] ERROR: cluster-definition.json not found at ${CHARON_DEF_FILE}" >&2
    echo "[setup] Files in ${WORK_DIR}:" >&2
    ls -la "${WORK_DIR}" >&2
    exit 1
fi

echo "[setup] Done. Definition file: ${CHARON_DEF_FILE}"
