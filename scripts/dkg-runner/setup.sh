#!/usr/bin/env bash
# setup.sh — Initialises WORK_DIR, generates per-node keys/ENRs, then creates
#             the cluster-definition.json via `pluto create dkg`.
#
# Usage: ./setup.sh
#
# Reads configuration from config.sh (or the current environment).
# Safe to call multiple times: WORK_DIR is wiped and recreated on every call.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="setup"

# ── Pre-flight ───────────────────────────────────────────────────────────────
# pluto is always required (used for `create dkg`).
# charon is required only when at least one slot uses it.
require_bin "pluto" "${PLUTO_BIN}" || exit 1
if (( CHARON_NODES > 0 )); then
    require_bin "charon" "${CHARON_BIN}" || exit 1
fi

# ── Wipe & recreate WORK_DIR ─────────────────────────────────────────────────
log_info "Removing old work directory (if any): ${WORK_DIR}"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

log_info "Creating per-node data directories and generating ENRs"

enrs=()

# ── Pluto nodes (slots 0 .. PLUTO_NODES-1) ───────────────────────────────────
for (( i = 0; i < PLUTO_NODES; i++ )); do
    data_dir="${WORK_DIR}/node-${i}"
    mkdir -p "${data_dir}"
    log_info "  Generating ENR for pluto node ${i} in ${data_dir}"
    enr=$(generate_enr "${PLUTO_BIN}" "${data_dir}" "pluto node ${i}") || exit 1
    log_info "  pluto node ${i}: ${enr}"
    enrs+=("${enr}")
done

# ── Charon nodes (slots PLUTO_NODES .. NODES-1) ───────────────────────────────
for (( i = PLUTO_NODES; i < NODES; i++ )); do
    data_dir="${WORK_DIR}/node-${i}"
    mkdir -p "${data_dir}"
    log_info "  Generating ENR for charon node ${i} in ${data_dir}"
    enr=$(generate_enr "${CHARON_BIN}" "${data_dir}" "charon node ${i}") || exit 1
    log_info "  charon node ${i}: ${enr}"
    enrs+=("${enr}")
done

# Join with commas in a subshell so IFS doesn't leak into the rest of the script.
enr_list=$(IFS=','; printf '%s' "${enrs[*]}")
log_info "Collected ${#enrs[@]} ENRs"

# `pluto create dkg --output-dir=DIR` writes cluster-definition.json directly
# into DIR (not into DIR/.charon/).
DEF_FILE="${WORK_DIR}/cluster-definition.json"

log_info "Running: ${PLUTO_BIN} create dkg"
"${PLUTO_BIN}" create dkg \
    --operator-enrs="${enr_list}" \
    --threshold="${THRESHOLD}" \
    --fee-recipient-addresses="${FEE_RECIPIENT}" \
    --withdrawal-addresses="${WITHDRAWAL_ADDR}" \
    --network="${NETWORK}" \
    --name=test-dkg \
    --output-dir="${WORK_DIR}"

if [[ ! -f "${DEF_FILE}" ]]; then
    log_err "cluster-definition.json not found at ${DEF_FILE}"
    log_err "Files in ${WORK_DIR}:"
    ls -la "${WORK_DIR}" >&2
    exit 1
fi

log_info "Done. Definition file: ${DEF_FILE}"
