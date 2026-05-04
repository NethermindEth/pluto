#!/usr/bin/env bash
# Runs the DKG ceremony locally with 4 Charon nodes, matching the CI matrix entry.

set -euo pipefail

cd "$(dirname "$0")/../.."

CHARON_BIN="${CHARON_BIN:-$HOME/projects/charon/charon}"

if [[ ! -x "${CHARON_BIN}" ]]; then
    echo "charon binary not found or not executable: ${CHARON_BIN}" >&2
    exit 1
fi

"${CHARON_BIN}" version

NODES="${NODES:-4}" \
THRESHOLD="${THRESHOLD:-3}" \
PLUTO_NODES="${PLUTO_NODES:-0}" \
CHARON_NODES="${CHARON_NODES:-4}" \
CHARON_BIN="${CHARON_BIN}" \
TIMEOUT="${TIMEOUT:-120}" \
    ./scripts/dkg-runner/run.sh
