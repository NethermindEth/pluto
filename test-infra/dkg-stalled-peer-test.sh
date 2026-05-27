#!/usr/bin/env bash
#
# E2E proof that the overall DKG timeout (`Config::timeout`, "--timeout",
# default 60s) is NOT enforced for the FROST DKG rounds.
#
# Starts a real 4-operator cluster (threshold 3) but only runs 3 Pluto nodes;
# the 4th operator never starts (a permanently stalled peer). A correct DKG
# aborts each running node with a timeout error within `--timeout`. The bug:
# the running nodes wait for the missing peer forever.
#
# This script ASSERTS THE CORRECT BEHAVIOUR, so it FAILS (exit 1) while the bug
# is present, and will PASS once the overall timeout is wired into the rounds.
#
# Usage:
#   docker build -t pluto:local .
#   PLUTO_IMAGE=pluto:local ./test-infra/dkg-stalled-peer-test.sh
#
# Env:
#   PLUTO_IMAGE  image under test (default: pluto:local)
#   DKG_TIMEOUT  per-node --timeout in seconds passed to the cluster (default 60)
#   WAIT_SECONDS how long to wait before asserting (default: DKG_TIMEOUT + 40)

set -euo pipefail

cd "$(dirname "$0")/.."

PLUTO_IMAGE="${PLUTO_IMAGE:-pluto:local}"
DKG_TIMEOUT="${DKG_TIMEOUT:-30}"
WAIT_SECONDS="${WAIT_SECONDS:-$((DKG_TIMEOUT + 30))}"
COMPOSE=(docker compose -f test-infra/docker-compose.dkg-stalled-peer.yml)

# DKG_TIMEOUT feeds each node's --timeout via the compose file.
export PLUTO_IMAGE DKG_TIMEOUT

cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Using image: ${PLUTO_IMAGE}; waiting ${WAIT_SECONDS}s (timeout=${DKG_TIMEOUT}s)"
cleanup
"${COMPOSE[@]}" up -d init setup-enr create-dkg fix-perms relay node0 node1 node2

echo "==> Cluster up with 3 of 4 operators; the 4th (node-3) never starts."
echo "==> A correct DKG should abort the running nodes within ~${DKG_TIMEOUT}s."
sleep "${WAIT_SECONDS}"

running=$("${COMPOSE[@]}" ps --status running --services | grep -Ec '^node[012]$' || true)

if [ "${running}" -gt 0 ]; then
  echo
  echo "FAIL: ${running}/3 Pluto DKG nodes are still running after ${WAIT_SECONDS}s with"
  echo "      one operator absent. The overall DKG timeout (--timeout=${DKG_TIMEOUT}s) is"
  echo "      NOT enforced — a single missing/stalled peer hangs the ceremony forever."
  echo
  echo "---- node0 recent logs ----"
  "${COMPOSE[@]}" logs --tail=15 node0 || true
  exit 1
fi

echo "PASS: the running nodes terminated within the timeout (overall DKG timeout enforced)."
