#!/usr/bin/env bash
#
# Regenerates crates/testutil/src/beaconmock/static.json by curling the listed
# endpoints from a real beacon node. Port of charon/testutil/beaconmock/
# gen_static.sh. Re-run when bumping spec/fork versions; the testutil build
# script validates the resulting file at compile time.
#
# Usage: BEACON_URL=https://beacon-holesky.example.com ./scripts/gen_static_beaconmock.sh

set -euo pipefail

if [[ -z "${BEACON_URL:-}" ]]; then
  echo "BEACON_URL not set (point it at a Holesky beacon node)" >&2
  exit 1
fi

ENDPOINTS=(
  /eth/v1/beacon/genesis
  /eth/v1/config/deposit_contract
  /eth/v1/config/fork_schedule
  /eth/v1/node/version
  /eth/v1/config/spec
  /eth/v2/beacon/blocks/0
)

repo_root=$(cd "$(dirname "$0")/.." && pwd)
target="${repo_root}/crates/testutil/src/beaconmock/static.json"

first=true
resp="{"
for endpoint in "${ENDPOINTS[@]}"; do
  if "${first}"; then
    first=false
  else
    resp+=","
  fi

  echo "Fetching ${endpoint}" >&2
  value=$(curl -fsS "${BEACON_URL}${endpoint}")
  resp+=" \"${endpoint}\": ${value}"
done
resp+=" }"

echo "Writing ${target}" >&2
echo "${resp}" | jq . > "${target}"
