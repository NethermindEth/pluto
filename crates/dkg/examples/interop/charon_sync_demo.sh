#!/usr/bin/env bash

set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: CHARON_DIR=/path/to/charon bash $0 --data-dir <node-dir> --relay-url <url>" >&2
  exit 2
fi

if [[ -z "${CHARON_DIR:-}" ]]; then
  echo "CHARON_DIR must point to a local Charon checkout" >&2
  exit 1
fi

if [[ ! -f "$CHARON_DIR/go.mod" ]]; then
  echo "CHARON_DIR does not look like a Charon repo: $CHARON_DIR" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d /tmp/pluto-charon-sync-demo.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

cp "$script_dir/charon_sync_demo.go" "$work_dir/main.go"
if [[ -f "$CHARON_DIR/go.sum" ]]; then
  cp "$CHARON_DIR/go.sum" "$work_dir/go.sum"
fi

cat > "$work_dir/go.mod" <<EOF
module pluto-charon-sync-demo

go 1.25

require github.com/obolnetwork/charon v0.0.0

replace github.com/obolnetwork/charon => $CHARON_DIR
EOF

(
  cd "$work_dir"
  export GOCACHE="${GOCACHE:-/tmp/pluto-charon-sync-demo-gocache}"
  export GOMODCACHE="${GOMODCACHE:-/tmp/pluto-charon-sync-demo-gomodcache}"
  GOWORK=off go run -mod=mod . "$@"
)
