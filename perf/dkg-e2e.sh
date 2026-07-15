#!/usr/bin/env bash
# Times full DKG ceremonies via scripts/dkg-runner: an all-pluto run vs an
# all-charon run, median of REPS repetitions each.
#
# Output: perf/out/dkg-times.json
#   [{"id": "tier3/dkg/ceremony_4node", "unit": "s",
#     "pluto_value": <median s>, "charon_value": <median s>}]
#
# Environment:
#   PLUTO_BIN   Path to pluto binary.  Default: target/release/pluto
#   CHARON_BIN  Path to charon binary. Default: perf/out/charon
#   NODES=4 THRESHOLD=3 REPS=3
#   RELAY_URL   Forwarded to dkg-runner (defaults to its built-in relay).
#   TIMEOUT     Per-ceremony timeout seconds (default 300).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/perf/out"

: "${PLUTO_BIN:=${ROOT_DIR}/target/release/pluto}"
: "${CHARON_BIN:=${OUT_DIR}/charon}"
: "${NODES:=4}"
: "${THRESHOLD:=3}"
: "${REPS:=3}"
: "${TIMEOUT:=300}"

log() {
    printf '[dkg-e2e] %s\n' "$*" >&2
}

for bin in "${PLUTO_BIN}" "${CHARON_BIN}"; do
    if ! [[ -x "${bin}" ]]; then
        log "ERROR: binary not found: ${bin}"
        exit 1
    fi
done

mkdir -p "${OUT_DIR}"

# run_variant <variant> <pluto-nodes> <charon-nodes>: prints median seconds.
run_variant() {
    local variant="$1" pluto_nodes="$2" charon_nodes="$3"
    local durations=()

    for rep in $(seq 1 "${REPS}"); do
        local work_dir="${OUT_DIR}/dkg-run-${variant}-${rep}"
        rm -rf "${work_dir}"

        log "variant=${variant} rep=${rep}/${REPS}"

        local start end
        start=$(python3 -c 'import time; print(time.time())')

        NODES="${NODES}" \
            THRESHOLD="${THRESHOLD}" \
            PLUTO_NODES="${pluto_nodes}" \
            CHARON_NODES="${charon_nodes}" \
            PLUTO_BIN="${PLUTO_BIN}" \
            CHARON_BIN="${CHARON_BIN}" \
            WORK_DIR="${work_dir}" \
            TIMEOUT="${TIMEOUT}" \
            RUN_SMOKE_VERIFY=0 \
            CI=1 \
            "${ROOT_DIR}/scripts/dkg-runner/run.sh" >"${work_dir}.log" 2>&1 || {
            log "variant=${variant} rep=${rep} FAILED (log: ${work_dir}.log)"
            return 1
        }

        end=$(python3 -c 'import time; print(time.time())')
        durations+=("$(python3 -c "print(${end} - ${start})")")
        log "variant=${variant} rep=${rep} took ${durations[-1]}s"
    done

    python3 -c "import statistics, sys; print(statistics.median([float(x) for x in sys.argv[1:]]))" "${durations[@]}"
}

PLUTO_MEDIAN=$(run_variant pluto "${NODES}" 0)
CHARON_MEDIAN=$(run_variant charon 0 "${NODES}")

cat >"${OUT_DIR}/dkg-times.json" <<EOF
[
  {
    "id": "tier3/dkg/ceremony_${NODES}node",
    "unit": "s",
    "pluto_value": ${PLUTO_MEDIAN},
    "charon_value": ${CHARON_MEDIAN}
  }
]
EOF

log "done: pluto=${PLUTO_MEDIAN}s charon=${CHARON_MEDIAN}s"
