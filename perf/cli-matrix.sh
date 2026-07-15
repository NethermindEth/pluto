#!/usr/bin/env bash
# Hyperfine matrix comparing pluto and charon CLI commands, plus peak-RSS
# capture for `create cluster`.
#
# Outputs:
#   perf/out/hyperfine/tier3__cli__<case>.json   (hyperfine --export-json)
#   perf/out/cli-extra.json                      (peak RSS entries)
#
# Environment:
#   PLUTO_BIN   Path to pluto binary.  Default: target/release/pluto
#   CHARON_BIN  Path to charon binary. Default: perf/out/charon
#   RUNS        hyperfine runs per command (default 10)
#   WARMUP      hyperfine warmup runs (default 2)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/perf/out"
HF_DIR="${OUT_DIR}/hyperfine"
WORK_DIR="${OUT_DIR}/cli-matrix-work"

: "${PLUTO_BIN:=${ROOT_DIR}/target/release/pluto}"
: "${CHARON_BIN:=${OUT_DIR}/charon}"
: "${RUNS:=10}"
: "${WARMUP:=2}"

ADDR="0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"

log() {
    printf '[cli-matrix] %s\n' "$*" >&2
}

for bin in "${PLUTO_BIN}" "${CHARON_BIN}"; do
    if ! [[ -x "${bin}" ]]; then
        log "ERROR: binary not found: ${bin}"
        exit 1
    fi
done

command -v hyperfine >/dev/null || {
    log "ERROR: hyperfine is required"
    exit 1
}

mkdir -p "${HF_DIR}"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

# run_case <case-id-suffix> <subcommand-and-args...>
# Uses {dir} placeholder replaced with a per-command scratch dir.
run_case() {
    local case_id="$1"
    shift

    local pluto_dir="${WORK_DIR}/${case_id}-pluto"
    local charon_dir="${WORK_DIR}/${case_id}-charon"

    local pluto_cmd charon_cmd
    pluto_cmd="${PLUTO_BIN} $(printf '%s ' "${@//\{dir\}/${pluto_dir}}")"
    charon_cmd="${CHARON_BIN} $(printf '%s ' "${@//\{dir\}/${charon_dir}}")"

    log "case ${case_id}"
    hyperfine \
        --warmup "${WARMUP}" \
        --runs "${RUNS}" \
        --prepare "rm -rf ${pluto_dir} ${charon_dir}" \
        --command-name pluto "${pluto_cmd}" \
        --command-name charon "${charon_cmd}" \
        --export-json "${HF_DIR}/tier3__cli__${case_id}.json"
}

run_case create_enr create enr --data-dir='{dir}'

run_case create_cluster_4 create cluster \
    --cluster-dir='{dir}' \
    --nodes=4 --threshold=3 --num-validators=1 --network=goerli \
    --fee-recipient-addresses="${ADDR}" --withdrawal-addresses="${ADDR}" \
    --insecure-keys

run_case create_cluster_10 create cluster \
    --cluster-dir='{dir}' \
    --nodes=10 --threshold=7 --num-validators=10 --network=goerli \
    --fee-recipient-addresses="${ADDR}" --withdrawal-addresses="${ADDR}" \
    --insecure-keys

run_case create_cluster_4_secure create cluster \
    --cluster-dir='{dir}' \
    --nodes=4 --threshold=3 --num-validators=1 --network=goerli \
    --fee-recipient-addresses="${ADDR}" --withdrawal-addresses="${ADDR}"

# --- Peak RSS of create cluster (10 nodes) -----------------------------------

peak_rss_bytes() {
    local bin="$1" dir="$2"
    local time_output rss

    rm -rf "${dir}"

    if [[ "$(uname)" == "Darwin" ]]; then
        time_output=$({ /usr/bin/time -l "${bin}" create cluster \
            --cluster-dir="${dir}" \
            --nodes=10 --threshold=7 --num-validators=10 --network=goerli \
            --fee-recipient-addresses="${ADDR}" --withdrawal-addresses="${ADDR}" \
            --insecure-keys >/dev/null; } 2>&1)
        rss=$(awk '/maximum resident set size/ {print $1}' <<<"${time_output}")
    else
        time_output=$({ /usr/bin/time -v "${bin}" create cluster \
            --cluster-dir="${dir}" \
            --nodes=10 --threshold=7 --num-validators=10 --network=goerli \
            --fee-recipient-addresses="${ADDR}" --withdrawal-addresses="${ADDR}" \
            --insecure-keys >/dev/null; } 2>&1)
        rss=$(awk -F': ' '/Maximum resident set size/ {print $2 * 1024}' <<<"${time_output}")
    fi

    printf '%s' "${rss}"
}

log "capturing peak RSS for create cluster (10 nodes)"
PLUTO_RSS=$(peak_rss_bytes "${PLUTO_BIN}" "${WORK_DIR}/rss-pluto")
CHARON_RSS=$(peak_rss_bytes "${CHARON_BIN}" "${WORK_DIR}/rss-charon")

cat >"${OUT_DIR}/cli-extra.json" <<EOF
[
  {
    "id": "tier3/mem/create_cluster_rss",
    "unit": "bytes",
    "pluto_value": ${PLUTO_RSS},
    "charon_value": ${CHARON_RSS}
  }
]
EOF

log "done: $(ls "${HF_DIR}" | wc -l | tr -d ' ') hyperfine exports, RSS pluto=${PLUTO_RSS}B charon=${CHARON_RSS}B"
