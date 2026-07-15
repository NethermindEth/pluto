#!/usr/bin/env bash
# Pluto vs Charon performance-comparison harness.
#
# Runs matching Rust (criterion) and Go (go test -bench) workloads, plus
# optional process-level comparisons, normalizes everything into
# perf/out/results.json and renders perf/out/report.md.
#
# Usage: perf/run.sh [--tier 1|2|3|all] [--filter <substr>] [--quick]
#                    [--baseline <results.json>] [--fail-threshold <ratio>]
#
# Environment:
#   CHARON_SRC   Path to the charon Go source checkout. Defaults to ./charon.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/perf/out"

: "${CHARON_SRC:=${ROOT_DIR}/charon}"

TIER="all"
FILTER=""
QUICK=0
BASELINE=""
FAIL_THRESHOLD="1.15"

usage() {
    sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while (($#)); do
    case "$1" in
        --tier)
            TIER="${2:?--tier requires a value}"
            shift 2
            ;;
        --filter)
            FILTER="${2:?--filter requires a value}"
            shift 2
            ;;
        --quick)
            QUICK=1
            shift
            ;;
        --baseline)
            BASELINE="${2:?--baseline requires a path}"
            shift 2
            ;;
        --fail-threshold)
            FAIL_THRESHOLD="${2:?--fail-threshold requires a value}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'perf/run.sh: unknown argument %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

tier_enabled() {
    [[ "${TIER}" == "all" || "${TIER}" == *"$1"* ]]
}

log() {
    printf '[perf] %s\n' "$*" >&2
}

mkdir -p "${OUT_DIR}"

export GOTOOLCHAIN=auto

if [[ ! -d "${CHARON_SRC}" ]]; then
    log "ERROR: charon source not found at ${CHARON_SRC} (set CHARON_SRC)"
    exit 1
fi

GO_COUNT=6
CRITERION_FLAGS=(--noplot)
if ((QUICK)); then
    GO_COUNT=2
    CRITERION_FLAGS+=(--quick)
fi

# --- Tier 1+2: Rust criterion benches ---------------------------------------

# Package list entries are "<package>[:<feature>]".
RUST_BENCH_PACKAGES=()
if tier_enabled 1; then
    RUST_BENCH_PACKAGES+=(pluto-crypto pluto-k1util pluto-frost)
fi
if tier_enabled 1 || tier_enabled 2; then
    # pluto-core benches cover tier 1 (ssz, proto) and tier 2 (qbft).
    RUST_BENCH_PACKAGES+=(pluto-core:bench-util)
fi
if tier_enabled 2; then
    RUST_BENCH_PACKAGES+=(pluto-dkg:bench-util)
fi

if ((${#RUST_BENCH_PACKAGES[@]})); then
    log "running Rust criterion benches: ${RUST_BENCH_PACKAGES[*]}"
    # Remove stale criterion estimates so the report never mixes runs.
    rm -rf "${ROOT_DIR}/target/criterion"

    for entry in "${RUST_BENCH_PACKAGES[@]}"; do
        pkg="${entry%%:*}"
        features="${entry#"${pkg}"}"
        features="${features#:}"
        (cd "${ROOT_DIR}" && cargo bench -p "${pkg}" --benches \
            ${features:+--features "${features}"} -- \
            "${CRITERION_FLAGS[@]}" ${FILTER:+"${FILTER}"})
    done
fi

# --- Tier 1+2: Go benches ----------------------------------------------------

if tier_enabled 1 || tier_enabled 2; then
    GO_TIERS=""
    tier_enabled 1 && GO_TIERS+="1"
    tier_enabled 2 && GO_TIERS+="2"
    GO_BENCH_REGEX="^BenchmarkTier[${GO_TIERS}]"
    if [[ -n "${FILTER}" ]]; then
        GO_BENCH_REGEX="${FILTER}"
    fi

    log "running Go benches (count=${GO_COUNT})"
    (cd "${ROOT_DIR}/perf/go-bench" && go test \
        -bench "${GO_BENCH_REGEX}" \
        -benchmem \
        -count "${GO_COUNT}" \
        -run '^$' \
        -timeout 60m \
        . | tee "${OUT_DIR}/go-bench.txt")
fi

# --- Tier 3: process-level ---------------------------------------------------

if tier_enabled 3; then
    log "building pluto (release) and charon binaries"
    (cd "${ROOT_DIR}" && cargo build --release -p pluto-cli)
    (cd "${CHARON_SRC}" && go build -trimpath -ldflags "-s -w" \
        -o "${OUT_DIR}/charon" .)

    log "running CLI matrix (hyperfine)"
    PLUTO_BIN="${ROOT_DIR}/target/release/pluto" \
        CHARON_BIN="${OUT_DIR}/charon" \
        "${ROOT_DIR}/perf/cli-matrix.sh"

    log "running timed DKG ceremonies (dkg-runner)"
    if ! PLUTO_BIN="${ROOT_DIR}/target/release/pluto" \
        CHARON_BIN="${OUT_DIR}/charon" \
        "${ROOT_DIR}/perf/dkg-e2e.sh"; then
        log "WARNING: dkg-e2e failed (needs relay connectivity); continuing without it"
    fi
fi

# --- Normalize + render -------------------------------------------------------

log "normalizing results"
python3 "${ROOT_DIR}/perf/report/normalize.py" \
    --pairs "${ROOT_DIR}/perf/pairs.json" \
    --criterion "${ROOT_DIR}/target/criterion" \
    --go "${OUT_DIR}/go-bench.txt" \
    --hyperfine "${OUT_DIR}/hyperfine" \
    --extra "${OUT_DIR}/dkg-times.json" "${OUT_DIR}/cli-extra.json" \
    --suboptimal-threshold "${FAIL_THRESHOLD}" \
    --repo-root "${ROOT_DIR}" \
    -o "${OUT_DIR}/results.json"

log "rendering report"
python3 "${ROOT_DIR}/perf/report/render.py" "${OUT_DIR}/results.json" \
    ${BASELINE:+--baseline "${BASELINE}"} \
    -o "${OUT_DIR}/report.md"

log "report: ${OUT_DIR}/report.md"
