#!/usr/bin/env bash
# Compare `charon create cluster` and `pluto create cluster` across a small
# matrix of CLI argument combinations.
#
# The generated lock contains fresh validator keys, threshold shares, ENRs, and
# signatures derived from independent CSPRNGs in each binary, so Charon and Pluto
# cannot produce byte-identical lock files. This script compares the
# deterministic lock surface (cluster definition, counts, deposit amounts, etc.)
# and verifies that each command writes the same lock to every node directory.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "${PLUTO_BIN:-}" ]]; then
    PLUTO_BIN="${ROOT_DIR}/target/debug/pluto"
fi

if [[ -z "${CHARON_BIN:-}" ]]; then
    printf '[create-cluster-compare] ERROR: %s\n' \
        "CHARON_BIN must be set to the path of a built charon binary" >&2
    exit 1
fi

: "${WORK_DIR:=/tmp/create-cluster-compare}"
: "${KEEP_WORK:=0}"

FEE_RECIPIENT_ADDRESS="0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
WITHDRAWAL_ADDRESS="0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"

CASE_FILTER=""

usage() {
    cat <<'USAGE'
Usage: scripts/create-cluster-compare.sh [--case NAME] [--keep-work]

Environment:
  PLUTO_BIN     Path to pluto binary. Defaults to ./target/debug/pluto.
  CHARON_BIN    Path to charon binary. Required.
  WORK_DIR      Scratch/output directory. Defaults to /tmp/create-cluster-compare.
  KEEP_WORK     Keep scratch directory when set to 1/true/yes/on.

Cases:
  basic
  threshold-default
  two-partial-deposits
  four-partial-deposits
  target-gas-limit
  compounding
USAGE
}

while (($#)); do
    case "$1" in
        --case)
            CASE_FILTER="${2:?--case requires a name}"
            shift 2
            ;;
        --keep-work)
            KEEP_WORK=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
        *) return 1 ;;
    esac
}

log() {
    printf '[create-cluster-compare] %s\n' "$*"
}

fail() {
    printf '[create-cluster-compare] ERROR: %s\n' "$*" >&2
    exit 1
}

require_bin() {
    local label="$1"
    local bin="$2"

    if [[ -x "${bin}" ]] || command -v "${bin}" >/dev/null 2>&1; then
        return 0
    fi

    fail "${label} binary not found or not executable: ${bin}"
}

case_nodes() {
    case "$1" in
        basic) echo 4 ;;
        threshold-default) echo 3 ;;
        two-partial-deposits) echo 4 ;;
        four-partial-deposits) echo 4 ;;
        target-gas-limit) echo 4 ;;
        compounding) echo 4 ;;
        *) fail "unknown case: $1" ;;
    esac
}

case_args() {
    case "$1" in
        basic)
            printf '%s\0' \
                --nodes=4 \
                --threshold=3 \
                --num-validators=1 \
                --network=goerli \
                "--fee-recipient-addresses=${FEE_RECIPIENT_ADDRESS}" \
                "--withdrawal-addresses=${WITHDRAWAL_ADDRESS}" \
                --insecure-keys
            ;;
        threshold-default)
            printf '%s\0' \
                --nodes=3 \
                --num-validators=2 \
                --network=goerli \
                "--fee-recipient-addresses=${FEE_RECIPIENT_ADDRESS}" \
                "--withdrawal-addresses=${WITHDRAWAL_ADDRESS}" \
                --insecure-keys
            ;;
        two-partial-deposits)
            printf '%s\0' \
                --nodes=4 \
                --threshold=3 \
                --num-validators=1 \
                --network=goerli \
                --deposit-amounts=31,1 \
                "--fee-recipient-addresses=${FEE_RECIPIENT_ADDRESS}" \
                "--withdrawal-addresses=${WITHDRAWAL_ADDRESS}" \
                --insecure-keys
            ;;
        four-partial-deposits)
            printf '%s\0' \
                --nodes=4 \
                --threshold=3 \
                --num-validators=1 \
                --network=goerli \
                --deposit-amounts=8,8,8,8 \
                "--fee-recipient-addresses=${FEE_RECIPIENT_ADDRESS}" \
                "--withdrawal-addresses=${WITHDRAWAL_ADDRESS}" \
                --insecure-keys
            ;;
        target-gas-limit)
            printf '%s\0' \
                --nodes=4 \
                --threshold=3 \
                --num-validators=1 \
                --network=goerli \
                --target-gas-limit=30000000 \
                "--fee-recipient-addresses=${FEE_RECIPIENT_ADDRESS}" \
                "--withdrawal-addresses=${WITHDRAWAL_ADDRESS}" \
                --insecure-keys
            ;;
        compounding)
            printf '%s\0' \
                --nodes=4 \
                --threshold=3 \
                --num-validators=1 \
                --network=goerli \
                --compounding \
                "--fee-recipient-addresses=${FEE_RECIPIENT_ADDRESS}" \
                "--withdrawal-addresses=${WITHDRAWAL_ADDRESS}" \
                --insecure-keys
            ;;
        *)
            fail "unknown case: $1"
            ;;
    esac
}

run_case_for_bin() {
    local label="$1"
    local bin="$2"
    local name="$3"
    local out_dir="$4"
    shift 4
    local args=("$@")

    mkdir -p "${out_dir}"
    log "${name}: running ${label}"
    if ! "${bin}" create cluster --cluster-dir="${out_dir}" "${args[@]}" >"${out_dir}/create-cluster.stdout" 2>"${out_dir}/create-cluster.stderr"; then
        printf '%s\n' "---- ${label} stdout ----" >&2
        cat "${out_dir}/create-cluster.stdout" >&2 || true
        printf '%s\n' "---- ${label} stderr ----" >&2
        cat "${out_dir}/create-cluster.stderr" >&2 || true
        fail "${name}: ${label} create cluster failed"
    fi
}

lock_path() {
    local dir="$1"
    printf '%s/node0/cluster-lock.json' "${dir}"
}

canonical_summary() {
    jq -S '
      def validators: (.distributed_validators // .validators // []);
      def clean_address:
        if type == "string" then ascii_downcase else . end;
      {
        cluster_definition: {
          name: (.cluster_definition.name // ""),
          version: .cluster_definition.version,
          num_validators: .cluster_definition.num_validators,
          threshold: .cluster_definition.threshold,
          dkg_algorithm: .cluster_definition.dkg_algorithm,
          fork_version: .cluster_definition.fork_version,
          deposit_amounts: (.cluster_definition.deposit_amounts // [] | map(tostring)),
          consensus_protocol: (.cluster_definition.consensus_protocol // ""),
          target_gas_limit: (.cluster_definition.target_gas_limit // 0),
          compounding: (.cluster_definition.compounding // false),
          validators: (
            .cluster_definition.validators // []
            | map({
                fee_recipient_address: (.fee_recipient_address // "" | clean_address),
                withdrawal_address: (.withdrawal_address // "" | clean_address)
              })
          )
        },
        operator_count: (.cluster_definition.operators | length),
        distributed_validator_count: (validators | length),
        public_share_counts: [
          validators[]
          | (.public_shares // .pubshares // [])
          | length
        ],
        partial_deposit_amounts: [
          validators[]
          | (.partial_deposit_data // .deposit_data // [])
          | map(.amount | tostring)
        ],
        builder_registration_gas_limits: [
          validators[]
          | .builder_registration.message.gas_limit
        ],
        builder_registration_timestamps: [
          validators[]
          | .builder_registration.message.timestamp
        ],
        node_signature_count: (.node_signatures // [] | length),
        has_signature_aggregate: ((.signature_aggregate // "") != ""),
        lock_hash_hex_len: ((.lock_hash // "") | sub("^0x"; "") | length)
      }
    ' "$1"
}

verify_node_locks_same() {
    local label="$1"
    local dir="$2"
    local nodes="$3"
    local first
    first="$(lock_path "${dir}")"

    [[ -s "${first}" ]] || fail "${label}: missing lock file: ${first}"

    for ((i = 1; i < nodes; i++)); do
        local other="${dir}/node${i}/cluster-lock.json"
        [[ -s "${other}" ]] || fail "${label}: missing lock file: ${other}"
        if ! cmp -s "${first}" "${other}"; then
            fail "${label}: node${i}/cluster-lock.json differs from node0/cluster-lock.json"
        fi
    done
}

compare_files() {
    local left="$1"
    local right="$2"
    local diff_file="$3"

    if diff -u "${left}" "${right}" >"${diff_file}"; then
        return 0
    fi

    return 1
}

run_case() {
    local name="$1"
    local nodes
    local args
    local charon_dir
    local pluto_dir
    local case_dir

    nodes="$(case_nodes "${name}")"
    args=()
    while IFS= read -r -d '' arg; do
        args+=("${arg}")
    done < <(case_args "${name}")

    case_dir="${WORK_DIR}/${name}"
    charon_dir="${case_dir}/charon"
    pluto_dir="${case_dir}/pluto"

    rm -rf "${case_dir}"
    mkdir -p "${case_dir}"

    log "${name}: args: ${args[*]}"
    run_case_for_bin "charon" "${CHARON_BIN}" "${name}" "${charon_dir}" "${args[@]}"
    run_case_for_bin "pluto" "${PLUTO_BIN}" "${name}" "${pluto_dir}" "${args[@]}"

    verify_node_locks_same "${name}: charon" "${charon_dir}" "${nodes}"
    verify_node_locks_same "${name}: pluto" "${pluto_dir}" "${nodes}"

    canonical_summary "$(lock_path "${charon_dir}")" >"${case_dir}/charon.summary.json"
    canonical_summary "$(lock_path "${pluto_dir}")" >"${case_dir}/pluto.summary.json"

    if compare_files "${case_dir}/charon.summary.json" "${case_dir}/pluto.summary.json" "${case_dir}/summary.diff"; then
        log "${name}: semantic lock summary matches"
    else
        printf '%s\n' "---- ${name} semantic diff ----" >&2
        cat "${case_dir}/summary.diff" >&2
        fail "${name}: Charon and Pluto semantic lock summaries differ"
    fi
}

main() {
    require_bin "jq" "jq"
    require_bin "pluto" "${PLUTO_BIN}"
    require_bin "charon" "${CHARON_BIN}"

    if ! is_truthy "${KEEP_WORK}"; then
        rm -rf "${WORK_DIR}"
    fi
    mkdir -p "${WORK_DIR}"

    local cases=(
        basic
        threshold-default
        two-partial-deposits
        four-partial-deposits
        target-gas-limit
        compounding
    )

    local ran=0
    for case_name in "${cases[@]}"; do
        if [[ -n "${CASE_FILTER}" && "${CASE_FILTER}" != "${case_name}" ]]; then
            continue
        fi
        run_case "${case_name}"
        ran=$((ran + 1))
    done

    if (( ran == 0 )); then
        fail "no cases matched --case=${CASE_FILTER}"
    fi

    log "passed ${ran} case(s); artifacts: ${WORK_DIR}"
}

main "$@"
