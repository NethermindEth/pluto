#!/usr/bin/env bash
# verify-output-semantic.sh — semantic checks for DKG runner output.
#
# Env:
#   WORK_DIR   scratch directory used by run.sh (default: /tmp/dkg-run)
#   NODES      total node count (default: 4)
#   THRESHOLD  expected threshold (default: 3)
#
# Checks:
#   - every node lock is JSON-identical
#   - lock operator count, threshold, validator count are consistent
#   - every validator has one public share per node
#   - validator pubkey matches deposit data and builder registration pubkeys
#   - every node keystore pubkey set matches that node's public shares
#
# Does not decrypt keystores: collect.sh does not copy password files.

set -euo pipefail

WORK_DIR="${WORK_DIR:-/tmp/dkg-run}"
NODES="${NODES:-4}"
THRESHOLD="${THRESHOLD:-3}"
OUTPUT_DIR="${WORK_DIR}/output"
TMP_DIR="${WORK_DIR}/semantic-verify"

fail() {
    echo "::error::$*" >&2
    exit 1
}

warn() {
    echo "::warning::$*" >&2
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

node_dir() {
    printf '%s/node-%s' "${OUTPUT_DIR}" "$1"
}

lock_file() {
    printf '%s/cluster-lock.json' "$(node_dir "$1")"
}

norm_hex_jq='
  def normhex:
    if type != "string" then error("expected hex string")
    elif startswith("0x") then .[2:] | ascii_downcase
    else ascii_downcase
    end;
'

require_hex_len() {
    local label="$1"
    local value="$2"
    local expected_len="$3"
    [[ "${#value}" == "${expected_len}" ]] \
        || fail "${label}: hex length ${#value}, want ${expected_len}"
    [[ "${value}" =~ ^[0-9a-f]+$ ]] \
        || fail "${label}: not lowercase hex"
}

require_cmd jq
require_cmd sort
require_cmd cmp
require_cmd comm

[[ -d "${OUTPUT_DIR}" ]] || fail "output directory not found: ${OUTPUT_DIR}"
rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}"

# Every node must have a readable lock file; this is the core shared DKG output.
for (( i = 0; i < NODES; i++ )); do
    lock="$(lock_file "${i}")"
    [[ -s "${lock}" ]] || fail "node-${i}: missing or empty cluster-lock.json"
    jq -S -c . "${lock}" > "${TMP_DIR}/lock-${i}.json" \
        || fail "node-${i}: invalid cluster-lock.json"
done

# All nodes must agree on the exact same lock.
for (( i = 1; i < NODES; i++ )); do
    cmp -s "${TMP_DIR}/lock-0.json" "${TMP_DIR}/lock-${i}.json" \
        || fail "node-${i}: cluster-lock.json differs from node-0"
done

LOCK="${TMP_DIR}/lock-0.json"

# The lock topology must match the runner configuration.
operators_count="$(
    jq -r '(.cluster_definition // .definition).operators | length' "${LOCK}"
)"
[[ "${operators_count}" == "${NODES}" ]] \
    || fail "operator count mismatch: got ${operators_count}, want ${NODES}"

# Each operator must have one distinct ENR.
jq -r '
  (.cluster_definition // .definition).operators[] |
  (.enr // .ENR // empty)
' "${LOCK}" | sort > "${TMP_DIR}/operator-enrs"
operator_enr_count="$(wc -l < "${TMP_DIR}/operator-enrs" | tr -d ' ')"
[[ "${operator_enr_count}" == "${NODES}" ]] \
    || fail "operator ENR count mismatch: got ${operator_enr_count}, want ${NODES}"
duplicate_operator_enr="$(uniq -d "${TMP_DIR}/operator-enrs" | sed -n '1p')"
[[ -z "${duplicate_operator_enr}" ]] \
    || fail "duplicate operator ENR: ${duplicate_operator_enr}"

# The signing threshold must match the requested ceremony threshold.
actual_threshold="$(jq -r '(.cluster_definition // .definition).threshold | tonumber' "${LOCK}")"
[[ "${actual_threshold}" == "${THRESHOLD}" ]] \
    || fail "threshold mismatch: got ${actual_threshold}, want ${THRESHOLD}"
(( actual_threshold > 0 && actual_threshold <= NODES )) \
    || fail "threshold out of range: ${actual_threshold}"

# The lock must contain exactly the validator set declared by its definition.
validator_count="$(jq -r '(.distributed_validators // .validators) | length' "${LOCK}")"
declared_validators="$(jq -r '(.cluster_definition // .definition).num_validators | tonumber' "${LOCK}")"
[[ "${validator_count}" == "${declared_validators}" ]] \
    || fail "distributed validator count mismatch: got ${validator_count}, definition says ${declared_validators}"
(( validator_count > 0 )) || fail "validator count must be greater than zero"

# Lock hash and aggregate signature must have valid byte lengths.
lock_hash="$(jq -r "${norm_hex_jq}"'(.lock_hash // empty) | normhex' "${LOCK}")"
[[ -n "${lock_hash}" ]] || fail "missing lock_hash"
require_hex_len "lock_hash" "${lock_hash}" 64

signature_aggregate="$(jq -r "${norm_hex_jq}"'(.signature_aggregate // empty) | normhex' "${LOCK}")"
[[ -n "${signature_aggregate}" ]] || fail "missing signature_aggregate"
require_hex_len "signature_aggregate" "${signature_aggregate}" 192

# Node signatures are required by modern lock versions.
node_sig_count="$(jq -r '(.node_signatures // []) | length' "${LOCK}")"
if [[ "${node_sig_count}" != "0" && "${node_sig_count}" != "${NODES}" ]]; then
    fail "node_signatures count mismatch: got ${node_sig_count}, want 0 or ${NODES}"
fi
lock_version="$(jq -r '(.cluster_definition // .definition).version' "${LOCK}")"
if [[ "${lock_version}" =~ ^v1\.([7-9]|[1-9][0-9]+)\. && "${node_sig_count}" != "${NODES}" ]]; then
    fail "node_signatures count mismatch for ${lock_version}: got ${node_sig_count}, want ${NODES}"
fi
if (( node_sig_count > 0 )); then
    jq -r "${norm_hex_jq}"'(.node_signatures // [])[] | normhex' "${LOCK}" \
        > "${TMP_DIR}/node-signatures"
    sig_idx=0
    while IFS= read -r node_sig; do
        require_hex_len "node signature ${sig_idx}" "${node_sig}" 130
        sig_idx=$((sig_idx + 1))
    done < "${TMP_DIR}/node-signatures"
fi

# Distributed validator pubkeys must be unique.
jq -r "${norm_hex_jq}"'
  (.distributed_validators // .validators)[] |
  (.distributed_public_key // .pubkey // .pub_key) | normhex
' "${LOCK}" | sort > "${TMP_DIR}/validator-pubkeys"

duplicate_validator_pubkey="$(
    sort "${TMP_DIR}/validator-pubkeys" | uniq -d | sed -n '1p'
)"
[[ -z "${duplicate_validator_pubkey}" ]] \
    || fail "duplicate distributed validator pubkey: ${duplicate_validator_pubkey}"

for (( v = 0; v < validator_count; v++ )); do
    # Each distributed validator must have one public share per node.
    share_count="$(
        jq -r --argjson v "${v}" '(.distributed_validators // .validators)[$v] | (.public_shares // .pub_shares) | length' "${LOCK}"
    )"
    [[ "${share_count}" == "${NODES}" ]] \
        || fail "validator-${v}: public share count ${share_count}, want ${NODES}"

    validator_pubkey="$(
        jq -r --argjson v "${v}" "${norm_hex_jq}"'
          (.distributed_validators // .validators)[$v] |
          (.distributed_public_key // .pubkey // .pub_key) | normhex
        ' "${LOCK}"
    )"
    require_hex_len "validator-${v} distributed pubkey" "${validator_pubkey}" 96

    # Deposit data must belong to the same distributed validator pubkey.
    jq -r --argjson v "${v}" "${norm_hex_jq}"'
      (.distributed_validators // .validators)[$v] as $validator |
      (
        if $validator.deposit_data? then
          if ($validator.deposit_data | type) == "array" then $validator.deposit_data[] else $validator.deposit_data end
        elif $validator.partial_deposit_data? then
          $validator.partial_deposit_data[]
        else
          empty
        end
      ) |
      (.pubkey // .pub_key) | normhex
    ' "${LOCK}" > "${TMP_DIR}/validator-${v}-deposit-pubkeys"

    if [[ ! -s "${TMP_DIR}/validator-${v}-deposit-pubkeys" ]]; then
        fail "validator-${v}: no deposit data field"
    fi

    while IFS= read -r deposit_pubkey; do
        require_hex_len "validator-${v} deposit pubkey" "${deposit_pubkey}" 96
        [[ "${deposit_pubkey}" == "${validator_pubkey}" ]] \
            || fail "validator-${v}: deposit pubkey mismatch"
    done < "${TMP_DIR}/validator-${v}-deposit-pubkeys"

    # Builder registration, when present, must also target the same validator pubkey.
    reg_pubkey="$(
        jq -r --argjson v "${v}" "${norm_hex_jq}"'
          (.distributed_validators // .validators)[$v].builder_registration? as $reg |
          if ($reg == null or $reg == {}) then empty
          else (($reg.message // $reg.v1.message)? | (.pubkey // .pub_key) | normhex)
          end
        ' "${LOCK}"
    )"
    if [[ -n "${reg_pubkey}" ]]; then
        require_hex_len "validator-${v} builder registration pubkey" "${reg_pubkey}" 96
        [[ "${reg_pubkey}" == "${validator_pubkey}" ]] \
            || fail "validator-${v}: builder registration pubkey mismatch"
    fi

    # Save expected public share for each node, indexed by node order in the lock.
    for (( i = 0; i < NODES; i++ )); do
        share_pubkey="$(
            jq -r --argjson v "${v}" --argjson i "${i}" "${norm_hex_jq}"'
          (.distributed_validators // .validators)[$v] |
          (.public_shares // .pub_shares)[$i] | normhex
            ' "${LOCK}"
        )"
        require_hex_len "validator-${v} node-${i} public share" "${share_pubkey}" 96
        printf '%s\n' "${share_pubkey}" >> "${TMP_DIR}/node-${i}-expected-pubkeys"
    done
done

for (( i = 0; i < NODES; i++ )); do
    # Each node must have exactly one keystore for each distributed validator.
    : > "${TMP_DIR}/node-${i}-actual-pubkeys"
    shopt -s nullglob
    keystores=("$(node_dir "${i}")"/keystore-*.json)
    shopt -u nullglob
    (( ${#keystores[@]} > 0 )) || fail "node-${i}: no keystore files"
    (( ${#keystores[@]} == validator_count )) \
        || fail "node-${i}: keystore file count ${#keystores[@]}, want ${validator_count}"

    for keystore in "${keystores[@]}"; do
        keystore_pubkey="$(
            jq -r "${norm_hex_jq}"'.pubkey | normhex' "${keystore}" \
                || fail "node-${i}: invalid keystore json: ${keystore}"
        )"
        require_hex_len "node-${i} keystore pubkey" "${keystore_pubkey}" 96
        printf '%s\n' "${keystore_pubkey}" >> "${TMP_DIR}/node-${i}-actual-pubkeys"
    done

    # The node's keystore pubkeys must equal that node's public shares from the lock.
    sort -u "${TMP_DIR}/node-${i}-expected-pubkeys" > "${TMP_DIR}/node-${i}-expected.sorted"
    sort -u "${TMP_DIR}/node-${i}-actual-pubkeys" > "${TMP_DIR}/node-${i}-actual.sorted"

    expected_count="$(wc -l < "${TMP_DIR}/node-${i}-expected.sorted" | tr -d ' ')"
    actual_count="$(wc -l < "${TMP_DIR}/node-${i}-actual.sorted" | tr -d ' ')"
    [[ "${actual_count}" == "${expected_count}" ]] \
        || fail "node-${i}: keystore pubkey count ${actual_count}, want ${expected_count}"

    if ! cmp -s "${TMP_DIR}/node-${i}-expected.sorted" "${TMP_DIR}/node-${i}-actual.sorted"; then
        missing="$(comm -23 "${TMP_DIR}/node-${i}-expected.sorted" "${TMP_DIR}/node-${i}-actual.sorted" | head -3 | tr '\n' ' ')"
        extra="$(comm -13 "${TMP_DIR}/node-${i}-expected.sorted" "${TMP_DIR}/node-${i}-actual.sorted" | head -3 | tr '\n' ' ')"
        fail "node-${i}: keystore pubkeys do not match lock public shares; missing=${missing} extra=${extra}"
    fi
done

echo "Semantic DKG output check passed: ${NODES} nodes, ${validator_count} validators, threshold ${THRESHOLD}."
