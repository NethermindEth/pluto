#!/usr/bin/env bash
# lib.sh — shared helpers for the DKG runner scripts.
# Source after config.sh. Each script should set LOG_PREFIX before logging.

# Truthy check: 1/true/yes/on (case-insensitive).
is_truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
        *) return 1 ;;
    esac
}

# CI-mode: true when CI env var is truthy.
is_ci() {
    is_truthy "${CI:-}"
}

log_info() {
    printf '[%s] %s\n' "${LOG_PREFIX:-script}" "$*"
}

log_err() {
    printf '[%s] ERROR: %s\n' "${LOG_PREFIX:-script}" "$*" >&2
}

log_warn() {
    printf '[%s] WARN: %s\n' "${LOG_PREFIX:-script}" "$*" >&2
}

# Verify a binary exists and is executable (path or PATH-resolvable name).
require_bin() {
    local label="${1}"
    local bin="${2}"
    if [[ -x "${bin}" ]] || command -v "${bin}" >/dev/null 2>&1; then
        return 0
    fi
    log_err "${label} binary not found or not executable: ${bin}"
    return 1
}

# Run '<bin> create enr --data-dir=<dir>' and echo the captured ENR line.
# Returns 1 (with diagnostics) if the command fails or no ENR line is found.
generate_enr() {
    local bin="${1}"
    local data_dir="${2}"
    local label="${3}"
    local output
    if ! output=$("${bin}" create enr --data-dir="${data_dir}" 2>&1); then
        log_err "${label}: 'create enr' failed:"
        printf '%s\n' "${output}" >&2
        return 1
    fi
    local enr
    enr=$(printf '%s\n' "${output}" | grep -E '^enr:' | head -1 || true)
    if [[ -z "${enr}" ]]; then
        log_err "${label}: failed to extract ENR from 'create enr' output:"
        printf '%s\n' "${output}" >&2
        return 1
    fi
    printf '%s\n' "${enr}"
}

# Send SIGTERM to each PGID listed in <file>, wait up to <grace> seconds for the
# groups to exit, then SIGKILL any survivors. Missing file is a no-op.
# Args: <pgid-file> [grace-seconds]
kill_pgids() {
    local file="${1}"
    local grace="${2:-5}"
    [[ -f "${file}" ]] || return 0

    local pgid
    while IFS= read -r pgid; do
        [[ -z "${pgid}" ]] && continue
        if kill -0 -- "-${pgid}" 2>/dev/null; then
            kill -TERM -- "-${pgid}" 2>/dev/null || true
        fi
    done < "${file}"

    local waited=0
    while (( waited < grace )); do
        local alive=0
        while IFS= read -r pgid; do
            [[ -z "${pgid}" ]] && continue
            if kill -0 -- "-${pgid}" 2>/dev/null; then
                alive=1
                break
            fi
        done < "${file}"
        (( alive == 0 )) && return 0
        sleep 1
        waited=$(( waited + 1 ))
    done

    while IFS= read -r pgid; do
        [[ -z "${pgid}" ]] && continue
        if kill -0 -- "-${pgid}" 2>/dev/null; then
            log_warn "SIGKILL -> PGID ${pgid} (did not exit in ${grace}s)"
            kill -KILL -- "-${pgid}" 2>/dev/null || true
        fi
    done < "${file}"
}
