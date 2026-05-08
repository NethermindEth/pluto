#!/usr/bin/env bash
# stress.sh — Run N DKG ceremonies back-to-back (or in parallel) for stress
# testing. Each ceremony gets its own isolated WORK_DIR; results are aggregated
# into a TSV summary.
#
# Usage:
#   ./stress.sh [--help]
#
# Stress-test variables (all optional; defaults shown):
#   RUNS=10                          Total ceremonies to run.
#   WORKERS=1                        Concurrent ceremonies.
#   STRESS_WORK_DIR=/tmp/dkg-stress  Base directory; each run uses run-NNN/.
#   KEEP_PASSED=0                    When truthy, keep full per-run dirs even
#                                    on success. Default trims node-*/ on pass
#                                    to save disk; failed runs are always kept.
#   INTERACTIVE=auto                 auto|1|0. When auto (default), uses an
#                                    in-place TUI table when stdout is a TTY,
#                                    CI is unset, and the table fits the
#                                    terminal. Set to 1 to force, 0 to disable.
#
# Per-run variables (forwarded to run.sh — see run.sh --help for full list):
#   NODES, THRESHOLD, PLUTO_NODES, CHARON_NODES, RELAY_URL, NETWORK,
#   FEE_RECIPIENT, WITHDRAWAL_ADDR, TIMEOUT, NODE_EXIT_TIMEOUT,
#   SHUTDOWN_DELAY, PLUTO_BIN, CHARON_BIN.
# RELAY_URL is overridden per run with a random index in https://{0..4}.relay.obol.tech.
#
# WORK_DIR from the environment is ignored — stress.sh assigns one per run.
# CI is forced to "true" when WORKERS > 1 so node logs don't interleave.
#
# Outputs:
#   ${STRESS_WORK_DIR}/summary.tsv          TSV with one row per run.
#   ${STRESS_WORK_DIR}/run-NNN/run.log      Captured stdout/stderr of run.sh.
#   ${STRESS_WORK_DIR}/run-NNN/...          Whatever run.sh wrote (preserved
#                                           for failed runs; trimmed on pass
#                                           unless KEEP_PASSED is truthy).
#
# Exit codes:
#   0   — all RUNS ceremonies passed.
#   1   — one or more failed (failed runs preserved for inspection).
#   130 — interrupted; in-flight workers terminated.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
LOG_PREFIX="stress"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    grep '^#' "${BASH_SOURCE[0]}" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
fi

# ── Stress-test params ───────────────────────────────────────────────────────

: "${RUNS:=10}"
: "${WORKERS:=1}"
: "${STRESS_WORK_DIR:=/tmp/dkg-stress}"
: "${KEEP_PASSED:=0}"
: "${INTERACTIVE:=auto}"

if (( RUNS < 1 )); then
    log_err "RUNS must be >= 1 (got ${RUNS})"
    exit 1
fi
if (( WORKERS < 1 )); then
    log_err "WORKERS must be >= 1 (got ${WORKERS})"
    exit 1
fi
if (( WORKERS > RUNS )); then
    WORKERS=${RUNS}
fi

mkdir -p "${STRESS_WORK_DIR}"
SUMMARY="${STRESS_WORK_DIR}/summary.tsv"
printf 'run_id\tstatus\tduration_s\tstart_time\twork_dir\n' > "${SUMMARY}"

# Force CI=true when running in parallel so per-node logs don't interleave on
# the controlling terminal. Each run's stdout/stderr is captured to its own
# run.log regardless, so this only changes the live-tail behaviour.
WORKER_CI="${CI:-}"
if (( WORKERS > 1 )) && [[ -z "${WORKER_CI}" ]]; then
    WORKER_CI="true"
fi

# ── Interactive TUI vs append-only logging ───────────────────────────────────
#
# In TUI mode each run owns one terminal row that mutates pending → running →
# PASS/FAIL, plus a footer summary. The mode is auto-disabled when:
#   - stdout isn't a tty (piped, redirected, CI)
#   - CI env is truthy
#   - the table doesn't fit (RUNS + footer would exceed the terminal height)
# In all other cases, workers emit per-state log lines as before.

INTERACTIVE_MODE=0
INTERACTIVE_REASON=""
case "${INTERACTIVE}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
        INTERACTIVE_MODE=1
        ;;
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
        INTERACTIVE_MODE=0
        INTERACTIVE_REASON="forced off"
        ;;
    auto|AUTO|Auto|"")
        if ! [[ -t 1 ]]; then
            INTERACTIVE_REASON="stdout is not a tty"
        elif is_truthy "${CI:-}"; then
            INTERACTIVE_REASON="CI is set"
        else
            term_lines=$(tput lines 2>/dev/null || echo 0)
            # Need RUNS rows + 1 footer; leave a couple of lines breathing room
            # and for the prompt that comes back when we exit.
            if (( term_lines >= RUNS + 3 )); then
                INTERACTIVE_MODE=1
            else
                INTERACTIVE_REASON="terminal has ${term_lines} rows, need >= $(( RUNS + 3 )); resize taller or set INTERACTIVE=0 to silence"
            fi
        fi
        ;;
    *)
        log_err "INTERACTIVE must be auto|1|0 (got: ${INTERACTIVE})"
        exit 1
        ;;
esac

STATE_DIR="${STRESS_WORK_DIR}/.state"
rm -rf "${STATE_DIR}"
mkdir -p "${STATE_DIR}"
for (( i = 1; i <= RUNS; i++ )); do
    printf 'pending\n' > "${STATE_DIR}/$(printf 'run-%04d' "${i}")"
done

write_state() {
    local id="${1}"
    local state="${2}"
    printf '%s\n' "${state}" > "${STATE_DIR}/$(printf 'run-%04d' "${id}")"
}

# ANSI helpers (only emit escapes when we'll be drawing to the terminal).
ansi() {
    if (( INTERACTIVE_MODE )); then
        printf '\033[%sm' "${1}"
    fi
}
reset() {
    if (( INTERACTIVE_MODE )); then
        printf '\033[0m'
    fi
}

format_run_line() {
    local label="${1}"
    local state="${2}"
    local now="${3}"
    case "${state}" in
        pending)
            printf '  %s  %spending%s' "${label}" "$(ansi 2)" "$(reset)"
            ;;
        running:*)
            local since="${state#running:}"
            local elapsed=$(( now - since ))
            printf '  %s  %srunning%s   %3ds' \
                "${label}" "$(ansi 33)" "$(reset)" "${elapsed}"
            ;;
        pass:*)
            local dur="${state#pass:}"
            printf '  %s  %sPASS   %s   %3ds' \
                "${label}" "$(ansi '1;32')" "$(reset)" "${dur}"
            ;;
        fail:*)
            local dur="${state#fail:}"
            printf '  %s  %sFAIL   %s   %3ds' \
                "${label}" "$(ansi '1;31')" "$(reset)" "${dur}"
            ;;
    esac
}

# Lines drawn by the most recent draw_table call (RUNS rows + 1 footer).
# 0 means we haven't drawn yet, so the next call doesn't try to move the
# cursor up over content that isn't there.
TABLE_LINES=0

draw_table() {
    (( INTERACTIVE_MODE )) || return 0

    local now
    now=$(date +%s)

    # Move cursor back to the top of the previously-drawn block.
    if (( TABLE_LINES > 0 )); then
        printf '\033[%dA' "${TABLE_LINES}"
    fi

    local pass=0 fail=0 run=0 pend=0
    for (( i = 1; i <= RUNS; i++ )); do
        local label state
        label=$(printf 'run-%04d' "${i}")
        state=$(<"${STATE_DIR}/${label}")
        case "${state}" in
            pending)   (( pend++ )) ;;
            running:*) (( run++ )) ;;
            pass:*)    (( pass++ )) ;;
            fail:*)    (( fail++ )) ;;
        esac
        # \033[2K clears the entire line; \r ensures we start at column 0.
        printf '\r\033[2K%s\n' "$(format_run_line "${label}" "${state}" "${now}")"
    done

    printf '\r\033[2K  %sPASS%s %d   %sFAIL%s %d   %srun%s %d   %spend%s %d   (%d/%d done)\n' \
        "$(ansi '1;32')" "$(reset)" "${pass}" \
        "$(ansi '1;31')" "$(reset)" "${fail}" \
        "$(ansi 33)"     "$(reset)" "${run}" \
        "$(ansi 2)"      "$(reset)" "${pend}" \
        $(( pass + fail )) "${RUNS}"

    TABLE_LINES=$(( RUNS + 1 ))
}

# ── Cleanup / signal handling ────────────────────────────────────────────────

WORKER_PIDS=()

_kill_workers() {
    (( ${#WORKER_PIDS[@]} == 0 )) && return 0
    for pid in "${WORKER_PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            # Each worker is its own process group (set -m below), so signal
            # the whole group to take down run.sh and any node descendants.
            kill -TERM -- "-${pid}" 2>/dev/null \
                || kill -TERM "${pid}" 2>/dev/null \
                || true
        fi
    done
}

_on_signal() {
    if (( INTERACTIVE_MODE )) && (( TABLE_LINES > 0 )); then
        # Draw a final frame so any in-flight rows get a last update before
        # we leave them in place; then move below the table to print our
        # warning, so the cleanup messages don't overwrite it.
        draw_table
    fi
    log_warn "Caught signal — terminating ${#WORKER_PIDS[@]} in-flight worker(s)"
    _kill_workers
    wait 2>/dev/null || true
    log_info "Aborted. Partial summary at ${SUMMARY}"
    exit 130
}

trap '_on_signal' INT TERM

# ── Worker ───────────────────────────────────────────────────────────────────

run_one() {
    local id="${1}"
    local label
    label=$(printf 'run-%04d' "${id}")
    local run_dir="${STRESS_WORK_DIR}/${label}"
    local run_log="${run_dir}/run.log"

    rm -rf "${run_dir}"
    mkdir -p "${run_dir}"

    local started ended duration status start_time
    started=$(date +%s)
    start_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    local run_relay_url="https://$(( RANDOM % 5 )).relay.obol.tech"

    write_state "${id}" "running:${started}"
    if (( ! INTERACTIVE_MODE )); then
        log_info "[${label}] starting (relay: ${run_relay_url})"
    fi

    # Each ceremony runs in an isolated WORK_DIR. All other run.sh env vars
    # are inherited from this script's environment.
    if WORK_DIR="${run_dir}" CI="${WORKER_CI}" RELAY_URL="${run_relay_url}" \
        "${SCRIPT_DIR}/run.sh" >"${run_log}" 2>&1; then
        status="pass"
    else
        status="fail"
    fi

    ended=$(date +%s)
    duration=$(( ended - started ))

    write_state "${id}" "${status}:${duration}"

    # Atomic-ish append: a single printf-write of one line to a TSV is
    # effectively safe under typical bash buffering with WORKERS in single
    # digits, but parallel writers can in principle interleave. A flock
    # would be cleaner; we accept the small risk for portability (no
    # flock(1) on macOS by default).
    printf '%s\t%s\t%d\t%s\t%s\n' \
        "${label}" "${status}" "${duration}" "${start_time}" "${run_dir}" \
        >> "${SUMMARY}"

    if [[ "${status}" == "pass" ]]; then
        if (( ! INTERACTIVE_MODE )); then
            log_info "[${label}] PASS in ${duration}s"
        fi
        if ! is_truthy "${KEEP_PASSED}"; then
            # Keep run.log + cluster-lock.json for verification; drop the
            # node data dirs, which dominate disk usage.
            rm -rf "${run_dir}/node-"*/ 2>/dev/null || true
        fi
    else
        if (( ! INTERACTIVE_MODE )); then
            log_err "[${label}] FAIL after ${duration}s — preserved at ${run_dir}"
        fi
    fi
}

# ── Dispatch ─────────────────────────────────────────────────────────────────

log_info "=============================================="
log_info "DKG stress test"
log_info "  RUNS            = ${RUNS}"
log_info "  WORKERS         = ${WORKERS}"
log_info "  STRESS_WORK_DIR = ${STRESS_WORK_DIR}"
log_info "  KEEP_PASSED     = ${KEEP_PASSED}"
log_info "  CI (per worker) = ${WORKER_CI:-<unset>}"
if (( INTERACTIVE_MODE )); then
    log_info "  INTERACTIVE     = ${INTERACTIVE} (active)"
else
    log_info "  INTERACTIVE     = ${INTERACTIVE} (disabled${INTERACTIVE_REASON:+: ${INTERACTIVE_REASON}})"
fi
log_info "  (per-run config inherited from environment; see run.sh --help)"
log_info "=============================================="

# Job control: each backgrounded worker becomes its own process group leader,
# so $! == PGID and we can signal the whole tree (run.sh + nodes) on cleanup.
set -m

# Initial frame so the user sees the table immediately, with all rows pending.
draw_table

next=1
while (( next <= RUNS )) || (( ${#WORKER_PIDS[@]} > 0 )); do
    # Fill the worker pool up to WORKERS.
    while (( ${#WORKER_PIDS[@]} < WORKERS )) && (( next <= RUNS )); do
        run_one "${next}" &
        WORKER_PIDS+=("$!")
        next=$(( next + 1 ))
    done

    # Tick: redraw, sleep, then reap finished workers. Polled rather than
    # `wait -n` for portability across bash 3.2 (macOS default).
    draw_table
    sleep 1
    alive=()
    for pid in "${WORKER_PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            alive+=("${pid}")
        else
            wait "${pid}" 2>/dev/null || true
        fi
    done
    WORKER_PIDS=("${alive[@]+"${alive[@]}"}")
done

# Final frame so the table reflects the last state transition.
draw_table

trap - INT TERM

# ── Aggregate ────────────────────────────────────────────────────────────────

pass=$(awk -F'\t' 'NR>1 && $2=="pass"' "${SUMMARY}" | wc -l | tr -d ' ')
fail=$(awk -F'\t' 'NR>1 && $2=="fail"' "${SUMMARY}" | wc -l | tr -d ' ')
total=$(( pass + fail ))

if (( total == 0 )); then
    log_err "No runs completed."
    exit 1
fi

read -r dmin dmax dmean < <(
    awk -F'\t' 'NR>1 {
        d = $3 + 0
        if (n == 0 || d < min) min = d
        if (d > max) max = d
        sum += d
        n++
    } END {
        printf "%d %d %.1f", min, max, (n>0 ? sum/n : 0)
    }' "${SUMMARY}"
)

log_info "=============================================="
log_info "Stress test complete"
log_info "  Passed: ${pass}/${total}"
log_info "  Failed: ${fail}/${total}"
log_info "  Duration min/mean/max = ${dmin}s / ${dmean}s / ${dmax}s"
log_info "  Summary: ${SUMMARY}"
log_info "=============================================="

if (( fail > 0 )); then
    log_warn "Failed runs:"
    awk -F'\t' 'NR>1 && $2=="fail" {printf "  %s  (%ds)  %s\n", $1, $3, $5}' \
        "${SUMMARY}" >&2
    exit 1
fi
exit 0
