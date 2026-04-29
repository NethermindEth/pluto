#!/usr/bin/env bash
# tmux-run.sh — DKG ceremony runner with a split-pane tmux view.
#
# Layout (N = NODES):
#   Top pane (full width) : live monitor / status → collect → summary
#   Bottom row (N panes)  : tail -f per node log
#
# Usage: same env vars as run.sh
#   ./tmux-run.sh
#   PLUTO_NODES=4 CHARON_NODES=0 ./tmux-run.sh
#
# Requires: tmux (falls back to plain run.sh when not available)
# Controls (once inside):
#   Ctrl-B D    detach session (ceremony keeps running)
#   Ctrl-B [    enter scroll mode  (q / Enter to exit)
#   Ctrl-C      abort ceremony (top pane only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.sh
source "${SCRIPT_DIR}/config.sh"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    grep '^#' "${BASH_SOURCE[0]}" | grep -v '#!/' | sed 's/^# \?//'
    exit 0
fi

# ── Validation ────────────────────────────────────────────────────────────────

if (( PLUTO_NODES + CHARON_NODES != NODES )); then
    echo "[tmux-run] ERROR: PLUTO_NODES (${PLUTO_NODES}) + CHARON_NODES (${CHARON_NODES}) must equal NODES (${NODES})" >&2
    exit 1
fi

if (( THRESHOLD > NODES )); then
    echo "[tmux-run] ERROR: THRESHOLD (${THRESHOLD}) cannot exceed NODES (${NODES})" >&2
    exit 1
fi

# ── Fallback when tmux is not installed ───────────────────────────────────────

if ! command -v tmux &>/dev/null; then
    echo "[tmux-run] tmux not found — falling back to run.sh" >&2
    exec "${SCRIPT_DIR}/run.sh" "$@"
fi

SESSION="dkg-run"

# Kill any stale session with the same name.
tmux kill-session -t "${SESSION}" 2>/dev/null || true

# ── Phase 1: Setup (runs in current terminal so fatal errors are visible) ─────

echo "[tmux-run] === Phase 1: Setup ==="
"${SCRIPT_DIR}/setup.sh"

# ── Phase 2: Start node processes (log files are created here) ────────────────

echo "[tmux-run] === Phase 2: Start nodes ==="
"${SCRIPT_DIR}/start-nodes.sh"

# ── Phase 3: Build tmux session ───────────────────────────────────────────────

echo ""
echo "[tmux-run] Launching tmux session '${SESSION}'  (${NODES} nodes, ${PLUTO_NODES} pluto / ${CHARON_NODES} charon)"
echo "  Ctrl-B D  detach  |  Ctrl-B [  scroll mode  |  Ctrl-C in top pane  abort"
echo ""
sleep 1

# New detached session — window named "dkg", pane 0 is the only pane.
tmux new-session -d -s "${SESSION}" -n "dkg"

# Split pane 0 vertically to create the first bottom pane (pane 1 = node-0).
tmux split-window -v -t "${SESSION}:dkg.0"

# For each additional node, split the most recently created bottom pane
# horizontally.  Splitting pane i creates pane i+1 to its right, so the
# visual left-to-right order matches node indices 0, 1, 2, ...
for i in $(seq 1 $(( NODES - 1 ))); do
    tmux split-window -h -t "${SESSION}:dkg.${i}"
done

# Set monitor pane height to ~30% of the window (best-effort; tmux ≥ 2.1).
tmux set-window-option -t "${SESSION}:dkg" main-pane-height "30%" 2>/dev/null || true

# Make pane 0 the "main" pane; spread remaining panes evenly across the bottom.
tmux select-pane   -t "${SESSION}:dkg.0"
tmux select-layout -t "${SESSION}:dkg" main-horizontal

# ── Populate panes ────────────────────────────────────────────────────────────

# Pane 0 (top): monitor → collect → done message.
tmux send-keys -t "${SESSION}:dkg.0" \
    "source '${SCRIPT_DIR}/config.sh' && '${SCRIPT_DIR}/monitor.sh' && '${SCRIPT_DIR}/collect.sh' && printf '\n=== Ceremony complete. Outputs: ${WORK_DIR}/output ===\n' || printf '\n=== FAILED — see node logs below. Run ./reset.sh to clean up. ===\n'" \
    Enter

# Panes 1..NODES (bottom row): one per node, tail the log.
# The 'until' loop handles the rare case where the log file is not yet created.
for i in $(seq 0 $(( NODES - 1 ))); do
    pane=$(( i + 1 ))
    log="${WORK_DIR}/node-${i}/node.log"
    tmux send-keys -t "${SESSION}:dkg.${pane}" \
        "until [ -f '${log}' ]; do sleep 0.2; done; printf 'node-${i}\n---\n'; tail -n 80 -f '${log}'" \
        Enter
done

# Focus the monitor pane before attaching.
tmux select-pane -t "${SESSION}:dkg.0"

# Attach (or switch client if we are already inside a tmux session).
if [[ -n "${TMUX:-}" ]]; then
    tmux switch-client -t "${SESSION}"
else
    tmux attach-session -t "${SESSION}"
fi
