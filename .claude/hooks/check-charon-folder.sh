#!/usr/bin/env bash
set -euo pipefail

# SessionStart hook to check for Charon folder existence
# This reduces token usage by checking once at session start instead of repeatedly

# Read input (required for hook protocol, even if unused)
input=$(cat)

# Get the project directory
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"

# Check for Charon folder in common locations
CHARON_PATHS=(
  "charon"
  "../charon"
  "../../charon"
)

FOUND_PATH=""
for path in "${CHARON_PATHS[@]}"; do
  if [ -d "$path" ]; then
    FOUND_PATH=$(eval echo "$(pwd)/$path")
    break
  fi
done

# Build additional context
if [ -n "$FOUND_PATH" ]; then
  # Charon folder found - add it to context
  MESSAGE="Charon Go source available at: $FOUND_PATH. Use this path to reference charon codebase when requested. Do not try to recheck this path. This path is static and will not change."
else
  # Charon folder not found - provide guidance
  MESSAGE="Charon Go source not found. Clone from https://github.com/ObolNetwork/charon.git to enable reference during porting."
fi

# Output JSON with additional context for Claude
jq -n \
  --arg msg "$MESSAGE" \
  '{
    "hookSpecificOutput":{
      "hookEventName": "SessionStart",
      "additionalContext": $msg,
    }
  }'

exit 0
