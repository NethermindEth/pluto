#!/bin/bash
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
  # Expand ~ and resolve relative paths
  expanded_path=$(eval echo "$path")
  if [ -d "$expanded_path" ]; then
    FOUND_PATH="$expanded_path"
    break
  fi
done

# Build additional context
if [ -n "$FOUND_PATH" ]; then
  # Charon folder found - add it to context
  MESSAGE="<charon-reference>
Charon Go source code found at: $FOUND_PATH

The 'charon-reference' and 'charon-guide' skills can use this path to read Go source files when porting functionality to Pluto.

Skills can reference files like:
- $FOUND_PATH/app/app.go
- $FOUND_PATH/core/validatorapi/validatorapi.go
- $FOUND_PATH/p2p/p2p.go

Use the Read tool with these paths to examine Go implementation before porting to Rust.
</charon-reference>"
else
  # Charon folder not found - provide guidance
  MESSAGE="<charon-reference-warning>
Charon Go source code not found in common locations:
$(printf '  - %s\n' "${CHARON_PATHS[@]}")

If you need to reference Charon Go code during porting tasks:
1. Clone Charon: git clone https://github.com/ObolNetwork/charon.git
2. Place it in one of the expected locations above
3. Restart Claude Code session to pick up the new path

Without Charon source access, the 'charon-reference' and 'charon-guide' skills will have limited functionality.
</charon-reference-warning>"
fi

# Output JSON with additional context for Claude
jq -n \
  --arg msg "$MESSAGE" \
  '{
    "continue": true,
    "suppressOutput": false,
    "additionalContext": $msg
  }'

exit 0
