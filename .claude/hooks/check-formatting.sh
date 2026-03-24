#!/bin/bash
set -euo pipefail

# Read hook input (though we don't need it for this check)
input=$(cat)

# Check if we're in the project root
if [ ! -f "Cargo.toml" ]; then
  echo '{"continue": true, "systemMessage": "Not in Cargo workspace root, skipping format check"}' >&2
  exit 0
fi

# Run cargo +nightly fmt --all --check
if cargo +nightly fmt --all --check 2>&1; then
  # Formatting is correct
  echo '{"continue": true, "systemMessage": "✓ Code formatting verified with cargo +nightly fmt"}'
  exit 0
else
  # Formatting issues detected
  echo '{"continue": false, "systemMessage": "⚠️  Code formatting issues detected. Running cargo +nightly fmt --all to fix formatting before completing work."}' >&2

  # Auto-fix formatting
  cargo +nightly fmt --all 2>&1

  echo '{"continue": false, "systemMessage": "✓ Formatting applied with cargo +nightly fmt --all. Please review the changes and try stopping again."}' >&2
  exit 2
fi
