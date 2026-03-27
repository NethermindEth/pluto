#!/bin/bash
set -euo pipefail

# Read hook input (though we don't need it for this check)
input=$(cat)

# Check if we're in the project root
if [ ! -f "Cargo.toml" ]; then
  echo '{"continue": true, "systemMessage": "Not in Cargo workspace root, skipping format check"}'
  exit 0
fi

# Run cargo +nightly fmt --all --check
if cargo +nightly fmt --all --check 2>&1; then
  # Formatting is correct
  echo '{"continue": true, "systemMessage": "✓ Code formatting verified with cargo +nightly fmt"}'
  exit 0
else
  # Auto-fix formatting
  cargo +nightly fmt --all 2>&1

  echo '{"continue": true, "systemMessage": "✓ Formatting applied with cargo +nightly fmt --all."}'
  exit 0
fi
