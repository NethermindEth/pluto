#!/bin/bash
set -euo pipefail

# Read hook input (though we don't need it for this check)
input=$(cat)

# Check if we're in the project root
if [ ! -f "Cargo.toml" ]; then
  echo '{"continue": true, "systemMessage": "Not in Cargo workspace root, skipping format check"}'
  exit 0
fi

# Pinned nightly toolchain for rustfmt (single source of truth shared with CI,
# .githooks/pre-push and flake.nix). Falls back to floating `nightly`.
NIGHTLY="$(tr -d '[:space:]' < rustfmt-toolchain 2>/dev/null || echo nightly)"

if command -v cargo-+nightly >/dev/null 2>&1; then
  # Nix dev shell: `cargo +nightly fmt` is wrapped to the pinned nightly.
  TOOLCHAIN="nightly"
else
  # rustup: pin by dated toolchain name; install it if missing (no-op if present).
  TOOLCHAIN="$NIGHTLY"
  rustup toolchain install "$NIGHTLY" --component rustfmt --profile minimal >/dev/null 2>&1 || true
fi

# Run cargo fmt with the pinned nightly
if cargo "+$TOOLCHAIN" fmt --all --check 2>&1; then
  # Formatting is correct
  echo "{\"continue\": true, \"systemMessage\": \"✓ Code formatting verified with cargo +$TOOLCHAIN fmt ($NIGHTLY)\"}"
  exit 0
else
  # Auto-fix formatting
  cargo "+$TOOLCHAIN" fmt --all 2>&1

  echo "{\"continue\": true, \"systemMessage\": \"✓ Formatting applied with cargo +$TOOLCHAIN fmt --all ($NIGHTLY).\"}"
  exit 0
fi
