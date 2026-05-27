#!/usr/bin/env bash
# install-charon.sh — Downloads and installs the Charon binary from a release tarball.
#
# Usage:
#   CHARON_URL=https://... ./install-charon.sh [install_dir]
#
# Required env:
#   CHARON_URL — full URL to the Charon .tar.gz release archive.
#
# Optional argument:
#   install_dir — destination directory (default: bin). Created if missing.
#
# The binary is installed as ${install_dir}/charon (mode 0755).
# Exits non-zero on download, extract, or binary-discovery failure.

set -euo pipefail

if [[ -z "${CHARON_URL:-}" ]]; then
    echo "::error::CHARON_URL is required" >&2
    exit 1
fi

install_dir="${1:-bin}"
mkdir -p "${install_dir}"

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

echo "Downloading ${CHARON_URL}"
curl -fLsS "${CHARON_URL}" -o "${tmp}/charon.tar.gz"

echo "Extracting tarball"
tar -xzf "${tmp}/charon.tar.gz" -C "${tmp}"

bin_path=$(find "${tmp}" -type f \( -name charon -o -name 'charon-*' \) ! -name '*.tar.gz' | head -1)
if [[ -z "${bin_path}" ]]; then
    echo "::error::charon binary not found inside extracted tarball" >&2
    ls -R "${tmp}" >&2
    exit 1
fi

install -m 0755 "${bin_path}" "${install_dir}/charon"
echo "Installed ${install_dir}/charon"
