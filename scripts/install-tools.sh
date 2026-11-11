#!/usr/bin/env bash
# Install pinned security tools on a Linux CI runner, verifying every download
# against the vendor's published SHA-256 checksums (supply-chain hygiene:
# we never pipe `curl | sh` and never use an unpinned "latest").
# Usage: scripts/install-tools.sh gitleaks trivy syft
set -euo pipefail

GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
TRIVY_VERSION="${TRIVY_VERSION:-0.76.2}"
SYFT_VERSION="${SYFT_VERSION:-1.57.1}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

fetch_verify() { # <base-url> <archive> <checksums-file>
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$2" "$1/$2"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$3" "$1/$3"
  (cd "$tmp" && grep " $2\$" "$3" | sha256sum --check --strict -)
}

install_tool() {
  case "$1" in
    gitleaks)
      base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
      fetch_verify "$base" "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt"
      tar -xzf "$tmp/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -C "$BIN_DIR" gitleaks ;;
    trivy)
      base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
      fetch_verify "$base" "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt"
      tar -xzf "$tmp/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C "$BIN_DIR" trivy ;;
    syft)
      base="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}"
      fetch_verify "$base" "syft_${SYFT_VERSION}_linux_amd64.tar.gz" "syft_${SYFT_VERSION}_checksums.txt"
      tar -xzf "$tmp/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -C "$BIN_DIR" syft ;;
    *) echo "unknown tool: $1" >&2; exit 2 ;;
  esac
  echo "installed and verified: $1"
}

for t in "$@"; do install_tool "$t"; done
echo "$BIN_DIR" >> "${GITHUB_PATH:-/dev/null}"
