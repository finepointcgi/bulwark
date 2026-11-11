#!/bin/sh
# Installs the latest Bulwark release (or BULWARK_VERSION) for this OS/CPU and verifies its
# SHA-256 against the release's SHA256SUMS before installing.
#
#   curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.sh | sh
#
# Env: BULWARK_REPO (owner/repo), BULWARK_VERSION (e.g. 1.2.0), BULWARK_INSTALL_DIR (default ~/.local/bin)
set -eu

repo="${BULWARK_REPO:-OWNER/REPO}"
dir="${BULWARK_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=osx ;;
  *) echo "unsupported OS: $(uname -s) (Windows: download the .exe from the releases page)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

if [ -z "${BULWARK_VERSION:-}" ]; then
  BULWARK_VERSION=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
fi
[ -n "$BULWARK_VERSION" ] || { echo "could not determine the latest release of $repo" >&2; exit 1; }

asset="bulwark-$BULWARK_VERSION-$os-$arch"
base="https://github.com/$repo/releases/download/v$BULWARK_VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1); else actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1); fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "checksum mismatch for $asset; not installing" >&2; exit 1; }

mkdir -p "$dir"
install -m 0755 "$tmp/$asset" "$dir/bulwark"
echo "Installed bulwark $BULWARK_VERSION to $dir/bulwark"
case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to your PATH." ;; esac
