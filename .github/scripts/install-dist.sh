#!/usr/bin/env bash
# Install the `dist` (cargo-dist) release tool into ~/.cargo/bin, pinned by
# digest.
#
#   bash .github/scripts/install-dist.sh
#
# v-release.yml runs this in every job that installs dist, in place of the
# install script dist generates, so each job runs the same pinned build (as
# ci.yml does for PocketIC). The archive for the runner's platform is
# downloaded to a file and must match the digest recorded below before it is
# extracted; a mismatch, or a platform with no recorded digest, fails the job.
#
# Bumping `cargo-dist-version` in dist-workspace.toml means updating VERSION
# and every digest here, from archives checked independently of the release
# that serves them.

set -euo pipefail

VERSION=0.31.0

case "${RUNNER_OS:-}-${RUNNER_ARCH:-}" in
  Linux-X64)
    target=x86_64-unknown-linux-gnu ext=tar.xz
    want=cd355dab0b4c02fb59038fef87655550021d07f45f1d82f947a34ef98560abb8 ;;
  Linux-ARM64)
    target=aarch64-unknown-linux-gnu ext=tar.xz
    want=382cc29ff91ef12a5bf78ad8ee1804661d24e2fbe64b1bdedd6078723b677ae5 ;;
  macOS-X64)
    target=x86_64-apple-darwin ext=tar.xz
    want=fd4d8f9f07802359cbcdc52bac3abd7d5201c4b73a7cbcdd6faca2232a389f0c ;;
  macOS-ARM64)
    target=aarch64-apple-darwin ext=tar.xz
    want=decb01c64c12501931c3cac3111b368a7f48adf8d9e65455c08e5757b9a1fd6f ;;
  Windows-X64)
    target=x86_64-pc-windows-msvc ext=zip
    want=a14e17557b269b101405e0cc6b647581d56313c954a51c7fddd423bba21e17b2 ;;
  *)
    echo "install-dist: no pinned dist archive for '${RUNNER_OS:-}-${RUNNER_ARCH:-}'" >&2
    exit 1 ;;
esac

# Not every macOS has `sha256sum`; see build-mcpb.sh.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

asset="cargo-dist-$target.$ext"
bindir="$HOME/.cargo/bin"
work="$(mktemp -d)"
cd "$work"

curl --proto '=https' --tlsv1.2 -fLsS --retry 3 -o "$asset" \
  "https://github.com/axodotdev/cargo-dist/releases/download/v$VERSION/$asset"
got="$(sha256 "$asset")"
if [ "$got" != "$want" ]; then
  echo "install-dist: checksum mismatch for $asset: want $want, got $got" >&2
  exit 1
fi

mkdir -p "$bindir"
if [ "$ext" = zip ]; then
  # The Windows archive is flat: dist.exe at its root.
  pwsh -NoProfile -NonInteractive -Command \
    "Expand-Archive -LiteralPath '$asset' -DestinationPath out"
  cp out/dist.exe "$bindir/dist.exe"
else
  tar -xJf "$asset"
  cp "cargo-dist-$target/dist" "$bindir/dist"
  chmod +x "$bindir/dist"
fi

# Like dist's own installer, put the install directory on later steps' PATH.
if [ -n "${GITHUB_PATH:-}" ]; then
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$bindir"
  else
    echo "$bindir"
  fi >> "$GITHUB_PATH"
fi
