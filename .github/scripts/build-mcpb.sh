#!/usr/bin/env bash
# Build the Claude Desktop bundle (.mcpb) for one imcp2-local release.
#
#   .github/scripts/build-mcpb.sh <tag> <out-dir>
#   e.g. .github/scripts/build-mcpb.sh imcp2-local-v0.5.0 dist-mcpb
#
# The bundle is assembled from the release's own published archives, so it
# carries exactly the binaries that release attests, each checked against the
# release's .sha256 before use:
#
#   server/imcp2-local      universal macOS binary (arm64 + x86_64)
#   server/imcp2-local.exe  Windows x64
#
# Why universal: MCPB's `platform_overrides` key on the OS alone
# (darwin/win32/linux), not the CPU, so one bundle cannot choose between the
# Apple Silicon and Intel builds. One fat Mach-O runs on both. Windows needs
# no override: for binary servers Claude Desktop appends `.exe` to the
# command itself, so the manifest names the file without it.
#
# Every input archive must carry this repository's release-workflow
# attestation for this very tag before it is used (see verify_provenance).
#
# The manifest's version and tool list are filled in here, the tools from the
# release's own binary answering `tools/list`, so the install dialog can
# never advertise a surface the shipped server doesn't have.
#
# Env:
#   LIPO                   lipo implementation (default `lipo`; `llvm-lipo` works off macOS)
#   MCPB_VERSION           @anthropic-ai/mcpb CLI version (pinned below)
#   MCPB_ALLOW_UNATTESTED  `1` builds without verifying provenance; refused in CI
set -euo pipefail

tag="${1:?usage: build-mcpb.sh <tag> <out-dir>}"
out="${2:?usage: build-mcpb.sh <tag> <out-dir>}"
case "$tag" in
  imcp2-local-v*) ;;
  *) echo "not an imcp2-local release tag: $tag" >&2; exit 2 ;;
esac
version="${tag#imcp2-local-v}"
base="https://github.com/dfinity/imcp2/releases/download/$tag"
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
lipo="${LIPO:-lipo}"
mcpb="@anthropic-ai/mcpb@${MCPB_VERSION:-2.1.2}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Verifying the inputs' provenance needs `gh`. A local build may opt out
# explicitly, whether or not `gh` is installed, and says so loudly; CI never
# may, and fails rather than quietly verifying anyway.
if [ "${MCPB_ALLOW_UNATTESTED:-}" = "1" ]; then
  if [ -n "${CI:-}" ]; then
    echo "MCPB_ALLOW_UNATTESTED is refused in CI: a released bundle's inputs are always verified" >&2
    exit 1
  fi
  attested=0
  echo "WARNING: building from inputs whose provenance is NOT verified (MCPB_ALLOW_UNATTESTED=1)" >&2
elif command -v gh >/dev/null 2>&1; then
  attested=1
else
  echo "gh is required to verify the input archives' attestations" \
       "(outside CI, MCPB_ALLOW_UNATTESTED=1 builds without)" >&2
  exit 1
fi

# The .sha256 files come from the same mutable release as the archives, so
# they catch a corrupted download but cannot catch a replaced one — and this
# job goes on to attest what it builds, which would lend that attestation to
# whatever sat in the release. So each input must also carry an attestation
# from this repository's release workflow for this very tag; `--source-ref`
# refuses even a genuinely attested archive from an older release.
verify_provenance() {
  gh attestation verify "$1" --repo dfinity/imcp2 \
    --signer-workflow dfinity/imcp2/.github/workflows/imcp2-local-release.yml \
    --source-ref "refs/tags/$tag" --deny-self-hosted-runners >/dev/null
}

# Not every macOS has `sha256sum` (older releases have only `shasum`) — the
# very gap the release notes warn about in the installer, which then skips its
# check. This falls back instead of repeating that.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Download one release asset and refuse it unless it matches the release's
# published checksum.
fetch() {
  local asset="$1" want got
  curl -fsSL --retry 3 -o "$work/$asset" "$base/$asset"
  curl -fsSL --retry 3 -o "$work/$asset.sha256" "$base/$asset.sha256"
  want="$(awk '{print $1}' "$work/$asset.sha256")"
  got="$(sha256 "$work/$asset")"
  if [ "$want" != "$got" ]; then
    echo "checksum mismatch for $asset: want $want, got $got" >&2
    exit 1
  fi
  if [ "$attested" = 1 ] && ! verify_provenance "$work/$asset"; then
    echo "$asset has no release-workflow attestation for $tag; refusing it" >&2
    exit 1
  fi
}

fetch imcp2-local-aarch64-apple-darwin.tar.xz
fetch imcp2-local-x86_64-apple-darwin.tar.xz
fetch imcp2-local-x86_64-pc-windows-msvc.zip
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  tar -xJf "$work/imcp2-local-$t.tar.xz" -C "$work"
done
mkdir -p "$work/win"
unzip -q "$work/imcp2-local-x86_64-pc-windows-msvc.zip" -d "$work/win"

bundle="$work/bundle"
mkdir -p "$bundle/server"
"$lipo" -create -output "$bundle/server/imcp2-local" \
  "$work/imcp2-local-aarch64-apple-darwin/imcp2-local" \
  "$work/imcp2-local-x86_64-apple-darwin/imcp2-local"
chmod 0755 "$bundle/server/imcp2-local"
archs="$("$lipo" -archs "$bundle/server/imcp2-local")"
for a in arm64 x86_64; do
  case " $archs " in
    *" $a "*) ;;
    *) echo "universal binary is missing the $a slice (has: $archs)" >&2; exit 1 ;;
  esac
done

exe="$(find "$work/win" -type f -name 'imcp2-local.exe' | awk 'NR == 1')"
if [ -z "$exe" ]; then
  echo "no imcp2-local.exe in the Windows archive" >&2
  exit 1
fi
cp "$exe" "$bundle/server/imcp2-local.exe"
cp "$repo_root/crates/imcp2-local/mcpb/icon.png" "$bundle/icon.png"

# A binary this host can execute, to ask the shipped server for its tools.
case "$(uname -s)-$(uname -m)" in
  Darwin-*) host_bin="$bundle/server/imcp2-local" ;;
  Linux-x86_64 | Linux-aarch64)
    t="$(uname -m)-unknown-linux-gnu"
    fetch "imcp2-local-$t.tar.xz"
    tar -xJf "$work/imcp2-local-$t.tar.xz" -C "$work"
    host_bin="$work/imcp2-local-$t/imcp2-local"
    ;;
  *) echo "cannot introspect the tool list on $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

tools="$(python3 - "$host_bin" <<'PY'
import json, os, re, subprocess, sys

proc = subprocess.Popen(
    [sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
    env=dict(os.environ, IMCP2_NO_OPEN="1", RUST_LOG="error"),
)

def call(rid, method, params):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())

call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "build-mcpb", "version": "0"}})
proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
proc.stdin.flush()
listed = call(2, "tools/list", {})["result"]["tools"]
proc.kill()

def summary(tool):
    # The server's own display title where it has one ("Get Candid
    # interface"); otherwise the description's first sentence.
    title = (tool.get("annotations") or {}).get("title") or tool.get("title")
    if title:
        return title
    text = " ".join((tool.get("description") or "").split())
    first = re.match(r"(.+?[.!?])(?:\s|$)", text)
    return (first.group(1) if first else text)[:240]

print(json.dumps([{"name": t["name"], "description": summary(t)} for t in listed]))
PY
)"

jq --arg version "$version" --argjson tools "$tools" \
  '.version = $version | .tools = $tools' \
  "$repo_root/crates/imcp2-local/mcpb/manifest.base.json" > "$bundle/manifest.json"

npx -y "$mcpb" validate "$bundle/manifest.json"
mkdir -p "$out"
npx -y "$mcpb" pack "$bundle" "$out/imcp2-local.mcpb"
echo "built $out/imcp2-local.mcpb for $tag ($(echo "$tools" | jq length) tools; macOS slices: $archs)"
