#!/usr/bin/env bash
# Build the Claude Desktop bundle (.mcpb) for one imcp2-local release.
#
#   .github/scripts/build-mcpb.sh <tag> <out-dir>
#   e.g. .github/scripts/build-mcpb.sh v0.6.0 dist-mcpb
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
# The MCPB CLI that validates and packs the bundle comes from
# .github/scripts/mcpb-cli/package-lock.json, which pins its whole dependency
# tree with integrity hashes; it is installed with `npm ci --ignore-scripts`,
# so a release never resolves a dependency afresh or runs an install script.
#
# Env:
#   LIPO                   lipo implementation (default `lipo`; `llvm-lipo` works off macOS)
#   MCPB_ALLOW_UNATTESTED  `1` builds without verifying provenance; refused in CI
set -euo pipefail

tag="${1:?usage: build-mcpb.sh <tag> <out-dir>}"
out="${2:?usage: build-mcpb.sh <tag> <out-dir>}"
case "$tag" in
  v[0-9]*) ;;
  *) echo "not a vX.Y.Z release tag: $tag" >&2; exit 2 ;;
esac
version="${tag#v}"
base="https://github.com/dfinity/imcp2/releases/download/$tag"
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
lipo="${LIPO:-lipo}"

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
    --signer-workflow dfinity/imcp2/.github/workflows/v-release.yml \
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
# Each slice must come out of lipo exactly as it went in: that is what keeps
# the arm64 slice's signature valid, and what the archives' attestations
# vouch for. Checking for the architecture names alone would miss a lipo that
# rewrote one; `-thin` also fails outright if a slice is missing.
for pair in arm64:aarch64-apple-darwin x86_64:x86_64-apple-darwin; do
  a="${pair%%:*}"
  t="${pair#*:}"
  "$lipo" -thin "$a" -output "$work/slice-$a" "$bundle/server/imcp2-local"
  if ! cmp -s "$work/slice-$a" "$work/imcp2-local-$t/imcp2-local"; then
    echo "the universal binary's $a slice differs from the attested $t binary" >&2
    exit 1
  fi
done
archs="$("$lipo" -archs "$bundle/server/imcp2-local")"

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

# That was the last fetch, and nothing below needs a credential. What runs
# below does include code this repository didn't write (the mcpb CLI and its
# npm dependencies), so drop credentials from the environment first. This
# only narrows the exposure: a child can still read its parent's original
# environment. The boundary is the workflow's: the job running this holds no
# write or signing rights (see .github/workflows/imcp2-local-mcpb.yml). It also
# keeps a developer's own token out of a local build's subprocesses.
unset GH_TOKEN GITHUB_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN

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

# The locked CLI, installed into the scratch directory so the checkout stays
# clean. `npm ci` refuses a lockfile that disagrees with package.json and
# checks every tarball against its recorded integrity hash.
cli="$work/mcpb-cli"
mkdir -p "$cli"
cp "$repo_root/.github/scripts/mcpb-cli/package.json" \
   "$repo_root/.github/scripts/mcpb-cli/package-lock.json" "$cli/"
(cd "$cli" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error)
mcpb="$cli/node_modules/.bin/mcpb"

"$mcpb" validate "$bundle/manifest.json"
mkdir -p "$out"
"$mcpb" pack "$bundle" "$out/imcp2-local.mcpb"
echo "built $out/imcp2-local.mcpb for $tag ($(echo "$tools" | jq length) tools; macOS slices: $archs)"
