# imcp2-local

The Internet Computer MCP server for **local use**: a single-user binary your
AI tool (Claude Desktop, Claude Code, Codex, Cursor, Antigravity, the
Perplexity macOS app, …) spawns on your machine and talks to over **stdio**.
It serves the same tools as the hosted server at
[mcp.internetcomputer.org](https://mcp.internetcomputer.org) — canister reads
and writes in textual Candid, app discovery, OQL, canister management —
against the same **IC mainnet** and the same **production Internet
Identity**. What it drops is the hosted server's entire OAuth 2.1 layer: a
single-user process reached over a pipe needs no bearer tokens, so your II
login never passes through a third-party server.

Cloud-only AI surfaces (claude.ai web/mobile, Perplexity web, Codex Cloud)
cannot spawn local processes; they keep using the hosted server.

## Install

Release binaries (macOS arm64/x64, Linux x64/arm64, Windows x64) ship from
this repository's GitHub releases, built by `dist` from `imcp2-local-v*` tags.

**Verified install.** This binary acts as your Internet Identity, so prefer the
path that establishes where the artifact came from. Download the archive, check
its provenance against the workflow that built it, then install it into a
directory on your `PATH`:

```sh
# Resolve the newest binary release. `releases/latest` is NOT this crate's:
# production deploys publish `release-*` releases in this same repository, so
# the repository's latest release is usually one of those. Paginate rather
# than take a first page, for the same reason — this crate's tag is a small
# minority of the releases here.
TAG=$(gh api --paginate repos/dfinity/imcp2/releases --jq '.[].tag_name' \
        | grep -m1 '^imcp2-local-v')
TARGET=aarch64-apple-darwin   # or x86_64-apple-darwin, {x86_64,aarch64}-unknown-linux-gnu

# Chained: a failed download or a failed attestation stops the install.
curl -fLO "https://github.com/dfinity/imcp2/releases/download/$TAG/imcp2-local-$TARGET.tar.xz" &&
  gh attestation verify "imcp2-local-$TARGET.tar.xz" -R dfinity/imcp2 \
    --signer-workflow dfinity/imcp2/.github/workflows/imcp2-local-release.yml &&
  tar xf "imcp2-local-$TARGET.tar.xz" &&
  mkdir -p ~/.local/bin &&
  install "imcp2-local-$TARGET/imcp2-local" ~/.local/bin/
```

`~/.local/bin` stands in for any directory already on your `PATH`; the last
two commands create it and copy the binary there, nothing edits your shell
configuration.

(Windows ships `imcp2-local-x86_64-pc-windows-msvc.zip`; verify it the same way.)

**Installer script.** Shorter, and what the release notes lead with. It
downloads the binary for your platform, installs it plus an auto-updater into
`~/.cargo/bin`, and adds that directory to your PATH by appending a line to
every shell profile it can find — `IMCP2_LOCAL_NO_MODIFY_PATH=1` and
`IMCP2_LOCAL_DISABLE_UPDATE=1` opt out of those two. The shell script also
compares a checksum baked into itself, but skips that silently on stock macOS,
which has no `sha256sum`; the PowerShell installer checks none at all. Even
where the shell checksum runs, it ships inside the very script being piped to
a shell, so it catches a corrupted download rather than a bad release. On both
platforms the attestation above is what establishes provenance.

```sh
# Substitute the newest imcp2-local-v* tag; each release's notes carry the
# current command, and `releases/latest` is not this crate's release (above).
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/dfinity/imcp2/releases/download/imcp2-local-v0.5.0/imcp2-local-installer.sh | sh
```

**Claude Desktop bundle.** Each release also carries `imcp2-local.mcpb`.
Download it and double-click it: Claude Desktop installs and manages the
server itself — nothing lands on your `PATH`, and no `setup` is needed. It
holds a universal macOS binary (Apple Silicon and Intel) and the Windows one.
It is not yet code-signed, so expect Claude Desktop's unverified-developer
warning; on macOS, Gatekeeper may also refuse the server's first launch until
you allow it under System Settings → Privacy & Security. Organizations that
limit Claude Desktop to directory-listed extensions block it outright. The
bundle is attested like the archives, but by its own workflow:

```sh
gh attestation verify imcp2-local.mcpb -R dfinity/imcp2 \
  --signer-workflow dfinity/imcp2/.github/workflows/imcp2-local-mcpb.yml
```

**From source.**

```sh
cargo build --release -p imcp2-local
# binary at target/release/imcp2-local
```

## Register it with your AI tools

One command detects the clients installed on your machine and writes each
one's own MCP registration (with a one-time backup next to any file it
modifies):

```sh
imcp2-local setup            # register everywhere it can
imcp2-local setup --remove   # remove those imcp2 registrations
imcp2-local setup --print    # only show the per-client steps
```

Per client, that amounts to:

| Client | Registration |
|---|---|
| Claude Desktop | `claude_desktop_config.json` → `mcpServers.imcp2` |
| Claude Code | `claude mcp add --scope user --transport stdio imcp2 -- <path>` |
| Codex | `codex mcp add imcp2 -- <path>` when a recent `codex` is on PATH; else `$CODEX_HOME/config.toml` (default `~/.codex`) → `[mcp_servers.imcp2]` |
| Cursor | `~/.cursor/mcp.json` → `mcpServers.imcp2` |
| Antigravity | `~/.gemini/config/mcp_config.json` → `mcpServers.imcp2` |
| Perplexity (macOS) | Settings → Connectors → Add Connector → Advanced (the app's UI; `setup` prints the JSON to paste) |

Restart the client afterwards so it picks the server up.

## Signing in

On the first tool call that needs your identity, the agent calls the
`authenticate` tool: it answers with an [id.ai](https://id.ai) sign-in link
(and best-effort opens your browser), without blocking. Sign in with your
Internet Identity, pick the access level and session length on II's consent
screen, and the tab says it can be closed — the session is live. `auth_status`
(or simply retrying the original tool) confirms it.

Sessions are **in memory only**: you sign in again after a restart, when the
grant expires, or if you revoke it at id.ai (Manage access). Signing in again
is the same one-step browser round-trip — no client restart needed.

## Upgrading

Client registrations point at a stable installed path, so an upgrade is a
binary swap at that path — nothing to re-register, and no state to migrate
(the binary keeps nothing on disk). Installs made by the release installers
include the standalone updater: run `imcp2-local-update` to upgrade in place.

## Configuration

The defaults are production: IC mainnet (`https://icp-api.io`) and production
Internet Identity (`https://id.ai`). Environment overrides, mainly for tests:

| Variable | Effect |
|---|---|
| `IMCP2_IC_URL` | IC API endpoint. |
| `IMCP2_FETCH_ROOT_KEY` | Truthy: trust the endpoint's fetched root key — honoured **only** when `IMCP2_IC_URL` targets loopback (a local replica / PocketIC); startup refuses otherwise. |
| `II_URL_PROD` / `II_CANISTER_ID_PROD` | Override the Internet Identity instance (e.g. beta II, or an II canister in PocketIC). |
| `IMCP2_MANAGEMENT_ORIGIN` | Derivation origin of the canister-management identity. Defaults to the hosted server's origin so the same anchor keeps the same controller principal locally and hosted. |
| `IMCP2_NO_OPEN` | Truthy: never auto-open the browser on sign-in (the link is still returned in-band). |

All diagnostics go to stderr (`RUST_LOG` filters them); stdout is the MCP
JSON-RPC channel.

## Security model — treat it like a wallet

Whoever drives this binary **acts as your real Internet Identity accounts on
mainnet**, up to the access level and lifetime you chose on II's consent
screen. Concretely:

- The AI client that spawns the binary can call every tool as you — including,
  with full access, transfers and canister management. Prefer clients that ask
  before tool calls, and prefer **read-only** grants unless you need writes.
- Anything that can edit your client's MCP registration or replace the binary
  on disk can substitute a malicious server. Install from this repository's
  releases only, and verify downloads (below).
- The session key lives in the binary's memory and is never written to disk;
  the sign-in listener exists only during a login, on `127.0.0.1`, and serves
  only the login handshake. Revoke a session any time at id.ai.

## Verifying a download

Every platform archive carries a keyless provenance attestation proving it
was built by this repository's release workflow (the Claude Desktop bundle is
attested the same way by `imcp2-local-mcpb.yml`, which assembles it — see
Install):

```sh
# (Windows archives are .zip — substitute the extension.)
gh attestation verify imcp2-local-<target>.tar.xz -R dfinity/imcp2 \
  --signer-workflow dfinity/imcp2/.github/workflows/imcp2-local-release.yml
```

plus a SHA256 checksum alongside each archive. The convenience installers
(`.sh`/`.ps1`) and the checksum files themselves are assembled by the release
pipeline without their own attestations — verify the archive, or read an
installer before running it. macOS (Developer ID +
notarization) and Windows (Authenticode) code signing for the double-click
paths hooks into the same release pipeline once the organization's signing
credentials are in place — until then, install via the shell/PowerShell
installers, which are not subject to those OS gates.

## Releasing (maintainers)

Binary releases are cut by pushing an `imcp2-local-vX.Y.Z` tag (the version
must match this crate's `Cargo.toml`). Those tags must stay covered by the same
protected-tag ruleset as `v*`: the generated workflow publishes whatever commit
the tag names, so who can push the tag is the control that decides what ships; `.github/workflows/imcp2-local-release.yml`
(generated by `dist` from `dist-workspace.toml`) builds the five platform
archives, the installers, the updater companions, checksums, and the GitHub
attestations. Plain `vX.Y.Z` tags remain the crates.io publish trigger for
`imcp2`/`imcp2-core` and never ship binaries.
