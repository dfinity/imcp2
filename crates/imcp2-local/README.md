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

**Update calls carry the hosted server's authorization gate.** "The same tools"
includes the same write policy: `canister_update_call` requires an
`application_origin` that is a *registered* application — its developer having
accepted the [ICP MCP Developer Terms](https://mcp.internetcomputer.org/developer-terms)
— whose own `/.well-known/ic-architecture` manifest declares the target
canister, plus the financial guard inside that surface (see
[Update-call authorization](../../README.md#update-call-authorization)). The gate
lives in the shared `imcp2-core` tool implementation, so this binary cannot opt
out of it, and there is no local-mode bypass: **writing to your own canister
through this binary is refused unless it is registered.** Reads —
`canister_query`, `get_canister_candid`, the OQL tools, discovery — are
unaffected and need no registration. To install code, change settings, or run
lifecycle operations on canisters you control, use the
[`icp` CLI](https://github.com/dfinity/icp-cli).

## Install

Release binaries (macOS arm64/x64, Linux x64/arm64, Windows x64) ship from
this repository's GitHub releases with shell/PowerShell installers, built by
`dist` from `imcp2-local-v*` tags. Until the first release is cut, build from
source:

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
was built by this repository's release workflow:

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
