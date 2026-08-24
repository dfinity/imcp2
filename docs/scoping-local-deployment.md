# IMCP2 local deployment: a minimal stdio binary

Status: **draft** — design only, no code changes in this PR. This is the **full** design doc,
carrying code-level detail and evidence; a concise, high-level companion lives in
[`local-deployment.md`](local-deployment.md).

## Summary

We will ship **`imcp2-local`**: a separate, minimal binary that a user runs on their own
machine and connects to their AI tool of choice. It speaks MCP over **stdio**, talks to
**mainnet IC** (`https://icp-api.io`) and **production Internet Identity** (`https://id.ai`),
keeps the full Internet Identity session model (login with the user's real anchor, on-demand
per-app account delegations), and **drops the entire OAuth 2.1 authorization-server layer**.
Login runs as a **built-in browser handshake**: the binary opens the user's browser to II and
receives the delegation on a transient localhost callback.

The existing crate keeps its name and role: **`imcp2`** remains the published library and the
hosted server binary. The shared components move down into a new **`imcp2-core`** crate that
both the hosted server and the local binary build on, so `imcp2-local` compiles a genuinely
minimal dependency closure.

## Problem

Today the only way to use the IMCP2 tools is the **hosted** server: a public, multi-tenant
streamable-HTTP endpoint gated by an OAuth 2.1 authorization server. That shape is right for
cloud AI surfaces, but it forces two costs on a user who works from a desktop/CLI/IDE tool:

- **Trust.** The user's Internet Identity login — and every per-app account delegation minted
  from it — runs through a third-party server. A user acting on their real mainnet accounts
  (balances, canisters, cycles) may reasonably want the bridge to run on their own machine,
  where the session keys never leave a process they control.
- **Unnecessary machinery.** The OAuth 2.1 layer (bearer tokens, PKCE, dynamic client
  registration, redirect allow-lists, discovery documents) exists so *remote, third-party*
  clients can authenticate to a *public* endpoint. A single-user server reached over a stdio
  pipe by the client that spawned it needs none of it — carrying it anyway means more
  dependencies, more attack surface, and an operational state directory the local case
  doesn't want.

Meanwhile, the AI tools users actually run — Claude Desktop/Code, Codex, Cursor, Antigravity,
Perplexity's macOS app — all support spawning **local stdio MCP servers**, and their built-in
OAuth support applies only to *remote* servers. There is currently no IMCP2 artifact that
fits that slot.

## Non-goals

- **No change to the hosted server's behavior, name, or deployment.** The `imcp2` binary,
  Dockerfile (`CMD ["imcp2"]`, `Dockerfile:23,31`), `imcp2.service`, and deploy scripts stay
  as they are.
- **No session persistence in v1.** Sessions are in-memory (re-login per run), matching the
  hosted model and the existing roadmap; keychain-backed persistence is future work.
- **Not a path for cloud-only AI surfaces.** claude.ai web/mobile, Perplexity web/Windows,
  and Codex Cloud cannot reach `localhost`; they keep using the hosted server (which is why
  the OAuth layer stays in `imcp2` rather than being deleted).
- **No new auth scheme.** The local binary adds no API keys or tokens of its own; the OS
  process boundary replaces the bearer gate, and Internet Identity remains the only login.

## Approach

Hosted-vs-local is a **deployment axis, not a network one** — both talk to the same mainnet
and the same production II. What changes is who can reach the server and therefore what
machinery is needed:

| | Hosted `imcp2` (today) | `imcp2-local` (this design) |
|---|---|---|
| Where it runs | a public server | the user's own machine |
| MCP transport | streamable-HTTP | **stdio** |
| Reached by | remote, third-party MCP clients | the co-located client that spawned it |
| Client auth | **OAuth 2.1** (bearer tokens, PKCE, DCR) | **none** (process boundary) |
| II login | OAuth-wrapped connect handshake | **built-in browser handshake** |
| IC / II target | mainnet + prod II (beta opt-in) | mainnet + production II |

Decisions locked with the requester:
- **Separate binary**, minimal dependencies (a second crate, not a runtime flag).
- **stdio** MCP transport.
- **No OAuth 2.1** authorization server.
- **Built-in browser II handshake**: the binary mints the session key, opens the browser to
  production II, receives the delegation on a transient localhost callback, redeems it, and
  holds the session in memory.

Because it is single-user and reachable only through the pipe of the client that launched it,
dropping OAuth removes no security the local case needs — while keeping Internet Identity
preserves exactly what matters: the user logs in with their real anchor and acts as their
real II accounts on real mainnet apps, from a bridge they run themselves.

Every claim below was verified against the current code (v0.2.0 tree); `file:line`
references point at it.

## Design components

### 1. Crate layout — `imcp2-core` under `imcp2` and `imcp2-local`

The crate names stay stable — **`imcp2`** keeps its published identity (`Cargo.toml:2`) and
its binary name (the Dockerfile `CMD ["imcp2"]`, `imcp2.service`, and the deploy scripts all
build/run a binary named `imcp2` — `Dockerfile:23,31`, `deploy/native/*`) — and the shared
components move **down** into a new **`imcp2-core`** crate that both binaries build on. The
library's job is to expose components from which either a hosted binary (HTTP router, OAuth
AS) or a local binary can be composed; the crate boundary is what keeps the local closure
minimal.

- **`imcp2-core`** (lib, new) — the transport/OAuth-agnostic components:
  - `identities.rs` **kept verbatim** (the II session-key grant + on-demand per-app account
    delegations against production II — `IiInstance::prod()` at `identities.rs:185`,
    `registration_pubkey_b64` `:595`, `redeem_registration_delegation` `:936`,
    `delegated_identity_for` `:1030`, `list_accounts` `:873`).
  - `calls.rs` (Candid textual↔binary codec, `raw_call`), `discover.rs` (discovery + SSRF
    guard), `management.rs`, `skills.rs`.
  - `tools.rs` — the **entire** MCP tool surface. The `#[tool_router]` / 26×`#[tool]` /
    `#[tool_handler] impl ServerHandler for IcTools` macros expand into one impl on
    `IcTools` and **must stay co-located**; both binaries construct `IcTools` and differ
    only in transport + session source. The `SessionSource` seam and the plain
    `AuthedSession` struct (component 7) live here.
  - **new `iiconnect` module** — the II connect-handshake primitives lifted out of
    `auth.rs` (component 4), re-parameterised to plain values so they carry no
    `AuthStore`/OAuth state.
  - the `include_str!` assets those modules compile in: `static/` (the Candid/OQL
    references) and the connect-flow assets under `src/assets/` (page, CSS, logo).
  - Deps: rmcp `["server", "macros"]` (no transport), `ic-agent`/`candid`/`candid_parser`,
    tokio, serde/serde_json, reqwest/url/regex (discovery), the II-connect and management
    utilities (`base64`, `hex`, `sha2`, `crc32fast`, `getrandom`, `uuid`, `urlencoding`),
    `http` (the request-extension type the Bearer session arm reads), tracing.
- **`imcp2`** (existing crate: lib + the hosted `imcp2` binary) — depends on `imcp2-core`
  and adds the hosted composition: the OAuth 2.1 AS (the OAuth half of `auth.rs`),
  `McpServer`/`McpConfig`/the routers (`lib.rs`, including `state_dir`/`clients`/
  `require_resource`), `metrics.rs` + `prometheus`, `main.rs` + the landing-page assets,
  `tests/routers.rs`, and the PocketIC `e2e` harness (`src/e2e_handshake.rs` drives the
  OAuth routes, so it stays here with its optional `pocket-ic` dep). It **re-exports**
  `imcp2-core`'s public items (`pub use`), so existing embedders' `imcp2::…` imports keep
  compiling — the restructure is a minor version bump, not a break. `cargo build` here
  produces the `imcp2` server exactly as today; deploy configs unchanged.
- **`imcp2-local`** (bin, new) — depends on **`imcp2-core` only**: a few hundred lines that
  serve `IcTools` over rmcp's stdio transport (features `["server", "macros",
  "transport-io"]`), plus the browser-handshake login driver and the transient loopback
  callback listener. `axum`, `tower-http`, `prometheus`, and every OAuth module are simply
  **absent from its dependency graph** — under any build invocation, not just `-p` builds.

(One benign note: a `--workspace` build compiles rmcp once with both transport features
unified — harmless, the linker strips the unused transport; the isolation that matters is
that the OAuth/HTTP code never enters `imcp2-local`'s graph at all.)

**Published crates.** `imcp2` is on crates.io (v0.2.0), released from `v*` tags via trusted
publishing with a tag-equals-version guard (`.github/workflows/publish-crate.yml`). Because
crates.io does not accept path-only dependencies of a published crate, `imcp2-core` becomes a
second published crate: publish order core → `imcp2`, and the publish workflow is generalised
per-crate. Recommend versioning `imcp2-core` 0.x and documenting it as internal to the imcp2
family — its API is consumed through `imcp2`'s re-exports, with no independent stability
promises — so component-level churn doesn't force `imcp2` majors. Whether `imcp2-local`
itself is published (vs distributed as release binaries) is an independent choice; nothing
depends on it. The `.crate` packaging constraint carries over: `src/assets` and `static/`
ship with the crate that `include_str!`s them, i.e. they move to `imcp2-core`.

### 2. Dependency profile

The dependency story follows the crate boundaries: `imcp2-core` carries what the components
need and nothing HTTP-shaped; `imcp2` adds the hosted stack; `imcp2-local` adds a stdio
transport and a browser-opener.

**Baseline facts the split relies on.** The crate's direct dependencies are already lean:
all Ed25519 keygen/signing goes through `ic-agent`'s `BasicIdentity::from_raw_key`
(`fresh_ed25519`, `identities.rs:1252`); delegation chains are verified inside `ic-agent` —
client-side against the injected agent's root key (`DelegatedIdentity::new_with_root_key`,
`identities.rs:1285-1303`) and again by the replica at redeem — so no standalone
crypto-verification crates are involved; and every `schemars::JsonSchema` derive resolves
through `use rmcp::schemars` (rmcp's re-exported 1.x), so there is no direct schemars
dependency.

**In `imcp2-core`:**
- MCP: rmcp with features `["server", "macros"]` — no transport; each binary adds its own.
- IC + II: `ic-agent`, `candid` (`value`), `candid_parser`.
- discovery: `reqwest` (SSRF-pinned client, `discover.rs`), `url`, `regex`.
- canister management: `sha2` (Wasm hash + ledger AccountIdentifier), `crc32fast`, `base64`,
  `hex` (`management.rs`).
- II connect/delegation: `getrandom` (key seeds + CSP nonce), `urlencoding` (II link),
  `uuid` (connect `state`), `base64`/`hex` (delegation chain), `http` (the request-extension
  type the session lookup reads).
- foundation: `tokio`, `serde`, `serde_json`, `tracing`, `anyhow`.

**Added by `imcp2` (the hosted stack):** rmcp's `transport-streamable-http-server`; `axum`;
`tower-http` (CORS for the MCP endpoint's browser clients and the OAuth/well-known routes);
`prometheus` + `src/metrics.rs` (the `/metrics` exposition behind `MCP_SERVE_METRICS` —
axum-typed middleware coupled to `McpServer`; the `SessionGauges` counters it reads are plain
integers in core's `identities.rs`); `tokio-util` (cancellation for the streamable-HTTP
sessions); `tokio`'s `signal` (graceful HTTP drain) and `time` (session-reaper tick, OAuth
persist throttle) features; `sha2`'s second use, the OAuth PKCE S256 check; dev-deps `tower`
+ `http-body-util` (the HTTP router tests); and the optional `pocket-ic` behind the `e2e`
feature (`src/e2e_handshake.rs`). rmcp's `auth` feature is not used by either binary — the
OAuth AS is hand-rolled.

**Added by `imcp2-local`:** rmcp's `transport-io` (`rmcp::transport::stdio()` over tokio
stdin/stdout, in place of `StreamableHttpService`), `axum` (the transient login listener),
`open` (browser launch), and `tracing-subscriber` (stderr logging); dev-dependency:
`pocket-ic` (the local-flow integration tests, component 3).

The local binary's one HTTP surface is the transient login callback (component 5) — three
loopback routes served with **axum**, the same shape as the ICP CLI's web-identity flow
(`icp identity link web`: an axum `Router` on a `TcpListener` at `127.0.0.1:0`, graceful
shutdown on completion — `crates/icp-cli/src/commands/identity/link/web.rs`). `tower-http`
is still not needed: the only CORS requirement is one `Access-Control-Allow-Origin` header
on the `#4091` well-known, set directly on that response.

Net minimal local deps: `imcp2-core` +
`rmcp{server,macros,transport-io}` + `tokio` +
`anyhow` + `serde_json` + `url`/`urlencoding` + `tracing`/`tracing-subscriber` + a
browser-opener (`open` crate, or `std::process::Command`).

### 3. Mainnet and production II wiring

No replica changes: the local agent is `Agent::builder().with_url(IC_URL).build()` with
`IC_URL = "https://icp-api.io"` and **no** `fetch_root_key` (mainnet root key is baked in).
`Identities::new(IiInstance::prod()?, public_url, agent)` — production II. `public_url` is
only used as the management-identity derivation origin (`identities.rs:861-863`) and can be a
fixed local value; it need not be a reachable server.

The prod instance is env-overridable via `II_URL_PROD`/`II_CANISTER_ID_PROD`
(`identities.rs:185-190`; the plain `II_URL`/`II_CANISTER_ID` pair now overrides only
`IiInstance::beta()`), so the binary can be pointed at beta II for testing. The hosted
deployment serves **production II at `/mcp`** (beta is the opt-in `/mcp-beta` staging
instance), so the same II contract this binary relies on is exercised in production (see
Verification under Implementation Stages).

**Local-replica test configuration (the integration-test vehicle).** The same wiring
supports a test build that talks to a local replica: an explicit IC-endpoint override for
the agent, plus one `agent.fetch_root_key()` call so certificate verification trusts that
replica's key, plus the existing II overrides pointed at an II canister deployed there.
Guard: `fetch_root_key` is only ever called when the endpoint override is explicitly set to
a loopback target — refused otherwise — so a mis-set environment can never make a binary
trust a fetched root key against mainnet. Everything downstream works on a test network:
delegation chains are verified against the *injected agent's* root key
(`new_with_root_key`, `identities.rs:1285-1303`). Integration tests run this configuration
against **PocketIC** — the `pocket-ic` dev dependency, reusing the e2e harness's
real-II-canister setup (see Verification); the same override also lets a developer point a
test build at any other local replica, such as one spawned by the ICP CLI.

### 4. Dropping OAuth 2.1, keeping the II handshake

`auth.rs` splits along the boundary its own module docs already draw (`auth.rs:24-60`).

**Kept for local (the de-OAuth'd II browser handshake):**
- `ii_mcp_url` (`auth.rs:1284`) — builds II's `/mcp#callback=…&state=…&ttl=…&registration_key=…`
  link. Re-parameterise from `&AuthStore` to plain values.
- the pinned callback page `connect_callback_page`/`pinned_callback_page` + assets + CSP nonce
  (`auth.rs:1342-1515`). II delivers the delegation in the URL **fragment**, so the callback
  *must* be an HTML page that reads `location.hash` client-side and POSTs it back.
- `parse_registration_delegation` + the `Json*` chain types + the 64 KB pre-parse bound
  (`auth.rs:1673-1782`).
- a slimmed `connect_redeem` (`auth.rs:1839`): shape-check the fragment, single-flight, call
  `Identities::redeem_registration_delegation`, signal completion — **minus** the PKCE/code/
  token/cookie/redirect tail.
- the **`#4091` allow-list** `/.well-known/ii-auth-callbacks` (`auth.rs:1304,1319`) — still
  mandatory: II fail-closed-fetches it before honoring the callback.

**Dropped (the entire OAuth 2.1 AS):** `/authorize` (`auth.rs:1053`), `/token` + PKCE + tokens
(`auth.rs:1969-2137`), `/register` + DCR + the persisted client store (`auth.rs:2139-2221`;
`SharedClients` now wraps a bounded `ClientStore` persisting `{state_dir}/oauth-clients.json`
per `McpConfig::state_dir`, `auth.rs:799-820`), the hosted-redirect allow-list
(`auth.rs:434-687`), AS/PR discovery metadata (`auth.rs:2223-2262`), the `require_token`
bearer gate + `bearer_challenge` (`auth.rs:2264,2313`), the front-channel HTML error-screen
machinery, RFC 8707 resource-indicator enforcement (the `require_resource` flag), RFC 9207
`iss` emission on redirects, and the bounded/atomically-persisted DCR store. `AuthStore`
slims to
`{identities, public_url, authz}` (loses `clients`/`tokens`/`codes`, plus the hosted-only
`mcp_path` route prefix — the local build replaces it with a plain callback-base value — and
`require_resource`). With `clients` gone the local binary needs **no `state_dir` at all**:
it writes no files, and all its state is the in-memory `Identities` session map.

**Consent-Bound Completion / the initiator cookie can be dropped locally.** The `sid` cookie
(`auth.rs:170`, checked `:1869`) defends a *split-browser confused-deputy* that requires a
public, multi-tenant initiate endpoint an attacker can start a connect on. Locally there is
**no HTTP initiate endpoint**: the binary itself mints `X`, `priv(X)` never leaves the
process, and `/redeem` is loopback-only and single-user. The consenter proof alone — the
delegation's final hop must target the in-memory `X`, replica-verified at redeem
(`registration_identity`, `identities.rs:1285`) — suffices; keep the random `state` as the
callback↔connect correlator.

### 5. The built-in browser II login

1. Build the mainnet agent + `Identities` (prod II) once.
2. Mint the session: `registration_pubkey_b64(&session_id)` → in-memory Ed25519 `S` + the
   registration key `X`, returns base64url `pub(X)`. (Now fallible — it returns `Result`,
   refused only when the session map hits its CWE-770 capacity bound, which a single-user
   binary never does.)
3. Bind a transient listener on `127.0.0.1:0`; the callback origin is
   `http://127.0.0.1:<port>`. Both the II link's `callback` and the well-known entry derive
   from this one value, so they cannot drift (II matches by exact string equality).
4. Build the II link (`iiconnect::ii_mcp_url`) against `https://id.ai` and surface it to the
   user **in-band** — as the text result of an `authenticate` MCP tool (component 6) — plus a
   best-effort server-side browser auto-open via `open::that` (the `open` crate, as in the
   ICP CLI); the flow never depends on the auto-open succeeding. Do **not** rely on
   **stderr** for the URL: every
   client routes a stdio server's stderr to a log file/panel, never the chat (component 6).
   stdout is the JSON-RPC channel, so all logging stays on stderr.
5. Serve exactly three loopback routes: `GET /callback` (the pinned fragment-reading page),
   `POST /redeem` (slim redeem → `redeem_registration_delegation`), and
   `GET /.well-known/ii-auth-callbacks` (the `#4091` allow-list, one `Access-Control-Allow-Origin: *`
   header since II fetches it cross-origin).
6. On redeem success, record the grant in memory and shut the listener down. `IcTools` now
   serves tools over stdio, minting per-app delegations on demand against mainnet.

The loopback listener is the unavoidable minimum, not a design slip: II delivers the
delegation by *navigating the browser* to the callback (a URL fragment only a served page can
read and POST back), and the `#4091` check *fetches* `/.well-known/ii-auth-callbacks` from
the callback's **origin** before honoring it — both require a real HTTP origin. A custom URI
scheme has no origin for that fetch (and component 6's client research found custom schemes
unreliably opened), and II's MCP contract offers no device-grant-style manual alternative
(the RFC 8628 device grant was dropped from this server early on). This is the standard
native-app loopback redirect (RFC 8252 §7.3) — the same shape as `gh auth login` /
`gcloud auth login`. The listener is transient (up for the handshake, torn down on redeem or
timeout) and never serves the tool surface (component 8).

Login is **lazy and non-blocking**: it runs as an MCP tool the agent calls on the first
authenticated action — not at startup (most clients require the user to approve the first tool
call, and some cap `initialize` at ~10 s) — and it returns the URL immediately rather than
blocking on the callback (Codex times out a tool call at 60 s; Claude Code auto-backgrounds
calls over 2 min). A follow-up `auth_status` tool (or simply the next tool call) confirms the
grant landed. Component 6 covers the per-client specifics.

Sessions are **in-memory** (re-login per run), matching today's model and the roadmap.
Optional future work: persist the session seed `S` to an OS keychain to survive restarts —
but `S` is a live capability to the user's real anchor, so never plaintext.

### 6. Working with AI tool clients

The local binary is a **stdio** MCP server, so it is reachable by any client that can **spawn a
local subprocess**, and unreachable by one that only connects to a remote **URL**. The five
requested clients split cleanly along that line (verified against current docs, mid-2026):

| Client / surface | Local stdio? | Where you register it | Reaches `imcp2-local`? |
|---|---|---|---|
| **Claude Desktop** (mac/Win) | yes | `claude_desktop_config.json` → `mcpServers`; or a `.mcpb` bundle (one-click install) | ✅ |
| **Claude Code** (CLI) | yes | `claude mcp add --transport stdio … -- <bin>`; `.mcp.json` / `~/.claude.json` | ✅ |
| claude.ai web / mobile / Cowork | no | remote connectors (OAuth) only | ❌ → hosted |
| **Codex** CLI / IDE ext / desktop | yes | `~/.codex/config.toml` → `[mcp_servers.<n>]` | ✅ |
| Codex Cloud | no | HTTP MCP only | ❌ → hosted |
| **Cursor** | yes | `~/.cursor/mcp.json` or `.cursor/mcp.json` → `mcpServers` | ✅ (≤40 tools total; we expose ~26) |
| **Perplexity** macOS app | yes (via a `PerplexityXPC` helper) | Settings → Connectors → Add → Advanced JSON | ✅ macOS only |
| Perplexity web / Windows / remote | no | remote HTTPS URL + OAuth 2.1 + DCR + `/.well-known/mcp-connector.json` | ❌ → hosted |
| **Antigravity** IDE / CLI / 2.0 | yes | `~/.gemini/config/mcp_config.json` or `.agents/mcp_config.json` → `mcpServers` | ✅ |

**Two classes, two binaries.** Every desktop/CLI/IDE surface — Claude Desktop, Claude Code,
Codex (CLI/IDE/desktop), Cursor, Antigravity, and the **Perplexity macOS app** — runs
`imcp2-local` directly. The cloud/remote-only surfaces — claude.ai web/mobile, Perplexity
web/Windows, Codex Cloud — cannot reach `localhost`; they need the **hosted `imcp2`** server
(the OAuth path kept in component 4). This is precisely why the OAuth layer stays in `imcp2`
rather than being deleted: it is the only way to serve the cloud clients.

**Registration** (absolute binary path everywhere; `imcp2-local` needs no args):

- Claude Desktop / Cursor / Antigravity all use a `mcpServers` JSON object:
  ```json
  { "mcpServers": { "imcp2": { "command": "/usr/local/bin/imcp2-local" } } }
  ```
  (Antigravity: `~/.gemini/config/mcp_config.json`; Cursor: `~/.cursor/mcp.json`; Claude
  Desktop: `claude_desktop_config.json`, or ship a `.mcpb` bundle for one-click install.)
- Claude Code: `claude mcp add --transport stdio imcp2 -- /usr/local/bin/imcp2-local`
- Codex (`~/.codex/config.toml`):
  ```toml
  [mcp_servers.imcp2]
  command = "/usr/local/bin/imcp2-local"
  ```
- Perplexity macOS: Settings → Connectors → Add Connector → Advanced (needs the PerplexityXPC
  helper): `{ "command": "/usr/local/bin/imcp2-local", "args": [], "env": {} }`

These are the raw registration formats; component 9 gives the end-user setup paths that
avoid editing them by hand.

**Cross-client login invariants** (every subprocess-capable client agreed):
1. **Host OAuth never touches a stdio server.** All five drive OAuth only for *remote* servers;
   for a local stdio server the host just pipes stdin/stdout. So the II login is entirely the
   binary's own browser handshake (component 5) — which also sidesteps Antigravity's
   known-buggy remote MCP-OAuth.
2. **stderr is not shown in chat — anywhere.** Claude, Codex, Cursor, and Antigravity all route
   a stdio server's stderr to a log file/panel, and stdout is reserved for JSON-RPC. So the
   login URL is surfaced **in-band**: the `authenticate` tool returns it as text (the model
   relays it; Claude Desktop linkifies `http(s)`), backed by a best-effort browser auto-open.
   Use a plain `http(s)://…` URL — custom URI schemes are not reliably opened.
3. **First tool call needs approval.** Cursor/Antigravity default to "Ask", Codex to its
   approval policy — so login cannot run silently at startup; it triggers lazily on the first
   authenticated tool.
4. **Don't block on the callback** (Codex 60 s tool / 10 s `initialize`; Claude Code
   auto-backgrounds > 2 min): `authenticate` returns the URL and starts the listener
   immediately; a follow-up `auth_status` (or the next tool call) confirms completion.
5. **Absolute paths; stdout = JSON-RPC only** (all diagnostics to stderr). A self-contained
   native binary avoids the frequent wrong-runtime/path failures Node-based servers hit.

*(Implementation: `authenticate`/`auth_status` are **local-only** tools — defined in
`imcp2-core` but included in the tool router only when `IcTools` is constructed with the
singleton session source, so they never appear on the hosted server, which logs in via OAuth
instead. Cursor's ~40-tool cap is comfortable: the core exposes ~26 plus these.)*

**Serving the cloud clients (hosted `imcp2`).** claude.ai web/mobile and Perplexity-web reach
only a public HTTPS MCP endpoint with OAuth 2.1 — which hosted `imcp2` already is. Two
Perplexity-specific gaps to verify before claiming support there: it expects a
`/.well-known/mcp-connector.json` discovery document (not currently served), and its remote
OAuth has an open DCR bug that rejects RFC 7591 public-client registrations lacking a
`client_secret` (the same registrations that work on Claude/ChatGPT/Grok). Neither affects the
local binary.

### 7. Tool / session seam

Today a tool gets its `session_id` via bearer → `require_token` → `AuthedSession` injected in
the request extensions → `authed_session(ctx)` (`tools.rs:1493`). Under stdio there is one
user and one connection, so this collapses to a **singleton** session id set at login.

Minimal, verified seam (no tool-signature changes, no `identities.rs` changes):
- add `session: SessionSource { Bearer, Singleton(String) }` to `IcTools` (`tools.rs:52`);
- one `current_session_id(&self, &ctx) -> Option<String>` method replacing the free fn;
- rewrite the **13** lookup call-sites (`tools.rs:351,809,865,1298,1321,1344,1365,1386,1407,
  1428,1446,1464,1482`) to call it; the `.ok_or(…)` handling is unchanged;
- move the plain `AuthedSession` struct into `imcp2-core` beside the seam; the hosted
  `require_token` middleware (in `imcp2`) keeps inserting it into the request extensions.

The seam involves no conditional compilation: the Bearer arm reads `http::request::Parts`
(the `http` crate — axum merely re-exports it), which core depends on directly. Hosted
constructs `IcTools` with `Bearer`; local with `Singleton(sid)`.

Tools that are already session-free work unchanged locally: `get_canister_candid`,
`get_canister_api_doc`, `open_app`, `resolve_app`, `discover_app_canisters`, the skills/lookup
tools, and the anonymous path of `canister_query`.

### 8. Security model

**Trust boundary.** Dropping the bearer gate is sound *only because* the MCP tool surface
rides stdio: it has no listening socket — it is reachable only by the parent process holding
its stdin/stdout, i.e. the client that launched it. The one socket the binary ever opens is
the transient login listener (component 5), and reaching it confers nothing: the callback
page and the `#4091` well-known are static, and `/redeem` only advances the connect this
process started (`state` must match) with a chain targeting the in-process `X` — it can
neither invoke tools nor read the session. But the client then wields the user's
**real production II accounts** on mainnet (canister create/install/start/stop/delete, any
update call / cycles spend, per-app delegations for every origin). This must be stated plainly:
**treat the binary and its client config like a wallet.** There is no revocable token — only
the II grant (reconnect/expiry).

**Loopback hardening for the login listener:** bind `127.0.0.1` explicitly (never `0.0.0.0`);
validate the `Host` header (anti-DNS-rebinding — the `allowed_hosts_for` allow-list pattern,
`lib.rs:463-495`, which the hosted server feeds to rmcp via `with_allowed_hosts`,
`lib.rs:274`); up only for the
handshake. Even so, a rebinding attacker is largely inert: `/redeem` only advances the connect
*this* process started (`state` match) and `registration_identity` rejects any chain not
targeting our freshly-minted `X`.

### 9. End-user setup (UX)

The bar for setup: install the artifact, follow the prompts, sign in — **no JSON or config
editing anywhere**. Two things deliver that: per-client one-click/one-command paths where
the client provides one, and a `setup` subcommand in the binary for the rest.

| Client | What the user does |
|---|---|
| Claude Desktop | **Double-click the `imcp2.mcpb` bundle** → Claude Desktop shows its install dialog → Enable. (MCPB is Claude Desktop's plugin format; the bundle carries the per-platform binary and installs it in one step.) |
| Claude Code | Paste one command: `claude mcp add --transport stdio imcp2 -- <installed path>` |
| Codex (CLI / IDE / desktop) | Paste one command: `codex mcp add imcp2 -- <installed path>` |
| Cursor | Click the **"Add to Cursor"** install link on the docs page → Cursor opens its install prompt → Install. |
| Antigravity | Settings → Manage MCP Servers → Add (UI) — or run `imcp2-local setup`. |
| Perplexity (macOS) | Install Perplexity's local-MCP helper once (the app prompts for it), then Settings → Connectors → Add Connector and paste the binary path in the Simple tab. |

**`imcp2-local setup`** closes the remaining gaps: run once, it detects installed clients
(Claude Desktop, Claude Code, Codex, Cursor, Antigravity, Perplexity), shows what it will
register, and writes each client's MCP config itself — the user never opens a JSON/TOML
file. `imcp2-local setup --remove` undoes it. (What it writes is exactly the per-client
registration in component 6.)

**Upgrading.** Client registrations point at a stable install path, so an upgrade is a
binary swap at that path — nothing to re-register; each client picks the new version up the
next time it starts the server (typically on app restart). Distribution and updates follow
the ICP CLI: releases are built with cargo-dist (shell/PowerShell installers for the major
platforms, with `install-updater = true` shipping the standalone axoupdater program
alongside, so one `imcp2-local-update` run upgrades in place), and — like the ICP CLI's
`dist_update_suggestion` — the binary detects which channel installed it (axoupdater
receipt, Homebrew, npm) and, when a newer release exists, surfaces that channel's exact
upgrade command. The Claude Desktop bundle has its own channel: upgrades ship as new
`.mcpb` versions — double-click the new bundle to upgrade in place (directory-listed
extensions update automatically). There is nothing to migrate: the binary keeps no on-disk
state (sessions are in-memory), so after an upgrade the next use simply repeats the
one-step sign-in.

**Signing in** is then the same everywhere: on the first tool call that needs the user's
identity, the client asks to approve the `authenticate` tool, the browser opens to Internet
Identity, the user signs in, and the tab says it can be closed. The session lives in memory,
so quitting the client ends it; the next run repeats the same one-step sign-in.

### 10. Signing and provenance

Two distinct layers, for two different verifiers:

- **OS execution gates** (what lets the double-click work at all):
  - *macOS.* A browser-downloaded file carries the quarantine attribute, and Gatekeeper
    evaluates it at first execution — **including when an MCP client spawns the binary as a
    subprocess**, where a block surfaces as an opaque "server failed to start". Gatekeeper
    accepts exactly one thing: a **Developer ID** signature (Apple is the sole issuer of
    these certificates, via an Apple Developer Program *organization* membership) plus a
    **notarization** ticket. Pipeline: `codesign --options runtime --timestamp` on a macOS
    runner, then `xcrun notarytool submit --key <App Store Connect API key> --wait`. No
    installer artifact is needed — a bare signed + notarized binary passes (Gatekeeper
    checks its ticket online; stapling only matters for offline `.pkg`/`.dmg` installs).
    Without this, macOS blocks the file behind a buried System Settings "Open Anyway" flow
    (macOS 15 removed the right-click bypass) — unacceptable for a wallet-grade tool.
  - *Windows.* Authenticode via **Azure Trusted Signing** (Microsoft's managed service:
    org-validated identity, keys in a managed HSM as the CA/Browser rules require, a
    first-class GitHub Action, good SmartScreen reputation) — or an EV certificate through
    a cloud signing service (cargo-dist has built-in SSL.com eSigner support).
  - *Linux.* No OS gate; the cargo-dist release ships SHA256 checksums.
  - The shell installer, Homebrew, and npm channels never set the quarantine bit, so they
    work regardless — the OS-gate signing exists for the browser-download paths: the
    `.mcpb` and direct release downloads.
- **Supply-chain provenance**, uniform across every artifact (all three platforms' binaries
  and the `.mcpb`): **GitHub artifact attestations** — Sigstore-based and keyless (OIDC), so
  there are no long-lived signing secrets — verifiable with
  `gh attestation verify imcp2-local -R dfinity/imcp2`. This layer proves an artifact came
  from this repository's release workflow; it is for humans and auditors, and does not
  satisfy the OS gates above (Gatekeeper recognizes only Apple-issued signatures).
- **The `.mcpb` specifically.** Gatekeeper checks the **binary inside** the bundle
  (extraction inherits quarantine), so the per-OS signing above is the substance. The MCPB
  format does not currently specify bundle-level signing or install-time verification, so
  the bundle itself carries a provenance attestation, and trusted distribution comes from
  listing in Anthropic's extension directory (which also enables automatic updates).
- **Where it hooks in, and what DFINITY acquires.** The signing steps live in the
  cargo-dist release pipeline, with secrets in a protected GitHub environment (required
  reviewers — the same gating the deploy workflow uses). To acquire, with lead time for the
  org validations: an Apple Developer Program organization membership → a Developer ID
  Application certificate + an App Store Connect API key; an Azure Trusted Signing account
  (or an EV certificate); artifact attestations are free to enable.

One artifact per platform, with the `.mcpb` manifest pointing at the right per-OS binary;
building and signing these artifacts is a Stage 3 deliverable.

## Implementation Stages

**Stage 1 — extract `imcp2-core` (no behavior change to the `imcp2` binary).** Move
`identities/calls/discover/management/skills/tools` + the new `iiconnect` (extracted from
`auth.rs`) + `static/` + the connect assets into the new core crate; `imcp2` keeps the OAuth
AS, `McpServer`/`McpConfig`/`main.rs`, `metrics`, and the `e2e` harness, depends on core, and
re-exports its public items so embedders keep compiling. Apply the `SessionSource` seam
(component 7). *Exit:* the `imcp2` binary builds and its tests pass unchanged; `imcp2-core`
compiles standalone with no `axum`/`tower-http`/`prometheus`/OAuth in its graph.

**Stage 2 — the local binary.** `imcp2-local`: stdio `IcTools` server + the browser-handshake
login driver + the loopback callback listener. *Exit:* `cargo build -p imcp2-local`; a user
logs in against II and runs read/write tools as their accounts.

**Stage 3 — polish.** End-user packaging and setup (component 9: the `.mcpb` bundle, the
Add-to-Cursor link, the `setup` subcommand, the cargo-dist installers + updater — and
component 10's signing + attestation pipeline) and the
wallet-grade trust note; integration tests via the local-replica test configuration
(component 3), extending the PocketIC e2e harness to the local login flow (see
Verification); optional keychain-backed session persistence.

### Verification against production II

The II contract this binary depends on is already exercised end to end: the hosted
deployment serves **production II at `/mcp` on every deploy** (`main.rs:376-385`; beta is
the opt-in `/mcp-beta` staging instance), CI probes production health on a schedule, and a
hermetic end-to-end test of the full connect contract exists — `src/e2e_handshake.rs`
(`--features e2e`, optional `pocket-ic` dep, needs `II_WASM` + `POCKET_IC_BIN`) drives
register → authorize → the II registration-delegation ceremony → redeem → a real
`mcp_register_v2` → token against a real Internet Identity release build in PocketIC.
(Chains are verified client-side against the injected agent's root key —
`new_with_root_key`, `identities.rs:1285-1303` — so a binary pointed at a test network can
complete redemption after `fetch_root_key`, which is what makes a PocketIC-based test of the
*local* flow possible.)

What remains open is specific to the **local binary's `http://127.0.0.1` callback**, which
the hosted https deployment never exercises:
1. **Mixed content:** II's https document must `fetch()`
   `http://127.0.0.1:<port>/.well-known/…`. Loopback is "potentially trustworthy" (W3C Secure
   Contexts), so Chrome/Firefox allow https→http-loopback — prefer the `127.0.0.1` literal
   over the `localhost` name; Safari and enterprise policies are the unknowns.
2. **CORS:** the well-known response needs `Access-Control-Allow-Origin` (II fetches it
   cross-origin; `*` is fine with `credentials: omit`).

Verification plan: integration tests run `imcp2-local` in its **local-replica test
configuration** (component 3) against **PocketIC carrying a deployed II canister** — the
`pocket-ic` dev dependency, extending the existing e2e harness to drive the local
browser-handshake flow (loopback listener + slim redeem) with no live network. The
`II_URL_PROD`/`II_CANISTER_ID_PROD` overrides additionally allow pointing a binary at beta II.

## Appendix: evidence index

(Line refs stamped against the v0.2.0 tree, rebased onto `189fabd`.)

- Dependency baseline: no unused crypto deps in `Cargo.toml` (#100, `0e52fe9`); Ed25519 via
  `ic-agent` (`fresh_ed25519`, `identities.rs:1252`); chains verified by `ic-agent`
  client-side (`new_with_root_key`, `identities.rs:1285-1303`) and by the replica.
  `schemars` via `use rmcp::schemars` (all modules).
- rmcp features + streamable-HTTP wiring: `Cargo.toml:35-40`, `lib.rs:102-105,258-276`.
- Hosted-only surfaces: `prometheus`/`src/metrics.rs` (`lib.rs:76-81`, `Cargo.toml:64-69`,
  `MCP_SERVE_METRICS`); `McpConfig.state_dir`/`require_resource` (`lib.rs:144-158`,
  `IMCP2_STATE_DIR`/`OAUTH_REQUIRE_RESOURCE` in `main.rs`).
- OAuth AS vs II-connect split: `auth.rs:24-60` (module docs), handlers
  `auth.rs:1053/1987/2139`, connect subset `auth.rs:1284/1342-1515/1673-1782/1839`,
  `#4091` `auth.rs:1304/1319`.
- Session seam: `auth.rs:2264/2292`, `tools.rs:1493`, 13 call-sites listed in component 7.
- II login primitives: `identities.rs:595/936`, `ii_mcp_url` `auth.rs:1284`.
- Production II served at `/mcp` (#92, `main.rs:376-385`); PocketIC e2e handshake test
  `src/e2e_handshake.rs` (`e2e` feature); beta II constants `identities.rs:121-128`, candid
  verification note `identities.rs:929-935`, generic live-round-trip caveat
  `README.md:993-999`.
- Login listener + browser-open follow the ICP CLI's web-identity flow: axum `Router` on
  `TcpListener::bind("127.0.0.1:0")` with graceful shutdown, browser via `open::that`
  (`icp-cli` `crates/icp-cli/src/commands/identity/link/web.rs:284,347,375,378`; workspace
  deps `axum = "0.8"`, `open = "5"`).
- Distribution/updates follow the ICP CLI: cargo-dist with shell/PowerShell installers and
  `install-updater = true` (`icp-cli` `dist-workspace.toml`), channel detection + upgrade
  suggestion via axoupdater (`icp-cli` `crates/icp-cli/src/dist.rs:31,47-60`,
  `axoupdater = "0.10"`).
