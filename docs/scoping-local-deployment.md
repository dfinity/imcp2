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

The existing crate keeps its name and role: **`imcp2`** remains the shared library (published
on crates.io) and the hosted server binary; the hosted-only surfaces move behind a default-on
`hosted` cargo feature so `imcp2-local` compiles a genuinely minimal dependency closure.

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

- **Not a local `dfx` replica bridge.** The local binary targets mainnet + production II.
  There is no `fetch_root_key`, no SSRF-guard relaxation, no local II. (A replica-targeting
  mode was scoped earlier and explicitly rejected.)
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

### 1. Crate layout — `imcp2` + a minimal `imcp2-local`

The existing crate stays **`imcp2`** (its published, embeddable identity — `Cargo.toml:2`),
and its default binary stays **`imcp2`** (the Dockerfile `CMD ["imcp2"]`, `imcp2.service`, and
the deploy scripts all build/run a binary named `imcp2` — `Dockerfile:23,31`,
`deploy/native/*`, so renaming it would churn every deploy config). The local binary is a
**separate, minimal crate** so its dependency closure never includes the OAuth/HTTP machinery.

- **`imcp2`** (lib + the hosted `imcp2` binary):
  - The **library** is the shared, transport/OAuth-agnostic core both binaries build on:
    - `identities.rs` **kept verbatim** (the II session-key grant + on-demand per-app account
      delegations against production II — `IiInstance::prod()` at `identities.rs:185`,
      `registration_pubkey_b64` `:595`, `redeem_registration_delegation` `:936`,
      `delegated_identity_for` `:1030`, `list_accounts` `:873`).
    - `calls.rs` (Candid textual↔binary codec, `raw_call`), `discover.rs` (discovery + SSRF
      guard), `management.rs`, `skills.rs`.
    - `tools.rs` — the **entire** MCP tool surface. The `#[tool_router]` / 26×`#[tool]` /
      `#[tool_handler] impl ServerHandler for IcTools` macros expand into one impl on
      `IcTools` and **must stay co-located**; both binaries construct `IcTools` and differ
      only in transport + session source.
    - **new `iiconnect` module** — the II connect-handshake primitives lifted out of
      `auth.rs` (component 4), re-parameterised to plain values so they carry no
      `AuthStore`/OAuth state.
  - The **hosted binary** (`[[bin]] name = "imcp2"`, today's `main.rs`) and the OAuth 2.1
    layer (`auth.rs`, `McpServer`/routers in `lib.rs`, the landing page, `tests/routers.rs`)
    sit behind a **default-on `hosted` feature** that pulls `axum`/`tower-http`/`prometheus`
    as *optional* dependencies (`required-features = ["hosted"]` on the bin). The gate also
    covers `pub mod metrics` (the `/metrics` Prometheus exposition — axum-typed middleware,
    new on main) and `McpConfig`'s `state_dir`/`clients`/`require_resource` (the persisted
    DCR client store and RFC 8707 strict mode — all OAuth/HTTP-deployment concerns).
    `cargo build` here produces the `imcp2` server exactly as today, deploy configs unchanged.
    The existing `e2e` feature (`pocket-ic`, `src/e2e_handshake.rs`) keeps compiling — its
    optional dep never enters any binary's closure.
- **`imcp2-local`** (bin, new) — a few hundred lines that depend on
  `imcp2 = { default-features = false }`, so the `hosted` optional deps (`axum`/`tower-http`/
  the OAuth modules, `#[cfg(feature = "hosted")]`) are **not compiled**. It serves `IcTools`
  over rmcp's stdio transport, plus a browser-handshake login driver and a transient loopback
  callback listener. rmcp features here: `["server", "macros", "transport-io"]`.

`cargo build -p imcp2-local` compiles only the minimal closure. (Caveat: `cargo build
--workspace` unifies features, so it would build the shared `imcp2` lib with `hosted` on;
build the local binary with `-p imcp2-local` — or keep it out of the default workspace
members — to ship the genuinely minimal artifact.)

**Published crate.** `imcp2` is now on crates.io (v0.2.0), released from `v*` tags via
trusted publishing with a tag-equals-version guard (`.github/workflows/publish-crate.yml`).
Two consequences: the restructure is a semver-visible change to a crate with external
embedders (the default-on `hosted` feature and `default-features = false` become supported
public API → minor version bump), and the publish workflow must be generalised if
`imcp2-local` becomes a second published crate (publish `imcp2` before the dependent crate,
per-crate version guards). The `.crate` excludes `Dockerfile`/`deploy/`/`docs/`/`monitoring/`
(repo-only), while `src/assets` and `static/` deliberately ship because they are pulled in
via `include_str!` — which supports keeping those assets in the core crate.

*Alternative (stricter):* a three-crate split — `imcp2` (core lib, no bins), `imcp2-hosted`
(bin), `imcp2-local` (bin) — isolates dependencies regardless of build invocation, at the
cost of renaming the deployed binary to `imcp2-hosted` (deploy churn). The library changes
below are identical either way.

### 2. Dependency profile

**Already removed on main (#100).** The five vestigial direct deps this design originally
proposed dropping — `ed25519-dalek`, `p256`, `ic-signature-verification`,
`ic-representation-independent-hash`, and the top-level `schemars = "0.8"` — were removed on
main (commit `0e52fe9`); none appears in `Cargo.toml` at v0.2.0, so no stripping work
remains for them. The supporting facts still hold: all Ed25519 keygen/signing goes through
`ic-agent`'s `BasicIdentity::from_raw_key` (`fresh_ed25519`, `identities.rs:1252`), every
`schemars::JsonSchema` derive resolves through `use rmcp::schemars` (rmcp's re-exported 1.x),
and delegation chains are verified inside `ic-agent` — now both client-side against the
injected agent's root key (`DelegatedIdentity::new_with_root_key`, `identities.rs:1285-1303`)
and again by the replica at redeem — never by those crates. (`ed25519-dalek`/`p256` remain
*transitive* deps via `ic-agent`; #100 was direct-dep hygiene, not closure reduction.)

**rmcp features:** keep `server` + `macros`; **swap** `transport-streamable-http-server` →
the stdio/io transport (`transport-io` in rmcp 1.x — provides `rmcp::transport::stdio()` over
tokio stdin/stdout, replacing `StreamableHttpService`); **drop** `auth` (unused — the bearer
gate is hand-rolled in `auth.rs`, and drops with the OAuth AS).

**Stays, but not for OAuth** (so the local crate keeps them):
- discovery: `reqwest` (SSRF-pinned client, `discover.rs`), `url`, `regex`.
- canister management: `sha2` (Wasm hash + ledger AccountIdentifier; also the OAuth PKCE
  S256 check in `auth.rs`, which drops — management keeps it either way), `crc32fast`,
  `base64`, `hex` (`management.rs`).
- II connect/delegation: `getrandom` (key seeds + CSP nonce), `urlencoding` (II link),
  `uuid` (connect `state`; replaceable by `getrandom`), `base64`/`hex` (delegation chain).
- core: `ic-agent`, `candid` (`value`), `candid_parser`, `tokio`, `serde`, `serde_json`,
  `tracing`, `tracing-subscriber`, `anyhow`.

**Drops with the HTTP surface:** `tower-http` (CORS — it now backs two hosted surfaces, the
MCP endpoint's browser-client layer and the OAuth/well-known permissive layer; locally only
the `#4091` well-known needs one hand-set `Access-Control-Allow-Origin`), **`prometheus` +
`src/metrics.rs`** (new on main: the `/metrics` Prometheus exposition behind
`MCP_SERVE_METRICS` — axum-typed middleware coupled to `McpServer`, hosted-only; it must move
behind the `hosted` feature or the local crate carries the metrics stack for nothing — the
`SessionGauges` counters in `identities.rs` are plain integers and stay in core), `tokio-util`
(only cancels the streamable-HTTP sessions; the reaper can be managed without a token),
dev-deps `tower` + `http-body-util` (HTTP router tests), and `tokio`'s `signal` feature
(graceful HTTP drain) plus its `time` feature (used only by the session-reaper tick and the
OAuth persist throttle — subject to what rmcp's stdio transport itself requires).
`pocket-ic` (new on main, optional behind the `e2e` feature for `src/e2e_handshake.rs`)
never enters any binary's closure — no action needed.

**`axum`** shrinks to at most the transient login callback (component 5). The recommendation
is to **hand-roll** that 3-route loopback listener so the local crate drops
`axum`/`tower-http` entirely; reusing axum is the lower-effort fallback (an open decision
under Implementation Stages).

Net minimal local deps: `imcp2` (with `default-features = false`) +
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
`IiInstance::beta()`), so the binary can still be pointed at beta II for testing. Since #92
the hosted deployment itself serves **production II at `/mcp`** by default (beta is the
opt-in `/mcp-beta` staging instance), so prod II is no longer the unverified path (see
Verification under Implementation Stages).

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
machinery, and the OAuth hardening added since this design's first draft — RFC 8707
resource-indicator enforcement (the `require_resource` flag, #127), RFC 9207 `iss` emission
on redirects (#125), and the bounded/atomically-persisted DCR store (#137) — all on the
OAuth side, so the partition is unchanged. `AuthStore` slims to
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
   best-effort server-side browser auto-open. Do **not** rely on **stderr** for the URL: every
   client routes a stdio server's stderr to a log file/panel, never the chat (component 6).
   stdout is the JSON-RPC channel, so all logging stays on stderr.
5. Serve exactly three loopback routes: `GET /callback` (the pinned fragment-reading page),
   `POST /redeem` (slim redeem → `redeem_registration_delegation`), and
   `GET /.well-known/ii-auth-callbacks` (the `#4091` allow-list, one `Access-Control-Allow-Origin: *`
   header since II fetches it cross-origin).
6. On redeem success, record the grant in memory and shut the listener down. `IcTools` now
   serves tools over stdio, minting per-app delegations on demand against mainnet.

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

*(Implementation: `authenticate`/`auth_status` are **local-only** tools — define them in the
`imcp2` library gated to the local build so they never appear on the hosted server, which logs
in via OAuth instead. Cursor's ~40-tool cap is comfortable: `imcp2` exposes ~26 plus these.)*

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
- keep `authed_session` + the `auth` import behind the hosted arm only.

To avoid dragging axum into core, read `http::request::Parts` (the `http` crate) rather than
`axum::http::request::Parts` in the Bearer arm — axum merely re-exports it. Hosted constructs
`IcTools` with `Bearer`; local with `Singleton(sid)`.

Tools that are already session-free work unchanged locally: `get_canister_candid`,
`get_canister_api_doc`, `open_app`, `resolve_app`, `discover_app_canisters`, the skills/lookup
tools, and the anonymous path of `canister_query`.

### 8. Security model

**Trust boundary.** Dropping the bearer gate is sound *only because* the transport is stdio:
a stdio server has no listening socket — it is reachable only by the parent process holding
its stdin/stdout, i.e. the client that launched it. But that client then wields the user's
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

## Implementation Stages

**Stage 1 — carve out the core (no behavior change to the `imcp2` binary).** Make the
`imcp2` library the transport/OAuth-agnostic core: keep `identities/calls/discover/management/
skills/tools` + `static/` + connect assets, extract `iiconnect` from `auth.rs`, and put the
OAuth AS + `McpServer`/`main.rs` + `pub mod metrics` behind the default-on `hosted` feature
(optional `axum`/`tower-http`/`prometheus`), threading `McpConfig`'s
`state_dir`/`clients`/`require_resource` hosted-side and keeping the `e2e` feature compiling.
(The vestigial-dep cleanup this stage originally included was already done on main, #100.)
Apply the `SessionSource` seam (component 7). *Exit:* the `imcp2` binary builds and its tests
pass unchanged; `imcp2` with `default-features = false` compiles a minimal closure.

**Stage 2 — the local binary.** `imcp2-local`: stdio `IcTools` server + the browser-handshake
login driver + the loopback callback listener. *Exit:* `cargo build -p imcp2-local`; a user
logs in against II and runs read/write tools as their accounts.

**Stage 3 — polish.** Docs (how to add the binary to an MCP client config; the wallet-grade
trust note), extend the PocketIC e2e harness to the local login flow (see Verification),
optional session persistence.

### Verification against production II

The original concern here — that only beta II was verified — is resolved on main: since #92
the hosted deployment serves **production II at `/mcp` on every deploy** (`main.rs:376-385`;
beta is the opt-in `/mcp-beta` staging instance), CI probes production health on a schedule
(#113), and the crate gained a hermetic end-to-end test of the full connect contract —
`src/e2e_handshake.rs` (`--features e2e`, optional `pocket-ic` dep, needs `II_WASM` +
`POCKET_IC_BIN`) drives register → authorize → the II registration-delegation ceremony →
redeem → a real `mcp_register_v2` → token against a real Internet Identity release build in
PocketIC. So "does prod II implement the handshake" is answered in production. (Chains are
also now verified client-side against the injected agent's root key — `new_with_root_key`,
`identities.rs:1285-1303` — so a binary pointed at a test network can complete redemption
after `fetch_root_key`, which is what makes a PocketIC-based test of the *local* flow
possible.)

What remains open is specific to the **local binary's `http://127.0.0.1` callback**, which
the hosted https deployment never exercises:
1. **Mixed content:** II's https document must `fetch()`
   `http://127.0.0.1:<port>/.well-known/…`. Loopback is "potentially trustworthy" (W3C Secure
   Contexts), so Chrome/Firefox allow https→http-loopback — prefer the `127.0.0.1` literal
   over the `localhost` name; Safari and enterprise policies are the unknowns.
2. **CORS:** the well-known response needs `Access-Control-Allow-Origin` (II fetches it
   cross-origin; `*` is fine with `credentials: omit`).

Verification plan: extend the PocketIC e2e harness to drive the local browser-handshake flow
(loopback listener + slim redeem) with no live network; the
`II_URL_PROD`/`II_CANISTER_ID_PROD` overrides remain available to point a binary at beta II.

### Open decisions

1. **Loopback listener: hand-roll vs reuse axum.** *Recommend hand-roll* (3 routes, one CORS
   header) so the local crate drops `axum`/`tower-http` — the security-sensitive page/CSP is a
   static asset reused from core, not re-derived. Reuse-axum is the lower-effort fallback.
2. **Browser open:** `open`/`webbrowser` crate (convenience) vs `std::process::Command`
   (zero-dep). *Recommend* always return the URL in-band (the `authenticate` tool result) +
   best-effort auto-open; the flow never depends on auto-open succeeding.
3. **Session persistence:** in-memory only (recommend for v1) vs keychain-backed `S`.
4. **Crate layout:** `imcp2` + `imcp2-local` with a `hosted` feature (recommended, keeps the
   `imcp2` binary name) vs the stricter three-crate split (component 1).

(Login timing was resolved by the client research — lazy on the first authenticated tool
call, non-blocking.)

## Appendix: evidence index

(Line refs stamped against the v0.2.0 tree, rebased onto `189fabd`.)

- Vestigial deps: already removed on main in #100 (`0e52fe9`); Ed25519 via `ic-agent`
  (`fresh_ed25519`, `identities.rs:1252`); chains verified by `ic-agent` client-side
  (`new_with_root_key`, `identities.rs:1285-1303`) and by the replica. `schemars` via
  `use rmcp::schemars` (all modules).
- rmcp features + streamable-HTTP wiring: `Cargo.toml:35-40`, `lib.rs:102-105,258-276`.
- New hosted-only surfaces: `prometheus`/`src/metrics.rs` (`lib.rs:76-81`, `Cargo.toml:64-69`,
  `MCP_SERVE_METRICS`); `McpConfig.state_dir`/`require_resource` (`lib.rs:144-158`,
  `IMCP2_STATE_DIR`/`OAUTH_REQUIRE_RESOURCE` in `main.rs`).
- OAuth AS vs II-connect split: `auth.rs:24-60` (module docs), handlers
  `auth.rs:1053/1987/2139`, connect subset `auth.rs:1284/1342-1515/1673-1782/1839`,
  `#4091` `auth.rs:1304/1319`.
- Session seam: `auth.rs:2264/2292`, `tools.rs:1493`, 13 call-sites listed in component 7.
- II login primitives: `identities.rs:595/936`, `ii_mcp_url` `auth.rs:1284`.
- Production II served at `/mcp` since #92 (`main.rs:376-385`); PocketIC e2e handshake test
  `src/e2e_handshake.rs` (`e2e` feature); beta II constants `identities.rs:121-128`, candid
  verification note `identities.rs:929-935`, generic live-round-trip caveat
  `README.md:993-999`.
