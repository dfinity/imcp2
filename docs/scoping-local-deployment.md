# Scoping: a minimal local MCP server binary (stdio, no OAuth)

Status: **draft / scoping** — analysis and design only, no code changes here.

## 1. What "local deployment" means

A second, **separate binary** that a user runs **on their own machine** (run-it-yourself),
reached by a co-located MCP client (Claude Desktop, a local Claude Code, …). It still
talks to **mainnet IC** (`https://icp-api.io`) and **production Internet Identity**
(`https://id.ai`, `rdmx6-jaaaa-aaaaa-aaadq-cai`) — it is **not** a local `dfx` replica.

The distinction from the hosted server is the **deployment axis**, not the network:

| | Hosted `imcp2` (today) | Local binary (this scope) |
|---|---|---|
| Where it runs | a public server | the user's own machine |
| MCP transport | streamable-HTTP | **stdio** |
| Reached by | remote, third-party MCP clients | the co-located client that spawned it |
| Client auth | **OAuth 2.1** (bearer tokens, PKCE, DCR) | **none** (process boundary) |
| II login | OAuth-wrapped connect handshake | **built-in browser handshake** |
| IC / II target | mainnet + beta/prod II | **mainnet + production II** |

Because it is single-user and reachable only through the pipe of the client that launched
it, the entire OAuth 2.1 authorization-server layer — which exists so *remote* clients can
authenticate to a *public* endpoint — is unnecessary. Internet Identity itself is **kept**:
the user still logs in with their real anchor and acts as their real II accounts on real
mainnet apps, from a bridge they run themselves rather than trusting a hosted third party.

Design decisions locked with the requester:
- **Separate binary**, minimal dependencies (Cargo workspace split, not a runtime flag).
- **stdio** MCP transport.
- **No OAuth 2.1** authorization server.
- **Built-in browser II handshake**: the binary mints the session key, opens the browser to
  production II, receives the delegation on a transient localhost callback, redeems it, and
  holds the session in memory.

All findings below were verified against the current code; `file:line` references point at it.

## 2. Design overview — the `imcp2` crate + a minimal `imcp2-local` binary

The existing crate stays **`imcp2`** (its published, embeddable identity — `Cargo.toml:2`),
and its default binary stays **`imcp2`** (the Dockerfile `CMD ["imcp2"]`, `imcp2.service`, and
the deploy scripts all build/run a binary named `imcp2` — `Dockerfile:23,29`,
`deploy/native/*`, so renaming it would churn every deploy config). The local binary is a
**separate, minimal crate** so its dependency closure never includes the OAuth/HTTP machinery.

- **`imcp2`** (lib + the hosted `imcp2` binary):
  - The **library** is the shared, transport/OAuth-agnostic core both binaries build on:
    - `identities.rs` **kept verbatim** (the II session-key grant + on-demand per-app account
      delegations against production II — `IiInstance::prod()` at `identities.rs:126`,
      `registration_pubkey_b64` `:501`, `redeem_registration_delegation` `:821`,
      `delegated_identity_for` `:908`, `list_accounts` `:758`).
    - `calls.rs` (Candid textual↔binary codec, `raw_call`), `discover.rs` (discovery + SSRF
      guard), `management.rs`, `skills.rs`.
    - `tools.rs` — the **entire** MCP tool surface. The `#[tool_router]` / 26×`#[tool]` /
      `#[tool_handler] impl ServerHandler for IcTools` macros expand into one impl on
      `IcTools` and **must stay co-located**; both binaries construct `IcTools` and differ
      only in transport + session source.
    - **new `iiconnect` module** — the II connect-handshake primitives lifted out of
      `auth.rs` (see §5), re-parameterised to plain values so they carry no
      `AuthStore`/OAuth state.
  - The **hosted binary** (`[[bin]] name = "imcp2"`, today's `main.rs`) and the OAuth 2.1
    layer (`auth.rs`, `McpServer`/routers in `lib.rs`, the landing page, `tests/routers.rs`)
    sit behind a **default-on `hosted` feature** that pulls `axum`/`tower-http` as *optional*
    dependencies (`required-features = ["hosted"]` on the bin). `cargo build` here produces
    the `imcp2` server exactly as today, deploy configs unchanged.
- **`imcp2-local`** (bin, new) — a few hundred lines that depend on
  `imcp2 = { default-features = false }`, so the `hosted` optional deps (`axum`/`tower-http`/
  the OAuth modules, `#[cfg(feature = "hosted")]`) are **not compiled**. It serves `IcTools`
  over rmcp's stdio transport, plus a browser-handshake login driver and a transient loopback
  callback listener. rmcp features here: `["server", "macros", "transport-io"]`.

`cargo build -p imcp2-local` compiles only the minimal closure. (Caveat: `cargo build
--workspace` unifies features, so it would build the shared `imcp2` lib with `hosted` on;
build the local binary with `-p imcp2-local` — or keep it out of the default workspace
members — to ship the genuinely minimal artifact.)

*Alternative (stricter):* a three-crate split — `imcp2` (core lib, no bins), `imcp2-hosted`
(bin), `imcp2-local` (bin) — isolates dependencies regardless of build invocation, at the
cost of renaming the deployed binary to `imcp2-hosted` (deploy churn). The library changes
below are identical either way.

## 3. Dependency stripping (verified)

**Drop outright — zero references in `src/`** (verified by grep). These are pure dead weight
today, independent of the local work, but the local crate must not carry them:

- `ed25519-dalek` — all Ed25519 keygen/signing goes through `ic-agent`'s
  `BasicIdentity::from_raw_key` (`identities.rs:1044`), never this crate.
- `p256`, `ic-signature-verification` — the server never verifies delegation signatures
  itself; the replica verifies every hop at redeem (`identities.rs:1064`).
- `ic-representation-independent-hash` — unreferenced.
- top-level `schemars = "0.8"` — **vestigial**: every `schemars::JsonSchema` derive resolves
  through `use rmcp::schemars` (rmcp's re-exported 1.x), verified across all modules. rmcp's
  own schemars re-export must stay enabled; the direct dep is removed.

**rmcp features:** keep `server` + `macros`; **swap** `transport-streamable-http-server` →
the stdio/io transport (`transport-io` in rmcp 1.x — provides `rmcp::transport::stdio()` over
tokio stdin/stdout, replacing `StreamableHttpService`); **drop** `auth` (unused — the bearer
gate is hand-rolled in `auth.rs`, and drops with the OAuth AS).

**Stays, but not for OAuth** (so the local crate keeps them):
- discovery: `reqwest` (SSRF-pinned client, `discover.rs`), `url`, `regex`.
- canister management: `sha2` (Wasm hash + ledger AccountIdentifier), `crc32fast`, `base64`,
  `hex` (`management.rs`).
- II connect/delegation: `getrandom` (key seeds + CSP nonce), `urlencoding` (II link),
  `uuid` (connect `state`; replaceable by `getrandom`), `base64`/`hex` (delegation chain).
- core: `ic-agent`, `candid` (`value`), `candid_parser`, `tokio`, `serde`, `serde_json`,
  `tracing`, `tracing-subscriber`, `anyhow`.

**Drops with the HTTP surface:** `tower-http` (CORS — only the `#4091` well-known needs one
`Access-Control-Allow-Origin`, hand-settable), `tokio-util` (only cancels the streamable-HTTP
sessions; the reaper can be managed without a token), dev-deps `tower` + `http-body-util`
(HTTP router tests), and `tokio`'s `signal` feature (graceful HTTP drain).

**`axum`** shrinks to at most the transient login callback (§6). The recommendation is to
**hand-roll** that 3-route loopback listener so the local crate drops `axum`/`tower-http`
entirely; reusing axum is the lower-effort fallback (see §9 decision).

Net minimal local deps: `imcp2` (with `default-features = false`) +
`rmcp{server,macros,transport-io}` + `tokio` +
`anyhow` + `serde_json` + `url`/`urlencoding` + `tracing`/`tracing-subscriber` + a
browser-opener (`open` crate, or `std::process::Command`).

## 4. Talking to mainnet + production II

No replica changes: the local agent is `Agent::builder().with_url(IC_URL).build()` with
`IC_URL = "https://icp-api.io"` and **no** `fetch_root_key` (mainnet root key is baked in).
`Identities::new(IiInstance::prod()?, public_url, agent)` — production II. `public_url` is
only used as the management-identity derivation origin (`identities.rs:746`) and can be a
fixed local value; it need not be a reachable server.

`II_URL`/`II_CANISTER_ID` remain env-overridable (`identities.rs:120`), so the binary can be
pointed at **beta** II for testing (see §10 — beta is the only instance verified end-to-end
today) while defaulting to production per the locked decision.

## 5. Dropping OAuth 2.1, keeping the II handshake

`auth.rs` splits along the boundary its own module docs already draw (`auth.rs:24-60`).

**Kept for local (the de-OAuth'd II browser handshake):**
- `ii_mcp_url` (`auth.rs:750`) — builds II's `/mcp#callback=…&state=…&ttl=…&registration_key=…`
  link. Re-parameterise from `&AuthStore` to plain values.
- the pinned callback page `connect_callback_page`/`pinned_callback_page` + assets + CSP nonce
  (`auth.rs:808-978`). II delivers the delegation in the URL **fragment**, so the callback
  *must* be an HTML page that reads `location.hash` client-side and POSTs it back.
- `parse_registration_delegation` + the `Json*` chain types + the 64 KB pre-parse bound
  (`auth.rs:1170-1245`).
- a slimmed `connect_redeem` (`auth.rs:1302`): shape-check the fragment, single-flight, call
  `Identities::redeem_registration_delegation`, signal completion — **minus** the PKCE/code/
  token/cookie/redirect tail.
- the **`#4091` allow-list** `/.well-known/ii-auth-callbacks` (`auth.rs:770,785`) — still
  mandatory: II fail-closed-fetches it before honoring the callback.

**Dropped (the entire OAuth 2.1 AS):** `/authorize` (`auth.rs:566`), `/token` + PKCE + tokens
(`auth.rs:1427-1528`), `/register` + DCR + `SharedClients` persistence (`auth.rs:1532-1616`,
`465-474`), the hosted-redirect allow-list (`auth.rs:198-390`), AS/PR discovery metadata
(`auth.rs:1627-1652`), the `require_token` bearer gate + `bearer_challenge` (`auth.rs:1664`),
and the front-channel HTML error-screen machinery. `AuthStore` slims to
`{identities, public_url, authz}` (loses `clients`/`tokens`/`codes`).

**Consent-Bound Completion / the initiator cookie can be dropped locally.** The `sid` cookie
(`auth.rs:129`, checked `:1332`) defends a *split-browser confused-deputy* that requires a
public, multi-tenant initiate endpoint an attacker can start a connect on. Locally there is
**no HTTP initiate endpoint**: the binary itself mints `X`, `priv(X)` never leaves the
process, and `/redeem` is loopback-only and single-user. The consenter proof alone — the
delegation's final hop must target the in-memory `X`, replica-verified at redeem
(`registration_identity`, `identities.rs:1066`) — suffices; keep the random `state` as the
callback↔connect correlator.

## 6. The built-in browser II login

1. Build the mainnet agent + `Identities` (prod II) once.
2. Mint the session: `registration_pubkey_b64(&session_id)` → in-memory Ed25519 `S` + the
   registration key `X`, returns base64url `pub(X)`.
3. Bind a transient listener on `127.0.0.1:0`; the callback origin is
   `http://127.0.0.1:<port>`. Both the II link's `callback` and the well-known entry derive
   from this one value, so they cannot drift (II matches by exact string equality).
4. Build the II link (`iiconnect::ii_mcp_url`) against `https://id.ai` and surface it to the
   user **in-band** — as the text result of an `authenticate` MCP tool (§7) — plus a
   best-effort server-side browser auto-open. Do **not** rely on **stderr** for the URL: every
   client routes a stdio server's stderr to a log file/panel, never the chat (§7). stdout is
   the JSON-RPC channel, so all logging stays on stderr.
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
grant landed. §7 covers the per-client specifics.

Sessions are **in-memory** (re-login per run), matching today's model and the roadmap.
Optional future work: persist the session seed `S` to an OS keychain to survive restarts —
but `S` is a live capability to the user's real anchor, so never plaintext.

## 7. Working with AI tool clients

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
(the OAuth path kept in §5). This is precisely why the OAuth layer stays in `imcp2` rather than
being deleted: it is the only way to serve the cloud clients.

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
   binary's own browser handshake (§6) — which also sidesteps Antigravity's known-buggy remote
   MCP-OAuth.
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

## 8. Tool / session seam

Today a tool gets its `session_id` via bearer → `require_token` → `AuthedSession` injected in
the request extensions → `authed_session(ctx)` (`tools.rs:1475`). Under stdio there is one
user and one connection, so this collapses to a **singleton** session id set at login.

Minimal, verified seam (no tool-signature changes, no `identities.rs` changes):
- add `session: SessionSource { Bearer, Singleton(String) }` to `IcTools` (`tools.rs:52`);
- one `current_session_id(&self, &ctx) -> Option<String>` method replacing the free fn;
- rewrite the **13** lookup call-sites (`tools.rs:353,798,853,1286,1306,1326,1347,1368,1389,
  1410,1428,1446,1464`) to call it; the `.ok_or(…)` handling is unchanged;
- keep `authed_session` + the `auth` import behind the hosted arm only.

To avoid dragging axum into core, read `http::request::Parts` (the `http` crate) rather than
`axum::http::request::Parts` in the Bearer arm — axum merely re-exports it. Hosted constructs
`IcTools` with `Bearer`; local with `Singleton(sid)`.

Tools that are already session-free work unchanged locally: `get_canister_candid`,
`get_canister_api_doc`, `open_app`, `resolve_app`, `discover_app_canisters`, the skills/lookup
tools, and the anonymous path of `canister_query`.

## 9. Security model & open decisions

**Trust boundary.** Dropping the bearer gate is sound *only because* the transport is stdio:
a stdio server has no listening socket — it is reachable only by the parent process holding
its stdin/stdout, i.e. the client that launched it. But that client then wields the user's
**real production II accounts** on mainnet (canister create/install/start/stop/delete, any
update call / cycles spend, per-app delegations for every origin). This must be stated plainly:
**treat the binary and its client config like a wallet.** There is no revocable token — only
the II grant (reconnect/expiry).

**Loopback hardening for the login listener:** bind `127.0.0.1` explicitly (never `0.0.0.0`);
validate the `Host` header (anti-DNS-rebinding, `lib.rs:385` pattern); up only for the
handshake. Even so, a rebinding attacker is largely inert: `/redeem` only advances the connect
*this* process started (`state` match) and `registration_identity` rejects any chain not
targeting our freshly-minted `X`.

Decisions for the implementation PR (recommendations first):
1. **Loopback listener: hand-roll vs reuse axum.** *Recommend hand-roll* (3 routes, one CORS
   header) so the local crate drops `axum`/`tower-http` — the security-sensitive page/CSP is a
   static asset reused from core, not re-derived. Reuse-axum is the lower-effort fallback.
2. **Browser open:** `open`/`webbrowser` crate (convenience) vs `std::process::Command`
   (zero-dep). *Recommend* always return the URL in-band (the `authenticate` tool result) +
   best-effort auto-open; the flow never depends on auto-open succeeding.
3. **Login timing:** *resolved by the client research (§7)* — lazy on the first authenticated
   tool call, never at startup (clients gate the first call on approval and cap `initialize`),
   and non-blocking.
4. **Session persistence:** in-memory only (recommend for v1) vs keychain-backed `S`.

## 10. Risks to verify against PRODUCTION II

The single biggest external dependency: the in-repo II contract was verified only against
**beta** II (`fgte5-…`, `identities.rs:814`, `auth.rs:76`), but this binary targets
**production** II (`rdmx6-…`). Per the README, `/mcp-prod` "only completes once the production
II carries the `#4086` MCP feature set" (`README.md:724`). Verify against live `id.ai`:
1. that production II implements the connect handshake — `/mcp` link, `mcp_register_v2`
   (the `variant { Ok: record { expiration; permissions }; Err }` shape) and the `#4091`
   well-known validation;
2. **mixed content:** II's https document must `fetch()` `http://127.0.0.1:<port>/.well-known/…`.
   Loopback is "potentially trustworthy" (W3C Secure Contexts), so Chrome/Firefox allow
   https→http-loopback — prefer the `127.0.0.1` literal over the `localhost` name; Safari and
   enterprise policies are the unknowns;
3. **CORS:** the well-known response needs `Access-Control-Allow-Origin` (II fetches it
   cross-origin; `*` is fine with `credentials: omit`).

Mitigation while prod II catches up: the existing env overrides let the binary point at beta
II, which is verified end-to-end today.

## 11. Work breakdown

**Phase 1 — carve out the core (no behavior change to the `imcp2` binary).** Make the
`imcp2` library the transport/OAuth-agnostic core: keep `identities/calls/discover/management/
skills/tools` + `static/` + connect assets, extract `iiconnect` from `auth.rs`, and put the
OAuth AS + `McpServer`/`main.rs` behind the default-on `hosted` feature (optional
`axum`/`tower-http`). Apply the `SessionSource` seam (§8) and drop the 4 dead deps +
`schemars 0.8`. *Exit:* the `imcp2` binary builds and its tests pass unchanged; `imcp2` with
`default-features = false` compiles a minimal closure.

**Phase 2 — the local binary.** `imcp2-local`: stdio `IcTools` server + the browser-handshake
login driver + the loopback callback listener. *Exit:* `cargo build -p imcp2-local`; a user
logs in against II and runs read/write tools as their accounts.

**Phase 3 — polish.** Docs (how to add the binary to an MCP client config; the wallet-grade
trust note), the production-II verification (§10), optional session persistence.

## 12. Evidence index

- Dead deps (0 refs): `ed25519-dalek`/`p256`/`ic-signature-verification`/
  `ic-representation-independent-hash`; Ed25519 via `ic-agent` `identities.rs:1044`; replica
  verifies chains `identities.rs:1064`. `schemars` via `use rmcp::schemars` (all modules).
- rmcp features + streamable-HTTP wiring: `Cargo.toml:12`, `lib.rs:83,194-208`.
- OAuth AS vs II-connect split: `auth.rs:24-60` (module docs), handlers `auth.rs:566/1440/1570`,
  connect subset `auth.rs:750/808-978/1207-1245/1302`, `#4091` `auth.rs:770/785`.
- Session seam: `auth.rs:1664/1691`, `tools.rs:1475`, 13 call-sites listed in §8.
- II login primitives: `identities.rs:501/821`, `ii_mcp_url` `auth.rs:750`.
- Prod-vs-beta verification caveat: `identities.rs:79/814`, `README.md:724`.
