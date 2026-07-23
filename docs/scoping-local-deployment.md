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

## 2. Design overview — a 3-crate workspace

Split the crate so the local binary's dependency closure never includes the OAuth/HTTP
machinery. Feature flags are rejected: they are additive and unify per resolved graph, so a
`--features local` build would still compile the OAuth AS + axum closure into the shipped
artifact. `cargo build -p imcp-local` compiles only the local closure.

- **`imcp-core`** (lib) — everything both binaries share, all transport/OAuth-agnostic:
  - `identities.rs` **kept verbatim** (the II session-key grant + on-demand per-app account
    delegations against production II — `IiInstance::prod()` at `identities.rs:126`,
    `registration_pubkey_b64` `:501`, `redeem_registration_delegation` `:821`,
    `delegated_identity_for` `:908`, `list_accounts` `:758`).
  - `calls.rs` (Candid textual↔binary codec, `raw_call`), `discover.rs` (discovery + SSRF
    guard), `management.rs`, `skills.rs`.
  - `tools.rs` — the **entire** MCP tool surface. The `#[tool_router]` / 26×`#[tool]` /
    `#[tool_handler] impl ServerHandler for IcTools` macros expand into one impl on `IcTools`
    and **must stay co-located** in one crate; both binaries construct `IcTools` and differ
    only in transport + session source.
  - **new `iiconnect` module** — the II connect-handshake primitives lifted out of `auth.rs`
    (see §5), re-parameterised to plain values so they carry no `AuthStore`/OAuth state.
  - rmcp features: `["server", "macros"]` only (no transport).
- **`imcp-hosted`** (bin) — today's streamable-HTTP + OAuth 2.1 server, behavior unchanged.
  Adds the OAuth AS *wrapper* around `iiconnect`, the bearer gate, `McpServer`/routers
  (`lib.rs`), the landing page (`main.rs`), and `tests/routers.rs`.
- **`imcp-local`** (bin, new) — a few hundred lines: serve `IcTools` over rmcp's stdio
  transport; a browser-handshake login driver; a transient loopback callback listener.

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
entirely; reusing axum is the lower-effort fallback (see §8 decision).

Net minimal local deps: `imcp-core` + `rmcp{server,macros,transport-io}` + `tokio` +
`anyhow` + `serde_json` + `url`/`urlencoding` + `tracing`/`tracing-subscriber` + a
browser-opener (`open` crate, or `std::process::Command`).

## 4. Talking to mainnet + production II

No replica changes: the local agent is `Agent::builder().with_url(IC_URL).build()` with
`IC_URL = "https://icp-api.io"` and **no** `fetch_root_key` (mainnet root key is baked in).
`Identities::new(IiInstance::prod()?, public_url, agent)` — production II. `public_url` is
only used as the management-identity derivation origin (`identities.rs:746`) and can be a
fixed local value; it need not be a reachable server.

`II_URL`/`II_CANISTER_ID` remain env-overridable (`identities.rs:120`), so the binary can be
pointed at **beta** II for testing (see §9 — beta is the only instance verified end-to-end
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
4. Build the II link (`iiconnect::ii_mcp_url`) against `https://id.ai`, open the browser
   (print the URL to **stderr** always — stdout is the JSON-RPC channel — plus best-effort
   `open`/`webbrowser`).
5. Serve exactly three loopback routes: `GET /callback` (the pinned fragment-reading page),
   `POST /redeem` (slim redeem → `redeem_registration_delegation`), and
   `GET /.well-known/ii-auth-callbacks` (the `#4091` allow-list, one `Access-Control-Allow-Origin: *`
   header since II fetches it cross-origin).
6. On redeem success, record the grant in memory and shut the listener down. `IcTools` now
   serves tools over stdio, minting per-app delegations on demand against mainnet.

Sessions are **in-memory** (re-login per run), matching today's model and the roadmap.
Optional future work: persist the session seed `S` to an OS keychain to survive restarts —
but `S` is a live capability to the user's real anchor, so never plaintext.

## 7. Tool / session seam

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

## 8. Security model & open decisions

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
   (zero-dep). *Recommend* always print the URL + best-effort auto-open, flow never depends on
   auto-open succeeding.
3. **Login timing:** eager at startup vs lazy on first authenticated tool call.
4. **Session persistence:** in-memory only (recommend for v1) vs keychain-backed `S`.

## 9. Risks to verify against PRODUCTION II

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

## 10. Work breakdown

**Phase 1 — workspace split (no behavior change to hosted).** Create `imcp-core` + move
`identities/calls/discover/management/skills/tools` and `static/` + connect assets into it;
extract `iiconnect` from `auth.rs`; leave the OAuth AS + `McpServer`/`main.rs` in
`imcp-hosted`. Apply the `SessionSource` seam (§7) and drop the 4 dead deps + `schemars 0.8`.
*Exit:* hosted builds and its tests pass unchanged; local closure compiles.

**Phase 2 — the local binary.** `imcp-local`: stdio `IcTools` server + the browser-handshake
login driver + the loopback callback listener. *Exit:* `cargo build -p imcp-local`; a user
logs in against II and runs read/write tools as their accounts.

**Phase 3 — polish.** Docs (how to add the binary to an MCP client config; the wallet-grade
trust note), the production-II verification (§9), optional session persistence.

## 11. Evidence index

- Dead deps (0 refs): `ed25519-dalek`/`p256`/`ic-signature-verification`/
  `ic-representation-independent-hash`; Ed25519 via `ic-agent` `identities.rs:1044`; replica
  verifies chains `identities.rs:1064`. `schemars` via `use rmcp::schemars` (all modules).
- rmcp features + streamable-HTTP wiring: `Cargo.toml:12`, `lib.rs:83,194-208`.
- OAuth AS vs II-connect split: `auth.rs:24-60` (module docs), handlers `auth.rs:566/1440/1570`,
  connect subset `auth.rs:750/808-978/1207-1245/1302`, `#4091` `auth.rs:770/785`.
- Session seam: `auth.rs:1664/1691`, `tools.rs:1475`, 13 call-sites listed in §7.
- II login primitives: `identities.rs:501/821`, `ii_mcp_url` `auth.rs:750`.
- Prod-vs-beta verification caveat: `identities.rs:79/814`, `README.md:724`.
