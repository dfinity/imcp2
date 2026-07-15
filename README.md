# mcp-poc

Minimal MCP server that bridges an LLM to the Internet Computer.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding and signing against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

## Tools

Every tool declares an MCP `outputSchema` and, on success, attaches
**structured content** — a machine-readable object matching that schema —
alongside the human-readable text, so a model knows the expected shape of each
reply. The text is always present; the structured object is attached whenever
the reply serializes to an object (which the schema guarantees for normal
results).

| Tool | Args | Returns |
|------|------|---------|
| `open_app` | `app` (name **or** URL) | **One-call entry point** when a user names/links an app: resolves the Internet Identity `derivation_origin` *and* discovers the canisters behind it, together. A name or bare host is matched to the known-app registry first (so a wrong-TLD guess like `multidex.com` repairs to the canonical URL); an explicit `https://` URL is resolved as given. An unknown bare name, or a URL with no IC evidence, is *refused* (never guessed). Wraps `resolve_app` + `discover_app_canisters`; no auth |
| `discover_app_canisters` | `domain` | Canister ids behind a web domain — app-declared App Connect metadata first (`/ai-connect.html`'s `ic:canister-id` meta, `/.well-known/ic-app.json` manifest), then the frontend via `x-ic-canister-id` and backend candidates via `/env.json` + JS-bundle mining — each with provenance and its IC dashboard label/type where known |
| `icp_find_canister_by_name` | `query` | Canister ids matching a name/symbol, searched in the IC dashboard's service registries — ICRC token ledgers (e.g. `ckUSDC`) and the SNS project catalog |
| `icp_find_app_by_name` | `name` | A well-known app's front-end URL + `derivation_origin`, for a small built-in set (NNS, Oisy, MULTI/DEX, ICPSwap). The **first stop** whenever only an app *name* is known — never guess a domain from a name. Any other name returns no match and a `note` directing a web search for the app's URL (there's no on-chain name→URL directory) |
| `icp_lookup_canister_info_by_id` | `canister_id` | What a canister IS, per the IC dashboard: label/name, type, controllers, subnet, module hash, latest upgrade proposal |
| `get_canister_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text), plus an `oql` flag — `true` when it exposes an OQL query surface (a `schema` + `execute` pair), with a pointer to `icp_oql_guide` |
| `get_canister_api_doc` | `canister_id` | The canister's own prose API guide ("how this app behaves" — units, auth, lifecycle, mutation safety, polling, gotchas), read from its `getApiDoc`/`get_api_doc` method if present. Call first for an unfamiliar app |
| `call_canister` | `canister_id`, `method`, `args` (textual Candid), `is_query`, `derivation_origin?` / `app_url?`, `account?` | Reply as textual Candid; anonymous, or as your account at an app (identified by its canonical II `derivation_origin`, or an `app_url` the connector resolves). Echoes `derived_for_origin` / `requested` / `derivation_origin_source` / `acted_as_principal`. Query calls are rejected on an OQL canister — read it via the OQL tools |
| `get_app_principal` | `derivation_origin?` / `app_url?`, `account?` | The principal you act as at an app, without a call. Echoes `derived_for_origin` / `requested` / `derivation_origin_source` so an origin mismatch is visible |
| `list_app_accounts` | `derivation_origin?` / `app_url?` | The user's Internet Identity accounts at an app — the default account plus any named ones — with name, number, last-used, and the derivation origin they were listed for |
| `resolve_app` | `app_url` | Resolve an app URL to its Internet Identity derivation context: `application_origin`, the `derivation_origin` to use (declared in `/.well-known/ic-app.json`, else a built-in known-app value, else assumed = app origin — flagged via `derivation_origin_source`: `declared`/`known`/`app_url_default`, with `application_is_ic` echoing the gateway evidence), and the app's `alternative_origins` (informational). An origin with **no IC evidence** that would need the `app_url_default` assumption is **refused** (guessed-domain guard, with a "did you mean" repair when the host resembles a well-known app). Does not return a principal (no account chosen) or require auth — pass the `derivation_origin` to `get_app_principal`/`list_app_accounts` |
| `icp_list_skills` | — | The official [IC skills](https://skills.internetcomputer.org) (Motoko, mops/icp CLIs, cycles, stable memory, security, …), grouped by category |
| `icp_get_skill` | `name` | The full `SKILL.md` instructions for one skill (e.g. `motoko`, `icp-cli`, `cycles-management`) |
| `icp_oql_guide` | — | The OQL query-surface dialect guide (for canisters where `get_canister_candid` reports `oql: true`): the JSON query object, predicate grammar, edges, and paged result shape |
| `get_canister_oql_schema` | `canister_id`, `derivation_origin?`, `account?` | The canister's OQL schema catalogue (entities, primary keys, fields, edges) as JSON — wraps its `schema` method |
| `run_canister_oql_query` | `canister_id`, `query` (JSON object string), `derivation_origin?`, `account?` | Runs an OQL query (wraps `execute`, no Candid escaping) and returns `columns` + `rows` (rendered as a table) with `has_more` for paging |
| `icp_cycles_balance` | — | Your cycles-ledger balance (the funds `icp_create_canister`/`icp_top_up_canister` spend), as your standing II principal |
| `icp_create_canister` | `cycles?` / `icp?`, `controllers?`, `subnet?` | Create + fund a new canister — from your cycles-ledger balance (`cycles`) or by converting ICP from your ICP-ledger account via the CMC (`icp`); returns the new canister id |
| `icp_install_code` | `canister_id`, `wasm_base64` / `wasm_hex`, `mode?`, `arg?` | Install/reinstall/upgrade a Wasm module (single-shot, or via the chunk store for large modules) |
| `icp_canister_status` | `canister_id` | Run state, cycle balance, module hash, memory, controllers, allocations |
| `icp_update_canister_settings` | `canister_id`, `controllers?`, allocations, `freezing_threshold?`, `log_visibility?`, … | Update a canister's settings |
| `icp_start_canister` / `icp_stop_canister` / `icp_uninstall_code` / `icp_delete_canister` | `canister_id` | Canister lifecycle |
| `icp_top_up_canister` | `canister_id`, `cycles?` / `icp?` | Add cycles to an existing canister — from your cycles-ledger balance (`cycles`) or by converting ICP from your ICP-ledger account via the CMC (`icp`) |

`discover_app_canisters` is the entry point when the user names a **website** instead
of a canister id. Sources, most authoritative first: **app-declared metadata**
(below), the frontend via the `x-ic-canister-id` header, and backend candidates
mined from `/env.json` + the JS bundle (pick by label, prefer production/`IC_`
ids, confirm with `get_canister_candid`).

### Typical flow

Acting **for the user** at an app:

0–2. **`open_app(name-or-URL)`** — the one-call entry point. Pass the *name* the user
   said (well-known apps NNS/Oisy/MULTI/DEX/ICPSwap resolve offline) or a URL you
   have; it returns the `derivation_origin` **and** the app's canisters in one shot
   (it runs `resolve_app` + `discover_app_canisters` concurrently under the hood).
   **Never guess a domain from a name** — a lookalike like `<name>.com` is an
   unrelated or squatted site. The tool enforces this: a bare *unknown* name is
   refused (find the real URL — web-search or ask the user), and a URL that resolves
   to `app_url_default` while showing **no IC evidence** (no valid `x-ic-canister-id`
   gateway header, no `ic-app.json` derivation origin) is refused too; when the host
   resembles a known app the error names it and gives the real URL ("did you mean
   MULTI/DEX → `https://multidex.ai`"). For a single step, the narrower tools remain:
   **`icp_find_app_by_name`** (name→URL only), **`resolve_app(url)`** (origin only),
   **`discover_app_canisters(url)`** (canisters only).
3. **`list_app_accounts`** — if there's more than one account, ask which to use (and
   remember it).
4. **`get_app_principal`** — only when you need the principal *value* itself;
   `call_canister` / `run_canister_oql_query` act as the account without pre-fetching it.
5. **`get_canister_candid`** (and **`get_canister_api_doc`** if the canister exposes
   one) to learn the interface — the `oql: true` flag says whether OQL is available.
6. **Read** with `run_canister_oql_query` when OQL is available (for an OQL canister
   raw `call_canister` query calls are rejected — use the OQL tools), else
   `call_canister` with `is_query=true`.
7. **Act** with `call_canister` update calls, passing `derivation_origin` + `account`
   to act as the user.

Public/anonymous reads skip steps 3/4. The per-canister inspection (5) is
independent of the identity steps (3/4), so they can run in parallel. Managing your
**own** canisters (the `icp_*` create/install/status/… tools) acts as your standing
**management principal** at this server's origin — a *different* identity than the
per-app principals above.

### App-declared canister metadata (App Connect)

Apps that adopt **Internet Computer App Connect** serve a bridge page at
`/ai-connect.html` whose `<meta name="ic:canister-id">` declares the app's
**main backend** canister (spec §4.7/§6.1). Discovery reads that meta from the
raw served markup (no JavaScript is executed) and reports it as the
top-priority finding, labelled `main backend (App Connect)`.

The App Connect spec **defers** multi-canister enumeration (§6.3: how an app
lists *all* the canisters it comprises, with roles). To fill that gap, this
server also reads a proposed convention: a `/.well-known/ic-app.json` manifest
the app serves itself —

```json
{
  "derivation_origin": "https://<frontend-canister>.icp0.io",
  "canisters": [
    { "id": "aaaaa-…-cai", "role": "backend", "description": "orders + inventory API" },
    { "id": "bbbbb-…-cai", "role": "ledger" }
  ]
}
```

Each entry needs an `id` (a canister principal); `role` and `description` are
optional and become the finding's label (`role — description`). Unknown fields
are ignored, so the format can grow. Both sources are the app's own claim about
its composition — stronger than anything mined from client code — but an
SPA catch-all serving HTML at these paths simply yields no findings (no meta
tag; JSON parse fails), and every id is still validated as a principal.

The optional top-level **`derivation_origin`** is the app's declaration of the
Internet Identity derivation origin its frontends pin (see the identity section
above). It is the only authoritative way for `resolve_app` / `app_url` to learn a
**custom** derivation origin — there is no reverse lookup from an app URL to it —
so an app that uses one should declare it here; otherwise the connector assumes
the derivation origin equals the application origin and flags that assumption.

When the user names a **token, project, or service** (e.g. `ckUSDC`) rather than a
website or id, `icp_find_canister_by_name` resolves it via
[`dashboard.internetcomputer.org`](https://dashboard.internetcomputer.org)'s public
APIs — the ICRC token registry and the SNS catalog — to the matching canister id(s).
`icp_lookup_canister_info_by_id` goes the other way: given a bare id, it returns the dashboard's
label, type, controllers, subnet, and module hash, so a raw principal becomes an
identified service. (`discover_app_canisters` results are annotated with these labels
inline.) There is no public name-search over arbitrary canisters, so `icp_find_canister_by_name`
covers the IC's labelled services, which is where the meaningful ones live.

`call_canister` runs anonymously by default; pass a `derivation_origin` (or an
`app_url` like `https://oisy.com` that the connector resolves) to call as your
account at that app. The server mints a **short-lived account delegation on
demand** using the connection's registered Internet Identity session key (see
[Domain identities](#domain-identities-on-demand)) — there is no per-app sign-in
step. `get_app_principal` returns that account's principal
without a call. A user may hold several accounts at an app — a default account
everyone gets automatically (the anchor's current, user-controllable default at
that origin), plus any they have named — so `list_app_accounts` lists them (via II's
`get_accounts`), and `call_canister`/`get_app_principal`/`list_app_accounts` identify the
app by its `derivation_origin` (or an `app_url` the connector resolves — see the
note below), and take an optional `account` (a name from that list) to act as a
specific one; omit it for the default account. All these tools require a bearer
token (see Auth).

> **The derivation origin is explicit — and echoed.** Internet Identity derives
> the per-app principal from a **derivation origin**, which is *usually* but **not
> always** the visible website URL: an app can pin a *custom* derivation origin
> (via `derivationOrigin` + `/.well-known/ii-alternative-origins`) that browsers
> honour. The identity tools therefore take the derivation origin **explicitly**
> as `derivation_origin` (the exact canonical origin — never inferred from an
> alternative-origins list, which is the *inverse* relation), or an `app_url` the
> connector resolves. There is **no reverse lookup** from an app URL to a custom
> derivation origin, so `app_url` resolves to the app's **declared** origin
> (`/.well-known/ic-app.json` → `derivation_origin`) when present, else a built-in
> **known-app** value for a few apps that pin a custom origin without declaring it
> (NNS → `https://nns.ic0.app`, Oisy → `https://oisy.com`, MULTI/DEX →
> `https://hcv4s-…icp0.io`, ICPSwap → `https://app.icpswap.com`; an app's own
> declaration always overrides this), else it *assumes* the app origin — flagged in
> every result as `derivation_origin_source`
> (`explicit` / `declared` / `known` / `app_url_default`). Every identity result also echoes
> `derived_for_origin` (the origin actually used) alongside `requested` (what you
> passed), so a valid-but-wrong principal is **immediately visible** instead of
> silent. The `app_url_default` assumption is additionally **gated on IC evidence**:
> if the origin doesn't carry the gateway's `x-ic-canister-id` header (a valid
> canister principal, from the origin itself — not a redirect target — checked on
> the manifest response, else on the origin root), the `app_url` routes *refuse*
> to derive — that combination is the signature of a domain **guessed** from an app
> name (a lookalike/squatted site), and the refusal names the well-known app the
> host resembles when there is one. A genuinely non-IC-hosted app that uses
> Internet Identity can still be targeted deliberately by passing its origin as
> `derivation_origin` explicitly. Use `resolve_app(app_url)` to see the resolution (and the app's
> `alternative_origins`) before acting. Under the hood both routes go through the
> same origin canonicalizer the delegation path uses (bare `https://<host>`, with
> the `*.icp0.io`/`*.icp.net` → `*.ic0.app` gateway remap below). For backward
> compatibility the identity tools still accept the legacy parameter name `domain`
> as an alias for `derivation_origin`, so existing callers keep working unchanged.

### Skills awareness

`icp_list_skills` / `icp_get_skill` expose the official Internet Computer
[skills](https://skills.internetcomputer.org) — authoritative, current how-to
guides for authoring and shipping IC apps (the Motoko language, the `mops` and
`icp` CLIs, cycles management, stable memory & upgrades, canister security, DeFi,
auth, …). The catalogue is fetched live from the registry's manifest
(`/api/skills.json`, cached ~15 min) and each skill's `SKILL.md` on demand;
nothing is bundled, so the agent always sees the current skills. They are also
listed as MCP **resources** (`skill://<name>`) alongside the `candid://`
references. Override the registry origin with `SKILLS_URL`.

### OQL query surfaces

Some canisters expose **OQL** — a self-describing, agent-queryable surface over
their data via two Candid query methods: `schema : () -> (text) query` (a JSON
catalogue of entities, fields, and edges) and `execute : (text) -> (Result)
query` (a JSON query language with filters, aggregation, ordering, and edge
traversal). `get_canister_candid` detects the pair and reports `oql: true` (parsing the
interface behind the same CWE-674 guard the encode/decode path uses, so a
malformed `.did` just fails closed to `false`). Rather than inline the whole
dialect into every interface read, `get_canister_candid` emits only that flag plus a
one-line pointer; the full guide is served on demand by `icp_oql_guide` and as
the `oql://usage` MCP **resource**.

Two dedicated tools drive the surface: **`get_canister_oql_schema`** returns the entity/field
catalogue, and **`run_canister_oql_query`** takes the query as a plain JSON object string,
wraps it as `execute`'s single `text` argument (so the model never hand-escapes
JSON inside a Candid literal), and decodes the reply into `columns` + `rows` —
rendered as a markdown table, with `has_more` for paging. Both accept an optional
`derivation_origin`/`account` to query as the user's account (same on-demand
delegation as `call_canister`). Because OQL is the preferred read path when a
canister offers it, raw `call_canister` **query** calls are rejected on an OQL
canister (the tool returns a pointer to these two tools); `call_canister` then
handles only that canister's update calls. Detection stays name-based and the decode is fail-closed: a
reply that isn't a recognizable OQL result degrades to the raw Candid rather than
erroring. The design mirrors the reference IC connector's OQL primer (detect +
teach), adding an ergonomic executor suited to this server's structured-output
conventions.

### Creating & managing canisters

The management tools let the agent act **on chain as your standing Internet
Identity principal** — a stable per-connection identity (the one returned when you
authenticate). Because a user ingress message cannot attach cycles, creation and
top-ups fund the canister one of two ways, both keyed to that management principal
(the one `icp_cycles_balance` reports, default subaccount):

- **`cycles`** — drawn from your **cycles-ledger** balance
  (`um5iw-rqaaa-aaaaq-qaaba-cai`); fund it first (e.g. via the `icp` CLI /
  `cycles-management` skill) and check it with `icp_cycles_balance`.
- **`icp`** — a decimal-ICP amount transferred from that principal's
  **ICP-ledger** account (`ryjl3-tyaaa-aaaaa-aaaba-cai`, default subaccount) to
  the **CMC**, which mints cycles into the canister (`notify_create_canister` /
  `notify_top_up`). Best-effort, single attempt: if the transfer lands but the
  mint fails, the error carries the ICP-ledger block index to recover with — the
  call is **not** idempotent, so don't blindly re-run it.

`cycles` takes precedence if both are given. Lifecycle calls
(`icp_install_code`, `icp_canister_status`, `icp_update_canister_settings`,
`start`/`stop`/`uninstall`/`delete`) go to the management canister (`aaaaa-aa`)
with the effective canister id set to the target. `icp_install_code` takes the
compiled Wasm as base64/hex and uploads it via the chunk store automatically when
it exceeds the single-message limit.

Together these make the end-to-end flow work: *"create a Motoko canister that does
X and deploy a new canister with Y ICP worth of cycles"* → the agent reads the
relevant skills, writes and **builds** the Wasm in its own environment, then
`icp_create_canister(icp = Y)` and `icp_install_code`. (Compiling Motoko/Rust to Wasm
happens in the agent's environment, not in this server.)

## Connect from an MCP client

Add the server to Claude Code (replace the URL with wherever it's hosted):

```bash
claude mcp add --transport http ic-poc https://YOUR-HOST/mcp
```

Then run `/mcp` → **ic-poc** → authenticate: the client sends the browser to
**Internet Identity**'s `/mcp` handshake; you sign in once, II registers the
connection's session key as a time-boxed grant and returns you to the client, and
the tools become available. All clients use the same **authorization-code + PKCE**
flow.

> On II's consent screen, **leave the read-only option OFF** if you want to create
> or manage canisters — read-only is the default, and it makes every management
> tool inert (see [Read-only sessions](#read-only-sessions) below).

## Run

```bash
cargo run
# serves http://0.0.0.0:8000  (MCP streamable-HTTP at /mcp, info page at /)
# honours $PORT (default 8000) and $PUBLIC_URL (default http://localhost:8000)
```

## Deploy

The server is a single binary plus the `static/` assets. Two requirements when hosting:

- **HTTPS** — the id.ai passkey (WebAuthn) only works in a secure context.
- **`PUBLIC_URL`** — set it to the public https URL; it's used in the OAuth
  discovery documents, the sign-in redirect/callback, and the allowed-Host list.
  (II derives the MCP server origin from the connect callback, and each user
  must add this exact origin as their trusted MCP server in II Settings — there
  is no longer a deploy-time `mcp_server_origin` on II's side.)

A `Dockerfile` is included (works on Render / Fly / Cloud Run / Koyeb). For a
zero-signup public URL during testing, expose the local server with a tunnel:

```bash
cargo run &                                   # local server on :8000
cloudflared tunnel --url http://localhost:8000   # prints https://<name>.trycloudflare.com
# restart the server with PUBLIC_URL set to that URL:
PUBLIC_URL=https://<name>.trycloudflare.com cargo run
```

## Try it (raw MCP over curl)

```bash
# 1. initialize, grab the session id
SID=$(curl -s -D - -o /dev/null \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
  http://127.0.0.1:8000/mcp | grep -i '^mcp-session-id' | tr -d '\r' | awk '{print $2}')

H=(-H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -H "Mcp-Session-Id: $SID")
curl -s "${H[@]}" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' http://127.0.0.1:8000/mcp >/dev/null

# 2. call a real mainnet canister (ICP ledger)
curl -s "${H[@]}" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_canister","arguments":{"canister_id":"ryjl3-tyaaa-aaaaa-aaaba-cai","method":"icrc1_name","args":"()","is_query":true}}}' \
  http://127.0.0.1:8000/mcp | grep '^data: {' | sed 's/^data: //' | jq -r '.result.content[0].text'
# => ("Internet Computer")
```

## Auth (OAuth 2.1, login via Internet Identity)

`/mcp` is gated by a bearer token. II's `/mcp` handshake has **no redirect back
to this server** — the II tab makes two background `fetch()` POSTs to our
callback and then finishes on its own — so a classic authorization-code
`redirect_uri` can't be delivered *by II*. We bridge that gap with a single
**authorization-code + PKCE** flow, so any OAuth 2.1 client works:

- `/oauth/authorize` validates the client + redirect and PKCE, sets a
  **browser-binding cookie** (see below), and redirects to II's handshake. The
  key-request response carries a `finish_url` on our origin (with a one-time
  `finish_secret`), so after `mcp_register` II navigates the browser to
  `/oauth/finish`, which requires the cookie **and** the secret, confirms
  registration, mints a PKCE-bound code, and 302s to the client's
  `redirect_uri?code=…&state=…`.

The **RFC 8628 device grant was dropped**: no listed MCP client uses it, and it
adds a device-code phishing surface with none of the PKCE binding the rest of the
flow relies on.

Endpoints:

- `GET /.well-known/oauth-authorization-server` — AS metadata (advertises
  `grant_types_supported: ["authorization_code"]`)
- `GET /.well-known/oauth-protected-resource` — points clients at the AS
- `POST /oauth/register` — dynamic client registration (RFC 7591); `redirect_uris`
  are stored and persisted to `OAUTH_CLIENTS_FILE`; requested `grant_types` are
  honoured (intersected with `authorization_code`)
- `GET  /oauth/authorize` — validates the client + redirect, requires PKCE, sets
  the binding cookie, then redirects to II's handshake
- `GET  /oauth/finish` — II navigates here after registration; requires the
  binding cookie **and** the one-time `finish_secret`, confirms the grant is
  registered (proven, see below), then 302s to `redirect_uri?code=…&state=…`
- `POST /oauth/connect/callback` — serves II's **two cross-origin JSON POSTs**:
  a **single-use** key request `{state}` → `{public_key, finish_url}` (a fresh
  session keypair + one-time `finish_secret` embedded in `finish_url`; any later
  key request for the same `state` gets `403`), and a completion notification
  `{state, expiration, permissions}` → record the grant expiry + access level (a
  best-effort latency hint only)
- `POST /oauth/token` — exchanges an authorization `code` (PKCE) for the access token

"Registered" is proven by a signed `mcp_get_accounts` that returns `Ok` under the
minted session key — **not** by the completion POST, which is unauthenticated and
therefore only a latency hint. Unauthenticated `/mcp` requests get `401` with a
`WWW-Authenticate` header pointing at the resource metadata, as the MCP spec expects.

### Consent-Bound Completion (`/oauth/authorize` → `/oauth/finish`)

The `state` in the II connect link is echoed back to the client in the final
redirect, so it **cannot by itself prove** that the browser finishing at
`/oauth/finish` is the one that started at `/oauth/authorize` — nor that it is the
one that actually **consented** at II. Without a binding there's a session-fixation
takeover: an attacker registers a client (open DCR) with their own `redirect_uri` +
PKCE challenge, calls `/oauth/authorize`, reads the II connect link from the 302,
and phishes it to a victim who already trusts this origin in II Settings (II's
consent screen names only the *origin*, never the OAuth client, so nothing warns the
victim). The victim consents; the attacker completes the flow and redeems the code
with their own PKCE verifier — a token acting as the victim. (An initiator-only
cookie does *not* close this: the attacker is the initiator, so it holds the cookie.)

**The fix — Consent-Bound Completion.** `/oauth/finish` mints a code only when the
requesting browser presents **both** proofs, which can co-reside in one browser
only in the legitimate same-browser flow:

1. **initiator** — an unguessable `HttpOnly; Secure; SameSite=Lax` `sid` cookie
   (scoped to the instance's `…/oauth` path) set at `/oauth/authorize`;
2. **consenter** — a one-time `finish_secret` (≥128-bit) minted at the **single-use**
   key request and disclosed *only* in that response (embedded in `finish_url`), so
   only the browser that drove the II handshake holds it;
3. plus **proven** registration (signed `mcp_get_accounts` = `Ok`), not a bare
   completion POST.

Because the single-use key request delivers *both* the `finish_secret` and the
`public_key` a victim would register, the party that can register as the victim is
exactly the party that gets the secret — and the `sid` cookie pins the finisher to
the initiator. An attacker who initiates then phishes the II link holds `sid` but
never the secret (the victim's key request consumes it); the victim holds the secret
but never `sid`. Neither can finish. This closes the split-browser injection for
**all transports incl. loopback** (a loopback redirect resolves on the consenter's
own machine). `SameSite=Lax` still rides the top-level cross-site GET II uses to
navigate back to `finish_url`.

Load-bearing invariants (enforced in code): the key request is a single **atomic**
compare-and-set (P1) and II's frontend issues exactly one per connect (a retry
fails as "restart", never a takeover); `finish_secret` rides in the **query** (not a
path segment), is kept out of logs, and `/oauth/finish` sends `Referrer-Policy:
no-referrer` so it can't leak via `Referer` (P2); `registered` reflects a real
on-chain grant (P3).

> **Companion control (not in this change).** The *same-browser* variant — a victim
> socially engineered into running the whole flow toward an attacker-registered
> **hosted** `redirect_uri` — is not closed by Consent-Bound Completion (the
> victim's browser legitimately holds both proofs). It needs **hosted-redirect
> allow-listing**; loopback/native clients are safe either way (the code resolves on
> the consenter's own machine). So "H3 fully closed" = Consent-Bound Completion +
> hosted-redirect allow-listing — a product decision that trades only against open
> DCR for hosted clients.

### Registration delegation (Phase 2 — per-instance: beta on, prod on v1)

A successor connect flow (the *registration delegation* design) removes the
weakest link in v1: today II binds a session key it was merely **shown** (fetched
from our callback), so any path on the trusted origin that can be made to echo an
attacker's key lets II bind it. Phase 2 replaces the fetched key with a
**short-lived (~5 min), two-hop delegation chain `P_reg → Y → X`** delivered to a
**pinned callback page** as a URL fragment: II's canister signs `P_reg → Y`
toward an ephemeral key `Y` held only by II's frontend — so the piece that
transits the IC (replicas, boundary nodes, the public state tree) is inert on
its own — and the frontend extends it browser-side with a `Y`-signed hop to the
server's registration key `X`, assembling the redeemable chain only in the
consenting browser. The backend redeems it by signing **one** `mcp_register_v2`
call as `X`. II never again binds a bare key it was shown.

**The server runs both protocols side by side, selected per II instance:**

- **beta / staging (`/mcp`, beta.id.ai)** — Phase 2 **on** by default (disable
  with `MCP_REGISTRATION_DELEGATION=0`). Enabling is outbound-compatible with
  v1: the II link gains the `registration_key` param and the Phase-2 routes turn on,
  while every v1 handler stays live — so beta keeps connecting via v1 until beta
  II actually ships the new frontend + canister methods, and switches over when
  it does.
- **production (`/mcp-prod`, id.ai)** — **pinned to v1** by default (opt in
  later with `MCP_REGISTRATION_DELEGATION_PROD=1`). Its II link, callback, and
  finish flow are exactly the existing protocol; the Phase-2 routes `404`.

`/version` is the unauthenticated operations probe. It reports the running
build (`version`, `commit`, `built_at`, `started_at`), the H3/P1
`repeat_key_requests` health counter, which instance runs which protocol
(`registration_delegation: {beta, prod}`), and two real-time per-instance
**session gauges** — `live_sessions` (open grants) and `active_sessions` (a
subset: those also requesting recently):

```bash
curl -s https://<host>/version | jq '{live: .live_sessions, active: .active_sessions}'
# => { "live": { "beta": 0, "prod": 3 }, "active": { "beta": 0, "prod": 1 } }
```

**`live_sessions`** counts authenticated sessions whose II grant has not yet
expired. It tracks the grant lifecycle: a session is counted from the moment its
grant is redeemed until the grant expires, and sitting idle does not remove it —
an ongoing MCP session is often quiet for long stretches between tool calls and
is still a live session the whole time. The flip side: the server runs MCP
statelessly, so a client that disconnects for good produces no server-side
event, and its session keeps counting until the grant expires (the session
duration is what the user picked on II's consent screen, 10 minutes up to 30
days).

**`active_sessions`** is the subset of live sessions seen active within the last
~15 minutes — a ballpark of who is actually using the server right now. "Active"
means an authenticated request in that window, and also the connect that redeems
the grant (which is itself treated as activity) — so a freshly-connected session
counts immediately, before its first tool call; it is not strictly "made an
authenticated request". Prefer it for **timing a redeploy**: a restart wipes the
in-memory session and token maps, forcing every connected client to reconnect, so
the disruption falls on whoever is active at that moment, not on long-idle grants.
Because it is activity-based, a single reading is a point-in-time snapshot;
sample it over time (scrape `/version` on a schedule, or read request rate from
the request logs below) to find a genuinely low-traffic window before deploying.
`active_sessions ≤ live_sessions` always.

```bash
curl -s https://<host>/version | jq '.active_sessions'
# => { "beta": 0, "prod": 1 }
```

Session grants are also traceable in the logs (unit `mcp-poc`): a session logs
`session opened` (with `instance` and `session_id`) when its grant goes live,
and `session closed` when the grant expires and the per-instance reaper (60s
cadence) evicts it. These bracket what `live_sessions` counts, modulo the
reaper's cadence: the gauge drops the instant a grant expires, while the paired
`closed` log lands on the reaper's next sweep (up to 60s later), so `opened`
minus `closed` can momentarily exceed the gauge by the sessions expired since
that sweep.

**Callback allow-list (`/.well-known/ii-auth-callbacks`).** II is moving to
validate the connect callback named in the (attacker-craftable) link fragment
against a **server-declared allow-list**
([dfinity/internet-identity#4091](https://github.com/dfinity/internet-identity/pull/4091)):
before contacting the callback, II fetches
`<callback origin>/.well-known/ii-auth-callbacks` (`redirect: "error"`, no
credentials, `no-store`, 8 KB cap, `application/json` required) and requires the
callback URL to be **exactly** (string-equal) one of the declared entries —
**fail-closed**, so serving this document is mandatory once #4091 ships. This
server serves it for both instances (one origin-global document listing each
instance's `{prefix}/oauth/connect/callback`), built from the same helper that
builds the II links' callback URLs so the two can never drift.

The Phase-2 wire shapes match the **merged II contract** (verified against the
beta II canister's live `.did`, `fgte5-ciaaa-aaaad-aaatq-cai`): the connect
link carries `registration_key` = base64url(DER(`pub(X)`)); II navigates back
to the allow-listed callback with the chain **plus the connect state**:
`#delegation=<DelegationChain JSON>&state=…`
(agent-js `DelegationChain.toJSON()`: hex byte fields, hex-string expiration);
and redemption calls `mcp_register_v2(session_key)
-> variant { Ok : record { expiration; permissions }; Err : text }` (the server
decodes the outer `variant`; the `Ok` payload carries the grant expiry and the
access level). The access level and lifetime are
**not sent by the server**: the user chose them at consent, and II stored them at
`prepare_mcp_registration_delegation` on an index keyed by `P_reg`, so
`mcp_register_v2` recovers both the consent and the anchor from
`caller() == P_reg`. The server therefore sends only `pub(S)` and can alter
neither the anchor, the permissions, nor the TTL; the anchor number never
reaches (or is logged by) this server. (The chosen access level does come
*back* on the reply, feeding the read-only guard.)

Server side (on a Phase-2 instance):

- **`X`, a per-connect registration keypair** bound to the connect `sid`;
  `priv(X)` never leaves the backend, and `pub(X)` rides the II link
  (`registration_key`, base64url DER).
- **A pinned callback page** at `GET /oauth/connect/callback` — the *sole* reader
  of the returned fragment. It reads `location.hash` client-side, POSTs it (with
  the connect cookie) to `POST /oauth/connect/redeem`, and reflects nothing into
  the DOM; it ships a strict CSP (`default-src 'none'`, a per-response script
  nonce, `connect-src 'self'`).
- **Redemption** builds a `DelegatedIdentity` from `priv(X)` + the delegation and
  calls `mcp_register_v2` to bind the long-lived session key `S` to the anchor
  (which II recovers from `caller() == P_reg` — the server never names it).
  The fragment-delivered delegation subsumes `finish_secret` as the consenter
  proof, and synchronous registration removes the `grant_is_live` probe and the
  `finishing_page` poll. The read-only level comes back on the `mcp_register_v2`
  reply (feeding the same `require_write` guard as v1's completion POST).

> **Verified against deployed beta II.** `mcp_register_v2` and the
> delegation-minting methods (`prepare_mcp_registration_delegation`,
> `get_mcp_registration_delegation`) are **live on the beta II canister**
> (`fgte5-ciaaa-aaaad-aaatq-cai`); the shapes here (link param, fragment
> `DelegationChain` JSON, the one-argument `mcp_register_v2` candid, and the
> callback allow-list) match its published `.did`; re-verify if it ever moves.
> The design tracked II's implementation PRs
> [#4091](https://github.com/dfinity/internet-identity/pull/4091) /
> [#4092](https://github.com/dfinity/internet-identity/pull/4092) /
> [#4093](https://github.com/dfinity/internet-identity/pull/4093) through to
> this merged shape. Production II (`rdmx6-…`) keeps `registration_delegation`
> **off** (v1 flow) until it ships these methods. Retiring v1 on a Phase-2
> instance (the design's "v1 sunset") is a separate, later step. This also
> relies on **Phase 1** (the callback allow-list, an II-side validation) as its
> security precondition.

### Read-only sessions

II's consent screen **defaults to read-only** (opt-out). A user who just clicks
"Allow" gets a session whose per-app delegations are `permissions = "queries"`,
and the IC **rejects update calls made through them at ingress**. That makes the
entire canister-management surface inert — `create`/`install`/`start`/`stop`/
`uninstall`/`delete`, and even `icp_canister_status`, are update calls. To handle this
without opaque low-level errors:

- The completion POST now carries `permissions: "queries" | "all"` (§0), so the
  server learns the level at connect without minting a probe delegation. A
  missing or unrecognized value leaves the level **unknown** (not assumed
  writable): the update is attempted and the IC's ingress rejection is the
  fallback signal.
- Management tools check it up front and, for a *known* read-only session, return
  an actionable *"reconnect with read-only off"* message instead of an ingress error.
- `get_app_principal` reflects a read-only session in its output, so the agent won't
  attempt updates it can't make.

**The server is passive during the handshake and holds no key at link time.** On
the key-request POST it generates a fresh per-connection Ed25519 keypair and
returns only its **public** key (base64url, unpadded, DER). II's *frontend*
registers that key with the II canister (`mcp_register`, under the user's own
authentication) as a time-boxed grant bound to the user's anchor. **The server
never receives or verifies a delegation chain that represents itself, and never
calls `mcp_register`.** The issued access token is bound to the session key's
principal (`self_authenticating(session_pubkey)`), which is exactly the identity
the grant is bound to.

**PKCE (S256)** is required for the authorization-code flow; auth codes live 120s,
and the access token's lifetime **tracks the II grant** — it expires exactly when
the grant does, so the session duration the user picks on II's consent screen (10
minutes up to 30 days) is how long the client's token stays valid. Refresh tokens
remain a deliberate non-goal: with the token matched to the grant there is nothing
to refresh against — when the grant lapses, so does the token, and the client
re-runs the authorization-code flow. (If the grant expiration isn't known at issue
time — e.g. a dropped connect-completion POST — the token falls back to a 1h TTL;
the grant is the hard ceiling at II either way.) Treat any `Unauthorized` from II
as "session over → reconnect": the server surfaces a reconnect message and does
not retry.

Set the public base URL (used in the discovery docs, as the MCP origin, and as the
management identity's derivation origin) with `PUBLIC_URL`. The Internet Identity
instance is `II_URL` (browser login, default `beta.id.ai`) plus `II_CANISTER_ID`
(the canister the `mcp_*` calls target, default `fgte5-ciaaa-aaaad-aaatq-cai`) —
both point at the same II.

### Production instance (`/mcp-prod`)

The same server exposes a second, fully isolated instance connected to
**production** Internet Identity: MCP endpoint `/mcp-prod`, with its own
path-scoped authorization server under `/prod/oauth/*` (issuer
`<PUBLIC_URL>/prod`, an RFC 8414 path issuer; AS metadata at
`/.well-known/oauth-authorization-server/prod`, resource metadata at
`/.well-known/oauth-protected-resource/mcp-prod`). Configure with `II_URL_PROD`
(default `https://id.ai`) and `II_CANISTER_ID_PROD` (default
`rdmx6-jaaaa-aaaaa-aaadq-cai`).

Sessions and tokens are per-instance — a `/mcp` token is not valid on
`/mcp-prod` and vice versa — while dynamic client registrations are shared
(they only pin redirect URIs). II trust is by origin, so users enable this
server's origin as their trusted MCP server in their **id.ai** settings
(a separate identity from their beta anchor). Note: `/mcp-prod` only completes
once the production II carries the #4086 MCP feature set; until then the
connect fails at the II step with a "may not support MCP connect yet" hint.

## Domain identities (on demand)

There is no per-app browser sign-in. Instead the model is:

- **One registered session key per connection.** When you connect, the backend
  generates a per-connection Ed25519 **session key** and II's frontend registers
  it as a time-boxed grant bound to your anchor. The backend signs II's `mcp_*`
  calls directly with that key (its principal `self_authenticating(session_pubkey)`
  is what the grant is bound to). Reconnect when the grant expires or is revoked.
- **App delegations minted on demand.** When `call_canister` (or `get_app_principal`)
  is invoked with a `derivation_origin` (or an `app_url` like `https://oisy.com`), the backend mints a **short-lived
  per-app account delegation on demand**: signing *as the session key*, it calls
  Internet Identity's account-derivation methods directly — no browser round-trip
  — with the app's target origin and a fresh **per-app key** as `session_key`.
  The returned delegation is issued to that per-app key, so the backend signs the
  canister call with `ic-agent`'s `DelegatedIdentity` over `[user_key → per-app key]`.

The on-demand derivation calls these II canister methods (per
[dfinity/internet-identity#4086](https://github.com/dfinity/internet-identity/pull/4086)):

```candid
mcp_prepare_delegation :
  (target_origin: text, account_number: opt nat64, session_key: blob, max_ttl: opt nat64)
    -> (variant {
         Ok: record { user_key: blob; account_number: opt nat64; expiration: nat64 };
         Err: AccountDelegationError });
mcp_get_delegation :
  (target_origin: text, account_number: opt nat64, session_key: blob, expiration: nat64)
    -> (variant { Ok: SignedDelegation; Err: AccountDelegationError }) query;
```

- `session_key` is the DER pubkey of a **fresh per-app key**, distinct from the
  connection's session key; the minted delegation is issued to it.
- `target_origin` is the app's **bare** `https://<host>` origin. II derives the
  principal from an anchored regex on that bare origin, so the server first strips
  any path, query, fragment, trailing slash, or redundant `:443` (a stray one
  would derive a *different* principal), then applies the gateway remap:
  `*.icp0.io` / `*.icp.net` → `*.ic0.app`. Note this replicates only II's
  *domain-based* derivation — a **custom derivation origin** declared via
  `/.well-known/ii-alternative-origins` isn't visible through the `mcp_*` methods,
  so an app using one derives a different principal here than in a browser (see the
  caveat under [Tools](#tools)); fetching that declaration is a future enhancement.
- `account_number` names which of the anchor's accounts at `target_origin` to act
  as; `null` selects the (mutable) default account there. `prepare` resolves it
  and returns the concrete account in its reply, which is threaded back into
  `get` so both calls sign for the same account. The server passes `null` for the
  default account, or a specific number when an `account` name was given — resolved
  from `mcp_get_accounts` (see [Listing accounts](#listing-accounts) below).
- `max_ttl` is in **nanoseconds**; the server passes `null`, so II applies its
  default (≤ 1 hour, and never past the grant).
- These methods live on the **same II instance** as the connect-time login:
  `II_URL` (default `https://beta.id.ai`) is the browser login origin and
  `II_CANISTER_ID` (default `fgte5-ciaaa-aaaad-aaatq-cai`, that instance's
  canister) is the canister these calls target, over `https://icp-api.io`.
- Derived delegations are cached per `(session, derivation_origin, account_number)` and
  reused until they near expiry, then re-derived.

### Listing accounts

A user can hold several accounts at one app: a default account everyone gets
automatically (the anchor's current, user-controllable default at that origin),
plus any **named** accounts they created there. Each account is a **distinct
per-origin principal** — the app never sees a global, cross-app identity.
`list_app_accounts(derivation_origin)` returns them by calling II's

```candid
mcp_get_accounts : (target_origin: text)
  -> (variant { Ok: vec AccountInfo; Err: AccountDelegationError }) query;
type AccountInfo = record {
  account_number: opt nat64; origin: text; last_used: opt nat64; name: opt text;
};
```

signed as the session key. Like the delegation methods, II **recovers the anchor
from the caller** (the registered session-key principal), so no anchor number is
needed. To act as a non-default account, pass its `name` to
`call_canister`/`get_app_principal` as `account`; the server resolves the name to its
`account_number` via `mcp_get_accounts` and threads that into the on-demand
delegation. Omitting `account` uses the default account.

> **Status:** the connect handshake and the `mcp_register` / `mcp_get_accounts` /
> `mcp_prepare_delegation` / `mcp_get_delegation` canister methods are the
> session-key registration model from
> [dfinity/internet-identity#4086](https://github.com/dfinity/internet-identity/pull/4086)
> (the server is built against that candid contract). #4086 renames the on-demand
> delegation methods from the earlier `mcp_prepare_account_delegation` /
> `mcp_get_account_delegation` and removes `mcp_set_access` / `mcp_access_enabled`.
> The live round-trip works once that II build is deployed to the configured
> `II_URL`. Passing `account_number = null` resolves to the anchor's current
> (user-controllable) default account at the origin — which may be a named account
> the user set as their default there, not necessarily the anchor's base account.

## Roadmap

- [x] Candid tools over MCP streamable-HTTP; `discover_app_canisters`; Candid
      reference resources.
- [x] OAuth 2.1 auth (authorization-code + PKCE): II's `/mcp` handshake registers
      the connection's session key (two JSON callback POSTs, no delegation chain),
      with **Consent-Bound Completion** binding `/oauth/finish` to both the initiator
      (`sid` cookie) and the consenter (one-time `finish_secret`); expiring tokens.
      (The RFC 8628 device grant was dropped. Same-browser-variant closure needs
      hosted-redirect allow-listing — see Auth.)
- [x] On-demand **domain identities**: the registered session key mints per-app
      account delegations directly via II canister methods
      (`call_canister`/`get_app_principal` `derivation_origin`); no per-app browser flow.
- [x] **Per-app accounts**: `list_app_accounts(derivation_origin)` lists the user's accounts at
      an app (via `mcp_get_accounts`), and `call_canister`/`get_app_principal` take an
      `account` name to act as a specific (non-default) account.
- [ ] Deploy the `mcp_register` + `mcp_get_accounts` + `mcp_prepare_delegation` +
      `mcp_get_delegation` canister methods (server is built against #4086's candid
      contract; the live round-trip lands with the II side).
- [ ] Persist sessions/delegations (currently in-memory, lost on restart).
- [ ] Scoped delegations / per-call confirmation for sensitive methods.
