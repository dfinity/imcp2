# mcp-poc

Minimal MCP server that bridges an LLM to the Internet Computer.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding and signing against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

## Tools

| Tool | Args | Returns |
|------|------|---------|
| `discover_canisters` | `domain` | Canister ids behind a web domain (frontend via `x-ic-canister-id`; backend via `/env.json` + JS-bundle mining), each with provenance and its IC dashboard label/type where known |
| `find_canister` | `query` | Canister ids matching a name/symbol, searched in the IC dashboard's service registries — ICRC token ledgers (e.g. `ckUSDC`) and the SNS project catalog |
| `lookup_canister` | `canister_id` | What a canister IS, per the IC dashboard: label/name, type, controllers, subnet, module hash, latest upgrade proposal |
| `get_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text) |
| `call_canister` | `canister_id`, `method`, `args` (textual Candid), `is_query`, `domain?`, `account?` | Reply as textual Candid; called anonymously (no `domain`) or as your account at an application domain, derived on demand (`account` names a non-default account there) |
| `get_principal` | `domain`, `account?` | The principal you act as at an application domain (derives the delegation on demand, same as `call_canister`), without making a call |
| `list_accounts` | `domain` | The user's Internet Identity accounts at an app — the default account (the anchor's current default at that origin) plus any named ones — with name, account number, and last-used time; name one via `account` in `call_canister`/`get_principal` |
| `list_ic_skills` | — | The official [IC skills](https://skills.internetcomputer.org) (Motoko, mops/icp CLIs, cycles, stable memory, security, …), grouped by category |
| `get_ic_skill` | `name` | The full `SKILL.md` instructions for one skill (e.g. `motoko`, `icp-cli`, `cycles-management`) |
| `cycles_balance` | — | Your cycles-ledger balance (the funds `create_canister`/`top_up_canister` spend), as your standing II principal |
| `create_canister` | `cycles?` / `icp?`, `controllers?`, `subnet?` | Create + fund a new canister from your cycles-ledger balance; returns the new canister id |
| `install_code` | `canister_id`, `wasm_base64` / `wasm_hex`, `mode?`, `arg?` | Install/reinstall/upgrade a Wasm module (single-shot, or via the chunk store for large modules) |
| `canister_status` | `canister_id` | Run state, cycle balance, module hash, memory, controllers, allocations |
| `update_canister_settings` | `canister_id`, `controllers?`, allocations, `freezing_threshold?`, `log_visibility?`, … | Update a canister's settings |
| `start_canister` / `stop_canister` / `uninstall_code` / `delete_canister` | `canister_id` | Canister lifecycle |
| `top_up_canister` | `canister_id`, `cycles?` / `icp?` | Add cycles to an existing canister from your cycles-ledger balance |

`discover_canisters` is the entry point when the user names a **website** instead
of a canister id: frontend via the `x-ic-canister-id` header (authoritative),
backend candidates mined from `/env.json` + the JS bundle (pick by label, prefer
production/`IC_` ids, confirm with `get_candid`).

When the user names a **token, project, or service** (e.g. `ckUSDC`) rather than a
website or id, `find_canister` resolves it via
[`dashboard.internetcomputer.org`](https://dashboard.internetcomputer.org)'s public
APIs — the ICRC token registry and the SNS catalog — to the matching canister id(s).
`lookup_canister` goes the other way: given a bare id, it returns the dashboard's
label, type, controllers, subnet, and module hash, so a raw principal becomes an
identified service. (`discover_canisters` results are annotated with these labels
inline.) There is no public name-search over arbitrary canisters, so `find_canister`
covers the IC's labelled services, which is where the meaningful ones live.

`call_canister` runs anonymously by default; pass a `domain` (e.g. `oisy.com`) to
call as your account at that app. For a domain, the server mints a **short-lived
account delegation on demand** using the connection's registered Internet
Identity session key (see [Domain identities](#domain-identities-on-demand)) —
there is no per-app sign-in step. `get_principal` returns that account's principal
without a call. A user may hold several accounts at an app — a default account
everyone gets automatically (the anchor's current, user-controllable default at
that origin), plus any they have named — so `list_accounts(domain)` lists them
(via II's `get_accounts`), and `call_canister`/`get_principal` take an optional
`account` (a name from that list) to act as a specific one; omit it for the
default account. All these tools require a bearer token (see Auth).

> **Derivation is domain-based — not guaranteed to equal a browser sign-in.** II
> derives the per-app principal from the app's **domain**, which this server
> normalizes to a bare `https://<host>` (with the gateway remap below). That is
> usually the same identity a browser sign-in to the app would use, but **not
> always**: an app can declare a *custom derivation origin* via
> `/.well-known/ii-alternative-origins`, which browsers honour but the `mcp_*`
> methods don't expose — so from the domain alone the server derives a different
> principal, silently. If a principal, account, or balance doesn't match what the
> user sees in their browser at that app, that's the likely cause; the tools tell
> the agent to offer looking up the app's `ii-alternative-origins` and retrying.

### Skills awareness

`list_ic_skills` / `get_ic_skill` expose the official Internet Computer
[skills](https://skills.internetcomputer.org) — authoritative, current how-to
guides for authoring and shipping IC apps (the Motoko language, the `mops` and
`icp` CLIs, cycles management, stable memory & upgrades, canister security, DeFi,
auth, …). The catalogue is fetched live from the registry's manifest
(`/api/skills.json`, cached ~15 min) and each skill's `SKILL.md` on demand;
nothing is bundled, so the agent always sees the current skills. They are also
listed as MCP **resources** (`skill://<name>`) alongside the `candid://`
references. Override the registry origin with `SKILLS_URL`.

### Creating & managing canisters

The management tools let the agent act **on chain as your standing Internet
Identity principal** — a stable per-connection identity (the one returned when you
authenticate). Because a user ingress message cannot attach cycles, creation and
top-ups draw from your **cycles-ledger** balance (`um5iw-rqaaa-aaaaq-qaaba-cai`):
fund that principal first (e.g. via the `icp` CLI / `cycles-management` skill),
check it with `cycles_balance`, then `create_canister` (amount in `cycles`, or in
`icp` converted at the CMC's current rate). Lifecycle calls
(`install_code`, `canister_status`, `update_canister_settings`,
`start`/`stop`/`uninstall`/`delete`) go to the management canister (`aaaaa-aa`)
with the effective canister id set to the target. `install_code` takes the
compiled Wasm as base64/hex and uploads it via the chunk store automatically when
it exceeds the single-message limit.

Together these make the end-to-end flow work: *"create a Motoko canister that does
X and deploy a new canister with Y ICP worth of cycles"* → the agent reads the
relevant skills, writes and **builds** the Wasm in its own environment, then
`create_canister(icp = Y)` and `install_code`. (Compiling Motoko/Rust to Wasm
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
  key-request response carries a `finish_url` on our origin, so after
  `mcp_register` II navigates the browser to `/oauth/finish`, which checks that
  cookie, confirms registration, mints a PKCE-bound code, and 302s to the client's
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
  binding cookie, confirms the grant is live, then 302s to `redirect_uri?code=…&state=…`
- `POST /oauth/connect/callback` — serves II's **two cross-origin JSON POSTs**:
  a key request `{state}` → `{public_key, finish_url}` (a fresh session keypair,
  minted here), and a completion notification `{state, expiration, permissions}` →
  mark the grant live and record the session's access level
- `POST /oauth/token` — exchanges an authorization `code` (PKCE) for the access token

"Grant is live" means II's completion POST arrived **or** a signed
`mcp_get_accounts` now succeeds (belt-and-suspenders, since the completion POST is
best-effort). Unauthenticated `/mcp` requests get `401` with a `WWW-Authenticate`
header pointing at the resource metadata, as the MCP spec expects.

### Browser-session binding (`/oauth/authorize` → `/oauth/finish`)

The `state` in the II connect link is echoed back to the client in the final
redirect, so it **cannot by itself prove** that the browser finishing at
`/oauth/finish` is the one that started at `/oauth/authorize`. Without a binding
there's a session-fixation takeover: an attacker registers a client (open DCR)
with their own `redirect_uri` + PKCE challenge, calls `/oauth/authorize`, reads
the II connect link from the 302, and phishes it to a victim who already trusts
this origin in II Settings (II's consent screen names only the *origin*, never the
OAuth client, so nothing warns the victim). The victim consents, the server would
mint a code for the *attacker's* pending auth and 302 the victim to the attacker's
`redirect_uri`, and the attacker redeems it with their own PKCE verifier — a token
acting as the victim. (The "arrival ≠ registration" check guards a different
property; it doesn't bind the initiator to the consenting user, and II can't help
— its trust model only ever identifies the origin.)

The fix: `/oauth/authorize` sets an unguessable, single-use, `HttpOnly` `Secure`
`SameSite=Lax` cookie (scoped to the instance's `…/oauth` path) and `/oauth/finish`
requires it before minting the code — so only the browser that **started** the
flow can complete it. `SameSite=Lax` still rides the top-level cross-site GET II
uses to navigate back to `finish_url`.

### Read-only sessions

II's consent screen **defaults to read-only** (opt-out). A user who just clicks
"Allow" gets a session whose per-app delegations are `permissions = "queries"`,
and the IC **rejects update calls made through them at ingress**. That makes the
entire canister-management surface inert — `create`/`install`/`start`/`stop`/
`uninstall`/`delete`, and even `canister_status`, are update calls. To handle this
without opaque low-level errors:

- The completion POST now carries `permissions: "queries" | "all"` (§0), so the
  server learns the level at connect without minting a probe delegation (falling
  back to a missing value = full access).
- Management tools check it up front and, for a read-only session, return an
  actionable *"reconnect with read-only off"* message instead of an ingress error.
- `get_principal` reflects a read-only session in its output, so the agent won't
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
access tokens 1h (bounded by the II grant — refresh tokens are a deliberate
non-goal, as they'd add no security over the grant and only pay off with
server-side persistence). Treat any `Unauthorized` from II as "session over →
reconnect": the server surfaces a reconnect message and does not retry.

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
- **App delegations minted on demand.** When `call_canister` (or `get_principal`)
  is invoked with a `domain` (e.g. `oisy.com`), the backend mints a **short-lived
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
- Derived delegations are cached per `(session, domain, account_number)` and
  reused until they near expiry, then re-derived.

### Listing accounts

A user can hold several accounts at one app: a default account everyone gets
automatically (the anchor's current, user-controllable default at that origin),
plus any **named** accounts they created there. Each account is a **distinct
per-origin principal** — the app never sees a global, cross-app identity.
`list_accounts(domain)` returns them by calling II's

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
`call_canister`/`get_principal` as `account`; the server resolves the name to its
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

- [x] Candid tools over MCP streamable-HTTP; `discover_canisters`; Candid
      reference resources.
- [x] OAuth 2.1 auth (authorization-code + PKCE): II's `/mcp` handshake registers
      the connection's session key (two JSON callback POSTs, no delegation chain),
      with `/oauth/authorize`→`/oauth/finish` browser-session binding; expiring
      tokens. (The RFC 8628 device grant was dropped.)
- [x] On-demand **domain identities**: the registered session key mints per-app
      account delegations directly via II canister methods
      (`call_canister`/`get_principal` `domain`); no per-app browser flow.
- [x] **Per-app accounts**: `list_accounts(domain)` lists the user's accounts at
      an app (via `mcp_get_accounts`), and `call_canister`/`get_principal` take an
      `account` name to act as a specific (non-default) account.
- [ ] Deploy the `mcp_register` + `mcp_get_accounts` + `mcp_prepare_delegation` +
      `mcp_get_delegation` canister methods (server is built against #4086's candid
      contract; the live round-trip lands with the II side).
- [ ] Persist sessions/delegations (currently in-memory, lost on restart).
- [ ] Scoped delegations / per-call confirmation for sensitive methods.
