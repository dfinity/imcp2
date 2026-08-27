# IMCP2

Minimal MCP server that bridges an LLM to the Internet Computer — packaged as
an embeddable Rust **library crate** (`imcp2`) plus a thin deployment binary.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding and signing against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

**Not for financial operations.** IMCP2 is infrastructure tooling for reading,
building, and operating canisters — it is not a wallet or trading tool, and
financial operations (token transfers, spending approvals, payments, trades)
are unsupported by policy. The standardized ledger surface is refused
mechanically: `canister_update_call` rejects the ICRC-1/ICRC-2 (and related
ledger-standard) transfer/approval methods on every canister, and
`icp_top_up_canister` returns CLI instructions instead of executing anything.
For financial operations, users act themselves in a wallet or frontend they
control (e.g. [oisy.com](https://oisy.com)), in their own browser. Creating and
funding the user's **own** canisters (compute resources) remains available
through the dedicated `icp_create_canister` tool.

## Use as a library

Published on [crates.io](https://crates.io/crates/imcp2), API docs on
[docs.rs](https://docs.rs/imcp2):

```toml
[dependencies]
imcp2 = "0.2"
```

One `McpServer` serves one Internet Identity instance as two
[`axum`](https://github.com/tokio-rs/axum) routers:

- **`McpServer::mcp_router()`** — the MCP streamable-HTTP endpoint (the router
  fallback, bearer-token gated) plus the OAuth authorization server under
  `/oauth`, nested at the mount path of your choice.
- **`McpServer::well_known_router()`** — the OAuth discovery documents, merged
  at the application root (well-known URIs are origin-scoped), **parametric on
  the mount path**: the AS issuer is `{public_url}{mcp_path}` (an RFC 8414 path
  issuer) and the documents live at the path-inserted well-known locations.
  `root_well_known_router()` adds the plain-root fallback documents for the
  origin's default instance, and `auth_callbacks_router(&[…])` the
  origin-global II auth-callback allow-list covering every instance.

The IC `Agent` is **inherited from the caller**, not built by the library: a
host — an API boundary node or a gateway — passes in its own route-configured
agent, so the whole process links one `ic-agent` and shares one boundary-node
client. (`ic-agent` stays a direct dependency until
[`ic-bn-lib`](https://github.com/dfinity/ic-bn-lib) — the shared BN/gateway
crate it should eventually be sourced through — releases against ic-agent 0.49;
see `Cargo.toml`.)

```rust
use imcp2::{auth_callbacks_router, Agent, IiInstance, McpConfig, McpServer, SharedClients, IC_URL};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Standalone: a default mainnet agent. Embedded: hand in the host's own.
    let agent = Agent::builder().with_url(IC_URL).build()?;
    // Where imcp2 keeps operational state (the client-registration store).
    let state_dir = std::path::PathBuf::from("/var/lib/imcp2");
    let server = McpServer::new(McpConfig {
        agent,
        instance: IiInstance::beta().map_err(anyhow::Error::msg)?,
        public_url: "https://mcp.example.com".into(),
        mcp_path: "/mcp".into(),
        clients: SharedClients::load(&state_dir),
        state_dir,
        require_resource: true, // strict RFC 8707 (reject a missing `resource`)
    });
    server.spawn_session_reaper();
    let app = axum::Router::new()
        // nest_service (not nest): it also forwards the trailing-slash form.
        .nest_service(server.mcp_path(), server.mcp_router())
        .merge(server.well_known_router())
        // Exactly one instance per origin also answers the root probes and
        // serves the origin-global II auth-callback allow-list.
        .merge(server.root_well_known_router())
        .merge(auth_callbacks_router(&[&server]));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

Mounted at `/mcp`, that serves:

```
POST /mcp                          the MCP endpoint (401 + WWW-Authenticate until authorized)
GET  /mcp/oauth/authorize         ─┐
GET  /mcp/oauth/connect/callback   │ the OAuth authorization server
POST /mcp/oauth/connect/redeem     │ (login via Internet Identity;
POST /mcp/oauth/token              │  issuer https://mcp.example.com/mcp)
POST /mcp/oauth/register          ─┘
GET  /.well-known/oauth-authorization-server/mcp   (+ root + /mcp/.well-known/… alternates)
GET  /.well-known/oauth-protected-resource/mcp     (+ root fallback)
GET  /.well-known/ii-auth-callbacks                (origin-global, all instances)
```

Several instances share one origin by giving each its own `McpServer` (one
shared `SharedClients`, one `auth_callbacks_router` over all of them) — exactly
what the bundled binary does on staging, serving production Internet Identity at
`/mcp` and beta at `/mcp-beta` (see below).

### Metrics (`imcp2::metrics`)

Prometheus instrumentation, usable from the library (the `prometheus` crate at
the version `dfinity/ic` pins). **The registry belongs to the caller**:
`Metrics::new` registers into a `Registry` you supply — exposition stays your
job, and there is no `render` here.

```rust
let registry = prometheus::Registry::new();          // or the host's own
let metrics = imcp2::metrics::Metrics::new(
    &registry, version, commit, started_at, &[&server])?;
let app = app
    .layer(axum::middleware::from_fn_with_state(
        metrics.clone(), imcp2::metrics::write_request_metrics))
    .layer(axum::middleware::from_fn(imcp2::metrics::write_request_logs));
// in your exposition path (or on a timer): metrics.refresh().await
```

Published as `imcp2_*`: request counts and a latency histogram (`route` and
`method` labels are bounded — a label an outsider picks is a memory-exhaustion
primitive; see the module docs), `live_sessions` / `active_sessions` per II
instance (labelled `ii_instance`, because Prometheus's own `instance` target
label renames a colliding exposed one to `exported_instance`), `build_info`, and
process start time. `register_process_collector(&registry)` adds CPU/RSS/fd
separately — un-namespaced `process_*` belongs to the application, not the crate.

The bundled binary serves `/metrics` only when `$MCP_SERVE_METRICS` is set: the
native deployment sets it and has Caddy hide the path publicly; a PaaS deployment
from the bundled `Dockerfile` has no proxy in front and leaves it off.

## Tools

Every tool declares an MCP `outputSchema` and, on success, attaches
**structured content** — a machine-readable object matching that schema —
alongside the human-readable text, so a model knows the expected shape of each
reply. The text is always present; the structured object is attached whenever
the reply serializes to an object (which the schema guarantees for normal
results).

| Tool | Args | Returns |
|------|------|---------|
| `open_app` | `app` (name **or** URL) | **One-call entry point** when a user names/links an app: resolves the Internet Identity `derivation_origin` *and* discovers the canisters behind it, together. A name or bare host is matched to the known-app registry first (so a wrong-TLD guess repairs to the canonical URL); an explicit `https://` URL is resolved as given. An unknown bare name, or a URL with no IC evidence, is *refused* (never guessed). Also probes the app's own canisters and reports per-canister `oql`/`api_doc_available` capability flags plus a caller-gated data-access note (which canister holds the app data, and the origin to read it as the user). Wraps `resolve_app` + `discover_app_canisters`; no auth |
| `discover_app_canisters` | `domain` | Canister ids behind a web domain — app-declared App Connect metadata first (`/ai-connect.html`'s `ic:canister-id` meta, `/.well-known/ic-app.json` manifest), then the frontend via `x-ic-canister-id` and backend candidates via `/env.json` + JS-bundle mining — each with provenance, its IC dashboard label/type where known, and (for the app's own canisters) `oql`/`api_doc_available` capability flags from a one-shot Candid probe |
| `icp_find_canister_by_name` | `query` | Canister ids matching a name/symbol, searched in the IC dashboard's service registries — ICRC token ledgers (e.g. `ckUSDC`) and the SNS project catalog |
| `icp_find_app_by_name` | `name` | A well-known app's front-end URL + `derivation_origin`, for a small built-in set of well-known IC apps (e.g. NNS). The **first stop** whenever only an app *name* is known — never guess a domain from a name. Any other name returns no match and a `note` directing a web search for the app's URL (there's no on-chain name→URL directory) |
| `icp_lookup_canister_info_by_id` | `canister_id` | What a canister IS, per the IC dashboard: label/name, type, controllers, subnet, module hash, latest upgrade proposal |
| `get_canister_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text), plus two capability flags: `oql` (`true` when it exposes an OQL query surface — a `schema` + `execute` pair — with a pointer to `icp_oql_guide`) and `api_doc_available` (`true` when it declares a `getApiDoc`/`get_api_doc` method, gating `get_canister_api_doc`) |
| `get_canister_api_doc` | `canister_id` | The canister's own prose API guide ("how this app behaves" — units, auth, lifecycle, mutation safety, polling, gotchas), from its `getApiDoc`/`get_api_doc` method. Call **only** when `get_canister_candid`/`open_app` report `api_doc_available`. Returns a **structured** result in every case — `available` + the doc on success, else `available:false` with `expected`/`retry`/`next` so an expected absence is distinct from an unreachable canister |
| `canister_query` | `canister_id`, `method?` **or** `oql?`, `args?` (textual Candid), `derivation_origin?`, `account?`, `candid?` | READ a canister — provide EITHER a Candid `query` `method` (with `args`) OR an `oql` query (a JSON object string, run against `execute`). A Candid `method` query may be anonymous or as your account and returns textual Candid; an `oql` query **requires** `derivation_origin` and returns `columns` + `rows` (a table) with `has_more`, validating `start` against the schema on an empty result. On an OQL canister a Candid `method` query is rejected — use `oql`. `candid` is a fallback: the `.did` interface text to encode/decode against when the canister exposes no `candid:service` metadata. Echoes `derived_for_origin` / `requested` / `acted_as_principal` |
| `canister_update_call` | `canister_id`, `method`, `args` (textual Candid), `derivation_origin?`, `account?`, `candid?` | Make an UPDATE (state-changing) call; reply as textual Candid; anonymous, or as your account at an app (identified by its canonical II `derivation_origin`, obtained once from `open_app`/`resolve_app`). **Financial transactions are refused**: the ICRC-standard transfer/approval methods (ICRC-1/ICRC-2 and the ICRC-4/-7/-37 equivalents) are disallowed on every canister, and the ICP and cycles ledgers' own value-moving methods (the legacy `transfer`, `withdraw`, the `create_canister` spends) on those ledgers, to protect the user — the refusal directs the user to act themselves — in a wallet they control (e.g. [oisy.com](https://oisy.com)), or, for canister creation, with the [icp CLI](https://github.com/dfinity/icp-cli) in their own terminal. `candid` is the same `.did` fallback as on `canister_query`, used when the interface isn't published on-chain. Echoes `derived_for_origin` / `requested` / `acted_as_principal` |
| `get_app_principal` | `derivation_origin`, `account?` | The principal you act as at an app, without a call. Identify the app by its `derivation_origin` (from `open_app`/`resolve_app`). Echoes `derived_for_origin` / `requested` so an origin mismatch is visible |
| `list_app_accounts` | `derivation_origin` | The user's Internet Identity accounts at an app — the default account plus any named ones — with name, number, last-used, and the derivation origin they were listed for. Identify the app by its `derivation_origin` (from `open_app`/`resolve_app`) |
| `resolve_app` | `app_url` | Resolve an app URL to its Internet Identity derivation context: `application_origin`, the `derivation_origin` to use (declared in `/.well-known/ic-app.json`, else a built-in known-app value, else assumed = app origin — flagged via `derivation_origin_source`: `declared`/`known`/`app_url_default`, with `application_is_ic` echoing the gateway evidence), and the app's `alternative_origins` (informational). An origin with **no IC evidence** that would need the `app_url_default` assumption is **refused** (guessed-domain guard, with a "did you mean" repair when the host resembles a well-known app). Does not return a principal (no account chosen) or require auth — pass the `derivation_origin` to `get_app_principal`/`list_app_accounts` |
| `icp_list_skills` | — | The official [IC skills](https://skills.internetcomputer.org) (Motoko, mops/icp CLIs, cycles, stable memory, security, …), grouped by category |
| `icp_get_skill` | `name` | The full `SKILL.md` instructions for one skill (e.g. `writing-motoko`, `icp-cli`, `cycles-management`) |
| `icp_oql_guide` | — | The OQL query-surface dialect guide (for canisters where `get_canister_candid` reports `oql: true`): the JSON query object, predicate grammar, edges, and paged result shape. The entity/field names come from `get_canister_oql_schema` and queries run through `canister_query` (the `oql` argument) |
| `get_canister_oql_schema` | `canister_id`, `derivation_origin`, `account?` | The canister's OQL schema catalogue (entities, primary keys, fields, edges) as JSON — wraps its `schema` method — plus a ready-to-run `canister_query` example per entity. **`derivation_origin` is required**: the schema is caller-gated, so an anonymous read is rejected (for now) with guidance, rather than returning an empty list |
| `icp_cycles_balance` | — | Your cycles-ledger balance and management principal — the principal to add as a controller (via the icp CLI) so the management tools can operate canisters you create |
| `icp_create_canister` | `cycles?` / `icp?` | **How to** create + fund a new canister: returns `icp` CLI steps for the USER to run themselves (create, fund, and add your management principal as a controller) — executes nothing and moves no funds |
| `icp_install_code` | `canister_id`, `wasm_base64` / `wasm_hex`, `mode?`, `arg?` | Install/reinstall/upgrade a Wasm module (single-shot, or via the chunk store for large modules) |
| `icp_canister_status` | `canister_id` | Run state, cycle balance, module hash, memory, controllers, allocations |
| `icp_update_canister_settings` | `canister_id`, `controllers?`, allocations, `freezing_threshold?`, `log_visibility?`, … | Update a canister's settings |
| `icp_start_canister` / `icp_stop_canister` / `icp_uninstall_code` / `icp_delete_canister` | `canister_id` | Canister lifecycle |
| `icp_top_up_canister` | `canister_id`, `cycles?` / `icp?` | **Instructions only — nothing is executed and no funds move.** Returns the step-by-step [`icp` CLI](https://github.com/dfinity/icp-cli) commands — including where to get the CLI — for the user to add cycles to a canister themselves; `cycles`/`icp` are substituted into the printed commands. Provided for completeness, to reflect the platform capability |

`open_app` (its `app` argument takes a name **or** a URL) is the one-call entry point
when the user names or links an app: it resolves the Internet Identity
`derivation_origin` **and** discovers the
canisters behind the app together (see [Typical flow](#typical-flow)).
`discover_app_canisters` is the canister-only path underneath it, used directly
when you already have the app's domain or URL (its `domain` argument accepts
either) and only need the canister ids. Its sources are listed in the table row
above (app-declared metadata first, then the `x-ic-canister-id` frontend header,
then backend candidates mined from `/env.json` + the JS bundle); among the mined
candidates, pick by label, prefer production/`IC_` ids, and confirm with
`get_canister_candid`.

### Typical flow

Acting **for the user** at an app:

0–2. **`open_app(name-or-URL)`** — the one-call entry point. Pass the *name* the user
   said (well-known apps, e.g. NNS, resolve offline) or a URL you have (e.g.
   `https://opencloud.org`); it returns the `derivation_origin` **and** the app's canisters in one shot
   (it runs `resolve_app` + `discover_app_canisters` concurrently under the hood).
   **Never guess a domain from a name** — a lookalike like `<name>.com` is an
   unrelated or squatted site. The tool enforces this: a bare *unknown* name is
   refused (find the real URL — web-search or ask the user), and a URL that resolves
   to `app_url_default` while showing **no IC evidence** (no valid `x-ic-canister-id`
   gateway header, no `ic-app.json` derivation origin) is refused too; when the host
   resembles a known app the error names it and gives the real URL (a
   "did you mean" repair). For a single step, the narrower tools remain:
   **`icp_find_app_by_name`** (name→URL only), **`resolve_app(url)`** (origin only),
   **`discover_app_canisters(url)`** (canisters only).
3. **`list_app_accounts`** — if there's more than one account, ask which to use (and
   remember it).
4. **`get_app_principal`** — only when you need the principal *value* itself;
   `canister_query` / `canister_update_call` act as the account without pre-fetching it.
5. **`get_canister_candid`** to learn the interface — its `oql` flag says whether OQL
   is available, its `api_doc_available` flag whether to call **`get_canister_api_doc`**
   (call it only when that's true). For an OQL canister, get the entity/field names
   from **`get_canister_oql_schema`** (pass the `derivation_origin`).
6. **Read** with `canister_query`: use the `oql` argument when OQL is available,
   passing the `derivation_origin` — an OQL read **requires** it (an anonymous per-app
   read is rejected for now, and a Candid `method` query is rejected on an OQL
   canister). Otherwise pass a Candid `method`.
7. **Act** with `canister_update_call`, passing `derivation_origin` + `account`
   to act as the user.

Genuinely public reads via a `canister_query` Candid `method` query or the
public-metadata tools (`get_canister_candid`, `discover_app_canisters`) skip steps
3/4 and need no origin; OQL reads always require one. The per-canister inspection (5) is
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

Discovery fetches are **SSRF-hardened** (CWE-918). Only `https` URLs with a real
host are fetched, and every outbound fetch runs under a redirect guard (a 3xx may only
go to a **globally-routable** IP or the same host, never a different private
target; capped at 10 hops) with per-body and aggregate size caps, so a hostile or
accidental large body can't exhaust memory. The untrusted **user-supplied** site
fetches (an app origin from `discover_app_canisters`, `open_app`, or `resolve_app`)
additionally resolve the target host up front and **pin** the connection to that
validated globally-routable address, so a name resolving to a
private/loopback/link-local address is refused and re-resolution can't rebind
mid-flight. Fixed public-host enrichment (the IC dashboard, the skills registry)
uses the redirect guard but is not separately address-pinned. No JavaScript is
executed, and every extracted id is validated as a principal.

The optional top-level **`derivation_origin`** is the app's declaration of the
Internet Identity derivation origin its frontends pin (see the identity section
above). It is the only authoritative way for `open_app` / `resolve_app` to learn a
**custom** derivation origin from an app URL — there is no reverse lookup from an app URL to it —
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

`canister_query` and `canister_update_call` run anonymously by default; pass a
`derivation_origin` to call as
your account at that app. The server mints a **short-lived account delegation on
demand** using the connection's registered Internet Identity session key (see
[Domain identities](#domain-identities-on-demand)) — there is no per-app sign-in
step. `get_app_principal` returns that account's principal
without a call. A user may hold several accounts at an app — a default account
everyone gets automatically (the anchor's current, user-controllable default at
that origin), plus any they have named — so `list_app_accounts` lists them (via II's
`get_accounts`), and `canister_query`/`canister_update_call`/`get_app_principal`/`list_app_accounts` identify the
app by its `derivation_origin` (obtained once from `open_app`/`resolve_app` — see the
note below), and take an optional `account` (a name from that list) to act as a
specific one; omit it for the default account. All these tools require a bearer
token (see Auth).

> **The derivation origin is explicit — and echoed.** Internet Identity derives
> the per-app principal from a **derivation origin**, which is *usually* but **not
> always** the visible website URL: an app can pin a *custom* derivation origin
> (via `derivationOrigin` + `/.well-known/ii-alternative-origins`) that browsers
> honour. The identity-bearing tools (`canister_query`, `canister_update_call`,
> `get_app_principal`, `list_app_accounts`)
> therefore take the derivation origin **explicitly** as `derivation_origin` (the
> exact canonical origin — never inferred from an alternative-origins list, which is
> the *inverse* relation), and **only** that — they do **not** accept a raw website
> URL. A derivation origin is a *stable per-app value*, so you **resolve it once**
> and reuse it: `open_app` (or `resolve_app`) turns an app name/URL into it and
> reports how — `derivation_origin_source`: **declared**
> (`/.well-known/ic-app.json` → `derivation_origin`), else a built-in **known-app**
> value for a few apps that pin a custom origin without declaring it (e.g. NNS →
> `https://nns.ic0.app`; an app's own
> declaration always overrides this), else the app origin *assumed*
> (**app_url_default**). Feeding that resolved origin to an identity tool records
> `derivation_origin_source` = **explicit**. Every identity result echoes
> `derived_for_origin` (the origin actually used) alongside `requested` (what you
> passed), so a canonicalization mismatch is **immediately visible**. Why not accept
> a URL directly on every tool? Because the server is **stateless** — resolving a
> URL costs a network round-trip each call, and the derivation origin never changes
> per-app; forcing a single up-front `open_app`/`resolve_app` avoids re-resolving on
> every invocation and gives the agent **one** way to identify an app. The
> **guessed-domain gate** lives at that resolution step: `open_app`/`resolve_app`
> *refuse* an `app_url` whose `app_url_default` assumption would apply while the
> origin shows **no IC evidence** — the gateway's `x-ic-canister-id` header (a valid
> canister principal, from the origin itself, not a redirect target; checked on the
> manifest response, else the origin root) — since that's the signature of a domain
> **guessed** from an app name (a lookalike/squatted site), and the refusal names
> the well-known app the host resembles when there is one. A genuinely non-IC-hosted
> app that uses Internet Identity can still be targeted deliberately by passing its
> origin as `derivation_origin` (which is trusted verbatim, ungated). Under the hood
> the origin goes through the same canonicalizer the delegation path uses (bare
> `https://<host>`, with the `*.icp0.io`/`*.icp.net` → `*.ic0.app` gateway remap
> below). For backward compatibility the identity tools still accept the legacy
> parameter name `domain` as an alias for `derivation_origin`.

### Skills awareness

`icp_list_skills` / `icp_get_skill` expose the official Internet Computer
[skills](https://skills.internetcomputer.org) — authoritative, current how-to
guides for authoring and shipping IC apps (the Motoko language, the `mops` and
`icp` CLIs, cycles management, stable memory & upgrades, canister security,
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
traversal). `get_canister_candid` detects the pair and reports `oql: true`, parsing
the interface behind the same **CWE-674 guard** the encode/decode path uses. That
guard is a pre-parse structural check that rejects textual Candid over 1 MiB or
nested past 128 levels before the parser runs, so a malicious input can't
stack-overflow and abort the whole process, taking every concurrent session with
it; it covers the textual-Candid inputs (tool `args`, `.did` interfaces, and
install `arg`), and is fail-closed, so a malformed `.did` degrades to `oql: false`.
The same ceiling is enforced past the parser on the untrusted structures
themselves: type-alias chains in a fetched interface are depth-bounded during
resolution, and the type-less reply decode/render path is depth-bounded too, so
a hostile canister's `.did` or reply can't recurse the decoder even when each
individual layer is small.
The OQL query path is JSON rather than Candid, so it shares the same 1 MiB size cap
but is parsed by the JSON parser, not this structural guard. Rather than inline the
whole dialect into every interface read, `get_canister_candid` emits only that flag plus a
one-line pointer; the full guide is served on demand by `icp_oql_guide` and as
the `oql://usage` MCP **resource**.

Two tools drive the surface: **`get_canister_oql_schema`** returns the entity/field
catalogue (wrapping the `schema` method), and **`canister_query`** takes the query in
its `oql` argument as a plain JSON object string, wraps it as `execute`'s single
`text` argument (so the model never hand-escapes JSON inside a Candid literal), and
decodes the reply into `columns` + `rows` — rendered as a markdown table, with
`has_more` for paging. Both **require** a
`derivation_origin` (with an optional `account`) to query as the user's account —
the schema and rows are caller-gated, so an anonymous per-app read is **rejected**
(for now) with guidance to pass the origin rather than silently returning empty
(same on-demand delegation as a `canister_query` Candid `method` query, which stays
permissive so genuinely public canisters can still be read anonymously). Because OQL
is the preferred read path when a canister offers it, a Candid `method` **query**
through `canister_query` is rejected on an OQL canister (it returns a pointer to the
`oql` argument); `canister_update_call` then handles that canister's update calls.
Detection stays name-based and the decode is fail-closed: a
reply that isn't a recognizable OQL result degrades to the raw Candid rather than
erroring. The design mirrors the reference IC connector's OQL primer (detect +
teach), adding an ergonomic executor suited to this server's structured-output
conventions.

### Creating & managing canisters

The management tools let the agent act **on chain as your standing Internet
Identity principal** — a stable per-connection identity (the one returned when you
authenticate, printed by `icp_cycles_balance`).

**Creation and top-ups are instructions-only.** `icp_create_canister` and
`icp_top_up_canister` execute nothing and move no funds: each returns the
[`icp` CLI](https://github.com/dfinity/icp-cli) steps (including where to get
the CLI) for the user to run the operation themselves, in their own terminal,
with keys they control. The tools exist for completeness — to reflect the
Internet Computer platform capabilities — not to perform the operations on the
user's behalf. The creation steps end with `icp canister settings update …
--add-controller <PRINCIPAL>`: adding the management principal as a controller
is what lets the connector's lifecycle tools operate the new canister.

Lifecycle calls
(`icp_install_code`, `icp_canister_status`, `icp_update_canister_settings`,
`start`/`stop`/`uninstall`/`delete`) go to the management canister (`aaaaa-aa`)
with the effective canister id set to the target. `icp_install_code` takes the
compiled Wasm as base64/hex and uploads it via the chunk store automatically when
it exceeds the single-message limit.

Together these make the end-to-end flow work: *"create a Motoko canister that does
X and deploy it"* → the agent reads the relevant skills, writes and **builds** the
Wasm in its own environment, the user creates and funds the canister with the
`icp` CLI (`icp_create_canister` prints the exact steps), then `icp_install_code`
puts the Wasm on chain. (Compiling Motoko/Rust to Wasm happens in the agent's
environment, not in this server.)

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

> II's consent screen makes you choose an access level: **"Questions only"** or
> **"Actions & questions"**. Choose **Actions & questions** if you want to create
> or manage canisters — a Questions-only session makes every management tool
> inert (see [Read-only sessions](#read-only-sessions) below).

## Run

```bash
cargo run
# serves http://0.0.0.0:8000  (MCP at /mcp against production II, OAuth under it, info page at /)
# honours $PORT (default 8000), $PUBLIC_URL (default http://localhost:8000),
# $MCP_SERVE_BETA (set it to also serve the beta II instance at /mcp-beta, for staging),
# and $MCP_SERVE_METRICS (set it to serve the Prometheus exposition at /metrics)
```

`GET /` serves a self-contained, ICP-styled landing page that names the
production `/mcp` endpoint (staging also serves beta II at `/mcp-beta`) and lists
the tools grouped by purpose. `GET /version` is the operations probe (see [Auth](#auth-oauth-21-login-via-internet-identity)).

The binary also serves the official pages the connector directories require:
`/privacy-policy` (linked from the landing page's footer), `/support`, and
`/terms` — self-contained documents compiled in like every other asset. For the
OpenAI directory's domain-verification check, `GET
/.well-known/openai-apps-challenge` returns `$OPENAI_APPS_CHALLENGE_TOKEN`
verbatim as `text/plain` (trimmed), and 404s while the variable is unset or
blank — so the endpoint is inert except during a submission window.

## Deploy

The deployment binary is **self-contained**: the connect/landing HTML, CSS, and SVG
(`src/assets/`) and the reference docs (`static/`) are compiled in with `include_str!`,
so nothing has to ship next to it (both are build-time inputs only). The
only runtime file is the OAuth clients store, which the server always uses: it reads
the file on startup and writes it (best-effort) as client registrations change, so
give it a writable directory. imcp2 creates its operational files in
`IMCP2_STATE_DIR` (the clients store at `<dir>/oauth-clients.json`); it defaults to
the working directory. On `SIGTERM` (what
`systemctl stop`/`restart` sends) or `SIGINT`, the server drains in-flight requests
before exiting, so a redeploy doesn't cut off calls mid-flight. Two requirements
when hosting:

- **HTTPS** — the id.ai passkey (WebAuthn) only works in a secure context.
- **`PUBLIC_URL`** — set it to the public https URL; it's used in the OAuth
  discovery documents, the sign-in redirect/callback, and the allowed-Host list.
  (II derives the MCP server origin from the connect callback, and each user
  must add this exact origin as their trusted MCP server in II Settings — there
  is no longer a deploy-time `mcp_server_origin` on II's side.)
- **`OAUTH_REQUIRE_RESOURCE`** — strict RFC 8707 resource indicators, **on by
  default**: both OAuth legs require a `resource` naming this server, so a token
  can never be minted for (and replayed from) a different MCP server. Set it to a
  falsey value (`0`/`false`/`no`/`off`) only if you must serve a client too old to
  send `resource`; that reopens the confused-deputy path for such clients, so
  prefer updating the client.

A `Dockerfile` is included (works on Render / Fly / Cloud Run / Koyeb). The
reference deployment (`deploy/native/`, see its README) instead runs the binary
and Caddy as native systemd units: pushes to `main` auto-deploy staging, and
`release-*` tags deploy production, attaching the deployed binary to the GitHub
release. For a
zero-signup public URL during testing, expose the local server with a tunnel:

```bash
cargo run &                                   # local server on :8000
cloudflared tunnel --url http://localhost:8000   # prints https://<name>.trycloudflare.com
# restart the server with PUBLIC_URL set to that URL:
PUBLIC_URL=https://<name>.trycloudflare.com cargo run
```

## Probe it (curl)

The MCP endpoint is bearer-gated (see Auth), so tool calls need an OAuth-capable
MCP client — but the discovery surface and the auth handshake are probeable:

```bash
# OAuth discovery documents (path-inserted; root fallbacks also served)
curl -s http://127.0.0.1:8000/.well-known/oauth-authorization-server/mcp | jq
curl -s http://127.0.0.1:8000/.well-known/oauth-protected-resource/mcp | jq
curl -s http://127.0.0.1:8000/.well-known/ii-auth-callbacks | jq

# Unauthenticated MCP calls answer 401 with the RFC 9728 challenge clients
# use to find the authorization server:
curl -si -X POST \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
  http://127.0.0.1:8000/mcp | grep -i www-authenticate
# -> WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource/mcp"
```

Once you hold an access token (run the OAuth flow from an MCP client, see
[Connect](#connect-from-an-mcp-client)), you can call a tool directly. The service
runs **stateless** with plain-JSON responses: each POST is handled independently
(no `initialize` handshake and no `Mcp-Session-Id`), and a `tools/call` returns a
single JSON-RPC object, not an SSE stream. The POST handler still requires the dual
`Accept` header.

```bash
TOKEN=mcp-token-…   # from the OAuth flow (client -> Internet Identity sign-in)
H=(-H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN")

# anonymous public read from a real mainnet canister (ICP ledger); pass
# derivation_origin to call as your account at an app instead
curl -s "${H[@]}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canister_query","arguments":{"canister_id":"ryjl3-tyaaa-aaaaa-aaaba-cai","method":"icrc1_name","args":"()"}}}' \
  http://127.0.0.1:8000/mcp | jq -r '.result.content[0].text'
# => ("Internet Computer")
```

## Auth (OAuth 2.1, login via Internet Identity)

`/mcp` is gated by a bearer token, with login via Internet Identity's
**registration-delegation** connect handshake. II's `/mcp` handshake logs the user
in and navigates the browser back to a **pinned callback page** on our origin,
carrying a canister-signed delegation in the URL fragment. We bridge that to a
single **authorization-code + PKCE** flow, so any OAuth 2.1 client works:

- `/mcp/oauth/authorize` validates the client + redirect and PKCE, sets a
  **browser-binding cookie** (see below), and redirects to II's handshake, carrying
  this connect's registration public key `pub(X)` in the link fragment
  (`registration_key`). II certifies a short-lived, two-hop delegation chain and
  navigates the browser back to our pinned callback page (`GET
  /mcp/oauth/connect/callback`) with the chain in the fragment. That page POSTs the
  chain (with the cookie) to `/mcp/oauth/connect/redeem`, which redeems it (one
  `mcp_register_v2` call), mints a PKCE-bound code, and returns the client
  `redirect_uri?code=…&state=…` for the page to navigate to.

The **RFC 8628 device grant was dropped**: no listed MCP client uses it, and it
adds a device-code phishing surface with none of the PKCE binding the rest of the
flow relies on.

Endpoints:

The production instance is mounted at `/mcp` (the origin's default instance), so
its AS issuer is `<PUBLIC_URL>/mcp` and everything OAuth lives under it:

- `GET /.well-known/oauth-authorization-server/mcp` — AS metadata (RFC 8414
  path-inserted; also served at the OIDC-style `/mcp/.well-known/…` alternate
  and, for this default instance, at the plain root; advertises
  `grant_types_supported: ["authorization_code"]`)
- `GET /.well-known/oauth-protected-resource/mcp` — points clients at the AS
  (RFC 9728 §3.1 path-inserted; root fallback also served)
- `POST /mcp/oauth/register` — dynamic client registration (RFC 7591); `redirect_uris`
  are stored and persisted to `oauth-clients.json` in `IMCP2_STATE_DIR` (a bounded,
  LRU-evicted store — see [Bounded state](#bounded-state-memory--disk)); requested `grant_types` are
  honoured (intersected with `authorization_code`). A **hosted** `redirect_uri` is
  rejected unless its host is on the allow-list (see the Companion-control note
  below); loopback redirects are always accepted.

- `GET  /mcp/oauth/authorize` — validates the client + redirect, requires PKCE, sets
  the binding cookie, then redirects to II's handshake (with `registration_key`)
- `GET  /mcp/oauth/connect/callback` — the **pinned callback page**: II navigates here
  with the delegation in the URL fragment; the page reads it client-side and POSTs
  it to the redeem endpoint (it is the sole fragment reader and reflects nothing
  into the DOM)
- `POST /mcp/oauth/connect/redeem` — redeems the fragment delegation (requires the
  binding cookie), binds the session key via `mcp_register_v2`, mints a PKCE-bound
  code, and returns the client `redirect_uri?code=…&state=…`
- `POST /mcp/oauth/token` — exchanges an authorization `code` (PKCE) for the access token

Registration is **proven synchronously**: redemption is a signed `mcp_register_v2`
that must return `Ok`. Unauthenticated `/mcp` requests get `401` with a
`WWW-Authenticate` header pointing at the resource metadata, as the MCP spec expects.

### Browser-facing error screens

`/oauth/authorize` and the pinned connect callback are **front-channel** endpoints
the user reaches in a browser, so any error they stumble upon during sign-in or the
II handshake renders as a **nicely formatted, on-brand screen** — an editorial
headline, a best-effort diagnostic ("your client may be out of date; remove and
re-add the connector", etc.), and always the line *"If this error is unexpected,
please contact mcp@dfinity.org to report it."* — rather than a raw JSON blob. The
shared shell lives in `src/assets/connect-error.html` + `src/assets/connect.css` (reused from
the connect callback page: same parchment grid, serif display, foot-of-page "Hosted
by" mark, light/dark theming) and is fully self-contained under a strict, nonce'd,
non-scripted, unframeable CSP that reflects no request value. Authorize errors
**content-negotiate**: a browser (`Accept: text/html`) gets the screen, a
programmatic OAuth caller keeps the RFC-style JSON error. Handshake/redeem failures
surface on the callback page, which reveals the same contact line once it enters its
error state. The dedicated allow-list rejection (below) is a distinct, actionable
screen: it names the concrete next step (request access) instead of the report line.
The **back-channel** endpoints (`/oauth/token`, `/oauth/register`, the `/mcp` bearer
gate) stay JSON — no browser ever lands on them.

### Consent-Bound Completion (split-browser injection defense)

The `state` in the II connect link is echoed back to the client in the final
redirect, so it **cannot by itself prove** that the browser redeeming at
`…/oauth/connect/redeem` is the one that started at `…/oauth/authorize` — nor that it
is the one that actually **consented** at II. Without a binding there's a
session-fixation takeover: an attacker registers a client (open DCR) with their own
`redirect_uri` + PKCE challenge, calls `…/oauth/authorize`, reads the II connect link
from the 302, and phishes it to a victim who already trusts this origin in II
Settings (II's consent screen names only the *origin*, never the OAuth client, so
nothing warns the victim). The victim consents; the attacker completes the flow and
redeems the code with their own PKCE verifier — a token acting as the victim. (An
initiator-only cookie does *not* close this: the attacker is the initiator, so it
holds the cookie.)

**The fix.** `…/oauth/connect/redeem` mints a code only when the requesting browser
presents **both** proofs, which can co-reside in one browser only in the legitimate
same-browser flow:

1. **initiator** — an unguessable `HttpOnly; SameSite=Lax` connect cookie
   (`mcp_connect`, scoped to the instance's `…/oauth` path; `Secure` whenever
   `PUBLIC_URL` is https, i.e. everywhere but plain-HTTP local development) set
   at `…/oauth/authorize`;
2. **consenter** — the canister-signed delegation chain, delivered by II *only* to
   the consenting browser as a URL fragment and *required* to redeem, so only the
   browser that drove the II consent holds it;
3. plus **proven** registration — redemption is a signed `mcp_register_v2` that
   must return `Ok`, so it is synchronous and on-chain, never a bare notification.

In the confused-deputy path the delegation lands in the honest pinned page in the
**victim's** browser, whose connect cookie does not match the one the connect (and its
registration key `X`) was bound to, so the redeem aborts. An attacker who initiates
then phishes the II link holds the cookie but never the delegation (it reaches only the
consenting victim's browser); the victim holds the delegation but never the cookie.
Neither can redeem. This closes the split-browser injection for **all transports
incl. loopback** (a loopback redirect resolves on the consenter's own machine).
`SameSite=Lax` still rides the top-level cross-site GET II uses to navigate back to
the callback page.

> **Companion control: the hosted-redirect allow-list.** The *same-browser* variant
> (a victim socially engineered into running the whole flow toward an
> attacker-registered **hosted** `redirect_uri`) is not closed by Consent-Bound
> Completion alone, since the victim's browser legitimately holds both proofs. It
> **is** closed by a **hosted-redirect allow-list**: dynamic client registration
> accepts only a loopback redirect, or a hosted redirect whose host is (a subdomain
> of) an allow-listed registrable domain **and** whose path falls within that
> vendor's pinned OAuth-callback prefix (percent-encoded slashes and dots in the
> path are rejected, so the prefix check cannot be dodged by encoding), so an
> attacker cannot register a hosted destination it controls. The path pin
> matters because several allow-listed
> origins also serve third-party, script-capable content on the same origin
> (`perplexity.ai/page/…`, `chatgpt.com/g/…`, `/share/…`); a domain-only rule would
> let an attacker register such a path and capture the code from on-origin JS.
> Pinning to the vendor's dedicated callback path keeps every registration on a
> vendor-controlled, non-user-content endpoint. The list is seeded with the known
> MCP connector vendors' callback paths and widened per deployment with
> `OAUTH_ALLOWED_REDIRECT_PREFIXES` (additive; each entry a full `https://host/path`
> URL prefix, a bare domain is refused); loopback/native clients are exempt (the code
> resolves on the consenter's own machine). No redirect (loopback or hosted) may
> carry a **query or fragment**: the authorization endpoint appends `?code=…&state=…`,
> so a pre-existing query would risk `code=…&code=…` parameter pollution, and a
> fragment is meaningless on a redirect target. Enforced at both `…/oauth/register` and `…/oauth/authorize`. A client
> turned away is pointed at a contact address to request approval:
> `…/oauth/register` says so in its JSON `error_description`, and a browser that
> reaches `…/oauth/authorize` gets an on-brand "not allowed" page (not a raw error)
> naming the same contact.

### The registration-delegation connect handshake

The connect flow never lets II bind a session key it was merely **shown**. Instead
it uses a **short-lived (~5 min), two-hop delegation chain `P_reg → Y → X`**
delivered to a **pinned callback page** as a URL fragment: II's canister signs
`P_reg → Y` toward an ephemeral key `Y` held only by II's frontend — so the piece
that transits the IC (replicas, boundary nodes, the public state tree) is inert on
its own — and the frontend extends it browser-side with a `Y`-signed hop to the
server's registration key `X`, assembling the redeemable chain only in the
consenting browser. The backend redeems it by signing **one** `mcp_register_v2`
call as `X`, binding the long-lived session key `S` to the anchor. II never binds a
bare key it was shown.

`/version` is the unauthenticated operations probe. It reports the running
build (`version`, `commit`, `built_at`, `started_at`), the served **II
pairings** (`instances`: each mount path with the II origin and canister it
hands off to — the only way an external monitor can learn the pairing, since
neither the mount path nor the server's origin implies it and the `II_URL*`
variables can move it), and two real-time
per-instance **session gauges** — `live_sessions` (open grants) and
`active_sessions` (a subset: those also requesting recently):

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

Session grants are also traceable in the logs (unit `imcp2`): a session logs
`session opened` (with `instance` and `session_id`) when its grant goes live,
and `session closed` when the grant expires and the per-instance reaper (60s
cadence) evicts it. These bracket what `live_sessions` counts, modulo the
reaper's cadence: the gauge drops the instant a grant expires, while the paired
`closed` log lands on the reaper's next sweep (up to 60s later), so `opened`
minus `closed` can momentarily exceed the gauge by the sessions expired since
that sweep. The same sweep logs `abandoned connects reaped` (with a `count`) for
sign-ins that were started but never completed — those never opened a session, so
they get no paired `closed` line. See
[Bounded state](#bounded-state-memory--disk) for everything the sweep covers.

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
instance's `{mcp_path}/oauth/connect/callback`), built from the same helper that
builds the II links' callback URLs so the two can never drift.

The wire shapes match the **merged II contract** (verified against the
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

Server side:

- **`X`, a per-connect registration keypair** bound to the connect cookie;
  `priv(X)` never leaves the backend, and `pub(X)` rides the II link
  (`registration_key`, base64url DER).
- **A pinned callback page** at `GET …/oauth/connect/callback` — the *sole* reader
  of the returned fragment. It reads `location.hash` client-side, POSTs it (with
  the connect cookie) to `POST …/oauth/connect/redeem`, and reflects nothing into
  the DOM; it ships a strict CSP (`default-src 'none'`, a per-response script
  nonce, `connect-src 'self'`).
- **Redemption** builds a `DelegatedIdentity` from `priv(X)` + the delegation and
  calls `mcp_register_v2` to bind the long-lived session key `S` to the anchor
  (which II recovers from `caller() == P_reg` — the server never names it).
  Registration is synchronous, so there is no separate liveness probe or polling
  page. The read-only level comes back on the `mcp_register_v2` reply (feeding the
  `require_write` guard).

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
> this merged shape. This also relies on the callback allow-list (an II-side
> validation) as its security precondition.

### Bounded state (memory + disk)

Every map the server keeps is capped, because two of the endpoints that fill them
are reachable **without authentication**: `POST /oauth/register` (open dynamic
client registration, which MCP clients require) and `GET /oauth/authorize` (which
mints a session with two Ed25519 keypairs per call). Left unbounded, a bare
request loop against either was an unauthenticated memory-growth primitive, and
registration additionally rewrote the whole persisted store on every call —
O(N²) disk I/O for N registrations. Each map now has an **admission bound**
(what caps it between sweeps) and a **reaper** (what returns the memory), and
none of them can be filled at the expense of an authenticated user:

| State | Cap | When full |
| --- | --- | --- |
| Client registrations (`POST /oauth/register`) | 10 000 | least-recently-used registration is evicted; every `/oauth/authorize` marks its client used, so a flood evicts its own unused entries first, and an evicted client re-registers (DCR is automatic) |
| Connects in flight (`GET /oauth/authorize`, one session + one pending-authz entry each) | 1 024 | oldest pending connect is evicted; sessions holding a live grant are never touched |
| Sessions overall | 20 000 | a **new connect is refused** (`503`, on-brand "server is busy, try again" screen) rather than evicting an authenticated user's live grant |
| Authorization codes | 4 096 | closest-to-expiry code is evicted (inserting one requires a completed II consent) |
| Access tokens | 20 000 | closest-to-expiry token is evicted |
| Per-app delegation cache, **per session** | 64 origins/accounts | entry nearest expiry is evicted (it would be re-derived anyway) |

The per-instance reaper (60s cadence — `spawn_session_reaper`, which a deployment
must call) drops expired grants, **connects abandoned mid-handshake** (a session
that never redeemed a grant, after 15 minutes), pending authorizations past their
10-minute TTL, unexchanged authorization codes, and expired access tokens.
Registrations are the one long-lived map: they must survive a restart, so they
are persisted — now on a coalescing background writer (at most one full write per
2s) instead of one full rewrite per registration.

Note the server itself does **no rate limiting**; these bounds cap what a flood
can cost in memory and disk, not the request rate. Put a rate limiter in front
(the reverse proxy) if you need that.

### Read-only sessions

II's consent screen requires an explicit access-level choice: **"Questions
only"** or **"Actions & questions"**. A user who picks Questions only gets a
session whose per-app delegations are `permissions = "queries"`,
and the IC **rejects update calls made through them at ingress**. That makes the
entire canister-management surface inert — `create`/`install`/`start`/`stop`/
`uninstall`/`delete`, and even `icp_canister_status`, are update calls. To handle this
without opaque low-level errors:

- The `mcp_register_v2` reply carries `permissions: "queries" | "all"`, so the
  server learns the level at connect without minting a probe delegation. A
  missing or unrecognized value leaves the level **unknown** (not assumed
  writable): the update is attempted and the IC's ingress rejection is the
  fallback signal.
- Management tools check it up front and, for a *known* read-only session, return
  an actionable *"reconnect with read-only off"* message instead of an ingress error.
- `get_app_principal` reflects a read-only session in its output, so the agent won't
  attempt updates it can't make.

**The server generates a fresh per-connection Ed25519 session key `S` and binds it
itself.** At connect redemption it signs one `mcp_register_v2(pub(S))` call as the
registration key `X` (see the handshake above), which binds `S` to the user's
anchor as a time-boxed grant. `priv(S)` never leaves the backend. The issued access
token is bound to the session key's principal
(`self_authenticating(session_pubkey)`), which is exactly the identity the grant is
bound to.

**PKCE (S256)** is required for the authorization-code flow; auth codes live 120s,
and the access token's lifetime **tracks the II grant** — it expires exactly when
the grant does, so the session duration the user picks on II's consent screen (10
minutes up to 30 days) is how long the client's token stays valid. Refresh tokens
remain a deliberate non-goal: with the token matched to the grant there is nothing
to refresh against — when the grant lapses, so does the token, and the client
re-runs the authorization-code flow. (If the grant expiration isn't known at issue
time, the token falls back to a 1h TTL; the grant is the hard ceiling at II either
way.) Treat any `Unauthorized` from II
as "session over → reconnect": the server surfaces a reconnect message and does
not retry.

Set the public base URL (used in the discovery docs, as the MCP origin, and as the
management identity's derivation origin) with `PUBLIC_URL`. The `/mcp` endpoint is
**production** Internet Identity: `II_URL_PROD` (browser login, default
`https://id.ai`) plus `II_CANISTER_ID_PROD` (the canister the `mcp_*` calls target,
default `rdmx6-jaaaa-aaaaa-aaadq-cai`); both point at the same II.

### Staging: beta instance (`/mcp-beta`)

The staging deployment exposes a second, fully isolated instance connected to
**beta** Internet Identity at `/mcp-beta`, opt in with `MCP_SERVE_BETA`
(`1`/`true`/`yes`/`on`). It is off by default, so a production deployment serves
`/mcp` alone. When served it has its own authorization server under
`/mcp-beta/oauth/*` (issuer `<PUBLIC_URL>/mcp-beta`, an RFC 8414 path issuer; AS
metadata at `/.well-known/oauth-authorization-server/mcp-beta` plus the
OIDC-style `/mcp-beta/.well-known/…` alternate, resource metadata at
`/.well-known/oauth-protected-resource/mcp-beta`). Configure the beta II with
`II_URL` (default `https://beta.id.ai`) and `II_CANISTER_ID` (default
`fgte5-ciaaa-aaaad-aaatq-cai`).

Sessions and tokens are per-instance (a `/mcp` token is not valid on
`/mcp-beta` and vice versa), while dynamic client registrations are shared
(they only pin redirect URIs). II trust is by origin, so users enable this
server's origin as their trusted MCP server in their **beta.id.ai** settings
(a separate identity from their production anchor).

## Domain identities (on demand)

There is no per-app browser sign-in. Instead the model is:

- **One registered session key per connection.** When you connect, the backend
  generates a per-connection Ed25519 **session key** and II's frontend registers
  it as a time-boxed grant bound to your anchor. The backend signs II's `mcp_*`
  calls directly with that key (its principal `self_authenticating(session_pubkey)`
  is what the grant is bound to). Reconnect when the grant expires or is revoked.
- **App delegations minted on demand.** When `canister_query` / `canister_update_call` (or `get_app_principal`)
  is invoked with a `derivation_origin` (resolved once via `open_app`/`resolve_app`), the backend mints a **short-lived
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
  `*.icp0.io` / `*.icp.net` → `*.ic0.app`. `target_origin` replicates only II's
  *domain-based* derivation: a raw `derivation_origin` is canonicalized and used
  verbatim, with no recovery of a custom derivation origin from it. When an
  `app_url` is passed instead, `resolve_app` resolves the derivation origin by
  precedence **declared** (`/.well-known/ic-app.json` `derivation_origin`) >
  built-in **known-app** registry > application origin, so a custom origin an app
  declares (or that ships in the registry, e.g. `oisy.com`) **is** honoured, and
  the app's `/.well-known/ii-alternative-origins` list is fetched and surfaced by
  `resolve_app` (see the caveat under [Tools](#tools)). The one genuine limitation:
  there is no reverse lookup from an app URL to a custom origin the app has not
  declared.
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
`canister_query`/`canister_update_call`/`get_app_principal` as `account`; the server resolves the name to its
`account_number` via `mcp_get_accounts` and threads that into the on-demand
delegation. Omitting `account` uses the default account.

> **Status:** the connect handshake and the `mcp_register_v2` / `mcp_get_accounts` /
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
- [x] OAuth 2.1 auth (authorization-code + PKCE): II's `/mcp` **registration-delegation**
      handshake binds the connection's session key (a fragment-delivered, canister-signed
      delegation redeemed via `mcp_register_v2`), with **Consent-Bound Completion** binding
      `…/oauth/connect/redeem` to both the initiator (`mcp_connect` cookie) and the consenter (the
      fragment delegation); expiring tokens. The same-browser phishing variant is closed
      by a hosted-redirect allow-list (see Auth). (The RFC 8628 device grant was dropped.)
- [x] On-demand **domain identities**: the registered session key mints per-app
      account delegations directly via II canister methods
      (`canister_query`/`canister_update_call`/`get_app_principal` `derivation_origin`); no per-app browser flow.
- [x] **Per-app accounts**: `list_app_accounts(derivation_origin)` lists the user's accounts at
      an app (via `mcp_get_accounts`), and `canister_query`/`canister_update_call`/`get_app_principal` take an
      `account` name to act as a specific (non-default) account.
- [ ] Deploy the `mcp_register_v2` + `mcp_get_accounts` + `mcp_prepare_delegation` +
      `mcp_get_delegation` canister methods (server is built against the merged II
      candid contract; the live round-trip lands with the II side).
- [ ] Persist sessions/delegations (currently in-memory, lost on restart).
- [ ] Scoped delegations / per-call confirmation for sensitive methods.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright © DFINITY Stiftung.

## Contribution mode

This repository is **public but closed to external code contributions**: pull
requests from outside the DFINITY organization are not merged (and may be closed
automatically). **Bug reports and suggestions are welcome** — please open an
[issue](../../issues).

If this repository is later opened to external contributions, contributors will
be required to sign the [DFINITY CLA](https://github.com/dfinity/cla/), and this
section will be updated accordingly.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build and test the project, and
[SECURITY.md](SECURITY.md) for reporting security vulnerabilities. Participation
is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
