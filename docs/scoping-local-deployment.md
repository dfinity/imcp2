# Scoping: a secondary MCP server instance for local deployments

Status: **draft / scoping** — no code changes proposed here yet, only the
analysis and the design that an implementation PR would follow.

## 1. Goal

Today IMCP2 bridges an LLM to **mainnet**. This document scopes a second server
instance that bridges the same tools to a **local `dfx` replica** — so a
developer building canisters/apps locally can point an MCP client (Claude,
ChatGPT, Grok, …) at their own machine and use `open_app`, `canister_query`,
`canister_update_call`, canister management, and per-app Internet Identity
accounts against `http://localhost:4943` instead of `https://icp-api.io`.

The headline finding: **the server is already factored to make this mostly a
composition change, but four mainnet assumptions are hard-coded and would each
break a local instance.** The bulk of the work is (a) an agent bootstrap that
fetches the local root key, (b) a strictly-scoped relaxation of the discovery
SSRF/https guards, (c) local-aware origin canonicalization, and (d) a local
canister-creation path. Each is small; the care is in making sure none of them
can ever weaken the mainnet instances.

## 2. How the server is composed today

The crate is both a library and a binary (`Cargo.toml`, `src/lib.rs`,
`src/main.rs`).

- **`McpServer`** (`src/lib.rs`) is one server instance built from an
  **`McpConfig`**: an injected `ic-agent::Agent`, an **`IiInstance`** (which
  Internet Identity to log users in against), the public URL, the mount path,
  and a shared dynamic-client-registration store.
- **`main.rs`** composes **two** instances into one process:
  `/mcp` → **beta** II and `/mcp-prod` → **prod** II. Both are handed the
  **same** agent, built once as
  `Agent::builder().with_url(IC_URL).build()` where
  `IC_URL = "https://icp-api.io"` (`src/lib.rs:100`, `src/main.rs:85`).
- **`IiInstance`** (`src/identities.rs:106`) carries only *which II* — an origin
  and a canister id. `beta()` → `https://beta.id.ai` /
  `fgte5-ciaaa-aaaad-aaatq-cai`; `prod()` → `https://id.ai` /
  `rdmx6-jaaaa-aaaaa-aaadq-cai`. Both are already env-overridable
  (`II_URL`/`II_CANISTER_ID`, `II_URL_PROD`/`II_CANISTER_ID_PROD`).
- **Tools** (`src/tools.rs`) sign anonymous calls with the injected agent and
  mint per-app account delegations on demand from the connection's registered
  session key (`src/identities.rs`). Every identity-bearing agent is
  `self.agent.clone()` with the identity swapped
  (`Identities::agent_as`, `src/identities.rs:457`), so **whatever endpoint the
  injected agent points at is the endpoint every tool call rides** — anonymous
  reads, II delegation calls, and canister management alike.

### The key insight: two different axes

The existing beta/prod split varies along exactly one axis — **which mainnet
Internet Identity**. Both instances still talk to the **same replica**
(mainnet) through the **same agent**.

"Local deployment" varies along a *different* axis — **which replica**. That
difference is what cascades into the hard-coded assumptions below, because the
agent endpoint, the root key, the app origins, and the system canisters all
change together when you move off mainnet. A local instance is therefore not
"beta/prod plus a third II"; it is "a different agent + a local II + relaxed
guards," which is why it deserves its own scoping rather than another
`IiInstance::…()` constructor.

## 3. Gap analysis — what breaks against a local replica

Each item below is a concrete mainnet assumption, where it lives, why it breaks
locally, and what a local instance needs instead.

### 3.1 The agent never fetches the local root key — **hard blocker**

`main.rs` builds the agent against `IC_URL` and **never calls
`agent.fetch_root_key()`** (confirmed: no occurrence anywhere in `src/`).
`ic-agent` verifies every response certificate against the mainnet IC root key
baked into the crate. A local `dfx` replica has a **different** root key, so
*every* call — `read_state_canister_metadata` in `get_canister_candid`
(`src/tools.rs:85`), `canister_query`, `canister_update_call`, and the II
delegation calls `mcp_register_v2` / `mcp_get_accounts` /
`mcp_prepare_delegation` / `mcp_get_delegation` (`src/identities.rs`) — fails
certificate verification.

The server does **not** verify II's delegation signatures itself; it hands the
chain to the replica and lets the replica verify (`src/auth.rs:1198`+, "the
replica verifies every hop authoritatively"). So the root key matters purely at
the `ic-agent` layer, and `fetch_root_key()` on the local agent fixes the whole
surface at once.

**Needed:** a local agent built against the local replica URL that calls
`fetch_root_key().await` at startup. This is **insecure against mainnet by
design** (it trusts whatever key the endpoint returns), so it must be gated so
it can only ever run for the local instance (see §5).

### 3.2 `IC_URL` is not overridable — the local endpoint has nowhere to come from

`IC_URL` is a `const` and the only agent is built from it (`src/lib.rs:100`,
`src/main.rs:85`). II origin/canister are env-overridable but the **replica
endpoint** is not. A local instance needs its agent pointed at e.g.
`http://localhost:4943`.

**Needed:** a config knob (env var, e.g. `IC_URL_LOCAL`/`LOCAL_REPLICA_URL`) for
the local agent's endpoint, defaulting to the `dfx` default
`http://localhost:4943`.

### 3.3 Discovery refuses loopback and non-https — **blocks `open_app` locally**

`src/discover.rs` runs a deliberate SSRF guard (CWE-918): `resolve_public_url`
(`:958`) rejects any host that resolves to a non-global IP via `ip_is_global`
(`:915`) — loopback/private/CGNAT/etc. — **and** rejects any non-`https`
scheme. A local app is served at `http://<canister>.localhost:4943`, which is
both loopback and http, so `open_app`, `resolve_app`, and
`discover_app_canisters` all refuse it before any request. `redirect_hop_ok`
(`:997`) and `fetch_alternative_origins` (`:642`) share the same guard.

**Needed (design choice, see §4.3):** for the local instance only, a discovery
mode that permits `http` + loopback for a configured local host, while the
mainnet instances keep the guard fully intact. The relaxation must be a
per-instance capability, never a global toggle.

### 3.4 `target_origin` forces https and only remaps mainnet gateways

`target_origin` (`src/identities.rs:193`) computes the II derivation origin: it
strips the scheme and always re-emits `https://<host>`, and it remaps
`*.icp0.io` / `*.icp.net` → `*.ic0.app`. Local origins are
`http://<canister>.localhost:4943`; forcing `https` and dropping the port would
derive the wrong II principal (or none). The per-app account delegation is keyed
on this origin (`derive_app_delegation`, `src/identities.rs:974`), so a wrong
origin means wrong/absent accounts.

**Needed:** local-aware canonicalization that preserves `http://…localhost:port`
for the local instance. Scope carefully — this feeds the identity the user acts
as, so it must match exactly what the local II derives against.

### 3.5 Canister management hard-codes mainnet system canisters

`src/management.rs:40-45` pins the mainnet **cycles ledger**
(`um5iw-rqaaa-aaaaq-qaaba-cai`), **CMC** (`rkp4c-7iaaa-aaaaa-aaaca-cai`), and
**ICP ledger** (`ryjl3-tyaaa-aaaaa-aaaba-cai`). A bare local replica has none of
these, so `icp_create_canister` (both the cycles-ledger and the ICP→CMC funding
paths), `icp_top_up_canister`, and `icp_cycles_balance` cannot work locally
unless the developer ran `dfx nns install`.

The plain lifecycle calls to the management canister `aaaaa-aa`
(`Principal::management_canister()`, `src/management.rs:555`) — status, start,
stop, install, delete — work fine locally. Only **creation and funding** are
mainnet-shaped: locally, canisters are created with the management canister's
`provisional_create_canister_with_cycles` (free cycles, local/testnet only).

**Needed:** for the local instance, a creation path via
`provisional_create_canister_with_cycles`, and either hide or clearly degrade
the ICP/CMC/cycles-ledger tools (they only apply if a local NNS is installed).
Lowest-priority gap — reads/writes/discovery are the primary local use case; can
be a later phase.

### 3.6 Operational prerequisite — a local II with the MCP feature set

The connect handshake redirects the browser to `{ii_url}/mcp#…`
(`ii_mcp_url`, `src/auth.rs:750`) and the delegation methods target the II
canister. A **local** II must be a build that carries the merged MCP contract:
`mcp_register_v2`, `mcp_get_accounts`, `mcp_prepare_delegation`,
`mcp_get_delegation` (II #4086), the `/mcp` connect page and #4093 chain JSON,
and the #4091 callback allow-list fetch. Stock II may not have these (the README
roadmap still lists the live round-trip as pending, `README.md:836`).

Two sub-points to verify against the local II build:
- **Callback allow-list over http.** II fetches
  `<mcp-origin>/.well-known/ii-auth-callbacks` and requires an exact match
  (`src/auth.rs:780`+). Locally the MCP origin is `http://localhost:8000`;
  confirm the local II will fetch it over http/loopback.
- **Cookie `Secure` flag.** The connect cookie is `Secure` only when
  `public_url` is https; `normalize_public_url` (`src/lib.rs:468`) already
  preserves a local `http://localhost` origin, so a local run correctly omits
  `Secure`. No change expected — just noted.

This is an environment prerequisite, not server code, but the design must
document how to obtain/deploy such an II locally (e.g. `dfx deploy` an MCP-enabled
II WASM) or the instance is untestable end-to-end.

### 3.7 Non-blockers (degrade gracefully)

- **Dashboard enrichment** in discovery adds human names/kinds from the mainnet
  IC dashboard. Local canister ids won't be found; it fails soft (labels stay
  null). No change needed.
- **Known-app registry** (`KNOWN_DERIVATION_ORIGINS`, `KNOWN_APPS` in
  `discover.rs`) is mainnet apps; irrelevant locally but harmless — a local app
  is resolved as a URL, not a known name.
- **DNS-rebinding `allowed_hosts`** already includes loopback
  (`allowed_hosts_for`, `src/lib.rs:385`), so a locally-bound MCP server accepts
  its own `Host` header.

## 4. Proposed design

### 4.1 Shape: a local *run profile* of the same binary (recommended)

Run the **same** `imcp2` binary in a "local" configuration on the developer's
machine, next to their `dfx` replica. Concretely, `main.rs` gains a branch
(selected by env, e.g. `IMCP2_MODE=local` or presence of `LOCAL_REPLICA_URL`)
that, instead of composing beta+prod, composes a single **local** instance:

- an agent built against the local replica URL, with `fetch_root_key()` called;
- `IiInstance::local()` (new) from `II_URL_LOCAL` / `II_CANISTER_ID_LOCAL`;
- the local discovery capability enabled (see §4.3);
- mounted at `/mcp` (a lone instance can own the root well-known docs, per the
  existing `root_well_known_router` contract in `src/lib.rs:312`).

**Why a profile, not a third bundled instance in the hosted binary:** the hosted
server can't reach a developer's `localhost` replica, and — more importantly —
enabling `fetch_root_key()` and the SSRF relaxation inside the *hosted* process
would be a security regression for the mainnet instances sharing it. Keeping
"local" a separate run keeps those capabilities off the mainnet deployment
entirely.

**Alternatives considered:**
- *Third bundled instance `/mcp-local` in the same process as beta/prod.*
  Rejected: forces the dangerous capabilities into the hosted binary; a hosted
  box still can't see the developer's replica.
- *Separate `imcp2-local` binary / cargo feature.* Viable and arguably the
  safest (the mainnet build literally cannot contain `fetch_root_key`/relaxed
  discovery if they're behind `#[cfg(feature = "local")]`). Slightly more build
  plumbing. Worth deciding at implementation time; the library changes below are
  the same either way. **This is the main open decision (see §7).**

### 4.2 Config surface

New env vars, all read only on the local path:

| Var | Purpose | Default |
|---|---|---|
| `IMCP2_MODE` (or a `--local` flag) | select the local profile | unset → mainnet beta+prod (unchanged) |
| `LOCAL_REPLICA_URL` | local agent endpoint | `http://localhost:4943` |
| `II_URL_LOCAL` | local II origin | `http://<ii-canister>.localhost:4943` |
| `II_CANISTER_ID_LOCAL` | local II canister id | dfx-assigned (no default) |

`PUBLIC_URL` (existing) is the local MCP origin, e.g.
`http://localhost:8000` (already the default).

### 4.3 Library changes (small, additive)

1. **Agent bootstrap.** A helper (in `main.rs`, or a `local_agent()` in the lib)
   that builds the agent against `LOCAL_REPLICA_URL` and awaits
   `fetch_root_key()`. Guard: refuse to fetch the root key unless the URL is a
   loopback/local host, so it can never run against a real endpoint even if
   mis-configured.
2. **`IiInstance::local()`** — mirror `beta()`/`prod()` reading the `_LOCAL`
   vars (`src/identities.rs`).
3. **Local-aware discovery.** Thread a "local host allowed" capability into
   `McpConfig`/`Identities`/discovery so `resolve_public_url` and
   `redirect_hop_ok` permit `http` + the configured loopback host **for the
   local instance only**. Options, cheapest first:
   - **(a) Bypass discovery locally.** Simplest and safest: on the local
     instance, developers pass canister ids directly to
     `get_canister_candid` / `canister_query` (they know their own ids from
     `dfx`). `open_app`-style discovery of a localhost URL is disabled with a
     clear message. Ships value immediately with **zero** change to the SSRF
     guard.
   - **(b) Scoped relaxation.** Add a per-call/per-instance flag that lets the
     guard accept the one configured local origin (still pinning
     everything else). More faithful to the mainnet UX; more surface to review.
   Recommend shipping **(a)** first, then **(b)** if local `open_app` is wanted.
4. **Local-aware `target_origin`.** Preserve `http://host:port` for the local
   instance's derivation origins (§3.4).
5. **Local canister creation** (later phase): a
   `provisional_create_canister_with_cycles` path in `management.rs`, selected
   for the local instance.

### 4.4 What stays identical

The OAuth 2.1 AS, the registration-delegation connect handshake, session/token
model, the per-app on-demand delegation machinery, the tool schemas, and the
streamable-HTTP transport are all reused verbatim. The local instance is the
same product pointed at a different replica + II.

## 5. Security guardrails (non-negotiable)

- **`fetch_root_key()` must be unreachable from the mainnet instances.** Behind
  a cargo feature or a startup branch that only the local profile takes, plus a
  runtime assertion that the target URL is loopback. This is the single most
  important invariant — a mainnet agent that trusts a fetched root key is fully
  spoofable.
- **The SSRF/http relaxation must be per-instance, never global.** The mainnet
  discovery path keeps `ip_is_global` + https-only exactly as-is. Any relaxation
  is carried as an explicit capability on the local instance and defaults off.
- **No cross-contamination in one process.** Because the recommended shape runs
  local as its *own* process, the hosted binary never links the relaxed paths at
  runtime; a cargo feature makes that a compile-time guarantee.
- Preserve existing hardening (body-size caps, redirect limits, callback
  allow-list) unchanged.

## 6. Work breakdown

**Phase 1 — reads/writes against a local replica (core value)**
1. `LOCAL_REPLICA_URL` + local agent with guarded `fetch_root_key()`.
2. `IiInstance::local()` + `_LOCAL` env vars.
3. Local profile branch in `main.rs` composing the single local instance.
4. Discovery bypass locally (§4.3 option a) with a clear "pass canister ids
   directly" message.
5. Local-aware `target_origin`.
6. Docs: how to deploy an MCP-enabled II locally and connect a client.

*Exit:* `get_canister_candid`, `canister_query`, `canister_update_call`, and
per-app accounts work against a local replica + local II.

**Phase 2 — local discovery (optional UX parity)**
7. Scoped SSRF/http relaxation (§4.3 option b) so `open_app`/`resolve_app`
   resolve a localhost app.

**Phase 3 — local canister management**
8. `provisional_create_canister_with_cycles` creation path; hide/degrade the
   ICP/CMC/cycles-ledger tools unless a local NNS is present.

## 7. Open questions / decisions for the user

1. **Packaging:** separate `imcp2-local` binary or cargo `feature = "local"`,
   vs. a runtime `IMCP2_MODE=local` branch in the one binary? (Recommendation: a
   cargo feature — strongest compile-time guarantee that mainnet can't fetch a
   root key or relax SSRF.)
2. **Local discovery:** ship the bypass (Phase 1) only, or is `open_app` against
   a localhost app in scope (Phase 2)?
3. **Local II:** is there a canonical MCP-enabled II WASM/`dfx` recipe the docs
   should point to, or should the scope include producing one?
4. **Canister management locally:** in scope now (Phase 3) or deferred?

## 8. Out of scope

- Deploying/packaging a local II (an environment prerequisite; the scope only
  documents it).
- Persisting sessions (already a general roadmap item, `README.md:839`).
- Any change to the mainnet beta/prod instances' behavior.

## 9. Evidence index (file references)

- Agent build, no root-key fetch: `src/main.rs:85`, `src/lib.rs:100`.
- Per-instance agent injection: `src/lib.rs:103` (`McpConfig`), agent cloning
  `src/identities.rs:457`.
- II instances: `src/identities.rs:106-133`.
- `target_origin`: `src/identities.rs:193`.
- Discovery SSRF/https guard: `src/discover.rs:915`, `:958`, `:997`, `:642`.
- Management system canisters + provisional gap: `src/management.rs:40-45`,
  `:255`, `:555`.
- Connect handshake + callback allow-list: `src/auth.rs:750`, `:780`.
- `normalize_public_url` (Secure-cookie/local origin): `src/lib.rs:468`.
