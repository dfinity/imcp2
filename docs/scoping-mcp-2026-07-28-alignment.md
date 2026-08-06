# Scoping: aligning imcp2 with MCP revision 2026-07-28

Status: **draft / scoping** (2026-08-06). Analysis and sequencing only; no code
changes land in this document. It reads the [MCP 2026-07-28
specification](https://modelcontextprotocol.io/specification/2026-07-28) against
the current imcp2 codebase and ranks the design improvements the revision
enables. Spec-strength labels (MUST / SHOULD / MAY) and repo citations were
cross-checked by an adversarial verification pass; the "Corrections applied"
section at the end records what that pass changed.

The two immediate, imcp2-only wins (`iss` and CIMD) are called out in
"Sequencing" below. The first of them, RFC 9207 `iss`, is already implemented as
a separate small PR.

## 1. Headline

The single most consequential improvement is **adopting Client ID Metadata
Documents (CIMD) to replace imcp2's open Dynamic Client Registration**. It swaps
a spoofable, attacker-controlled `/register` body for a DNS/TLS-authenticated
`client_id` URL, re-bases the hardcoded hosted-redirect allow-list onto the
spec's blessed "domain trust policy," and gives the branding goal in
`scoping-client-branding.md` a non-spoofable key to hang name/logo on.

The meta-point: **imcp2's deliberate stateless, plain-JSON, no-session design is
exactly the structural shift 2026-07-28 makes mandatory.** The revision removes
protocol sessions, `initialize`, and `Mcp-Session-Id`, turning imcp2's "we
happen to be stateless" bet into the protocol's required shape. Most transport
work is therefore *deletion*, gated on rmcp shipping a "modern" path; the net-new
obligations are small (header/body validation, `iss`, `server/discover`).

## 2. What imcp2 already gets right (the spec now validates these)

- **Statelessness is now mandated, not tolerated.** The spec: "MCP is a stateless
  protocol... Servers MUST NOT rely on prior requests over the same connection."
  imcp2 runs `with_stateful_mode(false).with_json_response(true)`
  (`lib.rs:222-223`). The design commitment documented in-crate ("our tools are
  pure request/response with no server-initiated messages," `lib.rs:216-220`) is
  precisely what the revision requires.
- **Streamable HTTP, not HTTP+SSE.** The deprecated HTTP+SSE transport is exactly
  the legacy dance imcp2 avoids.
- **No server-initiated requests.** imcp2 uses no sampling/roots/elicitation, so
  MRTR's "breaking change" (server-initiated requests removed) costs it nothing;
  it can only *gain* the pattern.
- **Exact-match redirect validation and open-redirect hardening.** The MCP05
  (reject query/fragment) and CWE-601 (reject path percent-encoding) hardening in
  `redirect_uri_permitted` (`auth.rs:510-567`) is squarely what
  security-considerations demands ("validate exact redirect URIs against
  pre-registered values"; "clearly display the redirect URI hostname").
- **No token passthrough.** imcp2 calls the IC via its own II delegation/agent
  identity, never the client's MCP bearer, satisfying "MCP server MUST NOT pass
  through the token."
- **Confused-deputy consent.** The `sid` cookie Consent-Bound Completion
  (`auth.rs:1005-1008`, `1819-1820`) satisfies "MCP proxy servers using static
  client IDs MUST obtain user consent... before forwarding to third-party
  authorization servers."

> **Not yet confirmed, do not assume compliant:** *`Mcp-Session-Id` minting and
> GET/DELETE to 405.* The spec is explicit that rmcp's current
> `StreamableHttpService` historically **mints** session IDs and answers GET by
> opening a server-to-client SSE stream (and DELETE to terminate). Under
> 2026-07-28 both GET and DELETE **MUST** return `405`, and the server **MUST
> NOT** mint or echo `Mcp-Session-Id`. Whether `with_stateful_mode(false)` fully
> suppresses this in rmcp 1.7 is unverified, and imcp2's CORS config still lists
> `mcp-session-id` as an allowed/exposed header (`lib.rs:249,254`). The
> `LocalSessionManager` is still wired into `StreamableHttpService::new`
> (`lib.rs:215`), bypassed under stateless mode, and slated to become
> vestigial/removable once rmcp ships modern support, but present today.
> **Action:** audit GET/DELETE responses and session-id handling on the MCP
> endpoint; add an axum layer (or wait for rmcp) to force `405` and drop any
> session-id echo. This is an item to close, not a box already checked.

## 3. Ranked improvement opportunities

### #1 CIMD replacing open DCR (and subsuming the branding work)

**Impact: High / Effort: Med / Tractability: High (imcp2-only; no rmcp or II
dependency)**

- **New in 2026-07-28:** DCR (RFC 7591) is **DEPRECATED**; CIMD is the intended
  path. An authorization server (AS) **SHOULD** support CIMD and advertise
  `client_id_metadata_document_supported: true`. On a URL-form `client_id`, the AS
  **SHOULD** fetch it, **MUST** validate `client_id` == URL exactly, **MUST**
  validate redirect URIs against the fetched doc, **MUST** validate JSON
  structure/required fields, **SHOULD** cache per HTTP headers, and **SHOULD**
  consider SSRF. The AS **MAY** implement domain-based trust policies.
- **imcp2 today:** Open, unauthenticated DCR at `/oauth/register`
  (`auth.rs:1927`) storing a `ClientReg` of `redirect_uris`; it defends phishing
  with the hardcoded `DEFAULT_ALLOWED_REDIRECTS` domain+path allow-list
  (`auth.rs:399-409`) plus MCP05/CWE-601 hardening. The branding scoping doc
  exists precisely because DCR `client_name`/`logo_uri` are attacker-controlled
  and cannot be shown to II's consent screen.
- **Improvement:** Add a CIMD code path: accept URL-form `client_id`, fetch it
  with SSRF guards (https-only, deny loopback/link-local/private IPs, timeouts,
  size caps). The same same-origin-https + SSRF-fallback pattern already
  implemented in `skills.rs`'s `markdown_url_for_base` (which rejects
  `169.254.169.254`, `file://`, and cross-origin) is directly reusable. Enforce
  `client_id` == URL and redirect_uri in doc. **Rewrite `allowed_redirects()` as
  an allowed-`client_id`-host policy**, the spec's "domain allowed via trust
  policy." Advertise `client_id_metadata_document_supported: true` in AS metadata
  (`auth.rs:1985-1994`). Keep DCR only as deprecated backward-compat.
- **How it subsumes the branding work:** The verified, non-spoofable fact CIMD
  gives you is the **`client_id` domain** (DNS/TLS-authenticated; nobody can host
  at `https://chatgpt.com/...` without owning it). Key the curated vendor
  name/logo table on that domain. **Do NOT trust the doc's
  `client_name`/`logo_uri` directly**: CIMD provides no signing or attestation for
  display fields; they are as spoofable as DCR metadata. This matches the branding
  doc's own security spine (branding derived from the vetted vendor, never from
  client-supplied metadata) but gives it a cleaner cryptographic key than the
  redirect-path allow-list.
- **Caveat / risk:** The allow-list does **not** disappear; it moves from
  redirect-URI-domain to client-id-domain. A malicious actor can still host a
  valid CIMD with their own redirects; the phishing defense still rests on the
  curated trust policy (a spec **MAY**, plus mandatory hostname display). Real
  clients (chatgpt.com, claude.ai, cursor.com, and so on) will keep sending DCR
  for a long time, so this is *additive*, not a replacement, until the ecosystem
  moves. DCR is not removed before 2027-07-28.

### #2 Emit `iss` (RFC 9207) on all authorization responses

**Impact: High (correctness/security, clearly mandated) / Effort: Low /
Tractability: High (imcp2-only)**

> **Status: implemented** as a follow-up PR (`claude/oauth-iss-rfc9207`). Recorded
> here for completeness and because it was the top item in "Sequencing."

- **New in 2026-07-28:** The AS **SHOULD** include `iss` in *all* authorization
  responses (success and error); if it does, it **MUST** advertise
  `authorization_response_iss_parameter_supported: true`. A future revision
  upgrades this SHOULD to a MUST. Clients **MUST** reject a response missing `iss`
  when the flag is set.
- **imcp2 before the change:** No `iss` emitted anywhere. `build_redirect`
  (`auth.rs:1081-1088`) appended only `code` and `state`. AS metadata
  (`auth.rs:1985-1994`) did not advertise the flag. An `issuer()` method exists
  (`auth.rs:770-772`) but was used only for metadata/URL construction.
- **Improvement (shipped):** Add `iss=<issuer>` to every `/oauth/authorize`
  success redirect, byte-for-byte identical to the metadata `issuer` (no
  trailing-slash/case/port variance; clients use exact string compare), and add
  `authorization_response_iss_parameter_supported: true` to the RFC 8414 doc.
  imcp2's OAuth error paths render pages or return JSON rather than redirecting to
  the client, so there is no error-redirect to stamp.
- **Impact:** This was the single clearest hard gap versus the revision; it is the
  spec's named mix-up-attack mitigation. Effort was genuinely low: a couple of
  query-param appends plus one metadata field.
- **Caveat:** Emitting `iss` *without* the metadata flag is a spec violation, so
  the two ship together (they do).

### #3 Header/body validation: `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`

**Impact: Med-High (net-new obligation) / Effort: Med / Tractability: Med (axum
layer, or wait for rmcp)**

- **New in 2026-07-28:** Every POST **MUST** carry `MCP-Protocol-Version` (must
  match body `_meta`), `Mcp-Method` (must match `method`), and `Mcp-Name` (must
  match `params.name`/`params.uri`, for
  `tools/call`/`resources/read`/`prompts/get`). Any body-processing server
  **MUST** reject mismatch/missing/invalid-chars with `400` + `-32020
  HeaderMismatch`; unknown method to `404` + `-32601`; unsupported version to
  `400` + `-32022` with a `supported` list. `Mcp-Name` may arrive
  Base64-sentinel-encoded and the server **MUST** decode before comparing.
- **imcp2 today:** rmcp 1.7 validates `MCP-Protocol-Version` presence/known-ness
  only; it does **not** do the header-to-body match, nor `Mcp-Method`/`Mcp-Name`,
  nor emit `-32020/-32022`. imcp2 tops out at 2025-11-25 (no 2026-07-28 in rmcp
  1.7).
- **Improvement:** Add an axum middleware after `require_token` and before the
  rmcp service that validates the three headers against the parsed body and
  returns the mandated codes. Because imcp2's tool set is fixed (about 26 tools),
  the `Mcp-Name` to known-tool check doubles as cheap edge rejection of bogus
  calls.
- **Caveat:** This behavior only fully applies to *modern* (2026-07-28) requests.
  imcp2 must stay dual-era: legacy clients (all of them today) send neither
  `Mcp-Method` nor `Mcp-Name`. Gate the strict validation on the request being
  modern (protocol version in `_meta`). Cleanest once rmcp lands modern support;
  feasible as a hand-rolled layer sooner.

### #4 Implement `server/discover` (a MUST) plus per-request `_meta`/dual-era

**Impact: Med-High / Effort: Med-High (mostly rmcp-gated) / Tractability: Low-Med
(needs rmcp modern path for full form)**

- **New in 2026-07-28:** `initialize`/`notifications/initialized` removed; every
  request self-describes via `_meta` (`io.modelcontextprotocol/protocolVersion` +
  `clientCapabilities` required, `-32602`/`400` if missing; `clientInfo` SHOULD).
  Servers **MUST** implement `server/discover` (returns `supportedVersions`,
  `capabilities`, `serverInfo`, optional `instructions`, plus `ttlMs`/`cacheScope`).
  Servers **SHOULD** emit `serverInfo` in every result `_meta`.
  `MissingRequiredClientCapability` to `-32021`.
- **imcp2 today:** rmcp 1.7 still runs the `initialize` lifecycle.
  `IcTools::get_info()` supplies `ServerInfo`/`ServerCapabilities` once
  (`tools.rs:1876-1881`) with a rich instructions string. imcp2 has **no**
  `server/discover` (note: its `discover.rs` is *app-canister* discovery, an
  unrelated name collision).
- **Improvement:** When rmcp exposes the modern path, add `server/discover`
  returning `supportedVersions` (e.g. `["2026-07-28","2025-11-25"]`),
  `capabilities` mirroring `enable_tools().enable_resources()`, `serverInfo`
  (imcp2 has `Implementation::from_build_env()`), and fold the existing
  instructions + skills catalog into `instructions`. Set `cacheScope: "public"`
  (the surface is static per deployment). Become **dual-era**: the spec explicitly
  blesses one endpoint serving both (`initialize` to legacy; `_meta` to modern).
- **`clientInfo` for branding:** `io.modelcontextprotocol/clientInfo` (with the
  new base-protocol `icons` array) is the *protocol-native* channel for product
  name/logo, but the spec's "self-reported... SHOULD NOT rely on them for security
  decisions" is a first-party endorsement of the branding doc's allow-list gating.
  Read name/logo from clientInfo only for allow-listed vendors; reuse the spec's
  `icons` security rules (HTTPS/`data:` only, MIME allowlist, magic-byte sniff,
  no-credentials fetch, same-origin) for logo handling.
- **Caveat:** Hard-gated on rmcp shipping the modern per-request path; not doable
  in-crate on rmcp 1.7. The bearer gate (`require_token`) still applies to
  `server/discover`; keep it authenticated (the spec does not require otherwise).

### #5 CacheableResult + Resources for slow-changing on-chain metadata

**Impact: Med-High (real latency/cost plus fewer mainnet round-trips) / Effort:
Med / Tractability: Med**

- **New in 2026-07-28:** `ttlMs` + `cacheScope` (`public`/`private`) are
  **required** on `server/discover`, `tools/list`, `prompts/list`,
  `resources/list`, `resources/templates/list`, `resources/read` results, but
  **not** on `tools/call`. `tools/list` **SHOULD** be deterministic order
  (prompt-cache hits). Resource-not-found is now `-32602` (not `-32002`).
- **imcp2 today:** imcp2's cacheable, on-chain-derived outputs
  (`get_canister_candid`, `get_canister_api_doc`, `get_canister_oql_schema`,
  `discover_app_canisters`, `resolve_app`/`get_app_principal`) are delivered as
  `tools/call` results and therefore *cannot* carry `ttlMs`/`cacheScope`. There is
  no result cache for this interface metadata, so identical Candid/schema fetches
  re-hit mainnet on repeat calls. (imcp2 does cache per-session app delegations in
  `identities.rs`, but that is auth state, not tool-result caching.)
- **Improvement:** (a) Tag `tools/list` `cacheScope: "public"` + long `ttlMs`
  (the ~26 tools are compile-time fixed, identical for every II caller) and emit
  them in deterministic (name-sorted) order, for cross-token/gateway caching plus
  higher LLM prompt-cache hits at zero behavioral cost. (b) **Re-surface public
  on-chain metadata as MCP Resources** (`candid://<canister-id>`,
  `oql-schema://<canister-id>`) so they carry `cacheScope: "public"` +
  minutes-to-hours `ttlMs` (Candid changes only on redeploy). This is the *only*
  way to attach cache hints and eliminates repeated mainnet round-trips. Live-state
  reads (`canister_query`, `icp_canister_status`) stay tools or use
  `private`/short-TTL.
- **Caveat:** For a not-found canister/URI on the resource path, emit `-32602` +
  `data.uri` (imcp2 already uses `McpError::resource_not_found` at
  `tools.rs:2060,2071` for its resource surface; audit that rmcp's code becomes
  `-32602`, not `-32002`, on upgrade). Restructuring tool outputs into resources
  is real work; the `tools/list` tagging is cheap and worth doing first.

### #6 MRTR / elicitation for missing tool args (and in-band auth for the stdio binary)

**Impact: Med-High (UX across ~26 tools) / Effort: Med / Tractability: Low
(rmcp-gated)**

- **New in 2026-07-28:** MRTR replaces server-initiated requests. A server
  **MAY** return `InputRequiredResult` (`resultType: "input_required"`) with
  `inputRequests` (`ElicitRequest`/`CreateMessageRequest`/`ListRootsRequest`) plus
  opaque `requestState`; the client gathers input and **retries the original
  request** with `inputResponses` + echoed `requestState`. The server **MUST NOT**
  send an `inputRequests` type the client did not declare capability for; **MUST**
  treat `requestState` as attacker-controlled and integrity-protect it (HMAC/AEAD,
  principal-bound, TTL, per-request digest, server-side single-use).
- **imcp2 today:** Missing/ambiguous args (canister id, `derivation_origin`) fail
  with an in-band `err()` text result the LLM must recover from (e.g.
  `oql_needs_origin_error` `tools.rs:1488`; `get_app_principal` needs origin +
  session). No server-initiated anything.
- **Improvement, the canonical high-value use:** Instead of erroring, tools return
  `InputRequiredResult` with an `elicitation/create` describing exactly the missing
  field, encoding already-supplied args in AEAD-sealed `requestState`; the client
  re-prompts and retries; the call completes. Fall back to plain `err()` when the
  client did not declare `elicitation`. Also: destructive `icp_` ops
  (`delete`/`stop`/large top-up) can demand a typed confirmation via
  `input_required`.
- **Stdio-binary fit:** MRTR gives the scoped stdio-binary `authenticate` tool a
  spec-blessed shape. An unauthenticated call returns `InputRequiredResult`
  (ElicitRequest: "complete II login, then confirm") with the AEAD-sealed
  registration key `X` in `requestState`; the retry redeems and resumes the
  *original* call. The one-time-redemption MUST maps onto imcp2's single-use
  registration key.
- **Caveat:** MRTR is **not** an auth primitive; there is no "open this OAuth URL"
  request type, so the II browser bounce stays out-of-band at the transport/OAuth
  layer. MRTR carries only the *resume-after-consent correlation*. Its
  `requestState` security MUSTs align near-verbatim with imcp2's existing
  consent-binding threat model. rmcp-gated.

### #7 Tasks extension for long-running canister ops

**Impact: Med-High (fixes real timeout problem) / Effort: High (breaks
statelessness) / Tractability: Low (rmcp-gated + durability cost)**

- **New in 2026-07-28:** Official extension `io.modelcontextprotocol/tasks`. The
  server decides per-request to return a `CreateTaskResult` (`taskId`, status,
  TTL, poll interval); "the task must be durably created before the response is
  sent." The client polls `tasks/get`; mid-flight input via `tasks/update`;
  cooperative `tasks/cancel`. The client opts in once via capability, no
  per-request flag. The spec rationale explicitly names imcp2's problem: "clients
  and transport intermediaries impose timeouts that make [blocking] impractical
  beyond a few seconds."
- **imcp2 today:** The genuinely long-running mainnet tools (canister
  create/install, cycles top-up, and status/update calls) do
  `agent...call_and_wait()` and block the HTTP request against client transport
  timeouts. Install in particular can run minutes.
- **Improvement:** Return a `taskId` the client polls, resolving when the mainnet
  op completes.
- **Caveat / risk:** Tasks **requires server-side durability** ("durably created
  before the response"). This **breaks imcp2's deliberately stateless design** and
  needs a task store plus `tasks/get`/`update`/`cancel` handlers plus rmcp support.
  A real architectural add. Consider the lighter alternative first: per-request SSE
  progress (#8).

### #8 Per-request SSE progress + `logLevel` for long-running ops (lighter than Tasks)

**Impact: Med / Effort: Med / Tractability: Low (rmcp-gated)**

- **New in 2026-07-28:** A request may be answered with a request-scoped
  `text/event-stream` emitting `notifications/progress`/`notifications/message`
  then the final response, with no sessions, no GET, no resumability. Stream-close
  = cancellation ("MUST NOT send any further messages"). `io.modelcontextprotocol/logLevel`
  in `_meta` sets per-request verbosity (replaces stateful `logging/setLevel`).
  SHOULD set `X-Accel-Buffering: no`; SHOULD emit `:` keep-alives.
- **imcp2 today:** Long-running tools block and return one plain-JSON result;
  imcp2 enables only tools + resources, no logging capability (`tools.rs:1878`).
- **Improvement:** For the long-running update-call tools, return a request-scoped
  SSE stream emitting progress while the mainnet op proceeds, terminating with the
  final result. This stays within the stateless model (unlike Tasks, no durable
  store). Wire stream-close to abort the in-flight agent call. Set
  `X-Accel-Buffering: no` (imcp2 is hosted behind proxies).
- **Caveat:** rmcp must expose per-request SSE emission for the modern revision.
  **Decide which mainnet ops are safe to abort**: an already-submitted update call
  may still land on-chain regardless of stream close. Strictly additive UX win and
  the pragmatic middle ground versus full Tasks durability.

### #9 `x-mcp-header` routing/policy hooks on `icp_` management tools

**Impact: Med (edge policy for a hosted server) / Effort: Med / Tractability:
Med**

- **New in 2026-07-28:** Servers **MAY** annotate primitive
  (string/integer/boolean) statically-reachable top-level tool params with
  `x-mcp-header` so clients mirror them into `Mcp-Param-{name}` headers (`number`
  is not permitted); the server **MUST** validate any it recognizes against the
  body (`-32020` on mismatch).
- **imcp2 today:** Schemas come from schemars; the edge cannot route/rate-limit
  without parsing textual Candid.
- **Improvement:** Annotate `canister_id`/principal and target `network` (mainnet
  vs local), and a discriminator on destructive `icp_` ops, so imcp2's
  gateway/WAF/rate-limiter can act on `Mcp-Param-*` + `Mcp-Method`/`Mcp-Name`
  without touching the body, e.g. step-up or rate-limit per canister or per
  management operation.
- **Caveat:** schemars 1.x will not emit `x-mcp-header`; imcp2 must post-process
  the generated `inputSchema`. Only static top-level string/int/bool params
  qualify. imcp2 must validate `Mcp-Param-*` regardless once the schema declares
  them (same `-32020` path as #3).

### #10 Error-code hygiene

**Impact: Low-Med (forward-clean correctness) / Effort: Low / Tractability:
High**

- **New in 2026-07-28:** `-32002` (resource not found) to `-32602`;
  implementations of this version **MUST NOT** emit `-32002`/`-32042`. Do not
  squat `-32000` to `-32019` (legacy) or `-32020` to `-32099` (MCP-reserved:
  `-32020` HeaderMismatch, `-32021` MissingRequiredClientCapability, `-32022`
  UnsupportedProtocolVersion). App errors **SHOULD** live outside the reserved
  range.
- **imcp2 today:** Tool business errors are in-band `isError=true` text via
  `err()` (`tools.rs:2280`), no JSON-RPC codes, which is fine. Protocol codes
  appear on the resource surface (`McpError::resource_not_found`,
  `tools.rs:2060,2071`); audit what rmcp maps that to on upgrade.
- **Improvement:** Ensure resource-not-found emits `-32602` + `data.uri`; keep
  IC/agent failures as human-readable messages outside the reserved band; emit
  `-32020/-32021/-32022` where the HTTP binding requires (ties to #3).
- **Caveat:** Mostly framework-level; imcp2 owns the `supported`-versions list for
  `-32022`.

### #11 Skills-over-MCP alignment (SEP-2640, In Review)

**Impact: Low-Med / Effort: Low (when it lands) / Tractability: Blocked (WG
draft)**

- **New in the 2026-07-28 orbit:** SEP-2640 (Skills Extension, Resources-based) is
  *In Review*, coordinating with agentskills.io well-known-URI discovery plus a
  `skills.json` registry.
- **imcp2 today:** `skills.rs` already hand-rolls exactly this: a `skills.json`
  manifest + per-skill `SKILL.md` from `.well-known/skills/<name>/SKILL.md`,
  surfaced as tools (`icp_list_skills`/`icp_get_skill`, `tools.rs:1238-1265`) and
  as `skill://<name>` resources (`tools.rs:2027-2029`). imcp2 is an early reference
  case.
- **Improvement:** When SEP-2640 finalizes, migrate to the standard
  Resources-based Skills Extension so hosts discover IC skills natively.
- **Caveat:** WG draft, no action now, just do not diverge.

### #12 MCP Apps for interactive OQL tables / canister dashboards

**Impact: Low-Med (nice-to-have) / Effort: Med / Tractability: Low (per-client
host support varies)**

- **New in the 2026-07-28 orbit:** MCP Apps (`io.modelcontextprotocol/ui`): a tool
  declares a `ui://` HTML resource rendered in a sandboxed iframe; graceful
  degradation to text.
- **imcp2 today:** OQL results render as static GFM markdown tables via
  `render_table` (`calls.rs:1290`).
- **Improvement:** Layer a `ui://` resource for interactive OQL tables
  (sort/filter/drill-down) or a canister dashboard (cycles, module hash,
  controllers, live monitor), additive over the markdown text fallback.
- **Caveat:** imcp2's allow-listed clients (chatgpt.com, cursor, grok, perplexity)
  do not uniformly support Apps. Stays additive, never load-bearing.

### #13 OpenTelemetry trace propagation via `_meta`

**Impact: Low (observability) / Effort: Low / Tractability: Med**

- **New in 2026-07-28 (minor):** W3C trace context
  (`traceparent`/`tracestate`/`baggage`) carried in `_meta`.
- **imcp2 today:** No trace context read/propagated; a hosted server making
  mainnet agent calls would benefit from end-to-end tracing.
- **Improvement:** Read incoming trace context from `_meta` and propagate through
  the IC agent calls for cross-service tracing.
- **Caveat:** rmcp-gated for the `_meta` plumbing; low priority.

## Deprecations imcp2 must avoid or migrate off

| Deprecated | imcp2 exposure | Action |
|---|---|---|
| **DCR (RFC 7591)** | **HIGH: imcp2 IS an AS doing open DCR** | Migrate to CIMD (#1); keep DCR as backward-compat only until real clients move (not removed before 2027-07-28) |
| **HTTP+SSE transport** | None (already Streamable HTTP) | No action; validates the architecture |
| **Roots / Sampling** | None (imcp2 uses neither) | No action |
| **Logging capability** | Not enabled today | If the stdio binary logs, use **stderr**, not the MCP logging capability |
| `includeContext thisServer/allServers` | None | No action |

## 4. Sequencing

**Do first (correctness + security, imcp2-only, no rmcp/II dependency):**

1. **`iss` / RFC 9207 (#2)** the lowest effort, clearest mandate, closes the one
   unambiguous compliance gap; a future revision makes it a MUST. Ship it with the
   metadata flag. *(Done: `claude/oauth-iss-rfc9207`.)*
2. **CIMD adoption (#1)** the highest-impact security improvement; re-bases the
   whole DCR/allow-list/branding posture onto a spec-blessed, DNS-authenticated
   foundation. Higher effort but entirely in imcp2's control (no rmcp, no II).
   Coordinate with the branding work so name/logo key on the verified `client_id`
   domain from day one.

**Then (alignment, cheap wins that do not need the modern rmcp path):**

3. **`tools/list` deterministic order + `public`/long-`ttlMs` tagging** (part of
   #5), **error-code hygiene (#10)**, and **closing the GET/DELETE to 405 +
   session-id audit from Section 2**, all low effort, forward-clean, doable ahead
   of full modern support.

**Then (gated on rmcp shipping the 2026-07-28 modern path; plan now, build when
available):**

4. Header/body validation (#3), `server/discover` + dual-era `_meta` (#4), MRTR
   elicitation (#6), per-request SSE progress (#8), Resources-for-metadata caching
   (rest of #5).

**Defer / watch:** Tasks (#7, only if imcp2 accepts a durable store, breaking
statelessness; prefer #8 SSE first), Skills-over-MCP (#11, blocked on SEP-2640),
MCP Apps (#12), OTel (#13), `x-mcp-header` (#9).

**Honest dependency summary:** #1 and #2 are pure imcp2 work and should proceed
immediately. Nearly all transport/lifecycle items (#3, #4, #6, #8, and the
resource-caching half of #5) are **gated on rmcp 1.x adding a "modern"
per-request path**; rmcp 1.7 tops out at 2025-11-25 with no 2026-07-28 support.
#3's header validation and the Section 2 GET/DELETE/session hardening are the
transport items imcp2 could hand-roll as an axum layer ahead of rmcp. #4's
`clientInfo`/`icons` and #1's CIMD both feed the branding work, which
additionally needs **II-side coordination**: II must render the connecting
client's name/logo following the spec's `icons` security rules (HTTPS/`data:`
only, MIME allowlist, no inlined SVG). Tasks (#7) is the only item that would
actively regress imcp2's stateless design.

## Corrections applied (from the verification pass)

1. **Fixed a false "already compliant" claim (most significant).** An earlier
   draft listed "No `Mcp-Session-Id` minting, GET/DELETE already 405" under *what
   imcp2 already gets right*. The Streamable-HTTP spec states the **opposite**:
   rmcp's `StreamableHttpService` historically *mints* session IDs and answers GET
   with an SSE stream, and imcp2 should confirm/patch it. A repo check found **no**
   `405`/`METHOD_NOT_ALLOWED` handling in imcp2 source and a CORS entry still
   listing `mcp-session-id` (`lib.rs:249,254`). Reframed as an open **not-yet-
   confirmed** item with a concrete audit action, and added to the "cheap wins"
   list.
2. **Corrected the `LocalSessionManager` claim.** It is still constructed and
   passed into `StreamableHttpService::new` at `lib.rs:215` (bypassed under
   `with_stateful_mode(false)`, and becomes vestigial only once rmcp ships modern
   support).
3. **Removed fabricated / mis-attributed internal details in #5.** Dropped an
   unsupported "no result cache at all" citation and a specific claim about
   `candid_service` re-fetching the same `.did` several times per call; neither is
   grounded. Replaced with the supported point (cacheable outputs are delivered as
   `tools/call` results and cannot carry cache hints), and noted the delegation
   cache in `identities.rs` is auth state, not tool-result caching.
4. **Softened over-specific claims in #7.** Removed precise enumerated tool counts
   and per-client timeout figures that were not grounded. Kept the supported set
   (canister create/install, cycles top-up, status/update calls).
5. **Verified and retained** every MUST/SHOULD/MAY strength label in #1 to #10
   (CIMD support levels; `iss` SHOULD + MUST-advertise + future-MUST; header
   validation error codes `-32020/-32601/-32022`; `server/discover` MUST; required
   cache-hint operations; MRTR semantics; Tasks durability MUST; SSE/`logLevel`;
   `x-mcp-header` constraints; error-code renumbering) and all deprecations. The
   `skills.rs` `markdown_url_for_base` SSRF-reuse claim in #1 was confirmed
   accurate against the repo (it rejects `169.254.169.254`, `file://`, and
   cross-origin URLs).
