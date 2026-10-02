# Client ID Metadata Documents (CIMD) for imcp2: design record

Status: **implemented**.

- #191 added CIMD as a registration mode beside open DCR, opt-in through `OAUTH_CIMD_ENABLED`.
- #203 made it a `McpConfig` field, on by default in the `imcp2` binary, with
  `OAUTH_CIMD_ENABLED` kept as a kill switch.

This document began as the scoping plan for that work. It now records what was built, the
decisions that settled the plan's open questions (section 8), and where the plan was revised or
overtaken (sections 4 and 6). Code is referenced by symbol (file plus function, type, or
constant), never by line number. Bare numbers are dfinity/imcp2 PRs. The code cites this document
by section ("PR #143 §3.4", "§3.5"), so those section numbers are kept stable.

The original plan expanded the top-ranked improvement of the MCP 2026-07-28 alignment scoping
(#126, "CIMD replacing open DCR"). It folded in one correction from that review: imcp2's
same-origin URL check (`skills.rs`, `markdown_url_for_base`) is not an SSRF guard for a CIMD fetch.
That check compares only a candidate's host, not its port, against the configured skills origin.
It protects a fetch only when that origin is fixed, and a CIMD URL is chosen by the caller. The
address-pinned fetcher behind discovery is the right building block.

## Summary

CIMD is **trust-policy-gated and additive**:

- imcp2 fetches a Client ID Metadata Document only when the `client_id` URL is on a vetted vendor
  domain.
- It keeps open DCR for ordinary (non-URL) client IDs. A URL `client_id` off the trust policy is
  refused, never handed to DCR.
- It never trusts the document's display fields.

The new outbound-fetch surface on the unauthenticated `/oauth/authorize` path is therefore
confined to the vetted vendor domains and their subdomains, not an arbitrary-URL SSRF primitive.
Even those hosts are fetched under the SSRF guard.

## 1. What CIMD is, and the spec obligations

Under MCP 2026-07-28, Dynamic Client Registration (RFC 7591) is **deprecated** and CIMD is the
preferred replacement. A client does not POST a registration body and receive a server-minted
`client_id`. Instead, it presents its `client_id` **as an `https` URL**, and the JSON document at
that URL is its registration (`redirect_uris`, `client_name`, how it authenticates). Nobody can
serve a document at `https://chatgpt.com/…` without controlling that domain, so the URL's **host**
is DNS/TLS-authenticated.

Authorization-server obligations, from the OAuth CIMD draft
(`draft-ietf-oauth-client-id-metadata-document`, cited by name in `src/auth.rs`; the code does not
pin a numbered revision):

- **SHOULD** support CIMD and advertise `client_id_metadata_document_supported: true`.
- On a URL-form `client_id`:
  - **SHOULD** fetch the document;
  - **MUST** validate that the document's `client_id` equals the URL;
  - **MUST** validate the request's redirect URI against the document's `redirect_uris`;
  - **MUST** validate the JSON structure and required fields.
- **SHOULD** cache per the response's HTTP cache headers.
- **SHOULD** consider SSRF when fetching an attacker-influenced URL.
- **MAY** apply a domain-based trust policy, which is the hook this design leans on.

CIMD provides **no signing or attestation** of the document's contents. The display fields
(`client_name`, `logo_uri`) are exactly as spoofable as a DCR body. The only meaningful fact is the
**host** of the URL, and it authenticates the *document*, not the party using it. A public client
with loopback redirects can be impersonated by any local program that presents its `client_id`
(see 4).

## 2. Context: imcp2 before CIMD

- **Open DCR.** `POST /oauth/register` (`register`, unauthenticated) stores a `ClientReg` of
  `redirect_uris` under a server-minted `client-{uuid}`.
  - The store is bounded (`MAX_CLIENTS`, `MAX_REDIRECT_URIS`, `MAX_REDIRECT_URI_LEN`),
    LRU-evicted (`make_room_for_client`), and atomically persisted.
  - All of this is unchanged; DCR remains.
- **The phishing defense is a hosted-redirect allow-list.**
  - `DEFAULT_ALLOWED_REDIRECTS` is a curated list of `(domain, path, pin)` vendor callback
    entries.
  - `OAUTH_ALLOWED_REDIRECT_PREFIXES` lets operators add entries; `allowed_redirects` returns the
    effective list.
  - `redirect_uri_permitted` enforces host **and** pinned path at registration and at
    authorization (`validate_client` → `redirect_allowed`). Loopback is exempt (RFC 8252).
- **An SSRF-safe fetcher already existed, inside discovery** (`crates/imcp2-core/src/discover.rs`).
  - `resolve_public_url` is `https`-only and refuses a host unless every resolved address is
    globally routable.
  - The client is pinned to the validated addresses, so a re-resolution cannot rebind the
    connection.
  - Bodies are read under a byte cap.

  That was the right foundation. Discovery's reader and redirect policy were not, because both
  serve an opportunistic crawl:
  - **The reader is lossy.** Discovery's reader stops at the cap and returns what it has without
    saying so, decodes lossily, and hands back a partial body when a transfer fails. A truncated
    document whose prefix happens to be valid JSON could then be accepted as client metadata.
  - **The redirect policy is loose.** Discovery's redirect policy (`ssrf_redirect_policy`,
    `redirect_hop_ok`) follows any `https` hop to a globally routable IP literal, and any hop to
    the same host name, without comparing ports. A vetted `client_id` could then bounce the fetch
    to an unvetted public address, or to the vetted host on another port such as `:8443`. That
    gets around the origin gate of 3.1.

  Section 3.3 describes the strict fetcher that replaces both.

## 3. Design as implemented

### 3.1 What counts as a CIMD `client_id`, and the trust gate

`validate_client` (`src/auth.rs`) treats a `client_id` as CIMD only when CIMD is enabled for the
instance (see 3.8) and `cimd_client_id` accepts its shape:

- `https`, a host, and a path beyond `/`;
- no fragment and no userinfo (a query is tolerated);
- at most `CIMD_MAX_CLIENT_ID_LEN` bytes (the redirect-URI cap);
- it must serialize back to the identifier exactly as given (`parsed_as_given`), apart from
  scheme and host case and an explicit `:443`. That refuses everything the URL parser would
  silently rewrite.

Anything else is an ordinary DCR identifier. A URL `client_id` on an instance with CIMD off is an
unknown client.

**The trust gate runs before anything else** (`cimd_origin_trusted`):

- The URL must be `https` on the default port.
- Its host must equal, or be a dot-boundary subdomain of, a domain of the hosted-redirect
  allow-list (`vetted_domain` over `allowed_redirects`, including operator entries).
- The gate matches the **origin**, not the bare host. The SSRF guard connects to the port the URL
  names, so a host-only check would let `https://claude.ai:8443/…` past a `claude.ai` gate.
- **This is wider than the plan**, which proposed exact `https://<vetted-host>` origins. The gate
  instead reuses `redirect_uri_permitted`'s host rule over the same list, so there is one rule
  for who is vetted. That admits every subdomain of a vetted domain (see 5 for the DoS
  consequence).

A URL off the gate is refused before any request goes out (`ClientCheck::UntrustedClientOrigin`).
The browser gets the same "not approved" page as a hosted redirect off the allow-list; a non-HTML
client gets `403 invalid_client` naming the contact.

**The redirect check also runs before any fetch.** A request whose `redirect_uri` fails
`redirect_uri_permitted` is refused without asking even a vetted host for a document.

### 3.2 Request flow

At `/oauth/authorize`, `validate_client` returns one of four verdicts:

| Verdict | When | What the caller sees |
|---|---|---|
| `Allowed` | A DCR client with that registered redirect, or a CIMD client whose validated document lists it | The sign-in proceeds to Internet Identity |
| `Refused` | Unknown client, an invalid document (including a cached negative entry), or a redirect not listed or not permitted | The existing refusal paths |
| `UntrustedClientOrigin` | A URL `client_id` off the trust gate | The "not approved" page, or `403 invalid_client` |
| `MetadataUnavailable` | A transient failure, or the in-flight fetch bounds are full so no fetch was attempted (see 3.5) | `503 temporarily_unavailable`, "try again in a moment"; nothing about the cause is reflected |

On success, the CIMD URL is the `client_id` for the rest of the code and token flow.

### 3.3 The fetcher

`imcp2_core::public_fetch::fetch_public_document` is one SSRF-guarded GET of a small public
document. It reuses discovery's `resolve_public_url` and `read_capped_bytes` (both reshaped for
this in #191; see 6), but is **strict** where the crawl is opportunistic:

- **Address safety.** Every resolved address must be public, and the client is pinned to them.
  The connection is direct: no proxy is taken from the environment, since a proxy would resolve
  the host itself and the pin would bind nothing.
- **No redirects.** Any non-`200` is an error, so no other URL's bytes (another host, port, or
  path) can stand in for the document.
- **Strict body.** A body over the cap, a transfer that fails part-way, or invalid UTF-8 is an
  error, never a shorter or normalized document.
- **One deadline** over the whole operation, DNS included (`CIMD_FETCH_TIMEOUT`, 5 s). Claude
  waits at most 10 s for the authorize endpoint, so the fetch it triggers must finish well inside
  that.
- **Typed failures** (`FetchError`). The caller can tell what is about the URL from what is about
  the moment (sorted in `classify_fetch_error`; see 3.5).

The CIMD layer sets the fetcher's cap to `CIMD_MAX_BYTES` (8 KB; the draft recommends under 5 KB,
and real ones are under 1 KB) in `fetch_client_metadata_document`. The fetcher enforces it
strictly (`FetchError::TooLarge`). `fetch_and_validate_client_metadata` then requires the
response to be served as `application/json` (`is_json_media_type`) before parsing it.

### 3.4 Validation

Validation splits into two kinds, and the split decides what may be cached (3.5):

- **Document-intrinsic** outcomes are about the URL alone, and their result is cacheable,
  positively or negatively. They are checked in this order:
  1. the fetch outcome: a fetch failure about the URL counts, one about the moment does not
     (`classify_fetch_error`; the lists are in 3.5);
  2. the media type;
  3. the document's content (below).
- **Per-request** checks depend on this request's `redirect_uri` and are never cached (the last
  paragraph of this section).

`parse_client_metadata` checks only what the document says about itself:

- The document's `client_id` equals the URL **byte for byte**, with no normalization.
- It carries no `client_secret` or `client_secret_expires_at`. A member of either name with any
  value, `null` included, is refused.
- It can authenticate as a **public** client. Either `token_endpoint_auth_method` is `none`
  (absent counts as `none`), or `none` appears in `token_endpoint_auth_methods_supported`, which
  is ChatGPT's form.
- `grant_types` and `response_types`, if present, include `authorization_code` and `code`.
- `redirect_uris` is non-empty, has at most `MAX_REDIRECT_URIS` entries, and each is at most
  `MAX_REDIRECT_URI_LEN` bytes.
- A member the server reads, of the wrong type (an explicit `null` included), makes the document
  invalid. The members it reads are `client_id`, `client_name`, `redirect_uris`,
  `token_endpoint_auth_method`, `token_endpoint_auth_methods_supported`, `grant_types`, and
  `response_types`. Every other member, `logo_uri` and the other display fields included, is
  ignored without a type check.
- Of the listed redirects, only those that pass `redirect_uri_permitted` **and** are either
  loopback or **same-origin with the document URL** are kept. If none are left, the document is
  invalid.
  - The same-origin rule goes beyond the original plan. The document is self-asserted, so this is
    what ties the code's destination to the party that published it.
  - It means a vetted CIMD origin cannot list another vendor's callback.

Per request, the requested `redirect_uri` must be one of the kept redirects (loopback
port-agnostically, per RFC 8252 §7.3) through the same `redirect_allowed` check a DCR registration
gets. This check runs on **every** request against the cached document and never feeds the
negative cache. Otherwise a probe with a bad redirect could lock out a real client.

### 3.5 Caching, coalescing, and bounds

All of this lives in one `CimdState` per **process**, shared by every mounted instance
(`CimdState::shared`). The bounds hold per process, and a document fetched for one mount serves
the other.

- **One cache, two kinds of entry.** `CimdState::cache` is keyed by the raw `client_id` URL. It
  holds at most `CIMD_CACHE_MAX` (512) entries, counting validated documents and negative entries
  together.
  - **When full** (`remember_client_metadata`), expired entries are dropped first. If that frees
    nothing, the entry closest to expiry is removed, whichever kind it is. This is earliest-expiry
    eviction, not LRU: no access recency is recorded, so a heavily used document can be evicted
    just because it expires first. (The code calls it an LRU stand-in; it was chosen because it
    needs no write per cache hit.)
- **Validated documents.**
  - **Lifetime.** The origin's remaining freshness is computed by `imcp2_core::public_fetch`
    (reported as `PublicDocument::cache_max_age`). It is `s-maxage`, else `max-age`, across every
    `Cache-Control` line combined, else `Expires` less `Date`. The response's current age (the
    larger of `Age` and the time since `Date`) is subtracted.
  - **Bounds.** `cimd_ttl` caps that at `CIMD_CACHE_MAX_TTL` (24 h). With no freshness
    information, it uses `CIMD_CACHE_DEFAULT_TTL` (10 min) less the response's age.
  - **No floor**, unlike the plan, which proposed one so that a hostile `max-age` could not force
    a re-fetch per request. The lifetime is zero, and the document is not reused
    (`fetch_and_cache_client_metadata` remembers only a non-zero lifetime), when any of these
    hold:
    - `no-store`, `no-cache`, or `private`;
    - `Vary: *`, or a `Cache-Control` or `Vary` line that cannot be decoded;
    - a zero or invalid `max-age`/`s-maxage`, or an invalid or past `Expires`;
    - freshness the response's age has already used up.

    So when an origin forbids reuse, a redirect the client withdraws is gone with the next request.
    A document cached with positive freshness stays authoritative until its lifetime runs out (10
    min by default, at most 24 h), so a withdrawal from such an origin takes effect only then. The
    accepted cost of having no floor: a valid document from an origin that forbids reuse is
    fetched on every request. That is the origin's choice, and it is contained like every other
    fetch, by single-flight and the in-flight bounds.
  - **No revalidation.** The plan's `ETag` handling was not built. No conditional
    (`If-None-Match`) request is made, so an expired entry is fetched again in full.
- **Negative entries.** A URL whose document fails a document-intrinsic check is held in the same
  cache as invalid for `CIMD_NEGATIVE_TTL` (60 s), so repeating the same bogus path costs no
  fetch. That covers:
  - the guard refusing the URL;
  - any non-`200` answer that is not retryable: a `404`, a redirect, another `4xx`, or a `2xx`
    other than `200` such as `204` or `206`;
  - an oversized or non-UTF-8 body;
  - the wrong media type;
  - a failed validation.

  Never remembered:
  - **transient failures** (`classify_fetch_error`): unresolved DNS, the deadline, a failed
    connection, a body transfer that fails part-way, a `5xx`, or the retryable `408`, `421`, `425`,
    `429`;
  - a refusal by the in-flight bounds below;
  - **per-request failures** (see 3.4).
- **Single-flight.** Concurrent requests that miss the cache for one URL share one fetch and its
  outcome (`Flight`), including a failure or an uncacheable document.
  - A fetcher cancelled mid-way hands over to a waiter.
  - Once the fetcher has its outcome, it retires the flight before publishing it, still under the
    flight's lock (`CimdState::retire_flight`). A request arriving after that goes to the cache or
    fetches afresh. It never joins the old flight to reuse a `no-store` document or a transient
    failure.
  - A flight that never publishes, because every request in it was cancelled, is removed by the
    last holder out (`FlightGuard`). Either way, only that flight's own entry is removed, never a
    newer one.
- **In-flight bounds.**
  - At most `CIMD_MAX_INFLIGHT` (16) fetches process-wide, and `CIMD_MAX_INFLIGHT_PER_HOST` (4)
    per exact `client_id` host (`HostSlot`, keyed by `host_key`, not by the vetted domain).
    Requests sharing a single-flight do not each take a slot.
  - A request over the bounds gets `MetadataUnavailable`; it is not queued.
  - There is **deliberately no rate cap**. An in-flight slot frees within the 5 s deadline. A rate
    budget, by contrast, is something a flood of made-up paths could use up to lock real clients
    out. Rate limiting, if wanted, goes in front of the server (see the README).
- **Logging.** A fetch failure at a vetted domain is logged at warn at most once a minute per
  domain (`CimdState::warn_permitted`), and the rest at debug.
  - `validate_client` adds one debug event per refused or unavailable request.
  - At the binary's default filter (`info`, unless `RUST_LOG` says otherwise), a caller rotating
    made-up paths therefore cannot flood the log.
  - With debug logging enabled, every failure is still logged and such a flood reaches the
    output.

### 3.6 One source of truth for "vetted vendor"

The CIMD trust gate reads the redirect allow-list itself (`vetted_domain` over
`allowed_redirects`, operator entries included). The gate keeps no vendor registry of its own.

Branding, as designed in #200 (see 4), does keep a curated domain list (`CONNECTORS` in
`src/branding.rs`).
- A test (`connector_domains_are_the_compiled_in_allow_list_vendors`) holds it equal to the
  compiled-in `DEFAULT_ALLOWED_REDIRECTS` domains.
- A redirect is branded only when a compiled-in entry admits it, so operator-added entries are
  never branded.

### 3.7 Advertisement

`authorization_server_metadata` advertises `client_id_metadata_document_supported` (true when
CIMD is enabled for the instance) and `token_endpoint_auth_methods_supported: ["none"]`. The
`registration_endpoint` stays advertised for DCR.

### 3.8 Configuration and rollout

- **Embedding hosts** set `McpConfig::cimd_enabled` per instance.
- **The `imcp2` binary** has it on for every instance unless `OAUTH_CIMD_ENABLED` is falsey
  (`0`, `false`, `no`, `off`; read once at startup by `cimd_enabled` in `src/main.rs`).
- **History.** #191 shipped CIMD opt-in (`OAUTH_CIMD_ENABLED=1`). #203 made it the default. The
  variable is now a roll-out kill switch, marked in the code for removal once CIMD has run in
  production for a while.
- **Rollback.** If a vendor's document turns out to be shaped in a way this implementation
  refuses, set `OAUTH_CIMD_ENABLED=0` and **redeploy**.
  - On the native deploy, the value is rendered into the systemd unit at deploy time
    (`deploy/native/deploy.sh`), so a restart or a changed variable alone leaves CIMD on.
  - A `workflow_dispatch` of the same ref is enough; no rebuild is needed.
  - Claude and ChatGPT both select CIMD as soon as an authorization server advertises it, and
    re-read the metadata within minutes, falling back to DCR.

## 4. Branding: overtaken by #103 and #200

The plan proposed keying the curated vendor name and logo on the CIMD `client_id` domain, on the
grounds that it is a cleaner, DNS-authenticated key than the redirect allow-list. That is not the
design that was adopted.

Branding is specified in #103 and implemented in #200, which is in review and not yet on main.
It keys on **the redirect validated for each connect**, and only for redirects admitted by a
compiled-in `DEFAULT_ALLOWED_REDIRECTS` entry. The reasons:

- **One key covers both registration modes.** DCR and CIMD clients alike, with no second code
  path.
- **For CIMD clients the redirect key is at least as strong, and for native clients it is the
  only sound one.**
  - **Web clients:** the two keys agree. 3.4 requires a hosted redirect to be same-origin with the
    document URL, so the redirect's origin is the `client_id`'s origin.
  - **Native clients:** the plan's key fails. Loopback redirects are exempt from the same-origin
    rule and are matched on any port, and a CIMD client is public, with no secret. Any local
    program can therefore present a vetted vendor's `client_id` with its own loopback port and
    pass validation. An example is Claude Code's `https://claude.ai/oauth/claude-code-client-metadata`.
    A `client_id`-keyed brand would show that program as the vendor.
  - The redirect key leaves every loopback connect anonymous. Loopback-only CIMD clients such as
    Claude Code therefore get no branding, which differs from what the plan intended.
- **Branding is narrower than the CIMD gate.** It ignores operator-added allow-list entries.
- **It answers the question that matters on the consent screen.** That question is where this
  connect's authorization code goes, and the redirect decides that. #103 also explains why
  nothing about branding may ride the connect link.

What carries over unchanged is the security spine: branding comes from the server's curated
table, never from the document's `client_name` or `logo_uri`. No CIMD document field is ever
displayed. `client_name` is parsed (a wrong-typed one invalidates the document) but never shown or
logged, and nothing reads the document's logo or icons. The spec's `icons` rules therefore never
come into play: the logo II would show is a bundled image the server serves itself.

**The plan's caveat still holds:** this server supplies only the key and the curated name and
logo. Showing them on the consent screen is Internet Identity's side, and #103 lists what II must
do. Until II renders them, #200's branding endpoints are inert.

## 5. Security analysis

- **SSRF.**
  - Only trust-gated origins are fetched.
  - Each fetch goes through the address-pinned, all-addresses-public, no-proxy fetcher, so a
    vetted vendor's DNS pointing at an internal address is still refused.
  - No redirect is followed, so a vetted URL cannot be bounced to another host, port, or path.
- **Outbound amplification (DoS).** The fetch hangs off the unauthenticated `/oauth/authorize`.
  The gate bounds it to the vetted domains, but not to a number of hosts or fetches. Each of these
  makes every URL a cache miss:
  - path variation on a vetted host (`https://claude.ai/a`, `/b`, …);
  - subdomain variation under a vetted domain (`https://x1.claude.ai/…`, `https://x2.claude.ai/…`),
    where each name is a separate host.

  **What bounds it:** the in-flight caps (16 process-wide, and 4 per exact host), single-flight
  per URL, the 60 s negative cache for repeated bogus paths, the redirect check before any fetch,
  and the 5 s deadline.

  **The residual:**
  - **Slots can be kept busy.** A sustained flood can occupy the slots, so a real client whose
    document is not cached may be told to retry. A cached document needs no slot, and the
    default lifetime is 10 minutes.
  - **Subdomain floods escape the per-host cap.** Because `HostSlot` is keyed by the full host,
    one domain's subdomains can take all 16 process-wide slots. A name that does not resolve is a
    transient failure, never negative-cached, so such a flood is bounded only by the process-wide
    cap and the 5 s deadline.
  - **Negative entries share the cache.** When it is full, the entry closest to expiry is
    evicted. Every negative entry expires within 60 s of being stored, so while a flood keeps the
    cache full, the victim is a negative entry unless a validated document has even less time
    left. A flood can therefore displace a validated document only in its last 60 s or so of
    life: at any moment for a document whose whole lifetime is that short, and near the end for
    any other. A document pushed out early needs a slot to be fetched again.
  - **The rate cap was dropped on purpose.** The plan called a concurrency *and rate* cap
    load-bearing here. As built, the load is carried by the in-flight bounds without a rate cap
    (see 3.5). That follows the project's treatment of availability hardening as discretionary,
    and a rate limiter in front of the server is the documented mitigation.
- **Phishing.** The posture is unchanged. The curated allow-list remains the defense. A
  self-asserted document admits no redirect a DCR client could not already register, and the
  same-origin rule (3.4) ties a CIMD client's hosted redirects to its own origin.
- **Display-field spoofing.** No CIMD-supplied field is ever displayed (see 4).
- **Client authentication.** Only public clients are supported. A document that requires a
  secret-based method is invalid, and the token exchange still requires the connect's PKCE
  (S256) verifier.
- **Confused deputy.** The browser-binding cookie (`CONNECT_COOKIE`) that ties a connect to the
  browser that started it is unaffected.

## 6. Phasing: outcome

- **Phase 0 (shared SSRF fetcher): done, in a different shape, and not behavior-neutral.** The
  plan was to extract discovery's fetcher into a shared module with no behavior change. Instead,
  `imcp2_core::public_fetch` was added on top of discovery's SSRF guard, which #191 changed in
  three ways:
  - `resolve_public_url` became crate-visible and returns a typed `ResolveError`, which separates
    a refused URL from a resolver outage. That is what lets a DNS failure be transient rather
    than cached as a refusal.
  - The byte-level `read_capped_bytes` was split out of discovery's lossy reader.
  - The shared public-address check was tightened, for discovery too. IPv6 is now refused by
    default outside `2000::/3`. Inside `2001::/23` only the IANA-listed globally reachable
    assignments pass. `3fff::/20` and `192.88.99.0/24` (except `192.88.99.2`) are refused. So the
    discovery crawl now refuses some addresses it used to accept.

  Discovery's redirect handling and fail-soft reading are unchanged. `public_fetch` adds the
  strict reader and the no-redirect policy.
- **Phase 1 (CIMD accept path): done.** Shipped in #191, defaulted on in #203.
  - The plan's elements all shipped: the trust gate, the SSRF-safe strict fetch, `client_id`
    string match, redirect membership plus path pin, structure checks, caching, and the
    metadata flag.
  - **Different from the plan:**
    - the trust gate matches a vetted domain or any dot-boundary subdomain of it, not an exact
      origin (see 3.1);
    - there is no cache floor and no `ETag` revalidation (see 3.5).
  - **Beyond the plan:** the same-origin redirect rule and the public-client checks.
  - **The acceptance criterion was revised rather than met as written.** The plan required a
    per-host and global concurrency and rate cap plus negative caching. What shipped has the
    in-flight caps, single-flight, and the negative cache, and deliberately drops the rate cap
    (see 3.5 and 5).
- **Phase 2 (branding): redesigned, in review.** Keyed on the validated redirect rather than the
  CIMD domain: specified in #103, implemented in #200, not yet on main. Nothing is displayed until
  Internet Identity renders it (see 4).
- **Phase 3 (CIMD beyond the trust policy): not planned.** Opening CIMD to general fetching would
  widen the outbound surface to arbitrary URLs. It needs a deliberate decision, and the in-flight
  bounds and negative cache would carry the whole load.

## 7. Compatibility

- **DCR at `/oauth/register` remains.** It is deprecated in the spec but not removed, and some
  real clients still send DCR bodies.
- **CIMD is purely additive.**
  - A URL `client_id` on a vetted origin uses CIMD.
  - A URL `client_id` on any other origin is refused (3.1).
  - Every other client ID is looked up as a DCR registration, as before.
- **With CIMD off**, a URL `client_id` is an unknown client, and the metadata stops advertising
  the mechanism, so clients fall back to DCR.

## 8. Decisions on the plan's open questions

| # | Question | Decision |
|---|---|---|
| 1 | Non-vetted URL `client_id`: reject, or fall back to DCR? | **Reject**, before any fetch, with the "not approved" page or `403 invalid_client` naming the contact (3.1). |
| 2 | One list or two? | **One for the gate.** It reads the hosted-redirect allow-list (3.6). Branding (#200) keeps a curated subset, held equal to the compiled-in domains by a test. |
| 3 | Cache lifetime and persistence | **In memory, per process.** Origin freshness capped at 24 h, default 10 min. **No floor**, so an origin that forbids reuse has a withdrawn redirect drop out on the next request (a document cached with positive freshness stays until it expires); the accepted cost is a fetch per request for such an origin, bounded by the in-flight caps. No `ETag` revalidation. One 512-entry cache holds validated and negative entries (60 s) together (3.5). |
| 4 | Is document membership enough, or keep the path pin? | **Keep the pin, and add more.** A kept redirect must pass `redirect_uri_permitted` and be loopback or same-origin with the document (3.4). |
| 5 | Response-size cap and array bounds | **8 KB** (the plan proposed 64 KB). `redirect_uris` bounded as in DCR: at most 16 entries of 2048 bytes each (3.3, 3.4). |
| 6 | Spec version pinning | The code follows the CIMD draft's requirements as named in section 1 and cites the draft by name, without a numbered revision. |
| 7 | `iss` interaction | None. RFC 9207 `iss` is unaffected, and the metadata advertises both. |

## 9. Tests (CIMD-specific)

In `src/auth.rs`:

- **Shape and identity:** `cimd_client_id_shape`, `cimd_client_id_is_taken_as_given`,
  `cimd_host_key_is_one_spelling_per_host`.
- **Document validation:** `client_metadata_parsing`. It runs on the real ChatGPT and Claude Code
  documents and covers the rules in 3.4.
- **Trust gate and authorization:** `cimd_origin_trust_policy`, `cimd_client_authorization`,
  `authorize_points_an_unvetted_cimd_origin_at_the_contact`,
  `authorize_tells_a_cimd_client_to_retry_when_its_document_is_unavailable`.
- **Fetch handling:** `cimd_fetch_error_classification`, `cimd_media_type`,
  `cimd_cache_ttl_is_bounded`.
- **Concurrency:** `cimd_fetches_are_coalesced_and_bounded_per_host`,
  `cimd_cancelled_fetcher_hands_over_to_a_waiter`, `cimd_cancelled_fetch_leaves_nothing_behind`,
  `cimd_flight_retirement_rules`, `cimd_state_is_shared_by_every_store`,
  `cimd_warnings_are_sampled_per_vendor`.
- **Advertisement:** `as_metadata_advertises_cimd_only_where_enabled`.

In `crates/imcp2-core/src/public_fetch.rs` (the strict fetch that 3.3 and 5 rely on):

- **Guard and deadline:** `guard_refuses_before_fetching`, `one_deadline_covers_the_whole_fetch`,
  `unresolvable_host_is_unreachable_not_refused`.
- **Response acceptance:** `accept_refuses_redirects_and_errors`,
  `accept_takes_only_a_complete_valid_body`.
- **Freshness:** `freshness_honours_age_and_every_cache_control_line`, `cache_control_lifetime`,
  `delta_seconds_is_ascii_digits_only`.

In `src/main.rs`: **kill switch**, `cimd_opt_out_values`.

## 10. Where it lives

- `src/auth.rs`, section "Client ID Metadata Documents (CIMD)":
  - constants: `CIMD_*`;
  - shape and gate: `cimd_client_id`, `parsed_as_given`, `cimd_origin_trusted`, `vetted_domain`,
    `host_key`;
  - document handling: `parse_client_metadata`, `is_json_media_type`, `cimd_ttl`,
    `classify_fetch_error`, `fetch_client_metadata_document`,
    `fetch_and_validate_client_metadata`;
  - state and outcomes: `CimdState`, `HostSlot`, `Flight`, `FlightGuard`, `CimdError`,
    `ClientCheck`;
  - the flow:
    - `AuthStore::validate_client`;
    - `AuthStore::client_metadata_for`;
    - `AuthStore::fetch_and_cache_client_metadata`, which applies the in-flight bounds, warn
      sampling, the negative lifetime, and skips the cache when the lifetime is zero;
    - `AuthStore::remember_client_metadata`;
  - advertisement: `authorization_server_metadata`.
- `crates/imcp2-core/src/public_fetch.rs`: `fetch_public_document`, `FetchError`,
  `PublicDocument`. `crates/imcp2-core/src/discover.rs`: `resolve_public_url`, `ResolveError`,
  `read_capped_bytes`.
- `src/lib.rs` (`McpConfig::cimd_enabled`) and `src/main.rs` (`cimd_enabled`,
  `OAUTH_CIMD_ENABLED`): configuration. `deploy/native/` renders the variable into the unit.
- `README.md` and `deploy/native/README.md`: the operator-facing description and the
  `OAUTH_CIMD_ENABLED` entry.
