# Scoping: Client ID Metadata Documents (CIMD) for imcp2

Status: **draft / scoping**. Analysis and design only; no code changes land in
this document. It expands the top-ranked improvement from the MCP 2026-07-28
alignment scoping doc (PR #126, `docs/scoping-mcp-2026-07-28-alignment.md`; #1,
"CIMD replacing open DCR") into an implementable plan, and folds in the
correction from that PR's review: imcp2's existing same-origin URL check
(`skills.rs`'s `markdown_url_for_base`) is **not** a usable SSRF guard for a
CIMD fetch — the real building block is the address-pinned fetcher in
`discover.rs`.

Spec-strength labels (MUST / SHOULD / MAY) below follow the 2026-07-28 revision's
authorization section and the OAuth **Client ID Metadata Document** draft it
references. The exact draft version should be pinned before implementation (see
[Open questions](#8-open-questions--decisions)).

## Headline recommendation

Adopt CIMD **trust-policy-gated and additive**: imcp2 fetches a Client ID
Metadata Document **only when the `client_id` URL's host is already on the
curated vendor trust policy**, keeps open DCR for everything else, and never
trusts the document's display fields. This delivers the two real wins — spec
alignment and a DNS/TLS-authenticated domain key for branding — while collapsing
the new outbound-fetch surface to a finite set of vetted hosts instead of an
arbitrary-URL SSRF primitive on the unauthenticated `/authorize` path.

- **Impact:** High (spec alignment + non-spoofable branding key).
- **Effort:** Medium.
- **Tractability:** High — imcp2-only for the core (no rmcp, no II). Only the
  branding *display* half needs II coordination.

---

## 1. What CIMD is, and the spec obligations

Under MCP 2026-07-28, Dynamic Client Registration (RFC 7591) is **DEPRECATED**
and CIMD is the intended replacement. Instead of POSTing a registration body and
receiving a server-minted `client_id`, a client presents its `client_id` **as an
`https` URL** that resolves to a JSON metadata document (`client_name`,
`redirect_uris`, `logo_uri`, …). The identity is then **DNS/TLS-authenticated**:
nobody can serve a document at `https://chatgpt.com/…` without controlling that
domain.

Authorization-server obligations (paraphrased; pin exact strengths at
implementation time):

- **SHOULD** support CIMD and advertise
  `client_id_metadata_document_supported: true` in AS metadata.
- On a URL-form `client_id`, the AS **SHOULD** fetch the document, **MUST**
  validate `client_id` equals the fetched URL exactly, **MUST** validate the
  request's redirect URI against the document's `redirect_uris`, and **MUST**
  validate the JSON structure / required fields.
- **SHOULD** cache per the response's HTTP cache headers.
- **SHOULD** consider SSRF when fetching an attacker-influenced URL.
- **MAY** implement a domain-based trust policy (the hook this design leans on).

CIMD provides **no signing or attestation** of the document's contents — the
display fields (`client_name`, `logo_uri`) are exactly as spoofable as a DCR
body. The only cryptographically meaningful fact is the **host** of the URL.

## 2. Where imcp2 stands today

**Open DCR.** `POST /oauth/register` (`auth.rs:2095`, unauthenticated) stores a
`ClientReg` of `redirect_uris` (`auth.rs:175`) under a server-minted
`client-<uuid>`. The store is bounded (`MAX_CLIENTS` = 10 000, `auth.rs:137`;
`MAX_REDIRECT_URIS` = 16, `auth.rs:147`), LRU-evicted, and atomically persisted.

**Phishing defense = a hosted-redirect allow-list.** `DEFAULT_ALLOWED_REDIRECTS`
(`auth.rs:434`) is a curated list of `(vendor-host, callback-path-prefix)` pairs;
`redirect_uri_permitted` (`auth.rs:545`) enforces host **and** a pinned path
(MCP05 / CWE-601 hardening), at both register time and authorize time
(`validate_client`, `auth.rs:834`; `redirect_allowed`, `auth.rs:643`). Loopback
is exempt (RFC 8252). `allowed_redirects()` (`auth.rs:457`) is overridable via
`OAUTH_ALLOWED_REDIRECT_PREFIXES`.

**AS metadata.** `authorization_server_metadata` (`auth.rs:2179`) advertises the
`registration_endpoint` (`auth.rs:2185`), `authorization_code` grant, and S256.

**An SSRF-safe outbound fetcher already exists — but it is private and
discovery-specific.** `discover.rs` fetches attacker-influenced app URLs safely:

- `resolve_public_url` (`discover.rs:1106`): `https`-only, resolves the host and
  rejects the fetch unless **every** resolved address is globally routable
  (`ip_is_global`, `discover.rs:1056`, hardened against IPv6 transition prefixes
  in PR #133).
- `site_client` (`discover.rs:1182`): a reqwest client **pinned to the
  pre-validated addresses** (`resolve_to_addrs`), so no re-resolution can rebind
  the connection to an internal address between validation and connect; 15 s
  timeout; `ssrf_redirect_policy` (`discover.rs:1160`) that follows only bounded,
  `https`, global-IP-or-same-host redirects.
- Response-size caps and chunked reads (`discover.rs:1202-1205`) so a hostile
  body can't exhaust memory.

This is the correct foundation for a CIMD fetch. `skills.rs`'s
`markdown_url_for_base` is **not**: it only compares a candidate host against a
fixed trusted origin (ignoring ports) and rejects `169.254.169.254` merely
because that host differs from the skills origin — a protection that evaporates
when the URL is itself attacker-selected.

## 3. Design: trust-policy-gated, additive CIMD

### 3.1 The gating decision (the crux)

**Fetch a CIMD only when the `client_id` URL's host is on the trust policy.** A
URL `client_id` whose host is *not* vetted is not fetched at all.

Why gate rather than fetch any URL:

- It reduces the new SSRF/DoS surface from "any URL an unauthenticated caller
  supplies to `/authorize`" to "a finite, curated set of vendor hosts."
- It still yields both payoffs: standards alignment, and a DNS-authenticated
  domain to key branding on.
- It matches imcp2's current posture — the allow-list already makes DCR
  effectively "closed." Non-vetted clients simply keep using DCR.
- It is forward-compatible: [Phase 3](#6-phasing) can open CIMD to general
  (still SSRF-guarded) fetching if the ecosystem moves and the risk is accepted.

### 3.2 Request flow

At `/oauth/authorize` (`auth.rs:1012`), branch on the shape of `client_id`:

1. **Opaque `client-<uuid>`** → the existing DCR path (`validate_client`),
   unchanged.
2. **`https` URL** →
   - If the host is **not** on the client-id trust policy → **reject** with a
     clear error naming the contact for allow-listing (mirroring the DCR
     hosted-redirect rejection). *(Reject vs silent DCR-fallback is an open
     question — see §8.)*
   - If on the policy → fetch the document through the SSRF-safe fetcher (§3.3),
     then validate (§3.4). On success, treat the verified URL as the
     `client_id` for the rest of the code+token flow; cache the document (§3.5).

### 3.3 The fetcher (Phase 0 prerequisite)

Reuse the `discover.rs` machinery rather than writing a second SSRF guard.
Because those functions are currently private to `discover.rs`, **Phase 0** is a
small refactor: extract `resolve_public_url` / `site_client` /
`ssrf_redirect_policy` / the capped-read helper into a shared `pub(crate)`
module (e.g. `src/net.rs`). No behavior change; independently useful.

CIMD-specific fetch parameters:

- `GET`, `Accept: application/json`; require a JSON content type on the response.
- A **tighter response-size cap** than discovery's 256 KB metadata cap — a CIMD
  is a few KB; propose 64 KB.
- Keep the 15 s timeout, address pinning, `https`-only, and bounded redirects.

### 3.4 Validation

- `client_id` **exactly equals** the fetched URL (post-normalization the same
  way redirects are compared).
- The request's `redirect_uri` is a member of the document's `redirect_uris`
  **and** still passes `redirect_uri_permitted` (`auth.rs:545`). Keeping the
  existing host+path pin is deliberate belt-and-suspenders: if a vetted vendor's
  domain is ever compromised, the path pin still limits where a code can land.
- The JSON parses, required fields are present and well-typed, and arrays are
  size-bounded (same spirit as `MAX_REDIRECT_URIS`).

### 3.5 Caching

- Cache **validated** documents keyed by the `client_id` URL, honoring
  `Cache-Control` / `ETag` with a **TTL floor and ceiling** so a hostile
  `max-age` can neither pin a stale doc forever nor force a re-fetch per request.
- Bounded LRU, like the DCR store. **In-memory only** is likely sufficient (a
  cache miss just re-fetches), unlike DCR registrations which must survive a
  restart — but confirm (§8).

### 3.6 Re-keying the allow-list

Introduce a **client-id-host trust policy** (the spec's "domain allowed via
trust policy"). Recommendation: derive it from the *same curated vendor set*
that backs `DEFAULT_ALLOWED_REDIRECTS` (`auth.rs:434`) so there is one source of
truth for "who is a vetted vendor," rather than a second independent list.
`redirect_uri_permitted` continues to gate the redirect leg.

### 3.7 Advertise support

Add `client_id_metadata_document_supported: true` to
`authorization_server_metadata` (`auth.rs:2179`).

## 4. How this subsumes the branding work

The one non-spoofable fact CIMD yields is the **`client_id` domain**
(DNS/TLS-authenticated). Key the curated vendor name/logo table on that domain —
**never** on the document's `client_name`/`logo_uri`, which carry no attestation.
This is precisely the security spine of the client-branding scoping proposal
(PR #103) — branding derived from the vetted vendor, never from client-supplied
metadata — but with a cleaner cryptographic key than the redirect-path
allow-list.

Caveat: CIMD unblocks the *key*, not the *display*. Rendering the connecting
client's name/logo on the consent screen is II-side, and II must apply the spec's
`icons` security rules (HTTPS/`data:` only, MIME allow-list, no inlined SVG).
That half still needs II coordination.

## 5. Security analysis

- **SSRF:** gated to trust-policy hosts, so no arbitrary-URL fetch — and even a
  vetted host is fetched through the address-pinned, all-IPs-global fetcher, so a
  compromised/misconfigured vendor DNS pointing at an internal address is still
  rejected.
- **DoS (outbound amplification):** the fetch hangs off the *unauthenticated*
  `/authorize` path. Gating bounds it to known hosts; the validated-document
  cache turns repeat `/authorize` calls for a vetted `client_id` into cache
  hits; add a global concurrency/rate cap on outbound CIMD fetches so a burst
  can't fan out. (Consistent with this project's stance that availability
  hardening is discretionary, but cheap here.)
- **Phishing:** unchanged posture. The curated trust policy remains the phishing
  defense; CIMD only re-keys it from redirect-URI-host to the DNS-authenticated
  client-id-host. Mandatory consent-screen hostname display stays.
- **Display-field spoofing:** never trust `client_name`/`logo_uri`; brand from
  the vetted vendor keyed on the verified domain.
- **Confused deputy:** the existing `sid`-cookie consent binding is unaffected.

## 6. Phasing

- **Phase 0 — shared SSRF fetcher.** Extract the `discover.rs` fetcher into a
  `pub(crate)` module. No behavior change.
- **Phase 1 — CIMD accept path.** URL-form `client_id` in `/oauth/authorize`:
  trust-policy gate → SSRF-safe fetch → validate (`client_id`==URL, redirect
  membership + path pin, JSON structure) → cache. Add the client-id-host policy.
  Advertise the metadata flag. **Keep DCR** as deprecated backward-compat.
- **Phase 2 — branding.** Key the vendor name/logo table on the verified domain;
  coordinate the display rules with II.
- **Phase 3 — (optional, later).** Open CIMD beyond the trust policy to general
  SSRF-guarded fetching, if/when the ecosystem moves and the added surface is
  accepted.

## 7. What stays the same (compatibility)

DCR at `/oauth/register` remains (deprecated, not removed before 2027-07-28):
real clients — chatgpt.com, claude.ai, cursor.com, and so on — will keep sending
DCR bodies for a long time. CIMD is **purely additive**: a client presenting a
URL `client_id` on a vetted domain uses CIMD; everything else uses DCR.

## 8. Open questions / decisions

1. **Non-vetted URL `client_id`:** hard reject, or silently fall back to DCR? A
   reject is clearer and avoids a confusing partial-support surface; a fallback
   is more permissive. Recommend reject with an allow-listing contact.
2. **One list or two:** reuse the `DEFAULT_ALLOWED_REDIRECTS` vendor set as the
   client-id-host policy, or maintain a separate list? Recommend one source of
   truth.
3. **Cache lifetime & persistence:** in-memory only vs persisted; TTL floor /
   ceiling values; cache size cap.
4. **Redirect validation strictness:** is document membership sufficient for a
   vetted domain, or keep the additional `redirect_uri_permitted` path pin?
   Recommend keep it.
5. **Response-size cap** for a CIMD (proposed 64 KB) and array-length bounds.
6. **Spec version pinning:** which exact CIMD draft the 2026-07-28 revision
   references, and any normative fields beyond the ones named here.
7. **`iss` interaction:** none expected (RFC 9207 `iss` already shipped), but
   confirm the metadata document and the authorization response don't collide.

## Citations

- DCR / client store: `auth.rs:2095` (`register`), `auth.rs:2058`
  (`RegisterRequest`), `auth.rs:175` (`ClientReg`), `auth.rs:137`/`147` (bounds).
- Allow-list: `auth.rs:434` (`DEFAULT_ALLOWED_REDIRECTS`), `auth.rs:457`
  (`allowed_redirects`), `auth.rs:545` (`redirect_uri_permitted`), `auth.rs:614`
  (`is_wellformed_hosted_redirect`), `auth.rs:643` (`redirect_allowed`).
- Flow: `auth.rs:1012` (`authorize`), `auth.rs:834` (`validate_client`).
- AS metadata: `auth.rs:2179` (`authorization_server_metadata`), `auth.rs:2185`
  (`registration_endpoint`).
- SSRF-safe fetcher: `discover.rs:1106` (`resolve_public_url`), `discover.rs:1182`
  (`site_client`), `discover.rs:1160` (`ssrf_redirect_policy`), `discover.rs:1145`
  (`redirect_hop_ok`), `discover.rs:1056`/`1063`/`1079`
  (`ip_is_global`/`ipv4`/`ipv6`), `discover.rs:1202-1205` (size caps).
