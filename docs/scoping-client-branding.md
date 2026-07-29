# Scoping: surface the MCP client's product identity to Internet Identity (product name + logo)

Status: **draft / scoping** (2026-07-29). Analysis and design only, no code changes here.
Requires a coordinated counterpart change on the Internet Identity (`id.ai`) side; this
document defines the boundary contract for both.

## 1. Goal

When a user is bounced to `id.ai` to authorize a connect, Internet Identity today has **no
idea which MCP client** is asking. The consent screen is effectively anonymous: the user is
granting their real II accounts to "some bridge" with no name or mark to anchor the decision.

This extension lets II display **which vetted product** is requesting the connect (a name and a
logo), so the user consents with an informed picture of who is asking. Two parts:

1. The MCP server **provides a product-name string** to `id.ai/mcp` (in the connect link).
2. The MCP server **serves a logo associated with that product name** as a separate request that
   II makes back to the server's origin.

Two decisions frame everything below:

- **Branding is shown for allow-listed / vetted products only.** Client-supplied name and logo
  are never rendered (see 3).
- **The identifier is a curated product-name string, never a `client_id`.** Client IDs are not
  stable, so nothing keys on them (see 4).
- **v1 brands self-authenticating web connectors only.** Native / desktop apps (Claude Desktop,
  etc.) authenticate over loopback, which carries no verifiable identity, so they stay anonymous
  for now (see 4, "v1 scope").

## 2. Where this plugs into the current flow (verified, file:line)

- **The connect link** (`ii_mcp_url`, `auth.rs:1062`):
  `"{ii}/mcp#callback=...&state=...&ttl=...&registration_key=..."`. Everything rides the URL
  **fragment**, so it never goes on the wire; II reads it from `location.hash`. This is where the
  product-name string is added.
- **The authorize handler** (`authorize`, `auth.rs:865`): before building the link it has already
  validated the request's `redirect_uri` (`validate_client`, `auth.rs:890`). That `redirect_uri`
  is the direct, authoritative signal of product identity (see 4), so the product name is
  resolved right here.
- **The origin II already trusts for this connect** (`#4091`, `auth.rs:1082-1109`): before
  honoring a callback, II fetches `<callback origin>/.well-known/ii-auth-callbacks`
  (fail-closed, exact string match, 8 KB cap, CORS, `no-store`) and requires the callback to be a
  declared entry. That establishes the callback **origin** as a validated, server-controlled
  endpoint, which is exactly what the logo fetch reuses (II contacts no origin it has not already
  validated).
- **The vetting set already in the code** (`DEFAULT_ALLOWED_REDIRECTS`, `auth.rs:399`; gate
  `redirect_uri_permitted` via `allowed_redirects()` + `path_within_prefix`): the hosted-redirect
  allow-list of `(domain, path-prefix)` pairs the server already trusts, seeded with the real
  connector vendors. This is the source of truth for which products exist and get branding.

## 3. Vetting model: branding for allow-listed products only

Dynamic client registration is **unauthenticated and open** (`POST /oauth/register` takes all
callers, `auth.rs:1888`). So any client-supplied `client_name` / `logo_uri` is attacker-
controlled. Rendering it on a consent screen would be a phishing gift: a hostile client
registers `client_name: "Internet Identity"` with a lookalike mark and the user sees a spoofed,
trusted-looking prompt.

Decision (locked with the requester): **show branding only for vetted products, and source both
the name and the logo from a server-side curated table, never from client-supplied data.**
Consequences:

- The **displayed name and logo are curated by us**. An attacker registering
  `client_name: "Internet Identity"` is simply ignored, because we never surface client-supplied
  strings or images.
- A request that does not resolve to a vetted product gets the **status-quo anonymous consent
  screen**. Nothing regresses; it just gets no name/logo.
- There is **no open logo proxy** and **no SSRF surface** in v1: we never fetch an arbitrary
  client `logo_uri`. Logos are compiled-in assets (like the DFINITY logo already inlined into the
  callback page via `include_str!`, `auth.rs:1161`).

## 4. The identifier is a product name, not a `client_id`

`client_id`s are **not a durable identity**, so nothing in this design keys on them:

- Minted fresh per registration: `client-{uuid_v4}` (`auth.rs:1913`), a new random value each
  time anyone registers.
- Stable only for the life of one cached registration, and it churns everywhere else: reinstall
  / "remove the connector and add it again" (which the server's own error copy instructs,
  `auth.rs:923`) / expiry all mint a new id; the store is LRU-evicted at `MAX_CLIENTS` so an idle
  client is dropped and re-registers with a new id (`make_room_for_client`, `auth.rs:340`); and it
  is per-registration, not per-vendor, so one product maps to many ids across users and devices.

**Product identity comes from the vetted redirect vendor instead**, which is stable and already
curated. At authorize time the server matches the request's already-validated `redirect_uri`
against `allowed_redirects()`; a match yields a **curated product slug** (a short stable string
such as `chatgpt`, `claude`, `cursor`, `grok`, `perplexity`, `antigravity`), each mapped to a
human display name and a bundled logo:

| Allow-list domain (`auth.rs:399`) | Product slug | Display name |
|---|---|---|
| `chatgpt.com` | `chatgpt` | ChatGPT |
| `claude.ai` | `claude` | Claude |
| `cursor.com` | `cursor` | Cursor |
| `grok.com` | `grok` | Grok |
| `perplexity.ai` / `perplexity.com` | `perplexity` | Perplexity |
| `antigravity.google` | `antigravity` | Google Antigravity |

A client can only obtain a vetted `redirect_uri` if it genuinely is that vendor (it cannot
register a `chatgpt.com` OAuth callback it does not control, per the path-pinned allow-list at
`auth.rs:383-391`), so the redirect vendor is a sound proxy for product identity. The slug is
**server-determined**, never taken from the client.

### v1 scope: self-authenticating web connectors only

There are two classes of MCP client, and only one can be vouched for:

- **Web / cloud connectors** (claude.ai web, ChatGPT, Cursor, Grok, Perplexity) authenticate
  themselves by their redirect domain: a client cannot register a
  `claude.ai/api/mcp/auth_callback` redirect unless it genuinely is Claude (the path-pinned
  allow-list, `auth.rs:383-391`). These are the products in the table above, and they are what v1
  brands.
- **Native / desktop apps** (Claude Desktop, Cursor desktop, and the like) do OAuth with
  **loopback** redirects (`http://127.0.0.1:port/...`), which carry no vendor identity (loopback is
  exempt from the allow-list wholesale, `auth.rs:393`). The only identity signal they offer is the
  unauthenticated `client_name` they claim at registration, which a hostile local app could forge
  to inherit a trusted product's mark. So **native apps deliberately stay anonymous in v1** (the
  status-quo consent screen); the vetted-only rule (see 3) is worth more than covering them with a
  spoofable signal. Authenticating a native app needs a signed `software_statement` (RFC 7591) per
  vendor, deferred to a later phase (see 9).

## 5. The extension contract

### 5.1 MCP-server side (this repo)

1. **Resolve the product at authorize time.** In `authorize` (`auth.rs:865`), after
   `validate_client`, match `q.redirect_uri` against `allowed_redirects()` to get the product
   slug (or none for an unvetted redirect).
2. **Put the product slug in the connect link.** `ii_mcp_url` (`auth.rs:1062`) appends
   `&connector={slug}` to the fragment when a slug resolved; omit it otherwise. Additive: an II
   that does not know the param ignores it (see 8). The slug is not secret, so the fragment
   placement (consistent with the other params) is fine.
3. **Serve the name and logo by slug.** Two small unauthenticated GET endpoints on the same
   origin as the `#4091`-validated callback (see 6), each validating the slug against the fixed
   curated set before responding.

### 5.2 Internet Identity (`id.ai`) side (coordination required)

This is an extension to the connect contract, in the same family as `#4091` (callback allow-list)
and `#4093` (`registration_key`). II must:

1. Parse the `connector` slug from the connect-link fragment.
2. Derive the callback origin (already parsed for the `#4091` check) and fetch the product
   metadata + logo from that origin at the agreed paths (see 6). Only the already-validated
   callback origin is contacted, so no new allow-list is needed.
3. Render the name + logo on the consent screen with a **"verified connector"** treatment, and
   fall back to today's anonymous screen when the slug is absent or the fetch 404s.

## 6. Endpoints

Rooted at the instance issuer (`connect_callback_url` derives from `store.issuer()`,
`auth.rs:1088`), so they are same-origin with the callback II already trusts.

- **`GET {issuer}/branding/{slug}`** returns a tiny JSON metadata document for a vetted product,
  e.g. `{ "name": "ChatGPT", "logo": "<issuer>/branding/chatgpt/logo", "verified": true }`.
  `404` for any slug outside the curated set. Served with CORS (II fetches cross-origin, mirroring
  `auth_callbacks`, `auth.rs:1097`) and `no-store`.
- **`GET {issuer}/branding/{slug}/logo`** returns the bundled image bytes (SVG is fine: served as
  `image/svg+xml`), with `X-Content-Type-Options: nosniff` and a cache header. `404` otherwise.
  **II must render it via a fixed-size `<img src=...>`, never by inlining the SVG markup into the
  consent DOM**: an external SVG loaded through `<img>` cannot execute script, whereas inlined SVG
  can (see 7). No CORS is needed for `<img>` rendering.

The slug is matched against the fixed curated set before anything is served, so the path segment
cannot be used for traversal or to probe arbitrary keys.

## 7. Security

- **No client-supplied content is rendered, and no client-supplied identifier is trusted.** Both
  the slug and the displayed name/logo are server-determined from the vetted vendor (see 3, 4).
  This removes the consent-phishing vector at the root rather than trying to label it.
- **No SSRF.** v1 bundles logos; it never fetches a client `logo_uri`. If open self-service
  branding is ever added, it must reuse the SSRF-pinned client from `discover.rs`, be https-only,
  size- and dimension-capped, content-type allow-listed to raster (`png`/`jpeg`/`webp`), reject or
  fully sanitize SVG (SVG can carry script), and decode-then-re-encode to strip payloads.
- **Bounded, closed slug space.** Both GETs serve only from the fixed curated set; an unknown slug
  is a `404`. Responses are small, cacheable, and served from compiled-in assets.
- **Logo rendering on II (the one II-side must).** SVG is acceptable as the logo format, but only
  if II renders it through a fixed-size `<img src=...>`. It must never inline server-returned SVG
  into the consent DOM: inlined SVG can execute script, an `<img>`-loaded SVG cannot. (A raster
  logo would sidestep the concern entirely, but `<img>`-rendered SVG is safe and keeps the crisp
  vector mark.)
- **CORS / caching** mirror the `#4091` well-known: `Access-Control-Allow-Origin` for the JSON
  metadata (II uses `fetch`), and `no-store` so an intermediary cannot serve a mapping stale after
  a curation change.

## 8. Backward compatibility

Every piece is additive:

- An **old II** ignores the unknown `connector` fragment param and never calls the new endpoints,
  so connects behave exactly as today.
- An **old MCP server** (no endpoints, no param) simply omits the slug, so a new II falls back to
  the anonymous consent screen.
- **Unvetted clients** are unaffected: no slug, no name, no logo, same flow as now.

## 9. Work breakdown

- **Phase 1 (server).** Add the curated product table (slug -> display name + compiled-in logo
  asset) alongside the existing vendor allow-list, resolve the slug from `redirect_uri` in
  `authorize`, append `&connector={slug}` in `ii_mcp_url`, and add the two `/branding/{slug}`
  GET endpoints. Ship logos as bundled assets. Tests: redirect-to-slug resolution (hits and
  misses, including the env-added redirects), endpoint content types and 404 for unknown slugs,
  CORS/`no-store` headers.
- **Phase 2 (II coordination).** Agree the fragment param name (`connector`) and endpoint paths
  with the II team; II parses the slug, fetches metadata + logo from the callback origin, and
  renders the verified-connector treatment with an anonymous fallback.
- **Phase 3 (optional, later).** Extend coverage beyond self-authenticating web connectors, only
  if there is demand:
  - **Native / desktop apps** (Claude Desktop, etc.) via a signed `software_statement` (RFC 7591):
    the vendor issues a JWT asserting the product, the server verifies it against the vendor's
    known key, and only then does the app earn its slug. This is the authenticated way to close the
    gap left open in 4 ("v1 scope").
  - **Open self-service branding** via a reviewed `logo_uri`, with the full SSRF/sanitize pipeline
    in 7.

## 10. Open questions for the II team

1. Final name for the fragment param (`connector`) and the endpoint paths (`/branding/{slug}`).
2. Confirmation that II can render the logo via a fixed-size `<img src=...>` (SVG is the intended
   format; this is the one hard II-side requirement, see 6/7).
3. Exact consent-screen treatment for "verified connector" vs the anonymous fallback, and whether
   II wants the name via the JSON metadata doc or also mirrored in the fragment.
4. Whether II wants a single metadata document (name + logo URL together) or separate name and
   logo requests.
