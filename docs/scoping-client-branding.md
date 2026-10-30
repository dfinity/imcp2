# Scoping: surface the MCP client's product identity to Internet Identity (product name + logo)

Status: **scoping, revised 2026-09-24**. The imcp2 server side is implemented in
dfinity/imcp2#200. This document is the boundary contract that the Internet Identity (`id.ai`)
counterpart builds against.

Two conventions:

- Code is referenced by symbol (file plus function, type, or constant), never by line number,
  so the references survive edits.
- Bare numbers follow one rule: #191 and #200 are imcp2 PRs (dfinity/imcp2); #4091 and #4093
  are Internet Identity issues (dfinity/internet-identity).

> **What changed since the first draft (2026-07-29).** The first draft put the product slug in
> the connect-link fragment (`&connector=<slug>`) and served `GET {issuer}/branding/{slug}` to
> anyone. That let a consent screen vouch for a product the server never tied to the connect
> (see 5). The contract below replaces it: II asks the server, **by the connect's `state`**,
> which product this connect is for, and the server answers from its own record of the redirect
> it validated. **Nothing about branding rides the link.**

## 1. Goal

When a user is bounced to `id.ai` to authorize a connect, Internet Identity today has **no idea
which MCP client** is behind it. The consent screen names the server (its verified origin and
the `name` from its `/.well-known/ii-app-metadata` document), but nothing says which product the
connect is for. The user grants their real II accounts to a bridge on behalf of an unnamed
client.

This extension lets II show **which vetted product will receive the access this connect grants**
(a name and a logo), so the user consents knowing where their accounts are going. It has two
parts:

1. II asks the MCP server about **the one connect it is showing**:
   `GET {issuer}/branding?state={state}` returns the curated display name and a logo URL, or
   `404` when the connect is not for a vetted product.
2. The logo URL points at a **static, compiled-in image** on the same server.

Four decisions frame everything below:

- **Branding is shown for vetted products only.** Client-supplied names and logos are never
  rendered (see 3).
- **The server decides, per connect.** The answer comes from the `redirect_uri` that the server
  validated and recorded for that connect. Nothing the client or the link asserts is trusted
  (see 4, 5).
- **Product identity is never keyed on a `client_id`.** Client IDs are not durable identities;
  the product comes from the connect's validated redirect instead (see 4).
- **v1 brands redirect-identified web connectors only.** Native and desktop apps (Claude
  Desktop, etc.) authenticate over loopback, which carries no verifiable identity, so they stay
  anonymous for now (see 4, "v1 scope").

## 2. Where this plugs into the current flow

- **The connect link** (`iiconnect::ii_mcp_url` in `crates/imcp2-core`, built by `authorize` in
  `src/auth.rs`) has the form `{ii}/mcp#callback=…&state=…&ttl=…&registration_key=…`.
  - Everything rides the URL **fragment**, which II reads from `location.hash`.
  - `state` is the pending-connect id, `sess-{uuid v4}`, minted by `authorize`.
  - After consent, II navigates the tab back to `callback` with
    `#delegation=…&state=…` in the fragment.
  - **Branding adds nothing to the link.** II already parses `state` and `callback` for the
    connect itself; the branding lookup reuses both.
- **The pending connect** (`AuthzPending`, held in `AuthStore`'s pending-connect map) is where
  `authorize` records the connect's `redirect_uri`.
  - The redirect is validated first. `validate_client`, which `authorize` runs on every request,
    checks it against the client's registration (DCR) or metadata document (CIMD). It applies
    `redirect_uri_permitted` itself: through `redirect_allowed`, and for CIMD also before the
    document is fetched. A redirect that has left the allow-list is therefore refused even for a
    client that registered earlier.
  - The entry lives for `CONNECT_TTL` (600 s) from `authorize`. It survives
    `/oauth/connect/redeem` and is removed when the code is successfully exchanged at
    `/oauth/token`. A failed exchange (client_id or PKCE mismatch) uses up the code but leaves
    the entry until it expires.
  - Before it expires, the entry can also be dropped by the pending-connect cap
    (`insert_pending` → `make_room` evicts the entry with the least remaining lifetime when the
    map is full) or by a server restart, since the map is held in memory. The expiry sweep
    (`reap_expired`) only reclaims entries already past `CONNECT_TTL`.
  - Branding reads this record **read-only** (`AuthStore::pending_redirect_uri`).
- **Code delivery.** A connect's authorization code is minted at `/oauth/connect/redeem` and
  sent only to the `redirect_uri` recorded for it (`connect_redeem` → `build_redirect`).
  - Redemption is refused unless the browser presents that connect's binding cookie
    (`CONNECT_COOKIE`, set at `authorize`).
  - Redemption also uses that connect's own registration key, so a delegation minted for a
    different key does not redeem it.
  - This is why the recorded redirect answers the security-relevant question: **it names who
    receives this connect's authorization code**. It does not prove who started the connect
    (see 4).
- **The origin II has already validated for this connect** (#4091, served by `auth_callbacks`).
  - Before honoring a callback, II fetches `<callback origin>/.well-known/ii-auth-callbacks`
    (fail-closed, exact string match, 8 KB cap, CORS, `no-store`) and requires the callback to
    be a declared entry.
  - Every declared callback is `{issuer}/oauth/connect/callback` (`connect_callback_url`), and
    the branding endpoints are rooted at that same `{issuer}` (see 6).
  - This validation proves only that the origin *declared* the callback, not that it is an
    honest imcp2 deployment. Whether to show the verified-connector treatment is II's own trust
    decision (see 6.2, requirement 4, and 7).
- **The vetting set** is `DEFAULT_ALLOWED_REDIRECTS` in `src/auth.rs`: the compiled-in list of
  `(domain, path, pin)` callback entries for the real connector vendors.
  - `redirect_uri_permitted` admits a redirect against this list plus any operator entries
    from `OAUTH_ALLOWED_REDIRECT_PREFIXES`.
  - Branding admits only the compiled-in entries (`redirect_uri_on_default_allow_list`), so
    operator entries are never branded (see 4).

## 3. Vetting model: branding for vetted products only

Dynamic client registration is **unauthenticated and open**: `POST /oauth/register` takes all
callers. Any client-supplied `client_name` or `logo_uri` is therefore attacker-controlled.
Rendering it on a consent screen would be a phishing gift: a hostile client registers
`client_name: "Internet Identity"` with a look-alike mark, and the user sees a spoofed,
trusted-looking prompt.

Decision (locked with the requester): **show branding only for vetted products, and source both
the name and the logo from a server-side curated table, never from client-supplied data.** This
has three consequences:

- **We curate the displayed name and logo.** An attacker who registers
  `client_name: "Internet Identity"` is simply ignored, because client-supplied strings and
  images are never surfaced.
- **A connect that does not resolve to a vetted product gets the anonymous consent screen it
  gets today.** Nothing regresses; it just gets no name or logo.
- **There is no open logo proxy and no SSRF surface** in v1. The server never fetches a
  client's `logo_uri`. Logos are compiled-in assets, like the DFINITY logo already inlined into
  the callback page with `include_str!`.
  - Today every connector shares one neutral placeholder mark: original artwork, deliberately
    not a vendor's logo, since reproducing one is a trademark and licensing question this repo
    should not decide.
  - Each vendor's licensed mark replaces the placeholder in its `Connector::logo` when
    available. It must be a static, script-free SVG with no external references. A unit test
    enforces this for every bundled logo (see 7), and each new mark is also reviewed by hand.
    The factual product **names** ship now.

## 4. Product identity comes from the validated redirect, not a `client_id`

`client_id`s are **not a durable identity**, so nothing in this design keys on them:

- **DCR ids churn.**
  - `register` mints `client-{uuid v4}` fresh for every registration.
  - Reinstalling, or "remove the connector and add it again" (which the server's own error text
    tells users to do), mints a new id.
  - The client store is LRU-evicted at `MAX_CLIENTS` (`make_room_for_client`), so an idle
    client is dropped and re-registers under a new id.
  - Ids are per registration, not per vendor, so one product maps to many ids across users and
    devices.
- **CIMD ids (#191) are stable, but they are still the client's own claim.** A Client ID
  Metadata Document `client_id` is an `https` URL.
  - Its origin must be allow-listed (`cimd_origin_trusted`).
  - The document's `redirect_uris` are held to a stricter rule than a DCR registration. A URI is
    kept only if a DCR registration could have registered it (`redirect_uri_permitted`) and,
    unless it is loopback, it is on the document's own origin. Any other URI is dropped
    (`parse_client_metadata`). A trusted CIMD origin therefore cannot list another vendor's
    callback.
  - Keying on the validated redirect covers CIMD and DCR clients uniformly, without a second
    code path.

**Product identity comes from the connect's validated redirect.** When II asks about a connect,
the server takes that connect's recorded `redirect_uri` and matches it against the curated
table (`CONNECTORS` in `src/branding.rs`, resolved by `connector_for_redirect`):

| Vendor domain (`DEFAULT_ALLOWED_REDIRECTS`) | Product slug | Display name |
|---|---|---|
| `chatgpt.com` | `chatgpt` | ChatGPT |
| `claude.ai` | `claude` | Claude |
| `cursor.com` | `cursor` | Cursor |
| `grok.com` | `grok` | Grok |
| `perplexity.ai` / `perplexity.com` | `perplexity` | Perplexity |
| `antigravity.google` | `antigravity` | Google Antigravity |

- **Only compiled-in callbacks are branded.** A redirect resolves only if a
  `DEFAULT_ALLOWED_REDIRECTS` entry admits it, under validation's own rules
  (`redirect_uri_on_default_allow_list`).
  - An `OAUTH_ALLOWED_REDIRECT_PREFIXES` entry is accepted for redirects but never branded,
    even on a vendor's domain (say, another path on `claude.ai`).
  - A vendor's name therefore rests only on the callback paths reviewed in this repo, never on
    a deployment's configuration.
- **A unit test holds the table's domain set equal to the compiled-in allow-list's vendor
  domains.** Adding a new vendor domain to the allow-list therefore fails the test suite (and
  CI) until someone decides its branding.
- **The slug is server-determined.** The branding answer never takes it as input: the answer is
  keyed on `state` and resolved from the connect's recorded redirect. The slug appears in the
  logo URL the server hands back. The logo route accepts a slug only from the curated set
  (anything else gets `404`) and serves a static per-product image that makes no claim about
  any connect.

**Why the redirect is a sound proxy for where the access goes.** Anyone may *register* a
vetted redirect: DCR is open, and nothing stops a stranger registering
`https://claude.ai/api/mcp/auth_callback`. What a stranger cannot do is *receive the code* for
it.

- The allow-list requires the vendor's domain or one of its dot-boundary subdomains.
- The path must equal the vendor's pinned callback path (`PathPin::Exact`) or sit under it at a
  segment boundary (`PathPin::Prefix`). Every seeded entry is `Prefix` except ChatGPT's
  `/connector_platform_oauth_redirect`.
- It refuses non-default ports (an explicit `:443` is the same origin and is accepted),
  userinfo, queries, fragments, and any percent-encoding.
- So the code for a connect recorded with that redirect is delivered, in the user's browser, to
  a URL under the vendor's pinned callback path on the vendor's own domain.

This relies on an assumption the redirect allow-list already makes for the whole flow: **the
vendor controls every subdomain of its listed domain and everything served under its pinned
callback path.** Branding adds no trust beyond validation, but it puts the vendor's name on that
trust. Two things would break it:

- a dangling or third-party subdomain of a vendor domain;
- a handler under a prefix pin that leaks or forwards the query.

Narrowing branded entries to exact hosts and `Exact` pins, vendor by vendor, would shrink this.

Under that assumption, a connect branded "Claude" delivers its authorization code only to
Claude. That does **not** mean Claude started it:

- Open DCR lets an attacker register Claude's callback under their own `client_id` and start a
  connect. If the user approves it, the attacker still does not receive the code.
- The code is also useless to Claude. `/oauth/token` (`token_authorization_code`) issues a
  token only for that connect's PKCE verifier (`authorize` requires S256), and the attacker
  holds the verifier.
- **Residual risk: a leaked code.** The code could leak within `CODE_TTL` (120 s) after it
  reaches the vendor's callback, and the attacker could then exchange it.
  - It could leak on the user-agent side (browser history, an extension) or on the vendor side
    (the vendor's logs).
  - The most direct case is the hostile local app from section 5. Running as the same OS user,
    it can often read the browser profile's history. It can register the vendor's callback
    through open DCR with its own PKCE verifier, open `/oauth/authorize` in the user's real
    browser (so the binding cookie is there), have the user approve a connect branded as that
    vendor, then take the code from history.
  - The anonymous flow has the same leak. What branding adds is that such a connect looks
    vetted.
- **Residual risk: branding names the vendor, not the account.** An attacker who uses a vetted
  product can start a genuine connector flow from their own account there, then send the
  resulting `/oauth/authorize` URL to a victim.
  - That URL carries the vendor's `client_id`, the vendor's PKCE challenge, and a `state` tied
    to the attacker's session at the vendor.
  - The victim's browser opens it, so the binding cookie is in the victim's browser and
    redemption succeeds.
  - The screen truthfully says the access goes to Claude, and the code does reach Claude, which
    holds the verifier.
  - Whether the grant then lands in the victim's vendor account or the attacker's depends on
    the vendor. Its callback must reject a `state` that was not issued to the browser session
    delivering it (RFC 6749 §10.12). Nothing on the imcp2 or II side can check this.
  - The anonymous flow has the same exposure. Branding makes it look vetted, and "Claude" reads
    as "my Claude", which is why 6.2 requirement 5 constrains the wording.

All of this holds for a conforming browser. A user agent the attacker controls, such as an
embedded webview that reads every navigation, is out of scope for branding, as it is for the
whole flow.

**Host matching is validation's own rule** (`host_key` plus `host_is_or_under`, shared by
`redirect_uri_permitted` and `connector_for_redirect`):

- Case-insensitive, and a trailing root dot is ignored (`claude.ai.` is `claude.ai`).
- A subdomain matches only at a dot boundary, so `evilchatgpt.com` never matches `chatgpt.com`.

### v1 scope: redirect-identified web connectors only

There are two classes of MCP client, and only one can be vouched for:

- **Web and cloud connectors** (claude.ai web, ChatGPT, Cursor, Grok, Perplexity, Google
  Antigravity) are identified by their redirect domain. Codes for their path-pinned callbacks
  are delivered only under the vendor's domain (under the assumption above), whoever started
  the connect. These are the products in the table above, and they are what v1 brands.
- **Native and desktop apps** (Claude Desktop, Cursor desktop, and the like) do OAuth with
  **loopback** redirects (`http://127.0.0.1:port/…`), which carry no vendor identity. Loopback
  is exempt from the allow-list wholesale.
  - The only identity signal they offer is the unauthenticated `client_name` they claim at
    registration, which a hostile local app could forge to inherit a trusted product's mark.
  - So **native apps deliberately stay anonymous in v1**: branding lookups for their connects
    return `404`, and they get the anonymous consent screen.
  - The vetted-only rule (see 3) is worth more than covering native apps with a spoofable
    signal. Authenticating a native app needs a signed `software_statement` (RFC 7591) per
    vendor, deferred to a later phase (see 10).

## 5. Why nothing about branding rides the link

**The fragment is written by whoever drives the browser.** For a native (loopback) client, that
is the client itself:

- It can call `/oauth/authorize` itself and read the II link from the `302`'s `Location`
  header. The connect's binding cookie then lands in the app's HTTP client, not in the user's
  browser.
- Separately, it can open any URL it likes in the user's browser.
- From II's point of view, every fragment field is therefore attacker-chosen. The same fact is
  why #4091 exists for `callback`.

**What the first draft allowed.**

1. A hostile local app registers a loopback client and starts a connect.
2. It opens the II link in the user's browser with `&connector=claude` appended.
3. The unbound `/branding/claude` endpoint confirms "Claude, verified".
4. The user approves what II presents as a verified "Claude" connect that Claude never started.

At step 4 the consent screen has already vouched for an identity the server never tied to this
connect. In a conforming browser the grant then fails at `/oauth/connect/redeem`: the app read
the link by calling `/oauth/authorize` itself, so the binding cookie (`CONNECT_COOKIE`) is in
the app, not the browser. An app that controls the user agent would complete the grant too
(out of scope; see 4). Either way, a label the fragment asserts cannot be checked by anyone.

**The fix is to bind branding to the connect.** The answer for `state` S is derived from S's
recorded redirect. The hostile app's connect has a loopback redirect, so its lookup returns
`404` and II shows the anonymous screen. There is nothing to add to the link and nothing to
swap.

**Borrowing another connect's `state` does not help.** An attacker can put the `state` of a
connect whose redirect is vetted into a link, and II will show that connect's product. But
everything II then does is for that connect:

- Its code can be redeemed only by the browser holding that connect's binding cookie.
- It redeems only with that connect's own registration key.
- It is delivered only to that connect's vetted redirect.

Splicing S's `state` with another connect's `registration_key` fails closed at redemption,
because the delegation reaches only S's own server callback, `{issuer}/oauth/connect/callback`,
whose `connect_redeem` checks it against S's registration key. That relies on II delivering to
the same callback it took the branding issuer from. If II took branding from one callback and
delivered to another, the redemption check would never run. The II side must therefore bind
`callback` and `state` together (see 6.2, requirement 3).

## 6. The extension contract

### 6.1 MCP server (this repo, implemented in #200)

Both endpoints are rooted at the instance issuer, the same `{issuer}` as the #4091-declared
callback `{issuer}/oauth/connect/callback`. They are served CORS-open (`permissive_cors`: any
origin, method, and header) and need no credentials.

- **`GET {issuer}/branding?state={state}`** returns the branding for one pending connect.
  - **`200`**, with `Content-Type: application/json` and `Cache-Control: no-store` (the answer
    is per connect). The body is a JSON object with exactly these members, all always present:
    - `name`: string, the curated product name (e.g. `"Claude"`);
    - `logo`: string, an absolute URL on the issuer's origin, `{issuer}/branding/{slug}/logo`;
    - `verified`: boolean, always `true` from this server. It records the server's own curation
      and nothing more (see 6.2, requirement 4). A connect that is not vetted gets the `404`,
      never `verified: false`.

    For example:
    `{ "name": "Claude", "logo": "https://mcp.example.com/mcp/branding/claude/logo", "verified": true }`.
  - **`404`** with body `no connector branding` and `Cache-Control: no-store`, when:
    - `state` is missing, unknown, or expired;
    - the connect's redirect is not a vetted product (loopback, an unlisted host, or an
      operator-added entry);
    - the query is malformed, e.g. a repeated `state`.

    All these cases return the same response (status, headers, and body), so a `404` does not
    tell an unknown `state` apart from a live but unbranded connect. `state` is an unguessable
    UUID v4, so the endpoint cannot be used to enumerate connects.
  - The lookup is **read-only**: it neither consumes nor changes the pending connect.
  - It answers from `authorize` until the connect's code is successfully exchanged or
    `CONNECT_TTL` elapses, whichever comes first. The lookup checks the remaining lifetime
    itself, so it stops answering at `CONNECT_TTL` even before the sweep removes the entry. It
    can stop earlier if the entry is evicted by the pending-connect cap or the server restarts
    (see 2). II should call it when it shows the consent screen.
- **`GET {issuer}/branding/{slug}/logo`** returns the bundled image bytes.
  - `200` with `Content-Type: image/svg+xml`, `X-Content-Type-Options: nosniff`,
    `Cache-Control: public, max-age=3600`, and
    `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`.
    The CSP keeps the SVG inert if the URL is opened top-level on the issuer origin; an `<img>`
    ignores it.
  - `404` (`no-store`) for any slug outside the curated set, so the path segment cannot probe
    arbitrary keys.
  - It is a static per-product asset and makes no claim about any connect.
- **Not endpoints.** There is no `GET {issuer}/branding/{slug}` metadata route: that path falls
  through to the token-gated MCP endpoint and gets `401`. The connect link carries no branding
  parameter; a test asserts that `ii_mcp_url`'s output contains no `connector`.

### 6.2 Internet Identity (`id.ai`) side (coordination required)

This is an extension to the connect contract, in the same family as
dfinity/internet-identity#4091 (the callback allow-list) and dfinity/internet-identity#4093
(`registration_key`). II must do the following.

1. **Derive the issuer from the validated callback.** Let `cb` be the exact `callback` string
   that passed the #4091 check. #4091 compares it string-equal to a declared entry,
   `{issuer}/oauth/connect/callback` (`connect_callback_url`).
   - Require `cb` to start with `https://` and to end with `/oauth/connect/callback`. Also parse
     it (`const u = new URL(cb)`) and require `cb === u.origin + u.pathname`. `u.origin` carries
     no userinfo, and neither part carries a query or fragment, so this rejects any callback
     with one of those (even an empty `?` or `#`) and any non-canonical spelling. A suffix test
     alone would accept `https://h/mcp?x=/oauth/connect/callback`. A callback that fails either
     check gets no branding.
   - `{issuer}` is `cb` with that suffix removed by string operations. It usually carries the
     instance's mount path (e.g. `https://mcp.internetcomputer.org/mcp`; one origin can also
     serve `/mcp-beta`), and is a bare origin only for a root mount. A callback without this
     shape gets no branding.
   - A callback whose host is loopback (`localhost`, `127.0.0.0/8`, `[::1]`) gets no branding
     and no fetch. This is the local-server case: imcp2-local's callback is
     `http://127.0.0.1:<port>/callback`, which is exempt from #4091 and already fails the checks
     above.
   - This is unrelated to native apps. A native app connecting through a hosted server uses a
     loopback *redirect* at that server (see 4), but its callback is still the hosted
     `{issuer}/oauth/connect/callback`. The server answers `404` for such connects (see 6.1).
2. **Fetch `{issuer}/branding?state={state}`** with `credentials: "omit"`, `cache: "no-store"`,
   `redirect: "error"`, and a short timeout.
   - Build the URL by appending to the issuer string, e.g.
     `const u = new URL(issuer + "/branding"); u.searchParams.set("state", state);`.
   - Do not resolve `"branding"` or `"/branding"` against `issuer` with `new URL(rel, issuer)`.
     That drops the instance path and requests the wrong URL.
   - **Only one outcome yields branding:** a `200` whose `Content-Type` is `application/json`,
     whose body is within a small size cap (e.g. 4 KB; a real response is a few hundred bytes), and whose
     body is a JSON object with a non-empty string `name`, a string `logo`, and `verified`
     equal to the boolean `true`. Ignore unknown members. `name` and `logo` are then subject to
     requirement 5. Never render part of a response that fails this check.
   - **Every other outcome means "no branding"** and shows today's anonymous screen. That
     includes:
     - any other status (an MCP server older than #200 answers this path with `401`; a current
       one answers `404`);
     - a redirect, which `redirect: "error"` turns into a network error;
     - a CORS or network failure, or the timeout;
     - a body that is oversized, not JSON, or the wrong shape.

     Never read or display an error body.
   - A branding failure never produces a user-visible error and never aborts the connect. It may
     delay the consent step by at most the timeout above.
3. **Use one `callback` and one `state` for everything.** Parse `callback`, `state`, and
   `registration_key` from the link fragment once. Use that single result for the #4091 check,
   the branding lookup, the consent, and the return navigation. Never re-read `location.hash`,
   and never take these values from anywhere else.
   - Three callbacks MUST be the same string: the one that passed the #4091 check, the one
     `{issuer}` is derived from (requirement 1), and the one II navigates back to with the
     delegation.
   - The `state` in the branding lookup MUST be the value II echoes in the callback fragment
     (`#delegation=…&state=…`) when it navigates back after this consent.
   - This keeps the displayed product bound to the connect actually being approved, and to the
     server that will redeem it (see 5).
4. **Show branding only for origins II itself trusts.** The whole verified-connector
   treatment (name, logo, and badge) is gated here, not only the badge.
   - #4091 proves only that an origin *declared* the callback, not that it is an honest imcp2
     deployment. Any origin can serve a #4091 document and a `/branding` endpoint that answers
     `{ "name": "Claude", "logo": "https://evil.example/branding/claude/logo", "verified": true }`.
     That body passes the requirement 2 check, and its logo passes the requirement 5 same-origin
     check when the callback is on `https://evil.example`. Only this requirement stops it.
   - So II needs its own short list of trusted imcp2 origins (e.g. production
     `https://mcp.internetcomputer.org`). II MUST show name, logo, and badge only when the
     validated callback's origin (scheme, host, and port) **exactly equals** an entry on that
     list. For every other origin it MUST show the anonymous screen, whatever the response says.
   - No suffix, subdomain, or pattern matching: `https://evil.internetcomputer.org` and
     `https://mcp.internetcomputer.org.evil.example` must not match.
   - II should run this check before the requirement 2 fetch and skip the fetch for an unlisted
     origin. Its CSP `connect-src` (requirement 5) blocks that fetch anyway.
   - Trust is per origin. A deployment's #4091 document declares every instance mounted on that
     origin (for example a beta instance beside production), so listing an origin covers every
     issuer on it, including instances paired with a different II deployment.
     - Each instance's own links point only at its paired II, but the fragment is
       attacker-chosen (see 5). An II can therefore receive a connect whose callback is an
       instance aimed at another II, and will show that connect's branding.
     - That connect cannot complete: the instance redeems only against its own paired II, which
       holds no consent for the connect's `registration_key`, so `/oauth/connect/redeem` fails
       and no code is issued.
     - If II wants branding scoped more tightly than the origin, it can trust exact issuers (the
       `{issuer}` derived in requirement 1) instead of origins. Either way, it should avoid
       trusting origins that also serve instances paired with a different II.
   - The server's `verified: true` states only the server's own curation; the trust decision is
     II's.
5. **Render safely.**
   - Show `name` as plain text (never HTML), with a length cap.
   - Load `logo` only if it is on the same origin as the validated callback, and only through a
     **fixed-size `<img src=…>`** with `alt` set to the validated `name`. Never inline the SVG
     markup into the consent DOM: an SVG loaded through `<img>` cannot execute script, and an
     inlined one can.
   - `<img>` needs no CORS, but the logo is cross-origin to II. II's Content-Security-Policy
     must allow each trusted origin from requirement 4 in `img-src`, and in `connect-src` for
     the requirement 2 fetch, ideally generated from that same list. Otherwise the browser
     blocks both and every consent falls through to the anonymous screen.
   - The bundled logo is currently a generic placeholder (a check in a ring, the same for every
     product), so the verified treatment must not rely on the logo to convey verification.
   - On an origin that requirement 4 trusts, if `logo` fails the same-origin check or does not
     load, show `name` and the badge without a logo. Do not fall back to the anonymous screen
     just because the logo failed: the logo makes no claim about the connect, and `name`, which
     comes from the session-bound `200`, is the part that matters. (An untrusted origin never
     gets this far; see requirement 4.)
   - Word the treatment as where the access goes (e.g. "Access will go to Claude"). Do not word
     it as the product having started the request ("Claude wants to connect"), or as the user's
     own account ("your Claude").
   - The server vouches for which product the code is delivered to. It does not vouch for who
     started the connect, or for which account at that product will hold the grant (see 4). II
     should pair the name with a reminder to continue only if the user started this connection
     themselves.
6. **Keep the connector distinct from the server.**
   - The branding `name` and `logo` identify the MCP *client* whose callback receives this
     connect's code, not the server.
   - II already shows the server's identity: the #4091-verified callback origin, plus the `name`
     from that origin's `/.well-known/ii-app-metadata` document (e.g. "ICP MCP").
   - The connector branding adds to that identity and never replaces it. Never put the connector
     name in the origin or app-name slot.
   - Illustrative copy (the final treatment is II's call; see 11, question 4): "Access will go
     to <connector name>, through <app-metadata name> (<origin>)".

## 7. Security

- **No client-supplied content is rendered, and no client- or link-supplied identifier is
  trusted.** The displayed name and logo are curated, and which ones apply is decided from the
  connect's validated redirect (see 3, 4). This removes the consent-phishing vector at the root
  rather than labelling it.
- **Branding is bound to the connect.**
  - The product shown is the product whose callback receives this connect's authorization code.
  - A native app cannot get a vendor's label on a connect whose code it would receive: its
    loopback connect returns `404`. A connect it starts with a vetted redirect (open DCR lets it
    register one) delivers the code to that vendor's callback, not to the app, unless the code
    leaks from there (see the residuals below and 4).
  - Borrowing a vetted connect's `state` only delivers that connect's code to its own vendor
    (see 5).
- **Only reviewed callbacks carry a vendor's name.** Branding requires a compiled-in allow-list
  entry, so operator configuration can widen which redirects are accepted but never which are
  branded (see 4).
- **Residual: a leaked code from an attacker-started connect.** Anyone can register a vetted
  vendor's callback under their own `client_id` and start a connect with their own PKCE
  verifier. The code still goes only to the vendor's callback. If it leaks within `CODE_TTL`
  (120 s), through browser history, an extension, or the vendor's logs, the attacker can
  exchange it. A hostile local app that can read the user's browser profile is the realistic
  case. The anonymous screen has the same leak; branding makes such a connect look vetted
  (see 4).
- **Residual: a connect started from someone else's vendor account.** A link started in an
  attacker's own account at a vetted vendor is branded like any other connect. Its grant goes
  to that vendor, and into the attacker's account unless the vendor binds `state` to the
  browser session (see 4). Branding asserts which product receives the code, never whose
  account.
- **No connect oracle.**
  - Missing, unknown, expired, malformed, and unbranded all return the same `404`.
  - `state` is not a secret: it rides the link and appears in server logs. But it is an
    unguessable UUID v4 and short-lived.
  - A branded answer reveals two things, and only to someone who already holds its `state`:
    which vetted vendor the connect is for, and that the connect is still pending.
- **Read-only lookup.** A branding fetch cannot consume, extend, or otherwise disturb a pending
  connect.
- **The verified-connector treatment (name, logo, and badge) needs an II-side trust decision**
  (see 6.2, requirement 4). II shows no branding at all for an origin that is not on its list.
  Without that list, any origin could self-assert "verified Claude". This is the one place the
  design leans on II's own knowledge, and it is not optional.
- **No SSRF.** v1 bundles its logos and never fetches a client's `logo_uri`. If open
  self-service branding is ever added, it must:
  - reuse the SSRF-pinned client from `discover.rs`;
  - be https-only;
  - be size- and dimension-capped;
  - allow-list content types to raster formats (`png`, `jpeg`, `webp`);
  - reject or fully sanitize SVG, since SVG can carry script;
  - decode and re-encode images to strip payloads.
- **Bounded, closed slug space.** The logo route serves only the fixed curated set; an unknown
  slug gets `404`. Responses are small and served from compiled-in assets.
- **Logo rendering, on II and on the issuer origin.**
  - On II, SVG is acceptable only if II renders it through a fixed-size `<img src=…>`, never
    inlined (see 6.2, requirement 5).
  - The logo URL is also an ordinary GET on the issuer origin. Opened top-level (a direct link,
    or "open image in new tab"), it renders as an SVG document on the same origin as
    `/oauth/authorize` and `/oauth/connect/redeem`, where `<img>` isolation does not apply.
    Two layers cover that:
    - the sandboxing CSP on the logo response (see 6.1);
    - a unit test (`bundled_logos_are_static_svg`) that rejects script, event-handler
      attributes, embedded HTML (`foreignObject`, XHTML), animation, DTDs, and any `href`,
      `src`, or `url()` that is not an internal `#…` reference, including spaced and quoted
      spellings. It is a guard for hand-reviewed assets, not a general SVG sanitizer.
  - A raster logo would avoid the concern entirely.
- **CORS and caching.** Both endpoints are CORS-open (II calls the `GET {issuer}/branding?state=`
  lookup with `fetch`; the logo is loaded through `<img>`). Every response from the lookup, `200`
  or `404`, is `no-store`, because the answer is per connect and must never come from a shared
  cache. The static logo is cacheable for an hour (its `404` is `no-store`).

## 8. Backward compatibility

Every piece is additive:

- **Old II with a new server:** II never calls the new endpoints, and the link is unchanged, so
  connects behave exactly as today.
- **New II with an old server:** the `/branding` path falls through to the token-gated MCP
  endpoint (`401`). That is not a branding success under 6.2, requirement 2, so II shows the
  anonymous consent screen.
- **Unvetted clients and native apps:** the lookup returns `404`, so there is no name and no
  logo, and the flow is the same as now.

## 9. Testing (server side, #200)

- **Resolution and vetting unit tests** (`src/branding.rs`, `src/auth.rs`):
  - redirects resolve to products, including subdomains, a trailing root dot, and uppercase;
  - look-alike apexes, loopback, unlisted hosts, `http`, and redirects validation refuses
    (off-pin path, port, userinfo, query, percent-encoding) do not resolve;
  - an operator-style entry on a vendor's domain admits a redirect but does not vet it for
    branding (`default_allow_list_vetting_ignores_operator_entries`);
  - the logo-slug lookup is closed to the curated set;
  - the curated domains equal the allow-list's vendor domains;
  - every bundled logo is static SVG with only internal references, and the guard catches a
    set of unsafe SVGs, spaced and quoted spellings included (`bundled_logos_are_static_svg`).
- **Session binding** (`branding_is_bound_to_the_session`, `src/auth.rs`):
  - a vetted connect returns `200`;
  - a native (loopback) connect returns `404`, as do unknown and missing states;
  - an expired connect returns `404` (the test skips this check on a host whose monotonic clock
    started less than the connect TTL ago);
  - the lookup leaves the pending connect untouched.
- **Link:** the II link carries no `connector` parameter.
- **Router, over HTTP** (`tests/routers.rs`):
  - The DCR round trip registers loopback and both `claude.ai` spellings, runs `authorize`,
    reads `state` from II's link, and asks `/branding?state=`. It asserts `200`, `Claude`, and
    `no-store` for both claude.ai spellings, and `404` for the loopback connect.
  - Without a connect, `/branding` returns `404` with CORS headers and `no-store`.
  - The old unbound per-slug metadata path (`GET /branding/claude`) returns no branding: it gets
    a non-`200` response, because it falls through to the token-gated MCP endpoint.
  - The logo is served as SVG with `nosniff` and the sandboxing CSP.

## 10. Work breakdown

- **Phase 1 (server): done in #200.**
  - The curated table, with name and compiled-in placeholder logo per product.
  - Session-bound `GET {issuer}/branding?state=` and static `GET {issuer}/branding/{slug}/logo`.
  - Branding limited to compiled-in callbacks, with one host rule shared with redirect
    validation.
  - The tests in section 9.
- **Phase 2 (II coordination).** Agree this contract with the II team (see 11). II then
  implements the requirements in 6.2:
  - derives the issuer from the validated callback;
  - fetches by `state`, accepting only a response that passes the check in 6.2, requirement 2
    (a JSON `200`, size-capped, with `name`, `logo`, and `verified: true`, ignoring unknown
    members);
  - uses the one parsed `callback` and `state` for the #4091 check, the lookup, and the return
    navigation (see 5);
  - applies its trusted-origin list: name, logo, and badge only for an exactly matching origin,
    otherwise the anonymous screen (requirement 4);
  - renders safely (`name` as plain text, `logo` only from the callback's origin through a
    fixed-size `<img>`, CSP updated), keeping the connector distinct from the server's own name
    and origin. A logo that fails the origin check or does not load drops only the logo (and
    `name` still shows) (requirement 5). The anonymous screen is used only when the lookup
    yields no branding (requirement 2) or the origin is untrusted (requirement 4).
- **Phase 3 (optional, later).**
  - **Licensed vendor marks** replace the placeholder logo, per vendor, as licensing allows.
    Each must pass the bundled-logo test and a manual review (see 7).
  - **Native and desktop apps** (Claude Desktop, etc.) via a signed `software_statement`
    (RFC 7591). The vendor issues a JWT asserting the product, the server verifies it against
    the vendor's known key, and only then does the app's connect resolve to a product. This is
    the authenticated way to close the gap left open in section 4 ("v1 scope").
  - **Open self-service branding** via a reviewed `logo_uri`, with the full SSRF and sanitize
    pipeline from section 7.

## 11. Open questions for the II team

1. **How II finds the branding endpoint.** This document proposes deriving `{issuer}` by
   stripping `/oauth/connect/callback` from the validated callback (6.2, requirement 1). The
   alternative is for the server to declare its branding endpoint explicitly, for example as an
   additional member of the #4091 `/.well-known/ii-auth-callbacks` document. Which does II
   prefer?
2. **Where II keeps its list of trusted imcp2 origins** for the verified-connector treatment
   (name, logo, and badge; 6.2, requirement 4), which deployments go on it, and whether it
   trusts origins or exact issuers. For example, staging (`https://mcp.beta.id.ai`) serves a
   `/mcp` instance paired with production II beside a `/mcp-beta` instance paired with beta II.
   Whether to trust it, and at which granularity, is II's decision.
3. **Confirmation that II can render the logo** through a fixed-size `<img src=…>`, including
   adding the trusted imcp2 origins to its CSP `img-src` and `connect-src`. SVG is the intended
   format, and this is a hard II-side requirement (see 6.2, 7).
4. **The exact consent-screen treatment** for "verified connector" versus the anonymous
   fallback. That includes where the connector name and logo sit relative to the verified
   origin and its app-metadata name (6.2, requirement 6), and copy that says where the access
   goes rather than who started the request.
