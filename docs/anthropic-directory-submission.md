# Publishing IMCP2 to the Anthropic Connectors Directory

Everything needed to submit the production deployment
(`https://mcp.internetcomputer.org/mcp`) to Anthropic's Connectors Directory —
the catalog that serves Claude.ai, Claude Desktop, Claude Mobile, Cowork, and
Claude Code. Field drafts below are pre-filled from this repo and the live
deployment; paste and adapt them in the portal.

Verified against the official docs on **2026-07-31**. The portal UI may add
details (e.g. exact icon dimensions) not published in the docs.

## Where and how submission happens

- **Portal:** <https://claude.ai/admin-settings/directory/submissions/new>
  (status/feedback afterwards at
  <https://claude.ai/admin-settings/directory/submissions>).
- **Who can submit:** an **Owner** (or, on Enterprise, a custom role with the
  *Directory management* permission) of a Claude **Team or Enterprise
  organization**. There is no submission path for individual plans.
- **Governing documents:**
  [Anthropic Software Directory Policy](https://support.claude.com/en/articles/13145358)
  (effective 2026-04-15) and
  [Anthropic Software Directory Terms](https://support.claude.com/en/articles/13145338)
  (effective 2026-03-16).
- **Process docs:**
  [Submission](https://claude.com/docs/connectors/building/submission),
  [Review criteria](https://claude.com/docs/connectors/building/review-criteria),
  [Authentication](https://claude.com/docs/connectors/building/authentication).
- **Review:** automated policy scan first, then listing as a *Community*
  connector; Anthropic may escalate to a human *Verified* review on its own.
  No published SLA ("review times vary with queue volume"). Escalations and
  special requests: <mcp-review@anthropic.com>.
- **Not required:** listing in the open MCP Registry
  (registry.modelcontextprotocol.io) — the directory docs state its
  domain-ownership proof "applies only to the open MCP Registry, not the
  Anthropic Directory".

## Readiness: requirements already met

Verified against the live production deployment (2026-07-31):

| Requirement | Status |
|---|---|
| HTTPS remote server, Streamable HTTP transport | ✅ `rmcp` streamable-HTTP, stateless, JSON responses ([`src/lib.rs`](../src/lib.rs)) |
| OAuth 2.0, authorization-code + PKCE **S256**, advertised in metadata | ✅ `code_challenge_methods_supported: ["S256"]` in the live RFC 8414 document |
| Dynamic Client Registration (RFC 7591) — the out-of-the-box `oauth_dcr` mode | ✅ live probe: `POST /mcp/oauth/register` with the claude.ai callback → `201` |
| Claude's hosted callback `https://claude.ai/api/mcp/auth_callback` accepted | ✅ seeded in the redirect allow-list ([`src/auth.rs`](../src/auth.rs), `DEFAULT_ALLOWED_REDIRECTS`) |
| Claude Code loopback redirects (RFC 8252) | ✅ loopback redirects are exempt from the hosted allow-list |
| Discovery documents (RFC 8414 + RFC 9728, path-scoped + root fallback) | ✅ all four live, `WWW-Authenticate` on the 401 points at the resource metadata |
| Every tool: `title` + `readOnlyHint`/`destructiveHint` (+ `idempotentHint`, `openWorldHint`) | ✅ on all 10 served tools (and on the 16 deferred definitions), enforced by a unit test ([`src/tools.rs`](../src/tools.rs)) |
| No catch-all read/write tool; reads and writes are separate tools | ✅ 9 of the 10 served tools are read-only; the one write is `canister_update_call`. (The protocol/meta group — incl. the instructions-only funding helpers — is deferred to a future version.) |
| Tool names ≤ 64 chars | ✅ longest is 30 |
| `outputSchema` + structured content on every tool | ✅ enforced by a unit test |
| Certificates from a recognized authority | ✅ Let's Encrypt via Caddy |
| OAuth endpoint latency ≤ 10 s (discovery/registration/token) | ✅ all sub-second in probes |
| Support channel | ✅ <mcp@dfinity.org> (shown on every error screen) |
| Security-vulnerability reporting mechanism (a Software Directory Terms obligation) | ✅ [`SECURITY.md`](../SECURITY.md) → Hackenproof bug bounty |
| Public documentation by publish date | ✅ this repo's README + the landing page at <https://mcp.internetcomputer.org> |
| Status/health visibility | ✅ <https://mcp.internetcomputer.org/status/> |

Notes on auth mode: pure M2M `client_credentials` is unsupported by Claude
(every connection needs a user in the loop) — IMCP2's user-consent flow via
Internet Identity is exactly the supported shape. Claude registers a new DCR
client on each fresh connection; the server's registration store is a bounded
LRU of 10,000, which tolerates that churn, but Anthropic recommends **CIMD**
(Client ID Metadata Documents) for high-traffic directory listings — worth
considering as a follow-up if usage grows.

## Blockers to resolve before submitting

### 1. Privacy policy URL (hard blocker)

> "Missing or incomplete privacy policies result in immediate rejection."

The two existing DFINITY policies don't cover this service:

- The [Internet Identity Privacy Policy](https://identitysupport.dfinity.org/hc/en-us/articles/36662081856148-DFINITY-Internet-Identity-Privacy-Policy)
  (effective 2026-04-07) scopes itself solely to processing "when you link
  your Internet Identity account with your Google account" and states "This
  Privacy Policy does not apply to any other data processing". It never
  mentions the MCP server, OAuth sessions, or AI-assistant connections — it
  cannot be cited for this connector, though it is the precedent for
  publishing a service-specific policy on the help center.
- <https://dfinity.org/privacy> is the foundation-wide website policy; legal
  would need to confirm (unlikely as-is) that it covers this service's
  processing.

So a **dedicated ICP MCP privacy policy** is needed. Anthropic's review
checks that the linked policy covers data collection, use/storage,
third-party sharing, retention, and a contact channel. Mapped to what this
server actually does, it should cover at least:

- **Collected/processed:** the time-boxed delegation (session key, chosen
  duration and access level), named account labels, OAuth client
  registrations (generated client id, redirect URI, last-used timestamp —
  `client_name` is echoed in the response but not stored), issued tokens and
  auth codes, and tool-call arguments passing through the server (canister
  ids, Candid/OQL arguments — whatever the user's chat sends).
- **Storage/retention:** session, token, and account state is held in
  bounded **in-memory** stores (lost on restart; sessions capped at the II
  grant duration, ≤30 days) — but OAuth client registrations are **persisted
  to disk** (`oauth-clients.json` in `IMCP2_STATE_DIR`, kept in the unit's
  `StateDirectory` so client ids survive redeploys) with no time-based expiry, only LRU eviction
  at 10,000 entries; they contain no user personal data (client id, redirect
  URI, last-used timestamp). Host-side tracing logs record method, path,
  status, and latency per request (never query strings or bodies) plus auth
  events that include session ids and the Service-scoped principal; the
  Service's own logs do not systematically record client IPs or user agents
  (Caddy runs without access logs).
- **Public-network consequence:** calls the user makes execute on the
  Internet Computer, a public network, as the user's per-app principal; what
  an application records or publishes when called is governed by that
  application and may be publicly accessible — under the user's control, not
  a data-sharing choice of the server.
- **Third parties:** the connected AI assistant (results go back to it and
  its provider); the Internet Computer's public API boundary nodes
  (`icp-api.io`) and Internet Identity (`id.ai`), both **DAO-governed via
  the NNS, not DFINITY-operated**; the DFINITY-operated
  `dashboard.internetcomputer.org` and `skills.internetcomputer.org`; and,
  at the user's direction, the applications the user chooses to interact
  with — a call carries its arguments and the user's per-app principal to
  that application's operator, and app discovery fetches metadata from
  user-supplied origins. No analytics on the MCP endpoints today (say so
  explicitly, or disclose them if added).
- **Controller and contact:** DFINITY Stiftung; <mcp@dfinity.org>.

Publication venue: `https://mcp.internetcomputer.org/privacy-policy`, served
by the MCP server itself. The page and its route shipped in
[#112](https://github.com/dfinity/imcp2/pull/112) (effective date August 3,
2026) and the landing page's footer links it, so what remains is the
**production release**: staging serves it now, production at the next
`release-*` tag — cut on or after August 3 so the live page and its stated
effective date agree. Then enter that URL in the portal. The reviewed source
text is [`icp-mcp-privacy-policy-draft.md`](icp-mcp-privacy-policy-draft.md).

### 2. Financial-transactions policy (resolved in code)

The Directory Policy **prohibits connectors that transfer money,
cryptocurrency, or other financial assets, or execute financial
transactions**, and the portal's compliance step requires acknowledging this.

**Mitigations shipped across
[#153](https://github.com/dfinity/imcp2/pull/153) /
[#154](https://github.com/dfinity/imcp2/pull/154) — the stated and enforced
posture is that the server is not a financial tool (this section assumes
both are merged):**

- **No funding or management tools are served in this version at all.** The
  execution paths that once moved funds are removed from the binary
  ([#153](https://github.com/dfinity/imcp2/pull/153) /
  [#154](https://github.com/dfinity/imcp2/pull/154) made top-up and creation
  instructions-only), and the whole protocol/meta tool group — including those
  instructions-only helpers — is deferred from the served surface; we
  anticipate it will come in a future version. Creating, funding, and managing
  canisters is done by the user with the icp CLI in their own terminal.
- `canister_update_call` **refuses the standardized ledger methods** that
  move value or grant spending rights — the ICRC-standard names
  (ICRC-1/ICRC-2 plus ICRC-4/-7/-37) on every canister, and the ICP and
  cycles ledgers' own `transfer`/`send_dfx`/`withdraw`/`create_canister`
  methods on those ledgers; the refusal recommends the user act themselves
  in a wallet they control (oisy.com; a refused canister-creation spend
  points at the user-run icp CLI), and the policy is stated in the
  server-level instructions — deliberately not in the tool description,
  which stays free of financial language per maintainer review
  ([#154](https://github.com/dfinity/imcp2/pull/154)).
- The README, the landing page, and the server instructions all state
  explicitly that financial transactions are not supported.

**Posture, stated plainly — the black-and-white answer the compliance step
needs:** no tool initiates or executes a transfer of the user's funds.
Financial ledger methods are refused, and no funding or management tools are
served at all — users run those operations themselves with the icp CLI. The
financial-transactions acknowledgment is made on that basis, without
qualifications.

**Status: resolved in code.** An email to <mcp-review@anthropic.com>
(2026-07-31) had asked whether cycles funding and the general-purpose
`canister_update_call` pass review; the changes above made both questions
moot — funding no longer executes at all, and the update tool refuses
financial ledger methods. No open compliance question remains on this topic;
if a reply arrives, answer with the shipped posture.

Related honesty point for the same step: there is **no per-call confirmation**
for sensitive methods server-side today (an open roadmap item in the README) —
mitigations are the explicit access-level choice on the II consent screen
("Questions only" vs "Actions & questions", enforced at IC ingress),
revocability at any time via id.ai/manage/settings (≤5 min latency), and
accurate `destructiveHint` annotations (which make Claude prompt before each
destructive call).

### 3. Reviewer access — self-serve, no shared identity

**Decided:** reviewers create their own Internet Identity rather than being
handed a shared test account, and the test-credentials field points them at
the setup instructions on <https://mcp.internetcomputer.org>. This is the
right call for this connector: Internet Identity is passkey-based and
device-bound, so a "shared account" would mean circulating a recovery phrase,
and every read-only tool works against public network state, so a
freshly-created identity exercises the bulk of the surface within a minute.

One tension to be ready for: the review criteria say *"Test credentials are
required and must be a fully populated account."* Self-serve sign-up is a
reasonable answer for an authentication system nobody can pre-provision into,
but a reviewer may still ask for a populated account — most plausibly to
exercise `canister_update_call` against an app where the identity has data.
If that comes back, the fallback is a dedicated identity with a recovery
phrase in the team vault and an account at a demo app. (The
canister-management tools that would have needed a controlled canister and a
cycles balance are deferred to a future version.)

### 4. Production is behind `main`

The live server reports commit `48f1ed6`; `main` carries later hardening
(e.g. #98, #99, #107, #108). Cut a `release-*` tag so the deployment under
review includes them.

### 5. Icon asset — ready

The official ICP mark is committed at
[`assets/icp-logo.svg`](assets/icp-logo.svg), with square, transparent PNG
exports beside it for the portal's icon field:
[1024×1024](assets/icp-logo-1024.png) and [512×512](assets/icp-logo-512.png).
Upload whichever the portal asks for; exact specs surface in its UI, and any
smaller size downscales cleanly from the 1024.

The mark is ~2.05:1, so the exports centre it at 84% of the canvas width on a
square transparent field — no cropping, even margins, and it sits correctly on
both light and dark listing backgrounds. Regenerate with the Chromium
rasteriser if the source ever changes (lighter rasterisers mis-render its
`linearGradient` with a `rotate` transform). This is the *listing* icon only:
the served pages keep using the DFINITY wordmark
([`src/assets/dfinity-logo.svg`](../src/assets/dfinity-logo.svg)) for their
"Hosted by" footer.

## Portal field drafts

Paste-and-adapt; portal limits in parentheses.

- **Server URL:** `https://mcp.internetcomputer.org/mcp`
- **Transport:** Streamable HTTP
- **Authentication mode:** OAuth 2.0 with Dynamic Client Registration
  (`oauth_dcr`)
- **Name** (≤100 chars): `Internet Computer (ICP)` — matches what users
  search; the landing page's `ICP MCP` is the alternative. The display name is
  hard to change after publication.
- **URL slug** (permanent): `internet-computer`
- **Tagline** (≤55 chars): `Connect your AI chat to the Internet Computer`
- **Description** (≤2000 chars, draft):

  > The official connector between Claude and the Internet Computer, hosted by
  > DFINITY. Sign in once with Internet Identity — no keys or seed phrases in
  > the chat — and Claude can work with the IC directly: identify what a
  > canister is, fetch its Candid interface, read app data via typed queries
  > or OQL, and discover the canisters behind any IC app from its name or URL.
  > With your consent it can also act as your Internet Identity accounts at a
  > specific app. Financial transactions are not supported: token-ledger
  > transfer and approval methods are refused to protect you, and this version
  > includes no funding or canister-management tools — we anticipate those
  > will come in a future version.
  >
  > On the Internet Identity consent screen you explicitly choose the session
  > duration (10 minutes to 30 days) and the access level: "Questions only"
  > or "Actions & questions". For a Questions-only session, the Internet
  > Computer itself rejects actions at ingress, not just this server, and you
  > can revoke any connection at https://id.ai/manage/settings. Every tool
  > declares what it does (read-only, state-changing, or destructive — the
  > destructive ones prompt before running), returns structured results, and
  > identity-bearing results echo the app origin they were derived for, so
  > mismatches are visible. The server never guesses domains from app names —
  > lookalike domains are refused rather than resolved.
- **Categories** (1–5): Developer tools; plus whatever the portal offers
  closest to data/productivity/web3.
- **Documentation URL:** `https://mcp.internetcomputer.org` (landing page;
  README as backup: `https://github.com/dfinity/imcp2#readme`)
- **Privacy policy URL:** `https://mcp.internetcomputer.org/privacy-policy`
  — enter it only once the page is live (blocker 1); a missing or incomplete
  policy is documented as immediate rejection. Do not substitute the
  foundation-wide `dfinity.org/privacy`.
- **Support contact:** `mcp@dfinity.org`
- **Company:** DFINITY Foundation / DFINITY Stiftung, `https://dfinity.org`,
  plus a named primary contact for review updates.
- **Data handling:** declare the gateway model honestly. DFINITY operates
  the server itself plus `dashboard.internetcomputer.org` and
  `skills.internetcomputer.org`, but **not** the rest of what it talks to:
  the API boundary nodes (`icp-api.io`) and Internet Identity (`id.ai`) are
  DAO-governed through the NNS. So this is not "first-party APIs only" on
  two counts: that, and user-directed calls being forwarded to third-party
  application canisters chosen by the user (carrying the call arguments and
  the user's per-app principal), plus app discovery fetching metadata from
  user-supplied origins. Pick the portal option matching a
  legitimately-proxied/gateway service; if the options don't fit, put this to
  mcp-review as a follow-up (the 2026-07-31 email did not cover it) rather
  than self-certifying "own API". No personal-health data. No ads or
  sponsored content.
- **Icon:** [`docs/assets/icp-logo-1024.png`](assets/icp-logo-1024.png)
  (square, transparent; 512 variant beside it).
- **Allowed link URIs:** none needed (no `ui/open-link` usage).
- **Example prompts** (≥3 required; all work with a fresh Questions-only
  session):
  1. *"What interface does canister gftcp-myaaa-aaaar-qcaaa-cai expose,
     and what can it do?"*
  2. *"Open opencloud.org and list my accounts there."*
  3. *"Does the canister behind https://opencloud.org expose an API doc, and
     what does its interface look like?"*
  4. *"What canisters are behind https://opencloud.org, and which one holds
     the app's data?"*

### Reviewer test instructions (draft for the test-credentials field)

> 1. No shared test account is needed, and none would work well: Internet
>    Identity is passkey-based and device-bound. Create your own at
>    https://id.ai — it takes under a minute — then add the connector by
>    following the setup instructions at https://mcp.internetcomputer.org.
>    Every read-only tool works with any identity, because it reads public
>    network state.
> 2. On the consent screen pick a session duration and an access level:
>    "Questions only" exercises the 9 read-only-annotated tools; "Actions &
>    questions" additionally allows state-changing calls
>    (`canister_update_call`).
> 3. Try the example prompts above. On a Questions-only session a
>    state-changing call (`canister_update_call`) returns an actionable
>    reconnect message rather than an opaque error — that behavior is
>    intended. Access is revocable at any time at
>    https://id.ai/manage/settings.
> 4. Canister-management tools are not part of this version (we anticipate
>    they will come in a future version), so there is nothing to provision:
>    creating and managing canisters happens outside the connector, with the
>    icp CLI.
> 5. Financial ledger operations are refused by design: asking the assistant
>    to move tokens returns a policy message directing the user to a wallet
>    they control — that behavior is intended (financial transactions are
>    not supported).

### The seven compliance acknowledgments

Topics: directory guidelines, first-party API usage, financial transactions,
AI media generation, prompt injection, conversation-data collection, public
documentation. **Financial transactions** is a clean acknowledgment: no
tool initiates or executes a transfer of the user's funds — financial ledger
methods are refused, and no funding or management tools are served (users run
those operations with the icp CLI).
**First-party API usage** is answered by describing the architecture as it
is: DFINITY operates the connector itself; it reaches the network through
public Internet Computer infrastructure (`icp-api.io`, `id.ai`) and forwards
user-directed calls to the application canisters the user names — state
exactly that in the acknowledgment. The **prompt-injection** acknowledgment needs open disclosure rather
than a bare yes: tool descriptions are static and contain no hidden
instructions, but the `skill://`
resources intentionally return DFINITY-published how-to documents fetched
live from `skills.internetcomputer.org` at the user's request — describe
this in the submission so reviewers see documented, user-requested
functionality rather than covertly pulled behavioral instructions. The rest
are straightforwardly true: the server collects nothing from the
conversation beyond tool arguments and generates no media.

## Submission-day checklist

- [ ] Dedicated ICP MCP privacy policy live at `https://mcp.internetcomputer.org/privacy-policy` (page + landing-page link merged; needs the production release) and entered in the portal (blocker 1)
- [ ] Reply received from mcp-review@anthropic.com settling the financial-transactions and first-party-API acknowledgments (asked 2026-07-31; blocker 2)
- [x] Reviewer access settled: self-serve Internet Identity, instructions in the test-credentials field (blocker 3) — provision a funded identity only if a reviewer asks
- [ ] `release-*` tag cut; `/version` on production shows the intended commit (blocker 4)
- [x] Square PNG icon exported — `docs/assets/icp-logo-{1024,512}.png` (blocker 5)
- [ ] Every tool exercised once by the submitter (portal asks you to confirm this; MCP Inspector or a custom connector in Claude both count)
- [ ] Submitter has Owner / Directory-management access in DFINITY's Claude Team/Enterprise org
