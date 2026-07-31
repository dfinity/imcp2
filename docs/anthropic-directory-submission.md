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
| Every tool: `title` + `readOnlyHint`/`destructiveHint` (+ `idempotentHint`, `openWorldHint`) | ✅ on all 26 tools, enforced by a unit test ([`src/tools.rs`](../src/tools.rs)) |
| No catch-all read/write tool; reads and writes are separate tools | ✅ 17 read-only tools; writes split per operation |
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

Neither this repo nor the landing page links a privacy policy today, and the
two existing DFINITY policies don't cover this service:

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
  to disk** (`OAUTH_CLIENTS_FILE`, kept in the unit's `StateDirectory` so
  client ids survive redeploys) with no time-based expiry, only LRU eviction
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
- **Third parties:** DFINITY-operated services (boundary nodes,
  `dashboard.internetcomputer.org`, `skills.internetcomputer.org`, Internet
  Identity) plus, at the user's direction, the applications the user chooses
  to interact with — a call carries its arguments and the user's per-app
  principal to that application's operator, and app discovery fetches
  metadata from user-supplied origins. No analytics on the MCP endpoints
  today (say so explicitly, or disclose them if added).
- **Controller and contact:** DFINITY Stiftung; <mcp@dfinity.org>.

Publish it (help-center article alongside the II policy, or a page under
`mcp.internetcomputer.org`), link it from the landing page, and use that URL
in the portal. A draft in the II policy's style is ready for legal review at
[`icp-mcp-privacy-policy-draft.md`](icp-mcp-privacy-policy-draft.md).

### 2. Financial-transactions policy (decision needed)

The Directory Policy **prohibits connectors that transfer money,
cryptocurrency, or other financial assets, or execute financial
transactions**, and the portal's compliance step requires acknowledging this.
Three IMCP2 capabilities are exposed to that reading:

- `canister_update_call` can invoke arbitrary update methods as the user —
  including ICRC ledger `transfer`/`approve` (i.e. token transfers).
- `icp_create_canister` / `icp_top_up_canister` with the `icp` argument
  convert ICP from the user's ledger account via the CMC.

Options, in increasing order of product impact:

1. **Ask first.** Email <mcp-review@anthropic.com> describing the connector
   and these capabilities; ask whether cycles funding (compute-resource
   payment) and generic update calls are acceptable, before submitting.
   Recommended — a truthful compliance acknowledgment isn't possible today
   without an answer.
2. **Directory-safe profile.** Serve a restricted instance for the
   directory, keeping the full server available as a custom connector at
   another path. Note that a blocklist of known ledger canisters or transfer
   methods is NOT sufficient: `canister_update_call` can reach any custom
   ledger, or an intermediary canister that forwards a transfer. A profile
   that actually satisfies the prohibition has to drop the generic update
   tool and the `icp` conversion paths entirely, or restrict actions to a
   reviewed allow-list of non-financial operations.
3. **Submit as-is** and argue in the description that funds movement is gated
   by the explicit access-level choice on the II consent screen ("Questions
   only" vs "Actions & questions"). Risk:
   rejection at the automated scan, burning review-queue time.

Related honesty point for the same step: there is **no per-call confirmation**
for sensitive methods server-side today (an open roadmap item in the README) —
mitigations are the explicit access-level choice on the II consent screen
("Questions only" vs "Actions & questions", enforced at IC ingress),
revocability at any time via id.ai/manage/access (≤5 min latency), and
accurate `destructiveHint` annotations (which make Claude prompt before each
destructive call).

### 3. Reviewer test account (prepare before submitting)

The portal requires a *fully populated* test account with step-by-step
instructions. Internet Identity is self-serve, but passkeys are device-bound,
so a shared account needs a **recovery-phrase-based test identity**. Prepare:

1. A dedicated test II identity (create at <https://id.ai>, add a recovery
   phrase, store it in the team vault) with a couple of named accounts and —
   only if write tools are in scope — a small cycles-ledger balance.
2. Reviewer instructions (draft below) plus the recovery phrase in the
   portal's test-credentials field.

### 4. Production is behind `main`

The live server reports commit `48f1ed6`; `main` carries later hardening
(e.g. #98, #99, #107, #108). Cut a `release-*` tag so the deployment under
review includes them.

### 5. Icon asset

The portal asks for an icon (specs surface in the portal UI). Candidate
source: [`src/assets/dfinity-logo.svg`](../src/assets/dfinity-logo.svg) or the
official ICP mark — have a square PNG export ready.

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
  > specific app, and manage canisters you control: check status, create,
  > install code, start/stop, and top up with cycles.
  >
  > On the Internet Identity consent screen you explicitly choose the session
  > duration (10 minutes to 30 days) and the access level: "Questions only"
  > or "Actions & questions". For a Questions-only session, the Internet
  > Computer itself rejects actions at ingress, not just this server, and you
  > can revoke any connection at https://id.ai/manage/access. Every tool
  > declares what it does (read-only, state-changing, or destructive — the
  > destructive ones prompt before running), returns structured results, and
  > identity-bearing results echo the app origin they were derived for, so
  > mismatches are visible. The server never guesses domains from app names —
  > lookalike domains are refused rather than resolved.
- **Categories** (1–5): Developer tools; plus whatever the portal offers
  closest to data/productivity/web3.
- **Documentation URL:** `https://mcp.internetcomputer.org` (landing page;
  README as backup: `https://github.com/dfinity/imcp2#readme`)
- **Privacy policy URL:** unresolved — leave the submission blocked on
  blocker 1 and enter the dedicated ICP MCP policy's URL once published. Do
  not substitute the foundation-wide `dfinity.org/privacy`: an incomplete
  policy is documented as immediate rejection.
- **Support contact:** `mcp@dfinity.org`
- **Company:** DFINITY Foundation / DFINITY Stiftung, `https://dfinity.org`,
  plus a named primary contact for review updates.
- **Data handling:** declare the gateway model honestly. The server and the
  infrastructure it talks to are DFINITY-operated (IC boundary nodes,
  `dashboard.internetcomputer.org`, `skills.internetcomputer.org`, Internet
  Identity at `id.ai`), but it is not "first-party APIs only": user-directed
  calls are forwarded to third-party application canisters chosen by the
  user (carrying the call arguments and the user's per-app principal), and
  app discovery fetches metadata from user-supplied origins. Pick the portal
  option matching a legitimately-proxied/gateway service; if the options
  don't fit, ask in the mcp-review email (blocker 2) rather than
  self-certifying "own API". No personal-health data. No ads or sponsored
  content.
- **Allowed link URIs:** none needed (no `ui/open-link` usage).
- **Example prompts** (≥3 required; all work with a fresh Questions-only
  session):
  1. *"What is canister ryjl3-tyaaa-aaaaa-aaaba-cai? Who controls it and
     what's its interface?"*
  2. *"Open the NNS app and list my accounts there."*
  3. *"Find the ckUSDC ledger and show me its Candid interface."*
  4. *"What canisters are behind https://oisy.com, and which one holds the
     app's data?"*

### Reviewer test instructions (draft for the test-credentials field)

> 1. The connector authenticates with Internet Identity (passkey-based). Use
>    the provided test identity: open the connector's sign-in, choose
>    "Continue with recovery phrase" (or first create your own identity at
>    https://id.ai — takes under a minute; any identity works for read-only
>    tools, which read public chain state).
> 2. On the consent screen pick a session duration and an access level:
>    "Questions only" exercises the 17 read-only-annotated tools; "Actions &
>    questions" also exercises canister-management tools (needs the test
>    identity's cycles balance).
> 3. Try the example prompts above. Questions-only sessions cause management
>    tools to return an actionable reconnect message rather than an opaque
>    error — that behavior is intended. Access is revocable at any time at
>    https://id.ai/manage/access.

### The seven compliance acknowledgments

Topics: directory guidelines, first-party API usage, financial transactions,
AI media generation, prompt injection, conversation-data collection, public
documentation. Two need resolution before the boxes can be checked
truthfully: **financial transactions** (blocker 2) and **first-party API
usage** — the connector legitimately proxies the Internet Computer protocol
on DFINITY-operated infrastructure, but user-directed calls do reach
third-party application canisters; fold both questions into the mcp-review
email. The **prompt-injection** acknowledgment needs open disclosure rather
than a bare yes: tool descriptions are static and contain no hidden
instructions, but `icp_list_skills`/`icp_get_skill` (and the `skill://`
resources) intentionally return DFINITY-published how-to documents fetched
live from `skills.internetcomputer.org` at the user's request — describe
this in the submission so reviewers see documented, user-requested
functionality rather than covertly pulled behavioral instructions. The rest
are straightforwardly true: the server collects nothing from the
conversation beyond tool arguments and generates no media.

## Submission-day checklist

- [ ] Dedicated ICP MCP privacy policy published; its URL (not the foundation-wide one) entered in the portal and linked from the landing page (blocker 1)
- [ ] Financial-transactions stance settled with mcp-review@anthropic.com (blocker 2)
- [ ] Test II identity created, funded (if needed), recovery phrase in the team vault (blocker 3)
- [ ] `release-*` tag cut; `/version` on production shows the intended commit (blocker 4)
- [ ] Square PNG icon exported (blocker 5)
- [ ] Every tool exercised once by the submitter (portal asks you to confirm this; MCP Inspector or a custom connector in Claude both count)
- [ ] Submitter has Owner / Directory-management access in DFINITY's Claude Team/Enterprise org
