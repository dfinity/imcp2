# Publishing IMCP2 to the Anthropic Connectors Directory

Everything needed to submit the production deployment
(`https://mcp.internetcomputer.org/mcp`) to Anthropic's Connectors Directory —
the catalog that serves Claude.ai, Claude Desktop, Claude Mobile, Cowork, and
Claude Code. Field drafts below are pre-filled from this repo and the live
deployment; paste and adapt them in the portal.

Verified against the official docs on **2026-07-31**. The portal UI may add
details (e.g. exact icon dimensions) not published in the docs.

> **Server-state claims re-verified 2026-09-01.** Tool-surface numbers below
> were regenerated from a live scan of a deployed instance of the current
> build plus the code at `main` (the count is unit-pinned in
> [`crates/imcp2-core/src/tools.rs`](../crates/imcp2-core/src/tools.rs),
> `the_default_composition_defers_the_protocol_tools`). Production probes the
> same day found `mcp.internetcomputer.org` now fronted by Internet Computer
> HTTP-gateway infrastructure: `/mcp` and the OAuth discovery documents pass
> through, but `/version` and `/status/` answer with a redirect at that edge —
> the rows and steps below that relied on them say so inline.

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

Transport and auth rows were verified against the live production
deployment (2026-07-31, re-probed 2026-09-01). The tool-surface rows
(annotations, counts, names, schemas) describe `main` — the build under
submission — and match a live scan of a deployed instance of that build
(2026-09-01); production's exact commit can no longer be read externally
(see blocker 4), so have the operators confirm it before submitting:

| Requirement | Status |
|---|---|
| HTTPS remote server, Streamable HTTP transport | ✅ `rmcp` streamable-HTTP, stateless, JSON responses ([`src/lib.rs`](../src/lib.rs)) |
| OAuth 2.0, authorization-code + PKCE **S256**, advertised in metadata | ✅ `code_challenge_methods_supported: ["S256"]` in the live RFC 8414 document |
| Dynamic Client Registration (RFC 7591) — the out-of-the-box `oauth_dcr` mode | ✅ live probe: `POST /mcp/oauth/register` with the claude.ai callback → `201` |
| Client ID Metadata Documents — the `oauth_cimd` mode Anthropic recommends over DCR for directory listings | ✅ `client_id_metadata_document_supported: true` alongside `"none"` in `token_endpoint_auth_methods_supported`, the two flags Claude requires to select CIMD. Claude Code's live document (`https://claude.ai/oauth/claude-code-client-metadata`) is a fixture of the parsing test ([`src/auth.rs`](../src/auth.rs), `cimd_client_id` / `parse_client_metadata`) |
| Claude's hosted callback `https://claude.ai/api/mcp/auth_callback` accepted | ✅ seeded in the redirect allow-list ([`src/auth.rs`](../src/auth.rs), `DEFAULT_ALLOWED_REDIRECTS`) |
| Claude Code loopback redirects (RFC 8252) | ✅ loopback redirects are exempt from the hosted allow-list |
| Discovery documents (RFC 8414 + RFC 9728, path-scoped + root fallback) | ✅ all four live, `WWW-Authenticate` on the 401 points at the resource metadata |
| Every tool: `title` + `readOnlyHint`/`destructiveHint` (+ `idempotentHint`, `openWorldHint`) | ✅ on all 10 tools, enforced by a unit test ([`crates/imcp2-core/src/tools.rs`](../crates/imcp2-core/src/tools.rs)) |
| No catch-all read/write tool; reads and writes are separate tools | ✅ 9 of the 10 tools are read-only; the one write is `canister_update_call`. |
| Tool names ≤ 64 chars | ✅ longest is 23 (`get_canister_oql_schema`) |
| `outputSchema` + structured content on every tool | ✅ enforced by a unit test |
| Certificates from a recognized authority | ✅ Let's Encrypt via Caddy |
| OAuth endpoint latency ≤ 10 s (discovery/registration/token) | ✅ all sub-second in probes |
| Support channel | ✅ <mcp@dfinity.org> (shown on every error screen) |
| Security-vulnerability reporting mechanism (a Software Directory Terms obligation) | ✅ [`SECURITY.md`](../SECURITY.md) → Hackenproof bug bounty |
| Public documentation by publish date | ✅ this repo's README + the landing page at <https://internetcomputer.org/icp-mcp/> (its one home, maintained in dfinity/internetcomputer-org; `https://mcp.internetcomputer.org` permanently redirects there from the release that ships #165) |
| Status/health visibility | ⚠️ <https://mcp.internetcomputer.org/status/> is currently cut off: since the origin moved behind the gateway front it answers with a redirect to the landing page instead of the dashboard (observed 2026-09-01). Have the fronting layer forward `/status/` (and `/version`, which the dashboard and the health workflow read), or point the listing at a reachable status page, before submitting |

Notes on auth mode: pure M2M `client_credentials` is unsupported by Claude
(every connection needs a user in the loop) — IMCP2's user-consent flow via
Internet Identity is exactly the supported shape. Against a DCR-only server
Claude registers a new client on each fresh connection (the registration store
is a bounded LRU of 10,000, which tolerates that churn); Anthropic recommends
**CIMD** (Client ID Metadata Documents) for high-traffic directory listings,
and the server now advertises and implements it, so Claude selects CIMD and
registers nothing.

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
  `dashboard.internetcomputer.org`; and,
  at the user's direction, the applications the user chooses to interact
  with — a call carries its arguments and the user's per-app principal to
  that application's operator, and app discovery fetches metadata from
  user-supplied origins. No analytics on the MCP endpoints today (say so
  explicitly, or disclose them if added).
- **Controller and contact:** DFINITY Stiftung; <mcp@dfinity.org>.

Publication venue: `https://internetcomputer.org/icp-mcp/privacy-policy/` —
the page's one home, maintained in dfinity/internetcomputer-org
(`public/icp-mcp/privacy-policy/`) and live there
(dfinity/internetcomputer-org#77 refreshes its text to the current draft:
the identifier-linkability wording and the updated third-party list).
The MCP server no longer serves a copy: from the release that ships
[#165](https://github.com/dfinity/imcp2/pull/165),
`https://mcp.internetcomputer.org/privacy-policy` answers with a permanent
redirect to that home (until that release it still serves the previous
revision itself). Either URL works in the portal; prefer the canonical one.
The reviewed source
text is [`icp-mcp-privacy-policy-draft.md`](icp-mcp-privacy-policy-draft.md).

### 2. Financial-transactions policy

The Directory Policy **prohibits connectors that transfer money,
cryptocurrency, or other financial assets, or execute financial
transactions**, and the portal's compliance step requires acknowledging this.

**The server is not a financial tool, and does not support financial
transactions:**

- **The connector serves no funding, creation, or canister-management
  tools.** Creating, funding, and deploying canisters is work the user does
  with the icp CLI in their own terminal. The generic `canister_update_call`
  is not a way around that either: management-canister lifecycle calls must
  carry the TARGET canister as the request's effective canister id, which the
  update-call path does not set (it defaults to the callee, `aaaaa-aa`), so
  the boundary node rejects them. No dedicated management tooling is served,
  and
  none of this moves funds.
- `canister_update_call` **refuses the standardized value-moving methods** —
  the ICRC-standard transfer/approval names
  (ICRC-1/ICRC-2 plus ICRC-4/-7/-37) and the NNS/SNS governance method
  `manage_neuron` (neuron staking and disbursement, on every SNS DAO's
  governance as well as the NNS's) on every canister, and the ICP and
  cycles ledgers' own `transfer`/`send_dfx`/`withdraw`/`create_canister`
  methods on those ledgers, the cycles-minting canister's funding-completion
  methods (`notify_top_up`, `notify_create_canister`, `notify_mint_cycles`,
  `create_canister`), and refuses **every** update call on the
  financial-service canisters it carries; the refusal tells the user to
  perform the operation
  outside the connector, in a trusted interface they control, and names no
  venue (a refused canister-creation or funding-completion call points at the
  user-run icp CLI). The policy is stated in the server-level instructions —
  the field the directories scan — where it covers the whole surface at once,
  and a unit test holds it there. What those instructions state is the policy
  itself, not its implementation: the method families and canister scopes are
  in the guard and in the refusal an attempted call receives, so the
  instructions carry no copy of that list to keep in sync.
- The README and the server instructions both state explicitly that
  financial transactions are not supported. The landing page is no longer one
  of them: #165 moved it to <https://internetcomputer.org/icp-mcp/>,
  maintained in dfinity/internetcomputer-org, and the page committed there
  carries no policy text. Stating otherwise here would be a claim about
  content this repository cannot keep true, so adding the posture to that
  page belongs in that repository.

**Posture, stated plainly — the black-and-white answer the compliance step
needs:** no tool initiates or executes a transfer of the user's funds.
Financial ledger methods are refused, and no funding or management tools are
served at all — users run those operations themselves with the icp CLI. The
financial-transactions acknowledgment is made on that basis, without
qualifications.

**mcp-review thread:** an email to <mcp-review@anthropic.com> (2026-07-31)
asked ahead about this acknowledgment. No reply is needed to submit; if one
arrives, answer with the posture above.

Related point for the same step: the **model-readable metadata describes the
surface and the constraints on using it, without attempting to manipulate
Claude**. The server instructions, all 10 tool descriptions, and every
argument and reply schema each say what their tool does, returns, rejects, and
requires — the guidance a caller needs to use it correctly and safely, which
both directories expect a description to carry, including `open_app`'s "do not
construct a domain from the name". What none of them carries is the set of
manipulations the directories prohibit: unrelated behavioral instructions,
overly broad triggering, preference over or interference with other tools,
calls to unrelated external software, and hidden or obfuscated instructions. A
unit test (`model_readable_metadata_respects_marketplace_policy`) guards that
across every one of those surfaces, and what it guarantees is worth stating
exactly: it rejects an enumerated set of phrasings — the ones that appeared here
before, plus the ones review named — and, completely, any character outside a
small allowlist, so nothing invisible can ride along in a field doc. Judging a
novel phrasing of a prohibited intent stays human review's job.
`the_policy_gate_catches_what_it_lists` keeps the gate live from both sides, and
`open_app_metadata_forbids_a_constructed_domain` pins the safeguard itself.
Each description also matches the tool's behavior, so no side effect is
implicit — with one deliberate exception: the financial-transactions policy is
stated in the server-level instructions and in no tool description (a policy
paragraph inside `canister_update_call`'s description would read as a hint that
the tool is usable for financial transactions), and a test
(`financial_policy_is_a_server_instruction_not_a_description`) keeps it that
way. The refusal itself is the tool's error text at call time.

Related honesty point for the same step: there is **no per-call confirmation**
for sensitive methods server-side today —
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
phrase in the team vault and an account at a demo app. (No controlled canister or
cycles balance is needed: the connector has no canister-management tools.)

### 4. Production build can no longer be verified from outside

Production has been redeployed since this document first flagged it as
behind `main` (it then reported `bbf0844`, v0.1.1, the old 26-tool surface):
as of 2026-09-01 the live `/mcp` endpoint, the OAuth discovery documents,
and the II callbacks document all match the current codebase's shape, and a
deployed instance of the current build serves the 10-tool surface this
document describes. What can NO longer be confirmed externally is the exact
commit: `mcp.internetcomputer.org` now sits behind Internet Computer
HTTP-gateway infrastructure that forwards only the MCP and OAuth paths, so
`/version` answers with a redirect at that edge instead of the build report.
Before submitting, have the operators confirm production runs a `release-*`
tag cut from current `main` (on-host `curl localhost:8000/version`, or the
deploy workflow's record) — or have the fronting layer forward `/version`
again so the check works from anywhere.

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
([`crates/imcp2-core/src/assets/dfinity-logo.svg`](../crates/imcp2-core/src/assets/dfinity-logo.svg)) for their
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
  > the chat — and Claude can work with the IC directly: fetch a canister's
  > Candid interface, read app data via typed queries
  > or OQL, and discover the canisters behind any IC app from its name or URL.
  > With your consent it can also act as your Internet Identity accounts at a
  > specific app. Financial transactions are not supported: token-ledger
  > transfer and approval methods are refused to protect you, and there are
  > no funding or canister-management tools.
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
- **Documentation URL:** `https://internetcomputer.org/icp-mcp/` (the landing
  page's home; `https://mcp.internetcomputer.org` permanently redirects there
  from the release that ships #165. README as backup:
  `https://github.com/dfinity/imcp2#readme`)
- **Privacy policy URL:** `https://internetcomputer.org/icp-mcp/privacy-policy/`
  (live; the old `https://mcp.internetcomputer.org/privacy-policy` permanently
  redirects there from the release that ships #165). A missing or incomplete
  policy is documented as immediate rejection. Do not substitute the
  foundation-wide `dfinity.org/privacy`.
- **Support contact:** `mcp@dfinity.org`
- **Company:** DFINITY Foundation / DFINITY Stiftung, `https://dfinity.org`,
  plus a named primary contact for review updates.
- **Data handling:** declare the gateway model honestly. DFINITY operates
  the server itself plus `dashboard.internetcomputer.org`, but **not** the
  rest of what it talks to:
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
>    state-changing call made AS YOUR APP ACCOUNT (`canister_update_call`
>    with a `derivation_origin`, so it is signed with that session's
>    delegation) is rejected by the network, and the tool reports the
>    failed call — that behavior is intended, and reconnecting under
>    "Actions & questions" is what permits such calls. A call with no
>    `derivation_origin` is not signed with the delegation at all: it runs
>    as the anonymous principal, so the access level does not decide it.
>    The connector's own checks still do — the financial-transactions guard
>    runs before any identity resolution or network I/O, so a call it refuses
>    is refused with or without an origin — and past that the canister
>    decides. The server instructions describe both, so the assistant can
>    explain which case a call is in. Access is revocable at
>    any time at https://id.ai/manage/settings.
> 4. No canister creation, funding, or dedicated management tool is served,
>    so there is nothing to provision: that work happens outside the
>    connector, with the icp CLI. (`canister_update_call` is not a substitute:
>    management-canister lifecycle calls need the target as the effective
>    canister id, which that path does not set, so the boundary node rejects
>    them.)
> 5. Financial ledger operations are refused by design: asking the assistant
>    to move tokens returns a policy message saying financial transactions
>    are not supported and recommending the operation be performed outside
>    this connector, in a trusted interface you control — that behavior is
>    intended. The message names no specific venue, and a test enforces
>    that, so do not expect it to name a wallet.

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
exactly that in the acknowledgment. The **prompt-injection** acknowledgment is a clean yes: tool
descriptions are static and contain no hidden instructions, and the
`skill://` resources return DFINITY-authored how-to documents from a
reviewed, versioned bundle compiled into the binary at build time — the
server retrieves no instructions over the network. The rest
are straightforwardly true: the server collects nothing from the
conversation beyond tool arguments and generates no media.

## Submission-day checklist

- [ ] Privacy policy entered in the portal — enter `https://internetcomputer.org/icp-mcp/privacy-policy/`, the page's one home (live; dfinity/internetcomputer-org#77 refreshes its text to the current draft, and the old mcp.internetcomputer.org URL redirects there from the release that ships #165) (blocker 1)
- [x] Financial-transactions acknowledgment is a clean yes (blocker 2): the server does not support financial transactions. No mcp-review reply is needed; if one arrives, answer with the stated posture. The first-party-API/data-handling question was NOT in the 2026-07-31 email: raise it with mcp-review only if the portal's data-handling options don't fit
- [x] Reviewer access settled: self-serve Internet Identity, instructions in the test-credentials field (blocker 3) — if a reviewer asks for a populated account, provision a demo-app account (no funding needed: there are no funding or canister-management tools)
- [ ] `release-*` tag cut; production confirmed to run the intended commit by the operators — externally `/version` is cut off by the gateway front, so the check is on-host or via the deploy workflow's record (blocker 4)
- [x] Square PNG icon exported — `docs/assets/icp-logo-{1024,512}.png` (blocker 5)
- [ ] Every tool exercised once by the submitter (portal asks you to confirm this; MCP Inspector or a custom connector in Claude both count)
- [ ] Submitter has Owner / Directory-management access in DFINITY's Claude Team/Enterprise org
