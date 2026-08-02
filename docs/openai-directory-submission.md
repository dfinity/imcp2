# Publishing IMCP2 to the ChatGPT Plugins Directory (OpenAI)

Everything needed to list the production deployment
(`https://mcp.internetcomputer.org/mcp`) in OpenAI's directory — the catalog
OpenAI now calls the **universal Plugins Directory, shared by ChatGPT and
Codex**, built on the Apps SDK and MCP. Companion to
[`anthropic-directory-submission.md`](anthropic-directory-submission.md);
where a requirement matches Anthropic's, the same evidence applies.

Verified against OpenAI's official docs on **2026-08-01**. The portal UI may
add details not published in the docs.

## Where and how submission happens

- **Portal:** <https://platform.openai.com/plugins> (the plugin submission
  portal on the OpenAI Platform dashboard).
- **Who can submit:** a **verified organization** (or verified individual) on
  the OpenAI Platform — complete individual/business verification in
  organization settings first. Submitters need the **"Apps Management"**
  permission with write access
  (`platform.openai.com/settings/organization/people/roles`); "non-owner
  submitters need write access to create or submit drafts".
- **Governing documents:** the
  [App submission guidelines](https://developers.openai.com/apps-sdk/app-submission-guidelines)
  and the [submission flow](https://developers.openai.com/plugins/deploy/submission);
  auth requirements at
  [Authentication](https://developers.openai.com/plugins/build/auth).
- **Review:** "OpenAI reviews the submission. Review timelines may vary as
  OpenAI builds and scales the review process." After approval, the developer
  chooses publication timing from the portal. Updates re-enter review: scan
  the MCP server, submit a new version, publish the approved version.

## The submission form (seven tabs)

1. **Info** — name, descriptions, logo, category, publisher identity. All
   policy URLs must be public and match the verified publisher.
2. **MCP** — production server URL (type: *Universal*, a fixed endpoint) and
   auth details; **domain verification** (below); then *Scan Tools* to
   discover and annotate tools.
3. **Skills** — optional; static skills can be imported from the server scan.
4. **Prompts** — starter prompts demonstrating realistic workflows.
5. **Testing** — **minimum 5 positive and 3 negative test cases** with
   expected outcomes and reproducible steps; they must pass on ChatGPT web
   *and* mobile.
6. **Global** — country/region availability.
7. **Submit** — release notes and policy attestations.

## Readiness: requirements already met

| Requirement | Status |
|---|---|
| OAuth 2.1 authorization-code + PKCE **S256**, per the MCP authorization spec | ✅ live; `code_challenge_methods_supported: ["S256"]` |
| Client registration: DCR (`registration_endpoint`) — CIMD and predefined clients also accepted | ✅ RFC 7591 DCR live and verified |
| Discovery documents (RFC 8414 AS metadata + RFC 9728 protected-resource) | ✅ all live, path-scoped + root fallback |
| ChatGPT's callback `https://chatgpt.com/connector/oauth/{callback_id}` accepted | ✅ the redirect allow-list pins `("chatgpt.com", "/connector/oauth/")` as a prefix ([`src/auth.rs`](../src/auth.rs), `DEFAULT_ALLOWED_REDIRECTS`) |
| No machine-to-machine grants (client credentials etc. unsupported by ChatGPT) | ✅ user-consent authorization-code flow only |
| Tools explicitly annotated `readOnlyHint` / `destructiveHint` / `openWorldHint` — "incorrect or missing action labels are a common cause of rejection" | ✅ set on all 26 tools. The unit test enforces annotation presence and the `readOnlyHint`/`destructiveHint` values; `openWorldHint` is declared everywhere but not asserted by the test, so re-check it in the portal's Scan Tools step |
| Tool names "human-readable, specific, and descriptive"; accurate descriptions; minimum-information requests | ✅ reviewed against the same bar for the Anthropic listing |
| Public HTTPS production endpoint, stable and complete ("trial or demo plugins will not be accepted") | ✅ production deployment |
| Privacy policy disclosing "categories of personal data collected, purposes of use, categories of recipients, data retention timelines" | ⏳ **pending the production release**: the rewritten policy matches these four required disclosures exactly and is live on staging, but `https://mcp.internetcomputer.org/privacy-policy` serves nothing until the next `release-*` tag ships it (see the checklist) |
| Customer support contact | ✅ <mcp@dfinity.org> |
| Logo | ✅ [`docs/assets/icp-logo-1024.png`](assets/icp-logo-1024.png) |

Note the legacy redirect `chatgpt.com/connector_platform_oauth_redirect` is
not in the allow-list; per OpenAI's docs the current `{callback_id}` form is
what ChatGPT uses, and the legacy URI merely "continues to work" for old
connections. Add it via `OAUTH_ALLOWED_REDIRECT_PREFIXES` at deploy time only
if a reviewer reports a failure.

## Blockers and open items

### 1. Domain-verification endpoint — implemented, awaits the token

The portal requires proving control of the host: an endpoint at
`https://<host>/.well-known/openai-apps-challenge` must return **only** the
verification token revealed during submission ("do not return JSON, a list of
tokens, or multiple tokens"). The route ships with this PR: it serves
`$OPENAI_APPS_CHALLENGE_TOKEN` verbatim as `text/plain` (trimmed, so unit-file
whitespace can't break OpenAI's exact-match check) and 404s while the variable
is unset, so it is inert until a submission is in flight. When the portal
reveals the token: set the **repository variable**
`OPENAI_APPS_CHALLENGE_TOKEN` (Settings → Secrets and variables → Actions →
Variables — a variable, not a secret; the token is world-readable by design)
and deploy. Then have the portal run its check.

### 2. Demo account (same tension as Anthropic, stricter wording)

The guidelines say "provide a login and password for a fully featured demo
account" and warn that "plugins that require additional login steps ... will
be rejected". Internet Identity has no login/password — it is passkey-based
and self-serve. Position to state in the Testing tab: reviewers create their
own Internet Identity in under a minute (instructions on the landing page);
every read-only tool works with any identity because it reads public network
state. Have the fallback ready (a provisioned identity with a recovery
phrase, a controlled canister, and a cycles balance) if review pushes back —
and expect a higher chance of push-back than at Anthropic given the
login-and-password wording.

### 3. Policy check: commerce and crypto

OpenAI's restrictions differ usefully from Anthropic's blanket
financial-transfers prohibition:

- Prohibited: "Crypto or NFT offerings involving **speculation, consumer
  deception**". IMCP2 offers no speculation product — no trading, prices, or
  markets. Cycles funding is metered compute credit for the user's own
  canisters.
- Commerce rules ("only for physical goods", no digital-goods selling, no
  embedded checkout) govern *selling through the app*; IMCP2 sells nothing.
- `canister_update_call` can still, in principle, reach token ledgers at the
  user's direction. The description should say what the connector is
  (infrastructure tooling) and what gates actions (explicit "Actions &
  questions" opt-in, network-enforced), the same honesty posture as the
  Anthropic submission. There is no published pre-submission contact at
  OpenAI equivalent to mcp-review@anthropic.com; the attestations step is
  where this is declared.

### 4. Test cases (authoring work)

At least 5 positive + 3 negative cases with expected outcomes, passing on web
and mobile. Draft set:

Positive:
1. "What is canister ryjl3-tyaaa-aaaaa-aaaba-cai?" → identifies the ICP
   ledger, its controllers and interface.
2. "Find the ckUSDC ledger and show its interface" → resolves via the
   dashboard registry, returns the Candid interface.
3. "What canisters are behind https://oisy.com?" → App Connect discovery
   returns the app's canisters with provenance.
4. "Open the NNS app and list my accounts there" (signed in) → resolves the
   derivation origin, lists II accounts.
5. "Check the status of canister <test-canister-id>" (signed in, Actions
   session, identity controls it) → run state, cycles, module hash.
6. "Get the Motoko skill" → returns the skill document.

Negative:
1. "Open https://multidex.com" → refused by the IC-evidence gate, with the
   did-you-mean error naming the real app (`https://multidex.ai`). The
   explicit scheme matters: a bare `multidex.com` is deliberately treated as
   a wrong-TLD guess and *repaired* to the canonical URL rather than refused,
   so the bare form is not a negative case.
2. A management call on a "Questions only" session → actionable
   reconnect-with-actions message, not an opaque error.
3. Any authenticated tool with no sign-in → clean 401 → OAuth flow starts
   (no crash, no hang).
4. "Delete canister <id I don't control>" → the network rejects it; the
   error is surfaced legibly.

### 5. Decisions for the submitter

- **Country availability** (Global tab): presumably all countries; decide
  explicitly.
- **Category** and final listing copy: start from the Anthropic drafts (name
  `Internet Computer (ICP)`, the description in
  [`anthropic-directory-submission.md`](anthropic-directory-submission.md)),
  but the adaptation is more than field limits — that description names
  Claude throughout ("The official connector between Claude and the Internet
  Computer", "Claude can work with the IC directly"). Replace every
  platform-specific mention with ChatGPT (or neutral "your AI assistant")
  wording before submitting.
- **Which OpenAI org** submits, and who holds the Apps Management role.

## Submission-day checklist

- [ ] OpenAI Platform organization verified (business verification)
- [ ] Submitter holds the Apps Management write permission
- [ ] Repository variable `OPENAI_APPS_CHALLENGE_TOKEN` set to the portal's token and deployed; `curl https://mcp.internetcomputer.org/.well-known/openai-apps-challenge` returns exactly the token (blocker 1 — the route itself ships with this PR)
- [ ] Privacy policy live at `https://mcp.internetcomputer.org/privacy-policy` (same release as the Anthropic listing needs)
- [ ] Tools re-scanned in the portal after any server change; annotations verified in the scan
- [ ] 5+ positive and 3+ negative test cases entered, verified on web and mobile
- [ ] Starter prompts entered; country availability chosen
- [ ] Policy attestations reviewed against blocker 3's analysis
- [ ] Demo-account note entered per blocker 2, fallback identity ready

## Sources (fetched 2026-08-01)

- [App submission guidelines](https://developers.openai.com/apps-sdk/app-submission-guidelines)
- [Submit plugins (flow)](https://developers.openai.com/plugins/deploy/submission)
- [Authentication](https://developers.openai.com/plugins/build/auth)
- [Developers can now submit apps to ChatGPT](https://openai.com/index/developers-can-now-submit-apps-to-chatgpt/)
