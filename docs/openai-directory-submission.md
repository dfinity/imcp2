# Publishing IMCP2 to the ChatGPT Plugins Directory (OpenAI)

Everything needed to list the production deployment
(`https://mcp.internetcomputer.org/mcp`) in OpenAI's directory — the catalog
OpenAI now calls the **universal Plugins Directory, shared by ChatGPT and
Codex**, built on the Apps SDK and MCP. Companion to
[`anthropic-directory-submission.md`](anthropic-directory-submission.md);
where a requirement matches Anthropic's, the same evidence applies. The
plugin was **approved on 2026-10-13 and is published** (see the log below);
the blockers and drafts further down are what the submission was built from.
Keep them current for the next version.

Verified against OpenAI's official docs on **2026-08-01**; the submission
flow (publishing, daily MCP scans, resubmission) re-verified **2026-10-29**.
The portal UI may add details not published in the docs.

> **Server-state claims re-verified 2026-09-01.** Tool-surface numbers below
> were regenerated from a live scan of a deployed instance of the current
> build plus the code at `main` (the count is unit-pinned in
> [`crates/imcp2-core/src/tools.rs`](../crates/imcp2-core/src/tools.rs)).
> Production probes the same day found `mcp.internetcomputer.org` fronted by
> Internet Computer HTTP-gateway infrastructure that forwards only the MCP
> and OAuth paths — `/version`, `/status/` and
> `/.well-known/openai-apps-challenge` answer with a redirect at that edge.
> Domain verification is unaffected: OpenAI accepts the challenge on a
> **parent host name**, and the token is served from
> `https://internetcomputer.org/.well-known/openai-apps-challenge`
> (re-verified 2026-09-22; see blocker 1). The rows and steps below that rely
> on `/version` say so inline.

## Submission log

- **2026-09-30** — submitted through the portal as **"Internet Computer"**
  (OpenAI's receipt names it "Internet Computer (v1.0.0)"; submission
  `C-BkbT0QZDSZMg`, app id `asdk_app_6a8ed3b67b50819186d6538d464af5ef`).
- **2026-10-01** — **Rejected** by <openai-review@tm.openai.com>, the stated
  reason: "We're unable to complete your sign-in or OAuth flow. Please ensure
  valid, working credentials are included and that they include no
  additional setup or verification to access your service." The likely cause
  was on our side: the switch to CIMD-by-default alongside DCR
  ([#191](https://github.com/dfinity/imcp2/pull/191) and
  [#203](https://github.com/dfinity/imcp2/pull/203), merged 2026-09-23/24;
  "the migration from DCR-only to CIMD-mode" in the reply to the reporter)
  had broken dynamic client registration for ChatGPT, as a user had reported
  to mcp@dfinity.org on 2026-09-25: HTTP 400, redirect URI
  `https://chatgpt.com/connector_platform_oauth_redirect` not permitted,
  before Internet Identity sign-in — the error
  [#189](https://github.com/dfinity/imcp2/pull/189) had fixed on 2026-09-03
  (the note under the readiness table explains the two callback forms).
  OpenAI's email does not say where its attempt failed, so this is an
  inference. The test account itself (an SSO sign-in through `yettodo.org`,
  user `openai-icp-mcp@yettodo.org` as supplied to OpenAI, password in the
  portal's Testing tab — a separate account from Anthropic's) was correct.
  On 2026-10-05 the reporter was told the migration was complete and all
  clients should work again; what changed on the server is not recorded in
  this repository.
- **2026-10-02** — reply on the rejection thread, calling the failure a
  transient server error since resolved, and asking for a retry.
- **2026-10-12** — resubmitted through the portal as **"Internet Computer
  (ICP)"** (submission `C-MliBQBQ5AYYD`), with "improved submission
  documents" (the fields that changed are not recorded here). Later that day
  the review team answered the 2026-10-02 reply (case `16275156`): a review
  cannot be retried from the email thread; resubmit through the portal,
  which had already been done.
- **2026-10-13** — **Approved**: "Your plugin, Internet Computer (ICP), has
  been approved and is ready to publish" (app id
  `asdk_app_6acc9f589e548191a4ffa5a30842ac2d`). **Published** by the
  submitter from the portal (date not recorded; live in ChatGPT as of
  2026-10-29). The ChatGPT settings page the submitter used to confirm it is
  <https://chatgpt.com/settings/plugins-settings/plugin_asdk_app_6acc9f589e548191a4ffa5a30842ac2d>;
  whether it doubles as the public listing is unverified (see the
  checklist).
- **2026-10-28** — OpenAI's daily scan of the MCP server (it picks up new or
  updated tools and ships the ones that qualify to the listing without a new
  version going through review; the docs do not say what qualifies)
  reported that it could not run: "its MCP server authorization is missing
  or no longer works". Existing tools stay live. The fix is in the portal:
  open the plugin, **MCPs** tab, **Reconnect** (or **Connect account**) and
  complete the sign-in (open item in the checklist).

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
  the MCP server, submit a new version, publish the approved version. In
  practice both reviews answered within a day of submission; a rejection is
  not retried from its email thread (the thread is for contesting the
  decision), a retry is a resubmission in the portal. After publication
  OpenAI scans the server daily for tool changes, under an authorization the
  submitter grants on the plugin's MCPs tab and must restore when it lapses
  (see the log). Tool changes the daily scan accepts ship without re-review;
  anything else goes through a new version as above.

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
| Client registration: CIMD preferred; DCR (`registration_endpoint`) and predefined clients also accepted | ✅ both. CIMD implemented (trust-policy-gated per PR #143), advertised as `client_id_metadata_document_supported: true` by default (`McpConfig::cimd_enabled`; the `imcp2` binary has it on unless `OAUTH_CIMD_ENABLED=0`) — ChatGPT's live document (`https://chatgpt.com/oauth/client.json`) is a fixture of the parsing test ([`src/auth.rs`](../src/auth.rs)); it prefers `private_key_jwt` but lists `none`, which is what it uses against this AS — and RFC 7591 DCR live and verified |
| Discovery documents (RFC 8414 AS metadata + RFC 9728 protected-resource) | ✅ all live, path-scoped + root fallback |
| Both of ChatGPT's callbacks accepted — `https://chatgpt.com/connector_platform_oauth_redirect` (the form it sends us) and `https://chatgpt.com/connector/oauth/{callback_id}` | ✅ the redirect allow-list pins both paths for `chatgpt.com` ([`src/auth.rs`](../src/auth.rs), `DEFAULT_ALLOWED_REDIRECTS`) |
| No machine-to-machine grants (client credentials etc. unsupported by ChatGPT) | ✅ user-consent authorization-code flow only |
| Tools explicitly annotated `readOnlyHint` / `destructiveHint` / `openWorldHint` — "incorrect or missing action labels are a common cause of rejection" | ✅ set on all 10 tools (9 read-only; the one write is `canister_update_call`). The unit test enforces annotation presence and the `readOnlyHint`/`destructiveHint` values; `openWorldHint` is declared everywhere but not asserted by the test, so re-check it in the portal's Scan Tools step |
| Tool names "human-readable, specific, and descriptive"; accurate descriptions; minimum-information requests | ✅ reviewed against the same bar for the Anthropic listing. Replies are minimized to match: the account listing carries names and numbers only (no last-used timestamps), and no routine reply echoes the user's per-app principal — `get_app_principal` returns it on request |
| "Tools should behave exactly as their names, descriptions, and inputs indicate"; "side effects should never be hidden or implicit" | ✅ each description states what the tool does, returns, and rejects; the financial-transactions policy is stated in the server-level instructions rather than in any description |
| Descriptions explain when a tool applies, and must not attempt to manipulate the model: no unrelated behavioral instructions, no overly broad triggering, no preference over or interference with other plugins, no calls to unrelated external software, no hidden or obfuscated instructions | ✅ each description states what its tool does, returns, rejects, and requires — including the constraints a caller needs, such as `open_app`'s "do not construct a domain from the name" — while none of the five prohibited manipulations appears. A unit test (`model_readable_metadata_respects_marketplace_policy`) guards this across the server instructions, all 10 descriptions, and the argument and reply schemas — precisely: it rejects an enumerated set of phrasings (those that appeared here before, plus what review named) and, completely, any character outside a small allowlist, so no invisible character can ride along; judging a novel phrasing of a prohibited intent is human review's job, not the test's. `the_policy_gate_catches_what_it_lists` keeps it live from both sides, and `open_app_metadata_forbids_a_constructed_domain` pins the safeguard itself |
| Required identifiers must not depend on the model guessing them | ✅ `open_app` refuses an unknown bare name, and refuse a URL that would need its own origin assumed as the derivation origin when that origin shows no Internet Computer evidence, rather than resolving a guess (an app that declares its derivation origin is taken at its declaration, so that path is not gated by the evidence probe — but a CROSS-origin declaration is accepted only when the declared origin authorizes this app in its `/.well-known/ii-alternative-origins`, and an unauthorized one is refused outright rather than falling back, so a declaration is not a way around the identity checks); the description and the `app` schema both say to pass the user's name unchanged and to pass only a user-supplied or officially sourced URL. The IC-evidence check is stated for what it is — evidence that a domain is served from the Internet Computer, not that it is the intended app |
| Public HTTPS production endpoint, stable and complete ("trial or demo plugins will not be accepted") | ✅ production deployment |
| Privacy policy disclosing "categories of personal data collected, purposes of use, categories of recipients, data retention timelines" | ✅ the rewritten policy matches these four required disclosures exactly; its one home is `https://internetcomputer.org/icp-mcp/privacy-policy/` (the old mcp.internetcomputer.org URL permanently redirects there) |
| Customer support contact (OpenAI asks for a URL) | ✅ `https://internetcomputer.org/icp-mcp/support/` — the page's one home (the old mcp.internetcomputer.org URL permanently redirects there); routes users to <mcp@dfinity.org>, the public status page (status.internetcomputer.org), id.ai access management, GitHub issues, and the security policy |
| Terms of Service URL | ✅ `https://internetcomputer.org/icp-mcp/terms/` — the **ICP MCP User Terms**, the end-user agreement to enter in the portal (the old mcp.internetcomputer.org URL permanently redirects there). Swiss-law terms covering the credentials-never-held session model, the user's sole responsibility for authorized actions, irreversibility of network actions, and as-is/liability limits with the Art. 100 CO carve-out. Since 2026-09-01 the operator-side provisions live in a separate agreement, the [ICP MCP App Operator Terms](https://internetcomputer.org/icp-mcp/app-operator-terms/) (dfinity/internetcomputer-org#90), which governs how applications are made discoverable and is not the URL a directory listing wants. Both need the same legal pass as the privacy policy |
| Logo | ✅ [`docs/assets/icp-logo-1024.png`](assets/icp-logo-1024.png) |

Note `chatgpt.com/connector_platform_oauth_redirect` was previously recorded
here as a legacy URI deliberately left out of the allow-list. That was wrong,
and the submission failed on it: OpenAI's two callback forms are not old and
new but conditional on the authorization server. ChatGPT sends
`/connector/oauth/{callback_id}` only to a server *without* issuer
identification, and the stable `/connector_platform_oauth_redirect` to one
that advertises `authorization_response_iss_parameter_supported` — which our
AS metadata does. So the stable path is the one a ChatGPT connection registers
with us, and DCR was rejecting it with `invalid_redirect_uri`. Both paths are
now pinned in `DEFAULT_ALLOWED_REDIRECTS`, so neither needs an
`OAUTH_ALLOWED_REDIRECT_PREFIXES` entry at deploy time.

## Blockers and open items

### 1. Domain verification — resolved on the parent origin

The portal requires proving control of the host: an endpoint at
`https://<host>/.well-known/openai-apps-challenge` must return **only** the
verification token revealed during submission ("do not return JSON, a list of
tokens, or multiple tokens"). The route is merged and deployed in the app: it
serves `$OPENAI_APPS_CHALLENGE_TOKEN` verbatim as `text/plain` (trimmed, so
unit-file whitespace can't break OpenAI's exact-match check) and 404s while
the variable is unset, so it is inert until a submission is in flight.

**Resolved (2026-09-22) without touching the gateway.** OpenAI's submission
docs state that the challenge base "must be the MCP host name **or a parent
host name**; paths are ignored" — for a server at `https://api.example.com/mcp`,
`https://example.com` is an acceptable challenge base. The parent of
`mcp.internetcomputer.org` is `internetcomputer.org`, whose site repository
commits the token at `public/.well-known/openai-apps-challenge`
(dfinity/internetcomputer-org#99, 2026-09-03); it is live and returns exactly
the token as `text/plain`. The gateway front serving `mcp.internetcomputer.org`
forwards only the MCP and OAuth paths and answers `/.well-known/openai-apps-challenge`
with a redirect, but that no longer matters: when the portal asks where to
check the token, choose `internetcomputer.org` as the challenge base.

The app's own route stays as a fallback for the day the portal insists on the
server host itself. That would need the fronting layer to forward
`/.well-known/openai-apps-challenge` to the application (an allowlist entry,
like `/.well-known/oauth-*` and `/.well-known/ii-auth-callbacks`) and the
**repository secret** `OPENAI_APPS_CHALLENGE_TOKEN` set to the portal's token
(Settings → Secrets and variables → Actions → Secrets, repository level — both
deploy callers pass the same one) and deployed.

### 2. Demo account (same tension as Anthropic, stricter wording)

The guidelines say "provide a login and password for a fully featured demo
account" and warn that "plugins that require additional login steps ... will
be rejected". Internet Identity has no login/password — it is passkey-based
and self-serve. **Position drafted before submission (superseded — see *What
went in* below):** reviewers create their own Internet Identity in under a
minute (instructions on the landing page);
every read-only tool works with any identity because it reads public network
state. Have the fallback ready (a provisioned identity with a recovery
phrase in the team vault and an account at a demo app — no controlled
canister or cycles balance is needed: the plugin has no canister-management
tools) if review pushes back —
and expect a higher chance of push-back than at Anthropic given the
login-and-password wording.

**What went in:** the login-and-password requirement was met literally,
with an SSO test account rather than the self-serve text — Internet
Identity's *SSO* option with the company domain `yettodo.org`, signing in
through an Okta integrator org (user `openai-icp-mcp@yettodo.org`, password
in the portal's Testing tab) to an account at the YetToDo demo app, the same
arrangement as the Anthropic submission's account but a separate account.
The 2026-10-02 reply to OpenAI restates those credentials as the ones
supplied. The first review failed at sign-in or OAuth during the disruption
logged above; the resubmission passed. The upkeep notes in the companion's
blocker 3 apply to this account too: a clean-browser sign-in check after
every edit of the Testing tab, and a sign-in to the Okta admin console every
couple of months so the free integrator org is not deactivated.

### 3. Policy check: financial activity and commerce

OpenAI's restriction is the same prohibition Anthropic's is, not a narrower
one. The [app
guidelines](https://developers.openai.com/plugins/app-guidelines) prohibit
"execution of money transfers, crypto transfers, or investment trades"
outright, alongside "crypto or NFT offerings involving speculation, consumer
deception, or financial abuse" — so answer the attestation ("my plugin does
not initiate or execute money transfers, crypto transfers, or investment
trades on behalf of users") from the same non-financial posture the Anthropic
submission states, not from a narrower reading:

- **The plugin is not a financial tool.** Its purpose is reading, building,
  and operating canisters. It serves no funding, trading, creation, or
  dedicated canister-management tools — creating, funding, and deploying
  canisters is work the user does with the icp CLI in their own terminal. The
  generic `canister_update_call` does not reach management-canister lifecycle
  methods either: those calls must carry the target canister as the request's
  effective canister id, and the update-call path does not set one, so the
  boundary node rejects them.
- **No tool initiates or executes a transfer of the user's funds.**
  `canister_update_call` refuses the standardized value-moving methods
  (ICRC-1/ICRC-2 and the ICRC-4/-7/-37 equivalents, plus the NNS/SNS
  governance method `manage_neuron` — neuron staking and disbursement) on
  every canister, the ICP and cycles ledgers' own value-moving methods and
  the cycles-minting canister's funding-completion methods on those
  canisters, any method whose name carries a financial keyword as a whole
  word (`transfer`, `withdraw`, `swap`, `trade`, `exchange`, `pay`, `buy`,
  `deposit`, …, with no exemptions) on every canister, every update call to a canister
  whose own Candid interface declares ICRC-1 or ICRC-2 methods (every ICRC
  ledger and the ICP ledger, detected from the canister itself; an update
  call needs that published interface, so a canister that publishes none, or
  whose interface cannot be read, is refused outright), and every update call
  on the financial-service canisters it carries. The refusal tells the user to
  perform the
  operation outside the connector, in a trusted interface they control, and
  names no venue.
- **The descriptions match the behavior**, as the guidelines require ("tools
  should behave exactly as their names, descriptions, and inputs indicate";
  "side effects should never be hidden or implicit"):
  every tool description says what its tool does, what it returns, and which
  inputs it rejects (an anonymous OQL read, a Candid data query on an OQL
  canister, a URL with no Internet-Computer evidence). The
  financial-transactions policy is a separate, server-wide matter and is
  stated where the scan reads it: in the server-level instructions, covering
  the whole surface at once. Those instructions state the policy and describe
  the three checks that enforce it (by method name, by destination, by the
  canister's own published interface) and the one thing none of them judges;
  the keyword list, the interface markers and the canister ids live in the
  guard and in the refusal each attempted call receives, rather than in a
  copy that would have to be kept in sync. So no description promises a
  behavior the tool does not have, and no refusal is hidden.
- **The commerce and speculation rules have nothing to attach to.** The
  plugin sells nothing (no physical goods, no digital goods or
  subscriptions, no checkout) and offers no speculation product: no trading,
  prices, or markets.

So the attestation is a clean yes. The README and the server instructions
both state that financial transactions are not supported. The landing page is
not a third: #165 moved it to <https://internetcomputer.org/icp-mcp/>,
maintained in dfinity/internetcomputer-org, and it carries no policy text of
its own — adding it there is a separate change in that repository.

### 4. Test cases — entered with the submission

At least 5 positive + 3 negative cases with expected outcomes, passing on web
and mobile. The set below is what the submissions were built from (fold in
any edits made in the portal); keep it current for the next version:

Positive:
1. "What interface does canister gftcp-myaaa-aaaar-qcaaa-cai expose?" →
   the Candid interface plus capability flags, via get_canister_candid.
2. "Does the canister behind https://opencloud.org expose an API doc, and
   what does its interface look like?" → interface + capability flags via
   get_canister_candid / get_canister_api_doc.
3. "What canisters are behind https://opencloud.org?" → discovery returns
   the app's canisters with provenance.
4. "Open opencloud.org and list my accounts there" (signed in) → resolves
   the derivation origin, lists II accounts.
5. "Resolve https://opencloud.org to its Internet Identity derivation
   origin" → open_app returns the origin and how it was determined.

Negative:
1. "Open https://no-ic.example.com" (a reserved domain with no Internet
   Computer presence) → refused by the IC-evidence gate with guidance
   (ask the user for the real URL) rather than resolved to a
   wrong identity.
2. A state-changing call as your app account (canister_update_call with a
   `derivation_origin`, so it is signed with the session's delegation) on a
   "Questions only" session → the network rejects it and the tool reports the
   failed call; the server instructions describe the two Internet Identity
   access levels, so the assistant can explain why and what reconnecting
   changes. (Without a `derivation_origin` the call runs as the anonymous
   principal and the access level does not apply, so pass one to exercise
   this gate.)
3. Any authenticated tool with no sign-in → clean 401 → OAuth flow starts
   (no crash, no hang).
4. "Call an update method on a canister that rejects this caller" → the
   canister/network rejects it; the error is surfaced legibly.

### 5. Decisions for the submitter — taken with the submissions

The values chosen live in the portal; this doc records only what the emails
show. Read the rest off the portal before the next version.

- **Country availability** (Global tab): chosen with the submission; the
  value is not recorded here.
- **Category** and final listing copy: start from the Anthropic drafts (name
  `Internet Computer (ICP)`, the description in
  [`anthropic-directory-submission.md`](anthropic-directory-submission.md)),
  but the adaptation is more than field limits — that description names
  Claude throughout ("The official connector between Claude and the Internet
  Computer", "Claude can work with the IC directly"). Replace every
  platform-specific mention with ChatGPT (or neutral "your AI assistant")
  wording before submitting.
- **Which OpenAI org** submits, and who holds the Apps Management role:
  **submitted from the DFINITY Foundation organization** (the portal's
  notifications go to itowner@dfinity.org, billing@dfinity.org and the
  submitter), by the submitter.

## Submission-day checklist

- [x] OpenAI Platform organization verified (business verification) — the 2026-09-30 submission went through
- [x] Submitter holds the Apps Management write permission — same evidence
- [x] Production runs a release cut from current `main`, containing [#153](https://github.com/dfinity/imcp2/pull/153)–[#158](https://github.com/dfinity/imcp2/pull/158) — the 2026-10-12 resubmission was reviewed against the build production ran then (not recorded here); production has run 0.6.0 since 2026-10-28, which contains them. Externally `/version` is cut off by the gateway front; on-host `curl localhost:8000/version`, or the deploy workflow's record, stays the check for the next submission, since the deploy workflow also accepts older tags/SHAs (rollbacks)
- [x] Domain verification token served on the parent origin, `https://internetcomputer.org/.well-known/openai-apps-challenge` (dfinity/internetcomputer-org#99; returns exactly the token as `text/plain`, re-verified 2026-09-22). In the portal, choose `internetcomputer.org` as the challenge base; no gateway change is needed (blocker 1, resolved)
- [ ] Only if the portal insists on the server host itself: have the gateway front forward `/.well-known/openai-apps-challenge` to the application and set the repository secret `OPENAI_APPS_CHALLENGE_TOKEN` (the app's route serves it verbatim as `text/plain`; it 404s until the variable is set). Not needed while the parent-origin token is accepted
- [x] Privacy policy live at `https://internetcomputer.org/icp-mcp/privacy-policy/`, its one home (the old mcp.internetcomputer.org URL permanently redirects there)
- [x] Tools scanned in the portal for the submission; the 2026-10-12 resubmission included a fresh scan
- [ ] Verify `openWorldHint` on all 10 tools in the next *Scan Tools* run (the readiness table's note; whether it was checked in the submission scans is not recorded)
- [x] 5+ positive and 3+ negative test cases entered (the guidelines' stated minimum); the review passed (blocker 4)
- [x] Starter prompts entered; country availability chosen (blocker 5)
- [x] Policy attestations reviewed against the non-financial posture (blocker 3)
- [x] Demo-account note entered: the SSO test account, not the self-serve text (blocker 2)
- [x] Approved 2026-10-13, published (date not recorded); live in ChatGPT as of 2026-10-29 (app id `asdk_app_6acc9f589e548191a4ffa5a30842ac2d`)
- [ ] Reconnect the MCP authorization for OpenAI's daily scans (notice of 2026-10-28: portal → the plugin → **MCPs** → **Reconnect**), then confirm the next daily scan ran, or run *Scan Tools* in the portal once, so the listing carries the 0.6.0 tool descriptions and the server instructions that describe the guard; the guard itself has been live on production since 2026-10-28
- [ ] Record the public directory link to the listing here once known. No official URL format is documented (third-party coverage says a listing deep link exists); the settings URL in the log is the one the submitter used to confirm publication

## Sources (fetched 2026-08-01; submission flow re-verified 2026-10-29)

- [App submission guidelines](https://developers.openai.com/apps-sdk/app-submission-guidelines)
- [Submit plugins (flow)](https://developers.openai.com/plugins/deploy/submission)
- [Authentication](https://developers.openai.com/plugins/build/auth)
- [Developers can now submit apps to ChatGPT](https://openai.com/index/developers-can-now-submit-apps-to-chatgpt/)
