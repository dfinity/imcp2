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
| Tools explicitly annotated `readOnlyHint` / `destructiveHint` / `openWorldHint` — "incorrect or missing action labels are a common cause of rejection" | ✅ set on all 11 tools. The unit test enforces annotation presence and the `readOnlyHint`/`destructiveHint` values; `openWorldHint` is declared everywhere but not asserted by the test, so re-check it in the portal's Scan Tools step |
| Tool names "human-readable, specific, and descriptive"; accurate descriptions; minimum-information requests | ✅ reviewed against the same bar for the Anthropic listing |
| Public HTTPS production endpoint, stable and complete ("trial or demo plugins will not be accepted") | ✅ production deployment |
| Privacy policy disclosing "categories of personal data collected, purposes of use, categories of recipients, data retention timelines" | ✅ the rewritten policy matches these four required disclosures exactly and `https://mcp.internetcomputer.org/privacy-policy` is live (verified 2026-08-27); the next `release-*` refreshes its text to the current draft |
| Customer support contact (OpenAI asks for a URL) | ✅ `https://mcp.internetcomputer.org/support` — merged and live on production; routes users to <mcp@dfinity.org>, the status dashboard, id.ai access management, GitHub issues, and the security policy |
| Terms of Service URL | ✅ `https://mcp.internetcomputer.org/terms` — merged and live on production; Swiss-law terms covering the non-custodial model, user responsibility for authorized actions, irreversibility of network actions, as-is/liability limits with the Art. 100 CO carve-out. Needs the same legal pass as the privacy policy |
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
tokens, or multiple tokens"). The route is merged and deployed: it serves
`$OPENAI_APPS_CHALLENGE_TOKEN` verbatim as `text/plain` (trimmed, so unit-file
whitespace can't break OpenAI's exact-match check) and 404s while the variable
is unset, so it is inert until a submission is in flight. When the portal
reveals the token: set the **repository secret**
`OPENAI_APPS_CHALLENGE_TOKEN` (Settings → Secrets and variables → Actions →
Secrets, repository level — both deploy callers pass the same one) and
deploy. Then have the portal run its check.

### 2. Demo account (same tension as Anthropic, stricter wording)

The guidelines say "provide a login and password for a fully featured demo
account" and warn that "plugins that require additional login steps ... will
be rejected". Internet Identity has no login/password — it is passkey-based
and self-serve. Position to state in the Testing tab: reviewers create their
own Internet Identity in under a minute (instructions on the landing page);
every read-only tool works with any identity because it reads public network
state. Have the fallback ready (a provisioned identity with a recovery
phrase in the team vault and an account at a demo app — no controlled
canister or cycles balance is needed: the plugin has no canister-management
tools) if review pushes back —
and expect a higher chance of push-back than at Anthropic given the
login-and-password wording.

### 3. Policy check: commerce and crypto

OpenAI's restrictions differ usefully from Anthropic's blanket
financial-transfers prohibition:

- Prohibited: "Crypto or NFT offerings involving **speculation, consumer
  deception**". IMCP2 offers no speculation product — no trading, prices, or
  markets.
- Commerce rules ("only for physical goods", no digital-goods selling, no
  embedded checkout) govern *selling through the app*; IMCP2 sells nothing.
- The attestation "my plugin does not initiate or execute money transfers,
  crypto transfers, or investment trades on behalf of users" is satisfied by
  the shipped behavior — check it on that basis: no tool initiates or
  executes a transfer of the user's funds. Two independent reasons, either
  sufficient. First, `canister_update_call` executes only against a
  **registered application**: it requires an `application_origin` whose
  developer accepted the ICP MCP Developer Terms (published at
  `/developer-terms`) and whose own `/.well-known/ic-architecture` manifest —
  published under the [ICP service-discoverability protocol][protocol] and
  re-read on every call — declares the target canister; every failure refuses,
  and the registry ships empty. A ledger, minter, or exchange canister is never
  a registered application, so it is unreachable by a state-changing call
  whatever the method is named, and a canister id the plugin can otherwise
  discover behind a domain (gateway header, `/env.json`, JS bundle) is
  read-only. Second, within that registered surface `canister_update_call`
  refuses the financial ledger methods (ICRC-1/ICRC-2 and the ICRC-4/-7/-37
  equivalents on every canister, plus the NNS/SNS governance method
  `manage_neuron` — neuron staking and disbursement — on every canister,
  plus the ICP and cycles ledgers' own
  value-moving methods on those ledgers, plus every update call on a curated
  list of known financial-service canisters: token ledgers and minters,
  exchanges, wallet backends, staking/governance), with the policy stated in
  the server-level instructions rather than the tool descriptions (which stay
  free of financial language), and the plugin has no funding or
  canister-management tools at all. README, landing
  page, and server instructions state that financial transactions are not
  supported; the README and the server instructions additionally state the
  registration requirement for state-changing calls.

[protocol]: https://docs.internetcomputer.org/guides/frontends/service-discoverability/

### 4. Test cases (authoring work)

At least 5 positive + 3 negative cases with expected outcomes, passing on web
and mobile. Draft set:

Positive:
1. "What interface does canister gftcp-myaaa-aaaar-qcaaa-cai expose?" →
   the Candid interface plus capability flags, via get_canister_candid.
2. "Does the canister behind https://opencloud.org expose an API doc, and
   what does its interface look like?" → interface + capability flags via
   get_canister_candid / get_canister_api_doc.
3. "What canisters are behind https://opencloud.org?" → discovery returns
   the app's canisters with provenance, its own `/.well-known/ic-architecture`
   manifest first.
4. "Open opencloud.org and list my accounts there" (signed in) → resolves
   the derivation origin, lists II accounts.
5. "Resolve https://opencloud.org to its Internet Identity derivation
   origin" → resolve_app returns the origin and how it was determined.

Negative:
1. "Open https://no-ic.example.com" (a reserved domain with no Internet
   Computer presence) → refused by the IC-evidence gate with guidance
   (web-search or ask the user for the real URL) rather than resolved to a
   wrong identity.
2. "Transfer 1 ICP" → refused before any network call, with the financial
   policy and a pointer to a wallet the user controls. The financial guard is
   evaluated first, so this is the answer whatever `application_origin` is
   passed.
3. Any authenticated tool with no sign-in → clean 401 → OAuth flow starts
   (no crash, no hang).
4. "Call an update method on an app of your choosing" → refused, naming the
   ICP MCP Developer Terms: a state-changing call needs an
   `application_origin` that is a registered application whose own
   `/.well-known/ic-architecture` manifest declares the canister. With the
   registry shipping empty this is the outcome for every application, so it is
   the reviewer's expected result; the refusal offers the read path instead,
   and reads (positive cases 1-5) are unaffected.
5. A state-changing call on a "Questions only" session → refused by the
   registration gate above, before the access level is ever tested. Once an
   application is registered, a Questions-only session's update is rejected by
   the network instead, and the server instructions prime the assistant to
   explain the access level and recommend reconnecting under "Actions &
   questions".

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
- [ ] Production runs a release cut from current `main`: `curl https://mcp.internetcomputer.org/version` reports a commit that contains #153–#158 — verify immediately before submitting, since the deploy workflow also accepts older tags/SHAs (rollbacks), so a deployed challenge token alone does not prove the compliant build is live
- [ ] Repository secret `OPENAI_APPS_CHALLENGE_TOKEN` set to the portal's token and deployed; `curl https://mcp.internetcomputer.org/.well-known/openai-apps-challenge` returns exactly the token (blocker 1 — the route is merged and deployed; it 404s until the variable is set, by design)
- [x] Privacy policy live at `https://mcp.internetcomputer.org/privacy-policy` (verified 2026-08-27; the next release refreshes its text to the current draft)
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
