# ICP MCP Privacy Policy (source text)

> This is the source text for the page served at
> `https://mcp.internetcomputer.org/privacy-policy`
> (`src/assets/privacy-policy.html`). Keep the two in sync: the served page is
> what users and the Anthropic directory review actually see.
>
> **Revised against the privacy review of 2026-07-31.** Technical claims are
> drawn from this repository's behaviour and were re-verified for that
> revision (see "Logging audit" at the foot of this file). Re-verify them
> against the deployed release whenever the policy is republished.
>
> **Three items still need input before this can be called final** and are
> marked `[NEEDS INPUT]` in the text:
>
> 1. **Hosting locations.** Nothing in this repository records where the hosts
>    run. Swiss law requires naming the countries personal data is transferred
>    to and the safeguards relied on, so ops must supply the region(s) for the
>    application hosts and for anything holding logs or metrics.
> 2. **Legal bases.** Proposed per purpose below, but the mapping is a legal
>    determination, not an engineering one.
> 3. **Supervisory authority and EU representative.** The FDPIC is named. If
>    the Service is treated as offering services into the EEA, GDPR Art. 27
>    may require a representative, and one should be named here.

---

## ICP MCP Privacy Policy

**Effective Date: August 3, 2026**

We, DFINITY Stiftung, Genferstrasse 11, 8002 Zürich, Switzerland ("DFINITY
Foundation") disclose in this ICP MCP Privacy Policy ("Privacy Policy") how we
process personal data in connection with the ICP MCP server (the "Service"),
which lets an AI assistant interact with the Internet Computer and its
ecosystem of applications on your behalf.

This Privacy Policy covers the Service wherever we operate it:

- `mcp.internetcomputer.org`, the production deployment; and
- `mcp.beta.id.ai`, a pre-release deployment used for testing, which runs the
  same software against a test instance of Internet Identity.

It covers both authenticated use, where you have signed in with Internet
Identity, and unauthenticated use: browsing the Service's public pages or
using the tools that read public network information generates requests and
technical logs even when you never sign in.

This Privacy Policy does not apply to other data processing, including:
processing by your AI assistant's provider (for example, Anthropic for
Claude), under its own terms and privacy policy; processing by Internet
Identity, which is covered by the
[Internet Identity Privacy Policy](https://identitysupport.dfinity.org/hc/en-us/articles/36662081856148-DFINITY-Internet-Identity-Privacy-Policy);
and processing by the applications you choose to interact with through the
Service, which are operated by third parties under their own policies.

### How signing in works, and what the Service holds

The Internet Computer is a public network that runs applications reliably
using a consensus protocol. The Service lets an AI assistant read public
information from it without any sign-in.

For an assistant to act on your behalf, you sign in once with Internet
Identity. **Your long-term authentication credentials never leave Internet
Identity**: your passkeys, recovery phrase, and any linked accounts stay
there, are never entered into the chat, and are never shared with the
Service.

What the Service does hold, once you approve a connection, is a **delegated
session signing key**. Internet Identity issues it a time-limited, scope-
limited authorization to act as you, and the Service uses that key to sign
the requests your assistant makes. It is a signing credential, so it is worth
being precise about its limits: it is not your Internet Identity key, it
cannot be used to sign in as you anywhere else, and it stops working when the
authorization expires or you revoke it. Separately, your AI assistant holds an
OAuth access token that lets it reach the Service; that token's lifetime is
capped by the same authorization.

On the Internet Identity consent screen you make two explicit choices: how
long the connection lasts (from 10 minutes up to 30 days), and its access
level:

- **"Questions only"** lets the assistant read. Read access is not the same as
  harmless: acting as you, the Service can retrieve data that applications
  show only to you, including account balances, holdings, and activity
  history, and those results are returned to your assistant. What this level
  prevents is *changing* anything.
- **"Actions & questions"** additionally lets the assistant submit actions
  that change state.

For a "Questions only" connection, the Internet Computer network itself
rejects action requests; the restriction does not depend on the Service alone.

**The authorization is not restricted to particular applications.** Whichever
level you choose applies to any application your assistant is directed to: the
Service derives a per-application identity on demand for whichever application
is named at the time. Combined with a duration of up to 30 days, that is a
broad credential, so choose the shortest duration that suits your task, and
revoke connections you are no longer using at
[id.ai/manage/access](https://id.ai/manage/access).

The Service does not profile individual users, does not use advertising, and
does not use tracking cookies. It sets one transient, security-purpose cookie
during sign-in, described below.

### 1. Data Categories Processed, Purposes, and Legal Bases

`[NEEDS INPUT: the legal bases below are proposed; confirm with legal.]`

We process the following categories, solely to provide, secure, and improve
the Service.

**Session and authorization data**: the delegated session signing key, the
session duration and access level you chose, and the identifier the Service
uses for you at its own origin. Purpose: performing the requests your
assistant makes. Legal basis: performance of the service you requested.
During sign-in the Service also sets one transient cookie (`mcp_connect`;
HttpOnly, Secure, SameSite=Lax), set and read by the server only and not
accessible to scripts in web pages. It binds the sign-in to the browser that
started it, protecting you against session-fixation attacks, and is not used
for tracking. Legal basis: our legitimate interest in securing the sign-in,
and it is strictly necessary for a function you requested.

**Requests and their results**: the requests your assistant makes
(application and canister identifiers, method names, query and call
arguments) and **the results returned for them**. Both can contain arbitrary
personal data: your own, and data about third parties held by the
applications you query. Depending on what you ask for, results may include
account names and numbers, balances and holdings, activity and timestamps,
identifiers, web addresses, and application-specific records. The Service
encodes, signs, forwards, and returns this data; it processes it transiently
to execute each call and does not store it after the call completes, and it
does not store conversation content. Legal basis: performance of the service
you requested.

**Account information**: when your assistant uses tools that list your
Internet Identity accounts at an application, or that ask which identity you
use there, the Service processes those account names, numbers, and last-used
timestamps, and the per-application identity in question. A per-application
identity is a pseudonym specific to that application; depending on how you use
that application, you may consider it private. Processed to answer the
request; not stored after the session. Legal basis: performance of the
service you requested.

**Connection (OAuth) data**: when an assistant connects, the Service stores
its registration: a generated client identifier, the assistant's redirect
address, and a last-used timestamp, plus short-lived authorization codes and
access tokens. A registration describes assistant software rather than you,
but we treat it as pseudonymous personal data, because a redirect address can
identify an organisation, a deployment, or a device. Legal basis: performance
of the service you requested.

**Technical logs**: see section 5 for exactly what these contain. Purposes:
operating, securing, and debugging the Service, and abuse prevention. Legal
basis: our legitimate interest in keeping the Service available, secure, and
free of abuse.

**Aggregated operational metrics**: counts such as how many connections are
active and how often errors occur. These are aggregates and do not identify
individual users. Purpose: operating and improving the Service. Legal basis:
our legitimate interest in understanding and improving how the Service
performs.

### 2. Who Receives Data

Using the Service necessarily sends data to others. In order of how directly
each one is involved:

**Your AI assistant, and its provider.** Everything the Service returns goes
back to the assistant that asked for it. That includes results you requested
that contain private, account-specific data, your account names, and your
per-application identities. Your assistant's provider (for example, Anthropic
for Claude) processes that data under its own terms and privacy policy, not
this one. This is inherent to using an AI assistant as the interface.

**The Internet Computer network.** Your requests are executed by the network's
nodes, which are operated by independent node providers in a number of
countries, and reach it through public API boundary nodes (`icp-api.io`).
Internet Identity (`id.ai`) authenticates you. These are part of the Internet
Computer and are governed by its DAO, the Network Nervous System, rather than
operated by DFINITY Foundation.

**The applications you choose.** A question or action you direct at an
application carries your request and your per-application identity to that
application and its operator, who may be anyone. What an application records,
retains, or publishes is governed by that application, not by this Privacy
Policy, and may be publicly accessible. Actions that change state become part
of that application's state on a public network.

**Websites you ask the Service to look up.** When you ask it to find the
application behind a web address, the Service fetches metadata from that
address, which discloses the request to whoever runs that site.

**Two services DFINITY Foundation operates**: the public canister-metadata
service at `dashboard.internetcomputer.org` and the developer-skills service
at `skills.internetcomputer.org`.

**Our hosting and infrastructure providers**, which process data on our behalf
as processors under contract. `[NEEDS INPUT: name the hosting provider, and
any observability or error-reporting processor if one is introduced.]`

We do not sell your data, and we do not share it with third parties for their
own purposes.

### 3. International Transfers

`[NEEDS INPUT: state the country or countries the application hosts, logs,
and metrics reside in, and the transfer safeguard relied on where that is
outside Switzerland and the EEA.]`

Separately, and by design, the Internet Computer is a global public network:
its nodes are operated by independent providers in many countries, so
requests you submit and anything you write to an application are processed
internationally and outside our control. That is inherent to using a public
network rather than a transfer we arrange.

### 4. Data Retention

| Category | Retained |
|---|---|
| Session and authorization data (signing key, access level, duration) | In volatile memory only, never written to disk. Discarded when the duration you chose elapses (at most 30 days) or when the Service restarts, whichever comes first. |
| Requests, results, account information | Processed transiently; not retained after the call completes. |
| Authorization codes and access tokens | In memory only; codes expire after two minutes, tokens no later than the session duration you chose. |
| Connection (OAuth) registrations | Stored on disk so an assistant can reconnect across restarts. There is currently **no time limit**: a registration is kept until it is displaced once the store reaches its cap of 10,000, which for a rarely-used deployment can mean indefinitely. |
| Technical logs | Up to three months, then deleted. |
| Aggregated operational metrics | `[NEEDS INPUT: state a retention period, or state that they are not persisted beyond the current process.]` |

Revoking a connection ends the authorization immediately, but does not by
itself erase the session record: the delegated signing key stays in memory,
unusable, until the duration you originally chose elapses or the Service
restarts. We intend to discard it as soon as a revocation is observed; until
that ships, the row above describes the actual behaviour.

### 5. What Our Logs Contain

We would rather be specific than make sweeping promises, so:

- Every request produces one log line with the HTTP method, the path, the
  response status, and how long it took. Query strings and request bodies are
  never included, which keeps single-use codes and delegations out of logs.
- Sign-in and session events log the session identifier, the identifier the
  Service uses for you at its own origin, the access level, and expiry times.
- **No log line records the applications or canisters you interact with, the
  arguments you send, or the results you receive.** The parts of the Service
  that perform tool calls do no logging at all.
- Our web server is configured without access logging, so client IP addresses
  and browser user agents are not recorded as a matter of course. They are
  unavoidably processed in transit in order to serve a request, and can appear
  in diagnostic output when a connection or the process itself fails.
- Logs are held by the operating system's journal on our hosts, subject to the
  retention bound above.

### 6. Identifiers, and What They Could Link

Internet Identity gives each application a different identity for you, so
applications cannot recognise you across applications. The Service is a
participant in that design and we want to be plain about what it can see: to
do its job it handles your per-application identities, and the identifier it
holds for you at its own origin is stable for a given Internet Identity, so
in principle it could associate separate sessions with the same user. Two
things limit that in practice: per-application identities and the
applications you visit are never written to logs (section 5), and nothing the
Service discloses to an application lets that application recognise you
anywhere else.

### 7. Your Rights

Subject to the conditions in applicable law, you have the right to **access**
the personal data we hold about you, to have inaccurate data **rectified**, to
have data **erased**, to **restrict** or **object to** processing (including
processing based on our legitimate interests), and to receive data you
provided in a portable form. To exercise any of these, email
<mcp@dfinity.org>.

You can also act directly, without contacting us:

- **Disconnect** the connector in your assistant. This stops that assistant
  using the connection, but does not by itself end the underlying
  authorization.
- **Revoke** the authorization at
  [id.ai/manage/access](https://id.ai/manage/access), which lists every active
  connection for your Internet Identity so you can review and revoke access
  even if you no longer remember which assistant sessions are active.
  Revocation is carried out by Internet Identity and takes effect within at
  most five minutes, after which the Internet Computer rejects any request
  made with that authorization.

If you believe we have handled your personal data unlawfully, you may lodge a
complaint with the Swiss Federal Data Protection and Information Commissioner
(FDPIC), and, where the GDPR applies to you, with the supervisory authority of
your EU or EEA country of residence or workplace.
`[NEEDS INPUT: if an EU representative is required under GDPR Art. 27, name
them here.]`

Data you have submitted to applications on the Internet Computer through your
own requests is held by those applications, not by the Service; requests about
it should be directed to the relevant application operator.

### 8. Changes to This Policy

We may update this Privacy Policy. When we do, we will change the effective
date at the top of this page. For changes that materially affect how we use
your data or what an authorization permits, we will give reasonable advance
notice before the change takes effect, and will not apply them retroactively
to data already collected.

### 9. Contact

For questions about this Privacy Policy or the Service, or to exercise any of
the rights in section 7, email <mcp@dfinity.org>.

---

## Logging audit (2026-07-31)

Section 5 rests on this; redo it whenever the policy is republished.

- Application logging lives in three files only: `src/main.rs`,
  `src/auth.rs`, `src/identities.rs`. `calls.rs`, `discover.rs`, `tools.rs`,
  `management.rs`, and `skills.rs` contain **zero** `tracing::` calls, which
  is what makes the "no canister ids, arguments, or results in logs" claim
  safe. A grep for `tracing::` lines mentioning `derivation`, `canister`,
  `args`, or `origin` returns nothing.
- Request logging (`log_request`, `src/main.rs`) records method, path, status,
  and latency, and deliberately omits the query string and the body.
- Session/auth events log `session_id`, the Service-scoped principal, the
  access level, and expirations.
- `deploy/native/Caddyfile` configures no `log` directive, so the reverse
  proxy writes no access log.
- The status dashboard emits a single sanitised error line
  (`monitoring/mcp-status/server.js`).
- Everything lands in journald, bounded by the `MaxFileSec=1week` +
  `MaxRetentionSec=12week` drop-in that `deploy/native/deploy.sh` installs.
