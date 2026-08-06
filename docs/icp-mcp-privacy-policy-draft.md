# ICP MCP Privacy Policy (source text)

> This is the source text for the page served at
> `https://mcp.internetcomputer.org/privacy-policy`
> (`src/assets/privacy-policy.html`). Keep the two in sync: the served page is
> what users and directory reviews actually see. Technical claims are drawn
> from this repository's behaviour; re-verify them against the deployed
> release whenever the policy is republished (and update section 3 if the
> hosting region ever changes). Operational and review notes are maintained
> outside this repository.

---

## ICP MCP Privacy Policy

**Effective Date: August 3, 2026**

We, DFINITY Stiftung, Genferstrasse 11, 8002 Zürich, Switzerland ("DFINITY
Foundation") disclose in this ICP MCP Privacy Policy ("Privacy Policy") how we
process personal data in connection with the ICP MCP server (the "Service"),
which lets an AI assistant interact with the Internet Computer and its
ecosystem of applications on your behalf.

This Privacy Policy covers the Service at `mcp.internetcomputer.org`,
together with any pre-release deployments of the same software that we
operate. It covers both authenticated use, where you have signed in with Internet
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
Identity. **Your long-term credentials are never sent to the Service.**
Passkey private keys remain with your authenticator, recovery material
remains with you, and linked-account credentials remain with their
respective providers; none of them are entered into the chat or shared with
the Service.

What the Service does hold, once you approve a connection, is a **delegated
session signing key that the Service generates itself**, inside the server.
No secret key crosses a network in either direction: your credentials stay
where they already live, and the Service's key never leaves the Service. What
travels is only the key's public half, which Internet Identity signs,
issuing a time-limited, scope-limited authorization for that key to act as
you. The Service uses the session key with Internet Identity to obtain, for
each application you interact with, a further short-lived authorization and
per-application key (the connection material described in section 1), and
those per-application keys are what actually sign your requests. All of
these are signing credentials the Service generated itself, so it is worth
being precise about their limits: none of them is your Internet Identity
key, none can be used to sign in as you anywhere else, and revoking the
connection stops them in the two steps described in section 7. Separately,
your AI assistant holds an OAuth access token that lets it reach the
Service; that token's lifetime is capped by the same authorization.

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
[id.ai/manage/settings](https://id.ai/manage/settings).

The Service does not profile individual users, does not use advertising, and
does not use tracking cookies. It sets one transient, security-purpose cookie
during sign-in, described below.

### 1. Data Categories Processed, Purposes, and Legal Bases

We process the following categories, solely to provide, secure, and improve
the Service.

**Session and authorization data**: the delegated session signing key and
the session duration and access level you chose. Purpose: performing the
requests your assistant makes. Legal basis: performance of the service you
requested.
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
to execute each call and does not store it after the call completes, with
one exception, the per-application connection material described below. It
does not store conversation content. Legal basis: performance of the service
you requested.

**Account information**: when your assistant uses tools that list your
Internet Identity accounts at an application, or that ask which identity you
use there, the Service processes those account names, numbers, and last-used
timestamps, and the per-application identity in question. A per-application
identity is a pseudonym specific to that application; depending on how you use
that application, you may consider it private. Not stored after the session;
the account number and application used for an authenticated call are kept
during the session as part of the connection material described next. Legal
basis: performance of the service you requested.

**Per-application connection material**: the first time your assistant acts
at a given application, the Service derives the identity you use there and
keeps, for the remainder of the session: the application's domain, the
account number used, the per-application key it generated, and Internet
Identity's signed authorization for that application (itself valid for at
most one hour). Keeping this avoids re-deriving an authorization on every
call to the same application. The Service's own origin is treated as one
such application when you use the canister-management tools, and the
identity derived for it is stable across your connections. All of this is
held in memory only, bounded in size, and discarded when the session ends or
the Service restarts. Legal basis: performance of the service you requested.

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

**Our hosting provider.** The Service runs on servers we rent from Amazon Web
Services, which processes data on our behalf as a processor under its
data-processing terms. We use no other infrastructure processors today; if an
observability or error-reporting provider is ever introduced, it will be
named here first.

**Public authorities, where the law requires it.** If we are legally obliged
to disclose personal data, for example by a court order or a binding request
from a competent authority, we disclose the minimum required.

We do not sell personal data or disclose it for advertising. We disclose it
only to the recipients described above, as necessary to perform your
requests, secure the Service, or comply with law.

### 3. International Transfers

The Service's servers, and the technical logs they hold, are located in
**Germany** (Amazon Web Services' Frankfurt region). Germany is a member of
the European Economic Area, whose countries are recognised by the Swiss
Federal Council as providing adequate data protection, so no additional
transfer safeguard is required for this hosting. Amazon Web Services may
have limited remote access from other countries for support and operations;
that access is governed by the AWS Data Processing Addendum, which
incorporates the EU Standard Contractual Clauses, as extended to Swiss
transfers in line with the FDPIC's guidance, for any processing from a
country without an adequate level of data protection.

Separately, the Internet Computer is a global public network: its nodes are
operated by independent providers in many countries, whose locations are set
by the network's governance, not by us, and can include countries that
Switzerland and the EEA do not recognise as providing adequate data
protection. When you direct the Service to read from or act on an
application, the Service submits that request to the network deliberately,
on your instruction, and the network processes it internationally to execute
what you asked. What travels is the content of your request and its results
(section 1). Authenticated requests also carry the pseudonymous
per-application identifier described in section 6; unauthenticated public
reads use the Internet Computer's shared anonymous principal, which
identifies no one. This processing is inherent to the network's design and
applies to every request, so take it into account when deciding which
applications to direct the Service at.

### 4. Data Retention

| Category | Retained |
|---|---|
| Session and authorization data (signing key, access level, duration) | In volatile memory only, never written to disk. Discarded when the duration you chose elapses (at most 30 days) or when the Service restarts, whichever comes first. |
| Requests and results | Processed transiently; not retained after the call completes. |
| Per-application connection material (application domain, account number, per-application key, signed authorization) | In memory, per session; an entry is replaced when refreshed and all are discarded when the session ends or the Service restarts. The signed authorization itself expires at most one hour after issue. |
| Authorization codes and access tokens | In memory only; codes expire after two minutes, tokens no later than the session duration you chose. |
| Connection (OAuth) registrations | Stored on disk so an assistant can reconnect across restarts. There is currently **no time limit**: a registration is kept until it is displaced once the store reaches its cap of 10,000, which for a rarely-used deployment can mean indefinitely. |
| Technical logs | Up to three months, then deleted. |
| Aggregated operational metrics | Held in memory only, never written to disk: gauges are computed on demand, and the status dashboard keeps its most recent health report in memory until the next one replaces it or the process restarts. |

Revoking a connection takes effect in the two steps described in section 7.
Revocation does not by itself erase the session record: the delegated
signing key and the per-application connection material stay in memory until
the duration you originally chose elapses or the Service restarts. We intend
to discard them as soon as a revocation is observed; until that ships, the
table above describes the actual behaviour.

### 5. What Our Logs Contain

We would rather be specific than make sweeping promises, so:

- Every request that reaches the Service's application produces one log line
  with the HTTP method, the path, the response status, and how long it took.
  Query strings and request bodies are never included, which keeps
  single-use codes and delegations out of these logs. Requests to the status
  dashboard (`/status/`) bypass the application and produce no routine log
  line at all.
- Sign-in and session events log the session identifier, a per-connection
  identifier derived from that connection's key, the access level, and expiry
  times. The per-connection identifier is new for every connection, so log
  entries from different sessions cannot be linked to each other through it.
- **No log line records the applications or canisters you interact with, the
  arguments you send, or the results you receive.** The parts of the Service
  that perform tool calls do no logging at all.
- Our web server is configured without access logging, so client IP addresses
  and browser user agents are not recorded as a matter of course. They are
  unavoidably processed in transit in order to serve a request, and its
  diagnostics for failed requests can include connection details and the
  requested address, including any query string, when something goes wrong.
- Logs are held by the operating system's journal on our hosts, subject to the
  retention bound above.

### 6. Identifiers, and What They Could Link

Internet Identity gives each application a different identity for you, so
applications cannot recognise you across applications. The Service is a
participant in that design and we want to be plain about what it can see.
While a session is live it holds, in memory, the per-application identities
it has derived for you, including a stable identity for you at its own
origin that the canister-management tools act as; software holding that
stable identity could in principle associate separate sessions with the same
user. Three things limit that in practice: none of these identifiers is
written to logs, which carry only a per-connection identifier that is new
for every connection (section 5); the applications you visit are not written
to logs either; and nothing the Service discloses to an application lets
that application recognise you anywhere else.

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
  [id.ai/manage/settings](https://id.ai/manage/settings), which lists every active
  connection for your Internet Identity so you can review and revoke access
  even if you no longer remember which assistant sessions are active.
  Revocation is carried out by Internet Identity and takes effect in two
  steps: within at most five minutes, Internet Identity stops honouring the
  connection, so the Service can no longer obtain authorizations for any
  application; authorizations already issued for particular applications
  remain usable until they expire, at most one hour after they were issued.
  The practical worst case between revoking and all activity stopping is
  therefore about one hour.

If you believe we have handled your personal data unlawfully, you may lodge a
complaint with the Swiss Federal Data Protection and Information Commissioner
(FDPIC), and, where the GDPR applies to you, with the supervisory authority of
your EU or EEA country of residence or workplace.
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
