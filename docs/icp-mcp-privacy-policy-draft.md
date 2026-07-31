# ICP MCP Privacy Policy (DRAFT for legal review)

> **Status: draft, not published.** Written for review by DFINITY legal in the
> style and structure of the [Internet Identity Privacy Policy](https://identitysupport.dfinity.org/hc/en-us/articles/36662081856148-DFINITY-Internet-Identity-Privacy-Policy)
> (effective 2026-04-07). Square brackets mark decisions/values legal or ops
> must supply. Technical claims (what is stored, where, for how long) are
> drawn from this repository's actual behavior and should be re-verified
> against the deployed release at publication time. All decisions are made:
> the publication venue is
> `https://mcp.internetcomputer.org/privacy-policy`, served by the MCP
> server itself — implemented in
> [#112](https://github.com/dfinity/imcp2/pull/112) (merging it publishes
> the page on staging immediately and on production at the next `release-*`
> tag) — the contact address is `mcp@dfinity.org`, and the effective date is
> August 3, 2026.
>
> **Ops prerequisite before publishing:** the three-month log-retention bound
> stated in section 3 is enforced by
> [#111](https://github.com/dfinity/imcp2/pull/111); it must be deployed to
> both hosts before the policy is published.

---

## ICP MCP Privacy Policy

**Effective Date: August 3, 2026**

We, DFINITY Stiftung, Genferstrasse 11, 8002 Zürich, Switzerland ("DFINITY
Foundation") disclose in this ICP MCP Privacy Policy ("Privacy Policy") how we
process personal data when you connect an AI assistant to the ICP MCP server
at `mcp.internetcomputer.org` (the "Service") and use it to interact with the
Internet Computer and its ecosystem of applications.

This Privacy Policy does not apply to any other data processing, including,
without limitation: personal data processed by your AI assistant provider
(for example, Anthropic for Claude) under its own terms and privacy policy;
personal data processed by Internet Identity, which is covered by the
[Internet Identity Privacy Policy](https://identitysupport.dfinity.org/hc/en-us/articles/36662081856148-DFINITY-Internet-Identity-Privacy-Policy);
personal data processed by the applications you choose to interact with
through the Service, which are operated by third parties under their own
policies; and personal data that you share with users of the Internet
Computer or submit to its applications.

### Sign in without sharing keys, act only with consent

The Internet Computer is a public network that runs applications reliably
using a consensus protocol. The Service lets an AI assistant read public
information from it without any sign-in.

For the assistant to act on your behalf, you sign in once with Internet
Identity. No passwords, private keys, or seed phrases are ever entered into
the chat or shared with the Service. On the Internet Identity consent screen
you make two explicit choices: how long the connection lasts (from 10 minutes
up to 30 days), and its access level, either **"Questions only"** (the
assistant may only read) or **"Actions & questions"** (it may also submit
actions). For a "Questions only" connection, the Internet Computer network
itself rejects action requests; the restriction does not depend on the
Service alone. You can revoke a connection's access at any time at
[id.ai/manage/access](https://id.ai/manage/access); revocation is carried out
by Internet Identity and takes effect within at most five minutes.

The Service does not profile individual users and does not use advertising or
tracking cookies. It sets one transient, security-purpose cookie during
sign-in, described below, and may collect aggregated, anonymized usage
metrics, described below.

### 1. Data Categories Processed and Purposes of Use

We process the following categories of data, solely to provide the Service:

- **Session and authorization data.** When you sign in, the Service holds the
  connection's session key together with the session duration and access
  level ("Questions only" or "Actions & questions") you chose on the Internet
  Identity consent screen, for the sole purpose of performing the requests
  your AI assistant makes during the session. During sign-in, the Service
  sets one transient cookie (`mcp_connect`; HttpOnly, Secure, SameSite=Lax).
  This cookie is set and read by the server only and is not accessible to
  scripts running in web pages; it is used solely to bind the sign-in to the
  browser that initiated it, protecting you against session-fixation attacks.
  It is not used for tracking.
- **Account information.** When your AI assistant uses tools that list your
  Internet Identity accounts at an application, or that request the
  identifier (principal) you use at an application, the Service processes the
  names, numbers, and last-used timestamps of those accounts and the
  per-application principal in question. A per-application principal is a
  pseudonym specific to that application; depending on how you use the
  application, you may consider it private. The Service processes it only to
  answer your assistant's request and does not store it beyond the session.
- **Connection (OAuth) data.** When an AI assistant connects, the Service
  stores the assistant's OAuth client registration: a generated client
  identifier, the assistant's redirect address, and a last-used timestamp.
  A registration identifies the AI assistant software, not you, and contains
  no personal data about you; it is kept on disk so the assistant can
  reconnect across Service restarts, and is retained until it is displaced
  from a bounded store of registrations. The Service also issues short-lived
  authorization codes and access tokens whose lifetime is capped by the
  session duration you chose; these are held in memory only.
- **Tool-call data.** The requests your AI assistant makes (application and
  canister identifiers, method names, query and call arguments) pass through
  the Service, which encodes, signs, and forwards them to the Internet
  Computer and returns the responses. The Service processes this data
  transiently to execute each call and does not store conversation content.
- **Aggregated usage metrics.** We may derive aggregated, anonymized
  operational metrics from the Service, for example how many connections are
  active at a given time or how often errors occur, to operate, secure, and
  improve the Service. These metrics do not identify individual users.
- **Technical log data.** Our servers record technical logs: for each
  request, the method, path, response status, and latency (query strings and
  request bodies are never logged), together with service events and error
  traces that can include pseudonymous session identifiers and the
  pseudonymous identifier the Service uses for you. The Service's own logs
  do not systematically record client IP addresses or browser user agents.
  We use logs for operating, securing, and debugging the Service and for
  abuse prevention.

### 2. Data Sharing

The Service shares data in three ways.

First, with the AI assistant you connect, which is the point of the
Service: everything the Service returns goes back to that assistant,
including — when you ask for them — your Internet Identity account names
and your per-application identities. Your assistant's provider (for
example, Anthropic for Claude) processes that data under its own terms and
privacy policy, not this one.

Second, with the infrastructure that carries out your requests: the Internet
Computer's public API boundary nodes (`icp-api.io`), which submit your
requests to the network, and Internet Identity (`id.ai`), which
authenticates you. These are part of the Internet Computer and are governed
by its DAO, the Network Nervous System, rather than operated by DFINITY
Foundation; Internet Identity's own processing is covered by the
[Internet Identity Privacy Policy](https://identitysupport.dfinity.org/hc/en-us/articles/36662081856148-DFINITY-Internet-Identity-Privacy-Policy).
The Service also queries two services that DFINITY Foundation does operate:
the public canister-metadata service at `dashboard.internetcomputer.org` and
the developer-skills service at `skills.internetcomputer.org`.

Third, at your direction, with the applications you choose to interact
with. A question or action you send to an application necessarily carries
your request arguments and your per-application identity to that application
and its operator, who may be a third party; and when you ask the Service to
discover an application from its web address, the Service fetches metadata
from that address. Requests you direct at applications execute on the
Internet Computer, a public network. What an application records, retains,
or publishes when you interact with it is governed by that application and
its operator, not by this Privacy Policy, and may be publicly accessible.
Which applications to interact with, and what to submit to them, is under
your control; it is not a data-sharing choice of the Service.

We do not sell your data or share it with third parties for their own
purposes.

### 3. Data Retention

Session, authorization, and account data are held in the Service's volatile
memory only. They are never written to disk, they expire no later than the
session duration you chose (at most 30 days), and they are lost on a server
restart. OAuth client registrations, which contain no personal data about
you, are kept on disk and retained until displaced from a bounded store.
Tool-call data is processed transiently and not retained after the call
completes. Technical logs are retained for up to three months and then
deleted.

### 4. User Rights & Compliance

You can stop your AI assistant from using the Service at any time by
disconnecting the connector in the assistant. Disconnecting ends that
assistant's use of the connection, but it does not by itself end the
underlying authorization, which otherwise remains valid until the duration
you chose elapses. To end the authorization itself, revoke it at
[id.ai/manage/access](https://id.ai/manage/access): that page lists every
active connection for your Internet Identity, so you can review and revoke
access there even if you no longer remember which AI sessions are still
active. Revocation is carried out by Internet Identity and takes effect
within at most five minutes, after which the Internet Computer rejects any
request made with that authorization.

Revoking ends the authorization. The session record the Service holds in
memory (the session key and any cached application delegations, which
without a valid authorization can no longer be used to act for you) is
discarded when the session duration you originally chose elapses, or when
the Service restarts, whichever comes first. Apart from that record and the
technical logs described above, no data about you remains in the Service
after a session ends.

Data you have submitted to applications on the Internet Computer through
your own requests is held by those applications, not by the Service, and
requests concerning it should be directed to the relevant application
operator. For questions on how to exercise your rights, please send an email
to mcp@dfinity.org.

### 5. Changes to This Policy

We may update this Privacy Policy and we may post new versions from time to
time, at our discretion.

### 6. Contact

For questions about this Privacy Policy or the Service, please send an email
to mcp@dfinity.org.
