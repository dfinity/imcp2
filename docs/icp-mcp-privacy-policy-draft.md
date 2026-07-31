# ICP MCP Privacy Policy — DRAFT for legal review

> **Status: draft, not published.** Written for review by DFINITY legal in the
> style and structure of the [Internet Identity Privacy Policy](https://identitysupport.dfinity.org/hc/en-us/articles/36662081856148-DFINITY-Internet-Identity-Privacy-Policy)
> (effective 2026-04-07). Square brackets mark decisions/values legal or ops
> must supply. Technical claims (what is stored, where, for how long) are
> drawn from this repository's actual behavior and should be re-verified
> against the deployed release at publication time. Decisions needed:
> **(a)** the log-retention window, **(b)** the publication venue
> (help-center article alongside the II policy vs. a page on
> `mcp.internetcomputer.org`), **(c)** the contact address
> (`mcp@dfinity.org` vs. `support@dfinity.org`), **(d)** the effective date.

---

## ICP MCP Privacy Policy

**Effective Date: [YYYY-MM-DD]**

We, DFINITY Stiftung, Genferstrasse 11, 8002 Zürich, Switzerland ("DFINITY
Foundation") disclose in this ICP MCP Privacy Policy ("Privacy Policy") how we
process personal data when you connect an AI assistant to the ICP MCP server
at `mcp.internetcomputer.org` (the "Service") and use it to interact with the
Internet Computer.

This Privacy Policy does not apply to any other data processing, including,
without limitation: personal data processed by your AI assistant provider
(for example, Anthropic for Claude) under its own terms and privacy policy;
personal data processed by Internet Identity, which is covered by the
[Internet Identity Privacy Policy](https://identitysupport.dfinity.org/hc/en-us/articles/36662081856148-DFINITY-Internet-Identity-Privacy-Policy);
personal data processed by the applications and canister smart contracts you
choose to interact with through the Service, which are operated by third
parties under their own policies; and personal data that you share with users
of the Internet Computer or record on it when you use blockchain-based
technologies.

### Sign in without sharing keys, act only with consent

The Service lets an AI assistant read public Internet Computer state without
any sign-in. To act on your behalf, you sign in once with Internet Identity —
no passwords, private keys, or seed phrases are ever entered into the chat or
shared with the Service. On the Internet Identity consent screen you choose
how long the connection lasts (from 10 minutes up to 30 days) and whether it
may make state-changing calls; connections are read-only by default, and the
Internet Computer itself rejects state-changing calls from read-only
connections. The Service holds the resulting time-boxed authorization in
memory only and does not use it for anything except performing the calls your
AI assistant requests during your session.

The Service does not use analytics, does not serve advertising, and does not
use cookies, except for one transient, security-purpose cookie described
below.

### 1. Data Categories Processed and Purposes of Use

We process the following categories of data, solely to provide the Service:

- **Session and authorization data.** When you sign in, the Service holds
  your Internet Identity principal, the connection's session key, and the
  session duration and permission level (read-only or read-write) you chose
  on the Internet Identity consent screen. During sign-in, the Service sets
  one transient, security-purpose cookie (`sid`; HttpOnly, Secure,
  SameSite=Lax) used solely to bind the sign-in to the browser that initiated
  it, protecting you against session-fixation attacks. It is not used for
  tracking.
- **Account information.** When your AI assistant uses tools that list or act
  as your Internet Identity accounts at an application, the Service processes
  the names, numbers, and last-used timestamps of those accounts as returned
  by Internet Identity.
- **Connection (OAuth) data.** When an AI assistant connects, the Service
  stores its OAuth client registration (redirect address and client name) and
  issues short-lived authorization codes and access tokens whose lifetime is
  capped by the session duration you chose.
- **Tool-call data.** The requests your AI assistant makes — canister
  identifiers, method names, query and call arguments — pass through the
  Service, which encodes, signs, and forwards them to the Internet Computer
  and returns the responses. The Service processes this data transiently to
  execute each call and does not store conversation content.
- **Technical log data.** Like most web services, our servers record
  technical logs — IP address, user agent, request paths, timestamps, status
  codes, and error traces — used for operating, securing, and debugging the
  Service and for abuse prevention.

### 2. Data Sharing

The Service shares data only with infrastructure required to perform your
requests, operated by DFINITY Foundation: the Internet Computer API boundary
nodes (which submit your calls to the network), Internet Identity
(`id.ai`), the public canister-metadata service at
`dashboard.internetcomputer.org`, and the developer-skills service at
`skills.internetcomputer.org`. We do not sell or share your data with third
parties for their own purposes.

Note that calls you direct at the Internet Computer execute as your per-app
principal on a public blockchain: state-changing calls and their effects
become part of the Internet Computer's public, permanent state. This is
inherent to using a public network and is under your control — it is not a
data-sharing choice of the Service.

### 3. Data Retention

Session, authorization, account, and connection data are held in the
Service's volatile memory only — they are never written to disk, expire no
later than the session duration you chose (at most 30 days), and are lost on
a server restart. Tool-call data is processed transiently and not retained
after the call completes. Technical logs are retained for [N days] and then
deleted.

### 4. User Rights & Compliance

You can end the Service's ability to act for you at any time: disconnect the
connector in your AI assistant, or simply let the session expire — no data
about you remains in the Service after the session ends, other than technical
logs for the period stated above. Data you have recorded on the Internet
Computer through your own calls is public and permanent by design and cannot
be deleted by DFINITY Foundation. For questions on how to exercise your
rights, please send an email to [mcp@dfinity.org].

### 5. Changes to This Policy

We may update this Privacy Policy and we may post new versions from time to
time, at our discretion.

### 6. Contact

For questions about this Privacy Policy or the Service, please send an email
to [mcp@dfinity.org].
