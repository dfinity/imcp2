# ICP MCP Developer Terms (source text)

> This is the source text for the page served at
> `https://internetcomputer.org/icp-mcp/developer-terms/`
> (dfinity/internetcomputer-org, `public/icp-mcp/developer-terms/index.html`;
> `https://mcp.internetcomputer.org/developer-terms` permanently redirects
> there). Keep the two in sync: the served page is what publishers actually
> read and accept, and it is the URL
> [`imcp2_core::DEVELOPER_TERMS_URL`](../crates/imcp2-core/src/authorization.rs)
> points registrants at.
>
> The **revision below is the one the write gate enforces**: a registration
> authorizes state-changing calls only while its recorded acceptance equals
> `DEVELOPER_TERMS_VERSION`. Changing the revision here means changing that
> constant (and re-collecting acceptances) — a test pins the two together, so
> they cannot drift.

---

## ICP MCP Developer Terms

**Revision 2026-08-28 · in effect from 2026-08-28**

These Developer Terms ("Developer Terms") govern the registration of an
application for state-changing access through the ICP MCP server (the
"Service"), operated by DFINITY Stiftung, Genferstrasse 11, 8002 Zürich,
Switzerland ("DFINITY Foundation", "we"). They are addressed to the publisher
of an application — the person or entity that operates it and its canisters —
not to the end users who connect an AI assistant to the Service. End users are
governed by the [ICP MCP Terms of Service](https://internetcomputer.org/icp-mcp/terms/).

By registering an application, or by asking us to register one, you accept
these Developer Terms on behalf of the publisher.

### 1. What registration is for

The Service lets an AI assistant read public information from the Internet
Computer and, under an end user's Internet Identity authorization, act on that
user's behalf. Reading a canister requires no registration.

Registration governs state-changing (update) calls: the Service makes an update
call to a canister only when

- the call names your application's origin;
- that origin is registered under these Developer Terms, at the revision
  currently in effect;
- your application serves a `/.well-known/ic-architecture` manifest at that
  exact origin, per the
  [ICP service discoverability protocol](https://docs.internetcomputer.org/guides/frontends/service-discoverability/);
  and
- the manifest declares the canister being called.

The manifest is read afresh on every such call. Nothing else authorizes a
state-changing call — in particular, a canister id the Service can otherwise
discover behind your domain (a response header, an `/env.json`, a JavaScript
bundle) does not.

### 2. Publishing the manifest accurately

You are responsible for what your manifest declares. By registering, you
represent and warrant that:

- **You are entitled to expose every canister the manifest lists.** You control
  it, or the party that controls it has authorized you to expose it through the
  Service for state-changing calls. You must not list a canister operated by
  anyone else — a shared ledger, another application's backend, a system
  canister — in order to reach it through the Service.
- **The manifest describes your application's real composition**, and its
  `name`, `role`, and `description` fields do not misdescribe what a canister is
  or does.
- **You keep it current**: a canister you no longer operate, or no longer intend
  to be reachable, is removed promptly. Because the Service re-reads your
  manifest on every state-changing call, your removal takes effect on its next
  one.
- **The origin you register is one you control**, served over HTTPS.

### 3. What your MCP-reachable operations must not do

The Service is not a financial tool, and it must not become one by proxy. You
are responsible for the operations your declared canisters expose to it,
including operations they perform downstream on other canisters. For every
update method reachable through the Service, you must ensure that it:

- **does not transfer, trade, or move value, and does not grant spending
  rights** — neither directly nor by forwarding to a ledger, minter, exchange,
  wallet, or staking service — whatever the method is named. The Service
  independently refuses the standardized value-moving methods and calls to known
  finance-related canisters, but that guard is a backstop, not your compliance
  boundary: a bespoke method that moves value is a breach of these Developer
  Terms even where no automated check catches it;
- **is safe for an AI assistant to call** on a user's behalf under an
  instruction the user gave in their own words: not irreversible in a way a user
  would not expect from the request, not destructive of data the user cannot
  recover, and not a privileged administrative operation exposed to ordinary
  users;
- **handles the personal data it receives lawfully**, and only for the purpose
  the user's request implies. Data your canisters return through the Service
  reaches the user's AI assistant provider; you are responsible for your own
  lawful basis for that disclosure and for what your application does with the
  data it receives. The Service's own handling of personal data is described in
  the [ICP MCP Privacy Policy](https://internetcomputer.org/icp-mcp/privacy-policy/).

You must not use registration to circumvent the Service's authorization, rate,
or safety mechanisms, or to expose an operation you would not expose in your own
application's user interface.

### 4. Publishing a manifest is not registration

Serving a `/.well-known/ic-architecture` manifest is a technical statement about
your application's composition. It carries none of the promises in these
Developer Terms: not that you accepted them, not that you are entitled to expose
the canisters you list, not that your methods are safe to call, and not that
your application stays inside the policies above. Registration is what records
those promises, and both are required for a state-changing call.

### 5. Changes, suspension, and revocation

We may change these Developer Terms; when we do, we change the revision
identifier and effective date at the top of this page. A registration
authorizes state-changing calls only against the revision currently in effect —
when the revision changes, we will ask you to accept the new one, and until you
do your application's registration no longer authorizes those calls. Reads are
unaffected.

We may suspend or remove a registration at any time, with or without notice
where a security risk, a breach of these Developer Terms, or a legal obligation
requires it. Removal takes effect from the first call after we deploy it, and
nothing cached can keep a removed registration alive past that point. You may
ask us to remove your registration at any time. Registration is free of charge,
gives you no entitlement to the Service's availability, and grants no rights to
DFINITY Foundation's names, logos, or other trademarks.

### 6. Liability

The Service is provided "as is" and "as available", without warranties of any
kind. To the maximum extent permitted by law, DFINITY Foundation is not liable
for damages arising from your application's registration or from calls made to
your canisters through the Service. Nothing here excludes or limits liability
that cannot be excluded under applicable law, including liability under Swiss
law for damage caused by unlawful intent or gross negligence. You remain
responsible to your own users under your own terms; we are not a party to that
relationship.

### 7. Governing law and jurisdiction

These Developer Terms are governed by Swiss substantive law, excluding its
conflict of law rules. The exclusive place of jurisdiction is Zürich,
Switzerland.

### 8. Registering, and contact

To register an application, or to change or remove a registration, write to
mcp@dfinity.org from an address you can show controls the origin, naming the
origin and confirming acceptance of revision 2026-08-28 of these Developer
Terms. Registrations are recorded in the Service's open-source repository at
[github.com/dfinity/imcp2](https://github.com/dfinity/imcp2), so the set of
applications that may receive state-changing calls is public and reviewable.
