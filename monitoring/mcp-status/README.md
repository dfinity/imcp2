# IMCP (IC MCP) status dashboard

A small, dependency-free monitoring tool for the **IC MCP** server
([https://mcp.beta.id.ai](https://mcp.beta.id.ai) by default) and the **Internet
Identity** instance it is paired with.

It answers three questions and adds a few suggestions:

1. **Is the server running and responding on all advertised endpoints with the
   correct status codes?** — probes the landing page, the build/version endpoint
   (`/version`), the two OAuth discovery documents, the `/mcp` endpoint's
   unauthenticated `401` challenge, dynamic client registration, and the
   `/mcp/oauth/authorize` + `/mcp/oauth/token` endpoints, plus TLS certificate
   freshness. The landing-page check asks whether the root **answers for** the
   landing page, which no longer means holding a copy of it: the human-facing
   pages live in
   [dfinity/internetcomputer-org](https://github.com/dfinity/internetcomputer-org)
   (`public/icp-mcp/`), are served at <https://internetcomputer.org/icp-mcp/>,
   and this origin answers their old paths with permanent redirects so published
   links keep working. A `3xx` naming a destination is therefore as healthy as a
   `200` with the page — demanding `200 text/html` reported the live deployment
   as failing while it served everything correctly. Still a failure: a
   `4xx`/`5xx`, an unreachable server, or a redirect naming nowhere to go (no
   `Location`, a non-http one, or one pointing back at the URL just requested).
   The protocol documents keep their exact status codes: for the discovery
   documents, the `/mcp` challenge and the OAuth endpoints the status code *is*
   the contract MCP clients depend on, so a redirect there is a finding, not a
   detour.
2. **Which Internet Identity instance(s) is it linked to?** — read from the
   `instances` array the server advertises at `GET /version`, one entry per
   served mount (`{name, mcp_path, ii_origin, ii_canister}`). The server is the
   authority on its own pairing, so this is not guessed: an earlier version
   derived the II origin by stripping the `mcp.` label off the MCP host, which
   works only when the MCP server is a subdomain of its II — it mapped
   `mcp.internetcomputer.org` to `internetcomputer.org`, an unrelated site whose
   `404` on `/mcp` read as an Internet Identity outage. Advertised origins are
   still validated against the probe allowlist before use, so a misconfigured or
   compromised server cannot steer these probes at a third party; a rejected
   entry is reported rather than silently dropped. Pin an origin with
   `--ii` / `II_ORIGIN` to override the advertised list entirely.
3. **Is each II instance healthy and is its `/mcp` connect page served?** —
   question 3 runs once per served instance, so a staging deployment serving
   both `/mcp` (production II) and `/mcp-beta` (beta II) has both monitored.
   For each it
   checks the II frontend is reachable and IC-certified, reports its frontend
   canister id and related origins, confirms it serves its runtime config
   (textual Candid) at `/.config`, and verifies the `/mcp` connect page is
   served. The connect flow runs on a top-level navigation back to the server's
   pinned callback page and a `fetch()` from that page to the server (governed by
   CSP `connect-src`, which allows the https MCP origin) — neither is gated by
   `form-action` — so a served page is the health signal. (An older delegation flow
   form-POSTed the callback, which needed a relaxed `form-action`; that flow was
   retired in
   [internet-identity#4086](https://github.com/dfinity/internet-identity/pull/4086),
   and the `'self' http://127.0.0.1:*` `form-action` now on `/mcp` is for the
   unrelated `/cli` loopback flow.) Since
   [internet-identity#4052](https://github.com/dfinity/internet-identity/pull/4052)
   there is no global `mcp_server_origin` and **trust is per-user**: each
   identity adds the MCP server it trusts in II Settings, synced on-chain. So
   whether a *specific* identity trusts this server is not inspectable from here
   without authenticating — what is instance-wide and checkable is that the
   connect page itself is deployed.

Every check carries a plain-language description, and the report shows which
**deployment is running** — the MCP server's version and git commit (read from
`GET /version`, linked to the commit on GitHub), **when it was last redeployed**
(the server process's start time), and its build time. The web dashboard groups
the sections into **tabs** for easier navigation.

## Usage

No build step and no dependencies — just Node ≥ 20 (uses the global `fetch`).
The commands below are shown from the repository root; equivalent `npm` scripts
live in `monitoring/mcp-status/package.json` — run them from that directory
(e.g. `cd monitoring/mcp-status && npm start`).

```bash
# Text report for the default beta deployment (exit code 0 = healthy)
node monitoring/mcp-status/cli.js                                  # or: npm start

# Point it at another deployment (e.g. production)
node monitoring/mcp-status/cli.js --mcp https://mcp.id.ai

# Machine-readable output for alerting / CI
node monitoring/mcp-status/cli.js --json

# Live web dashboard at http://localhost:8080 (auto-refreshing)
# (target is fixed at startup; pass --mcp/--ii to monitor another deployment)
node monitoring/mcp-status/server.js --port 8080 --mcp https://mcp.id.ai   # or: npm run serve

# Unit tests
node --test monitoring/mcp-status/checks.test.js                  # or: npm test
```

CLI options: `--mcp <origin>`, `--ii <origin>`, `--timeout <ms>`, `--json`,
`--no-color`, `--strict` (exit non-zero on warnings too), `--help`. The exit
code is `0` when healthy and `1` on failures, so it slots straight into cron, a
CI job, or an uptime check.

### Allowed targets (SSRF guard)

The web server probes only the target fixed at startup — it never takes the
target from an incoming request, so a visitor cannot steer server-side requests
at arbitrary hosts. As defence in depth, every resolved origin is also validated
against a host allowlist: only `https` origins on `id.ai` (and its sub-domains),
plus loopback hosts for local development, may be probed. To monitor a
deployment on another domain, extend the allowlist via the
`MCP_STATUS_ALLOWED_HOSTS` environment variable (comma-separated host suffixes).

Redirects are **reported, never followed**. A `3xx` comes back as itself with
its destination in the detail line (`302 → https://…`), and each check decides
what that means: for the landing page a destination is the healthy answer; for
everything else it is a finding that says where the endpoint went. Two reasons.
A followed `Location` is a request the monitored server chose rather than the
operator, which is precisely what the allowlist above exists to prevent — and
following would blur the one distinction some checks exist to draw: an II that
has removed its `/mcp` connect page and redirects unknown paths to `/` would
land on a `200` and read as "connect page served".

`server.js` binds to `127.0.0.1` by default; override with `--host` /
`MCP_STATUS_HOST` only when you really mean to expose the port directly.
`/api/status` is cached for a short TTL (`MCP_STATUS_CACHE_TTL_MS`, default
15 s) and concurrent requests are coalesced into one probe run, so multiple
tabs / refreshes don't multiply load on the monitored server.

### Deployment

The standard deploy ([`deploy/native`](../../deploy/native)) ships this tool to
the host and runs it as the `imcp-status.service` systemd unit (bound to
`127.0.0.1:8137`, monitoring the deployment's own public origin). Caddy
publishes it at `https://<domain>/status/`, and the CI workflow runs the unit
tests below before rolling out. See the deploy README for details.

### Publishing to an Atlassian Statuspage (status.internetcomputer.org)

`server.js` can mirror the dashboard's overall verdict to one component on an
Atlassian Statuspage — the mechanism that puts MCP health on
[status.internetcomputer.org](https://status.internetcomputer.org/), which is
hosted SaaS whose components cannot be served from a repository, only driven
through its [REST API](https://developer.statuspage.io/). The pusher
(`statuspage.js`) is **off by default** and starts only when all three of these
are set:

| Variable | Value |
| -------- | ----- |
| `STATUSPAGE_PAGE_ID` | The page id (visible in the Statuspage admin, or as `page.id` in `https://<page>/api/v2/status.json`). |
| `STATUSPAGE_API_KEY` | An API key minted in the Statuspage admin (read from the environment, never argv; never logged). |
| `STATUSPAGE_COMPONENT_ID` | The id of the component to drive. |

One-time setup in the Statuspage admin: create the component (e.g. **"ICP MCP
server"**, optionally inside an existing group), mint an API key, and note the
page and component ids. On a deployed host, put the three variables in
`/etc/imcp-status/statuspage.env` (mode `600`, owner root) — the systemd unit
loads that file if present — and `systemctl restart imcp-status`.

The mapping is intentionally coarse (a public status page is not the detailed
dashboard):

| Dashboard verdict | Statuspage component status |
| ----------------- | --------------------------- |
| `pass` | `operational` |
| `warn` | `degraded_performance` |
| `fail`, but some service-availability checks still pass | `partial_outage` |
| `fail` with every service-availability check failing | `major_outage` |

"Service-availability checks" are the endpoint probes that report `fail` on a
failed request (landing page, discovery documents, the `/mcp` challenge, and
the OAuth endpoints). Auxiliary checks are excluded from the major-outage
test on purpose: `version` and `metadata-consistency` only degrade to `warn`
when the server is unreachable, and the TLS check can stay green while the
application behind the proxy is down — counting them would make a total
outage report as merely partial.

The pusher re-evaluates every `STATUSPAGE_PUSH_INTERVAL_MS` (default 60 s,
floor 15 s) and PATCHes the component **only when the mapped status changes**
(plus once at startup, since a restarted process cannot know the remote state)
— so a healthy steady state costs one API call per process lifetime. A failed
push is logged and retried on the next interval; it never affects the dashboard
itself.

Unlike visitor-triggered probe runs, the pusher's own runs are
**non-mutating**: it reuses a recent visitor-triggered report when one exists,
and otherwise probes with both registration checks skipped. The loopback
Dynamic Client Registration probe changes server state on every run (it mints
and persists a client_id in the server's LRU-bounded registration store), and
the allow-list probe would do the same whenever the server's guard regressed —
the very failure it detects — so an unattended periodic loop runs neither.
Both probes are still exercised by every interactive dashboard visit and CLI
run.

## Why a standalone tool (and not a page in the II frontend)?

The II frontend is a **static, prerendered, `ssr: false` SvelteKit app** served
from a canister — it has no server runtime to probe from. More importantly, the
signals that matter here are **not readable from a browser**: the MCP server's
`/mcp` `401` challenge and HTML landing page send no CORS headers, and the II
instance's `Content-Security-Policy` header (where recognition is verified)
can't be inspected cross-origin. Running the probes server-side in this small
Node tool sidesteps CORS entirely and lets the dashboard check everything that
actually matters.

## Files

| File               | Purpose                                                        |
| ------------------ | -------------------------------------------------------------- |
| `config.js`        | Target resolution (defaults, env vars, II-origin derivation).  |
| `checks.js`        | All probing logic; exports `runDashboard()`.                   |
| `report.js`        | ANSI/plain-text rendering for the CLI.                         |
| `cli.js`           | Command-line entry point.                                      |
| `server.js`        | HTTP server: serves the dashboard and runs probes server-side. |
| `public/index.html`| Self-contained auto-refreshing web dashboard.                  |
| `checks.test.js`   | `node:test` unit tests (stubbed `fetch`, no network).          |
| `package.json`     | Marks the tool as ESM (`type: module`) and defines npm scripts.|

## Current beta findings (snapshot)

Against `https://mcp.beta.id.ai` the server passes all endpoint checks — its
root answers `308 → https://internetcomputer.org/icp-mcp/`, where the landing
page is served. The linked IIs are `https://id.ai` and `https://beta.id.ai`
(frontend canister `gjxif-ryaaa-aaaad-ae4ka-cai`, backend
`fgte5-ciaaa-aaaad-aaatq-cai` for beta), whose `/mcp` connect pages are served
(the connect flow is `fetch()`/navigation-based, so its CSP is not asserted).
Whether a given identity trusts this MCP server is now per-user (set in II
Settings, synced on-chain) and so is not asserted here. With the linked IIs
healthy, the dashboard reports all green.
