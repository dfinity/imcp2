// Health probing logic for the IMCP (IC MCP) status dashboard.
//
// All probes run server-side (Node), which sidesteps the CORS restrictions that
// would block a browser from reading the MCP server's `/mcp` 401 challenge, its
// HTML landing page, or the Internet Identity instance's CSP header.
//
// The module is dependency-free: it uses the global `fetch`, `node:tls` for
// certificate inspection, and exports a single `runDashboard(config)` entry
// point that returns a fully structured, JSON-serialisable report.

import tls from "node:tls";
import {
  commitUrl,
  parseAdvertisedInstances,
  resolveConfig,
} from "./config.js";

/**
 * @typedef {"pass" | "warn" | "fail"} Status
 *
 * @typedef {Object} CheckResult
 * @property {string} id
 * @property {string} label
 * @property {string} description   Plain-language explanation of what this checks and why it matters.
 * @property {string} target        Human-readable target (method + url).
 * @property {string} expected      What a healthy server should return.
 * @property {Status} status
 * @property {number | null} httpStatus
 * @property {number | null} latencyMs
 * @property {string} detail        What was actually observed.
 *
 * @typedef {Object} Section
 * @property {string} id
 * @property {string} title
 * @property {Status} status
 * @property {CheckResult[]} checks
 *
 * @typedef {Object} Deployment
 * @property {string | undefined} version  The running build's package version.
 * @property {string | undefined} commit   The running build's git commit (or "unknown").
 * @property {string | undefined} commitUrl GitHub URL for the commit, when it is a real SHA.
 * @property {number | undefined} builtAt   Build time (Unix epoch seconds), when known.
 * @property {number | undefined} startedAt When the running process started (Unix epoch seconds) — the last redeployment.
 *
 * @typedef {Object} DashboardReport
 * @property {string} generatedAt
 * @property {{ mcpOrigin: string, iiOrigins: string[], iiOriginSource: string }} targets
 * @property {Deployment} deployment
 * @property {Status} overall
 * @property {Section[]} sections
 * @property {Record<string, unknown>} facts
 * @property {string[]} suggestions
 */

const STATUS_RANK = { pass: 0, warn: 1, fail: 2 };

/**
 * Aggregate a list of statuses into the worst (most severe) one.
 * @param {Status[]} statuses
 * @returns {Status}
 */
export const worstStatus = (statuses) =>
  statuses.reduce(
    (acc, s) => (STATUS_RANK[s] > STATUS_RANK[acc] ? s : acc),
    /** @type {Status} */ ("pass"),
  );

/** Redirect status codes that carry a `Location` a client is meant to follow. */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Whether a status code is a redirect. */
export const isRedirect = (status) => REDIRECT_STATUSES.has(status);

/**
 * Resolve a response's `Location` against the URL it answered, yielding an
 * absolute http(s) URL — or null when there is nothing usable to follow (no
 * header, an unparseable value, or a non-http scheme). A 3xx without a usable
 * target is a broken redirect, and callers treat it as such.
 *
 * @param {Headers} headers
 * @param {string} from the URL the response answered
 * @returns {string | null}
 */
const redirectTarget = (headers, from) => {
  const raw = headers.get("location");
  if (!raw) return null;
  let target;
  try {
    target = new URL(raw, from);
  } catch {
    return null;
  }
  return target.protocol === "https:" || target.protocol === "http:"
    ? target.toString()
    : null;
};

/**
 * A URL's request identity: the part a request is actually made of. `fetch`
 * never sends the fragment, so two URLs differing only there address the same
 * resource — a `Location: #elsewhere` names the resource just requested, not
 * a new destination, however different the two strings look.
 *
 * @param {string} url
 * @returns {string}
 */
const requestKey = (url) => {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.toString();
  } catch {
    return url;
  }
};

/**
 * Perform an HTTP request with a timeout, capturing status, headers, body and
 * latency without ever throwing (network errors are returned as `error`).
 *
 * Redirects are reported, never followed (`redirect: "manual"`). A probe that
 * followed one could not tell an endpoint serving a page from an endpoint
 * pointing at some other page that happens to be served — for the II's `/mcp`
 * connect page that is exactly the difference between healthy and gone — and a
 * followed `Location` is a request the monitored server chose, not the
 * operator, which the SSRF guard in config.js exists to prevent. So a 3xx comes
 * back as itself, with `location` naming where it points (resolved, http(s)
 * only; null when the header is missing or unusable), and each check decides
 * what that means: for the landing page a destination is the healthy answer,
 * for everything else it is a finding that says where the endpoint went.
 *
 * @param {string} url
 * @param {RequestInit & { timeoutMs?: number }} [init]
 */
const probe = async (url, init = {}) => {
  const { timeoutMs = 10_000, ...rest } = init;
  const start = Date.now();
  try {
    const res = await fetch(url, {
      redirect: "manual",
      ...rest,
      signal: AbortSignal.timeout(timeoutMs),
    });
    const bodyText = await res.text().catch(() => "");
    return {
      ok: true,
      status: res.status,
      headers: res.headers,
      bodyText,
      /** Where a 3xx points, when it names somewhere usable; null otherwise. */
      location: isRedirect(res.status)
        ? redirectTarget(res.headers, url)
        : null,
      latencyMs: Date.now() - start,
      error: /** @type {Error | null} */ (null),
    };
  } catch (err) {
    return {
      ok: false,
      status: /** @type {number | null} */ (null),
      headers: new Headers(),
      bodyText: "",
      location: /** @type {string | null} */ (null),
      latencyMs: Date.now() - start,
      error: /** @type {Error} */ (err),
    };
  }
};

/**
 * `" → <where>"` for a response that is a redirect with a usable target, `""`
 * otherwise — so a detail line that prints a 3xx also says where it went.
 * @param {{ location: string | null }} r
 */
const redirectNote = (r) => (r.location ? ` → ${r.location}` : "");

/** Safely JSON-parse a string, returning undefined on failure. */
const tryJson = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

/**
 * Inspect the TLS certificate of an https origin and report days-to-expiry.
 * @param {string} origin
 * @param {number} timeoutMs
 * @returns {Promise<{ validTo: string, daysRemaining: number } | { error: string }>}
 */
const inspectCertificate = (origin, timeoutMs) =>
  new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* noop */
      }
      resolve(value);
    };
    let host;
    try {
      host = new URL(origin).hostname;
    } catch {
      return done({ error: "invalid origin" });
    }
    const socket = tls.connect(
      { host, port: 443, servername: host, timeout: timeoutMs },
      () => {
        const cert = socket.getPeerCertificate();
        if (!cert || !cert.valid_to) {
          return done({ error: "no peer certificate" });
        }
        const validTo = new Date(cert.valid_to);
        const daysRemaining = Math.floor(
          (validTo.getTime() - Date.now()) / 86_400_000,
        );
        done({ validTo: validTo.toISOString(), daysRemaining });
      },
    );
    socket.on("error", (e) => done({ error: e.message }));
    socket.on("timeout", () => done({ error: "tls timeout" }));
  });

/**
 * Parse a single directive (e.g. "form-action") out of a CSP header value.
 * @param {string | null} csp
 * @param {string} directive
 * @returns {string[] | undefined} the directive's sources, or undefined if absent
 */
export const parseCspDirective = (csp, directive) => {
  if (!csp) return undefined;
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/);
    if (tokens[0] === directive) return tokens.slice(1);
  }
  return undefined;
};

// ---------------------------------------------------------------------------
// Section 1 — MCP server: advertised endpoints respond with correct codes
// ---------------------------------------------------------------------------

/**
 * @param {string} mcpOrigin
 * @param {number} timeoutMs
 * @param {{ mutating?: boolean }} [opts] With `mutating: false`, skip both
 *   registration probes. The loopback Dynamic Client Registration probe mints
 *   and persists a fresh client_id in the server's LRU-bounded registration
 *   store on every run. The allow-list probe stores nothing while the server's
 *   guard holds — but if that guard ever regresses (the exact failure it
 *   detects), each run would mint a client too, turning an unattended periodic
 *   caller into a store-grinding loop precisely when the server is broken.
 *   Interactive uses (a person loading the dashboard, a one-off CLI run) keep
 *   the default and still exercise both probes.
 * @returns {Promise<{ section: Section, facts: Record<string, unknown> }>}
 */
export const checkMcpEndpoints = async (
  mcpOrigin,
  timeoutMs,
  { mutating = true } = {},
) => {
  /** @type {CheckResult[]} */
  const checks = [];
  /** @type {Record<string, unknown>} */
  const facts = { origin: mcpOrigin };

  // 1. Landing page. The signal is that the root URL *answers for* the landing
  //    page, which no longer means holding a copy of it: the human-facing pages
  //    (the landing page and its /privacy-policy, /support and /terms subpages)
  //    are maintained in dfinity/internetcomputer-org and served under
  //    internetcomputer.org/icp-mcp/, and this origin answers their old paths
  //    with permanent redirects so published links keep working while the
  //    content exists exactly once. So a 3xx naming a destination is as healthy
  //    as a 200 with the page — what is not healthy is a 4xx/5xx, an
  //    unreachable server, or a 3xx that names nowhere to go.
  //
  //    The destination is reported, not followed (see probe): the check takes
  //    the redirect's word for where the page went, and says so.
  {
    const target = `${mcpOrigin}/`;
    const r = await probe(target, { timeoutMs });
    const ct = r.headers.get("content-type") ?? "";
    const servedHere = r.ok && r.status === 200 && /text\/html/i.test(ct);
    // A redirect back at the resource just requested is a loop, not a landing
    // page. Compared by request identity: `/` → `/#landing` re-fetches `/`.
    const movedTo =
      r.ok &&
      isRedirect(r.status) &&
      r.location &&
      requestKey(r.location) !== requestKey(target)
        ? r.location
        : null;
    const pass = servedHere || !!movedTo;
    facts.landing = { status: r.status, servedHere, movedTo };
    checks.push({
      id: "root",
      label: "Landing page",
      description:
        "Confirms the root URL answers for the server's human-facing landing page — either serving it (HTTP 200, HTML) or redirecting to where it is published. The landing pages are maintained and served at internetcomputer.org/icp-mcp/, and this origin redirects their old paths there, so a permanent redirect is the expected healthy answer; a 4xx/5xx, an unreachable server, or a redirect pointing nowhere is not.",
      target: `GET ${mcpOrigin}/`,
      expected:
        "200 text/html, or a redirect to where the landing page is served",
      status: pass ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : movedTo
          ? `${r.status} → ${movedTo}`
          : `${r.status}${redirectNote(r)}, content-type: ${ct || "(none)"}`,
    });
  }

  // 1b. Build/version: read, but not graded. `GET /version` is the server's own
  //     account of which build is running and which II instances it serves, so
  //     it still feeds the report's deployment banner and the II discovery in
  //     checkLinkage below. It is deliberately not a check: the endpoint is an
  //     operator convenience rather than part of the MCP contract, production's
  //     fronting edge answers it with a redirect to the landing site instead of
  //     serving it, and a build stamp nobody exposes says nothing about whether
  //     the MCP surface is up — grading it warned that column on every run,
  //     forever, while everything an MCP client depends on was served
  //     correctly. Only the banner is purely informational, though: when
  //     /version is missing it is simply omitted, but the advertised II list
  //     goes with it, and checkLinkage/checkIiHealth then fail on an II they
  //     cannot resolve. Pin one with --ii / II_ORIGIN (as the deployed
  //     production target does) and both run as normal.
  //
  //     On the probes below that DO check something, a redirect is reported
  //     with where it points rather than followed — for the protocol documents
  //     the status code IS the contract an MCP client depends on, and for the
  //     rest a detour is worth knowing about, not hiding.
  {
    const url = `${mcpOrigin}/version`;
    const r = await probe(url, { timeoutMs });
    const json = tryJson(r.bodyText);
    const commit =
      json && typeof json.commit === "string" ? json.commit : undefined;
    const version =
      json && typeof json.version === "string" ? json.version : undefined;
    const builtAt =
      json && Number.isFinite(json.built_at) ? json.built_at : undefined;
    const startedAt =
      json && Number.isFinite(json.started_at) ? json.started_at : undefined;
    facts.deployment = {
      version,
      commit,
      commitUrl: commitUrl(commit),
      builtAt,
      startedAt,
    };
    // Which II instances this server hands off to. Read here rather than
    // guessed from the hostname: see parseAdvertisedInstances in config.js for
    // why the hostname cannot answer this.
    facts.advertised = parseAdvertisedInstances(json);
  }

  // 2. OAuth Protected Resource Metadata (RFC 9728).
  let protectedResource;
  {
    const url = `${mcpOrigin}/.well-known/oauth-protected-resource`;
    const r = await probe(url, { timeoutMs });
    protectedResource = tryJson(r.bodyText);
    const hasFields =
      protectedResource &&
      Array.isArray(protectedResource.authorization_servers) &&
      typeof protectedResource.resource === "string";
    const resourceOk =
      hasFields && protectedResource.resource === `${mcpOrigin}/mcp`;
    const pass = r.ok && r.status === 200 && hasFields;
    facts.protectedResource = protectedResource;
    checks.push({
      id: "protected-resource",
      label: "OAuth Protected Resource Metadata",
      description:
        "Verifies the RFC 9728 metadata document that tells MCP clients which authorization server protects the /mcp resource.",
      target: `GET ${url}`,
      expected: "200 JSON with authorization_servers + resource",
      status: pass ? (resourceOk ? "pass" : "warn") : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: !pass
        ? r.error
          ? `request failed: ${r.error.message}`
          : `${r.status}${redirectNote(r)}, missing required fields`
        : resourceOk
          ? `resource=${protectedResource.resource}, AS=${protectedResource.authorization_servers.join(", ")}`
          : `resource=${protectedResource.resource} (expected ${mcpOrigin}/mcp)`,
    });
  }

  // 3. OAuth Authorization Server Metadata (RFC 8414).
  let asMeta;
  {
    const url = `${mcpOrigin}/.well-known/oauth-authorization-server`;
    const r = await probe(url, { timeoutMs });
    asMeta = tryJson(r.bodyText);
    const required = [
      "issuer",
      "authorization_endpoint",
      "token_endpoint",
      "registration_endpoint",
    ];
    const missing = asMeta
      ? required.filter((k) => typeof asMeta[k] !== "string")
      : required;
    const pass = r.ok && r.status === 200 && missing.length === 0;
    facts.authorizationServer = asMeta;
    checks.push({
      id: "as-metadata",
      label: "OAuth Authorization Server Metadata",
      description:
        "Verifies the RFC 8414 metadata advertising the authorize/token/registration endpoints and PKCE support that clients need to log in, and reports whether Client ID Metadata Documents are advertised (the registration mode Claude and ChatGPT prefer over DCR; off when the server runs with OAUTH_CIMD_DISABLED).",
      target: `GET ${url}`,
      expected: "200 JSON with issuer + authorize/token/register endpoints",
      status: pass ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: !pass
        ? r.error
          ? `request failed: ${r.error.message}`
          : `${r.status}${redirectNote(r)}, missing fields: ${missing.join(", ") || "n/a"}`
        : `issuer=${asMeta.issuer}, PKCE=${(asMeta.code_challenge_methods_supported || []).join(",") || "none"}, CIMD=${asMeta.client_id_metadata_document_supported === true ? "on" : "off"}`,
    });
  }

  // 3b. Cross-consistency of the two discovery documents.
  {
    const issuer = asMeta?.issuer;
    const asList = protectedResource?.authorization_servers;
    const consistent =
      typeof issuer === "string" &&
      Array.isArray(asList) &&
      asList.includes(issuer) &&
      issuer === `${mcpOrigin}/mcp`;
    checks.push({
      id: "metadata-consistency",
      label: "Discovery documents are self-consistent",
      description:
        "Cross-checks the two discovery documents agree: the authorization server's issuer must be this origin's /mcp path issuer and be listed as an authorization_server.",
      target: "oauth-protected-resource ↔ oauth-authorization-server",
      expected: "issuer === origin/mcp and listed as authorization_server",
      status: consistent ? "pass" : "warn",
      httpStatus: null,
      latencyMs: null,
      detail: consistent
        ? `issuer ${issuer} matches advertised authorization_servers`
        : `issuer=${issuer ?? "?"}, authorization_servers=${JSON.stringify(asList ?? null)}`,
    });
  }

  // 4. The MCP endpoint must answer an unauthenticated call with a 401 + a
  //    standards-compliant WWW-Authenticate challenge pointing at the resource
  //    metadata. This is the contract MCP clients rely on to discover auth.
  {
    const url = `${mcpOrigin}/mcp`;
    const r = await probe(url, {
      timeoutMs,
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "imcp-status-dashboard", version: "1.0.0" },
        },
      }),
    });
    const wwwAuth = r.headers.get("www-authenticate") ?? "";
    // The challenge points at the resource's path-aware metadata document
    // (RFC 9728 §3.1): the resource is `<origin>/mcp`, so its metadata lives at
    // `/.well-known/oauth-protected-resource/mcp`.
    const expectedMetadata = `${mcpOrigin}/.well-known/oauth-protected-resource/mcp`;
    const challengeOk =
      r.status === 401 &&
      /bearer/i.test(wwwAuth) &&
      wwwAuth.includes(expectedMetadata);
    checks.push({
      id: "mcp-challenge",
      label: "MCP endpoint OAuth challenge",
      description:
        "Checks that an unauthenticated call to /mcp returns 401 with a WWW-Authenticate: Bearer challenge pointing at the resource metadata — the handshake MCP clients use to discover how to authenticate.",
      target: `POST ${url} (no token)`,
      expected: `401 + WWW-Authenticate: Bearer resource_metadata="${expectedMetadata}"`,
      status: challengeOk ? "pass" : r.status === 401 ? "warn" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : `${r.status}${redirectNote(r)}, www-authenticate: ${wwwAuth || "(missing)"}`,
    });
  }

  // 5. Dynamic Client Registration (RFC 7591) must mint a client_id. Registered
  //    with a LOOPBACK redirect: loopback is always permitted (the hosted-redirect
  //    allow-list exempts it), so this is the dependency-free way to confirm a
  //    client can self-register without manual approval, which is what DCR is for.
  //    Skipped in non-mutating mode: this is the one probe that changes server
  //    state (the minted client_id is persisted in the LRU-bounded registration
  //    store), so an unattended periodic caller must not run it.
  if (mutating) {
    const url = `${mcpOrigin}/mcp/oauth/register`;
    const r = await probe(url, {
      timeoutMs,
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "imcp-status-dashboard",
        redirect_uris: ["http://127.0.0.1:8765/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
      }),
    });
    const json = tryJson(r.bodyText);
    const pass =
      (r.status === 200 || r.status === 201) &&
      json &&
      typeof json.client_id === "string";
    checks.push({
      id: "oauth-register",
      label: "OAuth Dynamic Client Registration",
      description:
        "Confirms Dynamic Client Registration (RFC 7591) issues a client_id for a loopback client, so native/CLI MCP clients can self-register without manual setup.",
      target: `POST ${url}`,
      expected: "200/201 JSON with client_id",
      status: pass ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : pass
          ? `registered client_id=${json.client_id}`
          : `${r.status}${redirectNote(r)}, body: ${r.bodyText.slice(0, 120)}`,
    });
  }

  // 5b. The hosted-redirect allow-list must REJECT a hosted redirect_uri on a
  //     domain that isn't approved (CWE-601 auth-code phishing guard). A
  //     non-allow-listed hosted redirect is refused with 400 invalid_redirect_uri
  //     before any client_id is issued; loopback (above) stays exempt. The probe
  //     uses a reserved `.invalid` host (RFC 2606) that can never be legitimately
  //     allow-listed by a deployment, so this can't false-alert if the allow-list
  //     is widened via OAUTH_ALLOWED_REDIRECT_PREFIXES.
  //     Also skipped in non-mutating mode: while the guard holds this stores
  //     nothing, but if it regressed (exactly what this probe detects) each run
  //     would mint a client — an unattended periodic caller must not become a
  //     store-grinding loop at the very moment the server is broken.
  if (mutating) {
    const url = `${mcpOrigin}/mcp/oauth/register`;
    const r = await probe(url, {
      timeoutMs,
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "imcp-status-dashboard-probe",
        redirect_uris: ["https://not-allowlisted.invalid/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
      }),
    });
    const json = tryJson(r.bodyText);
    const pass = r.status === 400 && json && json.error === "invalid_redirect_uri";
    checks.push({
      id: "oauth-register-allowlist",
      label: "OAuth redirect allow-list enforced",
      description:
        "Confirms a hosted redirect_uri on a non-allow-listed domain is rejected (400 invalid_redirect_uri), closing the open-registration auth-code phishing vector (CWE-601). Loopback redirects stay exempt.",
      target: `POST ${url}`,
      expected: "400 invalid_redirect_uri",
      status: pass ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : pass
          ? "rejected non-allow-listed hosted redirect_uri"
          : `expected 400 invalid_redirect_uri, got ${r.status}${redirectNote(r)}: ${r.bodyText.slice(0, 120)}`,
    });
  }

  // 6. Authorization endpoint liveness: rejects malformed input with 4xx
  //    (rather than 5xx / connection error). It is interactive, so we only
  //    assert it is alive and validating, not a full successful redirect.
  {
    const url = `${mcpOrigin}/mcp/oauth/authorize`;
    const r = await probe(url, { timeoutMs });
    const alive = r.ok && r.status >= 400 && r.status < 500;
    checks.push({
      id: "oauth-authorize",
      label: "OAuth Authorization endpoint liveness",
      description:
        "Confirms the authorization endpoint is alive and validates input, rejecting a malformed request with a 4xx rather than erroring or hanging.",
      target: `GET ${url} (no params)`,
      expected: "4xx (validates input; does not 5xx / hang)",
      status: alive ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : `${r.status}${redirectNote(r)}, ${r.bodyText.slice(0, 100)}`,
    });
  }

  // 7. Token endpoint liveness: a bogus grant must be rejected with 400.
  {
    const url = `${mcpOrigin}/mcp/oauth/token`;
    const r = await probe(url, {
      timeoutMs,
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=invalid&code_verifier=x&client_id=x",
    });
    const json = tryJson(r.bodyText);
    const alive = r.status === 400 && json && typeof json.error === "string";
    checks.push({
      id: "oauth-token",
      label: "OAuth Token endpoint liveness",
      description:
        "Confirms the token endpoint is alive and rejects an invalid grant with a standards-compliant 400 OAuth error.",
      target: `POST ${url} (invalid grant)`,
      expected: "400 with OAuth error (e.g. invalid_grant)",
      status: alive ? "pass" : r.status === 400 ? "warn" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : `${r.status}${redirectNote(r)}, error: ${json?.error ?? r.bodyText.slice(0, 80)}`,
    });
  }

  // TLS certificate freshness for the MCP host.
  {
    const cert = await inspectCertificate(mcpOrigin, timeoutMs);
    facts.mcpCertificate = cert;
    if ("error" in cert) {
      checks.push({
        id: "mcp-tls",
        label: "TLS certificate",
        description:
          "Checks the MCP host's TLS certificate is valid and not close to expiry.",
        target: mcpOrigin,
        expected: "valid certificate, > 21 days remaining",
        status: "warn",
        httpStatus: null,
        latencyMs: null,
        detail: `could not inspect certificate: ${cert.error}`,
      });
    } else {
      checks.push({
        id: "mcp-tls",
        label: "TLS certificate",
        description:
          "Checks the MCP host's TLS certificate is valid and not close to expiry.",
        target: mcpOrigin,
        expected: "valid certificate, > 21 days remaining",
        status:
          cert.daysRemaining < 0
            ? "fail"
            : cert.daysRemaining < 21
              ? "warn"
              : "pass",
        httpStatus: null,
        latencyMs: null,
        detail: `expires ${cert.validTo} (${cert.daysRemaining} days remaining)`,
      });
    }
  }

  return {
    section: {
      id: "endpoints",
      title: "MCP server endpoints",
      status: worstStatus(checks.map((c) => c.status)),
      checks,
    },
    facts,
  };
};

// ---------------------------------------------------------------------------
// Section 2 — Which II instance is the MCP server linked to?
// ---------------------------------------------------------------------------

/**
 * Resolve which II instance(s) the MCP server is paired with, from the
 * `instances` array it advertises at `GET /version` — one entry per mount, each
 * naming the II origin that mount hands off to. The server is the authority on
 * its own pairing, so this is read, not inferred.
 *
 * We still don't confirm the link by following `/mcp/oauth/authorize`
 * headlessly: that endpoint issues a *script-initiated* navigation (an HTML page
 * that calls `location.replace`), not an HTTP 3xx redirect — because the II
 * `/mcp` URL carries its params in the fragment and form-action CSP is enforced
 * across redirects — so there is no `Location` header to read and the probe
 * could never pass. What the advertised list does give us is the right origins
 * to probe, and all of them: the II-health section runs once per instance, so a
 * staging deployment serving production II at `/mcp` and beta II at `/mcp-beta`
 * has both monitored instead of just the one a hostname guess happened to name.
 *
 * @param {string} mcpOrigin
 * @param {import("./config.js").IiInstanceTarget[]} instances
 * @param {{ name: string, origin: string, reason: string }[]} rejected
 * @param {string} iiOriginSource
 * @returns {{ section: Section, facts: Record<string, unknown> }}
 */
export const checkLinkage = (
  mcpOrigin,
  instances,
  rejected,
  iiOriginSource,
) => {
  /** @type {CheckResult[]} */
  const checks = [];
  /** @type {Record<string, unknown>} */
  const facts = { instances, rejected };

  if (instances.length === 0) {
    checks.push({
      id: "ii-target",
      label: "Linked Internet Identity instance",
      description:
        "Identifies which Internet Identity instance(s) this MCP server is paired with, from the `instances` array it advertises at GET /version. Without it the pairing is unknowable from outside — the MCP origin does not imply its II — so the II-health checks below cannot run.",
      target: `GET ${mcpOrigin}/version`,
      expected: "an instances[] array naming each mount's II origin",
      status: "fail",
      httpStatus: null,
      latencyMs: null,
      detail:
        rejected.length > 0
          ? `every advertised II origin was rejected: ${rejected.map((r) => `${r.name} → ${r.origin} (${r.reason})`).join("; ")}`
          : "the server advertises no II instances at /version (a build predating the instances[] field, or an unreachable /version). Pin one with --ii / II_ORIGIN to probe it anyway.",
    });
  } else {
    for (const inst of instances) {
      checks.push({
        id: `ii-target:${inst.name}`,
        label: `Linked Internet Identity instance — ${inst.name}`,
        description:
          "Identifies which Internet Identity instance this mount hands off to, as advertised by the server at GET /version. The II-health section below probes this origin's reachability and /mcp connect page.",
        target: `${mcpOrigin}${inst.mcpPath ?? ""}`,
        expected: "a resolvable II origin",
        status: "pass",
        httpStatus: null,
        latencyMs: null,
        detail:
          `${inst.origin} (${iiOriginSource})` +
          (inst.iiCanister ? `, canister ${inst.iiCanister}` : ""),
      });
    }
    // Advertised but unprobeable: report it rather than quietly monitoring less
    // than the section's title implies.
    for (const r of rejected) {
      checks.push({
        id: `ii-target-rejected:${r.name}`,
        label: `Advertised II origin not probeable — ${r.name}`,
        description:
          "The server advertises this II origin, but the dashboard will not probe it: advertised origins are validated against the probe allowlist so a misconfigured or compromised server cannot steer these probes at a third party. Extend MCP_STATUS_ALLOWED_HOSTS if the origin is legitimate.",
        target: r.origin,
        expected: "an origin within the probe allowlist",
        status: "warn",
        httpStatus: null,
        latencyMs: null,
        detail: r.reason,
      });
    }
  }

  return {
    section: {
      id: "linkage",
      title: "Linked Internet Identity instances",
      status: worstStatus(checks.map((c) => c.status)),
      checks,
    },
    facts,
  };
};

// ---------------------------------------------------------------------------
// Section 3 — Is the linked II healthy, and does it recognise this MCP server?
// ---------------------------------------------------------------------------

/**
 * @param {string | undefined} iiOrigin
 * @param {string} mcpOrigin
 * @param {number} timeoutMs
 * @returns {Promise<{ section: Section, facts: Record<string, unknown> }>}
 */
export const checkIiHealth = async (
  iiOrigin,
  mcpOrigin,
  timeoutMs,
  instanceName,
) => {
  /** @type {CheckResult[]} */
  const checks = [];
  /** @type {Record<string, unknown>} */
  const facts = {};
  // One section per served II instance, so ids must be unique across them.
  // Unsuffixed when no instance is named, keeping single-target callers stable.
  const sfx = instanceName ? `:${instanceName}` : "";
  const named = instanceName ? ` — ${instanceName}` : "";

  if (!iiOrigin) {
    checks.push({
      id: "ii-unresolved",
      label: "Internet Identity health",
      description:
        "No Internet Identity origin could be resolved, so its health and recognition of this MCP server cannot be assessed.",
      target: "(unknown)",
      expected: "a resolved II origin to probe",
      status: "fail",
      httpStatus: null,
      latencyMs: null,
      detail: "no II origin resolved; cannot assess health",
    });
    return {
      section: {
        id: `ii-health${sfx}`,
        title: `Internet Identity health & recognition${named}`,
        status: "fail",
        checks,
      },
      facts,
    };
  }

  facts.origin = iiOrigin;
  const r = await probe(`${iiOrigin}/`, { timeoutMs });
  const csp = r.headers.get("content-security-policy");
  const canisterId = r.headers.get("x-ic-canister-id");
  const icCertificate = r.headers.get("ic-certificate");
  facts.canisterId = canisterId;

  // 1. Frontend reachability.
  checks.push({
    id: `ii-reachable${sfx}`,
    label: "II frontend reachable",
    description:
      "Confirms the linked Internet Identity frontend is reachable and returns HTTP 200.",
    target: `GET ${iiOrigin}/`,
    expected: "200",
    status: r.ok && r.status === 200 ? "pass" : "fail",
    httpStatus: r.status,
    latencyMs: r.latencyMs,
    detail: r.error
      ? `request failed: ${r.error.message}`
      : `${r.status}${redirectNote(r)}${canisterId ? `, canister ${canisterId}` : ""}`,
  });

  // 2. Served & certified by the Internet Computer (canister is live).
  checks.push({
    id: `ii-certified${sfx}`,
    label: "IC-certified response (canister live)",
    description:
      "Checks the II response carries an ic-certificate header, indicating it is served and certified by a live Internet Computer canister.",
    target: `${iiOrigin}/`,
    expected: "ic-certificate header present",
    status: icCertificate ? "pass" : "warn",
    httpStatus: r.status,
    latencyMs: r.latencyMs,
    detail: icCertificate
      ? `ic-certificate present${canisterId ? ` for canister ${canisterId}` : ""}`
      : "no ic-certificate header (response not certified by the IC?)",
  });

  // 3. /mcp connect page. Since dfinity/internet-identity#4052 the II no longer
  //    has a global `mcp_server_origin`, and trust is per-user: each identity
  //    adds the MCP server it trusts in II Settings, synced on-chain. So there is
  //    no global, unauthenticated signal that names this specific server —
  //    recognition is per-identity and not inspectable from here.
  //
  //    There is also no instance-wide CSP signal to assert. An older delegation
  //    flow form-POSTed the callback to the server, so a relaxed `form-action`
  //    (`'self' https:`) was its precondition — but dfinity/internet-identity
  //    #4086 retired that flow. The current connect flow never form-POSTs: II
  //    hands the browser back to the server's pinned callback page by top-level
  //    navigation (not governed by `form-action`), and that page redeems the
  //    delegation with a `fetch()` to the server (governed by `connect-src`,
  //    which allows the https origin). The tightened
  //    `form-action 'self' http://127.0.0.1:*` now on /mcp is for the unrelated
  //    /cli loopback flow, not MCP. So the only meaningful instance-wide health
  //    signal left is that the /mcp connect page is served.
  {
    const url = `${iiOrigin}/mcp`;
    const mr = await probe(url, { timeoutMs });
    const served = mr.ok && mr.status === 200;
    checks.push({
      id: `ii-mcp-flow${sfx}`,
      label: "II /mcp connect page served",
      description:
        "Confirms the II serves its /mcp connect page. The connect flow runs on a top-level navigation back to the server's pinned callback page and a fetch() from that page to the server (governed by CSP connect-src, which allows the https MCP origin) — neither is gated by form-action — so serving the page is the health signal. Since #4052 trust is per-user (each identity adds its trusted server in II Settings, synced on-chain), which servers a given identity trusts is not globally inspectable; this checks the instance-wide flow is enabled.",
      target: `GET ${url}`,
      expected: "200 (connect page served)",
      status: served ? "pass" : "fail",
      httpStatus: mr.status,
      latencyMs: mr.latencyMs,
      detail: mr.error
        ? `request failed: ${mr.error.message}`
        : served
          ? `${mr.status}, /mcp connect page served`
          : `${mr.status}${redirectNote(mr)}, /mcp connect page not served`,
    });
  }

  // 3b. II frontend config: the II still serves its runtime config as a textual
  //     Candid record at /.config (backend canister id, related origins, …). It
  //     no longer carries `mcp_server_origin` (removed in #4052 — MCP trust moved
  //     to per-user, on-chain settings), so we only confirm it is served and
  //     surface the backend canister id.
  {
    const url = `${iiOrigin}/.config`;
    const cr = await probe(url, { timeoutMs });
    // The config is text/plain Candid, so bodyText is the real content; prefer
    // the server-reported content-length for the byte count when present. (Guard
    // against a missing header: Number(null) is 0, which would wrongly win here.)
    // Fall back to the UTF-8 byte length, not String#length (UTF-16 code units).
    const lenRaw = cr.headers.get("content-length");
    const lenHeader = lenRaw === null ? NaN : Number(lenRaw);
    const bytes =
      Number.isFinite(lenHeader) && lenHeader >= 0
        ? lenHeader
        : Buffer.byteLength(cr.bodyText, "utf8");
    const looksLikeConfig =
      /\brecord\s*\{/.test(cr.bodyText) ||
      cr.bodyText.includes("backend_canister_id");
    // Surface the backend canister id (the II canister the delegation methods
    // target) from the textual Candid, for context.
    const m = cr.bodyText.match(
      /backend_canister_id\s*=\s*principal\s*"([^"]+)"/,
    );
    const backendCanisterId = m ? m[1] : undefined;
    const present = cr.ok && cr.status === 200 && looksLikeConfig;
    facts.config = { status: cr.status, bytes, backendCanisterId };
    checks.push({
      id: `ii-config${sfx}`,
      label: "II frontend config (.config)",
      description:
        "Checks the II frontend serves its runtime config (textual Candid) at /.config, reporting the backend canister id. (Post-#4052 this config no longer carries an mcp_server_origin — MCP trust moved to per-user, on-chain settings.)",
      target: `GET ${url}`,
      expected: "200 textual Candid config record",
      status: present ? "pass" : cr.status === 200 ? "warn" : "fail",
      httpStatus: cr.status,
      latencyMs: cr.latencyMs,
      detail: cr.error
        ? `request failed: ${cr.error.message}`
        : present
          ? `${cr.status}, ${bytes} bytes${backendCanisterId ? `, backend ${backendCanisterId}` : ""}`
          : `${cr.status}${redirectNote(cr)}, ${cr.bodyText.slice(0, 80) || "(empty)"}`,
    });
  }

  // 4. Report the II's configured related origins (context, not pass/fail).
  const frameAncestors = parseCspDirective(csp, "frame-ancestors");
  const relatedOrigins = (frameAncestors ?? []).filter((o) =>
    o.startsWith("http"),
  );
  facts.relatedOrigins = relatedOrigins;
  checks.push({
    id: `ii-related-origins${sfx}`,
    label: "II related origins",
    description:
      "Reports the II's configured related/alternative frontend origins (from the CSP frame-ancestors directive) for context.",
    target: `${iiOrigin} CSP frame-ancestors`,
    expected: "the II's alternative front-end origins",
    status: relatedOrigins.length > 0 ? "pass" : "warn",
    httpStatus: null,
    latencyMs: null,
    detail:
      relatedOrigins.length > 0
        ? relatedOrigins.join(", ")
        : "no related origins advertised",
  });

  // 5. TLS certificate freshness for the II host.
  const cert = await inspectCertificate(iiOrigin, timeoutMs);
  facts.certificate = cert;
  if ("error" in cert) {
    checks.push({
      id: `ii-tls${sfx}`,
      label: "TLS certificate",
      description:
        "Checks the Internet Identity host's TLS certificate is valid and not close to expiry.",
      target: iiOrigin,
      expected: "valid certificate, > 21 days remaining",
      status: "warn",
      httpStatus: null,
      latencyMs: null,
      detail: `could not inspect certificate: ${cert.error}`,
    });
  } else {
    checks.push({
      id: `ii-tls${sfx}`,
      label: "TLS certificate",
      description:
        "Checks the Internet Identity host's TLS certificate is valid and not close to expiry.",
      target: iiOrigin,
      expected: "valid certificate, > 21 days remaining",
      status:
        cert.daysRemaining < 0
          ? "fail"
          : cert.daysRemaining < 21
            ? "warn"
            : "pass",
      httpStatus: null,
      latencyMs: null,
      detail: `expires ${cert.validTo} (${cert.daysRemaining} days remaining)`,
    });
  }

  return {
    section: {
      id: `ii-health${sfx}`,
      title: `Internet Identity health & recognition${named}`,
      status: worstStatus(checks.map((c) => c.status)),
      checks,
    },
    facts,
  };
};

// ---------------------------------------------------------------------------
// Suggestions — actionable, partly derived from the live findings
// ---------------------------------------------------------------------------

/**
 * @param {Section[]} sections
 * @param {Record<string, unknown>} facts
 * @returns {string[]}
 */
export const buildSuggestions = (sections, facts) => {
  const suggestions = [];
  const checkById = {};
  /** @type {CheckResult[]} */
  const allChecks = [];
  for (const s of sections)
    for (const c of s.checks) {
      checkById[c.id] = c;
      allChecks.push(c);
    }

  // Ids are suffixed per instance (`ii-mcp-flow:prod`), so match on the family
  // rather than an exact id, and name the instances that are actually failing.
  const flowFailures = allChecks.filter(
    (c) =>
      (c.id === "ii-mcp-flow" || c.id.startsWith("ii-mcp-flow:")) &&
      c.status === "fail",
  );
  if (flowFailures.length > 0) {
    const which = flowFailures
      .map((c) => c.id.split(":")[1])
      .filter(Boolean)
      .join(", ");
    suggestions.push(
      `The linked II${which ? ` (${which})` : ""} does not serve its /mcp ` +
        "connect page. The MCP connect flow cannot run until an II build that " +
        "includes the /mcp flow is deployed at this origin.",
    );
  }
  if (checkById["mcp-challenge"]?.status !== "pass") {
    suggestions.push(
      "The unauthenticated /mcp response should be a 401 carrying " +
        'WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp". ' +
        "MCP clients rely on this header to discover the authorization server.",
    );
  }
  // The catch-all returns 401 for unknown paths, so uptime monitors can't use a
  // plain GET. Recommend a dedicated unauthenticated liveness endpoint.
  suggestions.push(
    "Add an unauthenticated GET /healthz (or /livez) that returns 200. " +
      "Unknown paths currently fall through to the OAuth 401 catch-all, so " +
      "external uptime monitors have no clean liveness probe.",
  );
  suggestions.push(
    "POST /mcp/oauth/register accepts anonymous dynamic client registration. " +
      "Ensure it is rate-limited and that stale/unused clients are pruned to " +
      "avoid unbounded growth, and that registrations are shared across all " +
      "server replicas (a freshly registered client_id was not immediately " +
      "usable at /mcp/oauth/authorize during probing).",
  );

  // facts.iiInstances is one entry per served II instance, so flatten before
  // scanning; a cert nearing expiry on ANY of them is worth the warning.
  const certWarn = [facts?.mcp, ...Object.values(facts?.iiInstances ?? {})]
    .map((f) => /** @type {any} */ (f)?.certificate ?? f?.mcpCertificate)
    .filter((c) => c && typeof c.daysRemaining === "number" && c.daysRemaining < 21);
  if (certWarn.length > 0) {
    suggestions.push(
      "A TLS certificate is within 21 days of expiry — verify automatic renewal.",
    );
  }

  suggestions.push(
    "Wire this dashboard into alerting: run `node monitoring/mcp-status/cli.js " +
      "--json` on a schedule (cron/CI) and page on a non-zero exit code, and/or " +
      "host `server.js` behind your status page. Track per-endpoint latency over " +
      "time to catch slow degradations before they become outages.",
  );

  return suggestions;
};

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Run the full dashboard against the resolved configuration.
 * @param {{ mcpOrigin?: string, iiOrigin?: string, timeoutMs?: number, mutating?: boolean }} [overrides]
 *   `mutating: false` skips both registration probes — the loopback Dynamic
 *   Client Registration check (always mutates) and the allow-list check
 *   (mutates whenever the guard it tests has regressed) — see
 *   checkMcpEndpoints. The report then carries neither of those checks.
 * @returns {Promise<DashboardReport>}
 */
export const runDashboard = async (overrides = {}) => {
  const cfg = resolveConfig(overrides);

  const endpoints = await checkMcpEndpoints(cfg.mcpOrigin, cfg.timeoutMs, {
    mutating: overrides.mutating !== false,
  });

  // Which IIs to probe. Normally the ones the server advertises at /version —
  // it is the authority on its own pairing, and it lists every mount, so both a
  // production deployment (`/mcp` alone) and staging (`/mcp` + `/mcp-beta`) are
  // covered without per-deployment config. An explicit --ii / II_ORIGIN replaces
  // that entirely, for a build that predates the instances[] field.
  const advertised = /** @type {any} */ (endpoints.facts.advertised) ?? {
    instances: [],
    rejected: [],
  };
  const instances = cfg.iiOverride
    ? [{ name: "configured", origin: cfg.iiOverride, mcpPath: undefined }]
    : advertised.instances;
  const rejected = cfg.iiOverride ? [] : advertised.rejected;
  const iiOriginSource = cfg.iiOverride
    ? "explicitly configured"
    : "advertised by the server at /version";

  const linkage = checkLinkage(
    cfg.mcpOrigin,
    instances,
    rejected,
    iiOriginSource,
  );

  // One II-health section per served instance. Sequential, not concurrent: the
  // list is short and this keeps the per-probe latencies reported here
  // comparable to what a single user experiences.
  const iiHealths = [];
  if (instances.length === 0) {
    iiHealths.push(await checkIiHealth(undefined, cfg.mcpOrigin, cfg.timeoutMs));
  } else {
    for (const inst of instances) {
      iiHealths.push(
        await checkIiHealth(
          inst.origin,
          cfg.mcpOrigin,
          cfg.timeoutMs,
          instances.length > 1 ? inst.name : undefined,
        ),
      );
    }
  }

  const sections = [
    endpoints.section,
    linkage.section,
    ...iiHealths.map((h) => h.section),
  ];
  const facts = {
    mcp: endpoints.facts,
    linkage: linkage.facts,
    // Keyed by instance name so a multi-instance deployment's facts stay
    // attributable. Named `iiInstances`, not `ii`: the old key held ONE
    // instance's facts, and a consumer reaching for `facts.ii.canisterId`
    // against this shape would silently read undefined. An absent key makes
    // that a visible break instead of a quiet wrong answer.
    iiInstances: Object.fromEntries(
      iiHealths.map((h, i) => [instances[i]?.name ?? "unresolved", h.facts]),
    ),
  };

  return {
    generatedAt: new Date().toISOString(),
    targets: {
      mcpOrigin: cfg.mcpOrigin,
      iiOrigins: instances.map((i) => i.origin),
      iiOriginSource,
    },
    deployment: /** @type {Deployment} */ (
      endpoints.facts.deployment ?? {
        version: undefined,
        commit: undefined,
        commitUrl: undefined,
        builtAt: undefined,
        startedAt: undefined,
      }
    ),
    overall: worstStatus(sections.map((s) => s.status)),
    sections,
    facts,
    suggestions: buildSuggestions(sections, facts),
  };
};
