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
import { commitUrl, deriveIiOrigin, resolveConfig } from "./config.js";

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
 * @property {{ mcpOrigin: string, iiOrigin: string | undefined, iiOriginSource: string }} targets
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

/**
 * Perform an HTTP request with a timeout, capturing status, headers, body and
 * latency without ever throwing (network errors are returned as `error`).
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
      latencyMs: Date.now() - start,
      error: /** @type {Error | null} */ (null),
    };
  } catch (err) {
    return {
      ok: false,
      status: /** @type {number | null} */ (null),
      headers: new Headers(),
      bodyText: "",
      latencyMs: Date.now() - start,
      error: /** @type {Error} */ (err),
    };
  }
};

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
 * @returns {Promise<{ section: Section, facts: Record<string, unknown> }>}
 */
export const checkMcpEndpoints = async (mcpOrigin, timeoutMs) => {
  /** @type {CheckResult[]} */
  const checks = [];
  /** @type {Record<string, unknown>} */
  const facts = { origin: mcpOrigin };

  // 1. Landing page.
  {
    const r = await probe(`${mcpOrigin}/`, { timeoutMs });
    const ct = r.headers.get("content-type") ?? "";
    const pass = r.ok && r.status === 200 && /text\/html/i.test(ct);
    checks.push({
      id: "root",
      label: "Landing page",
      description:
        "Confirms the server is up and serving its human-facing landing page (HTTP 200, HTML) at the root URL.",
      target: `GET ${mcpOrigin}/`,
      expected: "200 text/html",
      status: pass ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : `${r.status}, content-type: ${ct || "(none)"}`,
    });
  }

  // 1b. Build/version: which commit is actually running. Surfaced prominently
  //     in the report (with a GitHub link) so operators can confirm the live
  //     deployment; older builds without /version are treated as informational.
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
    const exposed = r.ok && r.status === 200 && !!commit;
    const known = exposed && commit !== "unknown";
    checks.push({
      id: "version",
      label: "Deployment version",
      description:
        "Reports the running build's version and commit via GET /version, so you can confirm exactly which deployment is live and trace it back to source.",
      target: `GET ${url}`,
      expected: "200 JSON with version + commit",
      status: known ? "pass" : "warn",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : exposed
          ? `version ${version ?? "?"}, commit ${commit}`
          : `${r.status}, no version info exposed`,
    });
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
          : `${r.status}, missing required fields`
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
        "Verifies the RFC 8414 metadata advertising the authorize/token/registration endpoints and PKCE support that clients need to log in.",
      target: `GET ${url}`,
      expected: "200 JSON with issuer + authorize/token/register endpoints",
      status: pass ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: !pass
        ? r.error
          ? `request failed: ${r.error.message}`
          : `${r.status}, missing fields: ${missing.join(", ") || "n/a"}`
        : `issuer=${asMeta.issuer}, PKCE=${(asMeta.code_challenge_methods_supported || []).join(",") || "none"}`,
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
      issuer === mcpOrigin;
    checks.push({
      id: "metadata-consistency",
      label: "Discovery documents are self-consistent",
      description:
        "Cross-checks the two discovery documents agree: the authorization server's issuer must match this origin and be listed as an authorization_server.",
      target: "oauth-protected-resource ↔ oauth-authorization-server",
      expected: "issuer === origin and listed as authorization_server",
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
    const expectedMetadata = `${mcpOrigin}/.well-known/oauth-protected-resource`;
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
        : `${r.status}, www-authenticate: ${wwwAuth || "(missing)"}`,
    });
  }

  // 5. Dynamic Client Registration (RFC 7591) must mint a client_id.
  {
    const url = `${mcpOrigin}/oauth/register`;
    const r = await probe(url, {
      timeoutMs,
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "imcp-status-dashboard",
        redirect_uris: ["https://example.org/callback"],
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
        "Confirms Dynamic Client Registration (RFC 7591) issues a client_id, so MCP clients can self-register without manual setup.",
      target: `POST ${url}`,
      expected: "200/201 JSON with client_id",
      status: pass ? "pass" : "fail",
      httpStatus: r.status,
      latencyMs: r.latencyMs,
      detail: r.error
        ? `request failed: ${r.error.message}`
        : pass
          ? `registered client_id=${json.client_id}`
          : `${r.status}, body: ${r.bodyText.slice(0, 120)}`,
    });
  }

  // 6. Authorization endpoint liveness: rejects malformed input with 4xx
  //    (rather than 5xx / connection error). It is interactive, so we only
  //    assert it is alive and validating, not a full successful redirect.
  {
    const url = `${mcpOrigin}/oauth/authorize`;
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
        : `${r.status}, ${r.bodyText.slice(0, 100)}`,
    });
  }

  // 7. Token endpoint liveness: a bogus grant must be rejected with 400.
  {
    const url = `${mcpOrigin}/oauth/token`;
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
        : `${r.status}, error: ${json?.error ?? r.bodyText.slice(0, 80)}`,
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
 * Resolve which II instance the MCP server is paired with. We don't try to
 * confirm the link by following `/oauth/authorize` headlessly: that endpoint
 * issues a *script-initiated* navigation (an HTML page that calls
 * `location.replace`), not an HTTP 3xx redirect — because the II `/mcp` URL
 * carries its params in the fragment and form-action CSP is enforced across
 * redirects — so there is no `Location` header to read and the probe could
 * never pass. Instead we resolve the origin (configured or naming-convention
 * derived); the II-health section below then checks that *resolved* origin is
 * reachable and has its `/mcp` delegation flow enabled. Note this does not
 * live-verify that the MCP server actually hands off to that II instance — the
 * pairing is inferred from config / the naming convention, not proven.
 *
 * @param {string} mcpOrigin
 * @param {string | undefined} configuredIi
 * @param {string} iiOriginSource
 * @returns {{ section: Section, iiOrigin: string | undefined, facts: Record<string, unknown> }}
 */
export const checkLinkage = (mcpOrigin, configuredIi, iiOriginSource) => {
  /** @type {CheckResult[]} */
  const checks = [];
  /** @type {Record<string, unknown>} */
  const facts = {};

  const iiOrigin = configuredIi ?? deriveIiOrigin(mcpOrigin);
  const resolvedSource =
    iiOriginSource === "explicit"
      ? "explicitly configured"
      : iiOriginSource === "derived"
        ? "derived from naming convention (mcp.<env>.id.ai → <env>.id.ai)"
        : "unknown";

  checks.push({
    id: "ii-target",
    label: "Linked Internet Identity instance",
    description:
      "Identifies which Internet Identity instance this MCP server is paired with (explicitly configured, or derived from the naming convention — the pairing is inferred, not live-verified). The II-health section below then checks that resolved origin is reachable and has its /mcp delegation flow enabled.",
    target: mcpOrigin,
    expected: "a resolvable II origin",
    status: iiOrigin ? "pass" : "fail",
    httpStatus: null,
    latencyMs: null,
    detail: iiOrigin
      ? `${iiOrigin} (${resolvedSource})`
      : "could not resolve a linked II origin",
  });

  return {
    section: {
      id: "linkage",
      title: "Linked Internet Identity instance",
      status: worstStatus(checks.map((c) => c.status)),
      checks,
    },
    iiOrigin,
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
export const checkIiHealth = async (iiOrigin, mcpOrigin, timeoutMs) => {
  /** @type {CheckResult[]} */
  const checks = [];
  /** @type {Record<string, unknown>} */
  const facts = {};

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
        id: "ii-health",
        title: "Internet Identity health & recognition",
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
    id: "ii-reachable",
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
      : `${r.status}${canisterId ? `, canister ${canisterId}` : ""}`,
  });

  // 2. Served & certified by the Internet Computer (canister is live).
  checks.push({
    id: "ii-certified",
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

  // 3. /mcp delegation flow. Since dfinity/internet-identity#4052 the II no
  //    longer has a global `mcp_server_origin`, and trust is per-user: each
  //    identity adds the MCP server it trusts in II Settings, synced on-chain.
  //    So there is no global, unauthenticated signal that names this specific
  //    server — recognition is per-identity and not inspectable from here.
  //    What IS instance-wide and inspectable is whether the `/mcp` connect page
  //    is served and whether its CSP `form-action` is relaxed to allow posting
  //    the delegation callback to an https MCP server (`'self' https:` on /mcp
  //    paths, vs the tighter `'self' http://127.0.0.1:*` SPA-wide). That relaxed
  //    form-action is what lets any https MCP server's connect callback POST
  //    back, so it is the authoritative health signal for the delegation flow.
  {
    const url = `${iiOrigin}/mcp`;
    const mr = await probe(url, { timeoutMs });
    const mcpFormAction = parseCspDirective(
      mr.headers.get("content-security-policy"),
      "form-action",
    );
    facts.mcpFormAction = mcpFormAction;
    // The callback is posted to an https origin, so the /mcp page's form-action
    // must permit https: (the `https:` scheme source, or this exact origin).
    const allowsHttpsPost =
      !!mcpFormAction &&
      (mcpFormAction.includes("https:") || mcpFormAction.includes(mcpOrigin));
    const served = mr.ok && mr.status === 200;
    checks.push({
      id: "ii-mcp-flow",
      label: "II /mcp delegation flow enabled",
      description:
        "Confirms the II serves its /mcp delegation page and that its CSP form-action is relaxed to allow posting the delegation callback to an https MCP server. Since #4052 trust is per-user (each identity adds its trusted server in II Settings, synced on-chain), so which servers a given identity trusts is not globally inspectable; this checks the instance-wide flow is enabled.",
      target: `GET ${url} CSP form-action`,
      expected: "200 and form-action allows https: (callback can post to https)",
      status: served ? (allowsHttpsPost ? "pass" : "warn") : "fail",
      httpStatus: mr.status,
      latencyMs: mr.latencyMs,
      detail: mr.error
        ? `request failed: ${mr.error.message}`
        : !served
          ? `${mr.status}, /mcp delegation page not served`
          : mcpFormAction
            ? allowsHttpsPost
              ? `form-action = [${mcpFormAction.join(", ")}] → can post the callback to https MCP servers`
              : `form-action = [${mcpFormAction.join(", ")}] (does NOT allow https: — the callback to ${mcpOrigin} would be blocked)`
            : "200 but no form-action directive in the /mcp CSP",
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
      id: "ii-config",
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
          : `${cr.status}, ${cr.bodyText.slice(0, 80) || "(empty)"}`,
    });
  }

  // 4. Report the II's configured related origins (context, not pass/fail).
  const frameAncestors = parseCspDirective(csp, "frame-ancestors");
  const relatedOrigins = (frameAncestors ?? []).filter((o) =>
    o.startsWith("http"),
  );
  facts.relatedOrigins = relatedOrigins;
  checks.push({
    id: "ii-related-origins",
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
      id: "ii-tls",
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
      id: "ii-tls",
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
      id: "ii-health",
      title: "Internet Identity health & recognition",
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
  for (const s of sections) for (const c of s.checks) checkById[c.id] = c;

  if (checkById["ii-mcp-flow"]?.status === "fail") {
    suggestions.push(
      "The linked II does not serve its /mcp delegation page. The MCP connect " +
        "flow cannot run until an II build that includes the /mcp flow is " +
        "deployed at this origin.",
    );
  } else if (checkById["ii-mcp-flow"]?.status === "warn") {
    suggestions.push(
      "The II /mcp page is served but its CSP form-action does not allow " +
        "https:, so it cannot post the delegation callback to an https MCP " +
        "server. Note that since #4052 each user also adds the trusted MCP " +
        "server in II Settings (synced on-chain): a connect only succeeds for " +
        "servers the signed-in identity has trusted, which this dashboard " +
        "cannot verify without authenticating.",
    );
  }
  if (checkById["mcp-challenge"]?.status !== "pass") {
    suggestions.push(
      "The unauthenticated /mcp response should be a 401 carrying " +
        'WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource". ' +
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
    "POST /oauth/register accepts anonymous dynamic client registration. " +
      "Ensure it is rate-limited and that stale/unused clients are pruned to " +
      "avoid unbounded growth, and that registrations are shared across all " +
      "server replicas (a freshly registered client_id was not immediately " +
      "usable at /oauth/authorize during probing).",
  );

  const certWarn = [facts?.mcp, facts?.ii]
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
 * @param {{ mcpOrigin?: string, iiOrigin?: string, timeoutMs?: number }} [overrides]
 * @returns {Promise<DashboardReport>}
 */
export const runDashboard = async (overrides = {}) => {
  const cfg = resolveConfig(overrides);

  const endpoints = await checkMcpEndpoints(cfg.mcpOrigin, cfg.timeoutMs);
  const linkage = checkLinkage(cfg.mcpOrigin, cfg.iiOrigin, cfg.iiOriginSource);
  const iiHealth = await checkIiHealth(
    linkage.iiOrigin,
    cfg.mcpOrigin,
    cfg.timeoutMs,
  );

  const sections = [endpoints.section, linkage.section, iiHealth.section];
  const facts = {
    mcp: endpoints.facts,
    linkage: linkage.facts,
    ii: iiHealth.facts,
  };

  return {
    generatedAt: new Date().toISOString(),
    targets: {
      mcpOrigin: cfg.mcpOrigin,
      iiOrigin: linkage.iiOrigin,
      iiOriginSource: cfg.iiOriginSource,
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
