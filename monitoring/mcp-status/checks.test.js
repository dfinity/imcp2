// Unit tests for the IMCP status dashboard probing logic.
// Run with:  node --test monitoring/mcp-status/checks.test.js
//        or: cd monitoring/mcp-status && npm test
//
// These tests stub the global `fetch` so they make no real network calls.
// (TLS certificate inspection targets unresolvable test hostnames and so
// degrades to a "warn" without hitting the network meaningfully.)

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  worstStatus,
  isRedirect,
  parseCspDirective,
  checkMcpEndpoints,
  checkLinkage,
  checkIiHealth,
  buildSuggestions,
} from "./checks.js";
import {
  commitUrl,
  isAllowedOrigin,
  normaliseOrigin,
  parseAdvertisedInstances,
  resolveConfig,
} from "./config.js";

const byId = (section, id) => section.checks.find((c) => c.id === id);

/** Build a minimal Response-like object honouring the fields checks.js reads. */
const resp = (status, { headers = {}, body = "" } = {}) => ({
  status,
  headers: new Headers(headers),
  text: async () => body,
});

/**
 * Install a fetch stub that dispatches on "METHOD url". A route value is either a
 * `resp(...)` object or a function `(init) => resp(...)` that answers by request
 * (used to mirror the /oauth/register allow-list, which branches on the body).
 * @param {Record<string, ReturnType<typeof resp> | ((init: RequestInit) => ReturnType<typeof resp>)>} routes
 */
const stubFetch = (routes) => {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const key = `${init.method ?? "GET"} ${url.split("?")[0]}`;
    const route = routes[key];
    if (route) return typeof route === "function" ? route(init) : route;
    throw new Error(`unexpected fetch: ${key}`);
  };
  return () => {
    globalThis.fetch = original;
  };
};

/**
 * `/oauth/register` mock mirroring the hosted-redirect allow-list: a loopback
 * redirect mints a client_id (201); a non-allow-listed hosted redirect is
 * rejected (400 invalid_redirect_uri).
 */
const registerRoute = (init) => {
  const ru = (JSON.parse(init.body ?? "{}").redirect_uris ?? [])[0] ?? "";
  let loopback = false;
  try {
    const u = new URL(ru);
    // Match the server's is_loopback_redirect: http scheme, NO userinfo, and a
    // loopback HOSTNAME (so a look-alike like http://localhost.evil.com, or an
    // authority trick like http://user@127.0.0.1, is NOT loopback). URL.hostname
    // yields the bracketed [::1]; accept the bare ::1 too for robustness.
    loopback =
      u.protocol === "http:" &&
      u.username === "" &&
      u.password === "" &&
      ["localhost", "127.0.0.1", "[::1]", "::1"].includes(u.hostname);
  } catch {
    loopback = false;
  }
  return loopback
    ? resp(201, { body: JSON.stringify({ client_id: "client-123" }) })
    : resp(400, { body: JSON.stringify({ error: "invalid_redirect_uri" }) });
};

/**
 * The route table of a well-behaved server, for tests that vary one endpoint.
 * Spread `...healthyRoutes(origin)` and override the key under test.
 */
const healthyRoutes = (origin) => ({
  [`GET ${origin}/`]: resp(200, { headers: { "content-type": "text/html" } }),
  [`GET ${origin}/version`]: resp(200, {
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ version: "0.1.0", commit: "abc123def4567890" }),
  }),
  [`GET ${origin}/.well-known/oauth-protected-resource`]: resp(200, {
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      authorization_servers: [`${origin}/mcp`],
      resource: `${origin}/mcp`,
    }),
  }),
  [`GET ${origin}/.well-known/oauth-authorization-server`]: resp(200, {
    body: JSON.stringify({
      issuer: `${origin}/mcp`,
      authorization_endpoint: `${origin}/mcp/oauth/authorize`,
      token_endpoint: `${origin}/mcp/oauth/token`,
      registration_endpoint: `${origin}/mcp/oauth/register`,
      code_challenge_methods_supported: ["S256"],
    }),
  }),
  [`POST ${origin}/mcp`]: resp(401, {
    headers: {
      "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
    },
    body: JSON.stringify({ error: "invalid_token" }),
  }),
  [`POST ${origin}/mcp/oauth/register`]: registerRoute,
  [`GET ${origin}/mcp/oauth/authorize`]: resp(400, { body: "missing client_id" }),
  [`POST ${origin}/mcp/oauth/token`]: resp(400, {
    body: JSON.stringify({ error: "invalid_grant" }),
  }),
});

test("worstStatus picks the most severe status", () => {
  assert.equal(worstStatus(["pass", "pass"]), "pass");
  assert.equal(worstStatus(["pass", "warn", "pass"]), "warn");
  assert.equal(worstStatus(["warn", "fail", "pass"]), "fail");
  assert.equal(worstStatus([]), "pass");
});

test("parseCspDirective extracts a directive's sources", () => {
  const csp =
    "default-src 'none';form-action 'self' http://127.0.0.1:* https://mcp.beta.id.ai;base-uri 'none'";
  assert.deepEqual(parseCspDirective(csp, "form-action"), [
    "'self'",
    "http://127.0.0.1:*",
    "https://mcp.beta.id.ai",
  ]);
  assert.equal(parseCspDirective(csp, "missing-directive"), undefined);
  assert.equal(parseCspDirective(null, "form-action"), undefined);
});

test("parseAdvertisedInstances reads every served mount from /version", () => {
  const { instances, rejected } = parseAdvertisedInstances({
    instances: [
      {
        name: "prod",
        mcp_path: "/mcp",
        ii_origin: "https://id.ai",
        ii_canister: "rdmx6-jaaaa-aaaaa-aaadq-cai",
      },
      {
        name: "beta",
        mcp_path: "/mcp-beta",
        ii_origin: "https://beta.id.ai",
        ii_canister: "fgte5-ciaaa-aaaad-aaatq-cai",
      },
    ],
  });
  assert.deepEqual(rejected, []);
  assert.deepEqual(
    instances.map((i) => [i.name, i.mcpPath, i.origin]),
    [
      ["prod", "/mcp", "https://id.ai"],
      ["beta", "/mcp-beta", "https://beta.id.ai"],
    ],
  );
  assert.equal(instances[0].iiCanister, "rdmx6-jaaaa-aaaaa-aaadq-cai");
});

// The whole point of reading the pairing instead of deriving it: an MCP origin
// that is not a subdomain of its II. The old `strip the mcp. label` rule turned
// mcp.internetcomputer.org into internetcomputer.org, an unrelated site whose
// 404 on /mcp read as an Internet Identity outage on a healthy deployment.
test("advertised instances are unrelated to the MCP hostname", () => {
  const { instances } = parseAdvertisedInstances({
    instances: [{ name: "prod", mcp_path: "/mcp", ii_origin: "https://id.ai" }],
  });
  assert.deepEqual(
    instances.map((i) => i.origin),
    ["https://id.ai"],
  );
});

// Advertised origins come from a remote response, so the allowlist still gates
// them: a server must not be able to point these probes at a third party.
test("parseAdvertisedInstances rejects origins outside the allowlist", () => {
  const { instances, rejected } = parseAdvertisedInstances({
    instances: [
      { name: "prod", mcp_path: "/mcp", ii_origin: "https://id.ai" },
      { name: "evil", mcp_path: "/x", ii_origin: "https://attacker.example" },
      { name: "junk", mcp_path: "/y", ii_origin: "not a url" },
    ],
  });
  assert.deepEqual(
    instances.map((i) => i.name),
    ["prod"],
  );
  assert.deepEqual(
    rejected.map((r) => r.name),
    ["evil", "junk"],
  );
  assert.match(rejected[0].reason, /allowlist/);
});

test("parseAdvertisedInstances tolerates a build with no instances[]", () => {
  for (const raw of [{}, undefined, null, { instances: "nope" }]) {
    assert.deepEqual(parseAdvertisedInstances(raw), {
      instances: [],
      rejected: [],
    });
  }
});

test("commitUrl builds a GitHub link only for real SHAs", () => {
  assert.equal(
    commitUrl("abc123def4567890"),
    "https://github.com/aterga/imcp2/commit/abc123def4567890",
  );
  assert.equal(commitUrl("unknown"), undefined);
  assert.equal(commitUrl(undefined), undefined);
  assert.equal(commitUrl(""), undefined);
});

test("normaliseOrigin rejects origins with a path", () => {
  assert.equal(normaliseOrigin("https://mcp.beta.id.ai/"), "https://mcp.beta.id.ai");
  assert.throws(() => normaliseOrigin("https://mcp.beta.id.ai/mcp"));
});

test("resolveConfig leaves the II origin unset unless pinned", () => {
  const cfg = resolveConfig({ mcpOrigin: "https://mcp.beta.id.ai" });
  assert.equal(cfg.mcpOrigin, "https://mcp.beta.id.ai");
  // No derivation: the server's /version is the authority on its pairing.
  assert.equal(cfg.iiOverride, undefined);

  const pinned = resolveConfig({
    mcpOrigin: "https://mcp.beta.id.ai",
    iiOrigin: "https://beta.id.ai",
  });
  assert.equal(pinned.iiOverride, "https://beta.id.ai");
  // A pinned origin is still allowlist-checked.
  assert.throws(() =>
    resolveConfig({
      mcpOrigin: "https://mcp.beta.id.ai",
      iiOrigin: "https://attacker.example",
    }),
  );
});

test("isAllowedOrigin enforces the host allowlist (SSRF guard)", () => {
  assert.equal(isAllowedOrigin("https://mcp.beta.id.ai"), true);
  assert.equal(isAllowedOrigin("https://id.ai"), true);
  assert.equal(isAllowedOrigin("http://localhost:8080"), true);
  // Rejected: internal hosts, non-https, look-alike domains, userinfo tricks.
  assert.equal(isAllowedOrigin("http://169.254.169.254"), false);
  assert.equal(isAllowedOrigin("https://evil.com"), false);
  assert.equal(isAllowedOrigin("https://evilid.ai"), false);
  assert.equal(isAllowedOrigin("https://id.ai.evil.com"), false);
  assert.equal(isAllowedOrigin("http://mcp.beta.id.ai"), false);
  assert.equal(isAllowedOrigin("https://mcp.beta.id.ai@evil.com"), false);
  // Non-default ports are rejected for remote hosts, allowed for loopback.
  assert.equal(isAllowedOrigin("https://mcp.beta.id.ai:8443"), false);
  assert.equal(isAllowedOrigin("https://mcp.beta.id.ai:443"), true);
  assert.equal(isAllowedOrigin("http://localhost:8137"), true);
});

test("resolveConfig rejects a disallowed origin", () => {
  assert.throws(
    () => resolveConfig({ mcpOrigin: "http://169.254.169.254" }),
    (e) => e.code === "DISALLOWED_ORIGIN",
  );
});

test("checkMcpEndpoints passes for a well-behaved server", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    ...healthyRoutes(origin),
    // Carries the build and start times this test asserts on.
    [`GET ${origin}/version`]: resp(200, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        version: "0.1.0",
        commit: "abc123def4567890",
        built_at: 1_700_000_000,
        started_at: 1_700_000_500,
      }),
    }),
  });
  try {
    const { section, facts } = await checkMcpEndpoints(origin, 2000);
    assert.equal(byId(section, "root").status, "pass");
    assert.equal(byId(section, "version").status, "pass");
    assert.equal(byId(section, "protected-resource").status, "pass");
    assert.equal(byId(section, "as-metadata").status, "pass");
    assert.equal(byId(section, "metadata-consistency").status, "pass");
    assert.equal(byId(section, "mcp-challenge").status, "pass");
    assert.equal(byId(section, "oauth-register").status, "pass");
    assert.equal(byId(section, "oauth-register-allowlist").status, "pass");
    assert.equal(byId(section, "oauth-authorize").status, "pass");
    assert.equal(byId(section, "oauth-token").status, "pass");
    // Deployment facts are captured and a GitHub commit link is derived.
    assert.equal(facts.deployment.version, "0.1.0");
    assert.equal(facts.deployment.commit, "abc123def4567890");
    assert.equal(
      facts.deployment.commitUrl,
      "https://github.com/aterga/imcp2/commit/abc123def4567890",
    );
    assert.equal(facts.deployment.builtAt, 1_700_000_000);
    assert.equal(facts.deployment.startedAt, 1_700_000_500);
    // Every check carries a human-readable description.
    for (const c of section.checks) {
      assert.ok(
        typeof c.description === "string" && c.description.length > 0,
        `check ${c.id} is missing a description`,
      );
    }
  } finally {
    restore();
  }
});

// The landing page and its subpages moved off this origin — they are
// maintained in dfinity/internetcomputer-org and served at
// internetcomputer.org/icp-mcp/ — and the server answers their old paths with
// permanent redirects so published links keep working. That is the deployed
// shape, so it has to read as healthy: asserting "200 text/html" reported a
// correctly working deployment as a failing one (and pushed a partial outage to
// the public status page).
test("checkMcpEndpoints tolerates a landing page that redirects off-origin", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    ...healthyRoutes(origin),
    // The stub throws on any unexpected fetch, so this also asserts the
    // off-origin destination is reported, never requested.
    [`GET ${origin}/`]: resp(308, {
      headers: { location: "https://internetcomputer.org/icp-mcp/" },
    }),
  });
  try {
    const { section, facts } = await checkMcpEndpoints(origin, 2000);
    const root = byId(section, "root");
    assert.equal(root.status, "pass");
    assert.equal(root.httpStatus, 308);
    assert.match(root.detail, /308 → https:\/\/internetcomputer\.org\/icp-mcp\//);
    assert.equal(facts.landing.movedTo, "https://internetcomputer.org/icp-mcp/");
    assert.equal(facts.landing.servedHere, false);
    // One failing check used to sink the whole section, and with it the
    // dashboard's overall verdict. (The section still warns here: the TLS check
    // cannot reach the unresolvable test hostname.)
    assert.notEqual(section.status, "fail");
  } finally {
    restore();
  }
});

// A redirect that stays on the origin is followed to the page, so the check
// still reports what was actually served rather than the hop.
test("checkMcpEndpoints follows a same-origin landing-page redirect", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    ...healthyRoutes(origin),
    [`GET ${origin}/`]: resp(301, { headers: { location: "/landing/" } }),
    [`GET ${origin}/landing/`]: resp(200, {
      headers: { "content-type": "text/html; charset=utf-8" },
    }),
  });
  try {
    const { section, facts } = await checkMcpEndpoints(origin, 2000);
    const root = byId(section, "root");
    assert.equal(root.status, "pass");
    assert.equal(root.httpStatus, 200);
    assert.match(root.detail, /after 1 redirect/);
    assert.equal(facts.landing.servedHere, true);
  } finally {
    restore();
  }
});

// Tolerating redirects must not tolerate broken ones: a 3xx is healthy because
// it names where the page went, so one that names nothing — or names itself —
// is still a failure.
test("checkMcpEndpoints fails a landing-page redirect that goes nowhere", async () => {
  const origin = "https://mcp.beta.test";
  for (const [label, root] of [
    ["no Location header", resp(308)],
    ["a non-http Location", resp(302, { headers: { location: "mailto:a@b.c" } })],
    ["a redirect to itself", resp(308, { headers: { location: "/" } })],
    ["a 404", resp(404, { headers: { "content-type": "text/plain" } })],
  ]) {
    let rootRequests = 0;
    const restore = stubFetch({
      ...healthyRoutes(origin),
      [`GET ${origin}/`]: () => {
        rootRequests += 1;
        return root;
      },
    });
    try {
      const { section } = await checkMcpEndpoints(origin, 2000);
      assert.equal(byId(section, "root").status, "fail", label);
      assert.equal(section.status, "fail", label);
      // The self-redirect must not be chased: a URL already fetched in this
      // probe is never re-fetched, so a loop ends at the first hop.
      assert.equal(rootRequests, 1, label);
    } finally {
      restore();
    }
  }
});

// A loop closes on any URL the probe already fetched, not only on the one it
// just asked for: `/ → /landing/ → /` leads nowhere new, so the last hop naming
// a *different* URL than the one it answered does not make it a destination.
test("checkMcpEndpoints fails a multi-hop landing-page redirect loop", async () => {
  const origin = "https://mcp.beta.test";
  /** @type {Record<string, number>} */
  const fetched = { "/": 0, "/landing/": 0 };
  const restore = stubFetch({
    ...healthyRoutes(origin),
    [`GET ${origin}/`]: () => {
      fetched["/"] += 1;
      return resp(308, { headers: { location: "/landing/" } });
    },
    [`GET ${origin}/landing/`]: () => {
      fetched["/landing/"] += 1;
      return resp(308, { headers: { location: "/" } });
    },
  });
  try {
    const { section, facts } = await checkMcpEndpoints(origin, 2000);
    assert.equal(byId(section, "root").status, "fail");
    assert.equal(facts.landing.movedTo, null);
    // Each URL in the cycle is fetched once and the loop is not chased.
    assert.deepEqual(fetched, { "/": 1, "/landing/": 1 });
  } finally {
    restore();
  }
});

// Following a redirect must be visible wherever the reported result came from a
// hop, not only on the landing-page check.
test("checkMcpEndpoints reports the hop that served /version", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    ...healthyRoutes(origin),
    [`GET ${origin}/version`]: resp(307, { headers: { location: "/v1/version" } }),
    [`GET ${origin}/v1/version`]: resp(200, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ version: "0.1.0", commit: "abc123def4567890" }),
    }),
  });
  try {
    const { section } = await checkMcpEndpoints(origin, 2000);
    const version = byId(section, "version");
    assert.equal(version.status, "pass");
    assert.match(version.detail, /commit abc123def4567890 \(after 1 redirect\)/);
  } finally {
    restore();
  }
});

// A 3xx may carry a body, and may still be streaming it. Abandoning it unread
// leaves that request active — and its connection checked out — after the probe
// has returned its verdict, so a followed hop's body has to be released.
test("checkMcpEndpoints releases the body of a followed redirect", async () => {
  const origin = "https://mcp.beta.test";
  let cancelled = 0;
  const restore = stubFetch({
    ...healthyRoutes(origin),
    [`GET ${origin}/`]: {
      status: 308,
      headers: new Headers({ location: "/landing/" }),
      body: {
        cancel: async () => {
          cancelled += 1;
        },
      },
      text: async () => "",
    },
    [`GET ${origin}/landing/`]: resp(200, {
      headers: { "content-type": "text/html" },
    }),
  });
  try {
    const { section } = await checkMcpEndpoints(origin, 2000);
    assert.equal(byId(section, "root").status, "pass");
    assert.equal(cancelled, 1, "the followed hop's body must be cancelled");
  } finally {
    restore();
  }
});

// The protocol documents are a different contract: MCP clients read the status
// code itself, so a 3xx where the spec says 200 stays a finding.
test("checkMcpEndpoints does not follow redirects on the protocol documents", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    ...healthyRoutes(origin),
    [`GET ${origin}/.well-known/oauth-protected-resource`]: resp(302, {
      headers: { location: "/.well-known/oauth-protected-resource/mcp" },
    }),
  });
  try {
    const { section } = await checkMcpEndpoints(origin, 2000);
    assert.equal(byId(section, "protected-resource").status, "fail");
    assert.equal(byId(section, "protected-resource").httpStatus, 302);
  } finally {
    restore();
  }
});

test("isRedirect recognises the redirect status codes", () => {
  for (const s of [301, 302, 303, 307, 308]) assert.equal(isRedirect(s), true, `${s}`);
  for (const s of [200, 304, 400, 401, 404, 500]) assert.equal(isRedirect(s), false, `${s}`);
});

test("checkMcpEndpoints in non-mutating mode never registers a client", async () => {
  const origin = "https://mcp.beta.test";
  /** @type {string[]} */
  const registerRedirects = [];
  const restore = stubFetch({
    ...healthyRoutes(origin),
    // Records every registration attempt, so the test can assert none was made.
    [`POST ${origin}/mcp/oauth/register`]: (init) => {
      registerRedirects.push(
        (JSON.parse(init.body ?? "{}").redirect_uris ?? [])[0] ?? "",
      );
      return registerRoute(init);
    },
  });
  try {
    const { section } = await checkMcpEndpoints(origin, 2000, {
      mutating: false,
    });
    // Both registration probes are skipped: the loopback DCR probe always
    // mints, and the allow-list probe would mint whenever the server's guard
    // regressed — the rest of the suite still runs.
    assert.equal(byId(section, "oauth-register"), undefined);
    assert.equal(byId(section, "oauth-register-allowlist"), undefined);
    assert.equal(byId(section, "root").status, "pass");
    assert.equal(byId(section, "oauth-token").status, "pass");
    assert.equal(
      registerRedirects.length,
      0,
      "no registration request of any kind may be sent in non-mutating mode",
    );
  } finally {
    restore();
  }
});

test("checkMcpEndpoints flags a missing OAuth challenge", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    ...healthyRoutes(origin),
    // 200 instead of a 401 challenge → wrong contract.
    [`POST ${origin}/mcp`]: resp(200, { body: "{}" }),
  });
  try {
    const { section } = await checkMcpEndpoints(origin, 2000);
    assert.equal(byId(section, "mcp-challenge").status, "fail");
  } finally {
    restore();
  }
});

test("checkMcpEndpoints flags a missing hosted-redirect allow-list", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    ...healthyRoutes(origin),
    // Guard MISSING: the server accepts ANY redirect (even a hosted one) with 201.
    [`POST ${origin}/mcp/oauth/register`]: resp(201, {
      body: JSON.stringify({ client_id: "leaked" }),
    }),
  });
  try {
    const { section } = await checkMcpEndpoints(origin, 2000);
    // DCR still mints a client_id for the loopback probe, but the allow-list
    // probe (a hosted redirect) wrongly succeeds, so the guard check goes red.
    assert.equal(byId(section, "oauth-register").status, "pass");
    assert.equal(byId(section, "oauth-register-allowlist").status, "fail");
  } finally {
    restore();
  }
});

test("checkLinkage reports one target per advertised instance", () => {
  const { section } = checkLinkage(
    "https://mcp.internetcomputer.org",
    [
      { name: "prod", mcpPath: "/mcp", origin: "https://id.ai" },
      { name: "beta", mcpPath: "/mcp-beta", origin: "https://beta.id.ai" },
    ],
    [],
    "advertised by the server at /version",
  );
  assert.equal(section.status, "pass");
  assert.deepEqual(
    section.checks.map((c) => c.id),
    ["ii-target:prod", "ii-target:beta"],
  );
  assert.match(byId(section, "ii-target:prod").detail, /https:\/\/id\.ai/);
  // The obsolete live-discovery check is gone.
  assert.equal(byId(section, "ii-discovery"), undefined);
});

test("checkLinkage fails when the server advertises no II instance", () => {
  const { section } = checkLinkage("https://mcp.test", [], [], "n/a");
  assert.equal(section.status, "fail");
  assert.equal(byId(section, "ii-target").status, "fail");
  assert.match(byId(section, "ii-target").detail, /advertises no II instances/);
});

// A rejected origin must be visible, not silently dropped — otherwise the
// section reads as fully monitored while covering less than it claims.
test("checkLinkage surfaces advertised origins the allowlist rejected", () => {
  const { section } = checkLinkage(
    "https://mcp.test",
    [{ name: "prod", mcpPath: "/mcp", origin: "https://id.ai" }],
    [{ name: "evil", origin: "https://attacker.example", reason: "not allowed" }],
    "advertised by the server at /version",
  );
  assert.equal(section.status, "warn");
  assert.equal(byId(section, "ii-target-rejected:evil").status, "warn");
});

test("checkIiHealth verifies the /mcp delegation flow and config", async () => {
  const ii = "https://beta.test";
  const mcp = "https://mcp.beta.test";
  const restore = stubFetch({
    [`GET ${ii}/`]: resp(200, {
      headers: {
        "x-ic-canister-id": "gjxif-ryaaa-aaaad-ae4ka-cai",
        "ic-certificate": "certificate=:abc:",
        // SPA-wide form-action is tight and never lists the MCP origin (#4052).
        "content-security-policy": `default-src 'none';form-action 'self' http://127.0.0.1:*;frame-ancestors 'self' ${ii} https://beta.identity.ic0.app`,
      },
    }),
    // The /mcp connect page is served (200) — that is the whole health signal;
    // the connect flow is fetch/navigation-based, so its CSP is not asserted.
    [`GET ${ii}/mcp`]: resp(200, {
      headers: {
        "content-security-policy": `default-src 'none';form-action 'self' http://127.0.0.1:*`,
      },
    }),
    [`GET ${ii}/.config`]: resp(200, {
      headers: { "content-type": "text/plain", "content-length": "110" },
      body: `record {\n  backend_canister_id = principal "fgte5-ciaaa-aaaad-aaatq-cai";\n  related_origins = opt vec { "${ii}"; };\n}`,
    }),
  });
  try {
    const { section, facts } = await checkIiHealth(ii, mcp, 2000);
    assert.equal(byId(section, "ii-reachable").status, "pass");
    assert.equal(byId(section, "ii-certified").status, "pass");
    assert.equal(byId(section, "ii-mcp-flow").status, "pass");
    assert.equal(byId(section, "ii-config").status, "pass");
    // The obsolete mcp_server_origin checks are gone.
    assert.equal(byId(section, "ii-recognises-mcp"), undefined);
    assert.equal(byId(section, "ii-config-mcp-origin"), undefined);
    assert.equal(facts.canisterId, "gjxif-ryaaa-aaaad-ae4ka-cai");
    assert.deepEqual(facts.relatedOrigins, [ii, "https://beta.identity.ic0.app"]);
    assert.equal(facts.config.status, 200);
    assert.equal(facts.config.backendCanisterId, "fgte5-ciaaa-aaaad-aaatq-cai");
  } finally {
    restore();
  }
});

// A frontend that canonicalises /mcp to /mcp/ is serving the connect page; the
// check reads the page it lands on, not the hop.
test("checkIiHealth follows a redirect to the served /mcp connect page", async () => {
  const ii = "https://beta.test";
  const mcp = "https://mcp.beta.test";
  const restore = stubFetch({
    [`GET ${ii}/`]: resp(308, { headers: { location: "/index.html" } }),
    [`GET ${ii}/index.html`]: resp(200, {
      headers: {
        "x-ic-canister-id": "gjxif-ryaaa-aaaad-ae4ka-cai",
        "ic-certificate": "certificate=:abc:",
      },
    }),
    [`GET ${ii}/mcp`]: resp(308, { headers: { location: `${ii}/mcp/` } }),
    [`GET ${ii}/mcp/`]: resp(200),
    [`GET ${ii}/.config`]: resp(307, { headers: { location: "/.config/" } }),
    [`GET ${ii}/.config/`]: resp(200, {
      headers: { "content-type": "text/plain" },
      body: `record { backend_canister_id = principal "fgte5-ciaaa-aaaad-aaatq-cai"; }`,
    }),
  });
  try {
    const { section, facts } = await checkIiHealth(ii, mcp, 2000);
    assert.equal(byId(section, "ii-reachable").status, "pass");
    assert.match(byId(section, "ii-reachable").detail, /after 1 redirect/);
    // Headers come from the response that actually served the page.
    assert.equal(byId(section, "ii-certified").status, "pass");
    assert.equal(facts.canisterId, "gjxif-ryaaa-aaaad-ae4ka-cai");
    assert.match(byId(section, "ii-certified").detail, /after 1 redirect/);
    assert.equal(byId(section, "ii-mcp-flow").status, "pass");
    assert.match(byId(section, "ii-mcp-flow").detail, /after 1 redirect/);
    assert.equal(byId(section, "ii-config").status, "pass");
    assert.match(byId(section, "ii-config").detail, /after 1 redirect/);
    assert.equal(facts.config.backendCanisterId, "fgte5-ciaaa-aaaad-aaatq-cai");
  } finally {
    restore();
  }
});

test("checkIiHealth fails when the /mcp flow is not served", async () => {
  const ii = "https://beta.test";
  const mcp = "https://mcp.beta.test";
  const restore = stubFetch({
    [`GET ${ii}/`]: resp(200, {
      headers: {
        "content-security-policy": `form-action 'self' http://127.0.0.1:*`,
      },
    }),
    [`GET ${ii}/mcp`]: resp(404),
    [`GET ${ii}/.config`]: resp(404),
  });
  try {
    const { section } = await checkIiHealth(ii, mcp, 2000);
    assert.equal(byId(section, "ii-mcp-flow").status, "fail");
    assert.equal(byId(section, "ii-config").status, "fail");
  } finally {
    restore();
  }
});

test("checkIiHealth passes on a served /mcp even with loopback-only form-action", async () => {
  const ii = "https://beta.test";
  const mcp = "https://mcp.beta.test";
  const restore = stubFetch({
    [`GET ${ii}/`]: resp(200, {
      headers: { "content-security-policy": `form-action 'self'` },
    }),
    // /mcp is served but its form-action only allows loopback (that entry is for
    // the unrelated /cli flow). The MCP connect flow uses a top-level navigation
    // to the pinned callback page + a fetch() (connect-src), not a form POST, so a
    // tightened form-action must NOT warn — a served page is healthy.
    [`GET ${ii}/mcp`]: resp(200, {
      headers: {
        "content-security-policy": `form-action 'self' http://127.0.0.1:*`,
      },
    }),
    [`GET ${ii}/.config`]: resp(200, {
      headers: { "content-type": "text/plain" },
      body: `record { backend_canister_id = principal "fgte5-ciaaa-aaaad-aaatq-cai"; }`,
    }),
  });
  try {
    const { section } = await checkIiHealth(ii, mcp, 2000);
    assert.equal(byId(section, "ii-mcp-flow").status, "pass");
    assert.equal(byId(section, "ii-config").status, "pass");
  } finally {
    restore();
  }
});

// With more than one served instance the check ids are suffixed so the two
// sections don't collide; buildSuggestions must still match them.
test("checkIiHealth suffixes its check ids per instance", async () => {
  const ii = "https://beta.test";
  const restore = stubFetch({
    [`GET ${ii}/`]: resp(200, { headers: { "ic-certificate": "certificate=:a:" } }),
    [`GET ${ii}/mcp`]: resp(200),
    [`GET ${ii}/.config`]: resp(200, {
      headers: { "content-type": "text/plain" },
      body: `record { backend_canister_id = principal "fgte5-ciaaa-aaaad-aaatq-cai"; }`,
    }),
  });
  try {
    const { section } = await checkIiHealth(ii, "https://mcp.test", 2000, "beta");
    assert.equal(section.id, "ii-health:beta");
    assert.match(section.title, /beta/);
    assert.equal(byId(section, "ii-mcp-flow:beta").status, "pass");
    // Unsuffixed ids must NOT appear once an instance is named.
    assert.equal(byId(section, "ii-mcp-flow"), undefined);
  } finally {
    restore();
  }
});

test("buildSuggestions names which instance's /mcp flow failed", () => {
  const sections = [
    {
      id: "ii-health:beta",
      title: "",
      status: "fail",
      checks: [
        { id: "ii-mcp-flow:prod", status: "pass" },
        { id: "ii-mcp-flow:beta", status: "fail" },
      ],
    },
  ];
  const suggestions = buildSuggestions(sections, {});
  const hit = suggestions.find((s) => s.includes("/mcp"));
  assert.ok(hit, "expected a suggestion about the /mcp connect flow");
  assert.match(hit, /beta/);
  assert.doesNotMatch(hit, /prod/);
});

test("buildSuggestions surfaces a /mcp delegation flow failure", () => {
  const sections = [
    {
      id: "ii-health",
      title: "",
      status: "fail",
      checks: [{ id: "ii-mcp-flow", status: "fail" }],
    },
  ];
  const suggestions = buildSuggestions(sections, {});
  assert.ok(
    suggestions.some((s) => s.includes("/mcp")),
    "expected a suggestion about the /mcp delegation flow",
  );
});
