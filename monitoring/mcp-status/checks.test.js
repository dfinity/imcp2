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
  parseCspDirective,
  checkMcpEndpoints,
  checkLinkage,
  checkIiHealth,
  buildSuggestions,
} from "./checks.js";
import {
  commitUrl,
  deriveIiOrigin,
  isAllowedOrigin,
  normaliseOrigin,
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
 * Install a fetch stub that dispatches on "METHOD url".
 * @param {Record<string, ReturnType<typeof resp>>} routes
 */
const stubFetch = (routes) => {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const key = `${init.method ?? "GET"} ${url.split("?")[0]}`;
    if (routes[key]) return routes[key];
    throw new Error(`unexpected fetch: ${key}`);
  };
  return () => {
    globalThis.fetch = original;
  };
};

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

test("deriveIiOrigin strips the mcp. label", () => {
  assert.equal(deriveIiOrigin("https://mcp.beta.id.ai"), "https://beta.id.ai");
  assert.equal(deriveIiOrigin("https://mcp.id.ai"), "https://id.ai");
  assert.equal(deriveIiOrigin("https://example.com"), undefined);
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

test("resolveConfig derives the II origin from the MCP origin", () => {
  const cfg = resolveConfig({ mcpOrigin: "https://mcp.beta.id.ai" });
  assert.equal(cfg.mcpOrigin, "https://mcp.beta.id.ai");
  assert.equal(cfg.iiOrigin, "https://beta.id.ai");
  assert.equal(cfg.iiOriginSource, "derived");
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
    [`GET ${origin}/`]: resp(200, { headers: { "content-type": "text/html" } }),
    [`GET ${origin}/version`]: resp(200, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        version: "0.1.0",
        commit: "abc123def4567890",
        built_at: 1_700_000_000,
        started_at: 1_700_000_500,
      }),
    }),
    [`GET ${origin}/.well-known/oauth-protected-resource`]: resp(200, {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        authorization_servers: [origin],
        resource: `${origin}/mcp`,
      }),
    }),
    [`GET ${origin}/.well-known/oauth-authorization-server`]: resp(200, {
      body: JSON.stringify({
        issuer: origin,
        authorization_endpoint: `${origin}/oauth/authorize`,
        token_endpoint: `${origin}/oauth/token`,
        registration_endpoint: `${origin}/oauth/register`,
        code_challenge_methods_supported: ["S256"],
      }),
    }),
    [`POST ${origin}/mcp`]: resp(401, {
      headers: {
        "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
      },
      body: JSON.stringify({ error: "invalid_token" }),
    }),
    [`POST ${origin}/oauth/register`]: resp(201, {
      body: JSON.stringify({ client_id: "client-123" }),
    }),
    [`GET ${origin}/oauth/authorize`]: resp(400, { body: "missing client_id" }),
    [`POST ${origin}/oauth/token`]: resp(400, {
      body: JSON.stringify({ error: "invalid_grant" }),
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

test("checkMcpEndpoints flags a missing OAuth challenge", async () => {
  const origin = "https://mcp.beta.test";
  const restore = stubFetch({
    [`GET ${origin}/`]: resp(200, { headers: { "content-type": "text/html" } }),
    [`GET ${origin}/version`]: resp(404),
    [`GET ${origin}/.well-known/oauth-protected-resource`]: resp(200, {
      body: JSON.stringify({ authorization_servers: [origin], resource: `${origin}/mcp` }),
    }),
    [`GET ${origin}/.well-known/oauth-authorization-server`]: resp(200, {
      body: JSON.stringify({
        issuer: origin,
        authorization_endpoint: `${origin}/oauth/authorize`,
        token_endpoint: `${origin}/oauth/token`,
        registration_endpoint: `${origin}/oauth/register`,
      }),
    }),
    // 200 instead of a 401 challenge → wrong contract.
    [`POST ${origin}/mcp`]: resp(200, { body: "{}" }),
    [`POST ${origin}/oauth/register`]: resp(201, {
      body: JSON.stringify({ client_id: "x" }),
    }),
    [`GET ${origin}/oauth/authorize`]: resp(400),
    [`POST ${origin}/oauth/token`]: resp(400, {
      body: JSON.stringify({ error: "invalid_grant" }),
    }),
  });
  try {
    const { section } = await checkMcpEndpoints(origin, 2000);
    assert.equal(byId(section, "mcp-challenge").status, "fail");
  } finally {
    restore();
  }
});

test("checkLinkage resolves the II origin without a live-discovery probe", () => {
  const { section, iiOrigin } = checkLinkage(
    "https://mcp.beta.test",
    undefined,
    "derived",
  );
  assert.equal(iiOrigin, "https://beta.test");
  assert.equal(section.status, "pass");
  // Only the target check remains; the obsolete live-discovery check is gone.
  assert.equal(section.checks.length, 1);
  assert.equal(section.checks[0].id, "ii-target");
  assert.equal(byId(section, "ii-discovery"), undefined);
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
    // The /mcp connect page relaxes form-action to allow https: callback posts.
    [`GET ${ii}/mcp`]: resp(200, {
      headers: {
        "content-security-policy": `default-src 'none';form-action 'self' https:`,
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

test("checkIiHealth warns when the /mcp form-action forbids https posts", async () => {
  const ii = "https://beta.test";
  const mcp = "https://mcp.beta.test";
  const restore = stubFetch({
    [`GET ${ii}/`]: resp(200, {
      headers: { "content-security-policy": `form-action 'self'` },
    }),
    // Page served, but form-action only allows loopback — an https callback POST
    // would be blocked, so the flow is reachable but misconfigured for remotes.
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
    assert.equal(byId(section, "ii-mcp-flow").status, "warn");
    assert.equal(byId(section, "ii-config").status, "pass");
  } finally {
    restore();
  }
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
