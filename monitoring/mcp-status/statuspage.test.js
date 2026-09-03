// Unit tests for the Statuspage pusher.
// Run with:  node --test monitoring/mcp-status/statuspage.test.js
//        or: cd monitoring/mcp-status && npm test
//
// These tests inject a stubbed `fetch`, so they make no real network calls.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_PUSH_INTERVAL_MS,
  DEFAULT_STATUSPAGE_API_BASE,
  MAX_PUSH_INTERVAL_MS,
  MIN_PUSH_INTERVAL_MS,
  componentStatusFor,
  pushComponentStatus,
  resolveStatuspageConfig,
  startStatuspagePusher,
} from "./statuspage.js";

/**
 * Minimal report with the fields the mapping reads. Statuses are assigned to
 * real service-availability check ids from checks.js, since the mapping keys
 * the major-outage decision on that explicit set.
 */
const AVAILABILITY_IDS = [
  "root",
  "protected-resource",
  "as-metadata",
  "mcp-challenge",
  "oauth-register",
  "oauth-register-allowlist",
  "oauth-authorize",
  "oauth-token",
];
const report = (overall, endpointStatuses = []) => ({
  overall,
  sections: [
    {
      id: "endpoints",
      title: "MCP server endpoints",
      status: endpointStatuses.includes("fail") ? "fail" : "pass",
      checks: endpointStatuses.map((status, i) => ({
        id: AVAILABILITY_IDS[i] ?? `c${i}`,
        status,
      })),
    },
  ],
});

/**
 * What the endpoints section actually looks like when the server is entirely
 * unreachable: every availability probe fails, but the auxiliary checks do NOT
 * — `metadata-consistency` degrades to "warn", and `mcp-tls` can stay "pass"
 * (a healthy reverse proxy fronting a dead application).
 */
const totalOutageReport = () => ({
  overall: "fail",
  sections: [
    {
      id: "endpoints",
      title: "MCP server endpoints",
      status: "fail",
      checks: [
        ...AVAILABILITY_IDS.map((id) => ({ id, status: "fail" })),
        { id: "metadata-consistency", status: "warn" },
        { id: "mcp-tls", status: "pass" },
      ],
    },
  ],
});

const FULL_ENV = {
  STATUSPAGE_PAGE_ID: "kc2llmsd16bk",
  STATUSPAGE_API_KEY: "sk-test-key",
  STATUSPAGE_COMPONENT_ID: "abcdef123456",
};

/** Response-like stub carrying the fields pushComponentStatus reads. */
const httpRes = (status, extra = {}) => ({
  status,
  ok: status >= 200 && status < 300,
  ...extra,
});

test("componentStatusFor maps the overall verdict", () => {
  assert.equal(componentStatusFor(report("pass")), "operational");
  assert.equal(componentStatusFor(report("warn")), "degraded_performance");
});

test("componentStatusFor: a partial endpoint failure is a partial outage", () => {
  assert.equal(
    componentStatusFor(report("fail", ["pass", "fail", "pass"])),
    "partial_outage",
  );
});

test("componentStatusFor: every availability check down is a major outage", () => {
  assert.equal(
    componentStatusFor(report("fail", ["fail", "fail", "fail"])),
    "major_outage",
  );
});

test("componentStatusFor: a realistic total outage is a major outage", () => {
  // Auxiliary checks (metadata-consistency, mcp-tls) do not fail when the
  // server is unreachable; they must not veto the major-outage verdict.
  assert.equal(componentStatusFor(totalOutageReport()), "major_outage");
});

test("componentStatusFor: a non-endpoint failure is a partial outage", () => {
  // Overall "fail" caused by another section (e.g. linked II unhealthy):
  // the endpoints section itself is green.
  assert.equal(
    componentStatusFor(report("fail", ["pass", "pass"])),
    "partial_outage",
  );
});

test("componentStatusFor fails loud on unrecognised input", () => {
  assert.equal(componentStatusFor(undefined), "partial_outage");
  assert.equal(
    componentStatusFor(/** @type {any} */ ({ overall: "bogus" })),
    "partial_outage",
  );
});

test("resolveStatuspageConfig: unset env means pusher off, silently", () => {
  assert.deepEqual(resolveStatuspageConfig({}), {});
});

test("resolveStatuspageConfig: only optional variables set warns and stays off", () => {
  // Silence is reserved for a completely unset configuration: setting only an
  // optional variable signals intent to run the pusher and must be diagnosable.
  const { config, warning } = resolveStatuspageConfig({
    STATUSPAGE_PUSH_INTERVAL_MS: "30000",
  });
  assert.equal(config, undefined);
  assert.match(warning, /STATUSPAGE_PUSH_INTERVAL_MS/);
  assert.match(warning, /STATUSPAGE_PAGE_ID/);
  assert.match(warning, /STATUSPAGE_API_KEY/);
  assert.match(warning, /STATUSPAGE_COMPONENT_ID/);
});

test("resolveStatuspageConfig: partial config warns and stays off", () => {
  const { config, warning } = resolveStatuspageConfig({
    STATUSPAGE_PAGE_ID: "kc2llmsd16bk",
  });
  assert.equal(config, undefined);
  assert.match(warning, /STATUSPAGE_API_KEY/);
  assert.match(warning, /STATUSPAGE_COMPONENT_ID/);
  assert.doesNotMatch(warning, /STATUSPAGE_PAGE_ID/);
});

test("resolveStatuspageConfig: full config resolves with defaults", () => {
  const { config, warning } = resolveStatuspageConfig(FULL_ENV);
  assert.equal(warning, undefined);
  assert.deepEqual(config, {
    pageId: "kc2llmsd16bk",
    apiKey: "sk-test-key",
    componentId: "abcdef123456",
    apiBase: DEFAULT_STATUSPAGE_API_BASE,
    intervalMs: DEFAULT_PUSH_INTERVAL_MS,
  });
});

test("resolveStatuspageConfig: interval is floored and garbage falls back", () => {
  const floored = resolveStatuspageConfig({
    ...FULL_ENV,
    STATUSPAGE_PUSH_INTERVAL_MS: "1000",
  });
  assert.equal(floored.config?.intervalMs, MIN_PUSH_INTERVAL_MS);
  const garbage = resolveStatuspageConfig({
    ...FULL_ENV,
    STATUSPAGE_PUSH_INTERVAL_MS: "abc",
  });
  assert.equal(garbage.config?.intervalMs, DEFAULT_PUSH_INTERVAL_MS);
});

test("resolveStatuspageConfig: an oversized interval is capped, not overflowed", () => {
  // Node's setInterval coerces delays above 2^31-1 ms to 1 ms, which would turn
  // a mistyped huge interval into near-continuous probing.
  const { config } = resolveStatuspageConfig({
    ...FULL_ENV,
    STATUSPAGE_PUSH_INTERVAL_MS: "9999999999999",
  });
  assert.equal(config?.intervalMs, MAX_PUSH_INTERVAL_MS);
});

test("resolveStatuspageConfig: a non-id value warns and stays off", () => {
  const { config, warning } = resolveStatuspageConfig({
    ...FULL_ENV,
    STATUSPAGE_COMPONENT_ID: "https://example.com/x",
  });
  assert.equal(config, undefined);
  assert.match(warning, /STATUSPAGE_COMPONENT_ID/);
});

test("pushComponentStatus PATCHes the component with the OAuth header", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  /** @type {{ url: string, init: RequestInit }[]} */
  const calls = [];
  await pushComponentStatus(config, "operational", async (url, init) => {
    calls.push({ url, init });
    return httpRes(200);
  });
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    `${DEFAULT_STATUSPAGE_API_BASE}/pages/kc2llmsd16bk/components/abcdef123456`,
  );
  assert.equal(calls[0].init.method, "PATCH");
  assert.equal(calls[0].init.headers.authorization, "OAuth sk-test-key");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    component: { status: "operational" },
  });
  // A stalled request must abort rather than pin the tick in flight forever.
  assert.ok(calls[0].init.signal instanceof AbortSignal);
});

test("pushComponentStatus discards the response body on success and error", async () => {
  // Node's fetch keeps the connection tied to an unread body until GC, so the
  // pusher must cancel it — including on error responses, which are the ones
  // that would be retried (and so accumulate) every interval.
  const { config } = resolveStatuspageConfig(FULL_ENV);
  const bodyRes = (status) => {
    const res = httpRes(status, { cancelled: 0 });
    res.body = {
      cancel: async () => {
        res.cancelled += 1;
      },
    };
    return res;
  };
  const ok = bodyRes(200);
  await pushComponentStatus(config, "operational", async () => ok);
  assert.equal(ok.cancelled, 1);
  const err = bodyRes(500);
  await assert.rejects(
    pushComponentStatus(config, "operational", async () => err),
  );
  assert.equal(err.cancelled, 1);
});

test("pushComponentStatus accepts any 2xx, not just 200", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  await pushComponentStatus(config, "operational", async () => httpRes(204));
});

test("pushComponentStatus throws on a non-2xx without leaking details", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  await assert.rejects(
    pushComponentStatus(config, "operational", async () => httpRes(401)),
    (e) => {
      assert.match(e.message, /401/);
      assert.doesNotMatch(e.message, /sk-test-key/);
      return true;
    },
  );
});

test("pusher pushes on change only, and once at startup", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  const reports = [report("pass"), report("pass"), report("warn")];
  let pushes = [];
  const pusher = startStatuspagePusher({
    getReport: async () => reports.shift(),
    config,
    fetchImpl: async (_url, init) => {
      pushes.push(JSON.parse(init.body).component.status);
      return httpRes(200);
    },
    log: () => {},
  });
  pusher.stop();
  // The constructor fires the first tick; awaiting tick() joins it while it is
  // in flight, so drive the sequence with three awaited ticks.
  await pusher.tick(); // joins the startup tick ("pass") — first push
  await pusher.tick(); // "pass" again — no push
  await pusher.tick(); // "warn" — pushes the change
  assert.deepEqual(pushes, ["operational", "degraded_performance"]);
});

test("pusher retries after a failed push instead of marking it done", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  let apiUp = false;
  const pushes = [];
  const logs = [];
  const pusher = startStatuspagePusher({
    getReport: async () => report("pass"),
    config,
    fetchImpl: async (_url, init) => {
      if (!apiUp) return httpRes(500);
      pushes.push(JSON.parse(init.body).component.status);
      return httpRes(200);
    },
    log: (line) => logs.push(line),
  });
  pusher.stop();
  await pusher.tick(); // API still down: logged, not thrown, not recorded
  assert.equal(pushes.length, 0);
  assert.ok(logs.some((l) => l.includes("push failed")));
  assert.ok(!logs.some((l) => l.includes("sk-test-key")));
  apiUp = true;
  await pusher.tick(); // same status as the failed attempt: must push now
  assert.deepEqual(pushes, ["operational"]);
});

test("pusher redacts the API key even when it straddles the log cap", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  const logs = [];
  const pusher = startStatuspagePusher({
    getReport: async () => {
      // Place the key across the 300-character truncation boundary: with 290
      // prefix characters the 11-character key occupies indices 290-300, so
      // truncating BEFORE redacting would leave the unmatchable 10-character
      // prefix "sk-test-ke" in the log. (289 would let the whole key fit
      // inside slice(0, 300), and the vulnerable ordering would pass too.)
      throw new Error("x".repeat(290) + "sk-test-key trailing");
    },
    config,
    fetchImpl: async () => httpRes(200),
    log: (line) => logs.push(line),
  });
  pusher.stop();
  await pusher.tick();
  assert.equal(logs.length, 1);
  assert.ok(!logs[0].includes("sk-t"));
  assert.ok(logs[0].includes("[redacted]"));
});

test("pusher survives a probe failure and logs it", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  const logs = [];
  const pusher = startStatuspagePusher({
    getReport: async () => {
      throw new Error("probe exploded");
    },
    config,
    fetchImpl: async () => httpRes(200),
    log: (line) => logs.push(line),
  });
  pusher.stop();
  await pusher.tick();
  assert.ok(logs.some((l) => l.includes("probe exploded")));
});
