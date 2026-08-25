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
  MIN_PUSH_INTERVAL_MS,
  componentStatusFor,
  pushComponentStatus,
  resolveStatuspageConfig,
  startStatuspagePusher,
} from "./statuspage.js";

/** Minimal report with the fields the mapping reads. */
const report = (overall, endpointStatuses = []) => ({
  overall,
  sections: [
    {
      id: "endpoints",
      title: "MCP server endpoints",
      status: endpointStatuses.includes("fail") ? "fail" : "pass",
      checks: endpointStatuses.map((status, i) => ({ id: `c${i}`, status })),
    },
  ],
});

const FULL_ENV = {
  STATUSPAGE_PAGE_ID: "kc2llmsd16bk",
  STATUSPAGE_API_KEY: "sk-test-key",
  STATUSPAGE_COMPONENT_ID: "abcdef123456",
};

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

test("componentStatusFor: every endpoint check down is a major outage", () => {
  assert.equal(
    componentStatusFor(report("fail", ["fail", "fail", "fail"])),
    "major_outage",
  );
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
    return { status: 200 };
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
});

test("pushComponentStatus throws on a non-200 without leaking details", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  await assert.rejects(
    pushComponentStatus(config, "operational", async () => ({ status: 401 })),
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
      return { status: 200 };
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
      if (!apiUp) return { status: 500 };
      pushes.push(JSON.parse(init.body).component.status);
      return { status: 200 };
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

test("pusher survives a probe failure and logs it", async () => {
  const { config } = resolveStatuspageConfig(FULL_ENV);
  const logs = [];
  const pusher = startStatuspagePusher({
    getReport: async () => {
      throw new Error("probe exploded");
    },
    config,
    fetchImpl: async () => ({ status: 200 }),
    log: (line) => logs.push(line),
  });
  pusher.stop();
  await pusher.tick();
  assert.ok(logs.some((l) => l.includes("probe exploded")));
});
