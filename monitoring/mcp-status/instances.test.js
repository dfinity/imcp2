// Unit tests for the per-instance reporter and the pusher's target selection.
// Run with: node --test monitoring/mcp-status/instances.test.js
//
// `run` stands in for runDashboard, so nothing here touches the network, and
// `now` is injected so cache ageing is tested by moving a clock, not by waiting.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createInstanceReporter, selectPusherTarget } from "./instances.js";

const TARGETS = [
  { name: "staging", mcpOrigin: "https://mcp.beta.test", iiOrigin: undefined },
  { name: "production", mcpOrigin: "https://mcp.test", iiOrigin: "https://ii.test" },
];

/** A report just detailed enough for the reporter: verdict, time, and echo of the run's inputs. */
const reportFor = (overrides, overall, generatedAt) => ({
  generatedAt,
  overall,
  targets: { mcpOrigin: overrides.mcpOrigin, iiOrigins: [], iiOriginSource: "" },
  deployment: {},
  sections: [],
  facts: { mutating: overrides.mutating !== false },
  suggestions: [],
});

/**
 * A fake runDashboard that records every call and answers with a configurable
 * verdict per origin. `hold` returns a run that stays pending until released,
 * for the coalescing tests.
 */
const fakeRun = (verdicts = {}) => {
  const calls = [];
  const pending = [];
  let clock = 0;
  const run = (overrides) => {
    calls.push(overrides);
    const report = reportFor(
      overrides,
      verdicts[overrides.mcpOrigin] ?? "pass",
      new Date(1_700_000_000_000 + clock++ * 1000).toISOString(),
    );
    if (run.hold) {
      return new Promise((resolve) => pending.push(() => resolve(report)));
    }
    return Promise.resolve(report);
  };
  run.hold = false;
  run.release = () => {
    for (const r of pending.splice(0)) r();
  };
  run.calls = calls;
  return run;
};

const clock = (start = 1_000_000) => {
  let t = start;
  const now = () => t;
  now.advance = (ms) => {
    t += ms;
  };
  return now;
};

test("getEnvelope probes every instance, keeps configured order, and takes the worst verdict", async () => {
  const run = fakeRun({ "https://mcp.test": "warn" });
  const reporter = createInstanceReporter({ targets: TARGETS, timeoutMs: 1234, run, now: clock() });
  const env = await reporter.getEnvelope();
  assert.deepEqual(env.instances.map((i) => i.name), ["staging", "production"]);
  assert.deepEqual(env.instances.map((i) => i.overall), ["pass", "warn"]);
  assert.equal(env.overall, "warn");
  // Each run gets that instance's own origin, pin and the shared timeout.
  assert.deepEqual(run.calls, [
    { mcpOrigin: "https://mcp.beta.test", iiOrigin: undefined, timeoutMs: 1234 },
    { mcpOrigin: "https://mcp.test", iiOrigin: "https://ii.test", timeoutMs: 1234 },
  ]);
  // The envelope is dated by its oldest column: everything shown is at least that fresh.
  assert.equal(env.generatedAt, env.instances[0].generatedAt);
  assert.ok(env.instances[0].generatedAt < env.instances[1].generatedAt);
});

test("a fail in any instance makes the envelope fail", async () => {
  const run = fakeRun({ "https://mcp.beta.test": "fail" });
  const reporter = createInstanceReporter({ targets: TARGETS, timeoutMs: 1, run, now: clock() });
  assert.equal((await reporter.getEnvelope()).overall, "fail");
});

test("reports are cached per instance for the TTL and refreshed after it", async () => {
  const run = fakeRun();
  const now = clock();
  const reporter = createInstanceReporter({
    targets: TARGETS,
    timeoutMs: 1,
    cacheTtlMs: 15_000,
    run,
    now,
  });
  await reporter.getEnvelope();
  assert.equal(run.calls.length, 2);
  now.advance(14_000);
  await reporter.getEnvelope();
  assert.equal(run.calls.length, 2, "within the TTL nothing is re-probed");
  now.advance(2_000);
  await reporter.getEnvelope();
  assert.equal(run.calls.length, 4, "past the TTL every instance is re-probed");
});

test("an explicit refresh bypasses the TTL but not the floor", async () => {
  const run = fakeRun();
  const now = clock();
  const reporter = createInstanceReporter({
    targets: TARGETS,
    timeoutMs: 1,
    cacheTtlMs: 15_000,
    forceMinAgeMs: 2_000,
    run,
    now,
  });
  await reporter.getEnvelope();
  now.advance(1_000);
  await reporter.getEnvelope(true);
  assert.equal(run.calls.length, 2, "a refresh inside the floor serves the cache");
  now.advance(1_500);
  await reporter.getEnvelope(true);
  assert.equal(run.calls.length, 4, "a refresh past the floor re-probes");
});

test("concurrent requests coalesce into one in-flight run per instance", async () => {
  const run = fakeRun();
  run.hold = true;
  const reporter = createInstanceReporter({ targets: TARGETS, timeoutMs: 1, run, now: clock() });
  const a = reporter.getEnvelope();
  const b = reporter.getEnvelope();
  const c = reporter.getInstanceReport("staging");
  assert.equal(run.calls.length, 2, "one run per instance, however many callers");
  run.release();
  const [ea, eb, rc] = await Promise.all([a, b, c]);
  assert.deepEqual(ea, eb);
  // The single-instance caller got the very same run's report.
  assert.equal(rc.generatedAt, ea.instances[0].generatedAt);
});

test("getInstanceReport answers null for a name that is not configured", async () => {
  const run = fakeRun();
  const reporter = createInstanceReporter({ targets: TARGETS, timeoutMs: 1, run, now: clock() });
  assert.equal(await reporter.getInstanceReport("nope"), null);
  assert.equal(await reporter.getInstanceReport("https://mcp.test"), null);
  assert.equal(run.calls.length, 0, "an unknown name never triggers a probe");
  const staging = await reporter.getInstanceReport("staging");
  assert.equal(staging.targets.mcpOrigin, "https://mcp.beta.test");
});

test("the pusher reuses a fresh visitor report, joins an in-flight one, and otherwise probes without mutating", async () => {
  const run = fakeRun();
  const now = clock();
  const reporter = createInstanceReporter({
    targets: TARGETS,
    timeoutMs: 1,
    cacheTtlMs: 15_000,
    run,
    now,
  });

  // Nothing cached: the pusher's own run is non-mutating and stays out of the
  // visitor cache — /api/status promises the full suite.
  const own = await reporter.getPusherReport("production", 60_000);
  assert.equal(own.facts.mutating, false);
  assert.equal(run.calls.length, 1);
  assert.deepEqual(run.calls[0], {
    mcpOrigin: "https://mcp.test",
    iiOrigin: "https://ii.test",
    timeoutMs: 1,
    mutating: false,
  });
  await reporter.getInstanceReport("production");
  assert.equal(run.calls.length, 2, "the visitor still gets a full run");
  assert.equal(run.calls[1].mutating, undefined);

  // A fresh visitor report is reused as-is.
  now.advance(5_000);
  const reused = await reporter.getPusherReport("production", 60_000);
  assert.equal(reused.facts.mutating, true);
  assert.equal(run.calls.length, 2);

  // Reuse is bounded by the cache TTL, not only by the pusher's interval.
  now.advance(11_000);
  await reporter.getPusherReport("production", 60_000);
  assert.equal(run.calls.length, 3);
  assert.equal(run.calls[2].mutating, false);

  // A visitor run already in flight is joined rather than doubled.
  now.advance(20_000);
  run.hold = true;
  const visitor = reporter.getInstanceReport("production");
  const pusher = reporter.getPusherReport("production", 60_000);
  assert.equal(run.calls.length, 4);
  run.release();
  assert.equal(await pusher, await visitor);

  // Concurrent pusher ticks share one non-mutating run.
  now.advance(20_000);
  run.hold = true;
  const t1 = reporter.getPusherReport("production", 60_000);
  const t2 = reporter.getPusherReport("production", 60_000);
  assert.equal(run.calls.length, 5);
  run.release();
  assert.equal(await t1, await t2);

  await assert.rejects(reporter.getPusherReport("nope", 60_000), /unknown target/);
});

test("createInstanceReporter refuses an empty target set", () => {
  assert.throws(() => createInstanceReporter({ targets: [], timeoutMs: 1 }), /at least one/);
});

test("selectPusherTarget defaults to the first instance and validates an explicit one", () => {
  assert.deepEqual(selectPusherTarget(TARGETS, {}), { name: "staging" });
  assert.deepEqual(selectPusherTarget(TARGETS, { STATUSPAGE_TARGET: " production " }), {
    name: "production",
  });
  const unknown = selectPusherTarget(TARGETS, { STATUSPAGE_TARGET: "prod" });
  assert.equal(unknown.name, undefined);
  assert.match(unknown.warning, /"prod" is not a configured target \(staging, production\)/);
});
