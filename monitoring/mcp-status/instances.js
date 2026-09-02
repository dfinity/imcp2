// The set of monitored instances and their cached reports.
//
// The dashboard used to hold one target and one cached report. Showing staging
// and production side by side means holding one of each per instance, with the
// same two disciplines the single cache had — a short TTL so open tabs and
// refreshes don't multiply load, and coalescing so concurrent requests share one
// probe run — now applied per instance, since each has its own probe budget and
// its own registration store being minted into.
//
// Nothing here talks to the network directly: `run` is `runDashboard` in
// production and a stub in tests, and `now` is injectable so cache ageing can be
// tested without waiting.

import { runDashboard, worstStatus } from "./checks.js";

/**
 * @typedef {import("./checks.js").DashboardReport} DashboardReport
 * @typedef {import("./config.js").Target} Target
 *
 * @typedef {DashboardReport & { name: string }} InstanceReport
 *
 * @typedef {Object} Envelope   What `/api/status` serves.
 * @property {string} generatedAt   The oldest instance report's time — every
 *   column shown is at least this fresh.
 * @property {import("./checks.js").Status} overall  Worst across instances.
 * @property {InstanceReport[]} instances  In configured order.
 */

/**
 * @param {Object} args
 * @param {Target[]} args.targets
 * @param {number} args.timeoutMs  Per-probe timeout handed to every run.
 * @param {number} [args.cacheTtlMs]  How long a report satisfies `/api/status`.
 * @param {number} [args.forceMinAgeMs]  Floor under an explicit refresh — so
 *   `?fresh=1` can't be used to hammer the monitored servers.
 * @param {typeof runDashboard} [args.run]
 * @param {() => number} [args.now]
 */
export const createInstanceReporter = ({
  targets,
  timeoutMs,
  cacheTtlMs = 15_000,
  forceMinAgeMs = 2_000,
  run = runDashboard,
  now = Date.now,
}) => {
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new Error("at least one target is required");
  }
  /**
   * @type {Map<string, { target: Target, at: number, report: DashboardReport | null,
   *   inFlight: Promise<DashboardReport> | null, pusherInFlight: Promise<DashboardReport> | null }>}
   */
  const state = new Map(
    targets.map((target) => [
      target.name,
      { target, at: 0, report: null, inFlight: null, pusherInFlight: null },
    ]),
  );
  const fresh = (s, maxAge) => s.report !== null && now() - s.at < maxAge;
  const overrides = (target) => ({
    mcpOrigin: target.mcpOrigin,
    iiOrigin: target.iiOrigin,
    timeoutMs,
  });

  /**
   * One instance's full report: cached for the TTL, coalesced while in flight.
   * Resolves to null for a name that is not configured — the caller turns that
   * into a 404, never into a probe of something a visitor named.
   *
   * @param {string} name
   * @param {boolean} [force]  Bypass the TTL (still floored and coalesced).
   * @returns {Promise<DashboardReport | null>}
   */
  const getInstanceReport = (name, force = false) => {
    const s = state.get(name);
    if (!s) return Promise.resolve(null);
    if (fresh(s, force ? forceMinAgeMs : cacheTtlMs)) {
      return Promise.resolve(s.report);
    }
    if (!s.inFlight) {
      s.inFlight = run(overrides(s.target))
        .then((report) => {
          s.at = now();
          s.report = report;
          return report;
        })
        .finally(() => {
          s.inFlight = null;
        });
    }
    return s.inFlight;
  };

  /**
   * Every instance, probed concurrently — they are different servers, so one
   * does not slow the other, and the page waits for the slowest either way.
   *
   * @param {boolean} [force]
   * @returns {Promise<Envelope>}
   */
  const getEnvelope = async (force = false) => {
    const reports = /** @type {DashboardReport[]} */ (
      await Promise.all(targets.map((t) => getInstanceReport(t.name, force)))
    );
    return {
      generatedAt: reports
        .map((r) => r.generatedAt)
        .sort()[0],
      overall: worstStatus(reports.map((r) => r.overall)),
      instances: targets.map((t, i) => ({ name: t.name, ...reports[i] })),
    };
  };

  /**
   * Report source for the Statuspage pusher, per instance. It runs unattended
   * around the clock, and the full suite's Dynamic Client Registration check
   * mints a client_id on the monitored server per run — so it reuses a recent
   * visitor-triggered report when there is one (already paid for), joins a
   * visitor run already in flight rather than doubling the load, and otherwise
   * probes with `mutating: false`. That non-mutating report is deliberately not
   * stored in the visitor cache: it lacks the two registration checks, and
   * `/api/status` promises the full suite.
   *
   * @param {string} name
   * @param {number} maxAgeMs  How recent a full report must be to be reused;
   *   also bounded by the cache TTL, so a tick never publishes state the
   *   dashboard itself already considers expired.
   * @returns {Promise<DashboardReport>}
   */
  const getPusherReport = (name, maxAgeMs) => {
    const s = state.get(name);
    if (!s) return Promise.reject(new Error(`unknown target "${name}"`));
    if (fresh(s, Math.min(maxAgeMs, cacheTtlMs))) {
      return Promise.resolve(/** @type {DashboardReport} */ (s.report));
    }
    if (s.inFlight) return s.inFlight;
    if (!s.pusherInFlight) {
      s.pusherInFlight = run({ ...overrides(s.target), mutating: false }).finally(
        () => {
          s.pusherInFlight = null;
        },
      );
    }
    return s.pusherInFlight;
  };

  return { targets, getInstanceReport, getEnvelope, getPusherReport };
};

/**
 * Which instance drives the Statuspage component. `STATUSPAGE_TARGET` names it;
 * unset, the first configured target does — which keeps a single-target
 * deployment behaving exactly as before. A name that matches nothing is a
 * warning and no pusher, not a silent fallback: a public status page fed from
 * the wrong instance is worse than one fed from none.
 *
 * @param {Target[]} targets
 * @param {Record<string, string | undefined>} [env]
 * @returns {{ name?: string, warning?: string }}
 */
export const selectPusherTarget = (targets, env = process.env) => {
  const wanted = env.STATUSPAGE_TARGET?.trim();
  if (!wanted) return { name: targets[0]?.name };
  if (targets.some((t) => t.name === wanted)) return { name: wanted };
  return {
    warning: `statuspage: pusher disabled — STATUSPAGE_TARGET "${wanted}" is not a configured target (${targets.map((t) => t.name).join(", ")})`,
  };
};
