// Publish the dashboard's verdict to an Atlassian Statuspage component.
//
// status.internetcomputer.org is a hosted Atlassian Statuspage: its components
// live in the Statuspage service, not in any repository, so the way to surface
// MCP health there is to push it. This module maps a DashboardReport onto one
// Statuspage component status and PATCHes that component through the Statuspage
// REST API (https://developer.statuspage.io/) on a fixed interval, from the
// same process that already runs the probes (`server.js`).
//
// The pusher is entirely optional and off by default: it starts only when all
// three STATUSPAGE_* variables below are set, so existing deployments are
// unaffected. Pushes are change-driven — the component is PATCHed when the
// mapped status differs from the last successfully pushed one (plus once at
// startup, since a restarted process cannot know the remote state) — so a
// healthy steady state costs one API call per process lifetime, well inside
// Statuspage's rate limit of about one request per second.
//
// Configuration (environment; see also the deploy unit's EnvironmentFile):
//   STATUSPAGE_PAGE_ID           Statuspage page id (e.g. "kc2llmsd16bk").
//   STATUSPAGE_API_KEY           API key minted in the Statuspage admin. It is
//                                read from the environment (never argv, so it
//                                doesn't show in `ps`) and never logged.
//   STATUSPAGE_COMPONENT_ID      Id of the component to drive. The component
//                                itself is created once, by hand, in the
//                                Statuspage admin (e.g. "ICP MCP server").
//   STATUSPAGE_PUSH_INTERVAL_MS  Interval between checks (default 60000,
//                                floored at 15000 so a typo cannot hammer the
//                                monitored server or the Statuspage API).
//   STATUSPAGE_API_BASE          API base URL override — for tests and mocks
//                                only (default https://api.statuspage.io/v1).

/** Default Statuspage REST API base URL. */
export const DEFAULT_STATUSPAGE_API_BASE = "https://api.statuspage.io/v1";

/** Default and minimum push-loop intervals, in milliseconds. */
export const DEFAULT_PUSH_INTERVAL_MS = 60_000;
export const MIN_PUSH_INTERVAL_MS = 15_000;

/**
 * Maximum push-loop interval: Node's timers take a signed 32-bit delay, and
 * setInterval coerces anything larger to 1 ms (with a TimeoutOverflowWarning) —
 * so an uncapped oversized value would fire near-continuously, the exact
 * opposite of what the operator asked for and of the minimum-interval floor.
 */
export const MAX_PUSH_INTERVAL_MS = 2 ** 31 - 1;

/**
 * Timeout for each Statuspage API request. Without one, a stalled request
 * would keep the tick's in-flight promise pending forever — every later tick
 * joins the in-flight run rather than starting a new one, so the pusher would
 * wedge and the public component would stay stale indefinitely.
 */
export const PUSH_TIMEOUT_MS = 10_000;

/**
 * @typedef {"operational" | "degraded_performance" | "partial_outage" | "major_outage"} ComponentStatus
 *
 * @typedef {Object} StatuspageConfig
 * @property {string} pageId
 * @property {string} apiKey
 * @property {string} componentId
 * @property {string} apiBase
 * @property {number} intervalMs
 */

/**
 * Map a dashboard report onto a Statuspage component status.
 *
 * "pass" and "warn" map directly. For "fail" the severity depends on where the
 * failure is: when every check in the "endpoints" section failed, the MCP
 * server itself is down or unreachable (major outage); any other failure —
 * some endpoints broken, or a linked Internet Identity instance unhealthy —
 * degrades the service without taking it out entirely (partial outage).
 * Anything unrecognised also lands in the "fail" branch: a monitor should fail
 * loud, not quietly report green on input it doesn't understand.
 *
 * @param {import("./checks.js").DashboardReport | undefined} report
 * @returns {ComponentStatus}
 */
export const componentStatusFor = (report) => {
  if (report?.overall === "pass") return "operational";
  if (report?.overall === "warn") return "degraded_performance";
  const endpoints = Array.isArray(report?.sections)
    ? report.sections.find((s) => s?.id === "endpoints")
    : undefined;
  const allEndpointsDown =
    endpoints !== undefined &&
    Array.isArray(endpoints.checks) &&
    endpoints.checks.length > 0 &&
    endpoints.checks.every((c) => c?.status === "fail");
  return allEndpointsDown ? "major_outage" : "partial_outage";
};

// Page and component ids are URL path segments; Statuspage ids are plain
// alphanumerics. Rejecting anything else keeps a mis-pasted value (a URL, a
// quoted string) from producing a confusing request instead of a clear error.
const ID_SHAPE = /^[a-z0-9]+$/i;

/**
 * Resolve the pusher configuration from the environment.
 *
 * Returns no config (pusher off) when none of the variables are set; returns a
 * warning instead of a config when the configuration is present but unusable
 * (some variables missing, or an id that is not a plain Statuspage id), so a
 * typo shows up in the logs rather than as a silently missing status feed.
 *
 * @param {Record<string, string | undefined>} [env]
 * @returns {{ config?: StatuspageConfig, warning?: string }}
 */
export const resolveStatuspageConfig = (env = process.env) => {
  const pageId = env.STATUSPAGE_PAGE_ID?.trim() || undefined;
  const apiKey = env.STATUSPAGE_API_KEY?.trim() || undefined;
  const componentId = env.STATUSPAGE_COMPONENT_ID?.trim() || undefined;

  const missing = [
    ...(pageId ? [] : ["STATUSPAGE_PAGE_ID"]),
    ...(apiKey ? [] : ["STATUSPAGE_API_KEY"]),
    ...(componentId ? [] : ["STATUSPAGE_COMPONENT_ID"]),
  ];
  if (missing.length === 3) return {};
  if (missing.length > 0) {
    return {
      warning: `statuspage: pusher disabled — partial configuration (missing ${missing.join(", ")})`,
    };
  }
  for (const [name, value] of [
    ["STATUSPAGE_PAGE_ID", pageId],
    ["STATUSPAGE_COMPONENT_ID", componentId],
  ]) {
    if (!ID_SHAPE.test(/** @type {string} */ (value))) {
      return {
        warning: `statuspage: pusher disabled — ${name} does not look like a Statuspage id (expected letters/digits only)`,
      };
    }
  }

  // Coerce the interval like resolveConfig does for the probe timeout: garbage
  // falls back to the default, a too-small value is floored rather than
  // honoured (each cycle can trigger a full probe run against the monitored
  // server, and Statuspage rate-limits its API), and a too-large value is
  // capped below Node's 32-bit timer limit (see MAX_PUSH_INTERVAL_MS).
  const rawInterval = env.STATUSPAGE_PUSH_INTERVAL_MS
    ? Number(env.STATUSPAGE_PUSH_INTERVAL_MS)
    : DEFAULT_PUSH_INTERVAL_MS;
  const intervalMs =
    Number.isFinite(rawInterval) && rawInterval > 0
      ? Math.min(
          Math.max(rawInterval, MIN_PUSH_INTERVAL_MS),
          MAX_PUSH_INTERVAL_MS,
        )
      : DEFAULT_PUSH_INTERVAL_MS;

  const apiBase = (
    env.STATUSPAGE_API_BASE || DEFAULT_STATUSPAGE_API_BASE
  ).replace(/\/+$/, "");

  return {
    config: {
      pageId: /** @type {string} */ (pageId),
      apiKey: /** @type {string} */ (apiKey),
      componentId: /** @type {string} */ (componentId),
      apiBase,
      intervalMs,
    },
  };
};

/**
 * PATCH the component's status on Statuspage.
 *
 * Errors are thrown with the HTTP status only — never the response body, which
 * is under the remote service's control, and never anything derived from the
 * API key.
 *
 * @param {StatuspageConfig} config
 * @param {ComponentStatus} status
 * @param {typeof fetch} [fetchImpl] injectable for tests
 */
export const pushComponentStatus = async (config, status, fetchImpl = fetch) => {
  const url = `${config.apiBase}/pages/${encodeURIComponent(config.pageId)}/components/${encodeURIComponent(config.componentId)}`;
  const res = await fetchImpl(url, {
    method: "PATCH",
    headers: {
      authorization: `OAuth ${config.apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ component: { status } }),
    // Bound the request like the dashboard probes bound theirs: a stalled
    // PATCH must become a retryable error, not an eternally in-flight tick.
    signal: AbortSignal.timeout(PUSH_TIMEOUT_MS),
  });
  if (res.status !== 200) {
    throw new Error(`Statuspage API responded ${res.status}`);
  }
};

/**
 * Reduce an error to a single safe log line: message only (no stack), control
 * characters stripped (so a network error cannot forge log entries — same
 * rationale as server.js's sanitiser), capped in length, and with the API key
 * redacted should it ever leak into a message.
 *
 * @param {unknown} e
 * @param {string} apiKey
 * @returns {string}
 */
const describeError = (e, apiKey) => {
  // Redact BEFORE truncating: capping first could cut the message in the
  // middle of an embedded key, and the surviving prefix would no longer match
  // the full-key replacement below.
  const full = String((e && /** @type {any} */ (e).message) || e);
  const raw = (apiKey ? full.split(apiKey).join("[redacted]") : full).slice(
    0,
    300,
  );
  let out = "";
  for (const ch of raw) {
    const code = /** @type {number} */ (ch.codePointAt(0));
    const dangerous =
      code < 0x20 ||
      code === 0x7f ||
      (code >= 0x80 && code <= 0x9f) ||
      code === 0x2028 ||
      code === 0x2029;
    out += dangerous ? " " : ch;
  }
  return out;
};

/**
 * Start the periodic pusher. Each tick obtains a report (through the caller's
 * cached `getReport`, so ticks and dashboard visitors share probe runs), maps
 * it, and PATCHes the component only when the mapped status changed since the
 * last successful push. A failed tick — probe or API — is logged and retried
 * on the next interval; it never throws and never takes the server down. The
 * interval timer is unref'd so the pusher alone never keeps the process alive.
 *
 * @param {Object} args
 * @param {() => Promise<import("./checks.js").DashboardReport>} args.getReport
 * @param {StatuspageConfig} args.config
 * @param {typeof fetch} [args.fetchImpl]  injectable for tests
 * @param {(line: string) => void} [args.log]
 * @returns {{ stop: () => void, tick: () => Promise<void> }}
 */
export const startStatuspagePusher = ({
  getReport,
  config,
  fetchImpl = fetch,
  log = (line) => console.error(line),
}) => {
  /** @type {ComponentStatus | undefined} */
  let lastPushed;
  /** @type {Promise<void> | null} */
  let inFlight = null;

  // A slow probe or API call must not stack a second run on top of itself:
  // while one is in flight, further ticks join it instead of starting anew
  // (which also makes manual ticks in tests deterministic).
  const tick = () => {
    if (inFlight) return inFlight;
    inFlight = (async () => {
      try {
        const status = componentStatusFor(await getReport());
        if (status !== lastPushed) {
          await pushComponentStatus(config, status, fetchImpl);
          lastPushed = status;
          log(`statuspage: component ${config.componentId} -> ${status}`);
        }
      } catch (e) {
        log(
          `statuspage: push failed (will retry): ${describeError(e, config.apiKey)}`,
        );
      }
    })().finally(() => {
      inFlight = null;
    });
    return inFlight;
  };

  void tick();
  const timer = setInterval(tick, config.intervalMs);
  timer.unref?.();
  return { stop: () => clearInterval(timer), tick };
};
