// Configuration and target resolution for the IMCP (IC MCP) status dashboard.
//
// The dashboard is environment-agnostic: only the MCP origin is configured (by
// default the beta deployment, mcp.beta.id.ai). Which Internet Identity
// instances to probe is read from that server's own `/version`, which lists one
// entry per mount — so a deployment whose MCP origin is unrelated to its II
// hosts, or which mounts more than one II, is monitored correctly without any
// per-deployment configuration.
//
// Probe targets are fixed by the operator (CLI flags, env vars, or defaults) —
// `server.js` never takes them from an incoming request — and on top of that
// the resolved origins are validated against a host allowlist before any
// request is made. Together this prevents the dashboard from being used as a
// server-side request forgery (SSRF) proxy against arbitrary or internal hosts.

/** Default MCP server origin to monitor. */
export const DEFAULT_MCP_ORIGIN = "https://mcp.beta.id.ai";

/** Per-probe network timeout in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/** GitHub repository the MCP server is built from (for commit links). */
export const DEFAULT_REPO_URL = "https://github.com/aterga/imcp2";

/** @returns {string} the repo base URL, overridable via MCP_STATUS_REPO_URL. */
export const repoUrl = () =>
  (process.env.MCP_STATUS_REPO_URL || DEFAULT_REPO_URL).replace(/\/+$/, "");

/**
 * Build a GitHub commit URL for a commit SHA, or undefined if the value is not
 * a plausible SHA (e.g. "unknown" from a build with no commit injected).
 * @param {string | undefined} commit
 * @returns {string | undefined}
 */
export const commitUrl = (commit) =>
  typeof commit === "string" && /^[0-9a-f]{7,40}$/i.test(commit)
    ? `${repoUrl()}/commit/${commit}`
    : undefined;

/**
 * Host suffixes that may be probed. A hostname is allowed when it equals one of
 * these or ends with `.<suffix>`. The list can be extended for other
 * deployments via the `MCP_STATUS_ALLOWED_HOSTS` environment variable
 * (comma-separated), but never narrowed below the built-in id.ai domains.
 */
const DEFAULT_ALLOWED_HOST_SUFFIXES = ["id.ai"];

/** Loopback hosts allowed over http/https for local development and testing. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/** @returns {string[]} the effective list of allowed host suffixes. */
const allowedHostSuffixes = () => {
  const extra = (process.env.MCP_STATUS_ALLOWED_HOSTS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return [...DEFAULT_ALLOWED_HOST_SUFFIXES, ...extra];
};

/**
 * Whether an origin is allowed to be probed. Only https origins on the default
 * port (443) whose hostname is within the allowlist are accepted. Loopback
 * hosts are additionally allowed over http/https on any port for local
 * development. Userinfo, non-default ports (for remote hosts) and non-http
 * schemes are rejected, to keep the SSRF surface minimal.
 *
 * @param {string} origin
 * @returns {boolean}
 */
export const isAllowedOrigin = (origin) => {
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (LOOPBACK_HOSTS.has(host)) {
    return url.protocol === "http:" || url.protocol === "https:";
  }
  if (url.protocol !== "https:") return false;
  // `url.port` is "" for the default port; anything else is a non-default port.
  if (url.port !== "") return false;
  return allowedHostSuffixes().some(
    (suffix) => host === suffix || host.endsWith(`.${suffix}`),
  );
};

/**
 * Assert that an origin is allowed to be probed, throwing a sanitised,
 * non-sensitive error otherwise. The thrown error carries
 * `code === "DISALLOWED_ORIGIN"` so callers can map it to a 400 response.
 *
 * @param {string} origin
 * @returns {string} the same origin, when allowed
 */
export const assertAllowedOrigin = (origin) => {
  if (!isAllowedOrigin(origin)) {
    const err = new Error(
      `origin not allowed: ${origin}. Allowed hosts: ${allowedHostSuffixes().join(", ")} (and loopback). Extend with MCP_STATUS_ALLOWED_HOSTS.`,
    );
    // @ts-expect-error augmenting the error with a discriminator code
    err.code = "DISALLOWED_ORIGIN";
    throw err;
  }
  return origin;
};

/**
 * @typedef {Object} IiInstanceTarget
 * @property {string} name      The instance's short name ("beta", "prod", …).
 * @property {string} origin    The Internet Identity origin it hands off to.
 * @property {string | undefined} mcpPath     Mount path this instance serves.
 * @property {string | undefined} iiCanister  That II's backend canister id.
 */

/**
 * Read the II instances a server advertises at `GET /version` (its `instances`
 * array: `{name, mcp_path, ii_origin, ii_canister}` per mount).
 *
 * This replaces deriving the II origin from the MCP hostname. That derivation
 * (strip the leading `mcp.` label) encoded an assumption that only holds when
 * the MCP server is a subdomain of its II: it maps `mcp.beta.id.ai` to
 * `beta.id.ai` correctly, but maps `mcp.internetcomputer.org` to
 * `internetcomputer.org` — an unrelated marketing site that legitimately 404s
 * on `/mcp`, which read as an Internet Identity outage on a healthy
 * deployment. It was also blind by construction: one origin cannot describe a
 * server that mounts more than one II (staging serves production II at `/mcp`
 * and beta II at `/mcp-beta`), so the non-default instance went unmonitored
 * everywhere.
 *
 * Origins here come from a remote response, so each is validated against the
 * host allowlist before it can be probed — a compromised or misconfigured
 * server must not be able to steer the dashboard's probes at a third party.
 * Rejected entries are returned separately so the caller can report them
 * rather than silently monitoring less than it appears to.
 *
 * @param {unknown} raw the parsed `/version` body (or any value, defensively)
 * @returns {{ instances: IiInstanceTarget[], rejected: { name: string, origin: string, reason: string }[] }}
 */
export const parseAdvertisedInstances = (raw) => {
  /** @type {IiInstanceTarget[]} */
  const instances = [];
  /** @type {{ name: string, origin: string, reason: string }[]} */
  const rejected = [];
  const list = /** @type {any} */ (raw)?.instances;
  if (!Array.isArray(list)) return { instances, rejected };

  for (const [i, entry] of list.entries()) {
    if (!entry || typeof entry !== "object") continue;
    const rawOrigin = entry.ii_origin;
    if (typeof rawOrigin !== "string" || rawOrigin === "") continue;
    const name =
      typeof entry.name === "string" && entry.name ? entry.name : `#${i + 1}`;
    let origin;
    try {
      origin = normaliseOrigin(rawOrigin);
    } catch {
      rejected.push({ name, origin: rawOrigin, reason: "not a valid origin" });
      continue;
    }
    if (!isAllowedOrigin(origin)) {
      rejected.push({
        name,
        origin,
        reason: `host not in the probe allowlist (${allowedHostSuffixes().join(", ")})`,
      });
      continue;
    }
    instances.push({
      name,
      origin,
      mcpPath: typeof entry.mcp_path === "string" ? entry.mcp_path : undefined,
      iiCanister:
        typeof entry.ii_canister === "string" ? entry.ii_canister : undefined,
    });
  }
  return { instances, rejected };
};

/**
 * Normalise an origin string (strip trailing slash, lower-case host) or throw.
 * @param {string} value
 * @returns {string}
 */
export const normaliseOrigin = (value) => {
  const url = new URL(value);
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new Error(`Expected an origin (no path), got: ${value}`);
  }
  return url.origin;
};

/**
 * Coerce the configured per-probe timeout to a positive, finite number of
 * milliseconds: the explicit override, else MCP_STATUS_TIMEOUT_MS, else the
 * default. An unset/garbage value (e.g. "abc") would otherwise yield NaN and
 * later make AbortSignal.timeout() throw at probe time, so it falls back too.
 *
 * @param {number | undefined} override
 * @returns {number}
 */
const resolveTimeout = (override) => {
  const raw =
    override ??
    (process.env.MCP_STATUS_TIMEOUT_MS
      ? Number(process.env.MCP_STATUS_TIMEOUT_MS)
      : DEFAULT_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
};

/**
 * @typedef {Object} Target
 * @property {string} name       Short label shown on the dashboard ("staging").
 * @property {string} mcpOrigin  The MCP server origin to probe.
 * @property {string | undefined} iiOrigin  Pinned II origin, replacing the
 *   list the server advertises at /version (see resolveConfig). Per target,
 *   because the reason to pin is per deployment: production's edge currently
 *   answers /version with a redirect, so its pairing cannot be read from it.
 */

/**
 * Target names appear as column headings, in `?target=` queries and in log
 * lines, so keep them to a short, unambiguous token.
 */
const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;

/**
 * Parse a whitespace-separated list of `name=origin` entries — the shape of
 * `--target` (repeated) and of the `MCP_STATUS_TARGETS` variable, which has to
 * be readable and quotable in a systemd unit file, where JSON is not.
 *
 * Only the shape is checked here; `resolveTargets` normalises and allowlists
 * the origins. Throws on a malformed entry or a duplicate name, because a
 * dashboard quietly monitoring fewer instances than configured is the failure
 * mode a status page must not have.
 *
 * @param {string | string[] | undefined} spec
 * @returns {{ name: string, origin: string }[]}
 */
export const parseTargetList = (spec) => {
  const entries = (Array.isArray(spec) ? spec : [spec ?? ""])
    .flatMap((s) => String(s).split(/\s+/))
    .filter(Boolean);
  const seen = new Set();
  return entries.map((entry) => {
    const eq = entry.indexOf("=");
    const name = eq === -1 ? "" : entry.slice(0, eq);
    const origin = eq === -1 ? "" : entry.slice(eq + 1);
    if (!TARGET_NAME.test(name) || !origin) {
      throw new Error(
        `Invalid target "${entry}": expected name=origin, where the name is 1-32 letters, digits, "_", "." or "-"`,
      );
    }
    if (seen.has(name)) throw new Error(`Duplicate target name "${name}"`);
    seen.add(name);
    return { name, origin };
  });
};

/**
 * Resolve the set of instances to monitor.
 *
 * A target list (`targets`, from `--target`/`MCP_STATUS_TARGETS`) defines the
 * set; per-target II pins (`targetIi`, from `--target-ii`/`MCP_STATUS_TARGET_II`,
 * same `name=origin` syntax) must name a target in it. Without a list, the
 * single-target configuration `resolveConfig` has always understood
 * (`mcpOrigin`/`iiOrigin`, then `MCP_ORIGIN`/`II_ORIGIN`, then the default)
 * yields one target named after its host — so an existing deployment keeps
 * working, and shows as a one-column dashboard.
 *
 * Every origin goes through `resolveConfig`, so the allowlist applies to each
 * configured instance exactly as it did to the single one.
 *
 * @param {{ targets?: string | string[], targetIi?: string | string[], mcpOrigin?: string, iiOrigin?: string, timeoutMs?: number }} [opts]
 * @returns {{ targets: Target[], timeoutMs: number }}
 */
export const resolveTargets = (opts = {}) => {
  const present = (v) =>
    v !== undefined &&
    (Array.isArray(v) ? v.length > 0 : String(v).trim() !== "");
  const listSpec = opts.targets ?? process.env.MCP_STATUS_TARGETS;
  const pinSpec = opts.targetIi ?? process.env.MCP_STATUS_TARGET_II;
  const hasList = present(listSpec);

  if (!hasList) {
    // A pin with nothing to pin into is a misspelled or half-typed multi-target
    // invocation, not a request for the single-target fallback: honouring the
    // fallback would monitor a different pairing than the operator wrote down,
    // and look healthy doing it.
    if (present(pinSpec)) {
      throw new Error(
        "--target-ii / MCP_STATUS_TARGET_II pins an instance in a target list, but no --target / MCP_STATUS_TARGETS is set",
      );
    }
    const cfg = resolveConfig({
      mcpOrigin: opts.mcpOrigin,
      iiOrigin: opts.iiOrigin,
      timeoutMs: opts.timeoutMs,
    });
    return {
      targets: [
        {
          name: new URL(cfg.mcpOrigin).hostname,
          mcpOrigin: cfg.mcpOrigin,
          iiOrigin: cfg.iiOverride,
        },
      ],
      timeoutMs: cfg.timeoutMs,
    };
  }

  // With a list active, every single-target setting is a contradiction rather
  // than a fallback: --mcp / MCP_ORIGIN would name an instance outside the list,
  // and --ii / II_ORIGIN would pin every target that has no pin of its own to one
  // II — silently changing pairings the list spelled out. Refuse all of them, so
  // the list is the whole configuration or the process does not start.
  const legacy = [
    ["--mcp", opts.mcpOrigin],
    ["--ii", opts.iiOrigin],
    ["MCP_ORIGIN", process.env.MCP_ORIGIN],
    ["II_ORIGIN", process.env.II_ORIGIN],
  ].filter(([, v]) => present(v));
  if (legacy.length > 0) {
    throw new Error(
      `${legacy.map(([k]) => k).join(", ")} cannot be combined with --target / MCP_STATUS_TARGETS: name every instance (and its II pin) in the target list`,
    );
  }

  const list = parseTargetList(listSpec);
  const pins = new Map(parseTargetList(pinSpec).map((p) => [p.name, p.origin]));
  for (const name of pins.keys()) {
    if (!list.some((t) => t.name === name)) {
      throw new Error(`II pin for unknown target "${name}"`);
    }
  }
  // Resolved directly rather than through resolveConfig, whose env fallbacks are
  // exactly what the check above rules out; the allowlist applies just the same.
  const targets = list.map(({ name, origin }) => ({
    name,
    mcpOrigin: assertAllowedOrigin(normaliseOrigin(origin)),
    iiOrigin: pins.has(name)
      ? assertAllowedOrigin(normaliseOrigin(/** @type {string} */ (pins.get(name))))
      : undefined,
  }));
  return { targets, timeoutMs: resolveTimeout(opts.timeoutMs) };
};

/**
 * Resolve the effective configuration from explicit overrides, falling back to
 * environment variables and finally the built-in defaults. All resolved origins
 * are validated against the host allowlist.
 *
 * `iiOverride` pins the II origin to probe, replacing whatever the server
 * advertises at `/version`. It exists for the case where the advertised value
 * cannot be trusted or reached (an old build with no `instances` array, a
 * server behind a rewriting proxy); leave it unset for normal operation, where
 * the server is the authority on its own pairing.
 *
 * @param {{ mcpOrigin?: string, iiOrigin?: string, timeoutMs?: number }} [overrides]
 * @returns {{ mcpOrigin: string, iiOverride: string | undefined, timeoutMs: number }}
 */
export const resolveConfig = (overrides = {}) => {
  const mcpOrigin = assertAllowedOrigin(
    normaliseOrigin(
      overrides.mcpOrigin ?? process.env.MCP_ORIGIN ?? DEFAULT_MCP_ORIGIN,
    ),
  );

  const explicitIi = overrides.iiOrigin ?? process.env.II_ORIGIN;
  const iiOverride = explicitIi
    ? assertAllowedOrigin(normaliseOrigin(explicitIi))
    : undefined;

  return { mcpOrigin, iiOverride, timeoutMs: resolveTimeout(overrides.timeoutMs) };
};
