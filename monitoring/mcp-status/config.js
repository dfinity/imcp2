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
 * server that mounts two IIs (`/mcp` → beta, `/mcp-prod` → production), so the
 * non-default instance went unmonitored everywhere.
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

  // Coerce the configured timeout to a positive, finite number of milliseconds.
  // An unset/garbage env var (e.g. "abc") would otherwise yield NaN and later
  // make AbortSignal.timeout() throw at probe time, so fall back to the default.
  const rawTimeout =
    overrides.timeoutMs ??
    (process.env.MCP_STATUS_TIMEOUT_MS
      ? Number(process.env.MCP_STATUS_TIMEOUT_MS)
      : DEFAULT_TIMEOUT_MS);
  const timeoutMs =
    Number.isFinite(rawTimeout) && rawTimeout > 0
      ? rawTimeout
      : DEFAULT_TIMEOUT_MS;

  return { mcpOrigin, iiOverride, timeoutMs };
};
