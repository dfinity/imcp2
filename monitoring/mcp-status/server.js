#!/usr/bin/env node
// Tiny HTTP server that hosts the IMCP status dashboard.
//
// It serves a self-contained HTML page at `/` and runs the health probes
// server-side at `/api/status`. Doing the probes server-side is what makes the
// dashboard work at all: the MCP server's `/mcp` 401 challenge, its landing
// page, and the II instance's CSP header are not CORS-readable from a browser.
//
// The instances to probe are fixed by the operator when the server is started —
// named targets via `--target name=origin` (repeatable) or MCP_STATUS_TARGETS,
// with optional per-target II pins via `--target-ii name=origin` or
// MCP_STATUS_TARGET_II; or the single-target `--mcp`/`--ii` flags and
// MCP_ORIGIN/II_ORIGIN variables, which yield one instance named after its
// host. They are deliberately NOT taken from the incoming request: a hosted
// status page must never let a visitor steer server-side requests at arbitrary
// hosts. `?target=<name>` selects among the configured instances only.
//
// Usage:
//   node monitoring/mcp-status/server.js [--port 8080] [--host 127.0.0.1] \
//     --target staging=https://mcp.beta.id.ai \
//     --target production=https://mcp.internetcomputer.org --target-ii production=https://id.ai
//   node monitoring/mcp-status/server.js --mcp <origin> [--ii <origin>]
//
// Binds to 127.0.0.1 by default so the probe endpoint is not directly exposed;
// front it with a TLS reverse proxy (e.g. Caddy) to publish it.

import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { resolveTargets } from "./config.js";
import { createInstanceReporter, selectPusherTarget } from "./instances.js";
import { sanitizeForLog } from "./log.js";
import {
  resolveStatuspageConfig,
  startStatuspagePusher,
} from "./statuspage.js";

const here = dirname(fileURLToPath(import.meta.url));

const DEFAULT_PORT = 8080;
const parsePort = () => {
  const idx = process.argv.indexOf("--port");
  const raw = idx !== -1 ? process.argv[idx + 1] : process.env.PORT;
  if (raw === undefined || raw === "") return DEFAULT_PORT;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    process.stderr.write(
      `Invalid port value; falling back to ${DEFAULT_PORT}\n`,
    );
    return DEFAULT_PORT;
  }
  return port;
};
const argValue = (flag) => {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 ? process.argv[idx + 1] : undefined;
};
/** Every value following a repeatable flag, in order. */
const argValues = (flag) =>
  process.argv.flatMap((a, i) => (a === flag ? [process.argv[i + 1]] : []));

// Resolve — and allowlist-check — every instance before listening, so a
// misconfigured target is a clear startup failure rather than a 400 on every
// request for the lifetime of the process.
let targets;
let timeoutMs;
try {
  const targetFlags = argValues("--target");
  const pinFlags = argValues("--target-ii");
  ({ targets, timeoutMs } = resolveTargets({
    targets: targetFlags.length ? targetFlags : undefined,
    targetIi: pinFlags.length ? pinFlags : undefined,
    mcpOrigin: argValue("--mcp"),
    iiOrigin: argValue("--ii"),
  }));
} catch (e) {
  process.stderr.write(`mcp-status: ${e?.message ?? e}\n`);
  process.exit(2);
}

// `/api/status` runs the full probe suite — which includes a dynamic OAuth
// client registration against each monitored server — so re-running it on
// every request (multiple open tabs, rapid refreshes, a publicly reachable URL)
// would multiply load and mint a fresh client each time. The reporter caches
// each instance's most recent report for a short TTL and coalesces concurrent
// requests into a single in-flight run per instance; an explicit refresh
// (`?fresh=1`) bypasses the TTL but never re-probes past a short floor.
const ttlEnv = Number(process.env.MCP_STATUS_CACHE_TTL_MS);
const reporter = createInstanceReporter({
  targets,
  timeoutMs,
  cacheTtlMs: Number.isFinite(ttlEnv) && ttlEnv > 0 ? ttlEnv : 15_000,
  forceMinAgeMs: 2_000,
});

const sendJson = (res, code, body) => {
  const payload = JSON.stringify(body);
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
};

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (url.pathname === "/" || url.pathname === "/index.html") {
      const html = await readFile(join(here, "public", "index.html"));
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      });
      res.end(html);
      return;
    }

    if (url.pathname === "/api/status") {
      // `?fresh=1` only controls caching and `?target=` only selects among the
      // instances fixed at startup, so neither widens the SSRF surface.
      const force = url.searchParams.get("fresh") === "1";
      const target = url.searchParams.get("target");
      if (target !== null) {
        // One instance, in the single-report shape the dashboard has always
        // served — for an uptime monitor that watches one deployment.
        const report = await reporter.getInstanceReport(target, force);
        if (!report) {
          sendJson(res, 404, { error: "unknown target" });
          return;
        }
        sendJson(res, report.overall === "fail" ? 503 : 200, report);
        return;
      }
      const envelope = await reporter.getEnvelope(force);
      // 503 when ANY instance fails: the page as a whole is then reporting an
      // outage, and a monitor watching this URL should see it as one.
      sendJson(res, envelope.overall === "fail" ? 503 : 200, envelope);
      return;
    }

    sendJson(res, 404, { error: "not found" });
  } catch (e) {
    // A misconfigured target is a client/operator error with a fixed, safe
    // message; any other failure is logged (sanitised) server-side and reported
    // generically so that no stack-trace or internal detail leaks to clients.
    if (e && e.code === "DISALLOWED_ORIGIN") {
      sendJson(res, 400, { error: "invalid or disallowed origin" });
    } else {
      console.error("mcp-status: request failed:", sanitizeForLog(e));
      sendJson(res, 500, { error: "internal error" });
    }
  }
});

const port = parsePort();
// Default to loopback: behind a reverse proxy (the intended deployment) the
// dashboard should not be reachable directly. Override with --host/MCP_STATUS_HOST
// (e.g. 0.0.0.0) only when binding all interfaces is genuinely wanted.
const host = argValue("--host") ?? process.env.MCP_STATUS_HOST ?? "127.0.0.1";
server.listen(port, host, () => {
  process.stdout.write(
    `IMCP status dashboard listening on http://${host}:${port}\n` +
      targets
        .map(
          (t) =>
            `  monitoring ${t.name}: ${t.mcpOrigin}` +
            (t.iiOrigin ? ` (II pinned to ${t.iiOrigin})` : ""),
        )
        .join("\n") +
      "\n",
  );
});

// Optionally mirror one instance's verdict to an Atlassian Statuspage component
// (e.g. on status.internetcomputer.org). Off unless the STATUSPAGE_* variables
// are set — see statuspage.js and the README. STATUSPAGE_TARGET names the
// instance that drives the component (default: the first configured). The
// pusher reuses a recent visitor-triggered report when one exists and otherwise
// probes without the state-mutating registration checks (see instances.js), so
// it never registers OAuth clients on its own.
const { config: statuspageConfig, warning: statuspageWarning } =
  resolveStatuspageConfig();
if (statuspageWarning) console.error(statuspageWarning);
if (statuspageConfig) {
  const { name: pushTarget, warning: targetWarning } = selectPusherTarget(targets);
  if (targetWarning) {
    console.error(targetWarning);
  } else {
    startStatuspagePusher({
      getReport: () =>
        reporter.getPusherReport(
          /** @type {string} */ (pushTarget),
          statuspageConfig.intervalMs,
        ),
      config: statuspageConfig,
    });
    process.stdout.write(
      `  statuspage: pushing ${pushTarget} to component ${statuspageConfig.componentId} ` +
        `(page ${statuspageConfig.pageId}) every ${statuspageConfig.intervalMs} ms\n`,
    );
  }
}
