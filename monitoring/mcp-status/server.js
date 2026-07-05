#!/usr/bin/env node
// Tiny HTTP server that hosts the IMCP status dashboard.
//
// It serves a self-contained HTML page at `/` and runs the health probes
// server-side at `/api/status`. Doing the probes server-side is what makes the
// dashboard work at all: the MCP server's `/mcp` 401 challenge, its landing
// page, and the II instance's CSP header are not CORS-readable from a browser.
//
// The probe targets are fixed by the operator when the server is started — via
// the defaults, `--mcp`/`--ii` flags, or the MCP_ORIGIN/II_ORIGIN env vars —
// and are deliberately NOT taken from the incoming request. A hosted status
// page must never let a visitor steer server-side requests at arbitrary hosts.
//
// Usage:
//   node monitoring/mcp-status/server.js [--port 8080] [--host 127.0.0.1] [--mcp <origin>] [--ii <origin>]
//
// Binds to 127.0.0.1 by default so the probe endpoint is not directly exposed;
// front it with a TLS reverse proxy (e.g. Caddy) to publish it.

import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runDashboard } from "./checks.js";

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

const defaults = {
  mcpOrigin: argValue("--mcp"),
  iiOrigin: argValue("--ii"),
};

// `/api/status` runs the full probe suite — which includes a dynamic OAuth
// client registration against the monitored server — so re-running it on every
// request (multiple open tabs, rapid refreshes, a publicly reachable URL) would
// multiply load and mint a fresh client each time. Cache the most recent report
// for a short TTL and coalesce concurrent requests into a single in-flight run.
const ttlEnv = Number(process.env.MCP_STATUS_CACHE_TTL_MS);
const CACHE_TTL_MS = Number.isFinite(ttlEnv) && ttlEnv > 0 ? ttlEnv : 15_000;
// An explicit refresh (`?fresh=1`) bypasses the TTL so the button feels live,
// but never re-probes more often than this floor — so it can't be used to hammer
// the monitored server (each run includes a dynamic client registration).
const FORCE_MIN_AGE_MS = 2_000;
/** @type {{ at: number, report: import("./checks.js").DashboardReport | null }} */
let cache = { at: 0, report: null };
/** @type {Promise<import("./checks.js").DashboardReport> | null} */
let inFlight = null;

/** @param {boolean} [force] bypass the normal TTL (still rate-floored + coalesced). */
const getReport = (force = false) => {
  const maxAge = force ? FORCE_MIN_AGE_MS : CACHE_TTL_MS;
  if (cache.report && Date.now() - cache.at < maxAge) {
    return Promise.resolve(cache.report);
  }
  if (!inFlight) {
    inFlight = runDashboard(defaults)
      .then((report) => {
        cache = { at: Date.now(), report };
        return report;
      })
      .finally(() => {
        inFlight = null;
      });
  }
  return inFlight;
};

const sendJson = (res, code, body) => {
  const payload = JSON.stringify(body);
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
};

// Replace control characters with spaces and cap the length, so that a logged
// error message can never forge or inject additional log entries. Covers C0
// controls + DEL, the C1 controls (U+0080–U+009F, incl. U+009B the 8-bit CSI),
// and the Unicode line/paragraph separators (U+2028/U+2029). Implemented with a
// codepoint filter to avoid embedding control-char literals.
const sanitizeForLog = (value) => {
  const input = String((value && value.message) || value).slice(0, 300);
  let out = "";
  for (const ch of input) {
    const code = ch.codePointAt(0);
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
      // `?fresh=1` only controls caching, never the probe target, so it does not
      // widen the SSRF surface (the target stays fixed at startup).
      const force = url.searchParams.get("fresh") === "1";
      const report = await getReport(force);
      sendJson(res, report.overall === "fail" ? 503 : 200, report);
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
      `  monitoring: ${defaults.mcpOrigin ?? "https://mcp.beta.id.ai (default)"}\n`,
  );
});
