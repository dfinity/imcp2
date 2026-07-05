// Unit tests for the CLI text rendering, focused on terminal-injection safety.
// Run with:  node --test monitoring/mcp-status/report.test.js
//        or: cd monitoring/mcp-status && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderText } from "./report.js";

/** A report whose probe-derived fields carry hostile control/ANSI/CR payloads. */
const evilReport = () => ({
  generatedAt: "2026-07-05T00:00:00.000Z",
  targets: {
    mcpOrigin: "https://mcp.example\x1b[31mSPOOF",
    iiOrigin: "https://id.example\rSPOOF",
  },
  deployment: {
    version: "1.2.3\x1b[2K",
    commit: "deadbeefcafe\rFORGED",
    commitUrl: "https://gh/x\x1b]0;title\x07",
    startedAt: undefined,
    builtAt: undefined,
  },
  overall: "fail",
  sections: [
    {
      status: "fail",
      title: "Section\x1b[1m",
      checks: [
        {
          id: "x",
          status: "fail",
          label: "Check\x1b[31m",
          target: "GET https://mcp.example",
          // The dangerous field: raw remote response bytes land here.
          detail: "200\x1b[2K\rFORGED ✔ PASS all-clear\ninjected-second-line",
          latencyMs: 12,
        },
      ],
    },
  ],
  suggestions: ["do the thing\x1b[0m\rand a forged line"],
});

test("renderText strips control/ANSI/CR from probe-derived text (CWE-150)", () => {
  const out = renderText(evilReport(), { color: false });
  // With color disabled the renderer emits no ANSI of its own, so any ESC or CR
  // in the output could only have come from unsanitized, attacker-controlled input.
  assert.ok(!out.includes("\x1b"), "ESC leaked into rendered output");
  assert.ok(!out.includes("\r"), "CR leaked into rendered output");
  assert.ok(!out.includes("\x07"), "BEL leaked into rendered output");

  // A newline embedded in `detail` must be flattened, not spawn a new line: the
  // whole payload stays on the single detail line.
  const detailLine = out.split("\n").find((l) => l.includes("FORGED"));
  assert.ok(detailLine, "detail line not found");
  assert.ok(
    detailLine.includes("injected-second-line"),
    "embedded newline should be flattened onto one line, not forge a new line",
  );
});

test("renderText still emits its own styling when color is enabled", () => {
  const out = renderText(evilReport(), { color: true });
  // Our deliberate ANSI (added after sanitization) survives...
  assert.ok(out.includes("\x1b[0m"), "expected reset codes from our own styling");
  // ...but a raw CR/BEL from the payload never does.
  assert.ok(!out.includes("\r"), "CR leaked through with color enabled");
  assert.ok(!out.includes("\x07"), "BEL leaked through with color enabled");
});
