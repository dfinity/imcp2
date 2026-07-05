// Unit tests for the CLI text rendering, focused on terminal-injection safety.
// Run with:  node --test monitoring/mcp-status/report.test.js
//        or: cd monitoring/mcp-status && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderText } from "./report.js";

// Dangerous characters, referenced by escape so the source stays printable:
//   ESC (C0), CR (C0), BEL (C0), U+009B (C1 8-bit CSI), U+2028/U+2029 (Unicode
//   line / paragraph separators). All can move the cursor or begin a new line.
const ESC = "\x1b";
const CR = "\r";
const BEL = "\x07";
const C1_CSI = "";
const LINE_SEP = " ";
const PARA_SEP = " ";

/** A report whose probe-derived fields carry hostile control/ANSI payloads. */
const evilReport = () => ({
  generatedAt: "2026-07-05T00:00:00.000Z",
  targets: {
    mcpOrigin: `https://mcp.example${ESC}[31mSPOOF`,
    iiOrigin: `https://id.example${CR}SPOOF`,
  },
  deployment: {
    version: `1.2.3${ESC}[2K`,
    commit: `deadbeefcafe${CR}FORGED`,
    commitUrl: `https://gh/x${ESC}]0;title${BEL}`,
    startedAt: undefined,
    builtAt: undefined,
  },
  overall: "fail",
  sections: [
    {
      status: "fail",
      title: `Section${ESC}[1m`,
      checks: [
        {
          id: "x",
          status: "fail",
          label: `Check${ESC}[31m`,
          target: "GET https://mcp.example",
          // The dangerous field: raw remote response bytes land here. Mixes an
          // ESC-based CSI, an 8-bit C1 CSI, and both Unicode separators.
          detail: `200${ESC}[2K${CR}FORGED${C1_CSI}[31m PASS all-clear${LINE_SEP}sneaky${PARA_SEP}line\ninjected-second-line`,
          latencyMs: 12,
        },
      ],
    },
  ],
  suggestions: [`do the thing${ESC}[0m${CR}and a forged line`],
});

test("renderText strips control/ANSI/CR from probe-derived text (CWE-150)", () => {
  const out = renderText(evilReport(), { color: false });
  // With color disabled the renderer emits no ANSI of its own, so any control
  // char in the output could only have come from unsanitized attacker input.
  assert.ok(!out.includes(ESC), "ESC leaked into rendered output");
  assert.ok(!out.includes(CR), "CR leaked into rendered output");
  assert.ok(!out.includes(BEL), "BEL leaked into rendered output");
  assert.ok(!out.includes(C1_CSI), "C1 CSI (U+009B) leaked into rendered output");
  assert.ok(!out.includes(LINE_SEP), "line separator (U+2028) leaked into output");
  assert.ok(!out.includes(PARA_SEP), "paragraph separator (U+2029) leaked into output");

  // The embedded newline AND the Unicode separators must be flattened, not spawn
  // new lines: the whole payload stays on one rendered detail line.
  const payloadLines = out
    .split("\n")
    .filter((l) => /FORGED|injected-second-line|sneaky/.test(l));
  assert.equal(payloadLines.length, 1, "payload must render on a single line");
  assert.ok(
    payloadLines[0].includes("injected-second-line"),
    "embedded newline should be flattened onto one line",
  );
  assert.ok(payloadLines[0].includes("sneaky"), "embedded separators should be flattened");
});

test("renderText still emits its own styling when color is enabled", () => {
  const out = renderText(evilReport(), { color: true });
  // Our deliberate ANSI (added after sanitization) survives...
  assert.ok(out.includes(`${ESC}[0m`), "expected reset codes from our own styling");
  // ...but a raw CR/BEL/C1 from the payload never does.
  assert.ok(!out.includes(CR), "CR leaked through with color enabled");
  assert.ok(!out.includes(BEL), "BEL leaked through with color enabled");
  assert.ok(!out.includes(C1_CSI), "C1 CSI leaked through with color enabled");
});
