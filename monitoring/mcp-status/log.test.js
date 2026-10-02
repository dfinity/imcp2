// Unit tests for the shared log sanitiser.
// Run with:  node --test monitoring/mcp-status/log.test.js
//        or: cd monitoring/mcp-status && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizeForLog } from "./log.js";

test("sanitizeForLog strips control characters and separators", () => {
  // C0 (LF, CR, ESC), DEL, a C1 control (the 8-bit CSI), and the Unicode line
  // and paragraph separators - each must become a plain space. Built from
  // codepoints so the test source embeds no control-char literals (same
  // rationale as the implementation).
  const ctl = (cp) => String.fromCodePoint(cp);
  const input = [
    "a",
    ctl(0x0a),
    "b",
    ctl(0x0d),
    "c",
    ctl(0x1b),
    "d",
    ctl(0x7f),
    "e",
    ctl(0x9b),
    "f",
    ctl(0x2028),
    "g",
    ctl(0x2029),
    "h",
  ].join("");
  assert.equal(sanitizeForLog(input), "a b c d e f g h");
});

test("sanitizeForLog caps the length at 300 characters", () => {
  assert.equal(sanitizeForLog("x".repeat(500)).length, 300);
});

test("sanitizeForLog prefers an Error's message and never its stack", () => {
  assert.equal(sanitizeForLog(new Error("boom")), "boom");
});
