// Shared log sanitisation for the IMCP status dashboard.
//
// Extracted from server.js so statuspage.js can reuse it instead of carrying
// a near-identical copy.

/**
 * Reduce a value (an Error or anything else) to a single safe log line:
 * message only (no stack), capped in length, with control characters replaced
 * by spaces so that a logged error message can never forge or inject
 * additional log entries. Covers C0 controls + DEL, the C1 controls
 * (U+0080–U+009F, incl. U+009B the 8-bit CSI), and the Unicode line/paragraph
 * separators (U+2028/U+2029). Implemented with a codepoint filter to avoid
 * embedding control-char literals.
 *
 * @param {unknown} value
 * @returns {string}
 */
export const sanitizeForLog = (value) => {
  const input = String(
    (value && /** @type {any} */ (value).message) || value,
  ).slice(0, 300);
  let out = "";
  for (const ch of input) {
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
