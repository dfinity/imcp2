//! The direct canister-call layer: `get_candid` (read a canister's Candid
//! interface) and `call_canister` (invoke a method with textual Candid in and
//! out). The LLM only ever deals with textual Candid — the binary
//! encoding/decoding against a method's declared types happens here, and the
//! `.did` interface is resolved from the canister's own `candid:service`
//! metadata (or a caller-supplied definition).
//!
//! The `#[tool]` entry points live on `IcTools` in `main.rs` (they need the
//! agent, identities, and request context); this module owns their argument and
//! output types plus the pure encode/decode/call helpers they delegate to.

use candid::{types::value::IDLArgs, Principal};
use ic_agent::Agent;
// rmcp re-exports schemars 1.x; the `#[tool]` output-schema machinery requires
// THAT version's `JsonSchema`, so derive the MCP types against it.
use rmcp::schemars;
use serde::{Deserialize, Serialize};

// ===========================================================================
// MCP-facing argument and output types (textual in, textual out — the LLM
// never touches binary Candid).
// ===========================================================================

/// Arguments for `get_candid`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetCandidArgs {
    /// Canister principal, e.g. "ryjl3-tyaaa-aaaaa-aaaba-cai" (the ICP ledger).
    pub canister_id: String,
}

/// Output of `get_candid`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct GetCandidOutput {
    /// The canister whose interface was read.
    pub canister_id: String,
    /// The Candid (`.did`) interface text.
    pub candid: String,
    /// True when the interface exposes the standard OQL query surface (both a
    /// `schema` and an `execute` method). When set, load `get_oql_guide` (or the
    /// `oql://usage` resource) to learn the JSON query dialect before querying.
    pub oql: bool,
}

/// Output of `get_oql_guide`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct OqlGuideOutput {
    /// The OQL usage guide (markdown): the `schema`/`execute` methods, the JSON
    /// query object, the predicate grammar, edges, and the result shape.
    pub content: String,
}

/// Arguments for `call_canister`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CallCanisterArgs {
    /// Target canister principal.
    pub canister_id: String,
    /// Method name to invoke.
    pub method: String,
    /// Arguments in textual Candid syntax, e.g. `()` or `(record { owner = principal "..." })`.
    #[serde(default = "default_args")]
    pub args: String,
    /// If true, perform a read-only `query` call; otherwise an `update` call.
    #[serde(default)]
    pub is_query: bool,
    /// Application domain to call as, e.g. "oisy.com" — its account delegation is
    /// derived on demand for this connection. Omit to call anonymously.
    #[serde(default)]
    pub domain: Option<String>,
    /// Which of your accounts at `domain` to act as, by account name (see
    /// list_accounts). Omit to use that app's default account. Ignored when
    /// `domain` is omitted (anonymous calls have no account).
    #[serde(default)]
    pub account: Option<String>,
    /// Optional Candid service definition (`.did` text) for the canister. Used to
    /// encode the args to the method's declared types and decode the reply, for
    /// when the canister's own `candid:service` metadata can't be read (e.g.
    /// access-restricted) — get it from get_candid, or ask the user for it.
    #[serde(default)]
    pub candid: Option<String>,
}

/// Output of `call_canister`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CallCanisterOutput {
    /// The canister that was called.
    pub canister_id: String,
    /// The method that was invoked.
    pub method: String,
    /// Whether this was a read-only query call (vs. an update call).
    pub is_query: bool,
    /// The decoded reply in textual Candid.
    pub reply: String,
}

pub fn default_args() -> String {
    "()".to_string()
}

// ===========================================================================
// Candid interface resolution + encode/decode/call helpers.
// ===========================================================================

/// The interface to encode/decode against: the canister's own `candid:service`
/// if exposed, else the caller-supplied `provided` definition.
pub async fn resolve_did(agent: &Agent, canister: Principal, provided: Option<&str>) -> Option<String> {
    if let Some(did) = candid_service(agent, canister).await {
        return Some(did);
    }
    provided.map(str::to_string)
}

/// The canister's `candid:service` interface (`.did` text), if exposed.
pub async fn candid_service(agent: &Agent, canister: Principal) -> Option<String> {
    let raw = agent
        .read_state_canister_metadata(canister, "candid:service")
        .await
        .ok()?;
    String::from_utf8(raw).ok()
}

/// Maximum byte length of caller-supplied textual Candid we will parse. Real
/// values are tiny and even large `.did` interfaces are well under this.
pub(crate) const MAX_CANDID_TEXT_BYTES: usize = 1024 * 1024;
/// Maximum nesting depth of caller-supplied textual Candid. `candid_parser` and
/// its AST / type-check / `Display` passes recurse with NO depth guard, so deeply
/// nested untrusted input (e.g. `opt opt … 1` thousands deep) would drive an
/// unrecoverable stack-overflow **process abort** (CWE-674), killing every
/// concurrent session. Real Candid nests only a handful of levels; 128 is far
/// above any legitimate value/interface yet far below the stack-overflow depth.
pub(crate) const MAX_CANDID_DEPTH: usize = 128;

/// Reject caller-supplied textual Candid (a value, or `.did` service text) that
/// is too large or too deeply nested to parse safely, BEFORE handing it to
/// `candid_parser` (CWE-674). `what` names the input for the error message.
///
/// Depth is measured structurally without parsing. The stack holds one frame per
/// open nesting level: a bracket group (`(` `{` `[`) or an `opt`/`vec` prefix. A
/// prefix wraps exactly the next value, so it stays on the stack until that value
/// *completes* — at the leaf token, string, or matching bracket closer that ends
/// it — NOT merely because the next token is a word: that word may be
/// `record`/`variant`, which opens a bracket the prefix must outlive (so
/// `opt record { … }` correctly counts as two levels, not one). String literals
/// are skipped so their contents can't inflate the count. It is a conservative
/// over-approximation that tracks the parser's container recursion without
/// under-counting nested `opt`/`vec`/bracket levels.
pub(crate) fn guard_candid_text(what: &str, text: &str) -> Result<(), String> {
    if text.len() > MAX_CANDID_TEXT_BYTES {
        return Err(format!(
            "{what} is too large to parse ({} bytes; limit {MAX_CANDID_TEXT_BYTES})",
            text.len()
        ));
    }
    // Frames: b'B' = bracket group, b'P' = pending opt/vec prefix awaiting its value.
    let mut stack: Vec<u8> = Vec::new();
    let bytes = text.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    // Pop the prefix frames waiting on a value that has just completed.
    fn resolve_prefixes(stack: &mut Vec<u8>) {
        while stack.last() == Some(&b'P') {
            stack.pop();
        }
    }
    // The next non-whitespace byte at/after `j` (to tell `record {` from a leaf).
    let peek_significant = |j: usize| -> Option<u8> {
        bytes[j..]
            .iter()
            .find(|&&b| !b.is_ascii_whitespace())
            .copied()
    };
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'"' => {
                // Skip a string literal (handles \" escapes) so its contents don't count.
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                // A string is a complete leaf value: resolve prefixes waiting on it.
                resolve_prefixes(&mut stack);
            }
            b'(' | b'{' | b'[' => {
                stack.push(b'B');
                if stack.len() > MAX_CANDID_DEPTH {
                    return Err(depth_err(what));
                }
                i += 1;
            }
            b')' | b'}' | b']' => {
                if stack.last() == Some(&b'B') {
                    stack.pop();
                }
                // The group is a complete value: resolve prefixes waiting on it.
                resolve_prefixes(&mut stack);
                i += 1;
            }
            b',' | b';' => {
                // End of one element: resolve its prefixes, keep the enclosing bracket.
                resolve_prefixes(&mut stack);
                i += 1;
            }
            _ if is_word(c) => {
                let start = i;
                while i < bytes.len() && is_word(bytes[i]) {
                    i += 1;
                }
                let word = &bytes[start..i];
                if word == b"opt" || word == b"vec" {
                    stack.push(b'P');
                    if stack.len() > MAX_CANDID_DEPTH {
                        return Err(depth_err(what));
                    }
                } else if !matches!(peek_significant(i), Some(b'{') | Some(b'(') | Some(b'[')) {
                    // A leaf token (a number, `nat`, `principal`, `blob`, a field
                    // name, …) that does NOT open a group completes a value, so
                    // resolve prefixes waiting on it. A group-introducing keyword
                    // (`record`/`variant`/…) instead leaves them pending until its
                    // bracket closes, so `opt record { … }` keeps both levels.
                    resolve_prefixes(&mut stack);
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

fn depth_err(what: &str) -> String {
    format!("{what} is nested too deeply (limit {MAX_CANDID_DEPTH}) — refusing to parse")
}

/// Encode textual Candid args to bytes. With `did` (the canister interface),
/// coerce the args to the method's declared parameter types — so plain literals
/// land as the method expects (`42` -> `nat64`, `1` -> `float64`, `opt`/`vec`
/// element types) with no `: type` annotations. Without it (interface
/// unreadable and no `candid` supplied), fall back to type-less inference, where
/// numeric literals default to `int`/`float64` and must be annotated (see the
/// `candid://textual-syntax` resource).
pub fn encode_args(did: Option<&str>, method: &str, args_text: &str) -> Result<Vec<u8>, String> {
    // The value MUST be parsed to encode it, so an oversized/over-nested value is
    // a hard reject (CWE-674). An over-limit `did` is non-fatal: skip the typed
    // path (don't parse it) and fall back to type-less encoding below.
    guard_candid_text("the `args` value", args_text)?;
    let parsed = candid_parser::parse_idl_args(args_text)
        .map_err(|e| format!("could not parse args `{args_text}`: {e}"))?;
    if let Some(did) = did.filter(|d| guard_candid_text("the `candid` interface", d).is_ok()) {
        if let Ok((env, Some(actor))) = candid_parser::utils::CandidSource::Text(did).load() {
            if let Ok(func) = env.get_method(&actor, method) {
                return parsed
                    .to_bytes_with_types(&env, &func.args)
                    .map_err(|e| format!("args don't match `{method}`'s Candid signature: {e}"));
            }
        }
    }
    parsed
        .to_bytes()
        .map_err(|e| format!("could not encode args `{args_text}`: {e}"))
}

/// Decode reply `bytes` to textual Candid. With `did`, decode against the
/// method's declared return types so record/variant field names are recovered;
/// otherwise (or on any failure) fall back to type-less decoding.
pub fn decode_reply(did: Option<&str>, method: &str, bytes: &[u8]) -> String {
    if let Some(text) = did.and_then(|d| decode_bytes_with_did(d, method, bytes)) {
        return text;
    }
    match IDLArgs::from_bytes(bytes) {
        Ok(decoded) => decoded.to_string(),
        Err(e) => format!("(call succeeded but reply is not decodable as Candid: {e})"),
    }
}

/// Decode Candid `bytes` against the return types of `method` declared in the
/// `.did` text, recovering record/variant field names. None if the interface
/// can't be parsed, the method isn't found, or decoding fails.
pub fn decode_bytes_with_did(did: &str, method: &str, bytes: &[u8]) -> Option<String> {
    // Skip (fall back to type-less decoding) if the interface is too large/nested
    // to parse safely (CWE-674).
    guard_candid_text("the `candid` interface", did).ok()?;
    let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
    let actor = actor?;
    let func = env.get_method(&actor, method).ok()?;
    let decoded = IDLArgs::from_bytes_with_types(bytes, &env, &func.rets).ok()?;
    Some(decoded.to_string())
}

/// True when `did` exposes the standard OQL query surface: BOTH a `schema` and
/// an `execute` method. Detection is name-based, matching the reference IC
/// connector — OQL is a recommended convention (not a hard contract), so a
/// canister whose method signatures differ slightly should not be denied the
/// guidance.
///
/// Fail-closed: the interface is untrusted, canister-supplied text, so it runs
/// through [`guard_candid_text`] (CWE-674) BEFORE `candid_parser` parses it —
/// exactly as [`decode_bytes_with_did`] does. Anything we cannot safely bound or
/// parse yields `false`, never an error or a panic (a `.did` too large/nested to
/// check simply doesn't advertise OQL — the same graceful degradation the decode
/// path uses).
pub fn has_oql(did: &str) -> bool {
    if guard_candid_text("the `candid` interface", did).is_err() {
        return false;
    }
    let Ok((env, Some(actor))) = candid_parser::utils::CandidSource::Text(did).load() else {
        return false;
    };
    env.get_method(&actor, "schema").is_ok() && env.get_method(&actor, "execute").is_ok()
}

/// Perform a query or update call and return the raw Candid reply bytes.
pub async fn raw_call(
    agent: &Agent,
    canister: Principal,
    method: &str,
    arg: Vec<u8>,
    is_query: bool,
) -> Result<Vec<u8>, ic_agent::AgentError> {
    if is_query {
        agent.query(&canister, method).with_arg(arg).call().await
    } else {
        agent.update(&canister, method).with_arg(arg).call_and_wait().await
    }
}

#[cfg(test)]
mod tests {
    // CWE-674: the pre-parse guard rejects over-deep / oversized textual Candid
    // (which would otherwise stack-overflow candid_parser and abort the process),
    // without false-positiving on realistic values.
    #[test]
    fn candid_guard_rejects_deep_and_oversized() {
        use super::{guard_candid_text, MAX_CANDID_TEXT_BYTES};
        // Realistic, shallow values/interfaces pass.
        assert!(guard_candid_text("v", "()").is_ok());
        assert!(guard_candid_text("v", "(record { a = opt 1; b = vec { 1; 2; 3 } })").is_ok());
        // The finding's exact vector: keyword nesting with NO brackets is caught.
        let deep_opt = format!("{}1", "opt ".repeat(5000));
        assert!(guard_candid_text("v", &deep_opt).is_err(), "deep opt-chain must be refused");
        // Bracket nesting is caught too.
        assert!(guard_candid_text("v", &"{".repeat(200)).is_err(), "deep brackets must be refused");
        // Mixed prefix+group nesting must count BOTH levels per step (each
        // `opt record {` is depth 2), so the `opt` prefix isn't lost to the
        // following `record` keyword. 100 levels ⇒ ~200 frames ⇒ refused.
        let deep_mixed = format!(
            "{}1{}",
            "opt record { a = ".repeat(100),
            " }".repeat(100),
        );
        assert!(
            guard_candid_text("v", &deep_mixed).is_err(),
            "deep opt-record nesting must be refused (no prefix under-count)"
        );
        // ...but a shallow mixed value stays well under the limit.
        assert!(
            guard_candid_text("v", "(opt record { a = opt variant { b = vec { 1; 2 } } })").is_ok()
        );
        // Oversized-but-shallow input is caught by the byte cap.
        let big = "0,".repeat(MAX_CANDID_TEXT_BYTES);
        assert!(guard_candid_text("v", &big).is_err(), "oversized input must be refused");
        // No false positives: brackets inside a STRING don't count, and many
        // SIBLING (non-nested) opts stay shallow.
        assert!(guard_candid_text("v", &format!("\"{}\"", "(".repeat(10_000))).is_ok());
        assert!(guard_candid_text("v", &format!("(record {{ {} }})", "a = opt 1; ".repeat(1000))).is_ok());
    }

    // OQL detection is name-based (both `schema` and `execute` must be present),
    // fail-closed (unparseable / over-limit interfaces yield `false`, never a
    // panic), so the untrusted candid:service text can't crash detection.
    #[test]
    fn has_oql_detects_schema_and_execute() {
        use super::has_oql;
        // Both methods present → OQL.
        let oql = r#"
            service : {
                schema : () -> (text) query;
                execute : (text) -> (variant { ok : text; err : text }) query;
                unrelated : (nat) -> (nat) query;
            }
        "#;
        assert!(has_oql(oql), "schema + execute should be detected as OQL");

        // Missing `execute` → not OQL.
        let only_schema = "service : { schema : () -> (text) query; }";
        assert!(!has_oql(only_schema), "schema alone is not OQL");

        // Missing `schema` → not OQL.
        let only_execute = "service : { execute : (text) -> (text) query; }";
        assert!(!has_oql(only_execute), "execute alone is not OQL");

        // A plain canister with neither method → not OQL.
        let plain = "service : { greet : (text) -> (text) query; }";
        assert!(!has_oql(plain), "unrelated interface is not OQL");

        // Name-based, not signature-based: differing arg/return types still count
        // (matches the reference connector; OQL is a recommended convention).
        let loose = "service : { schema : () -> (blob); execute : (blob) -> (nat); }";
        assert!(has_oql(loose), "detection is by method name, not signature");

        // Fail-closed: garbage / non-service text is not OQL (no panic).
        assert!(!has_oql("not a candid interface at all"), "garbage is not OQL");
        assert!(!has_oql(""), "empty is not OQL");

        // Fail-closed: an over-nested interface trips the CWE-674 guard BEFORE
        // parsing, so it degrades to `false` rather than aborting the process.
        let over_deep = format!("service : {{ schema : () -> ({}nat{}); }}",
            "vec ".repeat(5000), "");
        assert!(!has_oql(&over_deep), "over-limit interface must fail closed to false");
    }
}
