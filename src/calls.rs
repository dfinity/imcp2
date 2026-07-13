//! The direct canister-call layer: `get_canister_candid` (read a canister's Candid
//! interface) and `call_canister` (invoke a method with textual Candid in and
//! out). The LLM only ever deals with textual Candid — the binary
//! encoding/decoding against a method's declared types happens here, and the
//! `.did` interface is resolved from the canister's own `candid:service`
//! metadata (or a caller-supplied definition).
//!
//! The `#[tool]` entry points live on `IcTools` in `main.rs` (they need the
//! agent, identities, and request context); this module owns their argument and
//! output types plus the pure encode/decode/call helpers they delegate to.

use candid::{
    types::value::{IDLArgs, IDLField, IDLValue},
    types::Label,
    Principal,
};
use ic_agent::Agent;
// rmcp re-exports schemars 1.x; the `#[tool]` output-schema machinery requires
// THAT version's `JsonSchema`, so derive the MCP types against it.
use rmcp::schemars;
use serde::{Deserialize, Serialize};

// ===========================================================================
// MCP-facing argument and output types (textual in, textual out — the LLM
// never touches binary Candid).
// ===========================================================================

/// Arguments for `get_canister_candid`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetCandidArgs {
    /// Canister principal, e.g. "ryjl3-tyaaa-aaaaa-aaaba-cai" (the ICP ledger).
    pub canister_id: String,
}

/// Output of `get_canister_candid`.
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

/// Arguments for `run_canister_oql_query`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OqlQueryArgs {
    /// Canister principal that exposes the OQL surface (get_canister_candid reports
    /// `oql: true`).
    pub canister_id: String,
    /// The OQL query as a JSON object string — passed straight to the canister's
    /// `execute` method, so NO Candid escaping is needed (write plain JSON). E.g.
    /// `{"start":"employee","where":{"icontains":{"field":"lastName","value":"smith"}},"select":["firstName","lastName"],"limit":10}`.
    /// See get_oql_guide (or get_canister_oql_schema) for the dialect and entity/field names.
    pub query: String,
    /// Query AS the user's account at an app, given its canonical Internet
    /// Identity derivation origin (not necessarily the visible URL). Accepts the
    /// legacy name `domain`. Omit to query anonymously.
    #[serde(default, alias = "domain")]
    pub derivation_origin: Option<String>,
    /// Which of your accounts to act as, by account name (see list_app_accounts).
    /// Omit for that app's default account; ignored when querying anonymously.
    #[serde(default)]
    pub account: Option<String>,
}

/// Output of `run_canister_oql_query`: the `execute` result decoded into a table.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct OqlQueryOutput {
    /// The canister that was queried.
    pub canister_id: String,
    /// Column names, in order (the cell `name`s of the first row).
    pub columns: Vec<String>,
    /// Result rows, each aligned to `columns`, with cell values rendered as scalars.
    pub rows: Vec<Vec<String>>,
    /// True when more rows remain — re-query with a higher `offset` to page.
    pub has_more: bool,
    /// The principal the query was signed as — null for an anonymous query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acted_as_principal: Option<String>,
    /// When querying as an app account: the effective Internet Identity derivation
    /// origin used (after canonicalization). Null for anonymous queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_for_origin: Option<String>,
    /// When querying as an app account: exactly what you supplied as
    /// `derivation_origin`, echoed so a mismatch with `derived_for_origin` (from
    /// canonicalization) is visible. Null for anonymous queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
}

/// Arguments for `get_canister_oql_schema`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OqlSchemaArgs {
    /// Canister principal that exposes the OQL surface (get_canister_candid reports
    /// `oql: true`).
    pub canister_id: String,
    /// Read AS the user's account at an app, given its canonical Internet
    /// Identity derivation origin (not necessarily the visible URL). Accepts the
    /// legacy name `domain`. Omit to read anonymously.
    #[serde(default, alias = "domain")]
    pub derivation_origin: Option<String>,
    /// Which of your accounts to act as (see list_app_accounts). Ignored when reading
    /// anonymously.
    #[serde(default)]
    pub account: Option<String>,
}

/// Output of `get_canister_oql_schema`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct OqlSchemaOutput {
    /// The canister whose schema was read.
    pub canister_id: String,
    /// The entity/field/edge catalogue returned by `schema` (JSON text,
    /// pretty-printed when it parses).
    pub schema: String,
    /// The principal the read was signed as — null for an anonymous read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acted_as_principal: Option<String>,
    /// When reading as an app account: the effective Internet Identity derivation
    /// origin used (after canonicalization). Null for anonymous reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_for_origin: Option<String>,
    /// When reading as an app account: exactly what you supplied as
    /// `derivation_origin`, echoed so a mismatch with `derived_for_origin` (from
    /// canonicalization) is visible. Null for anonymous reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
}

/// Arguments for `get_api_doc`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApiDocArgs {
    /// Canister principal to read the API documentation from.
    pub canister_id: String,
}

/// Output of `get_api_doc`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ApiDocOutput {
    /// The canister the doc came from.
    pub canister_id: String,
    /// The method the doc was read from (`getApiDoc` or `get_api_doc`).
    pub method: String,
    /// The API documentation (markdown): how the app behaves — units, auth,
    /// lifecycle, non-obvious semantics, mutation safety, polling rules, gotchas.
    pub doc: String,
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
    /// Call AS the user's account at an app, identified by its exact canonical
    /// Internet Identity derivation origin — NOT necessarily the visible URL. For
    /// an app with a custom derivation origin, pass that canonical origin (do not
    /// infer it from an alternativeOrigins list). Accepts the legacy name
    /// `domain`. Omit both this and `app_url` to call anonymously; provide at most
    /// one. The account delegation is derived on demand for this connection.
    #[serde(default, alias = "domain")]
    pub derivation_origin: Option<String>,
    /// Call AS the user's account at an app, identified by its URL; the connector
    /// resolves the derivation origin (declared one if the app publishes it, else
    /// the application origin — see the result's `derivation_origin_source`).
    /// Alternative to `derivation_origin`.
    #[serde(default)]
    pub app_url: Option<String>,
    /// Which of your accounts to act as, by account name (see list_app_accounts).
    /// Omit to use that app's default account. Ignored for anonymous calls.
    #[serde(default)]
    pub account: Option<String>,
    /// Optional Candid service definition (`.did` text) for the canister. Used to
    /// encode the args to the method's declared types and decode the reply, for
    /// when the canister's own `candid:service` metadata can't be read (e.g.
    /// access-restricted) — get it from get_canister_candid, or ask the user for it.
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
    /// The principal the call was signed as — null for an anonymous call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acted_as_principal: Option<String>,
    /// When called as an app account: the effective Internet Identity derivation
    /// origin used (after canonicalization). Null for anonymous calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_for_origin: Option<String>,
    /// When called as an app account: exactly what you supplied
    /// (`derivation_origin` or `app_url`), echoed so a mismatch with
    /// `derived_for_origin` is visible. Null for anonymous calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    /// When called as an app account: how `derived_for_origin` was determined
    /// (`explicit` | `declared` | `known` | `app_url_default`) — matches the other
    /// identity tools. `app_url_default` means the app declares no derivation origin
    /// (and isn't a known app) and the app URL was assumed, so the principal is
    /// wrong for an app with a custom one. Null for anonymous calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_origin_source: Option<String>,
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

// ===========================================================================
// OQL execute/schema support (for the `run_canister_oql_query` / `get_canister_oql_schema` tools). The
// server does not model the OQL query language — it wraps the JSON query as the
// single `text` argument `execute` expects (so the model never hand-escapes
// JSON inside a Candid text literal) and decodes the tabular reply.
// ===========================================================================

/// Validate that an OQL `query` is a JSON object and return it re-serialized
/// compactly. `execute` takes one JSON object as text; validating here catches
/// malformed input before the call and normalizes formatting.
pub fn normalize_oql_query(query: &str) -> Result<String, String> {
    if query.len() > MAX_CANDID_TEXT_BYTES {
        return Err(format!(
            "the OQL query is too large ({} bytes; limit {MAX_CANDID_TEXT_BYTES})",
            query.len()
        ));
    }
    let value: serde_json::Value =
        serde_json::from_str(query).map_err(|e| format!("`query` must be valid JSON: {e}"))?;
    if !value.is_object() {
        return Err(
            "`query` must be a JSON object, e.g. {\"start\":\"employee\",\"limit\":10}".to_string(),
        );
    }
    Ok(value.to_string())
}

/// Encode a single `text` argument (the OQL query JSON) for `execute` — built as
/// a typed Candid value, so there is no textual escaping to get wrong.
pub fn encode_text_arg(text: &str) -> Result<Vec<u8>, String> {
    IDLArgs::new(&[IDLValue::Text(text.to_string())])
        .to_bytes()
        .map_err(|e| format!("could not encode the query argument: {e}"))
}

/// Encode the empty argument tuple `()` for `schema`.
pub fn encode_unit_arg() -> Result<Vec<u8>, String> {
    IDLArgs::new(&[])
        .to_bytes()
        .map_err(|e| format!("could not encode arguments: {e}"))
}

/// The parsed outcome of an OQL `execute` reply.
pub enum OqlResult {
    /// A decoded table: column names, string-rendered rows, and the paging flag.
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
        has_more: bool,
    },
    /// The canister returned its error arm (e.g. `variant { err = "…" }`).
    QueryError(String),
    /// The reply didn't match a recognizable OQL result shape; carries the raw
    /// decoded textual Candid so the caller can still surface the data.
    Unrecognized(String),
}

/// Decode an `execute` reply into a table. `did` (the canister interface) is used
/// to recover field names — without it the wire format hashes them and the shape
/// generally can't be recognized, so we fall back to `Unrecognized` with the raw
/// reply rather than guessing.
pub fn parse_execute_reply(did: Option<&str>, reply: &[u8]) -> OqlResult {
    let decoded = match did.and_then(|d| decode_args_with_did(d, "execute", reply)) {
        Some(args) => args,
        None => match IDLArgs::from_bytes(reply) {
            Ok(args) => args,
            Err(e) => return OqlResult::Unrecognized(format!("(undecodable reply: {e})")),
        },
    };
    match decoded.args.into_iter().next() {
        Some(val) => extract_oql(&val).unwrap_or_else(|| OqlResult::Unrecognized(val.to_string())),
        None => OqlResult::Unrecognized("(empty reply)".to_string()),
    }
}

/// Decode a reply that is a single `text` value (e.g. `schema` or the API-doc
/// method): the bare string. A non-text single value falls back to its type-less
/// rendering; a reply with MORE than one value renders the whole `IDLArgs` tuple
/// (so nothing is silently dropped, even though these methods return one value by
/// contract); an undecodable reply yields an explanatory string.
pub fn decode_text_reply(reply: &[u8]) -> String {
    let args = match IDLArgs::from_bytes(reply) {
        Ok(a) => a,
        Err(e) => return format!("(undecodable reply: {e})"),
    };
    match args.args.as_slice() {
        [] => "(empty reply)".to_string(),
        [IDLValue::Text(s)] => s.clone(),
        [single] => single.to_string(),
        _ => args.to_string(),
    }
}

/// Decode a `schema` reply — a single `text` (the JSON catalogue). Pretty-print
/// it when it parses as JSON; otherwise return it as-is.
pub fn decode_schema_reply(reply: &[u8]) -> String {
    let text = decode_text_reply(reply);
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or(text),
        Err(_) => text,
    }
}

/// The canister's API-documentation method name, if it declares one — `getApiDoc`
/// or `get_api_doc`, checked in that order (a canister uses one naming style).
/// Guarded (CWE-674) and fail-closed like the OQL detection: `None` if the
/// interface can't be parsed or declares neither.
pub fn api_doc_method(did: &str) -> Option<&'static str> {
    if guard_candid_text("the `candid` interface", did).is_err() {
        return None;
    }
    let Ok((env, Some(actor))) = candid_parser::utils::CandidSource::Text(did).load() else {
        return None;
    };
    ["getApiDoc", "get_api_doc"]
        .into_iter()
        .find(|m| env.get_method(&actor, m).is_ok())
}

/// Decode a reply against the declared return types of `method` in `did`,
/// returning the structured `IDLArgs` (field names recovered). Guarded (CWE-674)
/// like the rest of the decode path; None on any guard/parse/decode failure.
fn decode_args_with_did(did: &str, method: &str, bytes: &[u8]) -> Option<IDLArgs> {
    guard_candid_text("the `candid` interface", did).ok()?;
    let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
    let actor = actor?;
    let func = env.get_method(&actor, method).ok()?;
    IDLArgs::from_bytes_with_types(bytes, &env, &func.rets).ok()
}

/// Recognize an OQL result value: a `record { hasMore; rows }`, optionally
/// wrapped in a `variant { ok = … }` / `variant { err = … }`.
fn extract_oql(val: &IDLValue) -> Option<OqlResult> {
    match val {
        IDLValue::Record(fields) => {
            let rows_val = field_by_name(fields, "rows")?;
            let has_more = matches!(field_by_name(fields, "hasMore"), Some(IDLValue::Bool(true)));
            let (columns, rows) = rows_to_table(rows_val)?;
            Some(OqlResult::Table {
                columns,
                rows,
                has_more,
            })
        }
        IDLValue::Variant(var) => {
            let arm = &var.0;
            let name = label_name(&arm.id);
            if name.eq_ignore_ascii_case("ok") || name.eq_ignore_ascii_case("success") {
                // Known success arm — descend into the wrapped record.
                extract_oql(&arm.val)
            } else if name.eq_ignore_ascii_case("err") || name.eq_ignore_ascii_case("error") {
                Some(OqlResult::QueryError(cell_scalar(&arm.val)))
            } else {
                // Any other arm: don't assume it's an OQL result — fail closed to
                // Unrecognized (the caller surfaces the raw reply) rather than
                // recursing into an arbitrary variant.
                None
            }
        }
        _ => None,
    }
}

/// Turn the `rows : vec vec Cell` value into (columns, string rows). Columns are
/// taken from the first row's cell names; every row is then aligned to them by
/// name (per the primer: read cells by name, never by position).
///
/// Fail-closed: `None` (→ Unrecognized) if the value isn't a vec, if any row
/// isn't a vec, or if the first row yields no named cells — so a malformed /
/// non-OQL reply degrades to the raw Candid rather than a bogus "0 columns"
/// table. An empty `rows` (a query that matched nothing) is the one legitimate
/// zero-column case and returns an empty table.
fn rows_to_table(rows_val: &IDLValue) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    let IDLValue::Vec(rows) = rows_val else {
        return None;
    };
    if rows.is_empty() {
        return Some((Vec::new(), Vec::new()));
    }
    let mut columns: Vec<String> = Vec::new();
    let mut out_rows: Vec<Vec<String>> = Vec::new();
    for row in rows {
        let IDLValue::Vec(cells) = row else {
            return None;
        };
        let mut pairs: Vec<(String, String)> = Vec::new();
        for cell in cells {
            if let IDLValue::Record(cf) = cell {
                let name = match field_by_name(cf, "name") {
                    Some(IDLValue::Text(s)) => s.clone(),
                    _ => continue,
                };
                let value = field_by_name(cf, "value").map(cell_scalar).unwrap_or_default();
                pairs.push((name, value));
            }
        }
        if columns.is_empty() {
            if pairs.is_empty() {
                // First row carried no named cells — not a recognizable OQL row.
                return None;
            }
            columns = pairs.iter().map(|(n, _)| n.clone()).collect();
        }
        // Align this row to `columns` via a name→value map (first occurrence
        // wins, matching a linear find) so wide tables stay O(cols), not O(cols²).
        let mut by_name: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for (n, v) in &pairs {
            by_name.entry(n.as_str()).or_insert(v.as_str());
        }
        let aligned = columns
            .iter()
            .map(|c| by_name.get(c.as_str()).copied().unwrap_or("").to_string())
            .collect();
        out_rows.push(aligned);
    }
    Some((columns, out_rows))
}

/// Render one OQL cell value as a scalar string. Cell values are wrapped in a
/// `variant` (per the primer), so unwrap one level; text/principal are shown bare
/// and everything else falls back to Candid's own `Display`.
fn cell_scalar(v: &IDLValue) -> String {
    match v {
        IDLValue::Variant(var) => cell_scalar(&var.0.val),
        IDLValue::Opt(inner) => cell_scalar(inner),
        IDLValue::Text(s) => s.clone(),
        IDLValue::Principal(p) => p.to_text(),
        other => other.to_string(),
    }
}

/// Look up a record field by its (named) label. Matches `Label::Named` directly
/// so the hot decode loop doesn't allocate a `String` per field just to compare
/// against a constant key. The typed decode path recovers `Label::Named` for the
/// OQL fields we ask for ("rows", "hasMore", "name", "value"); a hashed
/// (`Label::Id`) label never equals a non-numeric key anyway.
fn field_by_name<'a>(fields: &'a [IDLField], name: &str) -> Option<&'a IDLValue> {
    fields
        .iter()
        .find(|f| matches!(&f.id, Label::Named(n) if n == name))
        .map(|f| &f.val)
}

fn label_name(l: &Label) -> String {
    match l {
        Label::Named(s) => s.clone(),
        Label::Id(n) | Label::Unnamed(n) => n.to_string(),
    }
}

/// Render a decoded OQL table as GitHub-flavored markdown, with a trailing
/// row-count / paging note.
pub fn render_table(columns: &[String], rows: &[Vec<String>], has_more: bool) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('|', "\\|").replace('\n', " ");
    if columns.is_empty() {
        return format!(
            "0 columns / {} row(s){}.",
            rows.len(),
            if has_more { " — more available" } else { "" }
        );
    }
    let mut out = String::new();
    out.push_str("| ");
    out.push_str(&columns.iter().map(|c| esc(c)).collect::<Vec<_>>().join(" | "));
    out.push_str(" |\n|");
    for _ in columns {
        out.push_str(" --- |");
    }
    out.push('\n');
    for row in rows {
        let cells: Vec<String> = (0..columns.len())
            .map(|i| esc(row.get(i).map(String::as_str).unwrap_or("")))
            .collect();
        out.push_str("| ");
        out.push_str(&cells.join(" | "));
        out.push_str(" |\n");
    }
    out.push_str(&format!(
        "\n{} row(s){}.",
        rows.len(),
        if has_more {
            " — more available; re-query with a higher `offset` to page"
        } else {
            ""
        }
    ));
    out
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
        // BOTH methods are present and the deep nesting is only in `schema`'s
        // return type, so the guard is the ONLY reason this returns false — were
        // the guard removed and parsing to succeed, detection would return true
        // and this assertion would fail (it can't pass by "missing execute").
        let over_deep = format!(
            "service : {{ schema : () -> ({}nat) query; execute : (text) -> (text) query; }}",
            "vec ".repeat(5000),
        );
        assert!(!has_oql(&over_deep), "over-limit interface must fail closed to false");
        // Positive control: the SAME two-method interface without the deep
        // nesting IS detected, so the false above is provably the guard (depth),
        // not the interface shape.
        let shallow_twin = "service : { schema : () -> (nat) query; execute : (text) -> (text) query; }";
        assert!(has_oql(shallow_twin), "shallow twin should be detected — isolates the guard as the cause");
    }

    // Encode a Candid reply of `ty` from its textual form, so parse_execute_reply
    // can be exercised end-to-end against a realistic `execute` return type.
    #[cfg(test)]
    fn encode_reply(did: &str, method: &str, textual: &str) -> Vec<u8> {
        let (env, actor) = candid_parser::utils::CandidSource::Text(did)
            .load()
            .expect("parse did");
        let actor = actor.expect("service");
        let func = env.get_method(&actor, method).expect("method");
        candid_parser::parse_idl_args(textual)
            .expect("parse value")
            .to_bytes_with_types(&env, &func.rets)
            .expect("encode value")
    }

    // run_canister_oql_query decoding: a `variant { ok = record { hasMore; rows } }` reply with
    // variant-wrapped cell values decodes into ordered columns + string rows, the
    // paging flag is read, an `err` arm surfaces as a QueryError, and a
    // non-conforming reply degrades to Unrecognized (never a panic).
    #[test]
    fn parse_execute_reply_builds_table() {
        use super::{parse_execute_reply, OqlResult};
        let did = "service : { \
            execute : (text) -> (variant { \
                ok : record { hasMore : bool; rows : vec vec record { name : text; value : variant { text : text; num : int } } }; \
                err : text \
            }) query; \
        }";

        // A two-row, two-column result with hasMore = true.
        let ok_reply = encode_reply(
            did,
            "execute",
            "(variant { ok = record { \
                hasMore = true; \
                rows = vec { \
                    vec { \
                        record { name = \"firstName\"; value = variant { text = \"Ada\" } }; \
                        record { name = \"lastName\"; value = variant { text = \"Lovelace\" } } \
                    }; \
                    vec { \
                        record { name = \"firstName\"; value = variant { text = \"Alan\" } }; \
                        record { name = \"lastName\"; value = variant { text = \"Turing\" } } \
                    } \
                } \
            } })",
        );
        match parse_execute_reply(Some(did), &ok_reply) {
            OqlResult::Table { columns, rows, has_more } => {
                assert_eq!(columns, vec!["firstName", "lastName"]);
                assert_eq!(rows, vec![
                    vec!["Ada".to_string(), "Lovelace".to_string()],
                    vec!["Alan".to_string(), "Turing".to_string()],
                ]);
                assert!(has_more, "hasMore = true must be read");
            }
            _ => panic!("expected a Table"),
        }

        // The error arm surfaces as QueryError.
        let err_reply = encode_reply(did, "execute", "(variant { err = \"bad query\" })");
        match parse_execute_reply(Some(did), &err_reply) {
            OqlResult::QueryError(msg) => assert_eq!(msg, "bad query"),
            _ => panic!("expected a QueryError"),
        }

        // Without the interface, field names are hashed on the wire, so the shape
        // isn't recognized — degrade to Unrecognized rather than guess/panic.
        assert!(matches!(
            parse_execute_reply(None, &ok_reply),
            OqlResult::Unrecognized(_)
        ));

        // A query that matched nothing (`rows = vec {}`) is a legitimate empty
        // table, NOT an error or Unrecognized.
        let empty = encode_reply(
            did,
            "execute",
            "(variant { ok = record { hasMore = false; rows = vec {} } })",
        );
        match parse_execute_reply(Some(did), &empty) {
            OqlResult::Table { columns, rows, has_more } => {
                assert!(columns.is_empty() && rows.is_empty() && !has_more, "empty result is a 0-row table");
            }
            _ => panic!("empty rows should be a Table, not an error/Unrecognized"),
        }
    }

    // Fail-closed decoding (per review): a variant reply whose arm is neither a
    // known success nor error arm, and a record whose rows carry no named cells,
    // both degrade to Unrecognized rather than being passed off as a table.
    #[test]
    fn parse_execute_reply_fails_closed_on_non_oql_shapes() {
        use super::{parse_execute_reply, OqlResult};

        // Unknown variant arm (not ok/success/err) → Unrecognized.
        let weird_did = "service : { execute : (text) -> (variant { weird : text }) query; }";
        let weird = encode_reply(weird_did, "execute", "(variant { weird = \"z\" })");
        assert!(
            matches!(parse_execute_reply(Some(weird_did), &weird), OqlResult::Unrecognized(_)),
            "an unknown variant arm must not be treated as an OQL table"
        );

        // A record with `rows`, but rows whose cells have no `name` field → the
        // first row yields no columns → Unrecognized (not a bogus 0-column table).
        let noname_did = "service : { execute : (text) -> (record { hasMore : bool; rows : vec vec record { foo : text } }) query; }";
        let noname = encode_reply(
            noname_did,
            "execute",
            "(record { hasMore = false; rows = vec { vec { record { foo = \"x\" } } } })",
        );
        assert!(
            matches!(parse_execute_reply(Some(noname_did), &noname), OqlResult::Unrecognized(_)),
            "rows without named cells must degrade to Unrecognized"
        );
    }

    // normalize_oql_query accepts a JSON object, rejects non-objects / invalid
    // JSON / oversized input (so a bad query fails before the canister call).
    #[test]
    fn normalize_oql_query_validates() {
        use super::{normalize_oql_query, MAX_CANDID_TEXT_BYTES};
        assert!(normalize_oql_query(r#"{"start":"employee","limit":10}"#).is_ok());
        assert!(normalize_oql_query(r#"["not","an","object"]"#).is_err(), "array is not an object");
        assert!(normalize_oql_query("not json").is_err(), "invalid JSON is rejected");
        let huge = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_CANDID_TEXT_BYTES));
        assert!(normalize_oql_query(&huge).is_err(), "oversized query is rejected");
    }

    // schema decoding: the single `text` reply is returned, pretty-printed when
    // it parses as JSON.
    #[test]
    fn decode_schema_reply_pretty_prints_json() {
        use super::decode_schema_reply;
        let did = "service : { schema : () -> (text) query; }";
        let reply = encode_reply(did, "schema", "(\"{\\\"entities\\\":[]}\")");
        let out = decode_schema_reply(&reply);
        assert!(out.contains("\"entities\""), "schema JSON should be surfaced: {out}");
        assert!(out.contains('\n'), "valid JSON should be pretty-printed: {out}");
    }

    // api_doc_method finds either naming (getApiDoc / get_api_doc), prefers
    // getApiDoc when both exist, and is None for a canister that has neither /
    // an unparseable interface (fail-closed, like has_oql).
    #[test]
    fn api_doc_method_detection() {
        use super::api_doc_method;
        assert_eq!(api_doc_method("service : { getApiDoc : () -> (text) query; }"), Some("getApiDoc"));
        assert_eq!(api_doc_method("service : { get_api_doc : () -> (text) query; }"), Some("get_api_doc"));
        assert_eq!(
            api_doc_method("service : { getApiDoc : () -> (text) query; get_api_doc : () -> (text) query; }"),
            Some("getApiDoc"),
            "prefers getApiDoc when both are declared"
        );
        assert_eq!(api_doc_method("service : { greet : (text) -> (text) query; }"), None);
        assert_eq!(api_doc_method("not a candid interface"), None);
    }

    // decode_text_reply returns the single `text` value verbatim (markdown doc),
    // without the JSON pretty-printing that decode_schema_reply layers on.
    #[test]
    fn decode_text_reply_returns_text_verbatim() {
        use super::decode_text_reply;
        let did = "service : { getApiDoc : () -> (text) query; }";
        let reply = encode_reply(did, "getApiDoc", "(\"# API\\nHow this app behaves.\")");
        assert_eq!(decode_text_reply(&reply), "# API\nHow this app behaves.");

        // A multi-value reply keeps ALL values (renders the tuple) instead of
        // silently dropping the tail.
        let multi_did = "service : { foo : () -> (text, nat) query; }";
        let multi = encode_reply(multi_did, "foo", "(\"a\", 5 : nat)");
        let out = decode_text_reply(&multi);
        assert!(out.contains("a") && out.contains('5'), "multi-value reply keeps all values: {out}");
    }
}
