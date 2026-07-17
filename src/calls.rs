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
    /// `schema` and an `execute` method). When set, load `icp_oql_guide` (or the
    /// `oql://usage` resource) to learn the JSON query dialect before querying.
    pub oql: bool,
    /// True when the canister declares an API-documentation method
    /// (`getApiDoc`/`get_api_doc`) — computed with the SAME predicate
    /// get_canister_api_doc uses, so it tells you up front whether that call will
    /// return anything. Only call get_canister_api_doc when this is true; when it's
    /// false the canister has no prose doc and the Candid types here are the interface.
    pub api_doc_available: bool,
}

/// Output of `icp_oql_guide`.
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
    /// See icp_oql_guide (or get_canister_oql_schema) for the dialect and entity/field names.
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
    /// True when the query ran as the ANONYMOUS principal (no `derivation_origin`).
    /// Always present so a text-only client can tell an anonymous read from an
    /// authenticated one even on an empty result — per-app data is caller-gated,
    /// so an anonymous empty result usually means "not authenticated", not "no data".
    pub is_anonymous: bool,
    /// A diagnostic note for an EMPTY result (0 rows): the anonymous-read auth
    /// remediation (#1), an unknown-`start` repair (#7), or a note that the query
    /// matched nothing for the authenticated principal. Null when rows were returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When an empty result was diagnosed as an unknown `start` entity: the entities
    /// actually visible to this caller (validated against the schema for the SAME
    /// principal). Null unless that diagnosis fired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_entities: Option<Vec<String>>,
    /// The closest valid entity to an unknown `start` (e.g. "booking" → "bookings").
    /// Null unless an unknown-`start` diagnosis found a near match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_you_mean: Option<String>,
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
    /// True when the schema was read as the ANONYMOUS principal (no
    /// `derivation_origin`). Always present: the schema is itself caller-gated, so
    /// an anonymous read commonly returns NO entities — which means "not
    /// authenticated as your account", not "the app has no data model".
    pub is_anonymous: bool,
    /// A note when the schema came back with NO entities: the anonymous-read auth
    /// remediation (#1) when anonymous, else a note that this principal can see no
    /// entities here. Null when entities were returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// One ready-to-run `run_canister_oql_query` invocation per entity — a COMPLETE
    /// call (canister_id + a minimal `{start, limit}` query) that PRESERVES the
    /// identity this schema was read under (same `derivation_origin`/`account`), so
    /// copying an example doesn't silently drop back to anonymous. Read-only. Empty
    /// when the schema exposes no entities.
    pub example_queries: Vec<String>,
}

/// Arguments for `get_canister_api_doc`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApiDocArgs {
    /// Canister principal to read the API documentation from.
    pub canister_id: String,
}

/// Output of `get_canister_api_doc` — a STRUCTURED result in every case (not an
/// error when the doc simply isn't there), so the agent can distinguish "this app
/// has no prose doc" (expected, don't retry) from "couldn't reach it" (retry).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ApiDocOutput {
    /// The canister the doc was requested from.
    pub canister_id: String,
    /// True when an API-doc method was found and returned a doc (`doc` is set).
    pub available: bool,
    /// The method the doc was read from (`getApiDoc`/`get_api_doc`) — null when
    /// unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The API documentation (markdown): how the app behaves — units, auth,
    /// lifecycle, non-obvious semantics, mutation safety, polling rules, gotchas.
    /// Null when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// When `available` is false: whether absence is EXPECTED — the interface read
    /// fine and the canister simply declares no api-doc method (most canisters
    /// don't). True on the normal "no such method" path; false when we couldn't tell
    /// (interface unreadable / the call failed). Meaningless when `available`.
    pub expected: bool,
    /// When `available` is false: whether retrying might help. False when the method
    /// genuinely isn't declared (retrying won't conjure one); true for a transient
    /// failure (interface/method call unreachable). Meaningless when `available`.
    pub retry: bool,
    /// What to do next — e.g. "use get_canister_candid for the interface" when there
    /// is no doc, or "retry" on a transient failure. Null when `available`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
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
    /// Internet Identity derivation origin — NOT necessarily the visible URL (do
    /// not infer it from an alternativeOrigins list). Get it from open_app /
    /// resolve_app, which resolve an app NAME or URL to the derivation origin under
    /// the guessed-domain gate; then reuse it here. This does NOT accept a raw
    /// website URL — a derivation origin is a stable per-app value, resolved once
    /// and reused. Accepts the legacy name `domain`. Omit to call anonymously. The
    /// account delegation is derived on demand for this connection.
    #[serde(default, alias = "domain")]
    pub derivation_origin: Option<String>,
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
    /// When called as an app account: exactly what you supplied as
    /// `derivation_origin`, echoed so a mismatch with `derived_for_origin` (from
    /// canonicalization) is visible. Null for anonymous calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    /// When called as an app account: how `derived_for_origin` was determined —
    /// always "explicit" here, since this tool takes the canonical derivation origin
    /// directly. (The "declared"/"known"/"app_url_default" sources are reported by
    /// the resolver tools open_app / resolve_app, which turn a URL into an origin.)
    /// Null for anonymous calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_origin_source: Option<String>,
    /// True when the call ran as the ANONYMOUS principal (no `derivation_origin`).
    /// Always present so a text-only client can tell an anonymous read from an
    /// authenticated one — a per-app read that gates data by caller principal
    /// returns empty when anonymous, which is an auth artifact, not "no data".
    pub is_anonymous: bool,
    /// A note for a query call whose reply looks EMPTY while anonymous: the
    /// caller-gated auth remediation (#1). Computed only from local facts (anonymous
    /// + empty-looking reply); null otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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

/// Enforce "prefer OQL": when a canister exposes an OQL query surface, its data
/// must be READ through the dedicated OQL tools, not raw `call_canister` query
/// calls. Returns the guidance message to hand back to the caller when a query
/// call should be redirected, or `None` when the call may proceed.
///
/// Only *query* calls are redirected — OQL is read-only, so update calls
/// (`is_query == false`) always belong to `call_canister` and pass through. When
/// no interface text is available (`did == None` — neither the canister's own
/// `candid:service` metadata nor a caller-supplied `candid`), OQL can't be
/// detected, so the call passes through too (fail open: never block a call we
/// can't classify).
pub fn oql_query_redirect(did: Option<&str>, is_query: bool) -> Option<String> {
    if is_query && did.is_some_and(has_oql) {
        Some(
            "this canister exposes an OQL query surface, so its data is READ through the \
             dedicated OQL tools, NOT raw `call_canister` query calls. Do this instead, in order: \
             (1) `icp_oql_guide` for the JSON dialect (once), (2) `get_canister_oql_schema` for the \
             entity and field names, (3) `run_canister_oql_query` to run the query. If the request \
             is about the USER's own data (\"my …\", \"our …\"), pass the app's `derivation_origin` \
             to steps 2 and 3 — this canister gates data by caller principal, so an anonymous read \
             comes back empty (an auth artifact, not \"no data\"). Only UPDATE calls (state changes) \
             go through `call_canister`, with `is_query=false`."
                .to_string(),
        )
    } else {
        None
    }
}

// ===========================================================================
// Empty-read auth signal (#1) + OQL `start` validation (#7) + per-entity
// examples (#8). Per-app data is gated by the CALLER's principal, so a read made
// anonymously usually returns empty — with no signal that authentication is the
// missing ingredient. These helpers turn a silent empty into an actionable one,
// computed ONLY from local facts (anonymous + empty), never by probing whether
// authenticated data exists.
// ===========================================================================

/// The most examples/entities we enumerate in `get_canister_oql_schema` (#8) and
/// in the `valid_entities` list (#7) — a schema with a huge entity count would
/// otherwise bloat the reply.
pub(crate) const MAX_OQL_ENTITIES: usize = 40;

/// The #1 remediation note for a per-app read that came back EMPTY while
/// ANONYMOUS. Empty almost always means "not authenticated as your account", not
/// "no data", because the canister gates data by caller principal. `what` names
/// the empty thing ("the schema", "this query", "this query call"); `add_hint`
/// names the argument to add (a placeholder the agent fills — we NEVER bake in an
/// origin the tool guessed via app_url_default).
pub fn anonymous_empty_note(what: &str, add_hint: &str) -> String {
    format!(
        "Read anonymously (as principal 2vxsx-fae) and {what} came back empty. This canister \
         gates data by the CALLER's principal, so empty here most likely means \"not authenticated \
         as your account\", NOT \"no data\". Re-run this exact call adding {add_hint} to read as \
         your account — if you don't have it yet, open_app / resolve_app resolves it from the app's \
         URL or name."
    )
}

/// Whether a decoded OQL `schema` JSON exposes NO entities — the caller-gated
/// "empty schema" an anonymous read yields when the app shows a principal only the
/// entities it may see. Conservative: a schema that doesn't parse as the expected
/// `{"entities":[...]}` shape is NOT treated as empty (so we never raise a false
/// auth hint on an unrecognized shape).
pub fn oql_schema_is_empty(schema_json: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(schema_json) {
        Ok(v) => v
            .get("entities")
            .and_then(|e| e.as_array())
            .is_some_and(|a| a.is_empty()),
        Err(_) => false,
    }
}

/// The entity names declared in a decoded OQL `schema` JSON (the `name` of each
/// `entities[]` element, in order, de-duplicated, capped at [`MAX_OQL_ENTITIES`]).
/// Empty when the schema is absent/unparseable or lists none — used to validate a
/// query's `start` (#7) and to build per-entity examples (#8).
pub fn oql_entity_names(schema_json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(schema_json) else {
        return Vec::new();
    };
    let Some(arr) = v.get("entities").and_then(|e| e.as_array()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for e in arr {
        if let Some(name) = e.get("name").and_then(|n| n.as_str()) {
            if !out.iter().any(|n| n == name) {
                out.push(name.to_string());
                if out.len() >= MAX_OQL_ENTITIES {
                    break;
                }
            }
        }
    }
    out
}

/// The `start` entity of a normalized OQL query JSON, if present. Used to
/// hard-validate `start` (only) against the schema on an empty result (#7).
pub fn oql_query_start(query_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(query_json)
        .ok()
        .and_then(|v| v.get("start").and_then(|s| s.as_str()).map(str::to_string))
}

/// The closest entity name to `start`, for a "did you mean?" repair — a
/// case-insensitive exact match first, then a plural/singular flip
/// (`booking`↔`bookings`), then the smallest Levenshtein distance within a small
/// length-scaled threshold. `None` when nothing is close enough (so we never
/// suggest an unrelated entity).
pub fn closest_entity(start: &str, entities: &[String]) -> Option<String> {
    let lc = start.to_lowercase();
    // Exact, case-insensitive.
    if let Some(e) = entities.iter().find(|e| e.to_lowercase() == lc) {
        return Some((*e).clone());
    }
    // Plural/singular flip.
    if let Some(e) = entities.iter().find(|e| {
        let el = e.to_lowercase();
        el == format!("{lc}s") || format!("{el}s") == lc
    }) {
        return Some((*e).clone());
    }
    // Small edit distance, scaled to the shorter of the two names so short names
    // demand a tighter match. Pick the nearest; ties keep the first (schema order).
    let mut best: Option<(usize, &String)> = None;
    for e in entities {
        let el = e.to_lowercase();
        let d = levenshtein(&lc, &el);
        let bound = (lc.len().min(el.len()) / 3).clamp(1, 3);
        if d <= bound && best.map_or(true, |(bd, _)| d < bd) {
            best = Some((d, e));
        }
    }
    best.map(|(_, e)| e.clone())
}

/// Levenshtein edit distance (two-row DP). Small helper for [`closest_entity`];
/// inputs are short entity names, so the O(mn) cost is trivial.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// One ready-to-run `run_canister_oql_query` invocation per entity (#8) — a
/// COMPLETE call (canister_id + a minimal `{"start":<entity>,"limit":10}` query)
/// that PRESERVES the identity the schema was read under (the same
/// `derivation_origin` / `account`), so copying an example doesn't silently drop
/// back to anonymous. Read-only. Empty when the schema exposes no entities. Each
/// line is `run_canister_oql_query <compact-json-args>`.
pub fn oql_query_examples(
    canister_id: &str,
    schema_json: &str,
    derivation_origin: Option<&str>,
    account: Option<&str>,
) -> Vec<String> {
    oql_entity_names(schema_json)
        .into_iter()
        .map(|entity| {
            let mut args = serde_json::Map::new();
            args.insert("canister_id".into(), serde_json::Value::String(canister_id.to_string()));
            // `query` is a JSON-object STRING (that's what the tool takes). Build it
            // via serde_json (not format!) so an entity name containing a quote or
            // backslash — the schema is canister-supplied, hence untrusted — is
            // escaped and the example stays valid JSON.
            let query = serde_json::json!({ "start": entity, "limit": 10 }).to_string();
            args.insert("query".into(), serde_json::Value::String(query));
            if let Some(o) = derivation_origin {
                args.insert("derivation_origin".into(), serde_json::Value::String(o.to_string()));
            }
            if let Some(a) = account {
                args.insert("account".into(), serde_json::Value::String(a.to_string()));
            }
            format!("run_canister_oql_query {}", serde_json::Value::Object(args))
        })
        .collect()
}

/// Whether a decoded textual-Candid `reply` LOOKS empty — used only to attach the
/// #1 anonymous-read auth hint to a `call_canister` query result, so it must be
/// conservative (a false "empty" would raise a spurious auth hint). Recognizes the
/// unambiguous empties only: the unit tuple `()`, an empty/none `opt` (`(null)`),
/// an empty vector (`(vec {})` / `(opt vec {})`), and a `variant { none }` arm.
/// Anything else — including an explicit `variant { err = … }` (which is a real
/// error, not "empty") or any reply with content — returns false.
pub fn candid_reply_is_empty(reply: &str) -> bool {
    let t = reply.trim();
    // Unit / empty tuple.
    if t == "()" {
        return true;
    }
    // Strip one layer of the outer `( … )` tuple wrapper if present.
    let inner = t
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .map(str::trim)
        .unwrap_or(t);
    match inner {
        "" | "null" | "none" => true,
        _ => {
            // Whitespace-insensitive matches for the common empty shapes: an empty
            // vector `vec {}`, an opt wrapping one `opt vec {}`, and a "none" variant.
            let no_ws: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
            matches!(no_ws.as_str(), "vec{}" | "optvec{}")
                || no_ws.eq_ignore_ascii_case("variant{none}")
        }
    }
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

    // "Prefer OQL": call_canister must reject QUERY calls on an OQL canister (so
    // reads go through the dedicated OQL tools) while letting UPDATE calls and any
    // call on a non-OQL / unreadable interface pass through.
    #[test]
    fn oql_query_redirect_blocks_only_query_calls_on_oql_canisters() {
        use super::oql_query_redirect;
        let oql = "service : { schema : () -> (text) query; execute : (text) -> (text) query; }";
        let plain = "service : { stats : () -> (text) query; }";

        // Query call on an OQL canister → redirected, and the message names the
        // full guide→schema→query path (#5) plus the auth hint.
        let msg = oql_query_redirect(Some(oql), true).expect("query on OQL canister must be redirected");
        assert!(msg.contains("icp_oql_guide"), "message must point to the OQL guide: {msg}");
        assert!(msg.contains("get_canister_oql_schema"), "message must point to the OQL schema tool: {msg}");
        assert!(msg.contains("run_canister_oql_query"), "message must point to the OQL query tool: {msg}");
        assert!(msg.contains("derivation_origin"), "message must carry the auth hint (pass the origin): {msg}");

        // Update call on the SAME canister proceeds (OQL is read-only).
        assert!(oql_query_redirect(Some(oql), false).is_none(), "update calls must pass through");

        // Query call on a non-OQL canister proceeds.
        assert!(oql_query_redirect(Some(plain), true).is_none(), "non-OQL query must pass through");

        // Unknown / unreadable interface can't be classified → fail open (no block).
        assert!(oql_query_redirect(None, true).is_none(), "unreadable interface must not block");
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

    // #1: the anonymous-empty auth note names the missing-auth diagnosis and the
    // fix (add the origin), carries the `add_hint` verbatim, and does NOT bake in a
    // concrete origin the tool guessed — it stays a placeholder the agent fills.
    #[test]
    fn anonymous_empty_note_is_actionable_and_origin_free() {
        use super::anonymous_empty_note;
        let note = anonymous_empty_note("this query", "the app's `derivation_origin`");
        assert!(note.contains("anonymous"), "must name the anonymous read: {note}");
        assert!(note.to_lowercase().contains("not authenticated"), "must name the likely cause: {note}");
        assert!(note.contains("this query"), "must echo `what`: {note}");
        assert!(note.contains("the app's `derivation_origin`"), "must echo `add_hint`: {note}");
        // Never a fabricated origin — only the placeholder hint.
        assert!(!note.contains("https://"), "must not bake in a concrete origin: {note}");
    }

    // #1: an anonymous OQL schema with no entities is recognized as empty (an auth
    // artifact), while a populated schema and an unrecognizable shape are NOT (so we
    // never raise a false auth hint).
    #[test]
    fn oql_schema_is_empty_detects_only_empty_entities() {
        use super::oql_schema_is_empty;
        assert!(oql_schema_is_empty(r#"{"entities":[]}"#), "empty entities → empty");
        assert!(
            oql_schema_is_empty("{\n  \"entities\": []\n}"),
            "pretty-printed empty entities → empty"
        );
        assert!(!oql_schema_is_empty(r#"{"entities":[{"name":"bookings"}]}"#), "populated → not empty");
        assert!(!oql_schema_is_empty("not json"), "unparseable → not treated as empty");
        assert!(!oql_schema_is_empty("{}"), "no entities key → not treated as empty");
    }

    // #7/#8: entity names are extracted in order, de-duplicated, and capped; a
    // missing/garbage schema yields none.
    #[test]
    fn oql_entity_names_extracts_dedups_and_caps() {
        use super::{oql_entity_names, MAX_OQL_ENTITIES};
        let names = oql_entity_names(
            r#"{"entities":[{"name":"bookings"},{"name":"users"},{"name":"bookings"}]}"#,
        );
        assert_eq!(names, vec!["bookings", "users"], "in order, de-duplicated");
        assert!(oql_entity_names("garbage").is_empty(), "garbage → none");
        assert!(oql_entity_names("{}").is_empty(), "no entities → none");
        // Cap: a schema with more entities than the cap is trimmed.
        let many: String = (0..(MAX_OQL_ENTITIES + 10))
            .map(|i| format!("{{\"name\":\"e{i}\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let capped = oql_entity_names(&format!("{{\"entities\":[{many}]}}"));
        assert_eq!(capped.len(), MAX_OQL_ENTITIES, "entity list is capped");
    }

    // #7: the query's `start` entity is extracted for validation.
    #[test]
    fn oql_query_start_extracts_start() {
        use super::oql_query_start;
        assert_eq!(oql_query_start(r#"{"start":"bookings","limit":10}"#).as_deref(), Some("bookings"));
        assert_eq!(oql_query_start(r#"{"limit":10}"#), None, "no start → None");
        assert_eq!(oql_query_start("not json"), None, "garbage → None");
    }

    // #7: "did you mean?" resolves case, plural/singular, and small typos — and
    // refuses to suggest an unrelated entity.
    #[test]
    fn closest_entity_repairs_near_misses_only() {
        use super::closest_entity;
        let entities = vec!["bookings".to_string(), "users".to_string(), "appointments".to_string()];
        // The motivating case: singular guess → plural entity.
        assert_eq!(closest_entity("booking", &entities).as_deref(), Some("bookings"));
        // Case-insensitive exact.
        assert_eq!(closest_entity("Users", &entities).as_deref(), Some("users"));
        // Small typo within threshold.
        assert_eq!(closest_entity("userz", &entities).as_deref(), Some("users"));
        // Nothing close → no suggestion (don't send the agent to a wrong entity).
        assert_eq!(closest_entity("invoices", &entities), None);
    }

    // #8: one COMPLETE run_canister_oql_query per entity, each preserving the
    // identity the schema was read under (derivation_origin + account), so copying
    // an example doesn't silently drop back to anonymous.
    #[test]
    fn oql_query_examples_are_complete_and_preserve_identity() {
        use super::oql_query_examples;
        let schema = r#"{"entities":[{"name":"bookings"},{"name":"users"}]}"#;
        let ex = oql_query_examples("aaaaa-aa", schema, Some("https://app.example.com"), Some("work"));
        assert_eq!(ex.len(), 2, "one example per entity");
        assert!(ex[0].starts_with("run_canister_oql_query "), "names the tool: {}", ex[0]);
        assert!(ex[0].contains("aaaaa-aa"), "carries the canister id: {}", ex[0]);
        assert!(ex[0].contains("bookings"), "uses the entity as start: {}", ex[0]);
        assert!(ex[0].contains("https://app.example.com"), "preserves derivation_origin: {}", ex[0]);
        assert!(ex[0].contains("work"), "preserves account: {}", ex[0]);
        // Anonymous schema read → examples carry no identity args (stay anonymous).
        let anon = oql_query_examples("aaaaa-aa", schema, None, None);
        assert!(!anon[0].contains("derivation_origin"), "no origin when read anonymously: {}", anon[0]);
        // No entities → no examples.
        assert!(oql_query_examples("aaaaa-aa", "{}", None, None).is_empty());

        // Escaping: an entity name with a quote/backslash (the schema is
        // canister-supplied, hence untrusted) must still yield a VALID-JSON example.
        // The example line is `run_canister_oql_query <json-args>`; the `query` arg
        // is itself a JSON-object string — both must parse.
        let weird = r#"{"entities":[{"name":"we\"ird"}]}"#;
        let wex = oql_query_examples("aaaaa-aa", weird, None, None);
        assert_eq!(wex.len(), 1);
        let args_json = wex[0].strip_prefix("run_canister_oql_query ").expect("tool prefix");
        let args: serde_json::Value = serde_json::from_str(args_json).expect("args must be valid JSON");
        let query = args.get("query").and_then(|q| q.as_str()).expect("query string");
        let parsed: serde_json::Value = serde_json::from_str(query).expect("query must be valid JSON");
        assert_eq!(parsed.get("start").and_then(|s| s.as_str()), Some("we\"ird"), "entity name round-trips");
    }

    // #1: the conservative empty-reply detector recognizes the unambiguous empties
    // (used only to attach the anonymous-read auth hint on a call_canister query),
    // and never flags a reply with real content.
    #[test]
    fn candid_reply_is_empty_is_conservative() {
        use super::candid_reply_is_empty;
        assert!(candid_reply_is_empty("()"));
        assert!(candid_reply_is_empty("(null)"));
        assert!(candid_reply_is_empty("(vec {})"));
        assert!(candid_reply_is_empty("(vec{})"));
        assert!(candid_reply_is_empty("(opt vec {})"));
        assert!(candid_reply_is_empty("(variant { none })"));
        // Real content is never "empty".
        assert!(!candid_reply_is_empty("(vec { record { id = 1 } })"));
        assert!(!candid_reply_is_empty("(record { balance = 5 : nat })"));
        assert!(!candid_reply_is_empty("(opt record { a = 1 })"));
        assert!(!candid_reply_is_empty("(\"some text\")"));
        // An explicit error variant is a real error, NOT "empty" — so it must not
        // trip the anonymous-read auth hint (only `variant { none }` counts).
        assert!(!candid_reply_is_empty("(variant { err = \"not found\" })"));
        assert!(!candid_reply_is_empty("(variant { error = \"nope\" })"));
    }
}
