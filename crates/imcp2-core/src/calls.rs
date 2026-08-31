//! The direct canister-call layer: `get_canister_candid` (read a canister's Candid
//! interface), `get_canister_oql_schema` (its OQL entity/field catalogue),
//! `canister_query` (a read: a Candid query method OR an OQL query), and
//! `canister_update_call` (invoke an update method). The LLM only ever deals with
//! textual Candid — the binary encoding/decoding against a method's declared types
//! happens here, and the `.did` interface is resolved from the canister's own
//! `candid:service` metadata (or a caller-supplied definition).
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
    /// `oql://usage` resource) to learn the JSON query dialect, then call
    /// `get_canister_oql_schema` for the entity/field names and `canister_query`
    /// (its `oql` argument) to run the query.
    pub oql: bool,
    /// True when the canister declares an API-documentation method
    /// (`getApiDoc`/`get_api_doc`) — computed with the SAME predicate
    /// get_canister_api_doc uses, so it tells you up front whether that call has a
    /// method to read at all. It reports the declaration, not the outcome: the call
    /// can still reject or trap. False means no compatible method was DETECTED — the
    /// same predicate also comes up empty when the published interface cannot be
    /// parsed or exceeds the parser's limits, and `candid` here is accepted as any
    /// UTF-8 text — so it is not proof that the canister has no doc, though for most
    /// canisters the Candid types are indeed the whole interface.
    pub api_doc_available: bool,
}

/// Arguments for `get_canister_oql_schema`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OqlSchemaArgs {
    /// Canister principal that exposes the OQL surface (get_canister_candid reports
    /// `oql: true`).
    pub canister_id: String,
    /// The app's canonical Internet Identity derivation origin (not necessarily the
    /// visible URL), which this read is made as the user's account at. Accepts the
    /// legacy name `domain`. Required in practice: this server rejects a read with no
    /// origin, with guidance, rather than calling `schema` anonymously and returning
    /// an empty catalogue. That is the connector's own rule — it is not a claim that
    /// the canister gates its schema by caller. Optional in the type only, so that
    /// omitting it produces that guidance rather than a bare schema-validation
    /// failure.
    #[serde(default, alias = "domain")]
    pub derivation_origin: Option<String>,
    /// Which of your accounts to act as (see list_app_accounts). Omit to use that
    /// app's default account.
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
    /// The principal the read was signed as — the user's account at the app, since
    /// this read is always made as one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acted_as_principal: Option<String>,
    /// The effective Internet Identity derivation origin used, after
    /// canonicalization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_for_origin: Option<String>,
    /// Exactly what you supplied as `derivation_origin`, echoed so a mismatch with
    /// `derived_for_origin` (from canonicalization) is visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    /// Whether the schema was read as the ANONYMOUS principal. Always false here,
    /// because a read with no `derivation_origin` is rejected rather than made
    /// anonymously; the field keeps the same shape as the other tools' replies,
    /// where an anonymous read is possible.
    pub is_anonymous: bool,
    /// A note when the schema came back with NO entities: this principal can see no
    /// entities here. Null when entities were returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// One ready-to-run `canister_query` invocation per entity — a COMPLETE call
    /// (canister_id + a minimal `{start, limit}` OQL query in the `oql` argument) that
    /// PRESERVES the identity this schema was read under (same
    /// `derivation_origin`/`account`), so copying an example keeps that identity
    /// rather than losing the origin the OQL path requires — which would be
    /// rejected, not run anonymously. Read-only. Empty when the schema exposes no
    /// entities.
    pub example_queries: Vec<String>,
}

/// Output of `icp_oql_guide`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct OqlGuideOutput {
    /// The OQL usage guide (markdown): the `schema`/`execute` methods, the JSON
    /// query object, the predicate grammar, edges, and the result shape.
    pub content: String,
}

/// Arguments for `get_canister_api_doc`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ApiDocArgs {
    /// Canister principal to read the API documentation from.
    pub canister_id: String,
}

/// Output of `get_canister_api_doc` — every documentation outcome is STRUCTURED
/// (not an error when the doc simply isn't there), so the agent can distinguish
/// "no compatible method was detected" (expected, don't retry) from "no answer
/// was obtained" (a retry may help). The first is not proof of absence: the same
/// detection comes up empty on an interface the parser cannot read. An unusable
/// `canister_id` is rejected before any lookup and is a plain error, not this
/// shape.
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
    /// When `available` is false: whether this is the EXPECTED outcome — no
    /// compatible api-doc method was detected in the interface text, which is the
    /// normal case (most canisters declare none). True does NOT prove the canister
    /// declares one nowhere: the same detection returns nothing for an interface that
    /// was fetched but could not be parsed, or that exceeded the parser's limits, and
    /// that path sets true as well. False when no answer was obtained at all (the
    /// interface could not be FETCHED, or the call failed). Meaningless when
    /// `available`.
    pub expected: bool,
    /// When `available` is false: whether retrying might help. False when no
    /// compatible method was detected in the interface text — retrying will not
    /// change that reading, whether the canister declares none or the parser could
    /// not read what it declares. True when no answer was obtained — either the
    /// Candid interface could not be FETCHED, so whether a doc method exists is
    /// unknown, or the call to a declared method did not return. That covers a
    /// transient failure, but also a rejection or trap from the canister, which no
    /// retry will change. Meaningless when `available`.
    pub retry: bool,
    /// What to do next — e.g. "use get_canister_candid for the interface" when there
    /// is no doc, or "retry" on a transient failure. Null when `available`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

/// Arguments for `canister_update_call`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CanisterUpdateCallArgs {
    /// Target canister principal.
    pub canister_id: String,
    /// Update method name to invoke.
    pub method: String,
    /// Arguments in textual Candid syntax, e.g. `()` or `(record { owner = principal "..." })`.
    #[serde(default = "default_args")]
    pub args: String,
    /// Call as the user's account at an app, identified by its exact canonical
    /// Internet Identity derivation origin — not necessarily the visible URL, and
    /// not an alternativeOrigins entry. open_app and resolve_app resolve an app
    /// name or URL to it under the guessed-domain gate. This does not accept a raw
    /// website URL — a derivation origin is a stable per-app value. Accepts the
    /// legacy name `domain`. Omitted, the call is anonymous. The account
    /// delegation is derived on demand for this connection.
    #[serde(default, alias = "domain")]
    pub derivation_origin: Option<String>,
    /// Which of your accounts to act as, by account name (see list_app_accounts).
    /// Omit to use that app's default account. Ignored for anonymous calls.
    #[serde(default)]
    pub account: Option<String>,
    /// Optional Candid service definition (`.did` text) for the canister. Used to
    /// encode the args to the method's declared types and decode the reply, for
    /// when the canister's own `candid:service` metadata can't be read (e.g.
    /// access-restricted); get_canister_candid returns it when the canister
    /// publishes it.
    #[serde(default)]
    pub candid: Option<String>,
}

/// Output of `canister_update_call`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CanisterUpdateCallOutput {
    /// The canister that was called.
    pub canister_id: String,
    /// The method that was invoked.
    pub method: String,
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
    /// Always present so a text-only client can tell an anonymous call from an
    /// authenticated one.
    pub is_anonymous: bool,
}

/// Arguments for `canister_query` — a READ that runs EITHER a Candid `query` method
/// OR an OQL query. Provide exactly one of `method` (a query function from the
/// canister's Candid interface) or `oql` (an OQL query object).
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CanisterQueryArgs {
    /// Target canister principal.
    pub canister_id: String,
    /// A `query` method name from the canister's Candid interface, invoked as a
    /// read-only query call. Exactly one of `method` (a Candid query) and `oql` (an
    /// OQL query) is accepted. On a canister that exposes an OQL query surface
    /// (get_canister_candid reports `oql: true`), data reads are rejected on this
    /// path; `oql` is that canister's read path.
    #[serde(default)]
    pub method: Option<String>,
    /// Arguments for `method` in textual Candid syntax, e.g. `()` or
    /// `(record { owner = principal "..." })`. Ignored for an OQL query.
    #[serde(default = "default_args")]
    pub args: String,
    /// An OQL query as a JSON object string — passed straight to the canister's
    /// `execute` method, so no Candid escaping is needed (plain JSON). E.g.
    /// `{"start":"employee","where":{"icontains":{"field":"lastName","value":"smith"}},"select":["firstName","lastName"],"limit":10}`.
    /// Exactly one of `oql` and `method` is accepted. icp_oql_guide documents the
    /// dialect and get_canister_oql_schema returns the entity/field names.
    /// The OQL path requires `derivation_origin` (anonymous per-app reads are disabled).
    #[serde(default)]
    pub oql: Option<String>,
    /// Read as the user's account at an app, given its exact canonical Internet
    /// Identity derivation origin — not necessarily the visible URL. open_app and
    /// resolve_app resolve it; this does not accept a raw website URL. Accepts the
    /// legacy name `domain`. Required for an `oql` query; optional for a Candid
    /// `method` query (omitted, the query is anonymous).
    #[serde(default, alias = "domain")]
    pub derivation_origin: Option<String>,
    /// Which of your accounts to act as, by account name (see list_app_accounts).
    /// Omit to use that app's default account. Ignored for anonymous calls.
    #[serde(default)]
    pub account: Option<String>,
    /// Optional Candid service definition (`.did` text) for the canister. Used to
    /// encode the args to a Candid `method`'s declared types and decode the reply,
    /// for when the canister's own `candid:service` metadata can't be read;
    /// get_canister_candid returns it when the canister publishes it. Ignored for
    /// an OQL query.
    #[serde(default)]
    pub candid: Option<String>,
}

/// Output of `canister_query`. The populated fields depend on `mode`: a Candid
/// `method` query sets `method` + `reply`; an `oql` query sets `columns` + `rows`
/// (+ `has_more`). `valid_entities` and `did_you_mean` are optional even on an
/// empty result: they appear only when the schema re-read returns entities and the
/// query's `start` is not one of them.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CanisterQueryOutput {
    /// The canister that was queried.
    pub canister_id: String,
    /// Which query path ran: "candid" (a Candid `query` method) or "oql" (an OQL query).
    pub mode: String,
    /// (candid mode) the query method invoked. Null for an OQL query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// (candid mode) the decoded reply in textual Candid. Null for an OQL query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
    /// (oql mode) column names, in order (the cell `name`s of the first row). Empty
    /// for a Candid query.
    #[serde(default)]
    pub columns: Vec<String>,
    /// (oql mode) result rows, each aligned to `columns`, with cell values rendered
    /// as scalars. Empty for a Candid query.
    #[serde(default)]
    pub rows: Vec<Vec<String>>,
    /// (oql mode) true when more rows remain — re-query with a higher `offset` to page.
    #[serde(default)]
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
    /// When querying as an app account: how `derived_for_origin` was determined —
    /// always "explicit" here (this tool takes the canonical derivation origin
    /// directly). Null for anonymous queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_origin_source: Option<String>,
    /// True when the query ran as the ANONYMOUS principal (no `derivation_origin`).
    /// Always present so a text-only client can tell an anonymous read from an
    /// authenticated one even on an empty result: where an app does gate its data by
    /// caller, an anonymous empty result means "not authenticated" rather than "no
    /// data", and this flag is what lets a client tell the two apart. It does not
    /// establish that the canister gates anything.
    pub is_anonymous: bool,
    /// A diagnostic note for an EMPTY result: the anonymous-read auth remediation
    /// (#1), an unknown-`start` repair (#7, oql mode), or a note that the query
    /// matched nothing for the authenticated principal. Null when data was returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// (oql mode) when an empty result was diagnosed as an unknown `start` entity:
    /// the entities actually visible to this caller (validated against the schema for
    /// the SAME principal). Null unless that diagnosis fired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_entities: Option<Vec<String>>,
    /// (oql mode) the closest valid entity to an unknown `start` (e.g. "booking" →
    /// "bookings"). Null unless an unknown-`start` diagnosis found a near match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_you_mean: Option<String>,
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
/// Maximum number of `type` declarations in caller-supplied `.did` text.
///
/// [`MAX_CANDID_DEPTH`] measures INLINE nesting only, so it cannot see the
/// recursion a chain of sibling aliases forces:
/// `type t0 = opt t1; type t1 = opt t2; …` is flat — every alias is depth 1, and
/// the prefix frame pops at the `;` — yet resolving `t0` recurses once per link.
/// `candid_parser`'s type checker and `candid`'s type-table serializer both walk
/// that chain without a depth limit of their own, so within
/// [`MAX_CANDID_TEXT_BYTES`] an attacker packs tens of thousands of links and
/// drives an unrecoverable stack-overflow **process abort** (CWE-674). Measured
/// on a release build: ~10k links overflow a 2 MiB tokio worker stack. Checking
/// the chain is also QUADRATIC — 1k links ≈ 125 ms, 8k ≈ 10 s, so an interface
/// that fits the byte cap can burn minutes of CPU before it ever overflows.
///
/// 1024 bounds both: ~125 ms of checking, and a resolution depth ~90× below what
/// [`CANDID_PARSE_STACK_BYTES`] absorbs. Real interfaces are far smaller — NNS
/// governance, the largest in common use, declares under 200 types.
pub(crate) const MAX_CANDID_TYPE_DECLS: usize = 1024;

/// Stack given to the thread that parses untrusted textual Candid. Tool handlers
/// run on tokio worker threads with a 2 MiB stack; 32× that is a wide margin —
/// thousands of times the depth [`guard_candid_text`] admits — though with input
/// capped at [`MAX_CANDID_TEXT_BYTES`] it is a margin, not a proof. Virtual, so an
/// idle mapping costs no resident memory.
const CANDID_PARSE_STACK_BYTES: usize = 64 * 1024 * 1024;

/// Deep-stack parse threads allowed to be alive at once, per core (min 4). These
/// parses are CPU-bound, and running them inline on the tokio workers already
/// capped them at roughly one per core; the permit restores that ceiling instead
/// of letting untrusted traffic multiply threads — and 64 MiB stack mappings —
/// with request concurrency. Waiting for a permit blocks the caller exactly as a
/// busy worker used to, and every parse is bounded by [`MAX_CANDID_TEXT_BYTES`]
/// and [`MAX_CANDID_DEPTH`], so the queue always drains.
const CANDID_PARSE_THREADS_PER_CORE: usize = 1;

/// Free deep-stack parse permits, and the condvar sleepers wait on.
fn candid_parse_permits() -> &'static (std::sync::Mutex<usize>, std::sync::Condvar) {
    static PERMITS: std::sync::OnceLock<(std::sync::Mutex<usize>, std::sync::Condvar)> =
        std::sync::OnceLock::new();
    PERMITS.get_or_init(|| {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        let limit = (cores * CANDID_PARSE_THREADS_PER_CORE).max(4);
        (std::sync::Mutex::new(limit), std::sync::Condvar::new())
    })
}

/// Holds one [`candid_parse_permits`] slot; returns it on drop, including while
/// unwinding from a parser panic.
struct CandidParsePermit;

impl CandidParsePermit {
    /// Block until a slot is free, then take it.
    fn acquire() -> Self {
        let (free, wakeup) = candid_parse_permits();
        // The critical sections below cannot panic, so the lock cannot be poisoned.
        let mut free = free.lock().expect("candid parse permits poisoned");
        while *free == 0 {
            free = wakeup.wait(free).expect("candid parse permits poisoned");
        }
        *free -= 1;
        Self
    }
}

impl Drop for CandidParsePermit {
    fn drop(&mut self) {
        let (free, wakeup) = candid_parse_permits();
        *free.lock().expect("candid parse permits poisoned") += 1;
        wakeup.notify_one();
    }
}

/// Run `f` — a parse of untrusted textual Candid, plus everything done with the
/// resulting AST before it is dropped — on a dedicated thread with a
/// [`CANDID_PARSE_STACK_BYTES`] stack, at most
/// [`CANDID_PARSE_THREADS_PER_CORE`]-per-core of them at a time. `None` only if
/// that thread can't be spawned (resource exhaustion); callers then degrade
/// exactly as they do for input they can't parse, and never fall back to parsing
/// on the caller's small stack.
///
/// Defense in depth behind [`guard_candid_text`] (CWE-674). A stack overflow is an
/// uncatchable process abort that would drop every concurrent session, and
/// `candid_parser`'s parse / type-check / `Display` / `Drop` passes all recurse
/// unguarded, so the depth limit must never be the only thing standing between a
/// hostile input and the guard page: should the scanner ever mis-measure a value,
/// the parse still has to run thousands of levels deep before it can hurt anyone.
///
/// The permit is held by the CALLING thread for the whole call, so these must not
/// nest: an `f` that itself calls `on_deep_stack` could exhaust the permits and
/// wait on itself. Every current caller parses directly instead.
pub(crate) fn on_deep_stack<T: Send>(f: impl FnOnce() -> T + Send) -> Option<T> {
    let _permit = CandidParsePermit::acquire();
    let mut out = None;
    let mut panicked = None;
    std::thread::scope(|scope| {
        let slot = &mut out;
        let spawned = std::thread::Builder::new()
            .name("candid-parse".into())
            .stack_size(CANDID_PARSE_STACK_BYTES)
            .spawn_scoped(scope, move || *slot = Some(f()));
        if let Ok(handle) = spawned {
            if let Err(payload) = handle.join() {
                panicked = Some(payload);
            }
        }
    });
    // A panic inside `f` must surface on the caller's thread exactly as it would
    // have without this helper — not be silently laundered into `None`.
    if let Some(payload) = panicked {
        std::panic::resume_unwind(payload);
    }
    out
}

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
/// are skipped so their contents can't inflate the count, and comments are skipped
/// exactly as the lexer skips them (see [`skip_trivia`] — a `"` inside a comment
/// must NOT open a string, or the scan would desynchronize from the parser and
/// under-count). It is a conservative over-approximation that tracks the parser's
/// container recursion without under-counting nested `opt`/`vec`/bracket levels.
///
/// Inline depth is not the whole story: a `.did` can force recursion that is
/// nowhere visible in its nesting, by chaining sibling type aliases. So the scan
/// also counts `type` declarations and holds them to [`MAX_CANDID_TYPE_DECLS`],
/// which bounds the longest possible alias chain. Counting the bare word is exact
/// — Candid lexes `type` as a keyword, never an identifier, so it cannot appear as
/// a field name (`record { type : nat }` is a syntax error); the quoted form
/// `record { "type" : nat }` is a string literal, which the scan already skips.
pub(crate) fn guard_candid_text(what: &str, text: &str) -> Result<(), String> {
    if text.len() > MAX_CANDID_TEXT_BYTES {
        return Err(format!(
            "{what} is too large to parse ({} bytes; limit {MAX_CANDID_TEXT_BYTES})",
            text.len()
        ));
    }
    // Frames: b'B' = bracket group, b'P' = pending opt/vec prefix awaiting its value.
    let mut stack: Vec<u8> = Vec::new();
    // `type` declarations seen so far — an upper bound on the alias-chain length,
    // and so on the recursion resolving one costs (see MAX_CANDID_TYPE_DECLS).
    let mut type_decls = 0usize;
    let bytes = text.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    // Pop the prefix frames waiting on a value that has just completed.
    fn resolve_prefixes(stack: &mut Vec<u8>) {
        while stack.last() == Some(&b'P') {
            stack.pop();
        }
    }
    // The next significant (non-trivia) byte at/after `j` — used to tell
    // `record {` from a leaf, so an interposed comment can't hide the `{`.
    let peek_significant = |j: usize| -> Option<u8> { bytes.get(skip_trivia(bytes, j)).copied() };
    let mut i = 0;
    while i < bytes.len() {
        // Whitespace and comments carry no structure and never complete a value.
        i = skip_trivia(bytes, i);
        let Some(&c) = bytes.get(i) else { break };
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
                if word == b"type" {
                    type_decls += 1;
                    if type_decls > MAX_CANDID_TYPE_DECLS {
                        return Err(format!(
                            "{what} declares too many types (limit \
                             {MAX_CANDID_TYPE_DECLS}) — refusing to parse"
                        ));
                    }
                }
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

/// Advance past everything `candid_parser`'s lexer treats as trivia — whitespace
/// and comments — returning the index of the next significant byte (or
/// `bytes.len()`). Candid has BOTH `//` line comments (to the next `\n`, or EOF)
/// and `/* … */` block comments, which **nest**; the lexer skips them in the value
/// and `.did` grammars alike.
///
/// [`guard_candid_text`] MUST skip them the same way. The scanner treats a `"` as
/// the start of a string literal whose contents it ignores, so a quote hidden in a
/// comment — `//"` — would otherwise make the guard swallow all the structure that
/// follows (depth stays 0, `Ok`) while the parser, which drops the comment, goes on
/// to parse the arbitrarily deep value after it: an unrecoverable stack-overflow
/// process abort (CWE-674). Any divergence must err toward over-counting, never
/// under-counting; an unclosed comment simply runs to EOF here, and the parser
/// rejects it as a lexical error anyway.
fn skip_trivia(bytes: &[u8], mut j: usize) -> usize {
    loop {
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        match (bytes.get(j), bytes.get(j + 1)) {
            (Some(b'/'), Some(b'/')) => {
                j += 2;
                while j < bytes.len() && bytes[j] != b'\n' {
                    j += 1;
                }
            }
            (Some(b'/'), Some(b'*')) => {
                // Mirrors the lexer's nesting counter: `/*` opens, `*/` closes.
                j += 2;
                let mut depth = 1usize;
                while depth > 0 && j < bytes.len() {
                    match (bytes[j], bytes.get(j + 1)) {
                        (b'/', Some(b'*')) => {
                            depth += 1;
                            j += 2;
                        }
                        (b'*', Some(b'/')) => {
                            depth -= 1;
                            j += 2;
                        }
                        _ => j += 1,
                    }
                }
            }
            // A lone `/` is not a Candid token at all (the parser errors on it);
            // leave it to the caller as a significant byte.
            _ => return j,
        }
    }
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
    on_deep_stack(|| {
        let parsed = candid_parser::parse_idl_args(args_text)
            .map_err(|e| format!("could not parse args `{args_text}`: {e}"))?;
        if let Some(did) = did.filter(|d| guard_candid_text("the `candid` interface", d).is_ok()) {
            if let Ok((env, Some(actor))) = candid_parser::utils::CandidSource::Text(did).load() {
                if let Ok(func) = env.get_method(&actor, method) {
                    return parsed.to_bytes_with_types(&env, &func.args).map_err(|e| {
                        format!("args don't match `{method}`'s Candid signature: {e}")
                    });
                }
            }
        }
        parsed
            .to_bytes()
            .map_err(|e| format!("could not encode args `{args_text}`: {e}"))
    })
    .unwrap_or_else(|| Err("could not spawn a thread to parse the `args` value".into()))
}

/// Candid's per-value decoding-cost budget for an untrusted canister reply (a
/// candid `DecoderConfig` quota — [`reply_decoder_config`]). The caller picks the
/// target canister, so the reply bytes are attacker-controlled (CWE-789): a
/// zero-byte element type lets a tiny reply declare an astronomical element count
/// (`vec null` × 4e7 in ~13 wire bytes, or far more via nesting), and decoding it
/// drives a multi-gigabyte allocation and an UNCATCHABLE `handle_alloc_error`/OOM
/// abort that drops every concurrent session (ICPBB-438) — `on_deep_stack` recovers
/// panics, not aborts.
///
/// candid charges this quota per decoded value, so the bound is ABSOLUTE: nesting
/// or padding the wire cannot raise it, and exceeding it returns the ordinary
/// "reply is not decodable" error instead of aborting. The worst case is the
/// zero-byte `vec null` path (~3 cost + ~48 B allocated per element with no
/// pre-sizing), so this cap keeps a rejected bomb's transient allocation to ~tens
/// of MB, while leaving realistic replies — orders of magnitude smaller — untouched.
/// A reply legitimately carrying >~1M decoded values would render to unusable
/// megabytes of text anyway; raise this if that ever becomes a real need.
const REPLY_DECODING_QUOTA: usize = 3_000_000;

/// A [`candid::DecoderConfig`] carrying [`REPLY_DECODING_QUOTA`] for both the
/// decoding and skipping counters, applied to every decode of untrusted reply bytes.
fn reply_decoder_config() -> candid::DecoderConfig {
    let mut cfg = candid::DecoderConfig::new();
    cfg.set_decoding_quota(REPLY_DECODING_QUOTA)
        .set_skipping_quota(REPLY_DECODING_QUOTA);
    cfg
}

/// Decode reply `bytes` to textual Candid. With `did`, decode against the
/// method's declared return types so record/variant field names are recovered;
/// otherwise (or on any failure) fall back to type-less decoding.
pub fn decode_reply(did: Option<&str>, method: &str, bytes: &[u8]) -> String {
    if let Some(text) = did.and_then(|d| decode_bytes_with_did(d, method, bytes)) {
        return text;
    }
    // Type-less fallback, run on the deep stack (CWE-674). The reply bytes are
    // attacker-controlled (the caller picks the target canister). candid's decoder
    // recurses once per nesting level, but that recursion is DEPTH-BOUNDED by
    // candid's own `stacker::remaining_stack()` guard: a recursive reply
    // (`type t = opt t` — a chain of one-byte `opt` tags) makes it return the
    // ordinary "not decodable" error before the stack is exhausted, on any stack
    // size; it does NOT overflow and abort the process (regression-pinned by
    // `decode_reply_rejects_a_deep_opt_chain_instead_of_aborting`). So
    // `REPLY_DECODING_QUOTA` bounds breadth and candid's guard bounds depth. The
    // deep stack is kept as defense-in-depth: it hands that guard generous headroom
    // and room to render (`Display`) and drop the decoded — already depth-bounded —
    // tree, both of which also recurse per level. Not nested: the DID path's
    // `on_deep_stack` has already returned by the time we reach here, and only the
    // rendered `String` crosses back.
    on_deep_stack(|| match IDLArgs::from_bytes_with_config(bytes, &reply_decoder_config()) {
        Ok(decoded) => decoded.to_string(),
        Err(e) => format!("(call succeeded but reply is not decodable as Candid: {e})"),
    })
    .unwrap_or_else(|| "(could not spawn a thread to decode the reply)".to_string())
}

/// Decode Candid `bytes` against the return types of `method` declared in the
/// `.did` text, recovering record/variant field names. None if the interface
/// can't be parsed, the method isn't found, or decoding fails.
pub fn decode_bytes_with_did(did: &str, method: &str, bytes: &[u8]) -> Option<String> {
    // Skip (fall back to type-less decoding) if the interface is too large/nested
    // to parse safely (CWE-674).
    guard_candid_text("the `candid` interface", did).ok()?;
    on_deep_stack(|| {
        let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
        let actor = actor?;
        let func = env.get_method(&actor, method).ok()?;
        let decoded = IDLArgs::from_bytes_with_types_with_config(bytes, &env, &func.rets, &reply_decoder_config()).ok()?;
        Some(decoded.to_string())
    })
    .flatten()
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
    on_deep_stack(|| {
        let Ok((env, Some(actor))) = candid_parser::utils::CandidSource::Text(did).load() else {
            return false;
        };
        env.get_method(&actor, "schema").is_ok() && env.get_method(&actor, "execute").is_ok()
    })
    .unwrap_or(false)
}

/// Whether `method` is callable as a Candid `query` in `did`: `Some(true)` for a
/// query (or composite-query) method, `Some(false)` for an update method, `None`
/// when the interface can't be parsed or the method isn't declared. Used by
/// `canister_query` to reject a Candid `method` query on an UPDATE method up front
/// (the replica rejects a query call to a non-query method) with a clear pointer to
/// `canister_update_call`, instead of an opaque runtime error.
///
/// `None` means "can't tell" — the caller fails OPEN (proceeds and lets the IC
/// decide), so an unreadable/over-limit interface never blocks a call. Guarded
/// (CWE-674) and fail-closed like [`has_oql`]: untrusted `.did` text runs through
/// [`guard_candid_text`] before `candid_parser` parses it.
pub fn is_query_method(did: &str, method: &str) -> Option<bool> {
    if guard_candid_text("the `candid` interface", did).is_err() {
        return None;
    }
    on_deep_stack(|| {
        let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
        let actor = actor?;
        let func = env.get_method(&actor, method).ok()?;
        Some(func.is_query())
    })
    .flatten()
}

/// Enforce "prefer OQL": when a canister exposes an OQL query surface, its data
/// must be READ with an OQL query (`canister_query`'s `oql` argument), not a raw
/// Candid `method` query call. Returns the guidance message to hand back when a
/// Candid `method` query should be redirected, or `None` when it may proceed.
///
/// Called only from `canister_query`'s Candid-`method` path — OQL is read-only, so
/// update calls (`canister_update_call`) never reach here and always pass through.
/// When no interface text is available (`did == None` — neither the canister's own
/// `candid:service` metadata nor a caller-supplied `candid`), OQL can't be
/// detected, so the call passes through too (fail open: never block a call we
/// can't classify).
pub fn oql_query_redirect(did: Option<&str>) -> Option<String> {
    if did.is_some_and(has_oql) {
        Some(
            "this canister exposes an OQL query surface, so its data is READ with an OQL query, \
             NOT a raw Candid `method` query call. Do this instead, in order: (1) `icp_oql_guide` \
             for the JSON dialect (once), (2) `get_canister_oql_schema` for the entity and field \
             names, (3) call `canister_query` again with the `oql` argument (a JSON query object) \
             instead of `method`. This canister gates data by the caller's principal, so pass the \
             app's `derivation_origin` (from open_app / resolve_app) — an anonymous read is rejected. \
             UPDATE calls (state changes) go through `canister_update_call`."
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

/// Widest and tallest table [`rows_to_table`] will materialize from a reply
/// before it signals truncation (folded into `has_more`). Their product bounds
/// the dense `Vec<Vec<String>>` it builds: without a cap, a compact reply whose
/// first row declares tens of thousands of columns and that then carries
/// thousands of (even empty) rows densifies to `cols × rows` owned `String`s —
/// hundreds of MB out of an ~80 KB reply (ICPBB-384/385). The decode quota
/// (#132) does not catch this: the decoded tree stays small; the blow-up is in
/// OUR alignment loop, not candid's decoder. Real OQL pages are far smaller; a
/// larger result set is paged through `has_more` + offset, not widened here.
pub(crate) const MAX_OQL_COLUMNS: usize = 256;
pub(crate) const MAX_OQL_ROWS: usize = 1_000;

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

/// Longest name the fuzzy (edit-distance) repair will run its `O(m·n)` DP over.
/// A "did you mean?" repair only makes sense for identifier-length names, so a
/// `start` — or a (malicious) schema entity name — far longer than that is never
/// a near-miss and is skipped before the DP runs. Without this bound, an
/// attacker-sized `start` (the `oql` argument is agent-controlled) would run
/// Levenshtein against every entity and stall the async worker with pure CPU.
const MAX_FUZZY_NAME_LEN: usize = 128;

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
    // Fuzzy phase is bounded (CWE-770 / worker stall): an over-long `start` can't
    // be a typo of a short entity name, so skip the DP entirely rather than run it
    // against every entity. The exact/plural checks above already ran.
    if lc.len() > MAX_FUZZY_NAME_LEN {
        return None;
    }
    // Small edit distance, scaled to the shorter of the two names so short names
    // demand a tighter match. Pick the nearest; ties keep the first (schema order).
    let lc_chars = lc.chars().count();
    let mut best: Option<(usize, &String)> = None;
    for e in entities {
        let el = e.to_lowercase();
        let bound = (lc.len().min(el.len()) / 3).clamp(1, 3);
        // Edit distance is at least the CHARACTER-length difference, so a name
        // whose char count differs from `start` by more than the bound can never
        // qualify — skip the O(m·n) DP for it (this also caps a malicious schema's
        // over-long entity name: it can't be within `bound` of a start that passed
        // the length cap). The difference must be counted in `char`s, not bytes:
        // `levenshtein` works on `char`s, so a byte-length difference (inflated by
        // multi-byte chars) would wrongly prune a genuine near-miss.
        if lc_chars.abs_diff(el.chars().count()) > bound {
            continue;
        }
        let d = levenshtein(&lc, &el);
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

/// One ready-to-run `canister_query` invocation per entity (#8) — a COMPLETE call
/// (canister_id + a minimal `{"start":<entity>,"limit":10}` OQL query in the `oql`
/// argument) that PRESERVES the identity the schema was read under (the same
/// `derivation_origin` / `account`), so copying an example doesn't silently drop
/// back to anonymous. Read-only. Empty when the schema exposes no entities. Each
/// line is `canister_query <compact-json-args>`.
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
            // `oql` is a JSON-object STRING (that's what the tool takes). Build it
            // via serde_json (not format!) so an entity name containing a quote or
            // backslash — the schema is canister-supplied, hence untrusted — is
            // escaped and the example stays valid JSON.
            let query = serde_json::json!({ "start": entity, "limit": 10 }).to_string();
            args.insert("oql".into(), serde_json::Value::String(query));
            if let Some(o) = derivation_origin {
                args.insert("derivation_origin".into(), serde_json::Value::String(o.to_string()));
            }
            if let Some(a) = account {
                args.insert("account".into(), serde_json::Value::String(a.to_string()));
            }
            format!("canister_query {}", serde_json::Value::Object(args))
        })
        .collect()
}

/// Whether a decoded textual-Candid `reply` LOOKS empty — used only to attach the
/// #1 anonymous-read auth hint to a `canister_query` (Candid `method`) result, so it
/// must be conservative (a false "empty" would raise a spurious auth hint). Recognizes the
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
// OQL execute/schema support (for `canister_query`'s `oql` path and the
// `get_canister_oql_schema` tool). The server does not model the OQL query
// language — it wraps the JSON query as the single `text` argument `execute`
// expects (so the model never hand-escapes JSON inside a Candid text literal) and
// decodes the tabular reply.
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
    /// The reply's first row declared MORE than [`MAX_OQL_COLUMNS`] columns, so we
    /// refuse to densify a table that wide (unbounded `cols × rows` allocation,
    /// ICPBB-384/385). Distinct from row truncation on purpose: the dropped
    /// columns are chosen by the query's `select`, not by `offset`, so this is NOT
    /// pageable and must never be surfaced as `has_more`. The caller turns it into
    /// guidance to narrow `select`. Carries the actual column count for that hint.
    TooManyColumns { column_count: usize },
    /// The reply didn't match a recognizable OQL result shape; carries the raw
    /// decoded textual Candid so the caller can still surface the data.
    Unrecognized(String),
}

/// What [`rows_to_table`] made of a `rows : vec vec Cell` value. Keeps the two
/// truncation reasons apart so the caller can treat them differently: only ROW
/// truncation is pageable (→ `has_more`); a too-wide first row is refused.
enum TableOutcome {
    /// A densified table (at most [`MAX_OQL_ROWS`] rows). `rows_truncated` is true
    /// when rows past the cap were dropped — recoverable via a higher `offset`.
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
        rows_truncated: bool,
    },
    /// The first row declared `column_count` (> [`MAX_OQL_COLUMNS`]) columns.
    TooWide { column_count: usize },
}

/// Decode an `execute` reply into a table. `did` (the canister interface) is used
/// to recover field names — without it the wire format hashes them and the shape
/// generally can't be recognized, so we fall back to `Unrecognized` with the raw
/// reply rather than guessing.
pub fn parse_execute_reply(did: Option<&str>, reply: &[u8]) -> OqlResult {
    // Decode the attacker-controlled reply AND walk/render the decoded tree on the
    // deep stack (CWE-674). candid's `from_bytes*` decode recurses per nesting
    // level but is depth-bounded by candid's own `stacker::remaining_stack()` guard
    // (an over-deep reply returns "undecodable", NOT a process abort — see
    // `decode_reply_rejects_a_deep_opt_chain_instead_of_aborting`). The imcp2 walks
    // that follow — the recursive `extract_oql`/`cell_scalar`, the `Display`
    // fallback, and the tree's recursive `Drop` — recurse per level too, but only
    // over that already depth-bounded tree, with the deep stack as headroom. The
    // whole thing (creation through drop of the `IDLArgs`) stays on the deep stack;
    // only the rendered `OqlResult` (owned strings) crosses back. One
    // `on_deep_stack`, never nested: `decode_args_with_did` decodes in place.
    on_deep_stack(move || {
        let decoded = match did.and_then(|d| decode_args_with_did(d, "execute", reply)) {
            Some(args) => args,
            None => match IDLArgs::from_bytes_with_config(reply, &reply_decoder_config()) {
                Ok(args) => args,
                Err(e) => return OqlResult::Unrecognized(format!("(undecodable reply: {e})")),
            },
        };
        match decoded.args.into_iter().next() {
            Some(val) => extract_oql(&val).unwrap_or_else(|| OqlResult::Unrecognized(val.to_string())),
            None => OqlResult::Unrecognized("(empty reply)".to_string()),
        }
    })
    .unwrap_or_else(|| OqlResult::Unrecognized("(could not spawn a thread to decode the reply)".to_string()))
}

/// Decode a reply that is a single `text` value (e.g. `schema` or the API-doc
/// method): the bare string. A non-text single value falls back to its type-less
/// rendering; a reply with MORE than one value renders the whole `IDLArgs` tuple
/// (so nothing is silently dropped, even though these methods return one value by
/// contract); an undecodable reply yields an explanatory string.
pub fn decode_text_reply(reply: &[u8]) -> String {
    // Decode, match, render, and drop the attacker-controlled reply on the deep
    // stack (CWE-674). candid's `from_bytes` decode recurses per nesting level but
    // is depth-bounded by candid's own `stacker::remaining_stack()` guard (an
    // over-deep reply returns "undecodable", NOT a process abort). The `Display` of
    // a non-text single value / the whole tuple and the tree's recursive `Drop`
    // recurse per level too, but only over that already depth-bounded tree, with
    // the deep stack as headroom. Only the resulting `String` crosses back.
    on_deep_stack(|| {
        let args = match IDLArgs::from_bytes_with_config(reply, &reply_decoder_config()) {
            Ok(a) => a,
            Err(e) => return format!("(undecodable reply: {e})"),
        };
        match args.args.as_slice() {
            [] => "(empty reply)".to_string(),
            [IDLValue::Text(s)] => s.clone(),
            [single] => single.to_string(),
            _ => args.to_string(),
        }
    })
    .unwrap_or_else(|| "(could not spawn a thread to decode the reply)".to_string())
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
    on_deep_stack(|| {
        let Ok((env, Some(actor))) = candid_parser::utils::CandidSource::Text(did).load() else {
            return None;
        };
        ["getApiDoc", "get_api_doc"]
            .into_iter()
            .find(|m| env.get_method(&actor, m).is_ok())
    })
    .flatten()
}

/// Decode a reply against the declared return types of `method` in `did`,
/// returning the structured `IDLArgs` (field names recovered). None on any
/// guard/parse/decode failure.
///
/// MUST run on the deep stack: it parses the untrusted `.did` and decodes the reply,
/// both of which recurse unguarded (CWE-674), and the returned `IDLArgs` is later
/// walked and dropped by the caller. Its sole caller ([`parse_execute_reply`]) wraps
/// the whole decode-and-render in one [`on_deep_stack`], so this must NOT take its own
/// (a nested `on_deep_stack` could exhaust the parse permits and wait on itself).
fn decode_args_with_did(did: &str, method: &str, bytes: &[u8]) -> Option<IDLArgs> {
    guard_candid_text("the `candid` interface", did).ok()?;
    let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
    let actor = actor?;
    let func = env.get_method(&actor, method).ok()?;
    IDLArgs::from_bytes_with_types_with_config(bytes, &env, &func.rets, &reply_decoder_config()).ok()
}

/// Recognize an OQL result value: a `record { hasMore; rows }`, optionally
/// wrapped in a `variant { ok = … }` / `variant { err = … }`.
fn extract_oql(val: &IDLValue) -> Option<OqlResult> {
    match val {
        IDLValue::Record(fields) => {
            let rows_val = field_by_name(fields, "rows")?;
            let has_more = matches!(field_by_name(fields, "hasMore"), Some(IDLValue::Bool(true)));
            match rows_to_table(rows_val)? {
                TableOutcome::Table { columns, rows, rows_truncated } => Some(OqlResult::Table {
                    columns,
                    rows,
                    // Only ROW truncation is pageable, so only it may raise
                    // `has_more` (whose contract is "more rows — page with a higher
                    // `offset`"). Column truncation becomes TooManyColumns below:
                    // paging can't recover dropped columns, so conflating it with
                    // `has_more` would loop the agent forever on a wide final page.
                    has_more: has_more || rows_truncated,
                }),
                TableOutcome::TooWide { column_count } => {
                    Some(OqlResult::TooManyColumns { column_count })
                }
            }
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

/// Turn the `rows : vec vec Cell` value into a [`TableOutcome`]. The column set
/// is the first row's distinct cell names; every row is then aligned to it by
/// name (per the primer: read cells by name, never by position).
///
/// Two independent bounds cap the dense `cols × rows` allocation an
/// attacker-controlled reply could otherwise force (ICPBB-384/385), reported
/// SEPARATELY because they page differently:
///
///   * **width** — if the first row declares more than [`MAX_OQL_COLUMNS`]
///     distinct columns the table is refused ([`TableOutcome::TooWide`]). The
///     column set is chosen by the query's `select`, not by `offset`, so a
///     truncated-wide table is not recoverable by paging; the caller asks the
///     agent to narrow `select`. Refusing at the first row also bounds the dense
///     table before any row is materialized.
///   * **height** — rows past [`MAX_OQL_ROWS`] are not materialized and
///     `rows_truncated` is set, which the caller folds into `has_more` (a higher
///     `offset` DOES page these).
///
/// EVERY row's intermediate allocation is bounded to `O(columns)` too, not just
/// the final table: a row is aligned by rendering ONLY the cells whose name is a
/// known column (a `col_pos` lookup), so a reply with a narrow first row and a
/// later row carrying tens of thousands of junk cells cannot force a large
/// transient `Vec` before alignment. The per-cell scan is O(1)-space; a row's
/// junk cells cost a lookup each but allocate nothing. (This keeps the bound
/// local, rather than leaning on the decode quota to size intermediates.)
///
/// Fail-closed: `None` (→ Unrecognized) if the value isn't a vec, if any row
/// isn't a vec, or if the first row yields no named cells — so a malformed /
/// non-OQL reply degrades to the raw Candid rather than a bogus "0 columns"
/// table. An empty `rows` (a query that matched nothing) is the one legitimate
/// zero-column case and returns an empty table.
fn rows_to_table(rows_val: &IDLValue) -> Option<TableOutcome> {
    let IDLValue::Vec(rows) = rows_val else {
        return None;
    };
    if rows.is_empty() {
        return Some(TableOutcome::Table {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_truncated: false,
        });
    }
    let mut columns: Vec<String> = Vec::new();
    // Column name → its position in `columns` (first occurrence). Owned keys so
    // the map does not borrow `columns` (which is moved into the result), and
    // bounded to at most MAX_OQL_COLUMNS entries.
    let mut col_pos: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut out_rows: Vec<Vec<String>> = Vec::new();
    let mut rows_truncated = false;
    for row in rows {
        // Stop materializing once the row cap is hit; the remainder is `has_more`.
        if out_rows.len() >= MAX_OQL_ROWS {
            rows_truncated = true;
            break;
        }
        let IDLValue::Vec(cells) = row else {
            return None;
        };

        if columns.is_empty() {
            // First row establishes the columns (distinct names, first-occurrence
            // order). Count named cells with a plain counter — no allocation — so a
            // too-wide row is detected without ever building a full-width `Vec`.
            let mut named = 0usize;
            let mut over_wide = false;
            for cell in cells {
                if let IDLValue::Record(cf) = cell {
                    if let Some(IDLValue::Text(name)) = field_by_name(cf, "name") {
                        named += 1;
                        if !col_pos.contains_key(name.as_str()) {
                            if columns.len() == MAX_OQL_COLUMNS {
                                // A distinct name beyond the cap: refuse (keep
                                // scanning only to count, `col_pos` stays capped).
                                over_wide = true;
                            } else {
                                col_pos.insert(name.clone(), columns.len());
                                columns.push(name.clone());
                            }
                        }
                    }
                }
            }
            if named == 0 {
                // First row carried no named cells — not a recognizable OQL row.
                return None;
            }
            if over_wide {
                // Refuse rather than silently drop columns the query asked for; the
                // dropped set is chosen by `select`, not `offset`, so paging can't
                // recover it. `named` is the declared cell count (== column count
                // for a well-formed reply with no duplicate names).
                return Some(TableOutcome::TooWide { column_count: named });
            }
        }

        // Align this row to `columns`, rendering ONLY cells whose name is a known
        // column (first occurrence wins). Allocates O(columns), never O(cells).
        let mut aligned = vec![String::new(); columns.len()];
        let mut filled = vec![false; columns.len()];
        for cell in cells {
            if let IDLValue::Record(cf) = cell {
                if let Some(IDLValue::Text(name)) = field_by_name(cf, "name") {
                    if let Some(&pos) = col_pos.get(name.as_str()) {
                        if !filled[pos] {
                            filled[pos] = true;
                            aligned[pos] =
                                field_by_name(cf, "value").map(cell_scalar).unwrap_or_default();
                        }
                    }
                }
            }
        }
        out_rows.push(aligned);
    }
    Some(TableOutcome::Table { columns, rows: out_rows, rows_truncated })
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
    // CWE-789 (ICPBB-438): a ~13-byte reply declaring 40M zero-byte `vec null`
    // elements would, without a decoding quota, drive a multi-GB allocation and an
    // uncatchable abort. The `reply_decoder_config` quota bounds it, so the decode
    // returns the ordinary "not decodable" error instead of killing the process.
    #[test]
    fn decode_reply_rejects_a_vec_null_bomb_instead_of_aborting() {
        fn uleb128(mut n: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let b = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    out.push(b);
                    break;
                }
                out.push(b | 0x80);
            }
            out
        }
        // DIDL | one type T0 = vec (6d) null (7f) | one arg of T0 (01 00) | count.
        let mut bomb = vec![0x44, 0x49, 0x44, 0x4c, 0x01, 0x6d, 0x7f, 0x01, 0x00];
        bomb.extend(uleb128(40_000_000));
        assert!(bomb.len() <= 16, "the bomb is tiny on the wire: {} bytes", bomb.len());
        // Type-less path (did = None). Must return the decode-error string, not abort.
        let out = super::decode_reply(None, "m", &bomb);
        assert!(out.contains("not decodable"), "expected the decode-error path, got: {out:.120}");
    }

    // CWE-674 DEPTH counterpart to the breadth bomb above. A compact reply can
    // nest hundreds of thousands of `opt` levels (`type t = opt t`, one wire byte
    // per level), and candid's decoder, `IDLArgs`' `Display`, and the tree's
    // recursive `Drop` each recurse once per level — so without a depth bound a
    // ~300 KB reply would overflow the deep-stack thread and abort the process,
    // dropping every session. `REPLY_DECODING_QUOTA` bounds BREADTH, not depth;
    // DEPTH is bounded by candid's own `stacker::remaining_stack()` recursion
    // guard, which returns a decode error before the stack is exhausted (on any
    // stack size). This pins that: a 300k-deep `opt` reply must degrade to the
    // ordinary "not decodable" error, never a crash. It regression-guards against
    // a candid downgrade/regression that would drop the recursion guard.
    #[test]
    fn decode_reply_rejects_a_deep_opt_chain_instead_of_aborting() {
        // DIDL | 1 type: T0 = opt(6e) T0(00) | 1 arg of T0 (01 00) | value bytes.
        let mut deep = vec![0x44, 0x49, 0x44, 0x4c, 0x01, 0x6e, 0x00, 0x01, 0x00];
        deep.extend(std::iter::repeat_n(0x01u8, 300_000)); // 300k `opt` present tags
        deep.push(0x00); // a final null (opt absent) terminates the chain
        assert!(deep.len() < 350_000, "compact on the wire: {} bytes", deep.len());
        // Type-less path (did = None): decode + render + drop on the deep stack.
        // Require the genuine decode-error string: candid's recursion guard MUST
        // have run and rejected the chain. Accepting the "(could not spawn …)"
        // fallback would let a thread-spawn failure — which never reaches the
        // guard — pass the test, defeating its purpose.
        let out = super::decode_reply(None, "m", &deep);
        assert!(
            out.contains("not decodable"),
            "deep opt chain must reach candid's guard and decode-error gracefully, got: {out:.120}"
        );
    }

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

    // CWE-674, comment-hidden quote: `candid_parser`'s lexer drops `//` and
    // `/* */` comments (block comments NEST) in both grammars, so the guard must
    // too. A `"` inside a comment used to look like the start of a string literal
    // to the scanner, which then swallowed every following byte at depth 0 and
    // returned Ok — while the parser, seeing only a comment, went on to parse the
    // arbitrarily deep value behind it and overflowed the stack.
    #[test]
    fn candid_guard_is_comment_aware() {
        use super::guard_candid_text;
        // The premise, straight from the parser: a quote inside a comment is not
        // a string, and the value AFTER the comment is parsed normally. That is
        // exactly what a comment-blind guard would fail to account for.
        for hidden in ["//\"\n", "/*\"*/", "/* /* \" */ */"] {
            assert!(
                candid_parser::parse_idl_args(&format!("({hidden}opt opt 0)")).is_ok(),
                "candid_parser is expected to skip {hidden:?} and parse what follows"
            );
        }
        let deep = format!("{}0", "opt ".repeat(5000));
        // Every way of hiding a quote in a CLOSED comment must still be refused.
        for hidden in [
            "//\"\n",
            "// \" trailing text\n",
            "/*\"*/",
            "/* \" */",
            "/* /* \" */ */", // block comments nest, exactly as the lexer counts them
            "//\"\n//\"\n",
        ] {
            let attack = format!("({hidden}{deep})");
            assert!(
                guard_candid_text("v", &attack).is_err(),
                "quote hidden in {hidden:?} must not disable the depth scan"
            );
            // The same holds for the `.did` path and for bracket-only nesting.
            assert!(
                guard_candid_text("v", &format!("{hidden}{}", "{".repeat(200))).is_err(),
                "quote hidden in {hidden:?} must not disable bracket counting"
            );
        }
        // A comment may also sit BETWEEN a prefix and the group it wraps: the
        // `opt` must survive the comment and still outlive `record`'s braces.
        let deep_commented = format!(
            "{}1{}",
            "opt /* c */ record // c\n { a = ".repeat(100),
            " }".repeat(100),
        );
        assert!(
            guard_candid_text("v", &deep_commented).is_err(),
            "a comment between `opt` and `record {{` must not drop the prefix"
        );

        // No false positives: comments are trivia, and `//` or `/*` INSIDE a
        // string is ordinary string content, not a comment.
        assert!(guard_candid_text(
            "v",
            "// the service\nservice : { /* a method */ f : (nat) -> (nat) query; }"
        )
        .is_ok());
        assert!(guard_candid_text("v", "(opt /* c */ record /* c */ { a = opt 1 })").is_ok());
        assert!(guard_candid_text("v", &format!("(\"// {}\")", "(".repeat(10_000))).is_ok());
        assert!(guard_candid_text("v", &format!("(\"/* {}\")", "{".repeat(10_000))).is_ok());
        // A lone `/` is not a comment (nor any Candid token) — it must not stall
        // the scan or hide the nesting that follows it.
        assert!(guard_candid_text("v", &format!("/{}", "(".repeat(200))).is_err());
    }

    // End to end: the guard is what stands between a hostile `args` value and an
    // unrecoverable stack-overflow abort, so the comment-hidden vector must come
    // back as an ordinary error — while a legitimately nested value still encodes.
    #[test]
    fn encode_args_refuses_comment_hidden_deep_nesting() {
        use super::{encode_args, MAX_CANDID_DEPTH};
        let attack = format!("(//\"\n{}0)", "opt ".repeat(20_000));
        let err = encode_args(None, "m", &attack).expect_err("must be refused, not parsed");
        assert!(err.contains("nested too deeply"), "unexpected error: {err}");
        // Well under the limit: still parses and encodes (on the deep stack).
        let ok = format!("({}0)", "opt ".repeat(MAX_CANDID_DEPTH / 2));
        assert!(encode_args(None, "m", &ok).is_ok(), "legitimate nesting must still encode");
    }

    // CWE-674, flat alias chain: `type t0 = opt t1; type t1 = opt t2; …` is
    // INLINE-shallow — every alias is depth 1 and its prefix frame pops at the
    // `;` — so the depth scan alone never trips no matter how long the chain is.
    // Resolving `t0` still recurses once per link, and both `candid_parser`'s
    // type checker and `candid`'s type-table serializer follow it with no depth
    // limit, so the byte cap was the only thing bounding the recursion. The
    // declaration count is what actually bounds the chain.
    #[test]
    fn candid_guard_bounds_type_alias_chains() {
        use super::{guard_candid_text, MAX_CANDID_TYPE_DECLS};
        let chain = |n: usize, rhs: &dyn Fn(usize) -> String| {
            let mut s = String::new();
            for i in 0..n {
                s.push_str(&format!("type t{i}={};", rhs(i)));
            }
            s.push_str(&format!("type t{n}=nat;service:{{m:(t0)->(t0)}}"));
            s
        };
        // The reported vector, and the bare-`Var` chain that is even cheaper to
        // pack. Both stay at inline depth 1, so only the decl cap can catch them.
        let opt_link = |i: usize| format!("opt t{}", i + 1);
        let var_link = |i: usize| format!("t{}", i + 1);
        let links: [&dyn Fn(usize) -> String; 2] = [&opt_link, &var_link];
        for rhs in links {
            let attack = chain(20_000, rhs);
            assert!(attack.len() < super::MAX_CANDID_TEXT_BYTES, "vector must fit the byte cap");
            let err = guard_candid_text("d", &attack).expect_err("alias chain must be refused");
            assert!(err.contains("too many types"), "unexpected error: {err}");
        }
        // The cap is the thing being enforced, exactly: at the limit, through.
        let at_limit = chain(MAX_CANDID_TYPE_DECLS - 1, &|i| format!("opt t{}", i + 1));
        assert!(
            guard_candid_text("d", &at_limit).is_ok(),
            "an interface at the declaration limit must still be accepted"
        );
        let over = chain(MAX_CANDID_TYPE_DECLS, &|i| format!("opt t{}", i + 1));
        assert!(guard_candid_text("d", &over).is_err(), "one past the limit must be refused");

        // No false positives. `type` is a keyword, never an identifier, so it
        // cannot be a field name — but the QUOTED form is a legal field name, and
        // lives inside a string literal the scan skips. Thousands of those must
        // not be mistaken for declarations.
        let quoted = format!("service:{{m:(record{{{}}})->()}}", "\"type\":nat;".repeat(5_000));
        assert!(
            guard_candid_text("d", &quoted).is_ok(),
            "`\"type\"` field names are string content, not declarations"
        );
        // A realistic interface is nowhere near the cap.
        let realistic = format!(
            "{}service:{{ get:(t0)->(t0) query; set:(t0)->() }}",
            (0..180)
                .map(|i| format!("type t{i}=record{{a:nat;b:opt text}};"))
                .collect::<String>()
        );
        assert!(guard_candid_text("d", &realistic).is_ok(), "real interfaces must pass");
    }

    // The alias chain arrives through the caller-supplied `candid` argument, so
    // every entry point that parses interface text must refuse it — and refuse it
    // the way each already handles interfaces it cannot parse, never by erroring
    // out a call that would otherwise work.
    #[test]
    fn interface_entry_points_refuse_alias_chains() {
        use super::{
            api_doc_method, decode_bytes_with_did, encode_args, has_oql, is_query_method,
            MAX_CANDID_TYPE_DECLS,
        };
        // Just past the cap: cheap to check even if the guard ever stopped firing,
        // so a regression here shows up as a failure rather than a hung CI job.
        let n = MAX_CANDID_TYPE_DECLS + 100;
        let mut did = String::new();
        for i in 0..n {
            did.push_str(&format!("type t{i}=opt t{};", i + 1));
        }
        did.push_str(&format!(
            "type t{n}=nat;service:{{m:(t0)->(t0) query;schema:()->(text) query;\
             execute:(text)->(text) query;getApiDoc:()->(text) query}}"
        ));

        // Fail-closed detection paths: no OQL surface, no API doc, no verdict on
        // query-vs-update (the caller then fails open and lets the IC decide).
        assert!(!has_oql(&did), "an unparseable interface must not advertise OQL");
        assert_eq!(api_doc_method(&did), None);
        assert_eq!(is_query_method(&did, "m"), None);
        // Decode falls back to type-less rather than erroring.
        assert_eq!(decode_bytes_with_did(&did, "m", &[]), None);
        // An over-limit `candid` is non-fatal for encoding: the typed path is
        // skipped and the args still encode type-lessly.
        let encoded = encode_args(Some(&did), "m", "(42 : nat)");
        assert!(encoded.is_ok(), "an over-limit interface must not fail the call: {encoded:?}");
    }

    // Untrusted traffic must not be able to multiply 64 MiB parse threads with
    // request concurrency, so `on_deep_stack` holds a per-core permit — but a cap
    // that can deadlock or lose work would be worse than none. Far more callers
    // than permits must all still make progress, and every one must get its own
    // closure's result back.
    #[test]
    fn deep_stack_parses_are_capped_but_all_complete() {
        use super::on_deep_stack;
        let callers: Vec<_> = (0..64u32)
            .map(|i| std::thread::spawn(move || on_deep_stack(|| i * 2)))
            .collect();
        let got: Vec<_> = callers
            .into_iter()
            .map(|c| c.join().expect("caller must not panic or hang"))
            .collect();
        assert_eq!(got, (0..64u32).map(|i| Some(i * 2)).collect::<Vec<_>>());
        // Permits are returned, so a later call still runs rather than blocking.
        assert_eq!(on_deep_stack(|| "after"), Some("after"));
        // A panicking parse must surface on the caller's thread AND hand its
        // permit back; leaking one would wedge a slot for the process's lifetime.
        // (The parse thread's panic message on stderr here is expected.)
        let boom = std::panic::catch_unwind(|| on_deep_stack(|| panic!("parser blew up")));
        assert!(boom.is_err(), "a panic inside the parse must reach the caller");
        assert_eq!(on_deep_stack(|| "after panic"), Some("after panic"));
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

    // is_query_method classifies a method by its Candid mode so canister_query can
    // reject a query call to an UPDATE method up front: Some(true) for a query AND a
    // composite_query, Some(false) for an update, None when the method isn't declared
    // or the interface can't be parsed (fail-open, like has_oql).
    #[test]
    fn is_query_method_classifies_by_candid_mode() {
        use super::is_query_method;
        let did = "service : { \
            balance : (principal) -> (nat) query; \
            stats : () -> (text) composite_query; \
            transfer : (principal, nat) -> (nat); \
        }";
        assert_eq!(is_query_method(did, "balance"), Some(true), "query method → Some(true)");
        assert_eq!(is_query_method(did, "stats"), Some(true), "composite_query → Some(true)");
        assert_eq!(is_query_method(did, "transfer"), Some(false), "update method → Some(false)");
        assert_eq!(is_query_method(did, "missing"), None, "undeclared method → None (fail open)");
        assert_eq!(is_query_method("not a candid interface", "x"), None, "unparseable → None (fail open)");
        // Fail-open on an over-limit interface (CWE-674 guard), like has_oql.
        let over_deep = format!("service : {{ f : () -> ({}nat) query; }}", "vec ".repeat(5000));
        assert_eq!(is_query_method(&over_deep, "f"), None, "over-limit interface → None (fail open)");
    }

    // "Prefer OQL": canister_query must reject a Candid `method` query on an OQL
    // canister (so reads go through the `oql` path) while letting any query on a
    // non-OQL / unreadable interface pass through. Update calls never reach here
    // (canister_update_call doesn't call this).
    #[test]
    fn oql_query_redirect_blocks_candid_query_on_oql_canisters() {
        use super::oql_query_redirect;
        let oql = "service : { schema : () -> (text) query; execute : (text) -> (text) query; }";
        let plain = "service : { stats : () -> (text) query; }";

        // Candid `method` query on an OQL canister → redirected, and the message
        // names the full guide→schema→query path (#5) plus the auth hint.
        let msg = oql_query_redirect(Some(oql)).expect("query on OQL canister must be redirected");
        assert!(msg.contains("icp_oql_guide"), "message must point to the OQL guide: {msg}");
        assert!(msg.contains("get_canister_oql_schema"), "message must point to the OQL schema tool: {msg}");
        assert!(msg.contains("canister_query"), "message must point to canister_query's oql path: {msg}");
        assert!(msg.contains("`oql`"), "message must name the oql argument: {msg}");
        assert!(msg.contains("derivation_origin"), "message must carry the auth hint (pass the origin): {msg}");

        // Query on a non-OQL canister proceeds.
        assert!(oql_query_redirect(Some(plain)).is_none(), "non-OQL query must pass through");

        // Unknown / unreadable interface can't be classified → fail open (no block).
        assert!(oql_query_redirect(None).is_none(), "unreadable interface must not block");
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

    // OQL execute decoding: a `variant { ok = record { hasMore; rows } }` reply with
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

    /// One named `record { name; value }` OQL cell.
    #[cfg(test)]
    fn oql_cell(name: &str, val: &str) -> super::IDLValue {
        use super::{IDLField, IDLValue, Label};
        IDLValue::Record(vec![
            IDLField { id: Label::Named("name".into()), val: IDLValue::Text(name.into()) },
            IDLField { id: Label::Named("value".into()), val: IDLValue::Text(val.into()) },
        ])
    }

    /// Wrap a `rows : vec vec Cell` value in the `record { hasMore; rows }` shape
    /// that `extract_oql` recognizes, with the given `hasMore`.
    #[cfg(test)]
    fn oql_record(rows: Vec<super::IDLValue>, has_more: bool) -> super::IDLValue {
        use super::{IDLField, IDLValue, Label};
        IDLValue::Record(vec![
            IDLField { id: Label::Named("hasMore".into()), val: IDLValue::Bool(has_more) },
            IDLField { id: Label::Named("rows".into()), val: IDLValue::Vec(rows) },
        ])
    }

    // A first row wider than MAX_OQL_COLUMNS is REFUSED, not truncated: the
    // dropped columns are chosen by `select`, not `offset`, so a truncated-wide
    // table can't be paged. `rows_to_table` reports it as TooWide and `extract_oql`
    // maps that to TooManyColumns — crucially NOT to a `has_more` table, which
    // would loop the agent forever (ICPBB-384/385 + PR #136 review).
    #[test]
    fn rows_to_table_refuses_a_too_wide_first_row() {
        use super::{extract_oql, rows_to_table, OqlResult, TableOutcome, IDLValue, MAX_OQL_COLUMNS};

        let wide: Vec<IDLValue> = (0..MAX_OQL_COLUMNS + 44)
            .map(|c| oql_cell(&format!("c{c}"), "x"))
            .collect();
        let width = wide.len();
        // Extra rows after the wide first row must NOT flip this into a row-paged
        // table: width is decided at the first row, before any row is materialized.
        let mut rows: Vec<IDLValue> = vec![IDLValue::Vec(wide)];
        rows.extend((0..5).map(|_| IDLValue::Vec(Vec::new())));

        match rows_to_table(&IDLValue::Vec(rows.clone())).expect("recognizable") {
            TableOutcome::TooWide { column_count } => assert_eq!(column_count, width),
            TableOutcome::Table { .. } => panic!("an over-wide first row must be refused, not capped"),
        }

        // Through the public mapping: TooManyColumns, and never a has_more table.
        match extract_oql(&oql_record(rows, false)).expect("recognizable") {
            OqlResult::TooManyColumns { column_count } => assert_eq!(column_count, width),
            other => panic!("expected TooManyColumns, got a different arm: {}", oql_variant_name(&other)),
        }
    }

    // A NARROW reply taller than MAX_OQL_ROWS is capped to the row limit and
    // reports the remainder as `has_more` (a higher `offset` DOES page these),
    // even when the canister itself said hasMore = false.
    #[test]
    fn rows_to_table_caps_tall_replies_as_pageable() {
        use super::{extract_oql, rows_to_table, OqlResult, TableOutcome, IDLValue, MAX_OQL_ROWS};

        // Two columns (well within the width cap), MAX_OQL_ROWS + 100 rows.
        let make_rows = || {
            (0..MAX_OQL_ROWS + 100)
                .map(|r| {
                    IDLValue::Vec(vec![
                        oql_cell("id", &format!("{r}")),
                        oql_cell("name", "x"),
                    ])
                })
                .collect::<Vec<_>>()
        };

        match rows_to_table(&IDLValue::Vec(make_rows())).expect("recognizable") {
            TableOutcome::Table { columns, rows, rows_truncated } => {
                assert_eq!(columns, vec!["id".to_string(), "name".to_string()]);
                assert_eq!(rows.len(), MAX_OQL_ROWS, "materialized rows capped");
                assert!(rows_truncated, "dropped rows must be flagged");
                assert!(rows.iter().all(|r| r.len() == 2), "no ragged rows");
            }
            TableOutcome::TooWide { .. } => panic!("a narrow reply must not be refused"),
        }

        // The canister said hasMore = false, but we dropped rows, so the mapping
        // must still report has_more = true (offset paging recovers them).
        match extract_oql(&oql_record(make_rows(), false)).expect("recognizable") {
            OqlResult::Table { has_more, rows, .. } => {
                assert!(has_more, "row truncation must raise has_more even over canister's false");
                assert_eq!(rows.len(), MAX_OQL_ROWS);
            }
            other => panic!("expected a Table, got: {}", oql_variant_name(&other)),
        }
    }

    // The column cap is EXCLUSIVE: exactly MAX_OQL_COLUMNS distinct columns is
    // accepted; one more is refused. (Guards the `columns.len() == MAX_OQL_COLUMNS`
    // boundary against an off-by-one.)
    #[test]
    fn rows_to_table_column_cap_is_exclusive() {
        use super::{rows_to_table, TableOutcome, IDLValue, MAX_OQL_COLUMNS};

        let row_of = |n: usize| {
            IDLValue::Vec((0..n).map(|c| oql_cell(&format!("c{c}"), "x")).collect())
        };

        // Exactly at the cap → a normal table with all columns.
        match rows_to_table(&IDLValue::Vec(vec![row_of(MAX_OQL_COLUMNS)])).expect("recognizable") {
            TableOutcome::Table { columns, .. } => assert_eq!(columns.len(), MAX_OQL_COLUMNS),
            TableOutcome::TooWide { .. } => panic!("exactly MAX_OQL_COLUMNS must be accepted"),
        }
        // One over the cap → refused.
        match rows_to_table(&IDLValue::Vec(vec![row_of(MAX_OQL_COLUMNS + 1)])).expect("recognizable") {
            TableOutcome::TooWide { column_count } => assert_eq!(column_count, MAX_OQL_COLUMNS + 1),
            TableOutcome::Table { .. } => panic!("MAX_OQL_COLUMNS + 1 must be refused"),
        }
    }

    // The row cap is EXCLUSIVE: exactly MAX_OQL_ROWS rows materialize and are NOT
    // flagged; one more row is dropped and flags rows_truncated.
    #[test]
    fn rows_to_table_row_cap_is_exclusive() {
        use super::{rows_to_table, TableOutcome, IDLValue, MAX_OQL_ROWS};

        let rows_of = |n: usize| {
            IDLValue::Vec((0..n).map(|_| IDLValue::Vec(vec![oql_cell("id", "x")])).collect())
        };

        match rows_to_table(&rows_of(MAX_OQL_ROWS)).expect("recognizable") {
            TableOutcome::Table { rows, rows_truncated, .. } => {
                assert_eq!(rows.len(), MAX_OQL_ROWS);
                assert!(!rows_truncated, "exactly MAX_OQL_ROWS must not be flagged truncated");
            }
            TableOutcome::TooWide { .. } => panic!("a 1-column table is never too wide"),
        }
        match rows_to_table(&rows_of(MAX_OQL_ROWS + 1)).expect("recognizable") {
            TableOutcome::Table { rows, rows_truncated, .. } => {
                assert_eq!(rows.len(), MAX_OQL_ROWS, "the extra row is not materialized");
                assert!(rows_truncated, "one row over the cap must flag truncation");
            }
            TableOutcome::TooWide { .. } => panic!("a 1-column table is never too wide"),
        }
    }

    // A narrow first row followed by a row carrying a huge number of junk cells
    // must NOT blow up intermediate allocation: only cells whose name matches an
    // established column are rendered, so the wide junk row aligns to the 1-column
    // set and its unknown cells are skipped (PR #136 review, r3803651957).
    #[test]
    fn rows_to_table_bounds_a_wide_later_row() {
        use super::{rows_to_table, TableOutcome, IDLValue};

        // Row 0 establishes a single column "id"; row 1 carries "id" plus 5_000
        // junk cells with names that are NOT columns.
        let first = IDLValue::Vec(vec![oql_cell("id", "1")]);
        let mut wide_cells = vec![oql_cell("id", "2")];
        wide_cells.extend((0..5_000).map(|j| oql_cell(&format!("junk{j}"), "z")));
        let second = IDLValue::Vec(wide_cells);

        match rows_to_table(&IDLValue::Vec(vec![first, second])).expect("recognizable") {
            TableOutcome::Table { columns, rows, .. } => {
                assert_eq!(columns, vec!["id".to_string()], "later row can't add columns");
                assert_eq!(rows, vec![vec!["1".to_string()], vec!["2".to_string()]]);
                assert!(rows.iter().all(|r| r.len() == 1), "junk cells dropped, width stays 1");
            }
            TableOutcome::TooWide { .. } => panic!("a 1-column table is never too wide"),
        }
    }

    /// Name of an `OqlResult` arm, for assertion failure messages.
    #[cfg(test)]
    fn oql_variant_name(r: &super::OqlResult) -> &'static str {
        use super::OqlResult::*;
        match r {
            Table { .. } => "Table",
            QueryError(_) => "QueryError",
            TooManyColumns { .. } => "TooManyColumns",
            Unrecognized(_) => "Unrecognized",
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

    // Every type-less reply-decode path runs on the guarded deep stack (CWE-674). The
    // finding's repro is a recursive `opt` chain: a few KB on the wire, but it decodes
    // to a tree whose `from_bytes` / `Display` / recursive `Drop` (and the OQL walk)
    // recurse once per level. At attacker scale that overflows the ~2 MiB worker stack
    // and aborts the process; the fix decodes/renders/drops on the 64 MiB stack. This
    // exercises those paths end-to-end on a deeply-nested reply and asserts they return
    // a rendered value rather than erroring or mishandling it. DEPTH is kept modest so
    // CI stays fast (candid's decode/Display is superlinear in depth); it is not sized
    // to trigger an abort, which is uncatchable and cannot be asserted on anyway.
    #[test]
    fn typeless_reply_paths_bound_deep_nesting() {
        use super::{decode_reply, decode_text_reply, on_deep_stack, parse_execute_reply, OqlResult};
        use candid::{IDLArgs, IDLValue};
        // ~DEPTH-deep `opt opt … opt null`. Build, encode, AND drop the input tree on
        // the deep stack too, so the test harness thread (also ~2 MiB) can't overflow
        // while preparing the input.
        const DEPTH: usize = 2_000;
        let bytes = on_deep_stack(|| {
            let mut val = IDLValue::Null;
            for _ in 0..DEPTH {
                val = IDLValue::Opt(Box::new(val));
            }
            IDLArgs::new(&[val]).to_bytes().expect("encode nested opt reply")
        })
        .expect("spawn deep stack to encode");
        assert!(bytes.len() < 100_000, "nested opt is compact on the wire: {} bytes", bytes.len());

        // Type-less fallback (no `.did`): decodes + renders on the deep stack.
        assert!(decode_reply(None, "m", &bytes).contains("opt"));
        assert!(decode_text_reply(&bytes).contains("opt"));
        // The OQL path walks + renders the decoded tree; a non-OQL shape degrades to
        // Unrecognized, but crucially without overflowing.
        assert!(matches!(parse_execute_reply(None, &bytes), OqlResult::Unrecognized(_)));
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

    // The fuzzy phase is length-bounded so an attacker-sized `start` (or entity
    // name) can't stall the worker with an O(m·n) Levenshtein sweep. An over-long
    // `start` yields no suggestion (it isn't a typo of any short entity), while a
    // still-exact/plural match of any length is unaffected.
    #[test]
    fn closest_entity_bounds_the_fuzzy_phase() {
        use super::{closest_entity, MAX_FUZZY_NAME_LEN};
        let entities = vec!["bookings".to_string(), "users".to_string()];

        // A start longer than the cap is not fuzzy-matched (no near-miss possible).
        let huge = "u".repeat(MAX_FUZZY_NAME_LEN + 1);
        assert_eq!(closest_entity(&huge, &entities), None);

        // The cap is INCLUSIVE: a genuine near-miss whose length is EXACTLY the cap
        // is still repaired. This pins the boundary — flipping the guard to
        // `>= MAX_FUZZY_NAME_LEN` would drop this suggestion and fail the test.
        let at_cap_entity = "a".repeat(MAX_FUZZY_NAME_LEN); // len == cap
        let at_cap_typo = format!("{}b", "a".repeat(MAX_FUZZY_NAME_LEN - 1)); // one edit away, len == cap
        assert_eq!(
            closest_entity(&at_cap_typo, &[at_cap_entity.clone()]).as_deref(),
            Some(at_cap_entity.as_str()),
            "a near-miss exactly at the cap length must still be suggested"
        );
        // One char OVER the cap: the same near-miss is dropped (fuzzy phase skipped).
        let over_cap_typo = format!("{}b", "a".repeat(MAX_FUZZY_NAME_LEN));
        let over_cap_entity = "a".repeat(MAX_FUZZY_NAME_LEN + 1);
        assert_eq!(closest_entity(&over_cap_typo, &[over_cap_entity]), None);

        // Exact and plural repairs bypass the DP, so length never blocks them: a
        // huge entity name still matches its exact/plural `start`.
        let long_entity = "a".repeat(MAX_FUZZY_NAME_LEN * 4);
        let big = vec![long_entity.clone()];
        assert_eq!(closest_entity(&long_entity, &big).as_deref(), Some(long_entity.as_str()));
        assert_eq!(closest_entity(&format!("{long_entity}s"), &big).as_deref(), Some(long_entity.as_str()));

        // Unicode: the length-difference pruning counts chars, not bytes, so a
        // multi-byte near-miss (1 edit) is NOT wrongly pruned by a larger byte diff.
        let unicode_entities = vec!["abcde\u{1F4A9}".to_string()]; // 6 chars, 9 bytes
        assert_eq!(
            closest_entity("abcdeX", &unicode_entities).as_deref(), // 6 chars, 6 bytes; 1 edit away
            Some("abcde\u{1F4A9}"),
            "a 1-char edit must survive pruning even when the byte-length diff exceeds the bound"
        );
    }

    // #8: one COMPLETE canister_query per entity, each preserving the identity the
    // schema was read under (derivation_origin + account), so copying an example
    // doesn't silently drop back to anonymous.
    #[test]
    fn oql_query_examples_are_complete_and_preserve_identity() {
        use super::oql_query_examples;
        let schema = r#"{"entities":[{"name":"bookings"},{"name":"users"}]}"#;
        let ex = oql_query_examples("aaaaa-aa", schema, Some("https://app.example.com"), Some("work"));
        assert_eq!(ex.len(), 2, "one example per entity");
        assert!(ex[0].starts_with("canister_query "), "names the tool: {}", ex[0]);
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
        // The example line is `canister_query <json-args>`; the `oql` arg is itself a
        // JSON-object string — both must parse.
        let weird = r#"{"entities":[{"name":"we\"ird"}]}"#;
        let wex = oql_query_examples("aaaaa-aa", weird, None, None);
        assert_eq!(wex.len(), 1);
        let args_json = wex[0].strip_prefix("canister_query ").expect("tool prefix");
        let args: serde_json::Value = serde_json::from_str(args_json).expect("args must be valid JSON");
        let query = args.get("oql").and_then(|q| q.as_str()).expect("oql string");
        let parsed: serde_json::Value = serde_json::from_str(query).expect("oql must be valid JSON");
        assert_eq!(parsed.get("start").and_then(|s| s.as_str()), Some("we\"ird"), "entity name round-trips");
    }

    // #1: the conservative empty-reply detector recognizes the unambiguous empties
    // (used only to attach the anonymous-read auth hint on a canister_query Candid
    // `method` result), and never flags a reply with real content.
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
