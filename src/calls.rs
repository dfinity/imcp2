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

/// Encode textual Candid args to bytes. With `did` (the canister interface),
/// coerce the args to the method's declared parameter types — so plain literals
/// land as the method expects (`42` -> `nat64`, `1` -> `float64`, `opt`/`vec`
/// element types) with no `: type` annotations. Without it (interface
/// unreadable and no `candid` supplied), fall back to type-less inference, where
/// numeric literals default to `int`/`float64` and must be annotated (see the
/// `candid://textual-syntax` resource).
pub fn encode_args(did: Option<&str>, method: &str, args_text: &str) -> Result<Vec<u8>, String> {
    let parsed = candid_parser::parse_idl_args(args_text)
        .map_err(|e| format!("could not parse args `{args_text}`: {e}"))?;
    if let Some(did) = did {
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
    let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
    let actor = actor?;
    let func = env.get_method(&actor, method).ok()?;
    let decoded = IDLArgs::from_bytes_with_types(bytes, &env, &func.rets).ok()?;
    Some(decoded.to_string())
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
