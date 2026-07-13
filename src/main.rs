//! Minimal MCP PoC: an MCP server exposing tools over streamable HTTP that talk
//! to the Internet Computer via ic-agent.
//!
//!   1. `get_canister_candid`   — fetch a canister's Candid interface (`candid:service` metadata).
//!   2. `discover_app_canisters` — find the canisters behind a web domain.
//!   3. `call_canister` — call any method with textual Candid in, textual Candid out,
//!      as `anonymous` or as a domain identity derived ON DEMAND.
//!
//! The LLM only ever deals with textual Candid; encoding/decoding happens here.
//! Anonymous calls use the shared anonymous agent. A domain identity is minted
//! on demand from the connection's standing II delegation (see `identities`).

mod auth;
mod calls;
mod discover;
mod identities;
mod management;
mod skills;

use candid::Principal;
use ic_agent::{Agent, Identity};
use identities::Identities;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::{
        streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
        StreamableHttpServerConfig,
    },
    schemars, ErrorData as McpError, RoleServer, ServerHandler,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Public IC API boundary node. Anonymous queries/updates go here.
const IC_URL: &str = "https://icp-api.io";

/// Candid references exposed as MCP resources so the client writes correct
/// textual Candid. The textual-syntax cheat sheet is emphasised because every
/// tool here speaks textual Candid; the full type reference backs it up.
const CANDID_TEXTUAL_URI: &str = "candid://textual-syntax";
const CANDID_REFERENCE_URI: &str = "candid://reference";
/// URI scheme for IC skills exposed as MCP resources (`skill://<name>`).
const SKILL_URI_PREFIX: &str = "skill://";
const CANDID_TEXTUAL_MD: &str = include_str!("../static/candid-textual-syntax.md");
const CANDID_REFERENCE_MD: &str = include_str!("../static/candid-reference.md");

/// The OQL query-surface usage guide. Served on demand (via the `icp_oql_guide`
/// tool and the `oql://usage` resource) rather than inlined into every
/// `get_canister_candid` reply: `get_canister_candid` only signals `oql: true` plus a one-line
/// pointer here, so the guidance is delivered once, when the model chooses to
/// query, without bloating every interface read.
const OQL_USAGE_URI: &str = "oql://usage";
const OQL_PRIMER_MD: &str = include_str!("../static/oql-primer.md");

/// Bind address. Honours `$PORT` (set by most PaaS), defaulting to 8000.
fn bind_address() -> String {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    format!("0.0.0.0:{port}")
}

/// Hosts allowed in the `Host` header by rmcp's DNS-rebinding protection.
/// Defaults to loopback (good for local dev); when served behind a public URL
/// (tunnel/PaaS), the `PUBLIC_URL` host must be allowed or every `/mcp` request
/// is rejected before the bearer token is even checked.
fn allowed_hosts() -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Ok(url) = std::env::var("PUBLIC_URL") {
        if let Some(host) = url.split("://").nth(1).and_then(|r| r.split('/').next()) {
            let host = host.trim();
            if !host.is_empty() {
                hosts.push(host.to_string());
            }
        }
    }
    hosts
}

// Per-tool argument and output types live in the module that implements the
// tool: `calls` (get_canister_candid, call_canister), `discover`, `identities`,
// `skills`, `management`. main.rs only wires the tools together.

#[derive(Clone)]
struct IcTools {
    agent: Agent,
    identities: Identities,
    skills: skills::SkillsCatalog,
    tool_router: ToolRouter<IcTools>,
}

#[tool_router]
impl IcTools {
    fn new(agent: Agent, identities: Identities, skills: skills::SkillsCatalog) -> Self {
        Self {
            agent,
            identities,
            skills,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Fetch the Candid (.did) interface definition of an Internet Computer canister, read from its public `candid:service` metadata.",
        annotations(title = "Get Candid interface", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<calls::GetCandidOutput>(),
    )]
    async fn get_canister_candid(
        &self,
        Parameters(calls::GetCandidArgs { canister_id }): Parameters<calls::GetCandidArgs>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        match self
            .agent
            .read_state_canister_metadata(principal, "candid:service")
            .await
        {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(did) => {
                    // Signal an OQL query surface structurally (`oql: true`). When
                    // set, the guidance pointer is emitted as a SEPARATE content
                    // block, so the first block stays the raw `.did` (still valid,
                    // copy-pastable Candid) — the full primer is served on demand
                    // (see icp_oql_guide / OQL_USAGE_URI), never inlined.
                    let oql = calls::has_oql(&did);
                    let output = calls::GetCandidOutput { canister_id, candid: did.clone(), oql };
                    if oql {
                        let note = format!(
                            "This canister exposes an OQL query surface (a JSON query language \
                             over its data). Use get_canister_oql_schema to see its entities and fields, then \
                             run_canister_oql_query with a JSON query to read data as a table — these wrap the \
                             `schema`/`execute` methods for you (no Candid escaping). See \
                             icp_oql_guide (or the `{OQL_USAGE_URI}` resource) for the dialect."
                        );
                        Ok(ok_structured_blocks(vec![did, note], &output))
                    } else {
                        Ok(ok_structured(did, &output))
                    }
                }
                Err(e) => Ok(err(format!("metadata is not valid UTF-8: {e}"))),
            },
            Err(e) => Ok(err(format!(
                "could not read candid:service metadata: {e}"
            ))),
        }
    }

    #[tool(
        description = "Load the OQL query-surface guide: the JSON query dialect for canisters that expose OQL (get_canister_candid reports `oql: true`) — entities/fields/edges via `schema`, and the `execute` query object (filters, aggregation, ordering, edge traversal, paging). Use the get_canister_oql_schema and run_canister_oql_query tools to run it (they wrap the underlying methods); read this first so you write correct queries instead of guessing bespoke methods.",
        annotations(title = "Get the OQL query guide", read_only_hint = true, destructive_hint = false, open_world_hint = false),
        output_schema = schema_for_output::<calls::OqlGuideOutput>(),
    )]
    async fn icp_oql_guide(
        &self,
        Parameters(_args): Parameters<management::NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let output = calls::OqlGuideOutput { content: OQL_PRIMER_MD.to_string() };
        Ok(ok_structured(output.content.clone(), &output))
    }

    #[tool(
        description = "Run an OQL query against a canister that exposes the OQL surface (get_canister_candid reports `oql: true`). Pass the query as a JSON object string in `query` (see icp_oql_guide / get_canister_oql_schema for the dialect and field names) — it's sent to the canister's `execute` query method, so NO Candid escaping is needed. Returns the result decoded as `columns` + `rows` (rendered as a markdown table), with `has_more` for paging (re-query with a higher `offset`). Omit `derivation_origin` to query anonymously, or pass the app's canonical Internet Identity derivation origin to query as your account there — the result then echoes `derived_for_origin` / `requested` / `acted_as_principal` so an origin mismatch is visible.",
        annotations(title = "Run an OQL query", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<calls::OqlQueryOutput>(),
    )]
    async fn run_canister_oql_query(
        &self,
        Parameters(calls::OqlQueryArgs { canister_id, query, derivation_origin, account }): Parameters<calls::OqlQueryArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // Validate the query is a JSON object and wrap it as `execute`'s single
        // text arg — the model writes plain JSON, we do the Candid encoding.
        let query_json = match calls::normalize_oql_query(&query) {
            Ok(s) => s,
            Err(e) => return Ok(err(e)),
        };
        let arg_bytes = match calls::encode_text_arg(&query_json) {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };
        // Echo the effective derivation origin + acted-as principal (like
        // call_canister) so a canonicalization / wrong-origin mismatch is visible
        // even to text-only clients. `requested` is what the caller supplied
        // (trimmed); `derived_for_origin` is the canonical origin actually used.
        let requested = derivation_origin.as_ref().map(|s| s.trim().to_string());
        let origin = match clean_derivation_origin(derivation_origin) {
            Ok(o) => o,
            Err(e) => return Ok(err(e)),
        };
        let (agent, acted_as) = match self
            .resolve_agent(&ctx, origin.as_deref(), account.as_deref(), "querying")
            .await
        {
            Ok(a) => a,
            Err(e) => return Ok(err(e)),
        };
        let identity_note = origin.as_ref().map(|o| {
            let target = IdentityTarget {
                origin: o.clone(),
                requested: requested.clone().unwrap_or_else(|| o.clone()),
                source: "explicit".to_string(),
                application_origin: None,
            };
            format!("[{}]", identity_annotation(&target, acted_as.as_deref()))
        });
        let reply = match calls::raw_call(&agent, principal, "execute", arg_bytes, true).await {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("OQL execute failed: {e}"))),
        };
        // Decode the reply against the canister's interface so cell/field names
        // are recovered (the wire format hashes them).
        let did = calls::resolve_did(&agent, principal, None).await;
        match calls::parse_execute_reply(did.as_deref(), &reply) {
            calls::OqlResult::Table { columns, rows, has_more } => {
                // Primary block: the rendered table. Identity note (if any) is a
                // separate block so the table stays clean.
                let mut blocks = vec![calls::render_table(&columns, &rows, has_more)];
                if let Some(note) = &identity_note {
                    blocks.push(note.clone());
                }
                let output = calls::OqlQueryOutput {
                    canister_id,
                    columns,
                    rows,
                    has_more,
                    acted_as_principal: acted_as,
                    derived_for_origin: origin,
                    requested,
                };
                Ok(ok_structured_blocks(blocks, &output))
            }
            calls::OqlResult::QueryError(msg) => {
                Ok(err(format!("the canister returned an OQL error: {msg}")))
            }
            calls::OqlResult::Unrecognized(raw) => {
                // Not a recognizable OQL result — hand back the raw decoded reply
                // so the model still has the data (empty table in the structured form).
                let mut blocks =
                    vec![format!("(Could not parse this as an OQL table; raw reply below.)\n\n{raw}")];
                if let Some(note) = &identity_note {
                    blocks.push(note.clone());
                }
                let output = calls::OqlQueryOutput {
                    canister_id,
                    columns: Vec::new(),
                    rows: Vec::new(),
                    has_more: false,
                    acted_as_principal: acted_as,
                    derived_for_origin: origin,
                    requested,
                };
                Ok(ok_structured_blocks(blocks, &output))
            }
        }
    }

    #[tool(
        description = "Fetch the OQL schema catalogue of a canister that exposes the OQL surface (get_canister_candid reports `oql: true`): its entities, their primary keys, fields, and edges, as JSON. Call this before run_canister_oql_query so you know the queryable entities and exact field names. Omit `derivation_origin` to read anonymously, or pass the app's canonical Internet Identity derivation origin to read as your account there — the result then echoes `derived_for_origin` / `requested` / `acted_as_principal` so an origin mismatch is visible.",
        annotations(title = "Get the OQL schema", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<calls::OqlSchemaOutput>(),
    )]
    async fn get_canister_oql_schema(
        &self,
        Parameters(calls::OqlSchemaArgs { canister_id, derivation_origin, account }): Parameters<calls::OqlSchemaArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        let arg_bytes = match calls::encode_unit_arg() {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };
        let requested = derivation_origin.as_ref().map(|s| s.trim().to_string());
        let origin = match clean_derivation_origin(derivation_origin) {
            Ok(o) => o,
            Err(e) => return Ok(err(e)),
        };
        let (agent, acted_as) = match self
            .resolve_agent(&ctx, origin.as_deref(), account.as_deref(), "reading the schema")
            .await
        {
            Ok(a) => a,
            Err(e) => return Ok(err(e)),
        };
        let reply = match calls::raw_call(&agent, principal, "schema", arg_bytes, true).await {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("OQL schema call failed: {e}"))),
        };
        let schema = calls::decode_schema_reply(&reply);
        // Keep the primary block as the raw schema JSON (paste-able); surface the
        // identity note (like the other identity tools) as a SEPARATE block so a
        // mismatch is visible to text-only clients without breaking the JSON.
        let mut blocks = vec![schema.clone()];
        if let Some(o) = origin.as_ref() {
            let target = IdentityTarget {
                origin: o.clone(),
                requested: requested.clone().unwrap_or_else(|| o.clone()),
                source: "explicit".to_string(),
                application_origin: None,
            };
            blocks.push(format!("[{}]", identity_annotation(&target, acted_as.as_deref())));
        }
        let output = calls::OqlSchemaOutput {
            canister_id,
            schema,
            acted_as_principal: acted_as,
            derived_for_origin: origin,
            requested,
        };
        Ok(ok_structured_blocks(blocks, &output))
    }

    #[tool(
        description = "Read a canister's own API documentation — a prose \"how this app behaves\" guide covering units, auth, lifecycle, non-obvious semantics, mutation safety, polling rules, and gotchas — if it exposes a `getApiDoc` or `get_api_doc` method. Call this FIRST when working with an unfamiliar app: it explains behavior the Candid types alone don't (get_canister_candid still gives the exact method signatures). Returns the doc as markdown.",
        annotations(title = "Get a canister's API documentation", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<calls::ApiDocOutput>(),
    )]
    async fn get_canister_api_doc(
        &self,
        Parameters(calls::ApiDocArgs { canister_id }): Parameters<calls::ApiDocArgs>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // Read the interface to learn which naming the canister uses
        // (getApiDoc vs get_api_doc); the doc is public, so call anonymously.
        let did = calls::candid_service(&self.agent, principal).await;
        let method = match did.as_deref().and_then(calls::api_doc_method) {
            Some(m) => m,
            None => {
                return Ok(err(
                    "this canister doesn't expose a `getApiDoc`/`get_api_doc` method (or its \
                     Candid interface couldn't be read). Use get_canister_candid for the raw interface."
                        .into(),
                ))
            }
        };
        let arg_bytes = match calls::encode_unit_arg() {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };
        let reply = match calls::raw_call(&self.agent, principal, method, arg_bytes, true).await {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("{method} call failed: {e}"))),
        };
        let doc = calls::decode_text_reply(&reply);
        let output = calls::ApiDocOutput { canister_id, method: method.to_string(), doc };
        Ok(ok_structured(output.doc.clone(), &output))
    }

    /// The agent to sign calls with for a request, and the principal it signs as:
    /// the shared anonymous agent (principal `None`) when `origin` is `None`, else
    /// one backed by a short-lived account delegation for that Internet Identity
    /// derivation `origin`, derived on demand from this connection's standing
    /// credential. `origin` must be a VALIDATED derivation origin: call_canister
    /// passes the canonical one from [`resolve_identity_target`]; run_canister_oql_query /
    /// get_canister_oql_schema pass one validated by [`clean_derivation_origin`]. (get_app_principal
    /// and list_app_accounts don't use this helper — they call
    /// `Identities::delegated_identity_for` / `list_accounts` directly with a
    /// `resolve_identity_target` origin.) `delegated_identity_for` re-canonicalizes
    /// internally (idempotent), so an already-canonical origin is fine. `what`
    /// names the action for the no-session error.
    async fn resolve_agent(
        &self,
        ctx: &RequestContext<RoleServer>,
        origin: Option<&str>,
        account: Option<&str>,
        what: &str,
    ) -> Result<(Agent, Option<String>), String> {
        match origin {
            None => Ok((self.agent.clone(), None)),
            Some(origin) => {
                let session_id = authed_session(ctx)
                    .ok_or_else(|| format!("{what} as an app needs an authenticated session"))?
                    .session_id;
                let delegated = self
                    .identities
                    .delegated_identity_for(&session_id, origin, account)
                    .await?;
                let principal = delegated.sender().ok().map(|p| p.to_text());
                let agent = Agent::builder()
                    .with_url(IC_URL)
                    .with_identity(delegated)
                    .build()
                    .map_err(|e| format!("could not build agent: {e}"))?;
                Ok((agent, principal))
            }
        }
    }

    #[tool(
        description = "Call a method on an Internet Computer canister with textual Candid in and out. Args are encoded against the method's declared Candid types (so plain literals like 42 coerce correctly — no `: type` annotations needed). Omit both `derivation_origin` and `app_url` to call anonymously; provide one to call AS your account at that app — a short-lived account delegation is derived on demand from this connection's standing Internet Identity credential. `derivation_origin` is the app's EXACT canonical II derivation origin (not necessarily its visible URL; don't infer it from alternativeOrigins); `app_url` lets the connector resolve it. By default this uses the app's default account; pass `account` (a name from list_app_accounts) for a specific one. The result echoes `derived_for_origin` + `requested` + `acted_as_principal` so you can catch an origin mismatch. Set is_query=true for read-only query calls. If get_canister_candid couldn't fetch the interface, pass the `.did` text as `candid` so args/replies are still typed.",
        annotations(title = "Call a canister method", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<calls::CallCanisterOutput>(),
    )]
    async fn call_canister(
        &self,
        Parameters(calls::CallCanisterArgs {
            canister_id,
            method,
            args,
            is_query,
            derivation_origin,
            app_url,
            account,
            candid,
        }): Parameters<calls::CallCanisterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // The interface to encode/decode against: the canister's own
        // candid:service if exposed, else the caller-supplied `candid`.
        let did = calls::resolve_did(&self.agent, principal, candid.as_deref()).await;
        let arg_bytes = match calls::encode_args(did.as_deref(), &method, &args) {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };

        // Resolve which principal to act as: none = anonymous; else the app's
        // effective (canonical) II derivation origin, from an explicit
        // `derivation_origin` or resolved from `app_url`.
        let target = match resolve_identity_target(derivation_origin, app_url).await {
            Ok(t) => t,
            Err(e) => return Ok(err(e)),
        };
        // Pick the agent: no target uses the shared anonymous agent; a target
        // derives a short-lived account delegation for that origin on demand and
        // builds an agent backed by it (the server signs as the user's account).
        let origin = target.as_ref().map(|t| t.origin.as_str());
        let (agent, acted_as_principal) = match self
            .resolve_agent(&ctx, origin, account.as_deref(), "calling")
            .await
        {
            Ok(a) => a,
            Err(e) => return Ok(err(e)),
        };
        let reply_bytes = match calls::raw_call(&agent, principal, &method, arg_bytes, is_query).await {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("call failed: {e}"))),
        };
        // Decode against the Candid interface so field names are recovered.
        let reply = calls::decode_reply(did.as_deref(), &method, &reply_bytes);
        let (derived_for_origin, requested, derivation_origin_source) = match &target {
            Some(t) => (Some(t.origin.clone()), Some(t.requested.clone()), Some(t.source.clone())),
            None => (None, None, None),
        };
        // Keep the primary text block pure textual Candid (paste-able); surface the
        // identity note (so a wrong-principal is visible to text-only clients) as a
        // SEPARATE block rather than contaminating the reply.
        let mut blocks = vec![reply.clone()];
        if let Some(t) = &target {
            let acted = acted_as_principal.as_deref().unwrap_or("<unknown>");
            blocks.push(format!("[{}]", identity_annotation(t, Some(acted))));
        }
        let output = calls::CallCanisterOutput {
            canister_id, method, is_query, reply,
            acted_as_principal, derived_for_origin, requested, derivation_origin_source,
        };
        Ok(ok_structured_blocks(blocks, &output))
    }

    #[tool(
        description = "Get the Internet Computer principal you act as at an app, without making a canister call. Identify the app by `derivation_origin` (its EXACT canonical Internet Identity derivation origin — NOT necessarily the visible website URL, and never inferred from an alternativeOrigins list) OR by `app_url` (the connector resolves the derivation origin). The account delegation is derived on demand from this connection's standing Internet Identity credential. By default this resolves the app's default account; pass `account` (a name from list_app_accounts) for a specific one. The result returns the `principal` plus `derived_for_origin`, `requested`, and `derivation_origin_source` — compare the first two to catch an origin mismatch (a valid but WRONG principal). If `derivation_origin_source` is \"app_url_default\", the app declares no derivation origin and this assumed the app URL is the derivation origin; if the principal looks wrong for an app with a custom derivation origin, pass that canonical origin as `derivation_origin`.",
        annotations(title = "Get your principal at an app", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<identities::PrincipalOutput>(),
    )]
    async fn get_app_principal(
        &self,
        Parameters(identities::GetPrincipalArgs { derivation_origin, app_url, account }): Parameters<identities::GetPrincipalArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("getting an app principal needs an authenticated session".into())),
        };
        let target = match resolve_identity_target(derivation_origin, app_url).await {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(err("provide `derivation_origin` or `app_url` to identify the app".into())),
            Err(e) => return Ok(err(e)),
        };
        let delegated = match self
            .identities
            .delegated_identity_for(&session_id, &target.origin, account.as_deref())
            .await
        {
            Ok(d) => d,
            Err(e) => return Ok(err(e)),
        };
        let principal = match delegated.sender() {
            Ok(p) => p.to_text(),
            Err(e) => return Ok(err(format!("could not derive principal for {}: {e}", target.origin))),
        };
        // Surface a read-only session (H2) so the LLM won't attempt (and have the
        // IC reject at ingress) canister-management updates.
        let read_only = self.identities.is_read_only(&session_id).await == Some(true);
        let mut text = format!("{principal}\n\n[{}]", identity_annotation(&target, None));
        if read_only {
            text.push_str(
                "\n\n(This Internet Identity session is READ-ONLY: reads work, but canister \
                 management — create/install/start/stop/delete, and icp_canister_status — needs \
                 update access. Ask the user to reconnect with the read-only option turned OFF.)",
            );
        }
        let output = identities::PrincipalOutput {
            derived_for_origin: target.origin,
            requested: target.requested,
            derivation_origin_source: target.source,
            account,
            principal,
            read_only,
        };
        Ok(ok_structured(text, &output))
    }

    #[tool(
        description = "List the user's Internet Identity accounts at an app. Identify the app by `derivation_origin` (its EXACT canonical II derivation origin — not necessarily the visible URL) OR by `app_url` (resolved by the connector). Internet Identity gives the user a distinct principal per derivation origin, and within it they may hold several accounts: a default account everyone gets automatically (the anchor's current, user-controllable default there), plus any named accounts they created. Use this before acting on the user's behalf: if there's only the default account, just proceed (call_canister/get_app_principal with no `account`); if there are several, pick one with the user by passing its name as `account`. Returns each account's name (the default has none), number, and last-used time, plus `derived_for_origin`/`requested`/`derivation_origin_source` — if these accounts don't match what the user sees in their browser, the derivation origin is likely wrong (pass the app's canonical `derivation_origin`). Requires an authenticated session.",
        annotations(title = "List your accounts at an app", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<identities::AccountsOutput>(),
    )]
    async fn list_app_accounts(
        &self,
        Parameters(identities::ListAccountsArgs { derivation_origin, app_url }): Parameters<identities::ListAccountsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("listing your accounts needs an authenticated session".into())),
        };
        let target = match resolve_identity_target(derivation_origin, app_url).await {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(err("provide `derivation_origin` or `app_url` to identify the app".into())),
            Err(e) => return Ok(err(e)),
        };
        match self.identities.list_accounts(&session_id, &target.origin).await {
            Ok(accounts) => {
                let text = format_accounts(&target, &accounts);
                let output = identities::AccountsOutput {
                    derived_for_origin: target.origin,
                    requested: target.requested,
                    derivation_origin_source: target.source,
                    accounts: accounts.iter().map(identities::AccountEntry::from).collect(),
                };
                Ok(ok_structured(text, &output))
            }
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Resolve an application URL to its Internet Identity derivation context, so you don't have to figure out the derivation origin yourself. Returns the `application_origin`, the `derivation_origin` to pass to the identity tools, how it was determined (`derivation_origin_source`: \"declared\" — the app published it in /.well-known/ic-app.json, authoritative; \"known\" — from the connector's built-in registry of well-known custom-derivation-origin apps (e.g. NNS, Oisy, MULTI/DEX), used only when the app declares none; or \"app_url_default\" — assumed equal to the application origin, correct only if the app has no custom derivation origin, which cannot be verified), and the app's `alternative_origins` (informational — the INVERSE relation, never use it to infer the derivation origin). This does NOT return a principal — it resolves the origin only, since you haven't picked an account; to get the principal you act as, pass the returned `derivation_origin` to get_app_principal (choosing an `account`) or list_app_accounts. Use this first when you only know an app's URL; no authenticated session is required.",
        annotations(title = "Resolve an app's derivation origin", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<identities::ResolveAppOutput>(),
    )]
    async fn resolve_app(
        &self,
        Parameters(identities::ResolveAppArgs { app_url }): Parameters<identities::ResolveAppArgs>,
    ) -> Result<CallToolResult, McpError> {
        let app_url = match clean_app_url(&app_url) {
            Ok(u) => u,
            Err(e) => return Ok(err(e)),
        };
        // This tool surfaces `alternative_origins`, so fetch them (unlike the
        // identity hot path in resolve_identity_target). It resolves the derivation
        // origin ONLY — no principal is derived here, because the caller hasn't
        // chosen an account; that's get_app_principal / list_app_accounts' job. So
        // this needs no authenticated session.
        let resolved = match discover::resolve_app_identity(&app_url, true).await {
            Ok(r) => r,
            Err(e) => return Ok(err(e)),
        };
        let effective = identities::target_origin(&resolved.derivation_origin);

        let note = match resolved.derivation_origin_source {
            discover::DerivationSource::Declared => None,
            discover::DerivationSource::Known => Some(format!(
                "This app didn't declare a derivation origin in /.well-known/ic-app.json, but it's \
                 a known app that pins a custom one, so this used the built-in value {effective}. \
                 The app's own declaration, if it ships one, would override this."
            )),
            discover::DerivationSource::AppUrlDefault => Some(format!(
                "No derivation origin could be found for this app — its /.well-known/ic-app.json \
                 either declares no `derivation_origin` or couldn't be fetched (DNS/timeout/TLS/\
                 redirect), and it's not a known app — so this assumed the application origin, \
                 canonicalized to {effective} (what II derives against). If this app uses a custom \
                 derivation origin, that assumption yields a WRONG principal — supply the canonical \
                 origin explicitly."
            )),
        };
        let mut text = format!(
            "application_origin: {}\nderivation_origin: {} ({})\n",
            resolved.application_origin, effective, resolved.derivation_origin_source.as_str()
        );
        if !resolved.alternative_origins.is_empty() {
            text.push_str(&format!("alternative_origins: {}\n", resolved.alternative_origins.join(", ")));
        }
        if let Some(n) = &note {
            text.push_str(&format!("\nNOTE: {n}"));
        }
        let output = identities::ResolveAppOutput {
            application_origin: resolved.application_origin,
            derivation_origin: effective,
            derivation_origin_source: resolved.derivation_origin_source.as_str().to_string(),
            alternative_origins: resolved.alternative_origins,
            note,
        };
        Ok(ok_structured(text, &output))
    }

    #[tool(
        description = "Discover the Internet Computer canisters behind a web domain (e.g. \"oisy.com\"). Returns every canister id found, with provenance, most authoritative first: app-declared metadata — the App Connect page's `ic:canister-id` meta at /ai-connect.html (the app's MAIN backend) and the app's own /.well-known/ic-app.json manifest (ALL its canisters, with roles) — then the `x-ic-canister-id` header (the frontend/asset canister), a `/env.json` runtime config (e.g. backend_canister_id), and labelled/bare canister-id literals mined from the JS bundle. App-declared entries are the app's own claim about itself; env.json/bundle entries are mined candidates: pick by label (prefer production/IC ids) and confirm with get_canister_candid before calling.",
        annotations(title = "Discover canisters behind a domain", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<discover::DiscoverOutput>(),
    )]
    async fn discover_app_canisters(
        &self,
        Parameters(discover::DiscoverCanistersArgs { domain }): Parameters<discover::DiscoverCanistersArgs>,
    ) -> Result<CallToolResult, McpError> {
        match discover::discover(&domain).await {
            Ok(found) if !found.is_empty() => {
                let mut out = format!("Canisters discovered for {domain}:\n");
                for f in &found {
                    // Dashboard identity (name/type), filled in during discovery.
                    let identity = match (&f.name, &f.kind) {
                        (Some(n), Some(k)) => format!("  «{n}» ({k})"),
                        (Some(n), None) => format!("  «{n}»"),
                        _ => String::new(),
                    };
                    out.push_str(&format!(
                        "- {}{}{} [{}]\n",
                        f.canister_id,
                        f.label.as_deref().map(|l| format!("  — {l}")).unwrap_or_default(),
                        identity,
                        f.sources.join(", "),
                    ));
                }
                out.push_str(
                    "\n`ai-connect.html` and `ic-app.json` entries are DECLARED by the app itself \
                     (its main backend, and its own canister manifest with roles) — treat them as \
                     the app's claim about its composition. The `header` (x-ic-canister-id) entry \
                     is the frontend/asset canister. Others come from env.json or the JS bundle \
                     and may include multiple environments (prefer the production/IC ids). A \
                     «name» (type) is the IC dashboard's label for that id. Confirm an interface \
                     with get_canister_candid before calling.",
                );
                let output = discover::DiscoverOutput::from((domain, found));
                Ok(ok_structured(out, &output))
            }
            Ok(_) => {
                let text =
                    format!("No IC canisters found for {domain} — is it served from the Internet Computer?");
                let output = discover::DiscoverOutput::from((domain, Vec::new()));
                Ok(ok_structured(text, &output))
            }
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Find Internet Computer canisters by NAME. Searches the IC dashboard's service registries — the ICRC token ledgers (e.g. ckBTC, ckETH, ckUSDC, SNS tokens) by symbol/name, and the SNS project catalog by name — and returns matching canister ids. Use this when the user names a token, project, or service (e.g. \"ckUSDC\") rather than a canister id; then confirm with get_canister_candid and call methods with call_canister. (No public name-search exists over arbitrary canisters; this covers the IC's labelled services.)",
        annotations(title = "Find canisters by name", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<discover::FindCanisterOutput>(),
    )]
    async fn icp_find_canister_by_name(
        &self,
        Parameters(discover::FindCanisterArgs { query }): Parameters<discover::FindCanisterArgs>,
    ) -> Result<CallToolResult, McpError> {
        match discover::search_by_name(&query).await {
            Ok(matches) if !matches.is_empty() => {
                let mut out = format!("Canisters matching \"{query}\":\n");
                for m in &matches {
                    out.push_str(&format!(
                        "- {} — {} [{}]{}\n",
                        m.canister_id,
                        m.name,
                        m.kind,
                        m.note.as_deref().map(|n| format!("  — {n}")).unwrap_or_default(),
                    ));
                }
                out.push_str(
                    "\nConfirm an interface with get_canister_candid, then call methods with call_canister. \
                     For an SNS match the id is the project root — icp_lookup_canister_info_by_id it to learn more.",
                );
                let output = discover::FindCanisterOutput::from((query, matches));
                Ok(ok_structured(out, &output))
            }
            Ok(_) => {
                let text = format!(
                    "No named canisters found matching \"{query}\". This searches known tokens (ICRC \
                     ledgers) and SNS projects, so an arbitrary canister won't appear unless it's a \
                     labelled service. If you have a website, try discover_app_canisters; if you already \
                     have a canister id, try icp_lookup_canister_info_by_id or get_canister_candid."
                );
                let output = discover::FindCanisterOutput::from((query, Vec::new()));
                Ok(ok_structured(text, &output))
            }
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Identify what an Internet Computer canister IS, from the IC dashboard: its label/name (e.g. \"ICP Ledger\"), type (e.g. \"ledger\"), controllers, hosting subnet, module hash, language, and latest upgrade proposal. Use this to make sense of a bare canister id — e.g. one returned by discover_app_canisters.",
        annotations(title = "Identify a canister", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<discover::CanisterIdentityOutput>(),
    )]
    async fn icp_lookup_canister_info_by_id(
        &self,
        Parameters(discover::LookupCanisterArgs { canister_id }): Parameters<discover::LookupCanisterArgs>,
    ) -> Result<CallToolResult, McpError> {
        let client = match discover::http_client() {
            Ok(c) => c,
            Err(e) => return Ok(err(e)),
        };
        match discover::lookup_canister(&client, &canister_id).await {
            Ok(info) => {
                let text = format_canister_info(&info);
                let output = discover::CanisterIdentityOutput::from(info);
                Ok(ok_structured(text, &output))
            }
            Err(e) => Ok(err(e)),
        }
    }

    // ---- ICP skills awareness ----------------------------------------------

    #[tool(
        description = "List the official Internet Computer skills — authoritative how-to guides for authoring and shipping IC apps (Motoko language, mops/icp CLIs, cycles management, stable memory & upgrades, security, DeFi, auth, …). Returns each skill's name and a one-line description. Load a skill's full instructions with icp_get_skill(name). Consult these BEFORE writing Motoko/Rust canister code, building, or deploying.",
        annotations(title = "List Internet Computer skills", read_only_hint = true, destructive_hint = false, open_world_hint = false),
        output_schema = schema_for_output::<skills::SkillsOutput>(),
    )]
    async fn icp_list_skills(
        &self,
        Parameters(_args): Parameters<management::NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.skills.list().await {
            Ok(s) => {
                let text = skills::SkillsCatalog::format_list(&s);
                let output = skills::SkillsOutput::from(s);
                Ok(ok_structured(text, &output))
            }
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Fetch the full instructions (SKILL.md) of one Internet Computer skill by name (e.g. \"motoko\", \"icp-cli\", \"mops-cli\", \"cycles-management\", \"stable-memory\", \"canister-security\"). Call icp_list_skills first to see the available names. Use this to learn the exact, current way to do an IC task before doing it.",
        annotations(title = "Get an Internet Computer skill", read_only_hint = true, destructive_hint = false, open_world_hint = false),
        output_schema = schema_for_output::<skills::SkillOutput>(),
    )]
    async fn icp_get_skill(
        &self,
        Parameters(skills::GetSkillArgs { name }): Parameters<skills::GetSkillArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.skills.get(&name).await {
            Ok(md) => {
                let output = skills::SkillOutput { name, content: md };
                Ok(ok_structured(output.content.clone(), &output))
            }
            Err(e) => Ok(err(e)),
        }
    }

    // ---- Canister creation & management (as your standing II principal) -----

    #[tool(
        description = "Your cycles-ledger balance — the cycles that icp_create_canister and icp_top_up_canister spend. Acts as your Internet Identity principal (also printed). If it's empty, fund it first (e.g. via the icp CLI / cycles-management skill). Requires an authenticated session.",
        annotations(title = "Check your cycles balance", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CyclesBalance>(),
    )]
    async fn icp_cycles_balance(
        &self,
        Parameters(_args): Parameters<management::NoArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("checking your cycles balance needs an authenticated session".into())),
        };
        match management::cycles_balance(&self.identities, &sid).await {
            Ok(b) => Ok(ok_structured(b.human(), &b)),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Create and fund a NEW Internet Computer canister (as your Internet Identity). Fund it EITHER with `cycles` (exact, drawn from your cycles-ledger balance) OR with `icp` (a decimal-ICP string like \"0.5\", transferred from your ICP-ledger account and converted to cycles via the CMC). BOTH accounts belong to your management principal — the same principal icp_cycles_balance reports (its default subaccount); check/fund it before calling (cycles-ledger balance via icp_cycles_balance, or hold ICP in that principal's ICP-ledger account). The ICP path is best-effort with no retries: if the ICP transfer lands but the mint fails, the error carries the block index to recover with — do not blindly re-run. `cycles` wins if both are given. Controllers default to your own principal. Returns the new canister id — then build your Wasm (see the motoko/icp-cli skills) and install it with icp_install_code. Requires an authenticated session.",
        annotations(title = "Create a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CreatedCanister>(),
    )]
    async fn icp_create_canister(
        &self,
        Parameters(args): Parameters<management::CreateCanisterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("creating a canister needs an authenticated session".into())),
        };
        match management::create_canister(&self.identities, &sid, args).await {
            Ok(c) => Ok(ok_structured(c.human(), &c)),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Add cycles to an existing canister (as your Internet Identity). Fund EITHER with `cycles` (exact, drawn from your cycles-ledger balance) OR with `icp` (a decimal-ICP string, transferred from your ICP-ledger account and converted via the CMC straight into the target canister). Both accounts belong to your management principal — the one icp_cycles_balance reports (default subaccount). The ICP path is best-effort with no retries: if the transfer lands but the mint fails, the error carries the block index to recover with — do not blindly re-run. `cycles` wins if both are given. Requires an authenticated session.",
        annotations(title = "Top up a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_top_up_canister(
        &self,
        Parameters(args): Parameters<management::TopUpArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("topping up a canister needs an authenticated session".into())),
        };
        let canister_id = args.canister_id.clone();
        Ok(ok_canister_action(
            canister_id,
            management::top_up_canister(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Install a compiled Wasm module on a canister you control (as your Internet Identity). Provide the module as `wasm_base64` (or `wasm_hex`); large modules are uploaded via the chunk store automatically. `mode` is \"install\" (default, empty canister), \"reinstall\" (wipe state), or \"upgrade\" (preserve stable memory). `arg` is the init/upgrade argument in textual Candid, e.g. \"()\". Build the Wasm in your own environment first (see the motoko / icp-cli / mops-cli skills). Requires an authenticated session.",
        annotations(title = "Install code on a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_install_code(
        &self,
        Parameters(args): Parameters<management::InstallCodeArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("installing code needs an authenticated session".into())),
        };
        let canister_id = args.canister_id.clone();
        Ok(ok_canister_action(
            canister_id,
            management::install_code(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Report a canister's status: run state, cycle balance, module hash, memory size, controllers, and allocations. Controller-only (acts as your Internet Identity). This only READS status (it changes nothing), but on the IC it is an update call, so it needs a full (non-read-only) Internet Identity session. Requires an authenticated session.",
        annotations(title = "Get canister status", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_canister_status(
        &self,
        Parameters(args): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("reading canister status needs an authenticated session".into())),
        };
        let canister_id = args.canister_id.clone();
        Ok(ok_canister_action(
            canister_id,
            management::canister_status(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Update a canister's settings: controllers, compute/memory allocation, freezing threshold, reserved-cycles limit, wasm memory limit, or log visibility (\"controllers\"|\"public\"). Only the fields you pass are changed. WARNING: passing `controllers` REPLACES the whole set — include your own principal to remain a controller. Requires an authenticated session.",
        annotations(title = "Update canister settings", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_update_canister_settings(
        &self,
        Parameters(args): Parameters<management::UpdateSettingsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("updating settings needs an authenticated session".into())),
        };
        let canister_id = args.canister_id.clone();
        Ok(ok_canister_action(
            canister_id,
            management::update_canister_settings(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Start a stopped canister you control. Requires an authenticated session.",
        annotations(title = "Start a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_start_canister(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("starting a canister needs an authenticated session".into())),
        };
        let result = management::start_canister(&self.identities, &sid, &canister_id).await;
        Ok(ok_canister_action(canister_id, result))
    }

    #[tool(
        description = "Stop a running canister you control (required before deleting it). Requires an authenticated session.",
        annotations(title = "Stop a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_stop_canister(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("stopping a canister needs an authenticated session".into())),
        };
        let result = management::stop_canister(&self.identities, &sid, &canister_id).await;
        Ok(ok_canister_action(canister_id, result))
    }

    #[tool(
        description = "Remove a canister's code and state, leaving it empty (it keeps its id and cycles). Acts as your Internet Identity. Requires an authenticated session.",
        annotations(title = "Uninstall code from a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_uninstall_code(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("uninstalling code needs an authenticated session".into())),
        };
        let result = management::uninstall_code(&self.identities, &sid, &canister_id).await;
        Ok(ok_canister_action(canister_id, result))
    }

    #[tool(
        description = "Delete a canister permanently (irreversible — stop it first; remaining cycles are burned). Acts as your Internet Identity. Requires an authenticated session.",
        annotations(title = "Delete a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_delete_canister(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("deleting a canister needs an authenticated session".into())),
        };
        let result = management::delete_canister(&self.identities, &sid, &canister_id).await;
        Ok(ok_canister_action(canister_id, result))
    }
}

/// The authenticated MCP session of the calling request, if it carried a valid
/// bearer token (injected by [`auth::require_token`]).
fn authed_session(ctx: &RequestContext<RoleServer>) -> Option<auth::AuthedSession> {
    ctx.extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<auth::AuthedSession>())
        .cloned()
}

/// Which app principal an identity-bearing tool should act as, resolved from the
/// caller's `derivation_origin` and/or `app_url`.
#[derive(Debug)]
struct IdentityTarget {
    /// The EFFECTIVE (canonical) Internet Identity derivation origin to feed the
    /// delegation layer — echoed to the caller as `derived_for_origin`.
    origin: String,
    /// Exactly what the caller supplied (a `derivation_origin` or an `app_url`).
    requested: String,
    /// How `origin` was determined: "explicit" | "declared" | "known" | "app_url_default".
    source: String,
    /// The application origin, when the caller passed `app_url`.
    application_origin: Option<String>,
}

/// Resolve the caller's `derivation_origin` / `app_url` into an [`IdentityTarget`]
/// (or `None` when neither is given — an anonymous call). An explicit
/// `derivation_origin` is canonicalized and used verbatim (source `explicit`); an
/// `app_url` is resolved by [`discover::resolve_app_identity`] with precedence
/// DECLARED (the app's `/.well-known/ic-app.json`) > KNOWN (the built-in
/// `KNOWN_DERIVATION_ORIGINS` registry of well-known custom-origin apps) > the
/// application origin (flagged `app_url_default`) — so the source can be
/// `declared`, `known`, or
/// `app_url_default`. Both routes pass through the same canonicalizer the
/// delegation path uses, so the echoed `origin` is exactly what Internet Identity
/// derives against.
async fn resolve_identity_target(
    derivation_origin: Option<String>,
    app_url: Option<String>,
) -> Result<Option<IdentityTarget>, String> {
    match (derivation_origin, app_url) {
        (Some(_), Some(_)) => {
            Err("provide either `derivation_origin` or `app_url`, not both".to_string())
        }
        (Some(d), None) => {
            let d = clean_identity_arg("derivation_origin", &d)?;
            let origin = canonicalize_derivation_origin(&d)?;
            Ok(Some(IdentityTarget {
                origin,
                requested: d,
                source: "explicit".to_string(),
                application_origin: None,
            }))
        }
        (None, Some(u)) => {
            let u = clean_app_url(&u)?;
            // Identity hot path: we only need the derivation origin, not the
            // informational alternative-origins list — skip that extra fetch.
            let resolved = discover::resolve_app_identity(&u, false).await?;
            Ok(Some(IdentityTarget {
                origin: identities::target_origin(&resolved.derivation_origin),
                requested: u,
                source: resolved.derivation_origin_source.as_str().to_string(),
                application_origin: Some(resolved.application_origin),
            }))
        }
        (None, None) => Ok(None),
    }
}

/// Validate a user-supplied identity argument (`derivation_origin` / `app_url`):
/// trim surrounding whitespace, reject an empty/whitespace-only value, and reject
/// ASCII/Unicode control characters. Both fields are echoed back verbatim (as
/// `requested` / `derived_for_origin`) and `derivation_origin` feeds the delegation
/// origin, so a stray control char could corrupt a log line or the origin string —
/// fail closed rather than pass it through.
fn clean_identity_arg(field: &str, raw: &str) -> Result<String, String> {
    let v = raw.trim();
    if v.is_empty() {
        return Err(format!("`{field}` must not be empty"));
    }
    if v.chars().any(char::is_control) {
        return Err(format!("`{field}` must not contain control characters"));
    }
    Ok(v.to_string())
}

/// Canonicalize a cleaned `derivation_origin` to the effective origin the delegation
/// path derives against (`target_origin`), rejecting one that carries no host (e.g.
/// "https://" → `https://`) — which would otherwise derive against, and echo back,
/// an empty origin.
fn canonicalize_derivation_origin(cleaned: &str) -> Result<String, String> {
    let invalid = || {
        "`derivation_origin` must be an https origin or a bare host, with no user-info \
         (e.g. https://app.example.com or app.example.com)"
            .to_string()
    };
    // Reject any explicit scheme other than https (a bare host with no scheme is
    // fine — target_origin prepends https). Without this, target_origin would
    // rewrite a non-https scheme into a different origin than requested — `ftp://x`
    // mangled into a bogus `https://…`, or `http://x` silently upgraded to
    // `https://x` — contradicting the https-only contract and confusing debugging.
    // A bare host with no scheme is fine — target_origin prepends https. An explicit
    // scheme must be https, and we lowercase it before handing off: target_origin strips
    // only a lowercase `https://`, so an uppercase `HTTPS://` would otherwise survive
    // into the host and mangle the origin (e.g. `https://HTTPS:`), turning a valid input
    // into a rejection or a bogus origin. Rejecting a non-https scheme here also stops
    // target_origin from silently rewriting it (`ftp://x` → bogus `https://…`, `http://x`
    // → `https://x`), contradicting the https-only contract.
    let normalized = match cleaned.split_once("://") {
        Some((scheme, rest)) => {
            if !scheme.eq_ignore_ascii_case("https") {
                return Err(invalid());
            }
            format!("https://{rest}")
        }
        None => cleaned.to_string(),
    };
    let origin = identities::target_origin(&normalized);
    // Require the canonical origin to parse as an https URL with a real host and NO
    // user-info. `target_origin` keeps any `user@` prefix, but a browser origin never
    // has one, so `https://user@host` would derive a different principal than
    // `https://host` while `requested == derived_for_origin` hides the mismatch. This
    // also rejects a host-less input ("https://") and embedded spaces/invalid chars.
    let parsed = url::Url::parse(&origin).ok().filter(|u| {
        u.scheme() == "https"
            && u.host_str().map_or(false, |h| !h.is_empty())
            && u.username().is_empty()
            && u.password().is_none()
    });
    match parsed {
        // Reserialize to a canonical ASCII origin (lowercased host, no path/user-info),
        // exactly like the `app_url` path (`Url::origin().ascii_serialization()`), so a
        // mixed-case host echoes identically and hits the same delegation-cache key
        // instead of forking `https://Example.com` vs `https://example.com`.
        Some(u) if u.origin().is_tuple() => Ok(u.origin().ascii_serialization()),
        _ => Err(invalid()),
    }
}

/// Validate + canonicalize the optional `derivation_origin` taken by the tools that
/// accept ONLY that (run_canister_oql_query / get_canister_oql_schema): `None` stays `None` (anonymous); `Some`
/// is cleaned (trim / non-empty / no control chars) and canonicalized, so these paths
/// fail closed on the same bad input as `resolve_identity_target` instead of deriving
/// a valid-but-wrong principal from a blank/hostless origin.
fn clean_derivation_origin(derivation_origin: Option<String>) -> Result<Option<String>, String> {
    match derivation_origin {
        None => Ok(None),
        Some(d) => {
            let d = clean_identity_arg("derivation_origin", &d)?;
            Ok(Some(canonicalize_derivation_origin(&d)?))
        }
    }
}

/// Clean a user-supplied `app_url`: the shared identity-arg checks, plus reject an
/// explicit non-https scheme up front. The connector only ever fetches https
/// discovery targets (the SSRF guard refuses anything else), so an `http://` URL
/// would otherwise fail with a late, indirect error — reject it here with a clear
/// message. A bare host (no scheme) is fine; `resolve_app_identity` prepends https.
fn clean_app_url(raw: &str) -> Result<String, String> {
    let u = clean_identity_arg("app_url", raw)?;
    if let Some((scheme, _)) = u.split_once("://") {
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(
                "`app_url` must be an https URL or a bare host (the connector only fetches https origins)"
                    .to_string(),
            );
        }
    }
    // Require a real host and NO user-info, matching `canonicalize_derivation_origin`.
    // `resolve_app_identity` prepends https to a bare host and derives the application
    // origin via `Url::origin()`, which silently DROPS any `user:pass@` — so
    // `https://user@host` would resolve to `https://host` (differing from what the
    // caller supplied) and `https://` would yield no host. Reject both up front with a
    // clear message instead of a late, indirect downstream failure.
    let candidate = if u.contains("://") { u.clone() } else { format!("https://{u}") };
    let valid = url::Url::parse(&candidate).ok().map_or(false, |parsed| {
        parsed.scheme() == "https"
            && parsed.host_str().map_or(false, |h| !h.is_empty())
            && parsed.username().is_empty()
            && parsed.password().is_none()
    });
    if !valid {
        return Err(
            "`app_url` must be an https URL or bare host with a real host and no user-info \
             (e.g. https://app.example.com or app.example.com)"
                .to_string(),
        );
    }
    Ok(u)
}

/// A one-line identity annotation for the human-readable `text` (which text-only
/// clients see instead of the structured output): the origin II derived against,
/// how it was determined (`source`), and — whenever it differs from the derived
/// origin (canonicalization, http→https, a stripped path, or `app_url` defaulting)
/// — the caller's `requested` value. Echoing `requested` on ANY mismatch (not only
/// `app_url_default`) is what keeps a requested≠derived mismatch visible in every
/// client. `acted_as` prefixes the signed-as principal when known.
fn identity_annotation(target: &IdentityTarget, acted_as: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(p) = acted_as {
        s.push_str(&format!("signed as {p} — "));
    }
    s.push_str(&format!("derived for {} (source: {})", target.origin, target.source));
    if target.requested != target.origin {
        s.push_str(&format!("; requested {}", target.requested));
    }
    if target.source == "app_url_default" {
        s.push_str(
            " — the app declares no derivation origin, so this ASSUMES the app origin; \
             if the principal looks wrong, pass the app's canonical derivation_origin",
        );
    }
    s
}

/// Log each inbound request: method, path, response status, and latency — gives
/// visibility into what external MCP clients probe (discovery URLs, unknown
/// paths) at `RUST_LOG=info`. The query string is never logged — keeping the
/// single-use `?code=` / `?id=` and, critically, `/oauth/finish`'s one-time
/// `?fs=` (the `finish_secret`, H3/P2) out of logs — and request bodies are never
/// logged (the connect callback carries the connection-scoped `state`).
async fn log_request(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let elapsed_ms = started.elapsed().as_millis() as u64;
    tracing::info!(%method, %path, status, elapsed_ms, "http request");
    resp
}

#[tool_handler]
impl ServerHandler for IcTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().enable_resources().build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_instructions(
            "Internet Computer tools. Every tool speaks TEXTUAL Candid — the `(...)` value \
             syntax, e.g. `(record { owner = principal \"aaaaa-aa\"; amount = 5 : nat })`, never \
             the binary form. Tool names signal SCOPE: an `icp_` prefix marks IC protocol / \
             meta-level tools (dashboard name/id lookups, the official IC skills, the OQL dialect \
             guide, and canister creation/management); `…_app…` names \
             (`discover_app_canisters`, `get_app_principal`, `list_app_accounts`, `resolve_app`) \
             act on a whole APP, keyed by its Internet Identity derivation origin or app URL; and \
             `…canister…` names (`get_canister_candid`, `get_canister_api_doc`, \
             `get_canister_oql_schema`, `run_canister_oql_query`, `call_canister`) act on ONE \
             specific canister. Before writing Candid args, consult the `candid://textual-syntax` \
             resource (the value syntax these tools use); `candid://reference` has the full type \
             reference. When the user names a website/domain instead of a canister id, use \
             `discover_app_canisters` to find the canister(s) behind it — app-declared App Connect \
             metadata (/ai-connect.html meta, /.well-known/ic-app.json manifest) first, then the \
             frontend via header and backend candidates via env.json/JS bundle. When they name a \
             TOKEN, PROJECT or SERVICE (e.g. \
             \"ckUSDC\"), use `icp_find_canister_by_name` to look it up by name in the IC dashboard's \
             registries and get its canister id. `icp_lookup_canister_info_by_id(id)` tells you what a bare \
             canister id IS (dashboard label, type, controllers, subnet). `get_canister_candid` fetches a \
             canister's Candid interface. For an unfamiliar app, try `get_canister_api_doc` FIRST: if the \
             canister exposes a `getApiDoc`/`get_api_doc` method it returns a prose guide to how \
             the app behaves (units, auth, lifecycle, mutation safety, polling, gotchas) that the \
             Candid types alone don't convey. If `get_canister_candid` reports `oql: true`, the canister \
             exposes an OQL query surface — read `icp_oql_guide` for the dialect, then use \
             `get_canister_oql_schema` (entities and fields) and `run_canister_oql_query` (run a JSON query, get a table \
             back). Those two wrap the canister's `schema`/`execute` methods, so you don't \
             hand-encode Candid for OQL. `call_canister` calls a method with textual Candid \
             in/out: omit the identity args to call anonymously, or act AS your account at an app. \
             To act as an app account, identify the app by its `derivation_origin` — the EXACT \
             canonical origin Internet Identity derives its principal from, which is NOT \
             necessarily the visible website URL and must NEVER be inferred from an \
             ii-alternative-origins list — or by `app_url`, which the connector resolves (use \
             `resolve_app` to see what an app URL resolves to). A short-lived (<=5 min) account \
             delegation is minted ON DEMAND from this connection's standing credential, no extra \
             sign-in. `get_app_principal` returns the principal without a call; `list_app_accounts` lists \
             the user's accounts (a default one plus any named ones), and call_canister / \
             get_app_principal take an optional `account` (a name from that list) — omit it for the \
             default. Every identity result echoes `derived_for_origin` (the origin actually used), \
             `requested` (what you passed), and `derivation_origin_source`: if the source is \
             \"app_url_default\", the app declared no derivation origin and the app URL was ASSUMED \
             to be it — correct only if the app has no custom derivation origin. If a principal, \
             account, or balance doesn't match what the user sees in their browser, the derivation \
             origin is wrong: pass the app's canonical `derivation_origin` explicitly. The standing \
             credential is obtained when you connect \
             (authenticate via Internet Identity) and lasts for the session duration you choose when \
             connecting (up to 30 days); reconnect when it expires. \
             The session may be READ-ONLY (Internet Identity's consent screen defaults to read-only): \
             reads work, but the canister-management tools below make update calls the network \
             rejects for a read-only session — if one fails that way, ask the user to reconnect with \
             the read-only option turned OFF.\n\n\
             Typical flow (acting FOR THE USER at an app): (0) get the app URL from the user — no \
             tool maps an app NAME to a URL (`icp_find_canister_by_name` searches the token/SNS \
             registries for canister ids, not front-ends), so take it from the user or ask; (1) \
             `resolve_app(url)` gives the `derivation_origin`, and concurrently (2) \
             `discover_app_canisters(url)` gives the backend canister id; (3) `list_app_accounts` — \
             if there is more than one account, ask which to use and remember it; (4) \
             `get_app_principal` ONLY when you need the principal value itself (`call_canister` / \
             `run_canister_oql_query` act as the account without pre-fetching it); (5) inspect the \
             canister with `get_canister_candid` (and `get_canister_api_doc` if it exposes one) — its \
             `oql: true` flag says whether OQL is available; (6) READ with `run_canister_oql_query` \
             when OQL is available, else `call_canister` with is_query=true; (7) ACT with \
             `call_canister` update calls, passing `derivation_origin` + `account` to act as the \
             user. Public/anonymous reads skip 1/3/4. The per-canister inspection (5) is independent \
             of the identity steps (1/3/4), so they can run in parallel. Managing your OWN canisters \
             (the `icp_` create/install/status/… tools) acts as your standing MANAGEMENT principal at \
             this server's origin — a DIFFERENT identity than the per-app principals above.\n\n\
             To AUTHOR, BUILD and DEPLOY IC code, first consult the official IC skills: \
             `icp_list_skills` lists them and `icp_get_skill(name)` loads one. Especially `motoko` \
             (language), `mops-cli` (deps/build), `icp-cli` (build & deploy), `cycles-management` \
             (ICP↔cycles & funding), `stable-memory` (upgrades) and `canister-security`. Compiling \
             Motoko/Rust to Wasm happens in YOUR environment (guided by these skills); these tools \
             then put it on chain. To CREATE and MANAGE canisters as your Internet Identity, use: \
             `icp_cycles_balance` (your cycles-ledger balance), `icp_create_canister` (create + fund from \
             that balance — amount in `cycles` or `icp`), `icp_install_code` (install your compiled \
             Wasm — base64 — single-shot or chunked), `icp_canister_status`, `icp_update_canister_settings`, \
             `icp_start_canister`/`icp_stop_canister`/`icp_uninstall_code`/`icp_delete_canister`, and \
             `icp_top_up_canister`. These act as your standing II principal, which must hold cycles in \
             the cycles ledger first (fund it via the icp CLI / cycles-management skill). So to \
             \"build X and deploy a canister with Y ICP worth of cycles\": read the relevant skills, \
             write & build the Wasm locally, `icp_create_canister(icp=Y)`, then `icp_install_code`."
                .to_string(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let mut resources = vec![
            RawResource::new(CANDID_TEXTUAL_URI, "Candid textual syntax (used by these tools)")
                .no_annotation(),
            RawResource::new(CANDID_REFERENCE_URI, "Candid type reference (full spec)")
                .no_annotation(),
            RawResource::new(OQL_USAGE_URI, "OQL query surface usage guide")
                .no_annotation(),
        ];
        // Surface the IC skills as resources too (best-effort: if the registry is
        // unreachable, the candid resources above still list). Each `skill://<name>`
        // is read on demand in read_resource.
        if let Ok(skills) = self.skills.list().await {
            for s in skills {
                let title = if s.title.is_empty() {
                    format!("IC skill: {}", s.name)
                } else {
                    format!("IC skill: {}", s.title)
                };
                resources.push(
                    RawResource::new(format!("{SKILL_URI_PREFIX}{}", s.name), title).no_annotation(),
                );
            }
        }
        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        // Skills are fetched live by name; the candid references are static.
        if let Some(name) = request.uri.strip_prefix(SKILL_URI_PREFIX) {
            return match self.skills.get(name).await {
                Ok(md) => Ok(ReadResourceResult::new(vec![ResourceContents::text(
                    md,
                    request.uri,
                )])),
                Err(e) => Err(McpError::resource_not_found(
                    "resource_not_found",
                    Some(serde_json::json!({ "uri": request.uri, "error": e })),
                )),
            };
        }
        let body = match request.uri.as_str() {
            CANDID_TEXTUAL_URI => CANDID_TEXTUAL_MD,
            CANDID_REFERENCE_URI => CANDID_REFERENCE_MD,
            OQL_USAGE_URI => OQL_PRIMER_MD,
            other => {
                return Err(McpError::resource_not_found(
                    "resource_not_found",
                    Some(serde_json::json!({ "uri": other })),
                ))
            }
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            body,
            request.uri,
        )]))
    }
}

/// Render an IC dashboard canister identity as readable text for icp_lookup_canister_info_by_id.
fn format_canister_info(info: &discover::CanisterInfo) -> String {
    let mut s = format!("Canister {}\n", info.canister_id);
    s.push_str(&format!(
        "- name: {}\n",
        info.name.as_deref().unwrap_or("(unlabelled — not a known/named canister)")
    ));
    if let Some(t) = &info.canister_type {
        s.push_str(&format!("- type: {t}\n"));
    }
    if let Some(sub) = &info.subnet_id {
        s.push_str(&format!("- subnet: {sub}\n"));
    }
    if !info.controllers.is_empty() {
        s.push_str(&format!("- controllers: {}\n", info.controllers.join(", ")));
    }
    if let Some(lang) = &info.language {
        s.push_str(&format!("- language: {lang}\n"));
    }
    if let Some(mh) = &info.module_hash {
        s.push_str(&format!("- module hash: {mh}\n"));
    }
    if let Some(p) = info.latest_upgrade_proposal {
        s.push_str(&format!("- latest upgrade: NNS proposal {p}\n"));
    }
    s.push_str("\nFetch its interface with get_canister_candid, then call methods with call_canister.");
    s
}

/// Render the user's accounts at an app (from `Identities::list_accounts`) as
/// readable text for the `list_app_accounts` tool.
fn format_accounts(target: &IdentityTarget, accounts: &[identities::AccountInfo]) -> String {
    // A one-line derivation-origin header so a wrong origin (or requested≠derived
    // mismatch) is visible even to text-only clients.
    let header = format!("Accounts {}", identity_annotation(target, None));
    if accounts.is_empty() {
        return format!("{header}\n\nNo Internet Identity accounts found there.");
    }
    let mut out = format!("{header}\n\nYour accounts:\n");
    for a in accounts {
        // The default account (anchor's current default) has no name/number.
        let label = match &a.name {
            Some(name) => format!("\"{name}\""),
            None => "(default account — no name)".to_string(),
        };
        let number = match a.account_number {
            Some(n) => format!("account #{n}"),
            None => "default".to_string(),
        };
        let last_used = a
            .last_used
            .map(|ns| format!(", last used {ns} ns since epoch"))
            .unwrap_or_default();
        out.push_str(&format!("- {label} [{number}{last_used}]\n"));
    }
    if accounts.len() == 1 {
        out.push_str(
            "\nOnly the default account exists here — act on the user's behalf directly: \
             call_canister / get_app_principal with no `account`.",
        );
    } else {
        out.push_str(
            "\nThere are multiple accounts here. Confirm which one the user means (or act on each), \
             then pass its name as `account` to call_canister / get_app_principal. Omit `account` for \
             the default one.",
        );
    }
    out
}

/// The MCP `outputSchema` for `T`, for use in a `#[tool(output_schema = …)]`
/// attribute. Thin wrapper over rmcp's generator that unwraps the object-root
/// validation: a non-object schema is a programming error (every tool output
/// type is a struct), so it panics at router-construction time rather than
/// forcing an `.expect(…)` at each of the ~19 call sites.
fn schema_for_output<T: schemars::JsonSchema + std::any::Any>() -> std::sync::Arc<rmcp::model::JsonObject> {
    rmcp::handler::server::tool::schema_for_output::<T>().unwrap_or_else(|e| {
        panic!(
            "output schema for `{}` must be object-rooted: {e}",
            std::any::type_name::<T>()
        )
    })
}

fn ok(text: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(text)])
}

/// A success result carrying both the human-readable `text` and a machine-
/// readable `value` that conforms to the tool's declared `outputSchema`.
/// Clients that consume structured tool output get the typed form; the rest
/// still get the text.
///
/// MCP requires `outputSchema` (and therefore `structuredContent`) to be
/// object-rooted, so we only attach `value` when it serializes to a JSON
/// object; anything else (a bare array/string/number, or a serialization
/// failure) falls back to text-only rather than emitting structured content
/// that couldn't match the declared schema.
fn ok_structured<T: serde::Serialize>(text: String, value: &T) -> CallToolResult {
    ok_structured_blocks(vec![text], value)
}

/// Like [`ok_structured`], but emits several text content blocks instead of one.
/// The first block is the primary payload (e.g. a canister's raw `.did`); any
/// further blocks are separate notes. Keeping them distinct means a consumer
/// that copies the first block gets clean data (the `.did` stays valid,
/// paste-able Candid), while the model still sees the trailing note(s) — used by
/// `get_canister_candid` to attach the OQL pointer without contaminating the interface
/// text. The structured `value` is attached under the same object-rooted rule as
/// [`ok_structured`].
fn ok_structured_blocks<T: serde::Serialize>(texts: Vec<String>, value: &T) -> CallToolResult {
    let mut result = CallToolResult::success(texts.into_iter().map(Content::text).collect());
    result.structured_content = match serde_json::to_value(value) {
        Ok(v @ serde_json::Value::Object(_)) => Some(v),
        _ => None,
    };
    result
}

/// Map a management/lifecycle tool's `Result<String, String>` (the human
/// confirmation message) to a `CallToolResult`, attaching a
/// `management::CanisterActionOutput { canister_id, message }` as structured content on
/// success so the reply conforms to the tool's declared `outputSchema`.
///
/// The `canister_id` is normalized to its canonical principal text: the
/// management layer accepts ids with surrounding whitespace (it parses via
/// `Principal::from_text(s.trim())`) and renders the canonical form in its
/// messages, so we canonicalize here too to keep the structured field
/// consistent with the text. On the success path the id always parses (the
/// operation just used it); the trimmed input is only a defensive fallback.
fn ok_canister_action(canister_id: String, r: Result<String, String>) -> CallToolResult {
    match r {
        Ok(message) => {
            let canister_id = Principal::from_text(canister_id.trim())
                .map(|p| p.to_text())
                .unwrap_or_else(|_| canister_id.trim().to_string());
            let output = management::CanisterActionOutput { canister_id, message };
            ok_structured(output.message.clone(), &output)
        }
        Err(text) => err(text),
    }
}

fn err(text: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(text)])
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IC MCP PoC</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto">
<h1>Internet Computer MCP PoC</h1>
<p>MCP endpoints: <code>POST /mcp</code> (beta Internet Identity) · <code>POST /mcp-prod</code> (production Internet Identity)</p>
<p>Tools: <code>discover_app_canisters</code> (domain → canister ids), <code>icp_find_canister_by_name</code> (name → canister ids), <code>icp_lookup_canister_info_by_id</code> (id → dashboard identity), <code>get_canister_candid</code>, <code>call_canister</code> (anonymously, or as your account at an app — identified by its <code>derivation_origin</code> or <code>app_url</code>, delegation minted on demand), <code>get_app_principal</code> (your principal at an app, no call), <code>list_app_accounts</code> (your Internet Identity accounts at an app), <code>resolve_app</code> (app URL → its Internet Identity derivation origin; no principal — pick an account via <code>get_app_principal</code>). Identity results echo <code>derived_for_origin</code>/<code>requested</code> so an origin mismatch is visible. All speak textual Candid.</p>
<p>Skills: <code>icp_list_skills</code> / <code>icp_get_skill</code> (the official IC how-to guides — Motoko, mops, icp CLI, cycles, …).</p>
<p>App docs: <code>get_canister_api_doc</code> (a canister's own "how this app behaves" guide, if it exposes <code>getApiDoc</code>/<code>get_api_doc</code>).</p>
<p>OQL: <code>icp_oql_guide</code> (dialect), <code>get_canister_oql_schema</code> (entities/fields), <code>run_canister_oql_query</code> (run a JSON query, get a table) — for canisters that expose an OQL <code>schema</code>/<code>execute</code> surface (<code>get_canister_candid</code> reports <code>oql: true</code>).</p>
<p>Canister management (as your Internet Identity): <code>icp_cycles_balance</code>, <code>icp_create_canister</code>, <code>icp_install_code</code>, <code>icp_canister_status</code>, <code>icp_update_canister_settings</code>, <code>icp_start_canister</code>, <code>icp_stop_canister</code>, <code>icp_uninstall_code</code>, <code>icp_delete_canister</code>, <code>icp_top_up_canister</code>.</p>
</body></html>"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let agent = Agent::builder().with_url(IC_URL).build()?;
    tracing::info!("built ic-agent against {IC_URL}");

    // Two Internet Identity instances: beta serves `/mcp` (OAuth AS at the root
    // of PUBLIC_URL, unchanged), prod serves `/mcp-prod` (path-scoped AS under
    // `/prod`, issuer `<PUBLIC_URL>/prod` — RFC 8414 path issuer). Each has its
    // own Identities + AuthStore, so sessions/tokens never cross instances.
    let inst_beta = identities::IiInstance::beta().map_err(anyhow::Error::msg)?;
    let inst_prod = identities::IiInstance::prod().map_err(anyhow::Error::msg)?;
    for inst in [&inst_beta, &inst_prod] {
        tracing::info!(
            "II instance {}: {} ({}) at {} — connect protocol: {}",
            inst.name, inst.ii_url, inst.ii_canister, inst.mcp_path,
            if inst.registration_delegation { "registration-delegation (v2-ready, v1 honored)" } else { "v1 (fetched key)" },
        );
    }
    // Per-instance connect-protocol selection, surfaced on /version so operators
    // can confirm which instance runs which flow without reading env vars.
    let regdel_beta = inst_beta.registration_delegation;
    let regdel_prod = inst_prod.registration_delegation;
    let ids_beta = Identities::new(inst_beta);
    let ids_prod = Identities::new(inst_prod);
    let skills = skills::SkillsCatalog::new();

    let ct = tokio_util::sync::CancellationToken::new();
    // One rmcp streamable-HTTP service per instance, differing only in which
    // Identities store the tools sign with. Stateless + plain-JSON responses:
    // our tools are pure request/response with no server-initiated messages, and
    // this is the most compatible mode across MCP clients (ChatGPT's connector
    // does not complete the stateful SSE/session handshake the rmcp defaults
    // require).
    let make_mcp = |ids: Identities| {
        let agent = agent.clone();
        let skills = skills.clone();
        StreamableHttpService::new(
            move || Ok(IcTools::new(agent.clone(), ids.clone(), skills.clone())),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default()
                .with_stateful_mode(false)
                .with_json_response(true)
                .with_cancellation_token(ct.child_token())
                .with_allowed_hosts(allowed_hosts()),
        )
    };
    let mcp_beta = make_mcp(ids_beta.clone());
    let mcp_prod = make_mcp(ids_prod.clone());

    // Session reaper, one task per instance. It sweeps once shortly after
    // startup and then every 60s (tokio's interval fires its first tick
    // immediately; the startup sweep is harmless, the map is empty then),
    // evicting expired-grant sessions (emitting a "session closed" log each) and
    // giving the journal a close event to reconcile against "session opened".
    // This caps growth from expired grants (the common case: every
    // authenticated session eventually expires); sessions with no recorded
    // expiry (mid-connect, or a v1 session whose completion POST never arrived)
    // are deliberately kept and so are NOT bounded by this. Tied to the shutdown
    // token so the tasks stop cleanly on drain.
    for ids in [ids_beta.clone(), ids_prod.clone()] {
        let reap_ct = ct.child_token();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            // Skip missed ticks rather than the default Burst: if the runtime
            // stalls, resume with a single sweep at the next slot instead of
            // firing several back-to-back catch-up sweeps.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = reap_ct.cancelled() => break,
                    _ = tick.tick() => {
                        ids.reap_expired_sessions().await;
                    }
                }
            }
        });
    }

    // Dynamic client registrations are II-agnostic (redirect allow-list only),
    // so both instances share one store — and one persisted snapshot.
    let clients = auth::load_shared_clients();
    let store_beta = auth::AuthStore::new(ids_beta.clone(), clients.clone());
    let store_prod = auth::AuthStore::new(ids_prod.clone(), clients.clone());

    // The MCP resources are gated by a bearer token issued after Internet
    // Identity login (each by its own instance's store — a beta token is unknown
    // to /mcp-prod and vice versa). `route_layer` (not `layer`) applies the gate
    // ONLY to matched routes, so unmatched paths fall through to a 404 instead of
    // the token gate's 401 — and the `/oauth/*` and `/.well-known/*` routes stay
    // exempt from the bearer check.
    //
    // Browser-based MCP clients (e.g. the Grok/ChatGPT connector UIs) call the
    // resource via `fetch()`, so it needs CORS — applied OUTSIDE the bearer gate
    // so the OPTIONS preflight is answered (2xx) BEFORE authentication, and the
    // 401's `WWW-Authenticate` (the auth-discovery hint) is exposed cross-origin.
    // `Authorization` must be listed explicitly: the `*` wildcard for
    // `Access-Control-Allow-Headers` does NOT cover it per the Fetch spec.
    let mcp_cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::HeaderName::from_static("mcp-protocol-version"),
            axum::http::HeaderName::from_static("mcp-session-id"),
            axum::http::HeaderName::from_static("last-event-id"),
        ])
        .expose_headers([
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderName::from_static("mcp-session-id"),
        ]);
    let protected_mcp = axum::Router::new()
        .nest_service("/mcp", mcp_beta)
        .route_layer(axum::middleware::from_fn_with_state(
            store_beta.clone(),
            auth::require_token,
        ))
        .layer(mcp_cors.clone());
    let protected_mcp_prod = axum::Router::new()
        .nest_service("/mcp-prod", mcp_prod)
        .route_layer(axum::middleware::from_fn_with_state(
            store_prod.clone(),
            auth::require_token,
        ))
        .layer(mcp_cors);

    // The per-instance OAuth endpoints, relative to the instance's prefix.
    fn oauth_endpoints(store: auth::AuthStore) -> axum::Router {
        axum::Router::new()
            .route("/oauth/authorize", axum::routing::get(auth::authorize))
            .route("/oauth/finish", axum::routing::get(auth::finish))
            // The connect callback serves BOTH: v1's cross-origin JSON POSTs from
            // II's frontend, and — behind the registration-delegation flag — the
            // Phase-2 pinned callback PAGE on GET (the sole fragment reader). The
            // GET 404s when the flag is off, so v1 is unaffected.
            .route(
                "/oauth/connect/callback",
                axum::routing::post(auth::connect_callback).get(auth::connect_callback_page),
            )
            // Phase 2 only: the pinned page POSTs the fragment delegation here to
            // be redeemed (404s when the flag is off).
            .route("/oauth/connect/redeem", axum::routing::post(auth::connect_redeem))
            .route("/oauth/token", axum::routing::post(auth::token))
            .route("/oauth/register", axum::routing::post(auth::register))
            .with_state(store)
    }

    // Discovery documents.
    //
    // Beta (the default instance) keeps the root docs. Path-aware
    // protected-resource metadata (RFC 9728 §3.1): the resource `…/mcp` has a
    // path, so its metadata canonically lives at
    // `/.well-known/oauth-protected-resource/mcp`; clients that follow the
    // `resource_metadata` hint use the root doc. We deliberately do NOT add a
    // `/mcp`-suffixed *authorization-server* doc for beta: its issuer is
    // `base_url()` (no path), so per RFC 8414 a strict client requesting the
    // suffixed AS doc would reject it on issuer mismatch.
    //
    // Prod is a path issuer (`<base>/prod`), so its AS metadata lives at the
    // RFC 8414 path-inserted URL `/.well-known/oauth-authorization-server/prod`
    // (plus the OIDC-style `<issuer>/.well-known/…` alternate some clients
    // derive), and its resource doc at
    // `/.well-known/oauth-protected-resource/mcp-prod`.
    let discovery_beta = axum::Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(auth::authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(auth::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            axum::routing::get(auth::protected_resource_metadata),
        )
        .with_state(store_beta.clone());
    let discovery_prod = axum::Router::new()
        .route(
            "/.well-known/oauth-authorization-server/prod",
            axum::routing::get(auth::authorization_server_metadata),
        )
        .route(
            "/prod/.well-known/oauth-authorization-server",
            axum::routing::get(auth::authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp-prod",
            axum::routing::get(auth::protected_resource_metadata),
        )
        .with_state(store_prod.clone());

    // OAuth authorization-server + discovery endpoints (CORS-open for clients).
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);
    // The auth-callback allow-list (II #4091): before contacting the connect
    // callback named in the link fragment, II fetches this origin-global
    // document and requires the callback to be EXACTLY one of the declared
    // entries — fail-closed, so serving it is mandatory once #4091 ships. One
    // document declares both instances' callbacks (the path carries no
    // instance prefix). CORS-open: II's frontend fetches it cross-origin.
    let auth_callbacks = axum::Router::new()
        .route(auth::AUTH_CALLBACKS_WELL_KNOWN, axum::routing::get(auth::auth_callbacks))
        .with_state(vec![store_beta.clone(), store_prod.clone()]);
    let oauth = discovery_beta
        .merge(discovery_prod)
        .merge(oauth_endpoints(store_beta.clone()))
        .nest("/prod", oauth_endpoints(store_prod.clone()))
        .merge(auth_callbacks)
        .layer(cors);

    // When this process started — i.e. when the deployment last (re)started.
    // Every deploy restarts the service, so this is the "last redeployment" time.
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Per-instance handles for the /version live-session gauge (Arc-backed, so
    // cloning shares the same session maps the tools mutate).
    let ver_ids_beta = ids_beta.clone();
    let ver_ids_prod = ids_prod.clone();

    let app = axum::Router::new()
        .route("/", axum::routing::get(|| async { axum::response::Html(INDEX_HTML) }))
        // Unauthenticated build/version probe so operators and the status
        // dashboard can confirm exactly which deployment is live: the running
        // commit (baked in at build time via GIT_SHA), the build time
        // (BUILD_TIME), and when this process started (= last redeployment).
        // Timestamps are Unix epoch seconds (or null when unknown).
        .route(
            "/version",
            axum::routing::get(move || {
                // Clone the Arc-backed handles per request so the handler stays
                // `Fn` (reusable across requests) while the async body owns them.
                let ver_ids_beta = ver_ids_beta.clone();
                let ver_ids_prod = ver_ids_prod.clone();
                async move {
                    // Live sessions per instance: authenticated, non-expired
                    // sessions that made a request within the activity window, so
                    // a disconnected/idle client drops off (see
                    // `Identities::live_session_count`).
                    let live_beta = ver_ids_beta.live_session_count().await;
                    let live_prod = ver_ids_prod.live_session_count().await;
                    axum::Json(serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "commit": option_env!("GIT_SHA").unwrap_or("unknown"),
                        "built_at": option_env!("BUILD_TIME").and_then(|s| s.parse::<u64>().ok()),
                        "started_at": started_at,
                        // H3/P1 health: repeat key requests on a consumed connect_state.
                        // Expected ~0; a sustained rise means II is re-issuing the key
                        // request (breaks connects under strict single-use), so alert on it.
                        "repeat_key_requests": auth::repeat_key_requests(),
                        // Per-instance connect protocol: true = Phase-2 registration
                        // delegation enabled (v1 still honored until that II switches),
                        // false = pinned to the v1 fetched-key flow.
                        "registration_delegation": { "beta": regdel_beta, "prod": regdel_prod },
                        // Per-instance count of live sessions: authenticated,
                        // non-expired, and active within the last few minutes.
                        // A client that disconnects or goes idle drops off after
                        // the activity window.
                        "live_sessions": { "beta": live_beta, "prod": live_prod },
                    }))
                }
            }),
        )
        .merge(oauth)
        .merge(protected_mcp)
        .merge(protected_mcp_prod)
        // Log every inbound request (method, path, status, latency) so we can see
        // what external clients actually hit — discovery probes, unknown paths,
        // etc. Only the path is logged, never the query string, so single-use
        // secrets (`?code=`, `?c=`) don't land in logs.
        .layer(axum::middleware::from_fn(log_request));

    let bind = bind_address();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on http://{bind}  (MCP at /mcp, OAuth at /oauth/*)");
    // Drain-then-cancel, on ALL exit paths. `with_graceful_shutdown` stops
    // accepting new connections and drains the in-flight ones first; only then
    // do we cancel the rmcp services' token. Ordering matters: the token is
    // `with_cancellation_token(ct.child_token())`, and cancelling it asks rmcp
    // to terminate active sessions, so cancelling before the drain would cut the
    // very in-flight MCP requests we want to finish. Capturing the result rather
    // than `?`-ing it means an unexpected serve error (accept failure, etc.)
    // still cancels the token before the error propagates. (Stateless, no
    // long-lived SSE, so there's nothing for the token to cut post-drain.)
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    ct.cancel();
    serve_result?;
    Ok(())
}

/// Resolves when the process is asked to stop, so `axum` drains in-flight
/// requests before exit rather than being cut mid-response. The rmcp
/// cancellation token is cancelled by the caller *after* the drain completes,
/// not here (see the call site).
///
/// Handles BOTH signals: an interactive run is stopped with `SIGINT` (Ctrl-C),
/// but `systemctl stop`/`restart` sends **`SIGTERM`** — which this previously did
/// not catch, so a redeploy killed the process abruptly and severed in-flight
/// requests. We now wait on either.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // If the SIGTERM handler can't be installed, fall back to SIGINT only
        // rather than aborting startup.
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!("could not install SIGTERM handler ({e}); draining on SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

#[cfg(test)]
mod tests {
    use super::calls::decode_bytes_with_did;
    use candid::types::value::IDLArgs;
    use candid_parser::parse_idl_args;

    // Field names are hashed on the Candid wire; decoding against the method's
    // declared return type must recover them (type-less decoding shows hashes).
    #[test]
    fn typed_decode_recovers_field_names() {
        let did = "service : { stats : () -> (record { name : text; url : text }) query }";
        // Encode a record reply (names get hashed in the wire format).
        let bytes = parse_idl_args("(record { name = \"ICP\"; url = \"https://internetcomputer.org\" })")
            .unwrap()
            .to_bytes()
            .unwrap();

        // Type-less decode -> hashed field ids.
        let typeless = IDLArgs::from_bytes(&bytes).unwrap().to_string();
        assert!(!typeless.contains("name ="), "type-less should NOT have names: {typeless}");

        // Typed decode against the .did -> real field names.
        let typed = decode_bytes_with_did(did, "stats", &bytes).expect("typed decode");
        assert!(typed.contains("name ="), "typed should have `name`: {typed}");
        assert!(typed.contains("url ="), "typed should have `url`: {typed}");
    }

    // Every tool must carry MCP annotations, else clients fall back to the unsafe
    // defaults (readOnly=false, destructive=true) and mislabel reads like
    // get_canister_candid as destructive. Assert the read/write classification serializes.
    #[test]
    fn every_tool_has_correct_read_write_annotations() {
        let tools = super::IcTools::tool_router().list_all();
        assert_eq!(tools.len(), 24, "expected 24 tools, got {}", tools.len());
        assert!(
            tools.iter().all(|t| t.annotations.is_some()),
            "every tool must carry annotations (else clients assume write/destructive)"
        );
        let ann = |name: &str| {
            tools
                .iter()
                .find(|t| &*t.name == name)
                .unwrap_or_else(|| panic!("tool {name} not found"))
                .annotations
                .clone()
                .unwrap_or_else(|| panic!("tool {name} has no annotations"))
        };
        // Pure reads (and status, which reads but is an update call) are read-only,
        // AND set destructive_hint=false explicitly so a naive client that doesn't
        // gate destructive on read_only can't mislabel them.
        for name in [
            "get_canister_candid", "discover_app_canisters", "icp_find_canister_by_name", "icp_lookup_canister_info_by_id",
            "icp_list_skills", "icp_get_skill", "icp_oql_guide", "run_canister_oql_query", "get_canister_oql_schema",
            "get_canister_api_doc", "resolve_app", "list_app_accounts", "icp_cycles_balance", "get_app_principal", "icp_canister_status",
        ] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(true), "{name} should be read-only");
            assert_eq!(a.destructive_hint, Some(false), "{name} should set destructive=false explicitly");
        }
        // Destructive writes: not read-only, destructive.
        for name in ["icp_delete_canister", "icp_uninstall_code", "icp_install_code", "icp_update_canister_settings"] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(false), "{name} should not be read-only");
            assert_eq!(a.destructive_hint, Some(true), "{name} should be destructive");
        }
        // Additive/reversible writes: not read-only, not destructive.
        for name in ["icp_create_canister", "icp_top_up_canister", "icp_start_canister", "icp_stop_canister"] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(false), "{name} should not be read-only");
            assert_eq!(a.destructive_hint, Some(false), "{name} should not be destructive");
        }
        // The dual-mode caller is conservatively write + destructive.
        let cc = ann("call_canister");
        assert_eq!(cc.read_only_hint, Some(false));
        assert_eq!(cc.destructive_hint, Some(true));
    }

    // EVERY tool must declare an outputSchema so a model knows the shape of its
    // reply — and MCP requires that schema to be object-rooted. This guards the
    // whole surface: a new tool added without an output schema fails here.
    #[test]
    fn every_tool_declares_an_object_output_schema() {
        let tools = super::IcTools::tool_router().list_all();
        for t in &tools {
            let schema = t
                .output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("tool {} must declare an output schema", t.name));
            assert_eq!(
                schema.get("type"),
                Some(&serde_json::json!("object")),
                "tool {}'s outputSchema must be object-rooted per the MCP spec",
                t.name
            );
        }
    }

    // Spot-check icp_find_canister_by_name's schema lists the expected properties.
    #[test]
    fn find_canister_declares_output_schema() {
        let tools = super::IcTools::tool_router().list_all();
        let tool = tools
            .iter()
            .find(|t| &*t.name == "icp_find_canister_by_name")
            .expect("icp_find_canister_by_name tool not found");
        let schema = tool
            .output_schema
            .as_ref()
            .expect("icp_find_canister_by_name must declare an output schema");
        let props = schema
            .get("properties")
            .and_then(|v| v.as_object())
            .expect("outputSchema must have properties");
        assert!(props.contains_key("query"), "outputSchema should describe `query`");
        assert!(props.contains_key("matches"), "outputSchema should describe `matches`");
    }

    // The object-root guard in ok_structured must drop non-object payloads
    // (a bare array/string can't match an MCP object outputSchema) while
    // still attaching genuine objects.
    #[test]
    fn ok_structured_only_attaches_objects() {
        let obj = super::ok_structured("t".to_string(), &serde_json::json!({"a": 1}));
        assert!(obj.structured_content.is_some(), "an object payload must attach");

        let arr = super::ok_structured("t".to_string(), &serde_json::json!([1, 2, 3]));
        assert!(arr.structured_content.is_none(), "a bare array must be dropped");

        let s = super::ok_structured("t".to_string(), &"hello");
        assert!(s.structured_content.is_none(), "a bare string must be dropped");
    }

    // ok_canister_action normalizes the canister id to its canonical principal
    // text, so the structured field matches the id the management layer acted
    // on (it trims/parses the input) rather than echoing raw whitespace.
    #[test]
    fn ok_canister_action_canonicalizes_canister_id() {
        let result = super::ok_canister_action(
            "  ryjl3-tyaaa-aaaaa-aaaba-cai  ".to_string(),
            Ok("Started ryjl3-tyaaa-aaaaa-aaaba-cai.".to_string()),
        );
        let value = result.structured_content.expect("structured content must be attached");
        assert_eq!(
            value.get("canister_id"),
            Some(&serde_json::json!("ryjl3-tyaaa-aaaaa-aaaba-cai")),
            "structured canister_id must be the canonical, trimmed principal text"
        );
    }

    // A structured icp_find_canister_by_name reply must round-trip through the declared
    // schema shape: text for humans, plus a machine-readable object with a
    // `matches` array carrying each match's fields.
    #[test]
    fn find_canister_output_serializes_to_declared_shape() {
        let output = super::discover::FindCanisterOutput {
            query: "ckUSDC".to_string(),
            matches: vec![super::discover::FoundCanister {
                canister_id: "xevnm-gaaaa-aaaar-qafnq-cai".to_string(),
                name: "ckUSDC".to_string(),
                kind: "token".to_string(),
                note: None,
            }],
        };
        let result = super::ok_structured("human text".to_string(), &output);
        let value = result
            .structured_content
            .expect("structured content must be attached");
        assert_eq!(value.get("query"), Some(&serde_json::json!("ckUSDC")));
        let matches = value.get("matches").and_then(|v| v.as_array()).expect("matches array");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].get("canister_id"),
            Some(&serde_json::json!("xevnm-gaaaa-aaaar-qafnq-cai"))
        );
        assert_eq!(matches[0].get("kind"), Some(&serde_json::json!("token")));
    }

    // resolve_identity_target's precedence/validation rules are part of the tool
    // contract; cover the offline branches (the `app_url` branch needs the
    // network and is exercised separately). Supplying both args must be rejected.
    #[tokio::test]
    async fn resolve_identity_target_rejects_both_args() {
        let err = super::resolve_identity_target(
            Some("https://a.example".to_string()),
            Some("https://b.example".to_string()),
        )
        .await
        .expect_err("both args must be an error");
        assert!(err.contains("not both"), "unexpected message: {err}");
    }

    // A whitespace-only `derivation_origin` is empty after trimming and must be
    // rejected rather than canonicalized into a bogus origin.
    #[tokio::test]
    async fn resolve_identity_target_rejects_blank_derivation_origin() {
        let err = super::resolve_identity_target(Some("   ".to_string()), None)
            .await
            .expect_err("blank derivation_origin must be an error");
        assert!(err.contains("must not be empty"), "unexpected message: {err}");
    }

    // `derivation_origin` is trimmed before canonicalization, so surrounding
    // whitespace never leaks into either the echoed `requested` or the effective
    // `origin` fed to the delegation path.
    #[tokio::test]
    async fn resolve_identity_target_trims_derivation_origin() {
        let target = super::resolve_identity_target(Some("  https://example.com  ".to_string()), None)
            .await
            .expect("valid derivation_origin resolves")
            .expect("an explicit derivation_origin yields a target");
        assert_eq!(target.requested, "https://example.com", "requested must be trimmed");
        assert_eq!(target.origin, "https://example.com", "origin must be the canonical trimmed form");
        assert_eq!(target.source, "explicit");
        assert!(target.application_origin.is_none());
    }

    // Neither arg is the anonymous path: no target, no error.
    #[tokio::test]
    async fn resolve_identity_target_none_is_anonymous() {
        let target = super::resolve_identity_target(None, None)
            .await
            .expect("neither arg is valid (anonymous)");
        assert!(target.is_none(), "neither arg must yield no target");
    }

    // A control character in either identity arg is rejected up front (it would
    // otherwise be echoed back verbatim / corrupt the delegation origin).
    #[tokio::test]
    async fn resolve_identity_target_rejects_control_chars() {
        let err = super::resolve_identity_target(Some("https://ex\u{7}ample.com".to_string()), None)
            .await
            .expect_err("control chars must be rejected");
        assert!(err.contains("control characters"), "unexpected message: {err}");
    }

    // An uppercase scheme must canonicalize the same as lowercase — `target_origin`
    // strips only a lowercase `https://`, so without normalization `HTTPS://` would
    // survive into the host and mangle the origin instead of yielding `https://host`.
    #[tokio::test]
    async fn resolve_identity_target_normalizes_uppercase_scheme() {
        let t = super::resolve_identity_target(Some("HTTPS://example.com".to_string()), None)
            .await
            .expect("uppercase https scheme must be accepted")
            .expect("a derivation_origin yields a target");
        assert_eq!(t.origin, "https://example.com", "unexpected origin: {}", t.origin);
    }

    // A mixed-case HOST is canonicalized to lowercase, so the echoed origin and the
    // delegation-cache key match the app_url path (which serializes via Url::origin())
    // instead of forking `https://Example.COM` from `https://example.com`.
    #[tokio::test]
    async fn resolve_identity_target_lowercases_host() {
        let t = super::resolve_identity_target(Some("https://Example.COM".to_string()), None)
            .await
            .expect("mixed-case host must be accepted")
            .expect("a derivation_origin yields a target");
        assert_eq!(t.origin, "https://example.com", "host must be lowercased: {}", t.origin);
    }

    // A `derivation_origin` with no host (e.g. "https://") reduces to an empty
    // origin and must be rejected rather than derived against.
    #[tokio::test]
    async fn resolve_identity_target_rejects_hostless_derivation_origin() {
        let err = super::resolve_identity_target(Some("https://".to_string()), None)
            .await
            .expect_err("host-less derivation_origin must be rejected");
        assert!(err.contains("host"), "unexpected message: {err}");
    }

    // A non-http(s) scheme must be rejected, not mangled into a bogus https origin.
    #[tokio::test]
    async fn resolve_identity_target_rejects_non_http_scheme() {
        let err = super::resolve_identity_target(Some("ftp://example.com".to_string()), None)
            .await
            .expect_err("ftp:// must be rejected");
        assert!(err.contains("https origin"), "unexpected message: {err}");
    }

    // A whitespace-only `app_url` is rejected before any network resolution, so
    // the caller gets a clear error instead of a confusing downstream URL failure.
    #[tokio::test]
    async fn resolve_identity_target_rejects_blank_app_url() {
        let err = super::resolve_identity_target(None, Some("   ".to_string()))
            .await
            .expect_err("blank app_url must be rejected");
        assert!(err.contains("must not be empty"), "unexpected message: {err}");
    }

    // A non-https `app_url` scheme is rejected early with a clear message rather
    // than failing later in the SSRF guard.
    #[tokio::test]
    async fn resolve_identity_target_rejects_http_app_url() {
        let err = super::resolve_identity_target(None, Some("http://example.com".to_string()))
            .await
            .expect_err("http:// app_url must be rejected");
        assert!(err.contains("https URL"), "unexpected message: {err}");
    }

    // User-info in an app_url is silently dropped by `Url::origin()` downstream, so
    // `https://user@host` would resolve to `https://host` — a value the caller never
    // supplied. Reject it up front (consistent with derivation_origin validation).
    #[tokio::test]
    async fn resolve_identity_target_rejects_userinfo_app_url() {
        let err = super::resolve_identity_target(None, Some("https://user:pass@example.com".to_string()))
            .await
            .expect_err("app_url with user-info must be rejected");
        assert!(err.contains("user-info"), "unexpected message: {err}");
    }

    // A host-less app_url ("https://") has no origin to derive against and must be
    // rejected here rather than failing later in URL parsing / the SSRF guard.
    #[tokio::test]
    async fn resolve_identity_target_rejects_hostless_app_url() {
        let err = super::resolve_identity_target(None, Some("https://".to_string()))
            .await
            .expect_err("host-less app_url must be rejected");
        assert!(err.contains("real host"), "unexpected message: {err}");
    }

    // The human-readable identity annotation must surface a requested≠derived
    // mismatch (and the source) in ALL clients, not only for app_url_default.
    #[test]
    fn identity_annotation_surfaces_mismatch_and_source() {
        // requested == origin: origin + source, but no redundant `requested` echo.
        let t = super::IdentityTarget {
            origin: "https://nns.ic0.app".to_string(),
            requested: "https://nns.ic0.app".to_string(),
            source: "explicit".to_string(),
            application_origin: None,
        };
        let a = super::identity_annotation(&t, None);
        assert!(a.contains("derived for https://nns.ic0.app"), "{a}");
        assert!(a.contains("source: explicit"), "{a}");
        assert!(!a.contains("requested"), "no mismatch must not echo requested: {a}");

        // requested != origin (e.g. a stripped path): the mismatch is surfaced.
        let t2 = super::IdentityTarget {
            origin: "https://app.example.com".to_string(),
            requested: "https://app.example.com/some/path".to_string(),
            source: "explicit".to_string(),
            application_origin: None,
        };
        let a2 = super::identity_annotation(&t2, Some("aaaaa-aa"));
        assert!(a2.contains("signed as aaaaa-aa"), "{a2}");
        assert!(a2.contains("requested https://app.example.com/some/path"), "{a2}");

        // app_url_default keeps its explicit "assumed" guidance.
        let t3 = super::IdentityTarget {
            origin: "https://example.com".to_string(),
            requested: "https://example.com".to_string(),
            source: "app_url_default".to_string(),
            application_origin: Some("https://example.com".to_string()),
        };
        let a3 = super::identity_annotation(&t3, None);
        assert!(a3.contains("ASSUMES the app origin"), "{a3}");
    }

    // The OQL tools' derivation-origin path (run_canister_oql_query / get_canister_oql_schema) must fail
    // closed on the same bad input as resolve_identity_target: None stays anonymous,
    // control chars and host-less origins are rejected, and a valid one canonicalizes.
    #[test]
    fn clean_derivation_origin_validates_and_canonicalizes() {
        assert_eq!(super::clean_derivation_origin(None).unwrap(), None);
        assert!(super::clean_derivation_origin(Some("   ".to_string())).is_err(), "blank rejected");
        assert!(
            super::clean_derivation_origin(Some("https://a\u{7}b.com".to_string())).is_err(),
            "control chars rejected"
        );
        assert!(
            super::clean_derivation_origin(Some("https://".to_string())).is_err(),
            "host-less rejected"
        );
        assert!(
            super::clean_derivation_origin(Some("ftp://example.com".to_string())).is_err(),
            "non-http(s) scheme rejected"
        );
        assert!(
            super::clean_derivation_origin(Some("https://ex ample.com".to_string())).is_err(),
            "embedded space rejected"
        );
        assert!(
            super::clean_derivation_origin(Some("https://user@example.com".to_string())).is_err(),
            "user-info rejected (would derive a different principal than the bare origin)"
        );
        assert!(
            super::clean_derivation_origin(Some("http://example.com".to_string())).is_err(),
            "explicit http:// rejected (https-only contract; target_origin would silently upgrade it)"
        );
        assert_eq!(
            super::clean_derivation_origin(Some("  https://example.com  ".to_string())).unwrap(),
            Some("https://example.com".to_string()),
            "valid input trims + canonicalizes"
        );
    }
}
