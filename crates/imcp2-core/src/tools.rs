//! The MCP tools: an [`rmcp`] server handler exposing Internet Computer tools
//! over streamable HTTP.
//!
//! The LLM only ever deals with textual Candid; encoding/decoding happens in
//! `calls`. Anonymous canister calls use the shared agent injected by the
//! embedding application (see [`crate::McpServer`]); per-app identities are
//! minted on demand from the connection's registered session key (see
//! `identities`).

use candid::Principal;
use ic_agent::{Agent, Identity};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
    schemars, ErrorData as McpError, RoleServer, ServerHandler,
};

use crate::{calls, discover, identities, identities::Identities, management, skills};

/// Cap on the per-canister Candid probes open_app / discover_app_canisters run to
/// fill in OQL / api-doc capability flags (#3). Discovery output is already bounded,
/// but a large declared manifest could still list many ids — probe only the most
/// authoritative handful so the extra fan-out stays small.
const MAX_CAPABILITY_PROBES: usize = 8;

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

// Per-tool argument and output types live in the module that implements the
// tool: `calls` (get_canister_candid, canister_query, canister_update_call),
// `discover`, `identities`, `skills`, `management`. main.rs only wires the tools
// together.

#[derive(Clone)]
pub struct IcTools {
    agent: Agent,
    identities: Identities,
    skills: skills::SkillsCatalog,
    /// Where a tool call finds the Internet Identity session it acts as — the
    /// one per-deployment seam (see [`SessionSource`]).
    session: SessionSource,
}

#[tool_router]
impl IcTools {
    pub fn new(
        agent: Agent,
        identities: Identities,
        skills: skills::SkillsCatalog,
        session: SessionSource,
    ) -> Self {
        Self {
            agent,
            identities,
            skills,
            session,
        }
    }

    /// The session id this tool call acts as, per the deployment's
    /// [`SessionSource`]: looked up from the request's [`AuthedSession`]
    /// extension under `Bearer` (multi-user, hosted), or the fixed
    /// login-established session under `Singleton` (single-user, local).
    /// `None` means the call is unauthenticated ("needs an authenticated
    /// session" errors at the call sites are unchanged).
    fn current_session_id(&self, ctx: &RequestContext<RoleServer>) -> Option<String> {
        match &self.session {
            SessionSource::Bearer => authed_session(ctx).map(|s| s.session_id),
            SessionSource::Singleton(id) => {
                let _ = ctx;
                Some(id.clone())
            }
        }
    }

    #[tool(
        description = "Fetch the Candid (.did) interface definition of an Internet Computer canister, read from its public `candid:service` metadata. Also reports two capability flags: `oql` (the canister exposes the OQL query surface — READ it via icp_oql_guide → get_canister_oql_schema → canister_query with the `oql` argument, since a Candid `method` query is then rejected) and `api_doc_available` (a `getApiDoc`/`get_api_doc` method exists — call get_canister_api_doc for a prose behavior guide; skip that call when this is false).",
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
                    // Same predicate get_canister_api_doc uses, so the flag gates that
                    // call: true means a `getApiDoc`/`get_api_doc` method exists.
                    let api_doc_available = calls::api_doc_method(&did).is_some();
                    let output = calls::GetCandidOutput {
                        canister_id,
                        candid: did.clone(),
                        oql,
                        api_doc_available,
                    };
                    // Assemble any capability notes as separate blocks so the first
                    // block stays the raw, paste-able `.did`.
                    let mut notes = Vec::new();
                    if oql {
                        notes.push(format!(
                            "This canister exposes an OQL query surface (a JSON query language \
                             over its data), so READ it through the OQL tools — a Candid `method` \
                             query via canister_query is rejected here. Order: icp_oql_guide \
                             (dialect, once) → get_canister_oql_schema (entities/fields) → \
                             canister_query with the `oql` argument (run a JSON query, get a table). \
                             Those wrap the `schema`/`execute` methods (no Candid escaping). Per-app \
                             data is caller-gated, so the OQL read path REQUIRES the app's \
                             derivation_origin — an anonymous OQL read is rejected (for now), not \
                             silently empty; pass the derivation_origin from open_app / resolve_app. \
                             See icp_oql_guide (or the `{OQL_USAGE_URI}` resource) for the dialect. \
                             canister_update_call then handles UPDATE calls only."
                        ));
                    }
                    notes.push(if api_doc_available {
                        "This canister exposes an API-doc method (api_doc_available=true): call \
                         get_canister_api_doc for a prose \"how this app behaves\" guide (units, \
                         auth, lifecycle, gotchas)."
                            .to_string()
                    } else {
                        "This canister declares no API-doc method (api_doc_available=false) — don't \
                         call get_canister_api_doc; the Candid types above are the interface."
                            .to_string()
                    });
                    let mut blocks = vec![did];
                    blocks.extend(notes);
                    Ok(ok_structured_blocks(blocks, &output))
                }
                Err(e) => Ok(err(format!("metadata is not valid UTF-8: {e}"))),
            },
            Err(e) => Ok(err(format!(
                "could not read candid:service metadata: {e}"
            ))),
        }
    }

    #[tool(
        description = "Load the OQL query-surface guide: the JSON query dialect for canisters that expose OQL (get_canister_candid reports `oql: true`) — entities/fields/edges via `schema`, and the `execute` query object (filters, aggregation, ordering, edge traversal, paging). This is step ONE of the fixed sequence guide→schema→query: read this once, then `get_canister_oql_schema` for the exact entity/field names (they are the schema's own — often PLURAL and unlike the Candid types/methods, e.g. `bookings` not `Booking`/`getBookings`), then `canister_query` with the `oql` argument. Never guess bespoke per-question methods. The schema read and the query REQUIRE the app's `derivation_origin` (from open_app / resolve_app) — anonymous per-app reads are disabled for now and are rejected with guidance. Both wrap the `schema`/`execute` methods, so you write plain JSON — no Candid escaping.",
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
        description = "Fetch the OQL schema catalogue of a canister that exposes the OQL surface (get_canister_candid reports `oql: true`): its entities, their primary keys, fields, and edges, as JSON. The MIDDLE step of guide→schema→query: read `icp_oql_guide` once, then call THIS before canister_query so you use the exact entity/field names instead of guessing. Entity names are the schema's own — often PLURAL and different from the Candid types/methods (e.g. `bookings`, not `Booking`/`getBookings`). Returns the schema plus a ready-to-run `canister_query` example per entity (each preserving this call's identity). AUTH: `derivation_origin` is REQUIRED — the schema itself is gated by the caller's principal, so a read with no origin is REJECTED (anonymous per-app reads are disabled for now) with guidance to pass it, rather than returning an empty entity list you'd misread as \"the app has no data model\". Pass the app's canonical `derivation_origin` (from open_app / resolve_app) to read the entities visible to the USER; the reply echoes `derived_for_origin` / `acted_as_principal`.",
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
        // Anonymous per-app reads are disabled for now (the schema is itself gated by
        // the caller's principal): reject with guidance instead of returning an empty
        // entity list an agent would misread as "the app has no data model".
        let target = match resolve_identity_target(derivation_origin) {
            Ok(t) => t,
            Err(e) => return Ok(err(e)),
        };
        let Some(target) = target else {
            return Ok(err(oql_needs_origin_error("Reading the OQL schema")));
        };
        let requested = Some(target.requested.clone());
        let origin = Some(target.origin.clone());
        let (agent, acted_as) = match self
            .resolve_agent(&ctx, Some(target.origin.as_str()), account.as_deref(), "reading the schema")
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
        // An origin is required (rejected above if absent), so this is never anonymous.
        let is_anonymous = false;
        // #8: a COMPLETE canister_query per entity, carrying the SAME identity this
        // schema was read under (so copying one doesn't drop to anon).
        let example_queries =
            calls::oql_query_examples(&canister_id, &schema, Some(target.origin.as_str()), account.as_deref());
        // #1: an EMPTY schema (no visible entities) for this authenticated account is
        // "nothing visible here", not "the app has no data model".
        let empty_note = if calls::oql_schema_is_empty(&schema) {
            Some(
                "This account sees no OQL entities on this canister — confirm the \
                 derivation_origin/account are the ones the user uses in their browser."
                    .to_string(),
            )
        } else {
            None
        };
        // Keep the primary block as the raw schema JSON (paste-able); surface the
        // empty-note, the ready-to-run examples, and the identity note as SEPARATE
        // blocks so none of them break the JSON for a copy-paste consumer.
        let mut blocks = vec![schema.clone()];
        if let Some(note) = &empty_note {
            blocks.push(note.clone());
        }
        if !example_queries.is_empty() {
            blocks.push(format!(
                "Ready-to-run queries (read-only; each preserves this identity):\n{}",
                example_queries.join("\n")
            ));
        }
        blocks.push(format!("[{}]", identity_annotation(&target, acted_as.as_deref())));
        let output = calls::OqlSchemaOutput {
            canister_id,
            schema,
            acted_as_principal: acted_as,
            derived_for_origin: origin,
            requested,
            is_anonymous,
            note: empty_note,
            example_queries,
        };
        Ok(ok_structured_blocks(blocks, &output))
    }

    #[tool(
        description = "Read a canister's own API documentation — a prose \"how this app behaves\" guide covering units, auth, lifecycle, non-obvious semantics, mutation safety, polling rules, and gotchas — if it exposes a `getApiDoc`/`get_api_doc` method. Call this ONLY when get_canister_candid (or open_app) reports `api_doc_available: true`; most canisters have no such doc, and then the Candid types ARE the interface. Returns a STRUCTURED result in every case (never a bare error): on success `available: true` + the doc markdown; otherwise `available: false` with `expected` (true = interface read fine, no such method — don't retry) and `retry` (true = a transient/unreachable failure — retry) plus a `next` hint, so you can tell \"no doc here\" from \"couldn't reach it\".",
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
        // A structured "not available" (#6) so the agent can tell an EXPECTED
        // absence (interface read fine, no api-doc method — don't retry) from an
        // UNREACHABLE canister (couldn't read the interface / the call trapped —
        // retry) instead of getting one opaque error for both.
        let unavailable = |expected: bool, retry: bool, next: &str| {
            let output = calls::ApiDocOutput {
                canister_id: canister_id.clone(),
                available: false,
                method: None,
                doc: None,
                expected,
                retry,
                next: Some(next.to_string()),
            };
            ok_structured(next.to_string(), &output)
        };
        let Some(did) = did.as_deref() else {
            // Interface unreadable: can't tell whether an api-doc method exists, and
            // this is often transient (or access-restricted) — flag it retryable.
            return Ok(unavailable(
                false,
                true,
                "Couldn't read this canister's Candid interface, so its API-doc method (if any) is \
                 unknown — this may be transient. Retry, or read the interface with \
                 get_canister_candid.",
            ));
        };
        let method = match calls::api_doc_method(did) {
            Some(m) => m,
            None => {
                // Interface read fine; the canister simply declares no api-doc method
                // — expected for most canisters, and retrying won't change it.
                return Ok(unavailable(
                    true,
                    false,
                    "This canister declares no `getApiDoc`/`get_api_doc` method — most canisters \
                     don't. Use get_canister_candid for the interface; its api_doc_available flag \
                     mirrors this.",
                ));
            }
        };
        let arg_bytes = match calls::encode_unit_arg() {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };
        let reply = match calls::raw_call(&self.agent, principal, method, arg_bytes, true).await {
            Ok(b) => b,
            Err(e) => {
                // The method exists but the call failed — a transient/network issue,
                // so retryable (distinct from the "no such method" case above).
                return Ok(unavailable(
                    false,
                    true,
                    &format!("The {method} call failed ({e}); this is likely transient — retry."),
                ));
            }
        };
        let doc = calls::decode_text_reply(&reply);
        let output = calls::ApiDocOutput {
            canister_id,
            available: true,
            method: Some(method.to_string()),
            doc: Some(doc.clone()),
            expected: false,
            retry: false,
            next: None,
        };
        Ok(ok_structured(doc, &output))
    }

    /// The agent to sign calls with for a request, and the principal it signs as:
    /// the shared anonymous agent (principal `None`) when `origin` is `None`, else
    /// one backed by a short-lived account delegation for that Internet Identity
    /// derivation `origin`, derived on demand from this connection's standing
    /// credential. `origin` must be a VALIDATED derivation origin: the canonical one
    /// from [`resolve_identity_target`], which every caller here now passes
    /// (canister_update_call, both of canister_query's paths, and
    /// get_canister_oql_schema). (get_app_principal and
    /// list_app_accounts don't use this helper — they call
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
                let session_id = self
                    .current_session_id(ctx)
                    .ok_or_else(|| format!("{what} as an app needs an authenticated session"))?;
                let delegated = self
                    .identities
                    .delegated_identity_for(&session_id, origin, account)
                    .await?;
                let principal = delegated.sender().ok().map(|p| p.to_text());
                // Clone the injected agent and swap in the delegated identity:
                // authenticated calls ride the host's boundary-node routing,
                // never a second hard-coded endpoint.
                let mut agent = self.agent.clone();
                agent.set_identity(delegated);
                Ok((agent, principal))
            }
        }
    }

    /// Probe the app's OWN data canisters once (#3): fetch each candidate's Candid
    /// anonymously (the interface is public) and record its OQL / api-doc capability
    /// flags on the `DiscoveredCanister`. Only app-owned data candidates are probed
    /// — never the frontend or a shared system canister (ledger/II/NNS) — so the
    /// caller-gated data-access handle the flags feed stays correctly scoped. Probes
    /// run CONCURRENTLY and fail soft: an unreadable interface just leaves the flags
    /// null. Bounded by `MAX_CAPABILITY_PROBES` so a large manifest can't fan out
    /// unboundedly.
    async fn enrich_capabilities(&self, canisters: &mut [discover::DiscoveredCanister]) {
        let targets: Vec<(usize, Principal)> = canisters
            .iter()
            .enumerate()
            .filter(|(_, c)| discover::is_app_data_candidate(c))
            .filter_map(|(i, c)| Principal::from_text(&c.canister_id).ok().map(|p| (i, p)))
            .take(MAX_CAPABILITY_PROBES)
            .collect();
        if targets.is_empty() {
            return;
        }
        let mut set = tokio::task::JoinSet::new();
        for (i, principal) in targets {
            let agent = self.agent.clone();
            set.spawn(async move {
                let did = calls::candid_service(&agent, principal).await;
                // Only conclude flags when the interface was actually read; a failed
                // read leaves them null (unknown), not a misleading `false`.
                let flags = did
                    .as_deref()
                    .map(|d| (calls::has_oql(d), calls::api_doc_method(d).is_some()));
                (i, flags)
            });
        }
        while let Some(res) = set.join_next().await {
            if let Ok((i, Some((oql, api_doc)))) = res {
                canisters[i].oql = Some(oql);
                canisters[i].api_doc_available = Some(api_doc);
            }
        }
    }

    #[tool(
        description = "Make an UPDATE call (a state-changing call) on an Internet Computer canister method, with textual Candid in and out. Args are encoded against the method's declared Candid types (so plain literals like 42 coerce correctly — no `: type` annotations needed). Omit `derivation_origin` to call anonymously, or pass it to call AS your account at that app — a short-lived account delegation is derived on demand from this connection's standing Internet Identity credential. `derivation_origin` is the app's EXACT canonical II derivation origin (not necessarily its visible URL; don't infer it from alternativeOrigins). Get it once from open_app / resolve_app (which turn an app name or URL into the derivation origin under the guessed-domain gate) and reuse it here — this tool does NOT accept a raw website URL. By default this uses the app's default account; pass `account` (a name from list_app_accounts) for a specific one. The result echoes `derived_for_origin` + `requested` + `acted_as_principal` so you can catch an origin mismatch. For READ-only calls (Candid query methods or OQL queries) use canister_query instead. If get_canister_candid couldn't fetch the interface, pass the `.did` text as `candid` so args/replies are still typed.",
        annotations(title = "Make a canister update call", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<calls::CanisterUpdateCallOutput>(),
    )]
    async fn canister_update_call(
        &self,
        Parameters(calls::CanisterUpdateCallArgs {
            canister_id,
            method,
            args,
            derivation_origin,
            account,
            candid,
        }): Parameters<calls::CanisterUpdateCallArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // The interface to encode/decode against: the canister's own
        // candid:service if exposed, else the caller-supplied `candid`. Update calls
        // are never redirected (OQL is read-only), so no oql_query_redirect here.
        let did = calls::resolve_did(&self.agent, principal, candid.as_deref()).await;
        let arg_bytes = match calls::encode_args(did.as_deref(), &method, &args) {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };
        // Resolve which principal to act as: none = anonymous; else the app's
        // effective (canonical) II derivation origin, from the caller's explicit
        // `derivation_origin` (obtained once via open_app / resolve_app).
        let target = match resolve_identity_target(derivation_origin) {
            Ok(t) => t,
            Err(e) => return Ok(err(e)),
        };
        let origin = target.as_ref().map(|t| t.origin.as_str());
        let (agent, acted_as_principal) = match self
            .resolve_agent(&ctx, origin, account.as_deref(), "calling")
            .await
        {
            Ok(a) => a,
            Err(e) => return Ok(err(e)),
        };
        let reply_bytes = match calls::raw_call(&agent, principal, &method, arg_bytes, false).await {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("call failed: {e}"))),
        };
        // Decode against the Candid interface so field names are recovered.
        let reply = calls::decode_reply(did.as_deref(), &method, &reply_bytes);
        let (derived_for_origin, requested, derivation_origin_source) = match &target {
            Some(t) => (Some(t.origin.clone()), Some(t.requested.clone()), Some(t.source.clone())),
            None => (None, None, None),
        };
        let is_anonymous = target.is_none();
        // Keep the primary text block pure textual Candid (paste-able); surface the
        // identity note (so a wrong-principal is visible to text-only clients) as a
        // SEPARATE block rather than contaminating the reply.
        let mut blocks = vec![reply.clone()];
        if let Some(t) = &target {
            let acted = acted_as_principal.as_deref().unwrap_or("<unknown>");
            blocks.push(format!("[{}]", identity_annotation(t, Some(acted))));
        }
        let output = calls::CanisterUpdateCallOutput {
            canister_id, method, reply,
            acted_as_principal, derived_for_origin, requested, derivation_origin_source,
            is_anonymous,
        };
        Ok(ok_structured_blocks(blocks, &output))
    }

    #[tool(
        description = "If the request is about a specific app or the user's own data in it (a balance, holdings, a profile, \"what can it do\"), start with open_app first to resolve the app and discover its canisters, then compose the answer from what it returns, since there is rarely a dedicated per-feature tool. READ from an Internet Computer canister — provide EITHER a Candid `query` method OR an OQL query (exactly one). `method` is a query function from the canister's Candid interface, invoked with textual-Candid `args`; `oql` is an OQL query as a JSON object string, run against the canister's `execute` method (no Candid escaping — write plain JSON). Use `oql` when get_canister_candid reports `oql: true` (a Candid `method` query is then REJECTED — read via OQL); use `method` for a plain query canister such as a ledger. The `oql` path REQUIRES `derivation_origin` (per-app data is caller-gated; an anonymous OQL read is rejected for now) and returns `columns` + `rows` (a markdown table) with `has_more` for paging; on an empty result it validates the query's `start` against the schema and returns valid_entities + a did_you_mean repair. The `method` path may be anonymous, or pass `derivation_origin` + `account` to read AS your account; it returns the decoded reply in textual Candid. Get `derivation_origin` from open_app / resolve_app (not a raw URL), and the OQL entity/field names from get_canister_oql_schema. For state changes use canister_update_call.",
        annotations(title = "Query a canister (Candid method or OQL)", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<calls::CanisterQueryOutput>(),
    )]
    async fn canister_query(
        &self,
        Parameters(calls::CanisterQueryArgs {
            canister_id,
            method,
            args,
            oql,
            derivation_origin,
            account,
            candid,
        }): Parameters<calls::CanisterQueryArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // Normalize: an empty/whitespace-only `method`/`oql` counts as absent, so a
        // blank string doesn't masquerade as "both provided".
        let method = method.map(|m| m.trim().to_string()).filter(|m| !m.is_empty());
        let oql = oql.filter(|o| !o.trim().is_empty());
        match (method, oql) {
            (Some(_), Some(_)) => Ok(err(
                "provide EITHER `method` (a Candid query) OR `oql` (an OQL query) — not both."
                    .into(),
            )),
            (None, None) => Ok(err(
                "canister_query needs a read to run: pass `method` (a Candid query function) or \
                 `oql` (an OQL query object). For a canister that exposes an OQL surface \
                 (get_canister_candid reports oql: true) use `oql`; otherwise use `method`."
                    .into(),
            )),
            (Some(method), None) => {
                self.canister_candid_query(
                    &ctx, principal, canister_id, method, args, derivation_origin, account, candid,
                )
                .await
            }
            (None, Some(oql)) => {
                self.canister_oql_query(&ctx, principal, canister_id, oql, derivation_origin, account)
                    .await
            }
        }
    }

    /// `canister_query`'s Candid-`method` path: a read-only query call, encoded and
    /// decoded against the canister's Candid interface. Rejected on an OQL canister
    /// (data reads go through the `oql` path); may be anonymous or as an app account.
    #[allow(clippy::too_many_arguments)]
    async fn canister_candid_query(
        &self,
        ctx: &RequestContext<RoleServer>,
        principal: Principal,
        canister_id: String,
        method: String,
        args: String,
        derivation_origin: Option<String>,
        account: Option<String>,
        candid: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        // The interface to encode/decode against: the canister's own candid:service
        // if exposed, else the caller-supplied `candid`.
        let did = calls::resolve_did(&self.agent, principal, candid.as_deref()).await;
        // Prefer OQL: a canister that exposes an OQL query surface must be READ with
        // an OQL query, so reject a raw Candid `method` query here. Fail fast, before
        // encoding args.
        if let Some(msg) = calls::oql_query_redirect(did.as_deref()) {
            return Ok(err(msg));
        }
        // Read/write split: a query call to an UPDATE method is rejected by the
        // replica at runtime, so when the interface is readable and `method` is
        // declared as an update (not a query), fail fast with a clear pointer to
        // canister_update_call instead of an opaque failure. Fail OPEN when the
        // interface can't be read or the method isn't declared (is_query_method →
        // None): the IC then decides, matching the old permissive behavior. (The
        // reverse — a query method called as an update — is valid on the IC, so
        // canister_update_call stays permissive.)
        if let Some(did_text) = did.as_deref() {
            if calls::is_query_method(did_text, &method) == Some(false) {
                return Ok(err(format!(
                    "`{method}` is not a `query` method on this canister — its Candid signature is \
                     an update method, which the replica refuses to run as a query. Call it with \
                     canister_update_call instead (a state-changing update call)."
                )));
            }
        }
        let arg_bytes = match calls::encode_args(did.as_deref(), &method, &args) {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };
        let target = match resolve_identity_target(derivation_origin) {
            Ok(t) => t,
            Err(e) => return Ok(err(e)),
        };
        let origin = target.as_ref().map(|t| t.origin.as_str());
        let (agent, acted_as_principal) = match self
            .resolve_agent(ctx, origin, account.as_deref(), "querying")
            .await
        {
            Ok(a) => a,
            Err(e) => return Ok(err(e)),
        };
        let reply_bytes = match calls::raw_call(&agent, principal, &method, arg_bytes, true).await {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("query failed: {e}"))),
        };
        let reply = calls::decode_reply(did.as_deref(), &method, &reply_bytes);
        let (derived_for_origin, requested, derivation_origin_source) = match &target {
            Some(t) => (Some(t.origin.clone()), Some(t.requested.clone()), Some(t.source.clone())),
            None => (None, None, None),
        };
        let is_anonymous = target.is_none();
        // #1: an anonymous query whose reply LOOKS empty is most likely an auth
        // artifact (per-app data is caller-gated), not "no data". Computed only from
        // local facts (anonymous + empty-looking reply); conservative, so a reply
        // with real content never trips it.
        let note = (is_anonymous && calls::candid_reply_is_empty(&reply)).then(|| {
            calls::anonymous_empty_note(
                "this query call",
                "the app's canonical `derivation_origin` (from open_app / resolve_app)",
            )
        });
        let mut blocks = vec![reply.clone()];
        if let Some(n) = &note {
            blocks.push(n.clone());
        }
        if let Some(t) = &target {
            let acted = acted_as_principal.as_deref().unwrap_or("<unknown>");
            blocks.push(format!("[{}]", identity_annotation(t, Some(acted))));
        }
        let output = calls::CanisterQueryOutput {
            canister_id,
            mode: "candid".to_string(),
            method: Some(method),
            reply: Some(reply),
            columns: Vec::new(),
            rows: Vec::new(),
            has_more: false,
            acted_as_principal,
            derived_for_origin,
            requested,
            derivation_origin_source,
            is_anonymous,
            note,
            valid_entities: None,
            did_you_mean: None,
        };
        Ok(ok_structured_blocks(blocks, &output))
    }

    /// `canister_query`'s `oql` path (the former run_canister_oql_query tool): wrap
    /// the JSON query as `execute`'s single text arg, run it, and decode the tabular
    /// reply. Anonymous per-app OQL reads are disabled, so a `derivation_origin` is
    /// REQUIRED; an empty/failed result is diagnosed against the schema for the SAME
    /// principal (#1/#7).
    async fn canister_oql_query(
        &self,
        ctx: &RequestContext<RoleServer>,
        principal: Principal,
        canister_id: String,
        oql: String,
        derivation_origin: Option<String>,
        account: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        // Validate the query is a JSON object and wrap it as `execute`'s single text
        // arg — the model writes plain JSON, we do the Candid encoding.
        let query_json = match calls::normalize_oql_query(&oql) {
            Ok(s) => s,
            Err(e) => return Ok(err(e)),
        };
        let arg_bytes = match calls::encode_text_arg(&query_json) {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };
        // Anonymous per-app reads are disabled for now (this canister gates data by
        // the caller's principal), so an OQL query REQUIRES a derivation origin.
        let target = match resolve_identity_target(derivation_origin) {
            Ok(t) => t,
            Err(e) => return Ok(err(e)),
        };
        let Some(target) = target else {
            return Ok(err(oql_needs_origin_error("Running an OQL query")));
        };
        let requested = Some(target.requested.clone());
        let origin = Some(target.origin.clone());
        let derivation_origin_source = Some(target.source.clone());
        let (agent, acted_as) = match self
            .resolve_agent(ctx, Some(target.origin.as_str()), account.as_deref(), "querying")
            .await
        {
            Ok(a) => a,
            Err(e) => return Ok(err(e)),
        };
        let identity_note = format!("[{}]", identity_annotation(&target, acted_as.as_deref()));
        // An origin is required (rejected above if absent), so this is never anonymous.
        let is_anonymous = false;
        let reply = match calls::raw_call(&agent, principal, "execute", arg_bytes, true).await {
            Ok(b) => b,
            Err(e) => {
                // A trap is the OTHER way an invalid `start` shows up (#7): validate
                // it against the schema for THIS principal and fold the repair into
                // the error. Failed context: only the unknown-`start` repair is
                // appended, never a "came back empty" note.
                let d = diagnose_empty_oql(&agent, principal, &query_json, is_anonymous, EmptyContext::Failed).await;
                let mut msg = format!("OQL execute failed: {e}");
                if let Some(note) = d.note {
                    msg.push_str(&format!("\n\n{note}"));
                }
                return Ok(err(msg));
            }
        };
        // Decode the reply against the canister's interface so cell/field names are
        // recovered (the wire format hashes them).
        let did = calls::resolve_did(&agent, principal, None).await;
        match calls::parse_execute_reply(did.as_deref(), &reply) {
            calls::OqlResult::Table { columns, rows, has_more } => {
                // Validate-on-empty (#1/#7): a 0-row result is diagnosed with facts
                // from the SAME principal — unknown-`start` repair, or a benign
                // "0 rows for this account" — never by probing others.
                let mut diag = if rows.is_empty() {
                    diagnose_empty_oql(&agent, principal, &query_json, is_anonymous, EmptyContext::EmptyResult).await
                } else {
                    OqlEmptyDiagnosis::none()
                };
                if rows.is_empty() && diag.note.is_none() {
                    diag.note = Some(format!(
                        "Query matched 0 rows for this account{}.",
                        calls::oql_query_start(&query_json)
                            .map(|s| format!(" (start: \"{s}\")"))
                            .unwrap_or_default()
                    ));
                }
                let mut blocks = vec![calls::render_table(&columns, &rows, has_more)];
                if let Some(note) = &diag.note {
                    blocks.push(note.clone());
                }
                blocks.push(identity_note);
                let output = calls::CanisterQueryOutput {
                    canister_id,
                    mode: "oql".to_string(),
                    method: None,
                    reply: None,
                    columns,
                    rows,
                    has_more,
                    acted_as_principal: acted_as,
                    derived_for_origin: origin,
                    requested,
                    derivation_origin_source,
                    is_anonymous,
                    note: diag.note,
                    valid_entities: diag.valid_entities,
                    did_you_mean: diag.did_you_mean,
                };
                Ok(ok_structured_blocks(blocks, &output))
            }
            calls::OqlResult::QueryError(msg) => {
                // The canister returned its error arm. An invalid `start` can land
                // here too, so enrich with the schema-based repair (#7).
                let d = diagnose_empty_oql(&agent, principal, &query_json, is_anonymous, EmptyContext::Failed).await;
                let mut text = format!("the canister returned an OQL error: {msg}");
                if let Some(note) = d.note {
                    text.push_str(&format!("\n\n{note}"));
                }
                Ok(err(text))
            }
            calls::OqlResult::TooManyColumns { column_count } => {
                // The reply's first row was wider than the tool will densify. This
                // is NOT pageable (paging raises `offset`, which returns more rows,
                // not fewer columns), so give the actionable fix — narrow `select`
                // — rather than a `has_more` that would loop the agent forever.
                Ok(err(format!(
                    "This OQL result has {column_count} columns, more than the \
                     {max} this tool returns. Narrow the query's `select` to the \
                     columns you need and re-query. (Paging with a higher `offset` \
                     won't help — `offset` returns more rows, not fewer columns.)",
                    max = calls::MAX_OQL_COLUMNS,
                )))
            }
            calls::OqlResult::Unrecognized(raw) => {
                // Not a recognizable OQL result — hand back the raw decoded reply so
                // the model still has the data. Carry a `note` (rather than null) so a
                // structured-only consumer doesn't misread empty columns/rows as
                // "no data" when the reply actually carried content (in the text block).
                let unparsed_note =
                    "This reply couldn't be parsed as an OQL table; the raw decoded reply is in the \
                     text block. This is NOT an empty result — read the raw reply for the data."
                        .to_string();
                let blocks = vec![
                    format!("(Could not parse this as an OQL table; raw reply below.)\n\n{raw}"),
                    identity_note,
                ];
                let output = calls::CanisterQueryOutput {
                    canister_id,
                    mode: "oql".to_string(),
                    method: None,
                    reply: None,
                    columns: Vec::new(),
                    rows: Vec::new(),
                    has_more: false,
                    acted_as_principal: acted_as,
                    derived_for_origin: origin,
                    requested,
                    derivation_origin_source,
                    is_anonymous,
                    note: Some(unparsed_note),
                    valid_entities: None,
                    did_you_mean: None,
                };
                Ok(ok_structured_blocks(blocks, &output))
            }
        }
    }

    #[tool(
        description = "Get the Internet Computer principal you act as at an app, without making a canister call. Identify the app by `derivation_origin` — its EXACT canonical Internet Identity derivation origin (NOT necessarily the visible website URL, and never inferred from an alternativeOrigins list). Get it from open_app / resolve_app (which turn an app name or URL into the derivation origin under the guessed-domain gate); this tool does NOT accept a raw website URL. The account delegation is derived on demand from this connection's standing Internet Identity credential. By default this resolves the app's default account; pass `account` (a name from list_app_accounts) for a specific one. The result returns the `principal` plus `derived_for_origin` and `requested` — compare them to catch a canonicalization surprise. If the principal looks wrong, the derivation origin is wrong: re-resolve the app with open_app / resolve_app rather than guessing an origin.",
        annotations(title = "Get your principal at an app", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<identities::PrincipalOutput>(),
    )]
    async fn get_app_principal(
        &self,
        Parameters(identities::GetPrincipalArgs { derivation_origin, account }): Parameters<identities::GetPrincipalArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match self.current_session_id(&ctx) {
            Some(s) => s,
            None => return Ok(err("getting an app principal needs an authenticated session".into())),
        };
        // `derivation_origin` is a required String here, so this always yields a
        // target (never the anonymous None) unless it fails validation.
        let target = match resolve_identity_target(Some(derivation_origin)) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(err("`derivation_origin` must not be empty".into())),
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
        // Surface a query-only session (H2) so the LLM won't attempt (and have the
        // IC reject at ingress) canister-management updates.
        let read_only = self.identities.is_read_only(&session_id).await == Some(true);
        let mut text = format!("{principal}\n\n[{}]", identity_annotation(&target, None));
        if read_only {
            text.push_str(
                "\n\n(This Internet Identity session was authorized for \"Questions only\": reads work, \
                 but canister management — create/install/start/stop/delete, and icp_canister_status — \
                 needs update access. Ask the user to reconnect and choose \"Actions & questions\" on \
                 Internet Identity's consent screen.)",
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
        description = "List the user's Internet Identity accounts at an app. Identify the app by `derivation_origin` — its EXACT canonical II derivation origin (not necessarily the visible URL). Get it from open_app / resolve_app (which turn an app name or URL into the derivation origin under the guessed-domain gate); this tool does NOT accept a raw website URL. Internet Identity gives the user a distinct principal per derivation origin, and within it they may hold several accounts: a default account everyone gets automatically (the anchor's current, user-controllable default there), plus any named accounts they created. Use this before acting on the user's behalf: if there's only the default account, just proceed (canister_query / canister_update_call / get_app_principal with no `account`); if there are several, pick one with the user by passing its name as `account`. Returns each account's name (the default has none), number, and last-used time, plus `derived_for_origin`/`requested` — if these accounts don't match what the user sees in their browser, the derivation origin is wrong (re-resolve the app rather than guessing). Requires an authenticated session.",
        annotations(title = "List your accounts at an app", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<identities::AccountsOutput>(),
    )]
    async fn list_app_accounts(
        &self,
        Parameters(identities::ListAccountsArgs { derivation_origin }): Parameters<identities::ListAccountsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match self.current_session_id(&ctx) {
            Some(s) => s,
            None => return Ok(err("listing your accounts needs an authenticated session".into())),
        };
        // `derivation_origin` is a required String here, so this always yields a
        // target (never the anonymous None) unless it fails validation.
        let target = match resolve_identity_target(Some(derivation_origin)) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(err("`derivation_origin` must not be empty".into())),
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
        description = "ROUTING. Run this chain before answering anything that names, or implies, a specific app or the user's own data in one app (a balance, holdings, bookings, positions, profile, or \"what can it do\"): (1) Is the request about a specific APP's functionality or the user's data in it, rather than the IC protocol itself? (2) Is that app on the Internet Computer? If unsure, THIS tool (or icp_find_app_by_name) is how you find out: a known app or an IC-verifiable URL resolves, while an unrecognized app name, or a URL with no Internet Computer evidence, is refused rather than guessed. (3) If so, START HERE: one open_app call resolves the app AND discovers its service. An app feature is almost never a single named tool (there is no \"get_balance\"); you COMPOSE it from what open_app returns, reading the discovered canisters and their `oql`/`api_doc_available` flags to see how to READ (canister_query, including OQL) or ACT (canister_update_call). So never conclude \"there's no tool for that\" from the flat tool list without opening the app first. Open an Internet Computer app in ONE call, given its NAME or its URL — the recommended entry point when a user names an app. It resolves the app's Internet Identity derivation origin (like resolve_app) AND discovers the canisters behind it (like discover_app_canisters) together, so you don't chain those yourself. Pass a NAME (e.g. \"Oisy\", \"NNS\") or a URL (e.g. \"https://oisy.com\"): a name or bare host is matched to the built-in known-app registry FIRST (so even a wrong-TLD guess repairs to the canonical URL), and an explicit https:// URL is resolved as given. NEVER fabricate a domain from a name — an unknown bare name is refused with instructions to find the real URL (web search / ask the user), and a URL with no Internet Computer evidence is refused, both instead of guessing a wrong identity. Returns `app_url` (the one used), `derivation_origin` (+ its source) to act with, `alternative_origins`, and the discovered `canisters` (with provenance/labels AND per-canister `oql`/`api_doc_available` capability flags, from a one-shot Candid probe of the app's own canisters). A canister flagged `oql` holds the app's data, GATED BY THE CALLER's principal: to read the USER's own data (\"my …\", \"our …\") pass the returned `derivation_origin` to get_canister_oql_schema (for the entity/field names) and to canister_query (with the `oql` argument, to run the query). Those OQL reads REQUIRE `derivation_origin` — not `app_url` — and reject an anonymous read for now. No authenticated session required for open_app itself (no principal is derived here). Narrower tools remain for single steps: icp_find_app_by_name (name→URL only), resolve_app (origin only), discover_app_canisters (canisters only).",
        annotations(title = "Open an app (resolve origin + discover canisters)", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<discover::OpenAppOutput>(),
    )]
    async fn open_app(
        &self,
        Parameters(discover::OpenAppArgs { app }): Parameters<discover::OpenAppArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Clean the query like every other identity input: trim, reject empty, and
        // reject control chars — otherwise they'd be echoed into the UnknownName
        // error via find_app_by_name's note (the rest of the surface avoids this).
        let query = match clean_identity_arg("app", &app) {
            Ok(q) => q,
            Err(e) => return Ok(err(e)),
        };
        // Disambiguate name vs URL, repairing a known app's name/wrong-TLD to its
        // canonical URL and refusing a bare unknown name rather than guessing.
        let (app_url, app_url_source) = match discover::classify_app_query(&query) {
            discover::AppQuery::Known(m) => (m.app_url, "known_app_registry"),
            discover::AppQuery::Url(u) => (u, "as_provided"),
            discover::AppQuery::UnknownName => {
                // Echo find_app_by_name's web-search/ask guidance (it builds the
                // "not a known app; don't guess a domain" note from the registry).
                return Ok(err(discover::find_app_by_name(&query).note));
            }
        };
        let app_url = match clean_app_url(&app_url) {
            Ok(u) => u,
            Err(e) => return Ok(err(e)),
        };
        // Resolve (the gating step) and discover (canisters) run CONCURRENTLY so the
        // happy path doesn't pay for discovery sequentially. Discovery is spawned so it
        // can be ABORTED the moment resolution fails or the IC-evidence gate refuses:
        // that makes a refused/guessed origin return PROMPTLY (no waiting out
        // discovery's timeout) and cancels the REST of the crawl. It does not prevent
        // discovery from starting — because it runs concurrently with the gate, a few
        // requests may already be in flight before abort() — but those are bounded by
        // discover's own size/count caps, and the common (accepted) case keeps the
        // full concurrency win. Gating before starting discovery would eliminate that
        // residual I/O only by serializing the two, which the happy path pays for.
        let discovery = tokio::spawn({
            let url = app_url.clone();
            async move { discover::discover(&url).await }
        });
        let resolved = match discover::resolve_app_identity(&app_url, true).await {
            Ok(r) => r,
            Err(e) => {
                discovery.abort();
                return Ok(err(app_url_error_with_guidance(&app_url, e)));
            }
        };
        // The same guessed-domain gate as resolve_app / the identity routes: an
        // assumed origin with no IC evidence is refused, not resolved.
        if resolved.derivation_origin_source == discover::DerivationSource::AppUrlDefault
            && resolved.application_is_ic == Some(false)
        {
            discovery.abort();
            return Ok(err(unverified_app_url_error(&resolved.application_origin)));
        }
        let effective = identities::target_origin(&resolved.derivation_origin);
        let note = resolution_note(&resolved, &effective);
        // Origin resolution succeeded and passed the IC gate, so the derivation
        // context stands regardless of discovery. Collect the concurrent discovery
        // now, keeping a FAILURE distinct from "found nothing" (a JoinError — i.e. a
        // panic — is treated as a discovery failure, never a hard error).
        let (canisters, omitted, discovery_error) = match discovery.await {
            Ok(Ok(d)) => (d.canisters, d.omitted, None),
            Ok(Err(e)) => (Vec::new(), 0, Some(e)),
            Err(join_err) => (Vec::new(), 0, Some(format!("discovery task error: {join_err}"))),
        };
        // Enrich the app's OWN data canisters with OQL / api-doc capability flags
        // (#3), so open_app hands back a ready-to-use handle: which canister holds
        // the (caller-gated) data, and the origin to read it as the user.
        let mut discovered: Vec<discover::DiscoveredCanister> =
            canisters.iter().map(discover::DiscoveredCanister::from).collect();
        self.enrich_capabilities(&mut discovered).await;
        // The ready-to-use data-access handle: the resolved origin, scoped (by
        // is_app_data_candidate) to the app's own OQL canisters — never a guessed
        // origin, never II/NNS/ledger/frontend. `derivation_origin` only: the
        // data-access note names the OQL read tools (get_canister_oql_schema,
        // canister_query), which take `derivation_origin`, not a website URL, so
        // offering app_url here would send the agent to a param those tools don't accept.
        let handle = format!("derivation_origin=\"{effective}\"");

        let mut text = format!(
            "app_url: {app_url} ({app_url_source})\nderivation_origin: {effective} ({})\n",
            resolved.derivation_origin_source.as_str()
        );
        if !resolved.alternative_origins.is_empty() {
            text.push_str(&format!("alternative_origins: {}\n", resolved.alternative_origins.join(", ")));
        }
        if let Some(e) = &discovery_error {
            text.push_str(&format!(
                "\nCanister discovery FAILED ({e}) — this is NOT \"the app has no canisters\"; the \
                 derivation origin above is still valid. Retry discover_app_canisters, or proceed \
                 with a canister id you already have.\n"
            ));
        } else if discovered.is_empty() {
            text.push_str("\nNo canisters discovered — the app appears to declare none.\n");
        } else {
            text.push_str("\nCanisters:\n");
            for c in &discovered {
                text.push_str(&render_canister_line(c));
            }
            if omitted > 0 {
                text.push_str(&format!(
                    "(+{omitted} more findings dropped by the output cap; the list is \
                     authority-ordered, so the least authoritative entries were cut first)\n"
                ));
            }
        }
        if let Some(n) = &note {
            text.push_str(&format!("\nNOTE: {n}"));
        }
        if let Some(access) = data_access_note(&discovered, Some(&handle)) {
            text.push_str(&format!("\n\n{access}"));
        }
        text.push_str(
            "\n\nNext: inspect a canister with get_canister_candid — its oql / api_doc_available \
             flags say whether to read via OQL and whether get_canister_api_doc has a doc \
             (only call it when api_doc_available). To act as the user, pass the derivation_origin \
             above to canister_query (read) and canister_update_call (write); for an OQL canister, \
             call get_canister_oql_schema for the entity/field names, then canister_query with \
             the `oql` argument — plus an optional account from list_app_accounts. A \"my/our…\" \
             question is an AUTHENTICATED read: pass the origin.",
        );
        let output = discover::OpenAppOutput {
            app_url,
            app_url_source: app_url_source.to_string(),
            application_origin: resolved.application_origin,
            derivation_origin: effective,
            derivation_origin_source: resolved.derivation_origin_source.as_str().to_string(),
            alternative_origins: resolved.alternative_origins,
            application_is_ic: resolved.application_is_ic,
            canisters: discovered,
            omitted,
            discovery_error,
            note,
        };
        Ok(ok_structured(text, &output))
    }

    #[tool(
        description = "Resolve an application URL to its Internet Identity derivation context, so you don't have to figure out the derivation origin yourself. `app_url` must be a URL you actually HAVE — from the user, from icp_find_app_by_name, or from a web search of the app's official site. NEVER guess or fabricate a domain from an app's name (when you only know a NAME, call icp_find_app_by_name first): a lookalike domain is an unrelated or squatted site, and this tool REFUSES to resolve an origin that shows no evidence of being an Internet Computer app rather than hand back a wrong identity. Returns the `application_origin`, the `derivation_origin` to pass to the identity tools, how it was determined (`derivation_origin_source`: \"declared\" — the app published it in /.well-known/ic-app.json, authoritative; \"known\" — from the connector's built-in registry of well-known custom-derivation-origin apps (e.g. NNS, Oisy), used only when the app declares none; or \"app_url_default\" — the origin IS IC-served but declares nothing, so it was assumed to be its own derivation origin, correct only if the app has no custom one), and the app's `alternative_origins` (informational — the INVERSE relation, never use it to infer the derivation origin). This does NOT return a principal — it resolves the origin only, since you haven't picked an account; to get the principal you act as, pass the returned `derivation_origin` to get_app_principal (choosing an `account`) or list_app_accounts. Use this first when you only know an app's URL; no authenticated session is required.",
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
            Err(e) => return Ok(err(app_url_error_with_guidance(&app_url, e))),
        };
        // A guessed/lookalike domain fails HARD instead of resolving to a
        // plausible-but-wrong identity: no declared origin, not a known app, and
        // no sign the origin is even served from the IC. The error carries the
        // "did you mean" repair and the legitimate ways to obtain the URL.
        if resolved.derivation_origin_source == discover::DerivationSource::AppUrlDefault
            && resolved.application_is_ic == Some(false)
        {
            return Ok(err(unverified_app_url_error(&resolved.application_origin)));
        }
        let effective = identities::target_origin(&resolved.derivation_origin);
        let note = resolution_note(&resolved, &effective);
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
            application_is_ic: resolved.application_is_ic,
            note,
        };
        Ok(ok_structured(text, &output))
    }

    #[tool(
        description = "Discover the Internet Computer canisters behind a web domain (e.g. \"oisy.com\"). The domain must be one you actually have (from the user, icp_find_app_by_name, or a web search) — NEVER a domain guessed from an app's name; when you only know a NAME, call icp_find_app_by_name first. Returns every canister id found, with provenance, most authoritative first: app-declared metadata — the App Connect page's `ic:canister-id` meta at /ai-connect.html (the app's MAIN backend) and the app's own /.well-known/ic-app.json manifest (ALL its canisters, with roles) — then the `x-ic-canister-id` header (the frontend/asset canister), a `/env.json` runtime config (e.g. backend_canister_id), and labelled/bare canister-id literals mined from the JS bundle. App-declared entries are the app's own claim about itself; env.json/bundle entries are mined candidates: pick by label (prefer production/IC ids) and confirm with get_canister_candid before calling.",
        annotations(title = "Discover canisters behind a domain", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<discover::DiscoverOutput>(),
    )]
    async fn discover_app_canisters(
        &self,
        Parameters(discover::DiscoverCanistersArgs { domain }): Parameters<discover::DiscoverCanistersArgs>,
    ) -> Result<CallToolResult, McpError> {
        match discover::discover(&domain).await {
            Ok(d) if !d.canisters.is_empty() => {
                // Probe the app's own data canisters for OQL / api-doc capabilities
                // (#3), mirroring open_app. discover_app_canisters resolves no origin,
                // so the data-access note points at resolve_app / open_app for it.
                let mut discovered: Vec<discover::DiscoveredCanister> =
                    d.canisters.iter().map(discover::DiscoveredCanister::from).collect();
                self.enrich_capabilities(&mut discovered).await;
                let mut out = format!("Canisters discovered for {domain}:\n");
                for c in &discovered {
                    out.push_str(&render_canister_line(c));
                }
                if d.omitted > 0 {
                    out.push_str(&format!(
                        "(+{} more findings dropped by the output cap; the list is \
                         authority-ordered, so the least authoritative entries were cut first)\n",
                        d.omitted
                    ));
                }
                out.push_str(
                    "\n`ai-connect.html` and `ic-app.json` entries are DECLARED by the app itself \
                     (its main backend, and its own canister manifest with roles) — treat them as \
                     the app's claim about its composition. The `header` (x-ic-canister-id) entry \
                     is the frontend/asset canister. Others come from env.json or the JS bundle \
                     and may include multiple environments (prefer the production/IC ids). A \
                     «name» (type) is the IC dashboard's label for that id. `[oql]`/`[api-doc]` \
                     flags are from a Candid probe of the app's own canisters. Confirm an interface \
                     with get_canister_candid before calling.",
                );
                if let Some(access) = data_access_note(&discovered, None) {
                    out.push_str(&format!("\n\n{access}"));
                }
                let output = discover::DiscoverOutput {
                    domain,
                    canisters: discovered,
                    omitted: d.omitted,
                };
                Ok(ok_structured(out, &output))
            }
            Ok(d) => {
                let mut text =
                    format!("No IC canisters found for {domain} — is it served from the Internet Computer?");
                if let Some(m) = discover::similar_known_app(&domain) {
                    text.push_str(&format!(
                        " DID YOU MEAN {}? Its real URL is {} (derivation origin {}).",
                        m.name, m.app_url, m.derivation_origin
                    ));
                }
                text.push_str(
                    " If you GUESSED this domain from an app name, don't guess again: call \
                     icp_find_app_by_name with the name, or WEB SEARCH the app's official URL, \
                     or ask the user for it.",
                );
                let output = discover::DiscoverOutput::from((domain, d));
                Ok(ok_structured(text, &output))
            }
            // A fetch failure on a guessed domain (DNS-dead lookalikes like
            // "multi.dex") carries the same repair as the identity routes, so it
            // reads as "wrong URL — here's the real one", not a transient error.
            Err(e) => Ok(err(app_url_error_with_guidance(&domain, e))),
        }
    }

    #[tool(
        description = "Find Internet Computer canisters by NAME. Searches the IC dashboard's service registries — the ICRC token ledgers (e.g. ckBTC, ckETH, ckUSDC, SNS tokens) by symbol/name, and the SNS project catalog by name — and returns matching canister ids. Use this when the user names a token, project, or service (e.g. \"ckUSDC\") rather than a canister id; then confirm with get_canister_candid, read with canister_query, and write with canister_update_call. (No public name-search exists over arbitrary canisters; this covers the IC's labelled services.)",
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
                    "\nConfirm an interface with get_canister_candid, then read with canister_query and \
                     write with canister_update_call. \
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
        description = "Find a well-known Internet Computer APP by NAME and get its front-end URL and Internet Identity derivation origin — the missing name→app step (discovery otherwise needs a URL). ALWAYS call this FIRST when the user names an app and you don't have its URL — NEVER guess a domain from the name (lookalike domains like <name>.com/.app are unrelated or squatted sites, and the URL-taking tools refuse origins with no IC evidence). Offline and instant. Covers only a small built-in set of well-known IC apps (e.g. NNS, Oisy). For ANY other app there is NO on-chain name→URL directory, so the result's `note` directs you to WEB SEARCH the app's official URL (or ask the user) and then use resolve_app / discover_app_canisters. Returns `matches` (each with `app_url` + `derivation_origin`) — usually one, or none. This is name→app; for a token/service→canister-id use icp_find_canister_by_name, and for a URL→canisters use discover_app_canisters.",
        annotations(title = "Find a well-known app by name", read_only_hint = true, destructive_hint = false, open_world_hint = false),
        output_schema = schema_for_output::<discover::FindAppOutput>(),
    )]
    async fn icp_find_app_by_name(
        &self,
        Parameters(discover::FindAppArgs { name }): Parameters<discover::FindAppArgs>,
    ) -> Result<CallToolResult, McpError> {
        let output = discover::find_app_by_name(&name);
        let mut text = String::new();
        for m in &output.matches {
            text.push_str(&format!(
                "{} — {} (derivation_origin: {})\n",
                m.name, m.app_url, m.derivation_origin
            ));
        }
        text.push_str(&output.note);
        Ok(ok_structured(text, &output))
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
        description = "List the official Internet Computer skills — authoritative how-to guides for authoring and shipping IC apps (Motoko language, mops/icp CLIs, cycles management, stable memory & upgrades, security, auth, …). Returns each skill's name and a one-line description. Load a skill's full instructions with icp_get_skill(name). Consult these BEFORE writing Motoko/Rust canister code, building, or deploying.",
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
        description = "Fetch the full instructions (SKILL.md) of one Internet Computer skill by name (e.g. \"writing-motoko\", \"icp-cli\", \"mops-cli\", \"cycles-management\", \"stable-memory\", \"canister-security\"). Call icp_list_skills first to see the available names. Use this to learn the exact, current way to do an IC task before doing it.",
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
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
            None => return Ok(err("checking your cycles balance needs an authenticated session".into())),
        };
        match management::cycles_balance(&self.identities, &sid).await {
            Ok(b) => Ok(ok_structured(b.human(), &b)),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Create and fund a NEW Internet Computer canister (as your Internet Identity). SPENDS FUNDS: this draws cycles or ICP from your accounts and cannot be automatically reversed, so confirm with the user before calling it. Fund it EITHER with `cycles` (exact, drawn from your cycles-ledger balance) OR with `icp` (a decimal-ICP string like \"0.5\", transferred from your ICP-ledger account and converted to cycles via the CMC). BOTH accounts belong to your management principal — the same principal icp_cycles_balance reports (its default subaccount); check/fund it before calling (cycles-ledger balance via icp_cycles_balance, or hold ICP in that principal's ICP-ledger account). The ICP path is best-effort with no retries: if the ICP transfer lands but the mint fails, the error carries the block index to recover with — do not blindly re-run. `cycles` wins if both are given. Controllers default to your own principal. Returns the new canister id — then build your Wasm (see the writing-motoko/icp-cli skills) and install it with icp_install_code. Requires an authenticated session.",
        // destructive_hint = true: it adds a canister, but it does so by spending the
        // user's cycles or ICP irreversibly, and it is not idempotent (a retry spends
        // again). See the annotation test for why "additive" is the wrong read here.
        annotations(title = "Create a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CreatedCanister>(),
    )]
    async fn icp_create_canister(
        &self,
        Parameters(args): Parameters<management::CreateCanisterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
            None => return Ok(err("creating a canister needs an authenticated session".into())),
        };
        match management::create_canister(&self.identities, &sid, args).await {
            Ok(c) => Ok(ok_structured(c.human(), &c)),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Add cycles to an existing canister (as your Internet Identity). SPENDS FUNDS: this draws cycles or ICP from your accounts and cannot be automatically reversed, so confirm with the user before calling it. Fund EITHER with `cycles` (exact, drawn from your cycles-ledger balance) OR with `icp` (a decimal-ICP string, transferred from your ICP-ledger account and converted via the CMC straight into the target canister). Both accounts belong to your management principal — the one icp_cycles_balance reports (default subaccount). The ICP path is best-effort with no retries: if the transfer lands but the mint fails, the error carries the block index to recover with — do not blindly re-run. `cycles` wins if both are given. Requires an authenticated session.",
        // destructive_hint = true: same reasoning as icp_create_canister — the cycles
        // land in the target canister, but the funds leave the user's accounts for
        // good, and a retry spends again.
        annotations(title = "Top up a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_top_up_canister(
        &self,
        Parameters(args): Parameters<management::TopUpArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
            None => return Ok(err("topping up a canister needs an authenticated session".into())),
        };
        let canister_id = args.canister_id.clone();
        Ok(ok_canister_action(
            canister_id,
            management::top_up_canister(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Install a compiled Wasm module on a canister you control (as your Internet Identity). Provide the module as `wasm_base64` (or `wasm_hex`); large modules are uploaded via the chunk store automatically. `mode` is \"install\" (default, empty canister), \"reinstall\" (wipe state), or \"upgrade\" (preserve stable memory). `arg` is the init/upgrade argument in textual Candid, e.g. \"()\". Build the Wasm in your own environment first (see the writing-motoko / icp-cli / mops-cli skills). Requires an authenticated session.",
        annotations(title = "Install code on a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_install_code(
        &self,
        Parameters(args): Parameters<management::InstallCodeArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
            None => return Ok(err("installing code needs an authenticated session".into())),
        };
        let canister_id = args.canister_id.clone();
        Ok(ok_canister_action(
            canister_id,
            management::install_code(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Report a canister's status: run state, cycle balance, module hash, memory size, controllers, and allocations. Controller-only (acts as your Internet Identity). This only READS status (it changes nothing), but on the IC it is an update call, so it needs an Internet Identity session authorized for \"Actions & questions\" rather than \"Questions only\". Requires an authenticated session.",
        annotations(title = "Get canister status", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<management::CanisterActionOutput>(),
    )]
    async fn icp_canister_status(
        &self,
        Parameters(args): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
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
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
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
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
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
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
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
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
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
        let sid = match self.current_session_id(&ctx) {
            Some(s) => s,
            None => return Ok(err("deleting a canister needs an authenticated session".into())),
        };
        let result = management::delete_canister(&self.identities, &sid, &canister_id).await;
        Ok(ok_canister_action(canister_id, result))
    }
}

/// Where [`IcTools`] finds the Internet Identity session a tool call acts as —
/// the one seam between deployments. The tool implementations are identical
/// under both variants.
#[derive(Clone, Debug)]
pub enum SessionSource {
    /// Multi-user (the hosted server): resolve the session per request from
    /// the [`AuthedSession`] extension its bearer-token gate injected.
    Bearer,
    /// Single-user (a local server): every call acts as this one session,
    /// established by the binary's own login flow.
    Singleton(String),
}

/// The verified session id of an authenticated MCP session, injected into the
/// request extensions by the embedding server's auth gate (the hosted binary's
/// bearer-token middleware) and read back under [`SessionSource::Bearer`].
#[derive(Clone, Debug)]
pub struct AuthedSession {
    pub session_id: String,
}

/// The authenticated MCP session of the calling request, if the embedding
/// server's auth gate injected one. The transport surfaces the HTTP request's
/// `Parts` in the tool context's extensions; `http::request::Parts` is the
/// same type axum re-exports, so this reads what an axum middleware inserted
/// without this crate depending on axum.
fn authed_session(ctx: &RequestContext<RoleServer>) -> Option<AuthedSession> {
    ctx.extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<AuthedSession>())
        .cloned()
}

/// The rejection for an OQL read (`get_canister_oql_schema`, or `canister_query`'s
/// `oql` path) attempted with NO derivation origin. OQL reads per-app data gated by
/// the caller's principal, so an anonymous read is signed as 2vxsx-fae and returns
/// nothing useful — so, for the time being, we reject it outright rather than let it
/// silently come back empty. `what` names the action. Points at open_app /
/// resolve_app so the agent recovers the origin in one step.
fn oql_needs_origin_error(what: &str) -> String {
    format!(
        "{what} reads per-app data that this canister gates by the CALLER's principal, so it \
         cannot be done anonymously — pass `derivation_origin`, the app's canonical Internet \
         Identity origin, to read as your account. If you don't have it, resolve it from the \
         app's URL or name with open_app / resolve_app, then retry. (Anonymous per-app reads are \
         disabled for now; public metadata such as get_canister_candid still works without an origin.)"
    )
}

/// The diagnosis attached to an EMPTY / trapped OQL query result (#1 + #7).
struct OqlEmptyDiagnosis {
    /// The human-readable explanation of the empty result, if one applies.
    note: Option<String>,
    /// The entities visible to this caller, when an unknown-`start` diagnosis fired.
    valid_entities: Option<Vec<String>>,
    /// The nearest valid entity to an unknown `start` (`booking` → `bookings`).
    did_you_mean: Option<String>,
}

impl OqlEmptyDiagnosis {
    fn none() -> Self {
        Self { note: None, valid_entities: None, did_you_mean: None }
    }
}

/// Why `diagnose_empty_oql` was called — a genuinely EMPTY result (0-row table)
/// vs. a FAILED one (trap / OQL error arm). The `start`-entity repair applies to
/// both, but the "came back empty ⇒ likely not authenticated" / "no entities here"
/// notes describe an EMPTY result and would misdescribe a failure that already
/// carries its own error message, so they are emitted for `EmptyResult` only.
#[derive(Clone, Copy, PartialEq)]
enum EmptyContext {
    EmptyResult,
    Failed,
}

/// Diagnose why an OQL read came back EMPTY (0 rows) or FAILED (trap / error arm),
/// using ONLY facts gathered from the SAME agent/principal that ran the query —
/// never probing whether some OTHER principal would see data (no leak). This is
/// validate-on-empty, not an unconditional preflight: it runs a single extra
/// `schema` read for this principal and hard-validates the query's `start` entity
/// (only `start` — field and dotted-edge paths are treated advisorily by the caller).
///
///  - `start` isn't one of the visible entities → the #7 unknown-entity repair
///    (valid entities + a "did you mean?" near match). Emitted in BOTH contexts —
///    an unknown `start` is the common reason a query traps.
///  - The notes below describe an EMPTY RESULT and are emitted for `EmptyResult`
///    only (a `Failed` result keeps its own error message; "came back empty" would
///    misdescribe it):
///     - Anonymous + empty → the #1 auth remediation (empty is almost certainly
///       "not authenticated as your account", not "no data").
///     - Authenticated + the schema read SUCCEEDED and shows no entities → this
///       account sees no entities here. (A schema read that FAILED is left
///       undiagnosed — the caller falls back to a benign "0 rows" note — rather
///       than mislabeled "no entities".)
///     - `start` valid but 0 rows → authenticated gets no note here (the caller
///       adds the benign "0 rows"); anonymous still gets the auth hint.
async fn diagnose_empty_oql(
    agent: &Agent,
    principal: Principal,
    query_json: &str,
    is_anonymous: bool,
    ctx: EmptyContext,
) -> OqlEmptyDiagnosis {
    // The derivation_origin the caller would ADD to authenticate — a placeholder we
    // never fill with a guessed origin (#1).
    const ADD_HINT: &str = "the app's `derivation_origin` (its canonical Internet Identity origin)";
    // Re-read the schema for THIS principal (same agent). `None` = the read FAILED
    // (unknown, not "empty"); `Some(vec)` = it succeeded (possibly with no entities).
    // Keeping the two apart stops a transient schema failure from being mislabeled
    // "this account sees no entities".
    let entities: Option<Vec<String>> = match calls::encode_unit_arg() {
        Ok(arg) => match calls::raw_call(agent, principal, "schema", arg, true).await {
            Ok(reply) => Some(calls::oql_entity_names(&calls::decode_schema_reply(&reply))),
            Err(_) => None,
        },
        Err(_) => None,
    };
    let start = calls::oql_query_start(query_json);
    let mut d = OqlEmptyDiagnosis::none();

    // #7 unknown-`start` repair — needs a successful, non-empty schema. Applies in
    // BOTH contexts (an unknown entity is exactly what makes a query trap).
    if let Some(ents) = entities.as_ref().filter(|e| !e.is_empty()) {
        if let Some(s) = start.as_deref().filter(|s| !ents.iter().any(|e| e == s)) {
            d.did_you_mean = calls::closest_entity(s, ents);
            let dym = d
                .did_you_mean
                .as_deref()
                .map(|m| format!(" Did you mean \"{m}\"?"))
                .unwrap_or_default();
            d.note = Some(format!(
                "`start`: \"{s}\" is not a queryable entity on this canister. Valid entities \
                 (visible to this caller): {}.{dym}",
                ents.join(", ")
            ));
            d.valid_entities = Some(ents.clone());
            return d;
        }
    }

    // The remaining notes describe an EMPTY result — skip them on a failure, whose
    // own error message stands, and appending "came back empty" would contradict it.
    if ctx == EmptyContext::Failed {
        return d;
    }

    if is_anonymous {
        // Anonymous + empty (schema empty, unreadable, or `start` valid) → auth hint.
        d.note = Some(calls::anonymous_empty_note("this query", ADD_HINT));
    } else if matches!(entities.as_deref(), Some([])) {
        // Authenticated AND the schema read SUCCEEDED with no entities — a genuine
        // "nothing visible here" (not a failed re-read mislabeled as empty).
        d.note = Some(
            "This account sees no OQL entities on this canister, so there is nothing to query as \
             it — confirm the derivation_origin/account are the ones the user uses in their browser."
                .to_string(),
        );
    }
    // Otherwise (authenticated: `start` valid, OR the schema read failed): no
    // actionable diagnosis — leave `note` None so the caller adds the benign
    // "0 rows for this account" on an empty table.
    d
}

/// Which app principal an identity-bearing tool should act as, resolved from the
/// caller's `derivation_origin`.
#[derive(Debug)]
struct IdentityTarget {
    /// The EFFECTIVE (canonical) Internet Identity derivation origin to feed the
    /// delegation layer — echoed to the caller as `derived_for_origin`.
    origin: String,
    /// Exactly what the caller supplied as `derivation_origin`.
    requested: String,
    /// How `origin` was determined. Always "explicit" here: the identity-bearing
    /// tools take the canonical derivation origin DIRECTLY (they no longer accept an
    /// `app_url` to resolve). The "declared"/"known"/"app_url_default" sources come
    /// from the resolver tools (`open_app` / `resolve_app`), where a URL is turned
    /// into a derivation origin under the guessed-domain gate; feed their result
    /// here. Kept for parity with those tools' echoed `derivation_origin_source`.
    source: String,
}

/// Resolve the caller's `derivation_origin` into an [`IdentityTarget`] (or `None`
/// when it's absent — an anonymous call). The origin is canonicalized and used
/// VERBATIM (source `explicit`): these tools trust the caller to supply the exact
/// canonical origin Internet Identity derives against. There is deliberately no
/// `app_url` here — a derivation origin is a stable per-app value, so it's resolved
/// ONCE via `open_app` / `resolve_app` (which run the guessed-domain gate and return
/// it) and then reused across calls, rather than re-resolved on every invocation
/// against this stateless server.
fn resolve_identity_target(
    derivation_origin: Option<String>,
) -> Result<Option<IdentityTarget>, String> {
    match derivation_origin {
        None => Ok(None),
        Some(d) => {
            let d = clean_identity_arg("derivation_origin", &d)?;
            let origin = canonicalize_derivation_origin(&d)?;
            Ok(Some(IdentityTarget {
                origin,
                requested: d,
                source: "explicit".to_string(),
            }))
        }
    }
}

/// Append guess-repair guidance to an `app_url` resolution failure (DNS, TLS,
/// timeout, SSRF refusal): a fetch error on a domain FABRICATED from an app name
/// (e.g. "multi.dex") must redirect the caller to the name→URL tools — the same
/// way the no-IC-evidence refusal does — rather than read as a transient error
/// inviting the next guess.
fn app_url_error_with_guidance(app_url: &str, e: String) -> String {
    let mut msg = e;
    if let Some(m) = discover::similar_known_app(app_url) {
        msg.push_str(&format!(
            " DID YOU MEAN {}? Its real URL is {} (derivation origin {}).",
            m.name, m.app_url, m.derivation_origin
        ));
    }
    msg.push_str(
        " If you arrived at this URL by guessing from an app name, don't guess again — call \
         icp_find_app_by_name with the name, WEB SEARCH the app's official URL, or ask the user.",
    );
    msg
}

/// The refusal text for an `app_url` that resolved to `app_url_default` with NO
/// evidence of being served from the Internet Computer — almost always a domain
/// GUESSED from an app name (e.g. "multidex.com" for MULTI/DEX, whose real URL is
/// multidex.ai). Rather than resolving the guess to a plausible-but-wrong identity,
/// tools return this error, which (a) names the failure, (b) suggests the
/// well-known app the host resembles when there is one ("did you mean …"), and
/// (c) spells out the legitimate ways to obtain the URL — so the caller converges
/// on the real app instead of guessing again.
fn unverified_app_url_error(application_origin: &str) -> String {
    let mut msg = format!(
        "{application_origin} is reachable but shows NO evidence of being an Internet Computer \
         app — no valid `x-ic-canister-id` gateway header (the IC HTTP gateway sets one on every \
         response) — and its /.well-known/ic-app.json couldn't be fetched or declares no Internet \
         Identity derivation origin. Refusing to treat it as an app. "
    );
    if let Some(m) = discover::similar_known_app(application_origin) {
        msg.push_str(&format!(
            "DID YOU MEAN {}? Its real URL is {} (derivation origin {}) — use that instead. ",
            m.name, m.app_url, m.derivation_origin
        ));
    }
    msg.push_str(
        "If you arrived at this URL by GUESSING from an app name, stop guessing — a lookalike \
         domain is an unrelated or squatted site, and an identity derived there is wrong: \
         (1) call icp_find_app_by_name with the app's name (well-known apps resolve offline); \
         (2) if it's not known, WEB SEARCH the app's official URL; (3) or ask the user for it. \
         If this origin genuinely IS the app's canonical Internet Identity origin (e.g. a \
         non-IC-hosted app the user pointed you at), pass it explicitly as `derivation_origin` \
         to proceed deliberately.",
    );
    msg
}

/// The human `note` explaining how a resolved derivation origin was determined,
/// shared by `resolve_app` and `open_app` so the two stay in lock-step. `None` for
/// a Declared origin (self-evident); a Known origin explains the built-in registry;
/// an AppUrlDefault origin flags the assumption and, when the host resembles a
/// well-known app, appends a lookalike CAUTION (an IC-hosted squat can pass the
/// evidence gate yet still not be the app it mimics). `effective` is the
/// canonicalized derivation origin (`target_origin`).
fn resolution_note(resolved: &discover::AppIdentity, effective: &str) -> Option<String> {
    let lookalike = discover::similar_known_app(&resolved.application_origin).map(|m| {
        format!(
            " CAUTION: this host RESEMBLES the well-known app {} but is not one of its real \
             origins — {}'s URL is {} (derivation origin {}). If you meant {}, use that URL; \
             if you guessed this URL from the app's name, use icp_find_app_by_name instead of \
             guessing.",
            m.name, m.name, m.app_url, m.derivation_origin, m.name
        )
    });
    match resolved.derivation_origin_source {
        discover::DerivationSource::Declared => None,
        discover::DerivationSource::Known => Some(format!(
            "This app didn't declare a derivation origin in /.well-known/ic-app.json, but it's \
             a known app that pins a custom one, so this used the built-in value {effective}. \
             The app's own declaration, if it ships one, would override this."
        )),
        discover::DerivationSource::AppUrlDefault => Some(format!(
            "This origin showed evidence of being served from the Internet Computer (its \
             responses carry the gateway's `x-ic-canister-id` header), but its \
             /.well-known/ic-app.json couldn't be fetched or declares no `derivation_origin`, \
             and it isn't in the built-in known-app registry — so this ASSUMED the application \
             origin, canonicalized to {effective} (what II derives against). That is correct \
             for apps without a custom derivation origin; if this app pins a custom one, the \
             assumption yields a WRONG principal — supply the canonical origin explicitly.{}",
            lookalike.as_deref().unwrap_or_default()
        )),
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
/// how it was determined (`source`, always "explicit" for the identity-bearing
/// tools now that they take the canonical origin directly), and — whenever it
/// differs from the derived origin (canonicalization, http→https, a stripped path)
/// — the caller's `requested` value, so a requested≠derived mismatch stays visible
/// in every client. `acted_as` prefixes the signed-as principal when known.
fn identity_annotation(target: &IdentityTarget, acted_as: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(p) = acted_as {
        s.push_str(&format!("signed as {p} — "));
    }
    s.push_str(&format!("derived for {} (source: {})", target.origin, target.source));
    if target.requested != target.origin {
        s.push_str(&format!("; requested {}", target.requested));
    }
    s
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
             (`open_app`, `discover_app_canisters`, `get_app_principal`, `list_app_accounts`, `resolve_app`) \
             act on a whole APP, keyed by its Internet Identity derivation origin or app URL; and \
             `…canister…` names (`get_canister_candid`, `get_canister_api_doc`, \
             `get_canister_oql_schema`, `canister_query`, `canister_update_call`) act on ONE \
             specific canister. Before writing Candid args, consult the `candid://textual-syntax` \
             resource (the value syntax these tools use); `candid://reference` has the full type \
             reference.\n\n\
             NOT FOR FINANCIAL OPERATIONS. This server does not initiate or execute financial \
             transactions — money or token transfers, spending approvals, payments, or trades — on \
             the user's behalf, for marketplace compliance and user safety: canister_update_call \
             refuses the ICRC-1/ICRC-2 (and related ledger-standard) transfer/approval methods, and \
             icp_top_up_canister only returns CLI instructions. When the user asks for such an \
             operation, recommend they do it themselves in a wallet or app frontend they control, \
             in their own browser — e.g. their wallet at https://oisy.com.\n\n\
             START WITH open_app WHEN THE USER NAMES OR LINKS AN APP. `open_app(name-or-URL)` is the \
             one-call entry point: it takes an app NAME (e.g. \"Oisy\", \"NNS\") or a \
             URL, resolves the Internet Identity derivation origin AND discovers the canisters \
             together, probes the app's own canisters for their `oql`/`api_doc_available` \
             capabilities, and repairs a wrong-TLD guess to the canonical known-app URL — so you do \
             NOT chain resolve_app + discover_app_canisters yourself, and you do NOT start from \
             discover_app_canisters. (open_app bundles `resolve_app` + `discover_app_canisters`; use \
             those directly only for a single step.) RULE — names are not URLs: NEVER guess or \
             fabricate a domain from an app's name (e.g. <name>.com/.app); pass the NAME to open_app \
             (or `icp_find_app_by_name`) and let the connector resolve it, WEB SEARCH the official \
             URL, or ask the user. Lookalike domains are unrelated or squatted sites, and open_app / \
             every URL-taking tool REFUSES an origin that shows no evidence of being an Internet \
             Computer app instead of resolving it to a wrong identity. When the user names a TOKEN, \
             PROJECT or SERVICE (e.g. \"ckUSDC\"), use `icp_find_canister_by_name` for its canister \
             id; `icp_lookup_canister_info_by_id(id)` tells you what a bare canister id IS (dashboard \
             label, type, controllers, subnet).\n\n\
             \"MY / OUR …\" IS AN AUTHENTICATED READ. A question about the USER's OWN data in an app \
             (\"who am I meeting with…\", \"my bookings\", \"our balance\") reads data the app gates \
             by the CALLER's principal. An OQL read (get_canister_oql_schema, and canister_query \
             with the `oql` argument) REQUIRES the app's \
             `derivation_origin` (from open_app / resolve_app) — anonymous per-app reads are \
             disabled for now, so a call with no origin is REJECTED with guidance to pass it, rather \
             than silently returning empty. Authenticating never hurts a public read either — the \
             canister serves the request regardless of principal — so always pass the origin for app \
             data. (canister_query can still run a Candid `method` query anonymously for genuinely \
             public canisters like ledgers.)\n\n\
             INSPECTING A CANISTER. `get_canister_candid` fetches the interface and reports two \
             capability flags: `oql` and `api_doc_available` (open_app reports the same per \
             canister). If `oql: true`, READ the canister via OQL, in order: `icp_oql_guide` (the \
             JSON dialect, once) → `get_canister_oql_schema` (the entities and fields) → \
             `canister_query` with the `oql` argument \
             (run a JSON query, get a table). These wrap the canister's `schema`/`execute` methods, \
             so you never hand-encode Candid for OQL — and on an OQL canister a Candid `method` query \
             through canister_query is REJECTED (use `oql`; canister_update_call handles UPDATES). \
             Call `get_canister_api_doc` ONLY when `api_doc_available` is true: then it returns a \
             prose \"how this app behaves\" guide (units, auth, lifecycle, mutation safety, polling, \
             gotchas) the Candid types don't convey; when the flag is false the canister has no such \
             doc and the Candid types ARE the interface — don't call it.\n\n\
             PRESENT VALUES IN THE USER'S LOCAL FORMAT. Canister data is stored in canonical, \
             locale-neutral forms, so CONVERT it for the user rather than echoing the raw value. \
             Timestamps are almost always nanoseconds since the Unix epoch in UTC (IC time; divide \
             by 1e9 for seconds) — render them in the USER's time zone and date/number \
             conventions, not raw UTC nanoseconds. Physical quantities are usually SI/metric or an \
             app-defined unit — check `get_canister_api_doc` for the exact unit, then convert to the \
             user's locale for the measures that split US-customary vs metric: temperature (°C↔°F), \
             mass/weight (g,kg↔oz,lb), length/height/distance (cm,m,km↔in,ft,mi), and volume \
             (mL,L↔fl oz,US gal). Infer the user's locale and time zone from the conversation (their \
             language, where they are, the app) or ask when it matters; keep the raw value alongside \
             the converted one when precision matters (money, exact timestamps) or the source unit \
             is uncertain. Don't convert blindly — first establish the SOURCE unit (from \
             `get_canister_api_doc`, the field/entity name, or the schema), then convert.\n\n\
             `canister_query` (reads) and `canister_update_call` (writes) call a method with \
             textual Candid in/out: omit the identity args to call anonymously, or act AS your \
             account at an app. To act as an app account, identify the app by its \
             `derivation_origin` — the EXACT canonical origin Internet Identity derives its \
             principal from, which is NOT necessarily the visible website URL and must NEVER be \
             inferred from an ii-alternative-origins list. The identity-bearing tools \
             (canister_query, canister_update_call, get_app_principal, list_app_accounts, \
             get_canister_oql_schema) \
             take ONLY `derivation_origin`, NOT a website URL: a derivation origin is a stable \
             per-app value, so RESOLVE IT ONCE with `open_app` (or `resolve_app`) — which turn an \
             app name/URL into it under the guessed-domain gate — and reuse it across calls, rather \
             than re-resolving a URL every time on this stateless server. A short-lived (<=5 min) account \
             delegation is minted ON DEMAND from this connection's standing credential, no extra \
             sign-in. `get_app_principal` returns the principal without a call; `list_app_accounts` lists \
             the user's accounts (a default one plus any named ones), and canister_query / \
             canister_update_call / get_app_principal take an optional `account` (a name from that \
             list) — omit it for the default. Every identity result echoes `derived_for_origin` (the origin actually used) and \
             `requested` (what you passed), so a canonicalization mismatch is visible. If a principal, \
             account, or balance doesn't match what the user sees in their browser, the derivation \
             origin is wrong: re-resolve the app with `open_app`/`resolve_app` (don't guess an origin). The standing \
             credential is obtained when you connect \
             (authenticate via Internet Identity) and lasts for the session duration you choose when \
             connecting (up to 30 days); reconnect when it expires. \
             Internet Identity's consent screen asks the user to choose an access level, \
             \"Questions only\" or \"Actions & questions\". On a Questions-only session reads work, but \
             the canister-management tools below make update calls the network rejects — if one fails \
             that way, ask the user to reconnect and choose \"Actions & questions\".\n\n\
             Typical flow (acting FOR THE USER at an app): (0-2) `open_app(name-or-URL)` in ONE \
             call gives the `derivation_origin` AND the app's canisters (with `oql`/`api_doc_available` \
             flags) — pass the NAME the user said (well-known apps, e.g. NNS and Oisy, resolve \
             offline) or a URL you have, NEVER a domain guessed from the name (there is no on-chain \
             name→URL directory; `icp_find_canister_by_name` finds token/SNS canister ids, not \
             front-ends). If you want just one part, `icp_find_app_by_name` does name→URL, \
             `resolve_app(url)` the origin, `discover_app_canisters(url)` the canisters; (3) \
             `list_app_accounts` — if there is more than one account, ask which to use and remember \
             it; (4) `get_app_principal` ONLY when you need the principal value itself (`canister_query` / \
             `canister_update_call` act as the account without pre-fetching it); (5) inspect the \
             canister with `get_canister_candid` — its `oql` flag says whether to read via OQL, \
             its `api_doc_available` flag whether `get_canister_api_doc` has a doc; (6) READ as the \
             user with `canister_query`, passing the `derivation_origin` (REQUIRED for OQL): use the \
             `oql` argument when `oql: true` (get the entity/field names from get_canister_oql_schema; \
             an anonymous OQL read is rejected for now, and a Candid `method` \
             query is REJECTED on an OQL canister), else a Candid `method` query; (7) ACT with \
             `canister_update_call`, passing `derivation_origin` + `account` to act as the \
             user. Public metadata (get_canister_candid, discover_app_canisters) and public \
             canister_query Candid `method` queries need no origin; OQL reads always require one. The \
             per-canister inspection (5) is independent of the identity steps (1/3/4), so they can \
             run in parallel. Managing your OWN canisters \
             (the `icp_` create/install/status/… tools) acts as your standing MANAGEMENT principal at \
             this server's origin — a DIFFERENT identity than the per-app principals above.\n\n\
             To AUTHOR, BUILD and DEPLOY IC code, first consult the official IC skills: \
             `icp_list_skills` lists them and `icp_get_skill(name)` loads one. Especially \
             `writing-motoko` (language), `mops-cli` (deps/build), `icp-cli` (build & deploy), \
             `cycles-management` \
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

/// One canister line for the open_app / discover_app_canisters text output: id,
/// discovery label, dashboard «name» (type), sources, and any capability flags
/// (`[oql]` / `[api-doc]`) filled in by [`IcTools::enrich_capabilities`]. Shared by
/// both tools so their listings stay identical.
fn render_canister_line(c: &discover::DiscoveredCanister) -> String {
    let identity = match (&c.name, &c.kind) {
        (Some(n), Some(k)) => format!("  «{n}» ({k})"),
        (Some(n), None) => format!("  «{n}»"),
        _ => String::new(),
    };
    let mut caps = String::new();
    if c.oql == Some(true) {
        caps.push_str(" [oql]");
    }
    if c.api_doc_available == Some(true) {
        caps.push_str(" [api-doc]");
    }
    format!(
        "- {}{}{} [{}]{}\n",
        c.canister_id,
        c.label.as_deref().map(|l| format!("  — {l}")).unwrap_or_default(),
        identity,
        c.sources.join(", "),
        caps,
    )
}

/// The caller-gated data-access note (#3): when discovery surfaced OQL data
/// canister(s), spell out that their data is gated by the CALLER's principal (an OQL
/// read requires the origin — an anonymous read is rejected for now) and how to read
/// as the user. `handle` is the ready-to-use origin clause when the origin is
/// already resolved (open_app), or `None` when it isn't (discover_app_canisters), in
/// which case the note points at resolve_app / open_app to obtain it.
fn data_access_note(canisters: &[discover::DiscoveredCanister], handle: Option<&str>) -> Option<String> {
    if !canisters.iter().any(|c| c.oql == Some(true)) {
        return None;
    }
    let how = match handle {
        Some(clause) => format!(
            "To read it as the user, pass {clause} to get_canister_oql_schema (for the entity/field \
             names) and canister_query (with the `oql` argument), plus an optional account from list_app_accounts."
        ),
        None => "Resolve the app's derivation_origin (resolve_app / open_app) and pass it to \
                 get_canister_oql_schema (for the entity/field names) and canister_query (with the \
                 `oql` argument) to read as the user."
            .to_string(),
    };
    Some(format!(
        "Data access: the canister(s) flagged [oql] hold this app's data, gated by the CALLER's \
         principal — an OQL read REQUIRES the origin (an anonymous read is rejected for now). {how}"
    ))
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
    s.push_str("\nFetch its interface with get_canister_candid, then read with canister_query and write with canister_update_call.");
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
             canister_query / canister_update_call / get_app_principal with no `account`.",
        );
    } else {
        out.push_str(
            "\nThere are multiple accounts here. Confirm which one the user means (or act on each), \
             then pass its name as `account` to canister_query / canister_update_call / \
             get_app_principal. Omit `account` for the default one.",
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


#[cfg(test)]
mod tests {
    use super::calls::decode_bytes_with_did;
    use candid::types::value::IDLArgs;
    use candid_parser::parse_idl_args;

    // Anonymous per-app reads are disabled for now: the OQL read tools reject a
    // call with no origin, and the rejection must name what to pass and how to get
    // it (so the agent recovers in one step) — not just say "no".
    #[test]
    fn oql_needs_origin_error_is_actionable() {
        let msg = super::oql_needs_origin_error("Running an OQL query");
        assert!(msg.contains("Running an OQL query"), "echoes the action: {msg}");
        assert!(msg.contains("derivation_origin"), "names the arg to pass: {msg}");
        assert!(
            msg.contains("open_app") && msg.contains("resolve_app"),
            "names how to get the origin: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("anonymous"),
            "explains anonymous is disabled: {msg}"
        );
    }

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
        assert_eq!(tools.len(), 26, "expected 26 tools, got {}", tools.len());
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
            "get_canister_candid", "canister_query", "get_canister_oql_schema", "discover_app_canisters", "icp_find_canister_by_name", "icp_find_app_by_name", "icp_lookup_canister_info_by_id",
            "icp_list_skills", "icp_get_skill", "icp_oql_guide",
            "get_canister_api_doc", "open_app", "resolve_app", "list_app_accounts", "icp_cycles_balance", "get_app_principal", "icp_canister_status",
        ] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(true), "{name} should be read-only");
            assert_eq!(a.destructive_hint, Some(false), "{name} should set destructive=false explicitly");
        }
        // Destructive writes: not read-only, destructive. Two kinds live here.
        // Overwriting/removing state: delete, uninstall, install (reinstall and
        // upgrade replace the running module), settings (can hand control away).
        // And SPENDING THE USER'S FUNDS: create and top-up add a canister or its
        // cycles, so "additive" is tempting — but the cycles or ICP leave the user's
        // ledger accounts irreversibly, no tool here can claw them back, and neither
        // call is idempotent, so a client retry spends again. `destructiveHint` is
        // what a client gates its confirmation prompt on and its spec default is
        // `true`, so declaring `false` would be an affirmative (and wrong) promise
        // that a stray call costs the user nothing. Keep them here.
        for name in [
            "icp_delete_canister", "icp_uninstall_code", "icp_install_code", "icp_update_canister_settings",
            "icp_create_canister", "icp_top_up_canister",
        ] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(false), "{name} should not be read-only");
            assert_eq!(a.destructive_hint, Some(true), "{name} should be destructive");
        }
        // Additive/reversible writes: not read-only, not destructive. These change
        // run state only, cost nothing, and each is undone by its counterpart.
        for name in ["icp_start_canister", "icp_stop_canister"] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(false), "{name} should not be read-only");
            assert_eq!(a.destructive_hint, Some(false), "{name} should not be destructive");
        }
        // The update-call tool is conservatively write + destructive.
        let cc = ann("canister_update_call");
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

    // resolve_identity_target's validation rules are part of the tool contract. It
    // takes ONLY `derivation_origin` now (the identity-bearing tools no longer
    // accept an app_url to resolve — see clean_app_url tests for URL validation).

    // A whitespace-only `derivation_origin` is empty after trimming and must be
    // rejected rather than canonicalized into a bogus origin.
    #[test]
    fn resolve_identity_target_rejects_blank_derivation_origin() {
        let err = super::resolve_identity_target(Some("   ".to_string()))
            .expect_err("blank derivation_origin must be an error");
        assert!(err.contains("must not be empty"), "unexpected message: {err}");
    }

    // `derivation_origin` is trimmed before canonicalization, so surrounding
    // whitespace never leaks into either the echoed `requested` or the effective
    // `origin` fed to the delegation path.
    #[test]
    fn resolve_identity_target_trims_derivation_origin() {
        let target = super::resolve_identity_target(Some("  https://example.com  ".to_string()))
            .expect("valid derivation_origin resolves")
            .expect("an explicit derivation_origin yields a target");
        assert_eq!(target.requested, "https://example.com", "requested must be trimmed");
        assert_eq!(target.origin, "https://example.com", "origin must be the canonical trimmed form");
        assert_eq!(target.source, "explicit");
    }

    // No `derivation_origin` is the anonymous path: no target, no error.
    #[test]
    fn resolve_identity_target_none_is_anonymous() {
        let target = super::resolve_identity_target(None).expect("None is anonymous");
        assert!(target.is_none(), "None must yield no target");
    }

    // A control character is rejected up front (it would otherwise be echoed back
    // verbatim / corrupt the delegation origin).
    #[test]
    fn resolve_identity_target_rejects_control_chars() {
        let err = super::resolve_identity_target(Some("https://ex\u{7}ample.com".to_string()))
            .expect_err("control chars must be rejected");
        assert!(err.contains("control characters"), "unexpected message: {err}");
    }

    // An uppercase scheme must canonicalize the same as lowercase — `target_origin`
    // strips only a lowercase `https://`, so without normalization `HTTPS://` would
    // survive into the host and mangle the origin instead of yielding `https://host`.
    #[test]
    fn resolve_identity_target_normalizes_uppercase_scheme() {
        let t = super::resolve_identity_target(Some("HTTPS://example.com".to_string()))
            .expect("uppercase https scheme must be accepted")
            .expect("a derivation_origin yields a target");
        assert_eq!(t.origin, "https://example.com", "unexpected origin: {}", t.origin);
    }

    // A mixed-case HOST is canonicalized to lowercase, so the echoed origin and the
    // delegation-cache key match the resolver path (which serializes via Url::origin())
    // instead of forking `https://Example.COM` from `https://example.com`.
    #[test]
    fn resolve_identity_target_lowercases_host() {
        let t = super::resolve_identity_target(Some("https://Example.COM".to_string()))
            .expect("mixed-case host must be accepted")
            .expect("a derivation_origin yields a target");
        assert_eq!(t.origin, "https://example.com", "host must be lowercased: {}", t.origin);
    }

    // A `derivation_origin` with no host (e.g. "https://") reduces to an empty
    // origin and must be rejected rather than derived against.
    #[test]
    fn resolve_identity_target_rejects_hostless_derivation_origin() {
        let err = super::resolve_identity_target(Some("https://".to_string()))
            .expect_err("host-less derivation_origin must be rejected");
        assert!(err.contains("host"), "unexpected message: {err}");
    }

    // A non-http(s) scheme must be rejected, not mangled into a bogus https origin.
    #[test]
    fn resolve_identity_target_rejects_non_http_scheme() {
        let err = super::resolve_identity_target(Some("ftp://example.com".to_string()))
            .expect_err("ftp:// must be rejected");
        assert!(err.contains("https origin"), "unexpected message: {err}");
    }

    // `clean_app_url` (used by the resolver tools open_app / resolve_app) fails
    // closed on bad URLs up front, so a caller gets a clear error instead of a late
    // SSRF-guard/URL-parse failure. (The identity-bearing tools no longer take an
    // app_url; the resolvers do.)
    #[test]
    fn clean_app_url_rejects_bad_urls() {
        assert!(super::clean_app_url("   ").expect_err("blank").contains("must not be empty"));
        assert!(super::clean_app_url("http://example.com").expect_err("http").contains("https"));
        assert!(
            super::clean_app_url("https://user:pass@example.com")
                .expect_err("user-info")
                .contains("user-info")
        );
        assert!(super::clean_app_url("https://").expect_err("host-less").contains("real host"));
        // A good bare host / https URL passes through.
        assert_eq!(super::clean_app_url("oisy.com").unwrap(), "oisy.com");
        assert_eq!(super::clean_app_url("https://oisy.com").unwrap(), "https://oisy.com");
    }

    // The guessed-domain refusal (offline): the message must name the failure,
    // redirect to the legitimate name→URL steps, carry the "did you mean" repair
    // when the host resembles a well-known app, and keep the deliberate
    // `derivation_origin` escape hatch — that combination is what turns a guessing
    // loop into a one-step correction.
    #[test]
    fn unverified_app_url_error_redirects_and_repairs() {
        // The exact wild-observed guess: multidex.com for MULTI/DEX (multidex.ai).
        let msg = super::unverified_app_url_error("https://multidex.com");
        assert!(msg.contains("NO evidence"), "{msg}");
        assert!(msg.contains("icp_find_app_by_name"), "{msg}");
        assert!(msg.contains("WEB SEARCH"), "{msg}");
        assert!(msg.contains("DID YOU MEAN MULTI/DEX"), "{msg}");
        assert!(msg.contains("https://multidex.ai"), "{msg}");
        assert!(msg.contains("`derivation_origin`"), "escape hatch missing: {msg}");
        // A host resembling no known app still gets the redirect, just no repair.
        let plain = super::unverified_app_url_error("https://example.com");
        assert!(plain.contains("icp_find_app_by_name"), "{plain}");
        assert!(!plain.contains("DID YOU MEAN"), "{plain}");
    }

    // A fetch failure on a guessed domain (offline: the DNS-dead "multi.dex" guess)
    // carries the same repair, so it reads as "wrong URL — here's the real one"
    // rather than a transient error inviting the next guess.
    #[test]
    fn app_url_fetch_errors_carry_guess_guidance() {
        let msg = super::app_url_error_with_guidance(
            "multi.dex",
            "could not resolve multi.dex: no such host".to_string(),
        );
        assert!(msg.contains("could not resolve"), "{msg}");
        assert!(msg.contains("DID YOU MEAN MULTI/DEX"), "{msg}");
        assert!(msg.contains("https://multidex.ai"), "{msg}");
        assert!(msg.contains("icp_find_app_by_name"), "{msg}");
        // Unrelated hosts: guidance without a bogus suggestion.
        let plain = super::app_url_error_with_guidance("example.com", "timeout".to_string());
        assert!(!plain.contains("DID YOU MEAN"), "{plain}");
        assert!(plain.contains("icp_find_app_by_name"), "{plain}");
    }

    // The human-readable identity annotation must surface a requested≠derived
    // mismatch (and the source) in ALL clients.
    #[test]
    fn identity_annotation_surfaces_mismatch_and_source() {
        // requested == origin: origin + source, but no redundant `requested` echo.
        let t = super::IdentityTarget {
            origin: "https://nns.ic0.app".to_string(),
            requested: "https://nns.ic0.app".to_string(),
            source: "explicit".to_string(),
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
        };
        let a2 = super::identity_annotation(&t2, Some("aaaaa-aa"));
        assert!(a2.contains("signed as aaaaa-aa"), "{a2}");
        assert!(a2.contains("requested https://app.example.com/some/path"), "{a2}");
    }

    // resolve_identity_target backs every identity-bearing path now — including
    // canister_query's OQL mode and get_canister_candid's schema read — so it must
    // fail closed on bad derivation origins: control chars, host-less, a non-https
    // scheme, an embedded space, and user-info are all rejected; a valid one trims +
    // canonicalizes. (The None/blank/uppercase/lowercase-host cases have their own
    // tests above.)
    #[test]
    fn resolve_identity_target_canonicalizes_and_rejects_bad_origins() {
        use super::resolve_identity_target as r;
        assert!(r(Some("https://a\u{7}b.com".to_string())).is_err(), "control chars rejected");
        assert!(r(Some("https://".to_string())).is_err(), "host-less rejected");
        assert!(r(Some("ftp://example.com".to_string())).is_err(), "non-http(s) scheme rejected");
        assert!(r(Some("https://ex ample.com".to_string())).is_err(), "embedded space rejected");
        assert!(
            r(Some("https://user@example.com".to_string())).is_err(),
            "user-info rejected (would derive a different principal than the bare origin)"
        );
        assert!(
            r(Some("http://example.com".to_string())).is_err(),
            "explicit http:// rejected (https-only contract; target_origin would silently upgrade it)"
        );
        let t = r(Some("  https://example.com  ".to_string()))
            .expect("valid origin resolves")
            .expect("an explicit derivation_origin yields a target");
        assert_eq!(t.origin, "https://example.com", "valid input trims + canonicalizes");
    }
}
