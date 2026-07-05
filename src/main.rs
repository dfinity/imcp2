//! Minimal MCP PoC: an MCP server exposing tools over streamable HTTP that talk
//! to the Internet Computer via ic-agent.
//!
//!   1. `get_candid`   — fetch a canister's Candid interface (`candid:service` metadata).
//!   2. `discover_canisters` — find the canisters behind a web domain.
//!   3. `call_canister` — call any method with textual Candid in, textual Candid out,
//!      as `anonymous` or as a domain identity derived ON DEMAND.
//!
//! The LLM only ever deals with textual Candid; encoding/decoding happens here.
//! Anonymous calls use the shared anonymous agent. A domain identity is minted
//! on demand from the connection's standing II delegation (see `identities`).

mod auth;
mod discover;
mod identities;
mod management;
mod skills;

use candid::{types::value::IDLArgs, Principal};
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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetCandidArgs {
    /// Canister principal, e.g. "ryjl3-tyaaa-aaaaa-aaaba-cai" (the ICP ledger).
    canister_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CallCanisterArgs {
    /// Target canister principal.
    canister_id: String,
    /// Method name to invoke.
    method: String,
    /// Arguments in textual Candid syntax, e.g. `()` or `(record { owner = principal "..." })`.
    #[serde(default = "default_args")]
    args: String,
    /// If true, perform a read-only `query` call; otherwise an `update` call.
    #[serde(default)]
    is_query: bool,
    /// Application domain to call as, e.g. "oisy.com" — its account delegation is
    /// derived on demand for this connection. Omit to call anonymously.
    #[serde(default)]
    domain: Option<String>,
    /// Which of your accounts at `domain` to act as, by account name (see
    /// list_accounts). Omit to use that app's default account. Ignored when
    /// `domain` is omitted (anonymous calls have no account).
    #[serde(default)]
    account: Option<String>,
    /// Optional Candid service definition (`.did` text) for the canister. Used to
    /// encode the args to the method's declared types and decode the reply, for
    /// when the canister's own `candid:service` metadata can't be read (e.g.
    /// access-restricted) — get it from get_candid, or ask the user for it.
    #[serde(default)]
    candid: Option<String>,
}

fn default_args() -> String {
    "()".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DiscoverCanistersArgs {
    /// A web domain or URL served from the IC, e.g. "oisy.com".
    domain: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetPrincipalArgs {
    /// The application domain to resolve, e.g. "oisy.com". Returns the principal
    /// you act as at that app — its account delegation is derived on demand (same
    /// as call_canister) and its principal returned.
    domain: String,
    /// Which of your accounts at `domain` to resolve, by account name (see
    /// list_accounts). Omit to use that app's default account.
    #[serde(default)]
    account: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListAccountsArgs {
    /// The application domain whose accounts to list, e.g. "oisy.com".
    domain: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct FindCanisterArgs {
    /// A name, token symbol, or project to search for, e.g. "ckUSDC", "ICP",
    /// "OpenChat".
    query: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct LookupCanisterArgs {
    /// Canister principal to identify, e.g. "ryjl3-tyaaa-aaaaa-aaaba-cai".
    canister_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetSkillArgs {
    /// Skill name, e.g. "motoko", "icp-cli", "cycles-management".
    name: String,
}

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
    )]
    async fn get_candid(
        &self,
        Parameters(GetCandidArgs { canister_id }): Parameters<GetCandidArgs>,
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
                Ok(did) => Ok(ok(did)),
                Err(e) => Ok(err(format!("metadata is not valid UTF-8: {e}"))),
            },
            Err(e) => Ok(err(format!(
                "could not read candid:service metadata: {e}"
            ))),
        }
    }

    #[tool(
        description = "Call a method on an Internet Computer canister with textual Candid in and out. Args are encoded against the method's declared Candid types (so plain literals like 42 coerce correctly — no `: type` annotations needed). Omit `domain` to call anonymously, or pass an application domain (e.g. \"oisy.com\") to call as your account at that app — a short-lived account delegation is derived on demand from this connection's standing Internet Identity credential. By default this uses the app's default account; pass `account` (an account name from list_accounts) to act as a specific named account there. Set is_query=true for read-only query calls. If get_candid couldn't fetch the interface, pass the `.did` text as `candid` (e.g. ask the user for it) so args/replies are still typed.",
        annotations(title = "Call a canister method", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
    )]
    async fn call_canister(
        &self,
        Parameters(CallCanisterArgs {
            canister_id,
            method,
            args,
            is_query,
            domain,
            account,
            candid,
        }): Parameters<CallCanisterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // The interface to encode/decode against: the canister's own
        // candid:service if exposed, else the caller-supplied `candid`.
        let did = self.resolve_did(principal, candid.as_deref()).await;
        let arg_bytes = match encode_args(did.as_deref(), &method, &args) {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };

        // Pick the agent: no domain uses the shared anonymous agent; a domain
        // derives a short-lived account delegation for that app on demand and
        // builds an agent backed by it (the server signs as the user's account
        // for that app).
        let reply = match domain {
            None => raw_call(&self.agent, principal, &method, arg_bytes, is_query).await,
            Some(domain) => {
                let session_id = match authed_session(&ctx) {
                    Some(s) => s.session_id,
                    None => return Ok(err("calling as a domain needs an authenticated session".into())),
                };
                let delegated = match self
                    .identities
                    .delegated_identity_for(&session_id, &domain, account.as_deref())
                    .await
                {
                    Ok(d) => d,
                    Err(e) => return Ok(err(e)),
                };
                let agent = match Agent::builder().with_url(IC_URL).with_identity(delegated).build() {
                    Ok(a) => a,
                    Err(e) => return Ok(err(format!("could not build agent: {e}"))),
                };
                raw_call(&agent, principal, &method, arg_bytes, is_query).await
            }
        };

        let reply_bytes = match reply {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("call failed: {e}"))),
        };
        // Decode against the Candid interface so field names are recovered.
        Ok(ok(decode_reply(did.as_deref(), &method, &reply_bytes)))
    }

    #[tool(
        description = "Get the Internet Computer principal you act as at a given application `domain` (e.g. \"oisy.com\"), without making a canister call. The app's account delegation is derived on demand (same as call_canister) from this connection's standing Internet Identity credential, and its principal is returned. By default this resolves the app's default account; pass `account` (an account name from list_accounts) for a specific named account there. Use this when a flow needs the principal itself (e.g. to look up a balance or account) rather than to invoke a method. NOTE: the principal is derived from the app's DOMAIN, which is usually — but not always — the identity a browser sign-in to that app would use. Some apps declare a CUSTOM derivation origin (via /.well-known/ii-alternative-origins) that isn't exposed here; if the returned principal (or an account/balance) doesn't match what the user sees in their browser at that app, tell them so and offer to look up the app's ii-alternative-origins (web search / fetch) and retry.",
        annotations(title = "Get your principal at an app", read_only_hint = true, destructive_hint = false, open_world_hint = true),
    )]
    async fn get_principal(
        &self,
        Parameters(GetPrincipalArgs { domain, account }): Parameters<GetPrincipalArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("getting a domain principal needs an authenticated session".into())),
        };
        let delegated = match self
            .identities
            .delegated_identity_for(&session_id, &domain, account.as_deref())
            .await
        {
            Ok(d) => d,
            Err(e) => return Ok(err(e)),
        };
        match delegated.sender() {
            Ok(p) => {
                let mut out = p.to_text();
                // Surface a read-only session (H2) so the LLM won't attempt (and
                // have the IC reject at ingress) canister-management updates.
                if self.identities.is_read_only(&session_id).await == Some(true) {
                    out.push_str(
                        "\n\n(This Internet Identity session is READ-ONLY: reads work, but canister \
                         management — create/install/start/stop/delete, and canister_status — needs \
                         update access. Ask the user to reconnect with the read-only option turned OFF.)",
                    );
                }
                Ok(ok(out))
            }
            Err(e) => Ok(err(format!("could not derive principal for '{domain}': {e}"))),
        }
    }

    #[tool(
        description = "List the user's Internet Identity accounts at an application `domain` (e.g. \"oisy.com\"). Internet Identity gives the user a distinct principal per app (derived from the app's domain), and within an app they may hold several accounts: a default account everyone gets automatically (the anchor's current, user-controllable default at that origin), plus any named accounts they created. Use this before acting on the user's behalf at an app: if there's only the default account, just proceed (call_canister/get_principal with no `account`); if there are several, pick one with the user (or act on each) by passing its name as `account`. Returns each account's name (the default has none), account number, and last-used time. If these accounts don't match what the user sees in their browser at this app, it may use a custom derivation origin not exposed here (offer to look up its ii-alternative-origins and retry). Requires an authenticated session.",
        annotations(title = "List your accounts at an app", read_only_hint = true, destructive_hint = false, open_world_hint = true),
    )]
    async fn list_accounts(
        &self,
        Parameters(ListAccountsArgs { domain }): Parameters<ListAccountsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("listing your accounts needs an authenticated session".into())),
        };
        match self.identities.list_accounts(&session_id, &domain).await {
            Ok(accounts) => Ok(ok(format_accounts(&domain, &accounts))),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Discover the Internet Computer canisters behind a web domain (e.g. \"oisy.com\"). Returns every canister id found, with provenance: the `x-ic-canister-id` header (the frontend/asset canister — authoritative), a `/env.json` runtime config (e.g. backend_canister_id), and labelled/bare canister-id literals mined from the JS bundle. There is no authoritative reverse lookup for a site's backend, so results from env.json/bundle are candidates: pick by label (prefer production/IC ids) and confirm with get_candid before calling.",
        annotations(title = "Discover canisters behind a domain", read_only_hint = true, destructive_hint = false, open_world_hint = true),
    )]
    async fn discover_canisters(
        &self,
        Parameters(DiscoverCanistersArgs { domain }): Parameters<DiscoverCanistersArgs>,
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
                    "\nThe `header` (x-ic-canister-id) entry is the frontend/asset canister and is \
                     authoritative. Others come from env.json or the JS bundle and may include \
                     multiple environments (prefer the production/IC ids). A «name» (type) is the \
                     IC dashboard's label for that id. No authoritative reverse lookup exists — \
                     confirm an interface with get_candid before calling.",
                );
                Ok(ok(out))
            }
            Ok(_) => Ok(ok(format!(
                "No IC canisters found for {domain} — is it served from the Internet Computer?"
            ))),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Find Internet Computer canisters by NAME. Searches the IC dashboard's service registries — the ICRC token ledgers (e.g. ckBTC, ckETH, ckUSDC, SNS tokens) by symbol/name, and the SNS project catalog by name — and returns matching canister ids. Use this when the user names a token, project, or service (e.g. \"ckUSDC\") rather than a canister id; then confirm with get_candid and call methods with call_canister. (No public name-search exists over arbitrary canisters; this covers the IC's labelled services.)",
        annotations(title = "Find canisters by name", read_only_hint = true, destructive_hint = false, open_world_hint = true),
    )]
    async fn find_canister(
        &self,
        Parameters(FindCanisterArgs { query }): Parameters<FindCanisterArgs>,
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
                    "\nConfirm an interface with get_candid, then call methods with call_canister. \
                     For an SNS match the id is the project root — lookup_canister it to learn more.",
                );
                Ok(ok(out))
            }
            Ok(_) => Ok(ok(format!(
                "No named canisters found matching \"{query}\". This searches known tokens (ICRC \
                 ledgers) and SNS projects, so an arbitrary canister won't appear unless it's a \
                 labelled service. If you have a website, try discover_canisters; if you already \
                 have a canister id, try lookup_canister or get_candid."
            ))),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Identify what an Internet Computer canister IS, from the IC dashboard: its label/name (e.g. \"ICP Ledger\"), type (e.g. \"ledger\"), controllers, hosting subnet, module hash, language, and latest upgrade proposal. Use this to make sense of a bare canister id — e.g. one returned by discover_canisters.",
        annotations(title = "Identify a canister", read_only_hint = true, destructive_hint = false, open_world_hint = true),
    )]
    async fn lookup_canister(
        &self,
        Parameters(LookupCanisterArgs { canister_id }): Parameters<LookupCanisterArgs>,
    ) -> Result<CallToolResult, McpError> {
        let client = match discover::http_client() {
            Ok(c) => c,
            Err(e) => return Ok(err(e)),
        };
        match discover::lookup_canister(&client, &canister_id).await {
            Ok(info) => Ok(ok(format_canister_info(&info))),
            Err(e) => Ok(err(e)),
        }
    }

    // ---- ICP skills awareness ----------------------------------------------

    #[tool(
        description = "List the official Internet Computer skills — authoritative how-to guides for authoring and shipping IC apps (Motoko language, mops/icp CLIs, cycles management, stable memory & upgrades, security, DeFi, auth, …). Returns each skill's name and a one-line description. Load a skill's full instructions with get_ic_skill(name). Consult these BEFORE writing Motoko/Rust canister code, building, or deploying.",
        annotations(title = "List Internet Computer skills", read_only_hint = true, destructive_hint = false, open_world_hint = false),
    )]
    async fn list_ic_skills(
        &self,
        Parameters(_args): Parameters<management::NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.skills.list().await {
            Ok(s) => Ok(ok(skills::SkillsCatalog::format_list(&s))),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Fetch the full instructions (SKILL.md) of one Internet Computer skill by name (e.g. \"motoko\", \"icp-cli\", \"mops-cli\", \"cycles-management\", \"stable-memory\", \"canister-security\"). Call list_ic_skills first to see the available names. Use this to learn the exact, current way to do an IC task before doing it.",
        annotations(title = "Get an Internet Computer skill", read_only_hint = true, destructive_hint = false, open_world_hint = false),
    )]
    async fn get_ic_skill(
        &self,
        Parameters(GetSkillArgs { name }): Parameters<GetSkillArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.skills.get(&name).await {
            Ok(md) => Ok(ok(md)),
            Err(e) => Ok(err(e)),
        }
    }

    // ---- Canister creation & management (as your standing II principal) -----

    #[tool(
        description = "Your cycles-ledger balance — the cycles that create_canister and top_up_canister spend. Acts as your Internet Identity principal (also printed). If it's empty, fund it first (e.g. via the icp CLI / cycles-management skill). Requires an authenticated session.",
        annotations(title = "Check your cycles balance", read_only_hint = true, destructive_hint = false, open_world_hint = true),
    )]
    async fn cycles_balance(
        &self,
        Parameters(_args): Parameters<management::NoArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("checking your cycles balance needs an authenticated session".into())),
        };
        Ok(into_result(management::cycles_balance(&self.identities, &sid).await))
    }

    #[tool(
        description = "Create and fund a NEW Internet Computer canister, paying from your cycles-ledger balance (as your Internet Identity). Specify the amount as `cycles` (exact) or `icp` (a decimal-ICP string like \"0.5\", converted to cycles at the network's current rate). Controllers default to your own principal. You must already hold cycles in the cycles ledger (check with cycles_balance; fund via the icp CLI / cycles-management skill). Returns the new canister id — then build your Wasm (see the motoko/icp-cli skills) and install it with install_code. Requires an authenticated session.",
        annotations(title = "Create a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true),
    )]
    async fn create_canister(
        &self,
        Parameters(args): Parameters<management::CreateCanisterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("creating a canister needs an authenticated session".into())),
        };
        Ok(into_result(
            management::create_canister(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Add cycles to an existing canister, paying from your cycles-ledger balance. Specify `cycles` (exact) or `icp` (decimal-ICP string, converted at the current rate). Requires an authenticated session.",
        annotations(title = "Top up a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = true),
    )]
    async fn top_up_canister(
        &self,
        Parameters(args): Parameters<management::TopUpArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("topping up a canister needs an authenticated session".into())),
        };
        Ok(into_result(
            management::top_up_canister(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Install a compiled Wasm module on a canister you control (as your Internet Identity). Provide the module as `wasm_base64` (or `wasm_hex`); large modules are uploaded via the chunk store automatically. `mode` is \"install\" (default, empty canister), \"reinstall\" (wipe state), or \"upgrade\" (preserve stable memory). `arg` is the init/upgrade argument in textual Candid, e.g. \"()\". Build the Wasm in your own environment first (see the motoko / icp-cli / mops-cli skills). Requires an authenticated session.",
        annotations(title = "Install code on a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
    )]
    async fn install_code(
        &self,
        Parameters(args): Parameters<management::InstallCodeArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("installing code needs an authenticated session".into())),
        };
        Ok(into_result(
            management::install_code(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Report a canister's status: run state, cycle balance, module hash, memory size, controllers, and allocations. Controller-only (acts as your Internet Identity). This only READS status (it changes nothing), but on the IC it is an update call, so it needs a full (non-read-only) Internet Identity session. Requires an authenticated session.",
        annotations(title = "Get canister status", read_only_hint = true, destructive_hint = false, open_world_hint = true),
    )]
    async fn canister_status(
        &self,
        Parameters(args): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("reading canister status needs an authenticated session".into())),
        };
        Ok(into_result(
            management::canister_status(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Update a canister's settings: controllers, compute/memory allocation, freezing threshold, reserved-cycles limit, wasm memory limit, or log visibility (\"controllers\"|\"public\"). Only the fields you pass are changed. WARNING: passing `controllers` REPLACES the whole set — include your own principal to remain a controller. Requires an authenticated session.",
        annotations(title = "Update canister settings", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
    )]
    async fn update_canister_settings(
        &self,
        Parameters(args): Parameters<management::UpdateSettingsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("updating settings needs an authenticated session".into())),
        };
        Ok(into_result(
            management::update_canister_settings(&self.identities, &sid, args).await,
        ))
    }

    #[tool(
        description = "Start a stopped canister you control. Requires an authenticated session.",
        annotations(title = "Start a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
    )]
    async fn start_canister(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("starting a canister needs an authenticated session".into())),
        };
        Ok(into_result(
            management::start_canister(&self.identities, &sid, &canister_id).await,
        ))
    }

    #[tool(
        description = "Stop a running canister you control (required before deleting it). Requires an authenticated session.",
        annotations(title = "Stop a canister", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = true),
    )]
    async fn stop_canister(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("stopping a canister needs an authenticated session".into())),
        };
        Ok(into_result(
            management::stop_canister(&self.identities, &sid, &canister_id).await,
        ))
    }

    #[tool(
        description = "Remove a canister's code and state, leaving it empty (it keeps its id and cycles). Acts as your Internet Identity. Requires an authenticated session.",
        annotations(title = "Uninstall code from a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = true),
    )]
    async fn uninstall_code(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("uninstalling code needs an authenticated session".into())),
        };
        Ok(into_result(
            management::uninstall_code(&self.identities, &sid, &canister_id).await,
        ))
    }

    #[tool(
        description = "Delete a canister permanently (irreversible — stop it first; remaining cycles are burned). Acts as your Internet Identity. Requires an authenticated session.",
        annotations(title = "Delete a canister", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
    )]
    async fn delete_canister(
        &self,
        Parameters(management::CanisterRefArgs { canister_id }): Parameters<management::CanisterRefArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let sid = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("deleting a canister needs an authenticated session".into())),
        };
        Ok(into_result(
            management::delete_canister(&self.identities, &sid, &canister_id).await,
        ))
    }
}

impl IcTools {
    /// The interface to encode/decode against: the canister's own
    /// `candid:service` if exposed, else the caller-supplied `candid`.
    async fn resolve_did(&self, canister: Principal, provided: Option<&str>) -> Option<String> {
        if let Some(did) = self.candid_service(canister).await {
            return Some(did);
        }
        provided.map(str::to_string)
    }

    /// The canister's `candid:service` interface (`.did` text), if exposed.
    async fn candid_service(&self, canister: Principal) -> Option<String> {
        let raw = self
            .agent
            .read_state_canister_metadata(canister, "candid:service")
            .await
            .ok()?;
        String::from_utf8(raw).ok()
    }
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
/// Depth is measured structurally without parsing: `opt`/`vec` prefixes and the
/// `(` `{` `[` group openers each add a level (matching how the parser recurses),
/// closers and value separators pop the just-completed value's prefixes. String
/// literals are skipped so their contents can't inflate the count. It is a safe
/// over-approximation — it may over- but never under-count real nesting.
pub(crate) fn guard_candid_text(what: &str, text: &str) -> Result<(), String> {
    if text.len() > MAX_CANDID_TEXT_BYTES {
        return Err(format!(
            "{what} is too large to parse ({} bytes; limit {MAX_CANDID_TEXT_BYTES})",
            text.len()
        ));
    }
    // Stack of open nesting frames: b'B' = bracket group, b'P' = opt/vec prefix.
    let mut stack: Vec<u8> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
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
                continue;
            }
            b'(' | b'{' | b'[' => {
                stack.push(b'B');
                if stack.len() > MAX_CANDID_DEPTH {
                    return Err(depth_err(what));
                }
                i += 1;
            }
            b')' | b'}' | b']' => {
                while stack.last() == Some(&b'P') {
                    stack.pop();
                }
                if stack.last() == Some(&b'B') {
                    stack.pop();
                }
                while stack.last() == Some(&b'P') {
                    stack.pop();
                }
                i += 1;
            }
            b',' | b';' => {
                while stack.last() == Some(&b'P') {
                    stack.pop();
                }
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
                }
                // Any other word is a leaf/keyword token; leaves pop their wrapping
                // prefixes so sibling values don't accumulate.
                else {
                    while stack.last() == Some(&b'P') {
                        stack.pop();
                    }
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
fn encode_args(did: Option<&str>, method: &str, args_text: &str) -> Result<Vec<u8>, String> {
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
fn decode_reply(did: Option<&str>, method: &str, bytes: &[u8]) -> String {
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
fn decode_bytes_with_did(did: &str, method: &str, bytes: &[u8]) -> Option<String> {
    // Skip (fall back to type-less decoding) if the interface is too large/nested
    // to parse safely (CWE-674).
    guard_candid_text("the `candid` interface", did).ok()?;
    let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
    let actor = actor?;
    let func = env.get_method(&actor, method).ok()?;
    let decoded = IDLArgs::from_bytes_with_types(bytes, &env, &func.rets).ok()?;
    Some(decoded.to_string())
}

/// The authenticated MCP session of the calling request, if it carried a valid
/// bearer token (injected by [`auth::require_token`]).
fn authed_session(ctx: &RequestContext<RoleServer>) -> Option<auth::AuthedSession> {
    ctx.extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<auth::AuthedSession>())
        .cloned()
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

/// Perform a query or update call and return the raw Candid reply bytes.
async fn raw_call(
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
             the binary form. Before writing Candid args, consult the `candid://textual-syntax` \
             resource (the value syntax these tools use); `candid://reference` has the full type \
             reference. When the user names a website/domain instead of a canister id, use \
             `discover_canisters` to find the canister(s) behind it (frontend via header, \
             backend via env.json/JS bundle). When they name a TOKEN, PROJECT or SERVICE (e.g. \
             \"ckUSDC\"), use `find_canister` to look it up by name in the IC dashboard's \
             registries and get its canister id. `lookup_canister(id)` tells you what a bare \
             canister id IS (dashboard label, type, controllers, subnet). `get_candid` fetches a \
             canister's Candid interface. `call_canister` calls a method with textual Candid \
             in/out: omit `domain` to call anonymously, or pass an application domain (e.g. \
             domain=\"oisy.com\") to call as your account at that app — a short-lived (<=5 min) \
             account delegation for it is minted ON DEMAND from this connection's standing \
             Internet Identity credential, no extra sign-in. `get_principal` returns the principal \
             you act as at an application `domain` without making a call (e.g. to look up a \
             balance or account). A user may hold several accounts at an app (a default one plus \
             named ones); `list_accounts(domain)` lists them, and call_canister/get_principal take \
             an optional `account` (a name from that list) to act as a specific one — omit it for \
             the default account. The per-app principal is derived from the app's DOMAIN — usually, \
             but NOT always, the same identity a browser sign-in to that app would use: some apps \
             declare a custom derivation origin (via /.well-known/ii-alternative-origins) not \
             exposed here. If a principal, account, or balance doesn't match what the user sees in \
             their browser at that app, say so and offer to look up the app's ii-alternative-origins \
             (web search / fetch) and retry. The standing credential is obtained when you connect \
             (authenticate via Internet Identity) and lasts ~60 minutes; reconnect when it expires. \
             The session may be READ-ONLY (Internet Identity's consent screen defaults to read-only): \
             reads work, but the canister-management tools below make update calls the network \
             rejects for a read-only session — if one fails that way, ask the user to reconnect with \
             the read-only option turned OFF.\n\n\
             To AUTHOR, BUILD and DEPLOY IC code, first consult the official IC skills: \
             `list_ic_skills` lists them and `get_ic_skill(name)` loads one. Especially `motoko` \
             (language), `mops-cli` (deps/build), `icp-cli` (build & deploy), `cycles-management` \
             (ICP↔cycles & funding), `stable-memory` (upgrades) and `canister-security`. Compiling \
             Motoko/Rust to Wasm happens in YOUR environment (guided by these skills); these tools \
             then put it on chain. To CREATE and MANAGE canisters as your Internet Identity, use: \
             `cycles_balance` (your cycles-ledger balance), `create_canister` (create + fund from \
             that balance — amount in `cycles` or `icp`), `install_code` (install your compiled \
             Wasm — base64 — single-shot or chunked), `canister_status`, `update_canister_settings`, \
             `start_canister`/`stop_canister`/`uninstall_code`/`delete_canister`, and \
             `top_up_canister`. These act as your standing II principal, which must hold cycles in \
             the cycles ledger first (fund it via the icp CLI / cycles-management skill). So to \
             \"build X and deploy a canister with Y ICP worth of cycles\": read the relevant skills, \
             write & build the Wasm locally, `create_canister(icp=Y)`, then `install_code`."
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

/// Render an IC dashboard canister identity as readable text for lookup_canister.
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
    s.push_str("\nFetch its interface with get_candid, then call methods with call_canister.");
    s
}

/// Render the user's accounts at an app (from `Identities::list_accounts`) as
/// readable text for the `list_accounts` tool.
fn format_accounts(domain: &str, accounts: &[identities::AccountInfo]) -> String {
    if accounts.is_empty() {
        return format!("No Internet Identity accounts found at {domain}.");
    }
    let mut out = format!("Your accounts at {domain}:\n");
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
             call_canister(domain) / get_principal(domain) with no `account`.",
        );
    } else {
        out.push_str(
            "\nThere are multiple accounts here. Confirm which one the user means (or act on each), \
             then pass its name as `account` to call_canister / get_principal. Omit `account` for \
             the default one.",
        );
    }
    out
}

fn ok(text: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(text)])
}

fn err(text: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(text)])
}

/// Map a tool's `Result<String, String>` to a success/error `CallToolResult`.
fn into_result(r: Result<String, String>) -> CallToolResult {
    match r {
        Ok(text) => ok(text),
        Err(text) => err(text),
    }
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IC MCP PoC</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto">
<h1>Internet Computer MCP PoC</h1>
<p>MCP endpoints: <code>POST /mcp</code> (beta Internet Identity) · <code>POST /mcp-prod</code> (production Internet Identity)</p>
<p>Tools: <code>discover_canisters</code> (domain → canister ids), <code>find_canister</code> (name → canister ids), <code>lookup_canister</code> (id → dashboard identity), <code>get_candid</code>, <code>call_canister</code> (anonymously, or as your account at an application domain, derived on demand from the connection's standing Internet Identity delegation), <code>get_principal</code> (your principal at an application domain, no call), <code>list_accounts</code> (your Internet Identity accounts at an app domain). All speak textual Candid.</p>
<p>Skills: <code>list_ic_skills</code> / <code>get_ic_skill</code> (the official IC how-to guides — Motoko, mops, icp CLI, cycles, …).</p>
<p>Canister management (as your Internet Identity): <code>cycles_balance</code>, <code>create_canister</code>, <code>install_code</code>, <code>canister_status</code>, <code>update_canister_settings</code>, <code>start_canister</code>, <code>stop_canister</code>, <code>uninstall_code</code>, <code>delete_canister</code>, <code>top_up_canister</code>.</p>
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
            "II instance {}: {} ({}) at {}",
            inst.name, inst.ii_url, inst.ii_canister, inst.mcp_path
        );
    }
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
            .route("/oauth/connect/callback", axum::routing::post(auth::connect_callback))
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
    let oauth = discovery_beta
        .merge(discovery_prod)
        .merge(oauth_endpoints(store_beta.clone()))
        .nest("/prod", oauth_endpoints(store_prod.clone()))
        .layer(cors);

    // When this process started — i.e. when the deployment last (re)started.
    // Every deploy restarts the service, so this is the "last redeployment" time.
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let app = axum::Router::new()
        .route("/", axum::routing::get(|| async { axum::response::Html(INDEX_HTML) }))
        // Unauthenticated build/version probe so operators and the status
        // dashboard can confirm exactly which deployment is live: the running
        // commit (baked in at build time via GIT_SHA), the build time
        // (BUILD_TIME), and when this process started (= last redeployment).
        // Timestamps are Unix epoch seconds (or null when unknown).
        .route(
            "/version",
            axum::routing::get(move || async move {
                axum::Json(serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "commit": option_env!("GIT_SHA").unwrap_or("unknown"),
                    "built_at": option_env!("BUILD_TIME").and_then(|s| s.parse::<u64>().ok()),
                    "started_at": started_at,
                    // H3/P1 health: repeat key requests on a consumed connect_state.
                    // Expected ~0; a sustained rise means II is re-issuing the key
                    // request (breaks connects under strict single-use), so alert on it.
                    "repeat_key_requests": auth::repeat_key_requests(),
                }))
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
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            ct.cancel();
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decode_bytes_with_did;
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
        // Oversized-but-shallow input is caught by the byte cap.
        let big = "0,".repeat(MAX_CANDID_TEXT_BYTES);
        assert!(guard_candid_text("v", &big).is_err(), "oversized input must be refused");
        // No false positives: brackets inside a STRING don't count, and many
        // SIBLING (non-nested) opts stay shallow.
        assert!(guard_candid_text("v", &format!("\"{}\"", "(".repeat(10_000))).is_ok());
        assert!(guard_candid_text("v", &format!("(record {{ {} }})", "a = opt 1; ".repeat(1000))).is_ok());
    }

    // Every tool must carry MCP annotations, else clients fall back to the unsafe
    // defaults (readOnly=false, destructive=true) and mislabel reads like
    // get_candid as destructive. Assert the read/write classification serializes.
    #[test]
    fn every_tool_has_correct_read_write_annotations() {
        let tools = super::IcTools::tool_router().list_all();
        assert_eq!(tools.len(), 19, "expected 19 tools, got {}", tools.len());
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
            "get_candid", "discover_canisters", "find_canister", "lookup_canister",
            "list_ic_skills", "get_ic_skill", "list_accounts", "cycles_balance",
            "get_principal", "canister_status",
        ] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(true), "{name} should be read-only");
            assert_eq!(a.destructive_hint, Some(false), "{name} should set destructive=false explicitly");
        }
        // Destructive writes: not read-only, destructive.
        for name in ["delete_canister", "uninstall_code", "install_code", "update_canister_settings"] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(false), "{name} should not be read-only");
            assert_eq!(a.destructive_hint, Some(true), "{name} should be destructive");
        }
        // Additive/reversible writes: not read-only, not destructive.
        for name in ["create_canister", "top_up_canister", "start_canister", "stop_canister"] {
            let a = ann(name);
            assert_eq!(a.read_only_hint, Some(false), "{name} should not be read-only");
            assert_eq!(a.destructive_hint, Some(false), "{name} should not be destructive");
        }
        // The dual-mode caller is conservatively write + destructive.
        let cc = ann("call_canister");
        assert_eq!(cc.read_only_hint, Some(false));
        assert_eq!(cc.destructive_hint, Some(true));
    }
}
