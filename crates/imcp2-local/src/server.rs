//! The local MCP server: [`IcTools`] wrapped in a thin handler that adds the
//! two **local-only login tools**. They cannot live in `imcp2-core` — they
//! drive this binary's loopback listener and browser opener, which core cannot
//! call back into — so this wrapper carries them in its own `#[tool_router]`,
//! answers `tools/list` with the merged list, dispatches `tools/call` to its
//! own router first, and forwards everything else to the inner [`IcTools`]
//! handler verbatim. The hosted server contains none of this code, so its tool
//! surface stays login-free by construction (a core-side test guards the
//! boundary too).

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_router, ErrorData as McpError, RoleServer, ServerHandler};

use crate::login::{BeginOutcome, Grant, LoginDriver, LoginStatus};
use imcp2_core::IcTools;

pub struct LocalServer {
    tools: IcTools,
    login: LoginDriver,
    /// Whether the login flow will also try to open the browser itself —
    /// only phrasing: the link is always returned in-band.
    auto_open: bool,
}

/// Arguments of the `authenticate` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AuthenticateArgs {
    /// Start a fresh sign-in even when a session is already active — to switch
    /// accounts, raise the access level, or extend the grant. Default: an
    /// active session is reported instead of starting over.
    #[serde(default)]
    pub refresh: bool,
}

fn signed_in_line(g: &Grant) -> String {
    let who = match &g.principal {
        Some(p) => format!(" as {p}"),
        None => String::new(),
    };
    let access = match g.permissions {
        "queries" => "read-only",
        other => other,
    };
    format!(
        "Signed in{who} (access: {access}; the grant expires in about {}).",
        human_minutes(g.minutes_left())
    )
}

/// "45 min" / "3 hours" / "12 days" — the II consent screen offers session
/// lengths from minutes to a month, so raw minutes would read like a counter.
fn human_minutes(mins: u64) -> String {
    if mins >= 48 * 60 {
        format!("{} days", mins / (24 * 60))
    } else if mins >= 120 {
        format!("{} hours", mins / 60)
    } else {
        format!("{mins} min")
    }
}

#[tool_router]
impl LocalServer {
    pub fn new(tools: IcTools, login: LoginDriver, auto_open: bool) -> Self {
        Self {
            tools,
            login,
            auto_open,
        }
    }

    #[tool(
        description = "Sign in with Internet Identity. Returns an id.ai sign-in link for the USER to open in their browser (the server also tries to open it for them), and returns immediately — it never waits for the browser. After the user finishes, auth_status (or simply retrying the tool that needed a session) confirms the session. Call this when a tool answers that it needs an authenticated session. Repeat calls while a sign-in is pending return the same link.",
        annotations(
            title = "Sign in with Internet Identity",
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn authenticate(
        &self,
        Parameters(AuthenticateArgs { refresh }): Parameters<AuthenticateArgs>,
    ) -> Result<CallToolResult, McpError> {
        let text = match self.login.begin(refresh).await {
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Could not start the sign-in: {e}"
                ))]))
            }
            Ok(BeginOutcome::AlreadySignedIn(g)) => format!(
                "{} Pass refresh=true to sign in again (switch accounts or extend the session).",
                signed_in_line(&g)
            ),
            Ok(BeginOutcome::Pending { url, fresh }) => {
                let opener = if self.auto_open {
                    "I also asked the system to open it in your browser. "
                } else {
                    ""
                };
                let lead = if fresh {
                    "To sign in, open this Internet Identity link in your browser"
                } else {
                    "A sign-in is already waiting for you — open this Internet Identity link in your browser"
                };
                format!(
                    "{lead}:\n\n{url}\n\n{opener}The link is valid for 10 minutes. \
                     After you finish in the browser, call auth_status — or just retry \
                     the tool you wanted — to confirm the session."
                )
            }
        };
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(
        description = "Report the Internet Identity sign-in state of this local server: signed in (with the session principal, access level, and time to expiry), sign-in pending (with the link to finish it), expired, or signed out.",
        annotations(
            title = "Check sign-in status",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn auth_status(&self) -> Result<CallToolResult, McpError> {
        let text = match self.login.status().await {
            LoginStatus::SignedIn(g) => signed_in_line(&g),
            LoginStatus::Pending { url } => format!(
                "A sign-in is pending — waiting for the browser handshake to finish at:\n\n{url}"
            ),
            LoginStatus::Expired(g) => {
                let who = match &g.principal {
                    Some(p) => format!(" (was {p})"),
                    None => String::new(),
                };
                format!("The session expired{who}. Call authenticate to sign in again.")
            }
            LoginStatus::SignedOut => {
                "Not signed in. Call authenticate to get a sign-in link.".to_string()
            }
        };
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

impl ServerHandler for LocalServer {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = self.tools.get_info();
        info.server_info.name = "imcp2-local".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        // The core instructions apply verbatim; add how signing in works here
        // (the hosted server logs in via OAuth outside the tool surface, so
        // core's text says nothing about it).
        let core = info.instructions.take().unwrap_or_default();
        info.instructions = Some(format!(
            "{core}\n\n\
             SIGNING IN (this local server). Tool calls act as the USER's Internet Identity. \
             When a tool answers that it needs an authenticated session, call `authenticate`: \
             it returns an id.ai sign-in link (and best-effort opens the browser) and never \
             blocks — after the user finishes in the browser, `auth_status` or simply retrying \
             the original tool confirms. Sessions are in-memory: the user signs in again after \
             a restart, when the grant expires, or if they revoke it at id.ai."
        ));
        info
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self.tools.list_tools(request, context).await?;
        result.tools.extend(Self::tool_router().list_all());
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if Self::tool_router().has_route(&request.name) {
            let tcc = ToolCallContext::new(self, request, context);
            Self::tool_router().call(tcc).await
        } else {
            self.tools.call_tool(request, context).await
        }
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        Self::tool_router()
            .get(name)
            .cloned()
            .or_else(|| self.tools.get_tool(name))
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        self.tools.list_resources(request, context).await
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        self.tools.read_resource(request, context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imcp2_core::{identities::Identities, skills, IiInstance, SessionSlot, SessionSource};
    use rmcp::ServiceExt;

    fn test_server() -> LocalServer {
        let agent = imcp2_core::Agent::builder()
            .with_url(imcp2_core::IC_URL)
            .build()
            .expect("agent");
        let identities = Identities::new(
            IiInstance::prod().expect("prod II"),
            "https://mcp.internetcomputer.org".into(),
            agent.clone(),
        );
        let slot = SessionSlot::new();
        let tools = IcTools::new(
            agent,
            identities.clone(),
            skills::SkillsCatalog::new(),
            SessionSource::Singleton(slot.clone()),
        );
        let login = crate::login::LoginDriver::new(identities, slot, /* auto_open */ false);
        LocalServer::new(tools, login, /* auto_open */ false)
    }

    // The wrapper's own router carries EXACTLY the two login tools — the rest
    // of the surface comes from IcTools by forwarding, never by duplication —
    // and both declare honest annotations (auth_status is the read-only one).
    #[test]
    fn the_wrapper_router_carries_exactly_the_login_tools() {
        let tools = LocalServer::tool_router().list_all();
        let mut names: Vec<&str> = tools.iter().map(|t| &*t.name).collect();
        names.sort_unstable();
        assert_eq!(names, ["auth_status", "authenticate"]);
        let ann = |n: &str| {
            tools
                .iter()
                .find(|t| &*t.name == n)
                .and_then(|t| t.annotations.clone())
                .unwrap_or_else(|| panic!("{n} must carry annotations"))
        };
        assert_eq!(ann("authenticate").read_only_hint, Some(false));
        assert_eq!(ann("authenticate").destructive_hint, Some(false));
        assert_eq!(ann("auth_status").read_only_hint, Some(true));
        let auth = tools.iter().find(|t| &*t.name == "authenticate").unwrap();
        let schema = serde_json::to_value(&auth.input_schema).unwrap();
        assert!(
            schema["properties"]["refresh"].is_object(),
            "authenticate must declare its refresh flag: {schema}"
        );
    }

    // Expiry phrasing across the II consent screen's range (minutes → a month):
    // never a raw five-digit minute counter.
    #[test]
    fn expiry_is_reported_in_human_units() {
        assert_eq!(super::human_minutes(45), "45 min");
        assert_eq!(super::human_minutes(180), "3 hours");
        assert_eq!(super::human_minutes(30 * 24 * 60), "30 days");
    }

    // A REAL MCP round-trip over an in-process duplex pipe (the same
    // byte-stream shape stdio serves): initialize; tools/list is the merged
    // surface (all 26 core tools + the 2 login tools); tools/call dispatches
    // login tools to the wrapper and everything else to IcTools; the login
    // lifecycle (signed out → link → pending) runs through the MCP layer —
    // all with no network and no browser.
    #[tokio::test]
    async fn a_real_mcp_client_sees_the_merged_surface_and_the_login_flow() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = test_server().serve(server_io);
        let client = ().serve(client_io);
        let (server, client) = tokio::join!(server, client);
        let server = server.expect("server up");
        let client = client.expect("client up");

        // The server identifies as imcp2-local and teaches the login flow in
        // its instructions, on top of core's own text.
        let info = client.peer_info().expect("initialized");
        assert_eq!(info.server_info.name, "imcp2-local");
        let instructions = info.instructions.as_deref().unwrap_or_default();
        assert!(
            instructions.contains("SIGNING IN"),
            "login guidance must be taught"
        );
        assert!(
            instructions.contains("textual Candid"),
            "core guidance must survive the merge"
        );

        let tools = client.list_all_tools().await.expect("tools/list");
        assert_eq!(
            tools.len(),
            28,
            "26 core tools + authenticate + auth_status"
        );
        for expected in [
            "get_canister_candid",
            "canister_query",
            "authenticate",
            "auth_status",
        ] {
            assert!(
                tools.iter().any(|t| &*t.name == expected),
                "missing {expected}"
            );
        }

        let call = |name: &'static str, args: Option<serde_json::Value>| {
            let client = &client;
            async move {
                let mut params = rmcp::model::CallToolRequestParams::new(name);
                params.arguments = args.map(|v| v.as_object().expect("object args").clone());
                let result = client.call_tool(params).await.expect("tools/call");
                let text = result
                    .content
                    .iter()
                    .flat_map(|c| c.as_text().map(|t| t.text.clone()))
                    .collect::<Vec<_>>()
                    .join("\n");
                (result.is_error.unwrap_or(false), text)
            }
        };

        // Login lifecycle through the MCP layer.
        let (is_error, text) = call("auth_status", None).await;
        assert!(!is_error, "{text}");
        assert!(text.contains("Not signed in"), "{text}");

        let (is_error, text) = call("authenticate", Some(serde_json::json!({}))).await;
        assert!(!is_error, "{text}");
        assert!(text.contains("https://id.ai/mcp#callback="), "{text}");

        let (is_error, text) = call("auth_status", None).await;
        assert!(!is_error, "{text}");
        assert!(text.contains("sign-in is pending"), "{text}");

        // Forwarding: a core tool answers through the wrapper (its own error
        // path, so no network is touched).
        let (is_error, text) = call(
            "get_canister_candid",
            Some(serde_json::json!({ "canister_id": "not-a-canister" })),
        )
        .await;
        assert!(is_error, "an invalid canister id is a tool error");
        assert!(text.contains("invalid canister id"), "{text}");

        client.cancel().await.expect("client shutdown");
        server.cancel().await.expect("server shutdown");
    }
}
