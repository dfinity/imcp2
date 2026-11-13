//! The handler a server mounts to serve the deploy tools next to its own: an
//! inner [`ServerHandler`] (the core surface, or a wrapper of it) plus
//! [`IcDeployTools`], answering `tools/list` with the merged list, dispatching
//! `tools/call` to the deploy router first and the inner handler otherwise,
//! listing and reading the deploy skill next to the inner resources, and
//! appending to the inner instructions the paragraph that says deploying is
//! possible here, and how.
//!
//! Both servers compose this: the local one around its login tools, the
//! hosted one around the core surface. What differs between them — how the
//! bundle reaches the server, how many deploys run at once — the deploy tools
//! know themselves, so the paragraph reads from them.

use rmcp::{
    handler::server::tool::ToolCallContext,
    model::{
        CallToolRequestParams, CallToolResult, ListResourcesResult, ListToolsResult,
        PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult, Resource,
        ResourceContents, ServerInfo, Tool,
    },
    service::RequestContext,
    ErrorData as McpError, RoleServer, ServerHandler,
};

use crate::{skill_document, IcDeployTools, DEPLOY_SKILL_NAME, DEPLOY_SKILL_TITLE};

/// An inner handler with the deploy tools served beside it.
pub struct WithDeploy<H> {
    inner: H,
    deploy: IcDeployTools,
}

impl<H: ServerHandler> WithDeploy<H> {
    pub fn new(inner: H, deploy: IcDeployTools) -> Self {
        Self { inner, deploy }
    }

    pub fn inner(&self) -> &H {
        &self.inner
    }

    pub fn deploy(&self) -> &IcDeployTools {
        &self.deploy
    }

    /// The deploy tool of that name, when this server lists one (see
    /// [`IcDeployTools::tools`]).
    fn deploy_tool(&self, name: &str) -> Option<Tool> {
        self.deploy.tools().into_iter().find(|t| &*t.name == name)
    }

    /// The paragraph appended to the inner instructions.
    fn deploying(&self) -> String {
        let concurrency = match self.deploy.concurrency() {
            1 => "runs one deploy at a time".to_string(),
            n => format!("runs at most {n} deploys at a time, one per session"),
        };
        let bundle = if self.deploy.has_uploads() {
            "The bundle reaches this server through `icp_deploy_upload`: it returns a one-time \
             ticket and the curl command that uploads the archive, and the upload id that \
             command prints is what `icp_deploy_bundle` takes as `bundle_upload`."
        } else {
            "Pass the bundle as `bundle_path`, an absolute path on this machine."
        };
        format!(
            "DEPLOYING. This server adds `icp_deploy_bundle`, the one exception to the rule above \
             that no tool deploys: it deploys an icp project bundle (`icp project bundle --output \
             <file>`, built in the user's environment) to the environment it names, creating the \
             canisters that do not exist yet from the user's cycles balance (`icp_cycles_balance` \
             reports it) and upgrading those passed in `canister_ids`. It deploys as the user's \
             default Internet Identity account at https://cli.id.ai — the principal `icp identity \
             link web` links the CLI to, and so the CLI's own only when the CLI's selected \
             identity is that link; a local key or another account is a different principal, \
             which `icp identity principal` shows — not as the management identity the canister \
             tools act as. It needs an \"Actions & questions\" session, {concurrency}, lasts as \
             long as the deploy (send a progressToken to see each phase as it completes; \
             cancelling the call interrupts the deploy at its next step), and returns the \
             canister-id mapping to pass back next time. {bundle} The `skill://{DEPLOY_SKILL_NAME}` \
             resource walks through the loop: bundle, deploy, write the mapping back into the \
             project; `icp_deploy_guide` returns the same text."
        )
    }
}

impl<H: ServerHandler> ServerHandler for WithDeploy<H> {
    fn get_info(&self) -> ServerInfo {
        let mut info = self.inner.get_info();
        // A running deploy reports each phase mid-call: as progress when the
        // request carried a token, else as a logging message, which a client
        // only expects from a server that declares it.
        info.capabilities.logging = Some(Default::default());
        let inner = info.instructions.take().unwrap_or_default();
        info.instructions = Some(format!("{inner}\n\n{}", self.deploying()));
        info
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self.inner.list_tools(request, context).await?;
        result.tools.extend(self.deploy.tools());
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if self.deploy_tool(&request.name).is_some() {
            let tcc = ToolCallContext::new(&self.deploy, request, context);
            IcDeployTools::tool_router().call(tcc).await
        } else {
            self.inner.call_tool(request, context).await
        }
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.deploy_tool(name).or_else(|| self.inner.get_tool(name))
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let first_page = request.as_ref().and_then(|r| r.cursor.as_ref()).is_none();
        let mut result = self.inner.list_resources(request, context).await?;
        // The one skill the deploy tools add, next to the inner skills. Core
        // lists everything on one page today; should it ever page, the skill
        // belongs on the first page alone, not on every one.
        if first_page {
            result.resources.push(Resource::new(
                format!("skill://{DEPLOY_SKILL_NAME}"),
                format!("IC skill: {DEPLOY_SKILL_TITLE}"),
            ));
        }
        Ok(result)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        if let Some(md) = request.uri.strip_prefix("skill://").and_then(skill_document) {
            return Ok(ReadResourceResult::new(vec![ResourceContents::text(md, request.uri)]));
        }
        self.inner.read_resource(request, context).await
    }
}
