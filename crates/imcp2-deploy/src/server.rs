//! The handler a server mounts to serve the deploy tools next to its own: an
//! inner [`ServerHandler`] (the core surface, or a wrapper of it) plus
//! [`IcDeployTools`], answering `tools/list` with the merged list, dispatching
//! `tools/call` to the deploy router first and the inner handler otherwise,
//! listing and reading the deploy skill next to the inner resources, and
//! putting, where the inner instructions say that nothing here deploys, the
//! paragraph that says how deploying works.
//!
//! Both servers compose this: the local one around its login tools, the
//! hosted one around the core surface. What differs between them in what an
//! agent does — how the bundle reaches the server — the deploy tools know
//! themselves, so the paragraph reads from them.

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

    /// The paragraph on deploying: short, since every client reads it, and
    /// saying nothing of whose principal signs or of how many deploys run at
    /// once, which no agent acts on (a server that is full says so when asked).
    fn deploying(&self) -> String {
        let bundle = if self.deploy.has_uploads() {
            "Upload the bundle first: `icp_deploy_upload` returns the curl command, and the \
             upload id it prints goes in `bundle_upload`."
        } else {
            "Pass the bundle's absolute path as `bundle_path`."
        };
        format!(
            "DEPLOYING. `icp_deploy_bundle` deploys an icp project bundle (`icp project bundle \
             --output <file>`, built in the user's environment) to the Internet Computer, \
             creating new canisters from the user's cycles balance (`icp_cycles_balance` reports \
             it) and upgrading those named in `canister_ids`. {bundle} It needs an \"Actions & \
             questions\" session and lasts as long as the deploy; send a progressToken to see \
             each phase. It returns `canister_ids`, the app's development metadata: save it \
             unchanged and pass it back on the next deploy. `icp_deploy_guide` returns the full \
             steps."
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
        // The inner surface closes by saying it deploys nothing; here that
        // paragraph gives way to the one on how deploying works.
        let inner = info.instructions.take().unwrap_or_default();
        let inner = inner.replace(imcp2_core::DEPLOYS_ELSEWHERE, "");
        info.instructions = Some(format!("{}\n\n{}", inner.trim_end(), self.deploying()));
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
