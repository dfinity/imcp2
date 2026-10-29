//! imcp2-deploy — the `icp_deploy_bundle` MCP tool: deploy an icp project
//! bundle to the Internet Computer as the user, through the icp CLI's own
//! project library (`icp-project`, the code behind `icp deploy`).
//!
//! The tool takes a bundle (the `.tar.gz` that `icp project bundle` writes),
//! the name of an environment the bundle declares, and optionally the canister
//! ids an earlier deploy produced; it answers with the deploy's status and the
//! resulting canister-id mapping. Canisters the mapping does not name are
//! created (funded from the user's cycles-ledger balance), the rest are
//! upgraded in place; every phase of `icp deploy` runs — including the sync
//! steps that upload a frontend canister's assets.
//!
//! Calls are signed as the connection's **management identity** (see
//! `imcp2_core::identities`): the user's default Internet Identity account at
//! the server's own origin, the same stable principal the canister lifecycle
//! tools act as, so a canister created here stays manageable there.
//!
//! This crate is composed into the local server only. It depends on
//! `icp-project` straight from the icp-cli repository, which crates.io does
//! not allow, so it cannot be part of the published `imcp2-core`/`imcp2`
//! crates (see `Cargo.toml`).

use std::{collections::BTreeMap, sync::Arc};

use base64::Engine;
use camino::Utf8PathBuf;
use candid::Principal;
use ic_agent::Identity;
use imcp2_core::{identities::Identities, SessionResolver};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    schemars,
    service::RequestContext,
    tool, tool_router, ErrorData as McpError, RoleServer,
};
use serde::{Deserialize, Serialize};

mod calls;
mod deploy;
mod host;

pub use deploy::{deploy_bundle, BundleSource, DeployOutcome, DeployRequest, RequestError, Status};

/// The icp CLI's default funding for a canister it creates (`icp deploy
/// --cycles`): 2 trillion cycles.
pub const DEFAULT_CYCLES: u64 = 2_000_000_000_000;

/// The skill that teaches an agent the deploy loop around this tool — bundle
/// the project, call `icp_deploy_bundle` with the environment's canister-id
/// mapping, write the returned mapping back — served as the MCP resource
/// `skill://deploy-with-mcp` by the server that mounts the tool, next to
/// core's bundled IC skills. Compiled in, like those: what a client reads is
/// what was reviewed at build time.
pub const DEPLOY_SKILL_NAME: &str = "deploy-with-mcp";
/// Its title, for the resource listing.
pub const DEPLOY_SKILL_TITLE: &str = "Deploy with this MCP server";
/// The document itself (frontmatter + body), in the registry's SKILL.md shape.
pub const DEPLOY_SKILL_MD: &str = include_str!("../static/skills/deploy-with-mcp.md");

/// The skill document behind `skill://<path>`, when `path` names this crate's
/// skill — matched like core's bundled skills (trimmed, ASCII
/// case-insensitive), so the two lookups compose into one `skill://` space.
pub fn skill_document(path: &str) -> Option<&'static str> {
    path.trim().eq_ignore_ascii_case(DEPLOY_SKILL_NAME).then_some(DEPLOY_SKILL_MD)
}

/// Arguments of `icp_deploy_bundle`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeployBundleArgs {
    /// Absolute path, on this machine, of the bundle archive — the `.tar.gz`
    /// that `icp project bundle --output <file>` writes. Either this or
    /// `bundle_base64`, not both.
    #[serde(default)]
    pub bundle_path: Option<String>,
    /// The bundle archive itself, base64-encoded. Either this or
    /// `bundle_path`, not both.
    #[serde(default)]
    pub bundle_base64: Option<String>,
    /// The environment to deploy, by name, among those the bundle's manifest
    /// declares — `ic` for a bundle built with the default settings. It must
    /// target a connected network (mainnet or another reachable network), not
    /// a locally launched one.
    pub environment: String,
    /// Canister ids to start from: canister name → canister id, the contents of
    /// the `<environment>.ids.json` file the icp CLI keeps (or the
    /// `canister_ids` a previous call of this tool returned). A canister named
    /// here is upgraded in place; one that is not is created. Omit it on the
    /// first deploy of a project.
    #[serde(default)]
    pub canister_ids: Option<BTreeMap<String, String>>,
    /// Install mode: "auto" (default — install on an empty canister, upgrade
    /// otherwise), "install", "reinstall" (wipes the canister's state) or
    /// "upgrade".
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Cycles to fund each canister this deploy creates, taken from the user's
    /// cycles-ledger balance (see icp_cycles_balance). Default 2 trillion.
    #[serde(default)]
    pub cycles: Option<u64>,
    /// Subnet to create canisters on. Default: picked by the network.
    #[serde(default)]
    pub subnet: Option<String>,
    /// Fail instead of creating any canister that does not exist yet.
    #[serde(default)]
    pub no_create: bool,
    /// Skip the Candid interface compatibility check that an upgrade otherwise
    /// runs, and fails on, when the new interface breaks the old one.
    #[serde(default)]
    pub skip_candid_check: bool,
}

fn default_mode() -> String {
    "auto".into()
}

/// A canister created by the deploy.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CreatedCanister {
    pub name: String,
    pub canister_id: String,
}

/// Structured result of `icp_deploy_bundle`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DeployBundleOutput {
    /// `deployed`, `failed` (see `error`; `created` and `canister_ids` hold
    /// what landed before the failure), or `nothing_to_deploy` (the environment
    /// lists no canisters).
    pub status: String,
    /// The environment deployed.
    pub environment: String,
    /// The network that environment targets.
    pub network: String,
    /// The canisters the deploy targeted, in manifest order.
    pub canisters: Vec<String>,
    /// Canisters this deploy created, in creation order.
    pub created: Vec<CreatedCanister>,
    /// The resulting mapping, canister name → canister id: the ids passed in
    /// plus the ids created. Pass it back as `canister_ids` to upgrade these
    /// canisters next time.
    pub canister_ids: BTreeMap<String, String>,
    /// Why the deploy failed, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The deploy's phases and per-canister steps with their outcomes.
    pub log: Vec<String>,
}

impl DeployBundleOutput {
    fn from_outcome(outcome: &DeployOutcome) -> Self {
        Self {
            status: outcome.status.as_str().into(),
            environment: outcome.environment.clone(),
            network: outcome.network.clone(),
            canisters: outcome.canisters.clone(),
            created: outcome
                .created
                .iter()
                .map(|(name, id)| CreatedCanister { name: name.clone(), canister_id: id.to_text() })
                .collect(),
            canister_ids: outcome
                .canister_ids
                .iter()
                .map(|(n, id)| (n.clone(), id.to_text()))
                .collect(),
            error: outcome.error.clone(),
            log: outcome.log.clone(),
        }
    }

    /// The human-readable rendering: one summary line, the mapping, the log.
    fn human(&self) -> String {
        let mut text = match self.status.as_str() {
            "deployed" => format!(
                "Deployed environment '{}' to network '{}': {} canister(s), {} created.",
                self.environment,
                self.network,
                self.canisters.len(),
                self.created.len()
            ),
            "nothing_to_deploy" => format!(
                "Environment '{}' declares no canisters, so there was nothing to deploy.",
                self.environment
            ),
            _ => format!(
                "Deploying environment '{}' to network '{}' FAILED: {}",
                self.environment,
                self.network,
                self.error.as_deref().unwrap_or("unknown error")
            ),
        };
        if !self.canister_ids.is_empty() {
            text.push_str("\n\nCanister ids (pass these back as `canister_ids` to upgrade):");
            for (name, id) in &self.canister_ids {
                text.push_str(&format!("\n- {name}: {id}"));
            }
        }
        if !self.log.is_empty() {
            text.push_str("\n\nLog:");
            for line in &self.log {
                text.push('\n');
                text.push_str(line);
            }
        }
        text
    }
}

/// Turn the tool's arguments into a request, rejecting what cannot be deployed
/// before anything is read or written.
pub fn request_from_args(args: DeployBundleArgs) -> Result<DeployRequest, String> {
    let bundle = match (args.bundle_path, args.bundle_base64) {
        (Some(_), Some(_)) => {
            return Err("pass either bundle_path or bundle_base64, not both".into())
        }
        (None, None) => return Err("pass the bundle as bundle_path or bundle_base64".into()),
        (Some(path), None) => BundleSource::Path(Utf8PathBuf::from(path)),
        (None, Some(b64)) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| format!("bundle_base64 is not valid base64: {e}"))?;
            BundleSource::Bytes(bytes)
        }
    };
    let environment = args.environment.trim().to_string();
    if environment.is_empty() {
        return Err("environment must name an environment of the bundle, e.g. \"ic\"".into());
    }
    let mode = args.mode.trim().to_ascii_lowercase();
    if !matches!(mode.as_str(), "auto" | "install" | "reinstall" | "upgrade") {
        return Err(format!(
            "mode must be \"auto\", \"install\", \"reinstall\" or \"upgrade\", got \"{}\"",
            args.mode
        ));
    }
    let mut canister_ids = BTreeMap::new();
    for (name, id) in args.canister_ids.unwrap_or_default() {
        let principal = Principal::from_text(id.trim())
            .map_err(|e| format!("canister_ids[\"{name}\"] is not a canister id: {e}"))?;
        canister_ids.insert(name, principal);
    }
    let subnet = match args.subnet {
        Some(s) => Some(
            Principal::from_text(s.trim())
                .map_err(|e| format!("subnet is not a principal: {e}"))?,
        ),
        None => None,
    };
    Ok(DeployRequest {
        bundle,
        environment,
        canister_ids,
        mode,
        cycles: u128::from(args.cycles.unwrap_or(DEFAULT_CYCLES)),
        subnet,
        no_create: args.no_create,
        skip_candid_check: args.skip_candid_check,
    })
}

/// The deploy tool group: one tool, `icp_deploy_bundle`, served alongside the
/// core surface by the binary that composes it.
#[derive(Clone)]
pub struct IcDeployTools {
    identities: Identities,
    /// The authentication seam (see [`SessionResolver`]): asks the embedding
    /// binary which already-validated session this call acts as.
    session: SessionResolver,
}

#[tool_router(vis = "pub")]
impl IcDeployTools {
    pub fn new(identities: Identities, session: SessionResolver) -> Self {
        Self { identities, session }
    }

    #[tool(
        description = "Deploy an icp project bundle (the .tar.gz that `icp project bundle` writes) to the Internet Computer as the user, running every phase of `icp deploy`: create the canisters the bundle names that do not exist yet (funded from the user's cycles balance), wire their ids into each other, apply settings, install or upgrade the code, and run the sync steps (a frontend's asset upload). Pass the bundle by absolute path or base64, the environment name it was built for (usually \"ic\"), and, to upgrade rather than create, the canister_ids a previous deploy returned. Returns the status, the resulting canister-id mapping, and a log of each phase; on failure the mapping still holds every canister that was created.",
        annotations(title = "Deploy a project bundle", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<DeployBundleOutput>(),
    )]
    async fn icp_deploy_bundle(
        &self,
        Parameters(args): Parameters<DeployBundleArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let request = match request_from_args(args) {
            Ok(r) => r,
            Err(e) => return Ok(err(e)),
        };
        let Some(sid) = (self.session)(&ctx) else {
            return Ok(err("deploying a bundle needs an authenticated session".into()));
        };
        if let Err(e) = self.identities.require_write(&sid).await {
            return Ok(err(e));
        }
        let identity: Arc<dyn Identity> = match self.identities.management_identity(&sid).await {
            Ok(id) => Arc::new(id),
            Err(e) => return Ok(err(e)),
        };
        match deploy_bundle(identity, request).await {
            Err(RequestError(e)) => Ok(err(e)),
            Ok(outcome) => {
                let output = DeployBundleOutput::from_outcome(&outcome);
                let text = output.human();
                Ok(match outcome.status {
                    Status::Failed => err_structured(text, &output),
                    Status::Deployed | Status::NothingToDeploy => ok_structured(text, &output),
                })
            }
        }
    }
}

/// Same contract as the core surface's result builder: the human-readable
/// text plus `structuredContent` conforming to the declared `outputSchema`.
fn ok_structured<T: Serialize>(text: String, value: &T) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = structured(value);
    result
}

/// An error result that still carries the structured output: a failed deploy
/// has created canisters the caller must learn about, and `isError` alone
/// would hide them from a client that reads structured content.
fn err_structured<T: Serialize>(text: String, value: &T) -> CallToolResult {
    let mut result = CallToolResult::error(vec![ContentBlock::text(text)]);
    result.structured_content = structured(value);
    result
}

fn structured<T: Serialize>(value: &T) -> Option<serde_json::Value> {
    match serde_json::to_value(value) {
        Ok(v @ serde_json::Value::Object(_)) => Some(v),
        _ => None,
    }
}

fn err(text: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

/// Same panic-at-router-construction posture as the core surface: a
/// non-object output schema is a programming error.
fn schema_for_output<T: schemars::JsonSchema + std::any::Any>() -> Arc<rmcp::model::JsonObject> {
    rmcp::handler::server::tool::schema_for_output::<T>().unwrap_or_else(|e| {
        panic!("output schema for `{}` must be object-rooted: {e}", std::any::type_name::<T>())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(json: serde_json::Value) -> DeployBundleArgs {
        serde_json::from_value(json).expect("valid args")
    }

    // The skill is in the registry's SKILL.md shape (frontmatter naming it as
    // the URI does, a description for the agent's trigger decision), teaches
    // the three steps around the tool by name, and resolves under the same
    // lookup rules as core's bundled skills.
    #[test]
    fn the_deploy_skill_is_a_well_formed_skill_document() {
        let md = DEPLOY_SKILL_MD;
        assert!(md.starts_with("---\n"), "frontmatter first");
        let (front, body) = md[4..].split_once("\n---\n").expect("closed frontmatter");
        assert!(front.lines().any(|l| l == format!("name: {DEPLOY_SKILL_NAME}")), "{front}");
        assert!(front.lines().any(|l| l.starts_with("description: ")), "{front}");
        assert!(front.contains(&format!("title: {DEPLOY_SKILL_TITLE}")), "{front}");
        for needle in [
            "icp project bundle",
            "icp_deploy_bundle",
            "canister_ids",
            ".icp/data/mappings/<environment>.ids.json",
            "bundle_path",
            "bundle_base64",
            "authenticate",
            "icp_cycles_balance",
        ] {
            assert!(body.contains(needle), "the skill must mention `{needle}`");
        }
        // The steps are named in the order an agent performs them.
        let step = |n: &str| body.find(n).unwrap_or_else(|| panic!("missing heading {n}"));
        assert!(
            step("## Step 1: Bundle") < step("## Step 2: Request")
                && step("## Step 2: Request") < step("## Step 3: Update"),
            "steps out of order"
        );

        assert_eq!(skill_document("deploy-with-mcp"), Some(md));
        assert_eq!(skill_document(" Deploy-With-MCP "), Some(md));
        assert_eq!(skill_document("deploy-with-mcp/references/x.md"), None);
        assert_eq!(skill_document("icp-cli"), None);
    }

    // The group carries exactly the one tool, with honest annotations (it
    // creates canisters and can wipe state) and an object-rooted outputSchema
    // like every tool on the core surface.
    #[test]
    fn the_router_carries_the_one_deploy_tool() {
        let tools = IcDeployTools::tool_router().list_all();
        assert_eq!(tools.len(), 1);
        let tool = &tools[0];
        assert_eq!(&*tool.name, "icp_deploy_bundle");
        let ann = tool.annotations.clone().expect("annotations");
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        let schema = serde_json::to_value(&tool.input_schema).unwrap();
        for field in ["bundle_path", "bundle_base64", "environment", "canister_ids", "mode"] {
            assert!(schema["properties"][field].is_object(), "missing {field}: {schema}");
        }
        assert_eq!(schema["required"], serde_json::json!(["environment"]));
        let output =
            serde_json::to_value(tool.output_schema.as_ref().expect("outputSchema")).unwrap();
        assert_eq!(output["type"], "object");
        for field in ["status", "canister_ids", "created", "log"] {
            assert!(output["properties"][field].is_object(), "missing {field}: {output}");
        }
    }

    #[test]
    fn exactly_one_bundle_source_is_accepted() {
        let both = args(serde_json::json!({
            "bundle_path": "/tmp/b.tar.gz", "bundle_base64": "AAAA", "environment": "ic"
        }));
        assert!(request_from_args(both).unwrap_err().contains("not both"));
        let neither = args(serde_json::json!({ "environment": "ic" }));
        assert!(request_from_args(neither).unwrap_err().contains("bundle_path or bundle_base64"));
        let bad = args(serde_json::json!({ "bundle_base64": "***", "environment": "ic" }));
        assert!(request_from_args(bad).unwrap_err().contains("base64"));
    }

    #[test]
    fn the_request_takes_the_defaults_and_parses_the_ids() {
        let request = request_from_args(args(serde_json::json!({
            "bundle_path": "/tmp/b.tar.gz",
            "environment": " ic ",
            "canister_ids": { "backend": "aaaaa-aa" },
            "mode": "Upgrade"
        })))
        .unwrap();
        assert_eq!(request.environment, "ic");
        assert_eq!(request.mode, "upgrade");
        assert_eq!(request.cycles, u128::from(DEFAULT_CYCLES));
        assert_eq!(request.canister_ids["backend"], Principal::management_canister());
        assert!(request.subnet.is_none());
        assert!(!request.no_create && !request.skip_candid_check);
        assert!(matches!(request.bundle, BundleSource::Path(ref p) if p == "/tmp/b.tar.gz"));
    }

    #[test]
    fn bad_modes_ids_and_subnets_are_named_in_the_rejection() {
        let e = request_from_args(args(serde_json::json!({
            "bundle_path": "/b", "environment": "ic", "mode": "yolo"
        })))
        .unwrap_err();
        assert!(e.contains("mode") && e.contains("yolo"), "{e}");
        let e = request_from_args(args(serde_json::json!({
            "bundle_path": "/b", "environment": "ic", "canister_ids": { "backend": "nope" }
        })))
        .unwrap_err();
        assert!(e.contains("canister_ids[\"backend\"]"), "{e}");
        let e = request_from_args(args(serde_json::json!({
            "bundle_path": "/b", "environment": "ic", "subnet": "nope"
        })))
        .unwrap_err();
        assert!(e.contains("subnet"), "{e}");
        let e =
            request_from_args(args(serde_json::json!({ "bundle_path": "/b", "environment": " " })))
                .unwrap_err();
        assert!(e.contains("environment"), "{e}");
    }

    // The text a client without structured-output support reads carries the
    // same facts: the status, the mapping to pass back, and the log.
    #[test]
    fn the_human_text_carries_the_mapping_and_the_log() {
        let outcome = DeployOutcome {
            status: Status::Failed,
            environment: "ic".into(),
            network: "ic".into(),
            canisters: vec!["backend".into(), "frontend".into()],
            created: vec![("backend".into(), Principal::management_canister())],
            canister_ids: [("backend".to_string(), Principal::management_canister())].into(),
            error: Some("install failed".into()),
            log: vec!["Creating canisters: ok".into()],
        };
        let output = DeployBundleOutput::from_outcome(&outcome);
        assert_eq!(output.status, "failed");
        assert_eq!(output.created[0].canister_id, "aaaaa-aa");
        let text = output.human();
        assert!(text.contains("FAILED: install failed"), "{text}");
        assert!(text.contains("- backend: aaaaa-aa"), "{text}");
        assert!(text.contains("Creating canisters: ok"), "{text}");
        let result = err_structured(text, &output);
        assert_eq!(result.is_error, Some(true));
        assert_eq!(result.structured_content.unwrap()["canister_ids"]["backend"], "aaaaa-aa");
    }
}
