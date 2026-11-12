//! imcp2-deploy — the `icp_deploy_bundle` MCP tool: deploy an icp project
//! bundle to the Internet Computer as the user, through the icp CLI's own
//! project library (`icp-project`, the code behind `icp deploy`). Next to it,
//! `icp_cycles_balance`: the balance those deploys create canisters from.
//!
//! The tool takes a bundle (the `.tar.gz` that `icp project bundle` writes),
//! the name of an environment the bundle declares, and optionally the canister
//! ids an earlier deploy produced; it answers with the deploy's status and the
//! resulting canister-id mapping. Canisters the mapping does not name are
//! created (funded from the user's cycles-ledger balance), the rest are
//! upgraded in place; every phase of `icp deploy` runs — including the sync
//! steps that upload a frontend canister's assets.
//!
//! Calls are signed as the user's default Internet Identity account at
//! [`CLI_ORIGIN`] (`https://cli.id.ai`), the origin `icp identity link web`
//! links an `icp` identity to. When the CLI's selected identity is such a
//! link to the same account, the two deploy as the same principal: the
//! canisters are the ones `icp` lists and controls, and the cycles are the
//! same balance. The CLI can also use a local key (`icp identity new`) or a
//! link to another account, and those are other principals sharing neither;
//! `icp_cycles_balance` names the principal used here, for the user to
//! compare with `icp identity principal`. This is deliberately NOT the
//! management identity the canister lifecycle tools act as (the default
//! account at the server's own origin): a canister a deploy creates is
//! controlled by the principal here, and reaching it through the lifecycle
//! tools means adding their principal as a controller first.
//!
//! One deploy runs at a time per session: two at once for the same project,
//! each with the mapping as it was before either, would create two sets of
//! canisters. The second call is refused, not queued, since its mapping would
//! be stale by the time it ran. A server also caps how many deploys run at
//! once across every session ([`IcDeployTools::concurrent`]; one, unless it
//! says otherwise), and refuses rather than queues past the cap. A deploy's
//! working directory is kept under the directory the embedder names until the
//! outcome is assembled, so a call cut off mid-deploy leaves the ids it
//! created on disk.
//!
//! A deploy lasts as long as it lasts: the call reports each phase to the
//! client as it completes and is interrupted by the client cancelling the
//! request or, on the hosted server, going away ([`ClientGone`]). Where the
//! agent cannot hand the server a file — the hosted server — the bundle
//! arrives through an upload ticket ([`Uploads`], `icp_deploy_upload`).
//!
//! The crate is composed into the local server, and into the hosted one
//! behind its `deploy` feature ([`WithDeploy`] is the handler both mount).
//! It depends on `icp-project` straight from the icp-cli repository, which
//! crates.io does not allow, so the published `imcp2` crate cannot carry the
//! feature until the icp CLI's crates are published (see `Cargo.toml`).
//!
//! The bundle is untrusted input, and the rule it is held to is the
//! library's own: `icp_project::untrusted`, the one `icp --untrusted`
//! applies (dfinity/icp-cli#873, on #868 for what `icp project bundle`
//! writes; issue #865). This crate pins icp-cli's main at their merge, composes
//! the rule as the CLI does, and adds the bounds on the archive itself and the
//! checks on the bundle's shape (see [`host`]).

use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
};

use base64::Engine;
use camino::Utf8PathBuf;
use candid::Principal;
use ic_agent::{identity::DelegatedIdentity, Identity};
use imcp2_core::{cycles_balance_of, identities::Identities, CyclesBalance, SessionResolver};
#[allow(deprecated)]
use rmcp::model::{LoggingLevel, LoggingMessageNotificationParam};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, ProgressNotificationParam, ProgressToken},
    schemars,
    service::{Peer, RequestContext},
    tool, tool_router, ErrorData as McpError, RoleServer,
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

mod calls;
mod deploy;
mod host;
mod identity;
mod server;
mod uploads;

pub use deploy::{
    deploy_bundle, BundleSource, DeployOutcome, DeployRequest, RequestError, Status, Watch,
};
use identity::RefreshingIdentity;
pub use server::WithDeploy;
pub use uploads::{
    ReceiveError, Received, Uploads, DEFAULT_MAX_UPLOAD_BYTES, TICKET_HEADER, TICKET_TTL,
    UPLOAD_TTL,
};

/// The name of the upload-ticket tool, listed only by a server with an
/// upload store (see [`IcDeployTools::with_uploads`]).
pub const UPLOAD_TOOL: &str = "icp_deploy_upload";

/// A transport's word that the client of a request has gone: a token it
/// cancels when the connection carrying the request's response is dropped,
/// left in the HTTP request's extensions (which rmcp hands the tool as the
/// request parts). A deploy stops when it fires, since nobody would read
/// the answer.
#[derive(Clone, Debug)]
pub struct ClientGone(pub CancellationToken);

/// The icp CLI's default funding for a canister it creates (`icp deploy
/// --cycles`): 2 trillion cycles.
pub const DEFAULT_CYCLES: u64 = 2_000_000_000_000;

/// The skill that teaches an agent the deploy loop around this tool — bundle
/// the project, call `icp_deploy_bundle` with the environment's canister-id
/// mapping, write the returned mapping back — served as the MCP resource
/// `skill://deploy-with-mcp` by the server that mounts the tool, next to
/// core's bundled IC skills, and returned by `icp_deploy_guide` for a client
/// that does not read resources (as core serves its Candid guide both ways).
/// Compiled in, like those: what a client reads is what was reviewed at
/// build time.
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
    /// The upload id the curl command from `icp_deploy_upload` printed: the
    /// archive as this server received it. Only on a server that lists
    /// `icp_deploy_upload`; exactly one of the three bundle arguments.
    #[serde(default)]
    pub bundle_upload: Option<String>,
    /// The environment to deploy, by name, among those the bundle's manifest
    /// declares — `ic` for a bundle built with the default settings. It must
    /// be on the `ic` network: this tool deploys to the Internet Computer only.
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
    /// what landed before the failure), `interrupted` (the call was cancelled
    /// or the client went away; likewise), or `nothing_to_deploy` (the
    /// environment lists no canisters).
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
            "interrupted" => format!(
                "Deploying environment '{}' to network '{}' was INTERRUPTED: {}",
                self.environment,
                self.network,
                self.error.as_deref().unwrap_or("stopped before it finished")
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

/// The longest `bundle_base64` that can decode to [`host::MAX_BUNDLE_BYTES`]
/// bytes: four characters per three bytes, the last group padded.
const MAX_BUNDLE_BASE64_CHARS: usize = host::MAX_BUNDLE_BYTES.div_ceil(3) * 4;

/// Turn the tool's arguments into a request, rejecting what cannot be deployed
/// before anything is read or written.
pub fn request_from_args(mut args: DeployBundleArgs) -> Result<DeployRequest, String> {
    let given =
        [args.bundle_path.is_some(), args.bundle_base64.is_some(), args.bundle_upload.is_some()]
            .iter()
            .filter(|g| **g)
            .count();
    if given > 1 {
        return Err("pass one of bundle_path, bundle_base64 or bundle_upload, not several".into());
    }
    if let Some(id) = args.bundle_upload.take() {
        let id = id.trim();
        if id.is_empty() {
            return Err("bundle_upload is empty; pass the upload id the upload printed".into());
        }
        return finish_request(args, BundleSource::Upload(id.to_string()));
    }
    let bundle = match (args.bundle_path.take(), args.bundle_base64.take()) {
        (Some(_), Some(_)) => {
            return Err("pass either bundle_path or bundle_base64, not both".into())
        }
        (None, None) => {
            return Err("pass the bundle as bundle_path, bundle_base64 or bundle_upload".into())
        }
        (Some(path), None) => {
            let path = Utf8PathBuf::from(path.trim());
            if path.as_str().is_empty() {
                return Err("bundle_path is empty; pass the absolute path of the bundle".into());
            }
            if !path.is_absolute() {
                return Err(format!(
                    "bundle_path must be an absolute path on this machine, got '{path}'"
                ));
            }
            BundleSource::Path(path)
        }
        (None, Some(b64)) => {
            let b64 = b64.trim();
            // Bound the encoded text before allocating the decoded copy:
            // base64 spends four characters per three bytes, so anything
            // longer than this encodes more than the bundle limit.
            if b64.len() > MAX_BUNDLE_BASE64_CHARS {
                return Err(format!(
                    "bundle_base64 encodes more than the {} byte bundle limit",
                    host::MAX_BUNDLE_BYTES
                ));
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| format!("bundle_base64 is not valid base64: {e}"))?;
            if bytes.len() > host::MAX_BUNDLE_BYTES {
                return Err(format!(
                    "the bundle is {} bytes, above the {} byte limit",
                    bytes.len(),
                    host::MAX_BUNDLE_BYTES
                ));
            }
            BundleSource::Bytes(bytes)
        }
    };
    finish_request(args, bundle)
}

/// The rest of [`request_from_args`], once the bundle source is settled.
fn finish_request(args: DeployBundleArgs, bundle: BundleSource) -> Result<DeployRequest, String> {
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
            .map_err(|e| format!("canister_ids[\"{name}\"] is not a valid principal: {e}"))?;
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
        workdir: None,
    })
}

/// The deploy tool group, served alongside the core surface by the binary
/// that composes it: `icp_deploy_bundle`; `icp_cycles_balance` — the check a
/// deploy that will create canisters starts with; and `icp_deploy_guide`,
/// the skill around them as a tool result. The core surface
/// has a tool of that name too, in its protocol/meta half, which the local
/// server does not serve; this one is the same logic on the surface the
/// deploy loop runs on. Should the core half be served alongside one day,
/// drop this copy rather than list the name twice.
#[derive(Clone)]
pub struct IcDeployTools {
    identities: Identities,
    /// The authentication seam (see [`SessionResolver`]): asks the embedding
    /// binary which already-validated session this call acts as.
    session: SessionResolver,
    /// The deploys running: one slot per deploy the server allows at once,
    /// and the sessions holding one.
    slots: Slots,
    /// Where each deploy's working directory is made; see
    /// [`DeployRequest::workdir`].
    deploys_dir: Option<Utf8PathBuf>,
    /// Where uploaded bundles are received, and the URL a `PUT` goes to,
    /// on a server the agent cannot hand a file to.
    uploads: Option<(Uploads, String)>,
}

/// How many deploys a server runs at once, and for whom.
#[derive(Clone)]
struct Slots {
    /// One permit per deploy the server runs at once.
    free: Arc<tokio::sync::Semaphore>,
    /// How many there are in all, for the instructions.
    total: usize,
    /// The sessions with a deploy running: one each.
    sessions: Arc<Mutex<HashSet<String>>>,
}

/// A running deploy's claim on the server: a slot, and the session's one
/// deploy. Both are released when it drops, that is, when the deploy returns.
pub struct DeployClaim {
    _permit: tokio::sync::OwnedSemaphorePermit,
    session: Option<String>,
    sessions: Arc<Mutex<HashSet<String>>>,
}

impl DeployClaim {
    /// Make the claim the session's: refused if the session already has a
    /// deploy running.
    fn for_session(&mut self, sid: &str) -> Result<(), String> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if !sessions.insert(sid.to_string()) {
            return Err("a deploy is already running for this session; wait for it to finish, \
                        write the mapping it returns into the project, and deploy again from \
                        that"
                .into());
        }
        self.session = Some(sid.to_string());
        Ok(())
    }
}

impl Drop for DeployClaim {
    fn drop(&mut self) {
        if let Some(sid) = self.session.take() {
            self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&sid);
        }
    }
}

/// The derivation origin of the identity the deploy tools act as: the one the
/// icp CLI's `icp identity link web` (with no `--app`) signs in at. Internet
/// Identity derives one principal per anchor per origin, so a delegation at
/// this origin for the user's default account is the principal that link
/// gives the CLI.
pub const CLI_ORIGIN: &str = "https://cli.id.ai";

#[tool_router(vis = "pub")]
impl IcDeployTools {
    pub fn new(identities: Identities, session: SessionResolver) -> Self {
        Self {
            identities,
            session,
            slots: Slots {
                free: Arc::new(tokio::sync::Semaphore::new(1)),
                total: 1,
                sessions: Arc::default(),
            },
            deploys_dir: None,
            uploads: None,
        }
    }

    /// Run up to `n` deploys at once across sessions (one per session either
    /// way); the default is one. Past the cap a deploy is refused, not
    /// queued. `n` is at least one.
    pub fn concurrent(mut self, n: usize) -> Self {
        let n = n.max(1);
        self.slots.free = Arc::new(tokio::sync::Semaphore::new(n));
        self.slots.total = n;
        self
    }

    /// How many deploys this server runs at once.
    pub fn concurrency(&self) -> usize {
        self.slots.total
    }

    /// Serve `icp_deploy_upload` on `uploads`, with `upload_url` the absolute
    /// URL the agent `PUT`s an archive to (the server mounts the route; see
    /// [`Uploads`]). Without this, the tool is not listed and `bundle_upload`
    /// is refused.
    pub fn with_uploads(mut self, uploads: Uploads, upload_url: String) -> Self {
        self.uploads = Some((uploads, upload_url));
        self
    }

    /// Whether this server receives uploaded bundles.
    pub fn has_uploads(&self) -> bool {
        self.uploads.is_some()
    }

    /// Make each deploy's working directory under `dir` (made now) rather
    /// than the system temporary directory, so one a cut-off deploy leaves
    /// behind is somewhere the user is told to look. The directory is
    /// canonicalized: a relative `dir` is resolved against the working
    /// directory here, not when a deploy runs, so every path a deploy works
    /// with is absolute, and one reached through a link is named as it is.
    pub fn deploys_in(mut self, dir: &std::path::Path) -> Result<Self, String> {
        let dir = std::fs::create_dir_all(dir)
            .and_then(|()| dir.canonicalize())
            .map_err(|e| format!("cannot make the deploy directory '{}': {e}", dir.display()))?;
        let dir = Utf8PathBuf::from_path_buf(dir)
            .map_err(|p| format!("the deploy directory '{}' is not UTF-8", p.display()))?;
        self.deploys_dir = Some(dir);
        Ok(self)
    }

    /// Claim a slot for a deploy, or `None` while every slot is held.
    pub fn claim(&self) -> Option<DeployClaim> {
        let permit = self.slots.free.clone().try_acquire_owned().ok()?;
        Some(DeployClaim { _permit: permit, session: None, sessions: self.slots.sessions.clone() })
    }

    /// The session's identity at [`CLI_ORIGIN`]: its default account there,
    /// derived on demand like any other per-app delegation. Good for the
    /// next few minutes; a deploy uses [`RefreshingIdentity`] instead.
    async fn cli_identity(&self, sid: &str) -> Result<DelegatedIdentity, String> {
        self.identities.delegated_identity(sid, CLI_ORIGIN, None).await
    }

    #[tool(
        description = "Deploy an icp project bundle (the .tar.gz that `icp project bundle` writes) to the Internet Computer as the user, running every phase of `icp deploy`: create the canisters the bundle names that do not exist yet (funded from the user's cycles balance), wire their ids into each other, apply settings, install or upgrade the code, and run the sync steps (a frontend's asset upload). Pass the bundle by absolute path or base64, the environment name it was built for (usually \"ic\"), and, to upgrade rather than create, the canister_ids a previous deploy returned. The call lasts as long as the deploy and reports each phase as it completes, as a progress notification (send a progressToken) and a log message; cancelling the call interrupts the deploy at its next step. Returns the status, the resulting canister-id mapping, and a log of each phase; on failure or interruption the mapping still holds every canister that was created.",
        annotations(title = "Deploy a project bundle", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<DeployBundleOutput>(),
    )]
    async fn icp_deploy_bundle(
        &self,
        Parameters(args): Parameters<DeployBundleArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // So many deploys at a time, and the refusal reads nothing: it comes
        // even before who is asking.
        let Some(mut claim) = self.claim() else {
            return Ok(err(if self.concurrency() == 1 {
                "a deploy is already running on this server; wait for it to finish, write \
                 the mapping it returns into the project, and deploy again from that"
                    .into()
            } else {
                format!(
                    "this server is running its {} deploys at once already; wait and try again",
                    self.concurrency()
                )
            }));
        };
        // Who is asking comes before what they sent: an inline bundle is
        // decoded only for a session allowed to deploy, and one deploy per
        // session.
        let Some(sid) = (self.session)(&ctx) else {
            return Ok(err("deploying a bundle needs an authenticated session".into()));
        };
        if let Err(e) = self.identities.require_write(&sid).await {
            return Ok(err(e));
        }
        if let Err(e) = claim.for_session(&sid) {
            return Ok(err(e));
        }
        let mut request = match request_from_args(args) {
            Ok(r) => r,
            Err(e) => return Ok(err(e)),
        };
        request.workdir = self.deploys_dir.clone();
        // An uploaded bundle is the session's own, and the file goes with
        // the handle once the deploy has returned.
        let _upload = match request.bundle {
            BundleSource::Upload(ref id) => {
                let Some((uploads, _)) = &self.uploads else {
                    return Ok(err("this server takes no uploads; pass the bundle as \
                                   bundle_path or bundle_base64"
                        .into()));
                };
                let Some(taken) = uploads.take(id, &sid).await else {
                    return Ok(err(format!(
                        "no upload '{id}' for this session: it may have expired ({} minutes \
                         after the upload) or been deployed already; call {UPLOAD_TOOL} and \
                         upload the archive again",
                        UPLOAD_TTL.as_secs() / 60
                    )));
                };
                let path = match Utf8PathBuf::from_path_buf(taken.path().to_path_buf()) {
                    Ok(p) => p,
                    Err(p) => return Ok(err(format!("upload path is not UTF-8: {}", p.display()))),
                };
                request.bundle = BundleSource::Path(path);
                Some(taken)
            }
            _ => None,
        };
        // A per-app delegation lives five minutes and a deploy can outlast
        // it (an asset sync, several installs), so the identity the agent
        // signs with is kept fresh for as long as the deploy runs.
        let identity =
            match RefreshingIdentity::start(self.identities.clone(), sid, CLI_ORIGIN).await {
                Ok(id) => id,
                Err(e) => return Ok(err(e)),
            };
        // Each phase reaches the client as it completes, and the client's
        // cancellation of the request stops the deploy.
        let (lines, receiver) = tokio::sync::mpsc::unbounded_channel();
        let forwarder =
            tokio::spawn(forward_lines(ctx.peer.clone(), ctx.meta.get_progress_token(), receiver));
        // The stop: the client cancelling the request, or (on a server that
        // says so) going away.
        let stop = ctx.ct.child_token();
        let _link = link_client_gone(&ctx, stop.clone());
        let watch = Watch { stop, lines: Some(lines) };
        let result = deploy_bundle(identity, request, watch).await;
        // The sender went with the run; the forwarder ends once it has
        // delivered what is left.
        let _ = forwarder.await;
        match result {
            Err(RequestError(e)) => Ok(err(e)),
            Ok(outcome) => {
                let output = DeployBundleOutput::from_outcome(&outcome);
                let text = output.human();
                Ok(match outcome.status {
                    Status::Failed | Status::Interrupted => err_structured(text, &output),
                    Status::Deployed | Status::NothingToDeploy => ok_structured(text, &output),
                })
            }
        }
    }

    #[tool(
        description = "Return the cycles-ledger balance on the Internet Computer of the principal icp_deploy_bundle deploys as, and that principal: your default Internet Identity account at https://cli.id.ai, the one `icp identity link web` links an icp CLI identity to. When `icp identity principal` prints the same principal, the CLI and this tool share canisters and cycles; when it prints another (a local key, or a link to another account), they do not. Call it before a deploy that will create canisters, to check the balance covers them (2T cycles each by default), and to get the principal to add as a controller of a canister created elsewhere.",
        annotations(title = "Check your cycles balance", read_only_hint = true, destructive_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<CyclesBalance>(),
    )]
    async fn icp_cycles_balance(
        &self,
        Parameters(_args): Parameters<NoArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let Some(sid) = (self.session)(&ctx) else {
            return Ok(err("checking your cycles balance needs an authenticated session".into()));
        };
        let identity = match self.cli_identity(&sid).await {
            Ok(id) => id,
            Err(e) => return Ok(err(e)),
        };
        let principal = match identity.sender() {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("could not derive your principal: {e}"))),
        };
        // The balance a deploy draws on is the one on the Internet Computer,
        // whatever endpoint the rest of the server is pointed at.
        let agent = match deploy::mainnet_agent(Arc::new(identity)) {
            Ok(agent) => agent,
            Err(e) => return Ok(err(e)),
        };
        match cycles_balance_of(&agent, principal).await {
            Ok(balance) => Ok(ok_structured(balance.human(), &balance)),
            Err(e) => Ok(err(e)),
        }
    }

    #[tool(
        description = "Return the guide to deploying through this server: the loop around icp_deploy_bundle — bundle the project with `icp project bundle`, call the tool with the bundle and the environment's canister-id mapping, write the mapping it returns back into the project so the next deploy upgrades rather than creates — with what the tool needs and what it returns. The same text is served as the MCP resource `skill://deploy-with-mcp`; call this when the user asks you to deploy an icp project and you have not read that resource.",
        annotations(title = "Get the deploy guide", read_only_hint = true, destructive_hint = false, open_world_hint = false),
        output_schema = schema_for_output::<DeployGuideOutput>(),
    )]
    async fn icp_deploy_guide(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let output = DeployGuideOutput { content: DEPLOY_SKILL_MD.to_string() };
        Ok(ok_structured(output.content.clone(), &output))
    }

    #[tool(
        name = "icp_deploy_upload",
        description = "Get a one-time ticket to upload a bundle archive to this server, for icp_deploy_bundle to deploy: this server runs elsewhere than the project, so the archive `icp project bundle` wrote cannot be read by path. Returns the upload URL, the ticket, and the exact curl command to run; the command prints a JSON answer whose `upload_id` is what to pass to icp_deploy_bundle as `bundle_upload`. The ticket is good for a few minutes and one upload, and the upload for a quarter of an hour; ask for a new ticket after either lapses.",
        annotations(title = "Get a bundle upload ticket", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false),
        output_schema = schema_for_output::<UploadTicketOutput>(),
    )]
    async fn icp_deploy_upload(
        &self,
        Parameters(_args): Parameters<NoArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let Some((uploads, url)) = &self.uploads else {
            return Ok(err("this server takes no uploads; pass the bundle as bundle_path or \
                           bundle_base64"
                .into()));
        };
        // A ticket is for a session that could deploy what it uploads.
        let Some(sid) = (self.session)(&ctx) else {
            return Ok(err("uploading a bundle needs an authenticated session".into()));
        };
        if let Err(e) = self.identities.require_write(&sid).await {
            return Ok(err(e));
        }
        let minted = uploads.mint(&sid).await;
        let output = UploadTicketOutput {
            curl: format!(
                "curl -fsS -T <bundle.tar.gz> -H '{TICKET_HEADER}: {}' '{url}'",
                minted.ticket
            ),
            upload_url: url.clone(),
            ticket: minted.ticket,
            header: TICKET_HEADER.into(),
            expires_in_secs: minted.expires_in.as_secs(),
            max_bytes: uploads.max_bytes(),
        };
        let text = format!(
            "Upload the bundle within {} minutes by running, with the archive's path in place of \
             <bundle.tar.gz>:\n\n{}\n\nThe command prints a JSON answer; pass its `upload_id` to \
             icp_deploy_bundle as `bundle_upload` within {} minutes. The archive may be at most \
             {} bytes. The ticket is good for one upload.",
            output.expires_in_secs / 60,
            output.curl,
            UPLOAD_TTL.as_secs() / 60,
            output.max_bytes
        );
        Ok(ok_structured(text, &output))
    }
}

/// Tie `stop` to the transport's [`ClientGone`] token when the request carries
/// one, for as long as the returned guard lives: the deploy stops when the
/// client goes, and the tie is undone when the deploy returns.
fn link_client_gone(
    ctx: &RequestContext<RoleServer>,
    stop: CancellationToken,
) -> Option<tokio_util::sync::DropGuard> {
    let gone = ctx
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<ClientGone>())
        .map(|g| g.0.clone())?;
    let done = CancellationToken::new();
    let watched = done.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = gone.cancelled() => stop.cancel(),
            _ = watched.cancelled() => {}
        }
    });
    Some(done.drop_guard())
}

/// What `icp_deploy_upload` returns.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UploadTicketOutput {
    /// The absolute URL to `PUT` the archive to.
    pub upload_url: String,
    /// The one-time ticket, sent in the request header named by `header`.
    pub ticket: String,
    /// The request header the ticket goes in.
    pub header: String,
    /// Seconds the ticket is good for.
    pub expires_in_secs: u64,
    /// The most bytes the archive may have.
    pub max_bytes: usize,
    /// The command to run, with the archive's path in place of `<bundle.tar.gz>`.
    pub curl: String,
}

/// Deliver each log line of a running deploy to the client as it is made: as
/// a progress notification when the request carried a progress token (which
/// is also what keeps a client's per-call timeout from running out during a
/// long deploy), else as a logging message, the one other thing a server may
/// say mid-call. A client that cannot be reached is not an error here; the
/// outcome carries every line regardless.
// MCP logging is deprecated (SEP-2577) but still delivered; it is the
// fallback for a client that sends no progress token, nothing more.
#[allow(deprecated)]
async fn forward_lines(
    peer: Peer<RoleServer>,
    progress_token: Option<ProgressToken>,
    mut lines: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let mut progress = 0.0;
    while let Some(line) = lines.recv().await {
        progress += 1.0;
        let _ = match &progress_token {
            Some(token) => {
                let param =
                    ProgressNotificationParam::new(token.clone(), progress).with_message(line);
                peer.notify_progress(param).await
            }
            None => {
                let param = LoggingMessageNotificationParam::new(
                    LoggingLevel::Info,
                    serde_json::Value::String(line),
                )
                .with_logger("icp_deploy_bundle");
                peer.notify_logging_message(param).await
            }
        };
    }
}

/// `icp_cycles_balance` and `icp_deploy_guide` take no arguments.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct NoArgs {}

/// What `icp_deploy_guide` returns: the skill document, as the resource
/// serves it.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DeployGuideOutput {
    /// The guide, Markdown with its frontmatter.
    pub content: String,
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

    // The group carries the deploy tool, with honest annotations (it creates
    // canisters and can wipe state) and an object-rooted outputSchema like
    // every tool on the core surface, the read-only balance check beside it,
    // and the guide: the skill as a tool result, for a client that reads no
    // resources.
    #[test]
    fn the_router_carries_the_deploy_tool_the_balance_check_and_the_guide() {
        let tools = IcDeployTools::tool_router().list_all();
        assert_eq!(tools.len(), 4);
        let upload = tools.iter().find(|t| &*t.name == UPLOAD_TOOL).expect("upload ticket tool");
        assert_eq!(upload.annotations.clone().expect("annotations").destructive_hint, Some(false));
        let guide = tools.iter().find(|t| &*t.name == "icp_deploy_guide").expect("guide");
        let ann = guide.annotations.clone().expect("annotations");
        assert_eq!(ann.read_only_hint, Some(true));
        assert!(guide
            .description
            .as_deref()
            .unwrap_or_default()
            .contains("skill://deploy-with-mcp"));
        let output =
            serde_json::to_value(guide.output_schema.as_ref().expect("outputSchema")).unwrap();
        assert!(output["properties"]["content"].is_object(), "{output}");
        let balance = tools.iter().find(|t| &*t.name == "icp_cycles_balance").expect("balance");
        let ann = balance.annotations.clone().expect("annotations");
        assert_eq!(ann.read_only_hint, Some(true));
        let output =
            serde_json::to_value(balance.output_schema.as_ref().expect("outputSchema")).unwrap();
        assert!(output["properties"]["balance"].is_object(), "{output}");
        assert!(output["properties"]["principal"].is_object(), "{output}");

        let tool = tools.iter().find(|t| &*t.name == "icp_deploy_bundle").expect("deploy");
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
        assert!(request_from_args(both).unwrap_err().contains("not several"));
        let three = args(serde_json::json!({
            "bundle_path": "/tmp/b.tar.gz", "bundle_upload": "abc", "environment": "ic"
        }));
        assert!(request_from_args(three).unwrap_err().contains("not several"));
        let neither = args(serde_json::json!({ "environment": "ic" }));
        assert!(request_from_args(neither).unwrap_err().contains("bundle_upload"));
        let upload = args(serde_json::json!({ "bundle_upload": " abc ", "environment": "ic" }));
        let request = request_from_args(upload).unwrap();
        assert!(matches!(request.bundle, BundleSource::Upload(ref id) if id == "abc"));
        let empty = args(serde_json::json!({ "bundle_upload": " ", "environment": "ic" }));
        assert!(request_from_args(empty).unwrap_err().contains("empty"));
        let bad = args(serde_json::json!({ "bundle_base64": "***", "environment": "ic" }));
        assert!(request_from_args(bad).unwrap_err().contains("base64"));
    }

    // A relative deploy directory (a server started with a relative state
    // directory) is resolved when it is given, so a deploy's working
    // directory, and the paths it hands the library, are absolute.
    #[cfg(unix)]
    #[test]
    fn a_relative_deploy_directory_is_made_absolute() {
        let agent =
            imcp2_core::Agent::builder().with_url(imcp2_core::IC_URL).build().expect("agent");
        let identities = Identities::new(
            imcp2_core::IiInstance::prod().expect("prod II"),
            "https://mcp.example".into(),
            agent,
        );
        let tools = IcDeployTools::new(identities, Arc::new(|_: &_| None))
            .deploys_in(std::path::Path::new("state/deploys"))
            .unwrap();
        let dir = tools.deploys_dir.clone().unwrap();
        assert!(dir.is_absolute(), "{dir}");
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(dir.as_std_path(), cwd.join("state/deploys"));
        assert!(dir.is_dir(), "made now, not on first use");
        std::fs::remove_dir_all(cwd.join("state")).unwrap();
    }

    // Four base64 characters past the bound is refused on length alone, before
    // any decoding: the bundle limit is measured on the text, not after a copy
    // of it has been allocated.
    #[test]
    fn an_oversized_inline_bundle_is_refused_before_decoding() {
        let text = "A".repeat(MAX_BUNDLE_BASE64_CHARS + 4);
        let big = args(serde_json::json!({ "bundle_base64": text, "environment": "ic" }));
        let e = request_from_args(big).unwrap_err();
        assert!(e.contains("encodes more than"), "{e}");
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

    // The path is what the tool reads, so it is held to what the skill
    // teaches before any I/O: trimmed, present, absolute.
    #[test]
    fn a_bundle_path_is_trimmed_and_must_be_absolute() {
        let request = request_from_args(args(
            serde_json::json!({ "bundle_path": "  /b.tar.gz ", "environment": "ic" }),
        ))
        .unwrap();
        assert!(matches!(request.bundle, BundleSource::Path(ref p) if p == "/b.tar.gz"));
        for (path, needle) in [("relative/b.tar.gz", "absolute"), ("  ", "empty")] {
            let e = request_from_args(args(
                serde_json::json!({ "bundle_path": path, "environment": "ic" }),
            ))
            .unwrap_err();
            assert!(e.contains(needle), "{path:?}: {e}");
        }
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
        assert!(e.contains("canister_ids[\"backend\"] is not a valid principal"), "{e}");
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
