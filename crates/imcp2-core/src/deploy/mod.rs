//! The deploy tools — the `icp_deploy_bundle` MCP tool: deploy an icp project
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
//! says otherwise), and refuses rather than queues past the cap; a process
//! serving the tools at more than one endpoint gives them one set of slots
//! ([`DeploySlots`]), so the cap is the process's. A deploy's
//! working directory is kept under the directory the embedder names until the
//! outcome is assembled, so a call cut off mid-deploy leaves the ids it
//! created on disk.
//!
//! A deploy lasts as long as it lasts: the call reports each phase to the
//! client as it completes and is interrupted by the client cancelling the
//! request, by the server saying it is stopping
//! ([`IcDeployTools::stopped_by`]) or, on the hosted server, by the client
//! going away ([`ClientGone`]). Interrupted, it still answers, with every
//! canister it had created.
//!
//! A server takes the bundle one way. One on the project's machine — the
//! local server — reads it at the path the agent names (`bundle_path`). One
//! the agent cannot hand a file to — the hosted server — receives it through
//! an upload ticket ([`Uploads`], `icp_deploy_upload`) and deploys the upload
//! the agent names (`bundle_upload`); it reads no path a caller gives it.
//! Each lists the one argument it takes ([`IcDeployTools::tools`]).
//!
//! The module is composed into the local server, and into the hosted one
//! where its embedder turns the tools on ([`WithDeploy`] is the handler both
//! mount). It runs on the icp CLI's own crates (`icp-project` and its
//! siblings), from crates.io, which is where the wasmtime runtime in this
//! crate's dependencies comes from: a sync plugin runs on it.
//!
//! The bundle is untrusted input, and the rule it is held to is the
//! library's own: `icp_project::untrusted`, the one `icp --untrusted`
//! applies (dfinity/icp-cli#873, on #868 for what `icp project bundle`
//! writes; issue #865). This crate depends on the release that has them, composes
//! the rule as the CLI does, and adds the bounds on the archive itself and the
//! checks on the bundle's shape (see [`host`]).

use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
    time::Instant,
};

use crate::{cycles_balance_of, identities::Identities, CyclesBalance, SessionResolver};
use camino::{Utf8Path, Utf8PathBuf};
use candid::Principal;
use ic_agent::{identity::DelegatedIdentity, Identity};
#[allow(deprecated)]
use rmcp::model::{LoggingLevel, LoggingMessageNotificationParam};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, ProgressNotificationParam, ProgressToken, Tool},
    schemars,
    service::{Peer, RequestContext},
    tool, tool_router, ErrorData as McpError, RoleServer,
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

mod calls;
mod host;
mod identity;
mod observe;
mod run;
mod server;
mod uploads;

pub use host::{occupies, AllowedPlugins, BundleLimits, BLOCK_BYTES, ENTRY_BYTES, KNOWN_PLUGINS};
use identity::RefreshingIdentity;
pub use observe::{DeployObserver, Ended, Refused};
pub use run::{
    deploy_bundle, prune_abandoned_deploys, remove_old_deploy_records, BundleSource, DeployOutcome,
    DeployRequest, RequestError, Status, Watch, STOP_GRACE,
};
pub use server::WithDeploy;
pub use uploads::{
    Held, ReceiveError, Received, TakeError, Uploads, DEFAULT_MAX_EXTRACTED_BYTES,
    DEFAULT_MAX_UPLOAD_BYTES, DEFAULT_STORED_BUNDLES, TICKET_HEADER, TICKET_TTL, UPLOAD_IDLE,
    UPLOAD_TIME, UPLOAD_TTL,
};

/// The name of the deploy tool.
pub const DEPLOY_TOOL: &str = "icp_deploy_bundle";
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
pub const DEPLOY_SKILL_MD: &str = include_str!("../../static/skills/deploy-with-mcp.md");

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
    /// that `icp project bundle --output <file>` writes.
    // Listed by a server without an upload store, which takes this alone.
    #[serde(default)]
    pub bundle_path: Option<String>,
    /// The upload id the curl command from `icp_deploy_upload` printed: the
    /// bundle archive — the `.tar.gz` that `icp project bundle --output
    /// <file>` writes — as this server received it.
    // Listed by a server with an upload store, which takes this alone.
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

/// Turn the tool's arguments into a request, rejecting what cannot be deployed
/// before anything is read or written. A server takes the bundle one way: as
/// an upload id where it has an upload store (`uploads`), as a path where it
/// does not, and the other argument is refused, so a server reached over the
/// network reads no path a caller names. What comes back is that argument's
/// value and what makes the request of the bundle it stands for, so that an
/// upload is taken only once everything else has passed.
pub fn request_from_args(
    args: DeployBundleArgs,
    uploads: bool,
) -> Result<(String, impl FnOnce(BundleSource) -> DeployRequest), String> {
    let bundle = match (args.bundle_path, args.bundle_upload, uploads) {
        (Some(_), _, true) => {
            return Err(format!(
                "this server runs elsewhere than the project and reads no bundle_path; call \
                 {UPLOAD_TOOL}, upload the archive, and pass the upload id as bundle_upload"
            ))
        }
        (_, Some(_), false) => {
            return Err("this server takes no uploads; pass the bundle as bundle_path".into())
        }
        (None, None, true) => {
            return Err(format!(
                "pass the bundle as bundle_upload: the upload id from {UPLOAD_TOOL}"
            ))
        }
        (None, None, false) => {
            return Err("pass the bundle as bundle_path: the absolute path of the archive".into())
        }
        (None, Some(id), true) => {
            let id = id.trim();
            if id.is_empty() {
                return Err("bundle_upload is empty; pass the upload id the upload printed".into());
            }
            id.to_string()
        }
        (Some(path), None, false) => {
            let path = path.trim();
            if path.is_empty() {
                return Err("bundle_path is empty; pass the absolute path of the bundle".into());
            }
            if !Utf8Path::new(path).is_absolute() {
                return Err(format!(
                    "bundle_path must be an absolute path on this machine, got '{path}'"
                ));
            }
            path.to_string()
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
    let cycles = u128::from(args.cycles.unwrap_or(DEFAULT_CYCLES));
    let (no_create, skip_candid_check) = (args.no_create, args.skip_candid_check);
    Ok((bundle, move |bundle| DeployRequest {
        bundle,
        limits: BundleLimits::LOCAL,
        plugins: AllowedPlugins::Any,
        environment,
        canister_ids,
        mode,
        cycles,
        subnet,
        no_create,
        skip_candid_check,
        workdir: None,
    }))
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
    slots: DeploySlots,
    /// Cancelled when the server begins to stop; see [`Self::stopped_by`].
    stopping: Option<CancellationToken>,
    /// Where each deploy's working directory is made; see
    /// [`DeployRequest::workdir`].
    deploys_dir: Option<Utf8PathBuf>,
    /// Where uploaded bundles are received, and the URL a `PUT` goes to,
    /// on a server the agent cannot hand a file to. With it the bundle is
    /// an upload; without it, a path.
    uploads: Option<(Uploads, String)>,
    /// Told how each deploy call went; see [`Self::observed_by`].
    observer: Option<Arc<dyn DeployObserver>>,
}

/// How many deploys a server runs at once, and for whom. A clone is the same
/// slots: a process that serves the deploy tools at more than one endpoint
/// makes one of these and hands it to each ([`IcDeployTools::with_slots`]),
/// so the cap is on the process, which is what the memory behind it is.
#[derive(Clone)]
pub struct DeploySlots {
    /// One permit per deploy the server runs at once.
    free: Arc<tokio::sync::Semaphore>,
    /// How many there are in all, for the wording of the refusal.
    total: usize,
    /// The sessions with a deploy running: one each.
    sessions: Arc<Mutex<HashSet<String>>>,
    /// The deploys holding a slot, counted on their own: what is free of the
    /// permits says how many could begin, which is not the same thing to
    /// someone watching them end.
    running: Arc<Running>,
}

/// How many deploys hold a slot, and the word to whoever waits for none to.
#[derive(Default)]
struct Running {
    count: std::sync::atomic::AtomicUsize,
    ended: tokio::sync::Notify,
}

impl DeploySlots {
    /// Slots for `n` deploys at once (at least one), one per session.
    pub fn new(n: usize) -> Self {
        let n = n.max(1);
        Self {
            free: Arc::new(tokio::sync::Semaphore::new(n)),
            total: n,
            sessions: Arc::default(),
            running: Arc::default(),
        }
    }

    /// Wait until no deploy holds a slot. For a server that has told its
    /// deploys to stop: each one ends within [`STOP_GRACE`], and a process
    /// that exited before then would cut off the very answer the deploy is
    /// waiting to record.
    pub async fn idle(&self) {
        loop {
            // Listening before looking: a deploy that ends between the two
            // is not missed.
            let ended = self.running.ended.notified();
            if self.running() == 0 {
                return;
            }
            ended.await;
        }
    }

    /// How many deploys there may be at once.
    pub fn total(&self) -> usize {
        self.total
    }

    /// How many deploys hold a slot now.
    pub fn running(&self) -> usize {
        self.running.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A running deploy's claim on the server: a slot, and the session's one
/// deploy. Both are released when it drops, that is, when the deploy returns.
pub struct DeployClaim {
    _permit: tokio::sync::OwnedSemaphorePermit,
    session: Option<String>,
    sessions: Arc<Mutex<HashSet<String>>>,
    running: Arc<Running>,
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
        self.running.count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.running.ended.notify_waiters();
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
            slots: DeploySlots::new(1),
            stopping: None,
            deploys_dir: None,
            uploads: None,
            observer: None,
        }
    }

    /// Tell `observer` how each deploy call goes — refused, or how it ended
    /// and how long it held its slot — for a server to count (see
    /// [`DeployObserver`]).
    pub fn observed_by(mut self, observer: Arc<dyn DeployObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Run up to `n` deploys at once across sessions (one per session either
    /// way); the default is one. Past the cap a deploy is refused, not
    /// queued. `n` is at least one.
    pub fn concurrent(self, n: usize) -> Self {
        self.with_slots(DeploySlots::new(n))
    }

    /// Run deploys in `slots`, which other servers of the process may hold
    /// too: the cap, and the one deploy per session, are then across all of
    /// them.
    pub fn with_slots(mut self, slots: DeploySlots) -> Self {
        self.slots = slots;
        self
    }

    /// Interrupt the deploys running when `stopping` is cancelled, and refuse
    /// to begin one after: for a server to cancel as it starts shutting
    /// down, before it waits for its requests to finish. A deploy lasts
    /// minutes, longer than a server is given to stop, and one killed
    /// mid-run answers nothing; interrupted, it stops at its next step and
    /// returns the canisters it had created, as any interrupted deploy does.
    pub fn stopped_by(mut self, stopping: CancellationToken) -> Self {
        self.stopping = Some(stopping);
        self
    }

    /// How many deploys this server runs at once.
    pub fn concurrency(&self) -> usize {
        self.slots.total
    }

    /// Serve `icp_deploy_upload` on `uploads`, with `upload_url` the absolute
    /// URL the agent `PUT`s an archive to (the server mounts the route; see
    /// [`Uploads`]), and take the bundle as `bundle_upload` alone: the server
    /// is one the agent cannot hand a file to, so `bundle_path` is refused.
    /// Without this, it is the other way round and the tool is not listed.
    pub fn with_uploads(mut self, uploads: Uploads, upload_url: String) -> Self {
        self.uploads = Some((uploads, upload_url));
        self
    }

    /// Whether this server receives its bundles by upload, not by path.
    pub fn has_uploads(&self) -> bool {
        self.uploads.is_some()
    }

    /// The tools this server lists, which follow from how the bundle reaches
    /// it: `icp_deploy_upload` only where an upload store exists for it to
    /// mint tickets on, and of the deploy tool's two bundle arguments the one
    /// this server takes.
    pub fn tools(&self) -> Vec<Tool> {
        let refused = if self.has_uploads() { "bundle_path" } else { "bundle_upload" };
        Self::tool_router()
            .list_all()
            .into_iter()
            .filter(|t| self.has_uploads() || &*t.name != UPLOAD_TOOL)
            .map(|mut tool| {
                if &*tool.name == DEPLOY_TOOL {
                    let mut schema = (*tool.input_schema).clone();
                    if let Some(properties) =
                        schema.get_mut("properties").and_then(|p| p.as_object_mut())
                    {
                        properties.remove(refused);
                    }
                    tool.input_schema = Arc::new(schema);
                }
                tool
            })
            .collect()
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
        self.slots.running.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(DeployClaim {
            _permit: permit,
            session: None,
            sessions: self.slots.sessions.clone(),
            running: self.slots.running.clone(),
        })
    }

    /// The session's identity at [`CLI_ORIGIN`]: its default account there,
    /// derived on demand like any other per-app delegation. Good for the
    /// next few minutes; a deploy uses [`RefreshingIdentity`] instead.
    async fn cli_identity(&self, sid: &str) -> Result<DelegatedIdentity, String> {
        self.identities.delegated_identity(sid, CLI_ORIGIN, None).await
    }

    #[tool(
        description = "Deploy an icp project bundle (the .tar.gz that `icp project bundle` writes) to the Internet Computer as the user, running every phase of `icp deploy`: create the bundle's new canisters (funded from the user's cycles balance), wire their ids into each other, apply settings, install or upgrade the code, and run the sync steps (a frontend's asset upload). Pass the bundle the one way this server takes it (the bundle argument listed here), the environment name it was built for (usually \"ic\"), and, to upgrade rather than create, the canister_ids a previous deploy returned. The call lasts as long as the deploy and reports each phase as it completes, as a progress notification (send a progressToken) and a log message; cancelling the call interrupts the deploy at its next step. Returns the status, the resulting canister-id mapping, and a log of each phase; on failure or interruption the mapping still holds every canister that was created.",
        annotations(title = "Deploy a project bundle", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        output_schema = schema_for_output::<DeployBundleOutput>(),
    )]
    async fn icp_deploy_bundle(
        &self,
        Parameters(args): Parameters<DeployBundleArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // A server on its way out begins nothing it would have to interrupt.
        if self.stopping.as_ref().is_some_and(|s| s.is_cancelled()) {
            self.told(Told::Refused(Refused::Stopping), Instant::now());
            return Ok(err("this server is restarting; nothing was deployed. Try again in a \
                           minute, with the same bundle and mapping"
                .into()));
        }
        // So many deploys at a time, and the refusal reads nothing: it comes
        // even before who is asking.
        let Some(claim) = self.claim() else {
            self.told(Told::Refused(Refused::Busy), Instant::now());
            return Ok(err(if self.concurrency() == 1 {
                "a deploy is already running on this server; wait for it to finish, write \
                 the mapping it returns into the project, and deploy again from that"
                    .into()
            } else {
                "this server is running as many deploys as it can right now; try again in a \
                 few minutes"
                    .into()
            }));
        };
        // From here the call holds a slot until it returns, and what became
        // of it is told once, as it does — or as it is dropped, should the
        // transport give the call up while it runs: the slot goes back
        // either way, and a deploy that vanished from the count would make
        // the others look like all there were.
        let mut telling = Telling {
            tools: self,
            held_since: Instant::now(),
            told: Told::Ended(Ended::Interrupted),
        };
        let (result, told) = self.deploy_in_slot(claim, args, ctx).await;
        telling.told = told;
        Ok(result)
    }

    /// Tell the observer, if there is one, what became of a deploy call.
    fn told(&self, told: Told, held_since: Instant) {
        let Some(observer) = &self.observer else { return };
        match told {
            Told::Refused(why) => observer.refused(why),
            Told::Ended(how) => observer.ended(how, held_since.elapsed()),
        }
    }

    /// The deploy call once it holds a slot (`claim`, given back as this
    /// returns): the answer, and what to tell the observer of it.
    async fn deploy_in_slot(
        &self,
        mut claim: DeployClaim,
        args: DeployBundleArgs,
        ctx: RequestContext<RoleServer>,
    ) -> (CallToolResult, Told) {
        let rejected = |why: String| (err(why), Told::Ended(Ended::Rejected));
        // Who is asking comes before what they sent: a bundle is read only
        // for a session allowed to deploy, and one deploy per session.
        let Some(sid) = (self.session)(&ctx) else {
            return rejected("deploying a bundle needs an authenticated session".into());
        };
        if let Err(e) = self.identities.require_write(&sid).await {
            return rejected(e);
        }
        if let Err(e) = claim.for_session(&sid) {
            return (err(e), Told::Refused(Refused::SessionBusy));
        }
        let (bundle, into_request) = match request_from_args(args, self.has_uploads()) {
            Ok(r) => r,
            Err(e) => return rejected(e),
        };
        // An uploaded bundle is the session's own, extracted as it arrived:
        // the deploy takes its directory, and holds the room the store keeps
        // for a running deploy until it has returned. A bundle named by path
        // is the user's own file on the user's own machine, and is held to
        // what such a server takes — any sync plugin it brings among it,
        // where an upload's are the ones its server knows.
        let (source, (limits, plugins), _upload) = match &self.uploads {
            None => (
                BundleSource::Path(Utf8PathBuf::from(bundle)),
                (BundleLimits::LOCAL, AllowedPlugins::Any),
                None,
            ),
            Some((uploads, _)) => {
                let taken = match uploads.take(&bundle, &sid).await {
                    Ok(taken) => taken,
                    Err(TakeError::NoSuchUpload) => {
                        return rejected(format!(
                            "no upload '{bundle}' for this session: it may have expired ({} \
                             minutes after the upload) or been deployed already; call \
                             {UPLOAD_TOOL} and upload the archive again",
                            UPLOAD_TTL.as_secs() / 60
                        ))
                    }
                    Err(TakeError::NoRoom) => {
                        let why = format!(
                            "this server has no room to run another deploy right now; nothing \
                             was deployed and the upload is kept. Try again in a few minutes \
                             with the same `bundle_upload`; if it has expired by then ({} \
                             minutes after the upload), call {UPLOAD_TOOL} and upload again",
                            UPLOAD_TTL.as_secs() / 60
                        );
                        return (err(why), Told::Refused(Refused::NoRoom));
                    }
                };
                match Utf8PathBuf::from_path_buf(taken.dir().to_path_buf()) {
                    Ok(dir) => {
                        let source = BundleSource::Extracted { dir, bytes: taken.bytes() };
                        (source, (uploads.limits(), uploads.plugins()), Some(taken))
                    }
                    Err(p) => {
                        return rejected(format!("upload path is not UTF-8: {}", p.display()))
                    }
                }
            }
        };
        let mut request = into_request(source);
        request.limits = limits;
        request.plugins = plugins;
        request.workdir = self.deploys_dir.clone();
        // A per-app delegation lives five minutes and a deploy can outlast
        // it (an asset sync, several installs), so the identity the agent
        // signs with is kept fresh for as long as the deploy runs.
        // Every line the deploy logs carries the session it runs for.
        let span = tracing::info_span!("deploy", session = %sid);
        // The stop: the client cancelling the request, or (on a server that
        // says so) going away, or the server itself stopping. In place
        // before the first wait on the network, which is the identity's:
        // a request that held its slot and its upload through that wait,
        // deaf to a stop, would hold a stopping server with it.
        let stop = ctx.ct.child_token();
        let _link = link_stops(client_gone(&ctx).into_iter().chain(self.stopping.clone()), &stop);
        let starting = RefreshingIdentity::start(self.identities.clone(), sid, CLI_ORIGIN);
        let identity = match until(&stop, starting).await {
            Some(Ok(id)) => id,
            Some(Err(e)) => return rejected(e),
            None => {
                tracing::info!(parent: &span, "deploy stopped before it began");
                let RequestError(why) = RequestError::interrupted();
                return (err(why), Told::Ended(Ended::Interrupted));
            }
        };
        // Each phase reaches the client as it completes, and the client's
        // cancellation of the request stops the deploy.
        let (lines, receiver) = tokio::sync::mpsc::unbounded_channel();
        let forwarder =
            tokio::spawn(forward_lines(ctx.peer.clone(), ctx.meta.get_progress_token(), receiver));
        let watch = Watch { stop, lines: Some(lines) };
        let result = deploy_bundle(identity, request, watch).instrument(span.clone()).await;
        // The sender went with the run; the forwarder ends once it has
        // delivered what is left.
        let _ = forwarder.await;
        match result {
            Err(refused) => {
                tracing::warn!(parent: &span, "deploy refused: {refused}");
                let how = how_it_ended(Err(&refused));
                (err(refused.0), Told::Ended(how))
            }
            Ok(outcome) => {
                let output = DeployBundleOutput::from_outcome(&outcome);
                let text = output.human();
                let how = Told::Ended(how_it_ended(Ok(outcome.status)));
                match outcome.status {
                    Status::Failed | Status::Interrupted => (err_structured(text, &output), how),
                    Status::Deployed | Status::NothingToDeploy => {
                        (ok_structured(text, &output), how)
                    }
                }
            }
        }
    }

    #[tool(
        description = "Return the cycles balance icp_deploy_bundle creates canisters from, and the principal that holds it: the developer principal of the user's identity, distinct from its principals in apps. Call it before a deploy that will create canisters, to check the balance covers them (2T cycles each by default). The principal is where the user sends cycles to top the balance up, and what to add as a controller of a canister created elsewhere.",
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
        let agent = match run::mainnet_agent(Arc::new(identity)) {
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
        description = "Get a one-time ticket to upload a bundle archive to this server, for icp_deploy_bundle to deploy: this server runs elsewhere than the project, so the archive `icp project bundle` wrote cannot be read by path. Returns the upload URL, the ticket, and the exact curl command to run; the command prints a JSON answer whose `upload_id` is what to pass to icp_deploy_bundle as `bundle_upload`. The server extracts the archive as it arrives and stops the upload if the archive, or what it extracts to, passes the limits returned here (`max_bytes`, `max_extracted_bytes`); curl may report that as a failed transfer (broken pipe, connection reset) rather than as the server's answer, so read an upload that fails that way as a bundle that is too large. The ticket is good for a few minutes and one upload, and the upload for five minutes; ask for a new ticket after either lapses.",
        annotations(title = "Get a bundle upload ticket", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false),
        output_schema = schema_for_output::<UploadTicketOutput>(),
    )]
    async fn icp_deploy_upload(
        &self,
        Parameters(_args): Parameters<NoArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let Some((uploads, url)) = &self.uploads else {
            return Ok(err("this server takes no uploads; pass the bundle as bundle_path".into()));
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
                "curl -sS --fail-with-body -T <bundle.tar.gz> -H '{TICKET_HEADER}: {}' '{url}'",
                minted.ticket
            ),
            upload_url: url.clone(),
            ticket: minted.ticket,
            header: TICKET_HEADER.into(),
            expires_in_secs: minted.expires_in.as_secs(),
            max_bytes: uploads.limits().archive_bytes,
            max_extracted_bytes: uploads.limits().extracted_bytes,
        };
        let text = format!(
            "Upload the bundle within {} minutes by running, with the archive's path in place of \
             <bundle.tar.gz>:\n\n{}\n\nThe command prints a JSON answer; pass its `upload_id` to \
             icp_deploy_bundle as `bundle_upload` within {} minutes. The archive may be at most \
             {} bytes and extract to at most {} bytes; the server extracts it as it arrives and \
             stops the upload at either limit, which curl may report as a failed or reset \
             connection rather than as the server's answer. The ticket is good for one upload.",
            output.expires_in_secs / 60,
            output.curl,
            UPLOAD_TTL.as_secs() / 60,
            output.max_bytes,
            output.max_extracted_bytes
        );
        Ok(ok_structured(text, &output))
    }
}

/// The transport's [`ClientGone`] token, when the request carries one.
fn client_gone(ctx: &RequestContext<RoleServer>) -> Option<CancellationToken> {
    ctx.extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<ClientGone>())
        .map(|gone| gone.0.clone())
}

/// How a deploy that ran, or was refused before it could, is counted:
/// `Ok` its outcome's status, `Err` the refusal. A stop is an interruption
/// whenever it comes — while the bundle is still being read as much as
/// mid-run — and never a bundle that was rejected; and a refusal that is the
/// server's own failure is not one of the request.
fn how_it_ended(result: Result<Status, &RequestError>) -> Ended {
    match result {
        Ok(Status::Deployed | Status::NothingToDeploy) => Ended::Succeeded,
        Ok(Status::Failed) => Ended::Failed,
        Ok(Status::Interrupted) => Ended::Interrupted,
        Err(refused) if refused.was_interrupted() => Ended::Interrupted,
        Err(refused) if refused.is_server_fault() => Ended::SetupFailed,
        Err(_) => Ended::Rejected,
    }
}

/// What a deploy call tells the observer as it returns.
#[derive(Clone, Copy)]
enum Told {
    Refused(Refused),
    Ended(Ended),
}

/// Tells the observer what became of a deploy that holds a slot, when it is
/// dropped: what the call set it to as it returned, or — never set, the
/// call's future having been dropped mid-run — that it was interrupted.
struct Telling<'a> {
    tools: &'a IcDeployTools,
    held_since: Instant,
    told: Told,
}

impl Drop for Telling<'_> {
    fn drop(&mut self) {
        self.tools.told(self.told, self.held_since);
    }
}

/// `work`'s output, or `None` if `stop` is cancelled first — or already is:
/// the stop is looked at before the work is.
async fn until<T>(
    stop: &CancellationToken,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = stop.cancelled() => None,
        out = work => Some(out),
    }
}

/// Tie `stop` to each of `sources` for as long as the returned guard lives:
/// the deploy stops when any of them is cancelled, and the ties are undone
/// when the deploy returns.
fn link_stops(
    sources: impl Iterator<Item = CancellationToken>,
    stop: &CancellationToken,
) -> tokio_util::sync::DropGuard {
    let done = CancellationToken::new();
    for source in sources {
        let (stop, done) = (stop.clone(), done.clone());
        tokio::spawn(async move {
            tokio::select! {
                _ = source.cancelled() => stop.cancel(),
                _ = done.cancelled() => {}
            }
        });
    }
    done.drop_guard()
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
    pub max_bytes: u64,
    /// The most bytes the archive may extract to: the server extracts it as
    /// it arrives, and stops the upload when it passes this.
    pub max_extracted_bytes: u64,
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
                .with_logger(DEPLOY_TOOL);
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

    /// The request a server without an upload store makes of `json`, and
    /// the one a server with a store makes of it (of the upload id, which
    /// stands in for the path of the file received).
    fn by_path(json: serde_json::Value) -> Result<DeployRequest, String> {
        request_from_args(args(json), false).map(|(b, into)| into(BundleSource::Path(b.into())))
    }
    fn tools() -> IcDeployTools {
        let agent = crate::Agent::builder().with_url(crate::IC_URL).build().expect("agent");
        let identities = Identities::new(
            crate::IiInstance::prod().expect("prod II"),
            "https://mcp.example".into(),
            agent,
        );
        IcDeployTools::new(identities, Arc::new(|_: &_| None))
    }
    fn by_upload(json: serde_json::Value) -> Result<DeployRequest, String> {
        request_from_args(args(json), true).map(|(b, into)| into(BundleSource::Path(b.into())))
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
            "bundle_upload",
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

        let tool = tools.iter().find(|t| &*t.name == DEPLOY_TOOL).expect("deploy");
        let ann = tool.annotations.clone().expect("annotations");
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        let schema = serde_json::to_value(&tool.input_schema).unwrap();
        for field in ["bundle_path", "bundle_upload", "environment", "canister_ids", "mode"] {
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

    // A server takes the bundle one way and lists it that way: a path where
    // it has no upload store, an upload id where it has one. The other
    // argument is refused, whatever comes with it, so a server reached over
    // the network opens no path a caller names. An inline bundle is not an
    // argument at all.
    #[test]
    fn a_server_takes_the_bundle_one_way() {
        let path = serde_json::json!({ "bundle_path": "/tmp/b.tar.gz", "environment": "ic" });
        let upload = serde_json::json!({ "bundle_upload": " abc ", "environment": "ic" });
        let both = serde_json::json!({
            "bundle_path": "/tmp/b.tar.gz", "bundle_upload": "abc", "environment": "ic"
        });
        let neither = serde_json::json!({ "environment": "ic" });
        let inline = serde_json::json!({ "bundle_base64": "AAAA", "environment": "ic" });

        let request = by_path(path.clone()).unwrap();
        assert!(matches!(request.bundle, BundleSource::Path(ref p) if p == "/tmp/b.tar.gz"));
        for refused in [upload.clone(), both.clone()] {
            assert!(by_path(refused).unwrap_err().contains("takes no uploads"));
        }
        for missing in [neither.clone(), inline.clone()] {
            assert!(by_path(missing).unwrap_err().contains("as bundle_path"));
        }

        let request = by_upload(upload).unwrap();
        assert!(matches!(request.bundle, BundleSource::Path(ref id) if id == "abc"));
        for refused in [path, both] {
            let e = by_upload(refused).unwrap_err();
            assert!(e.contains("reads no bundle_path") && e.contains(UPLOAD_TOOL), "{e}");
        }
        for missing in [neither, inline] {
            assert!(by_upload(missing).unwrap_err().contains("as bundle_upload"));
        }
        let empty = serde_json::json!({ "bundle_upload": " ", "environment": "ic" });
        assert!(by_upload(empty).unwrap_err().contains("empty"));
    }

    // And lists the one argument it takes, with the upload tool beside it
    // only where there is a store to upload to.
    #[test]
    fn a_server_lists_the_bundle_argument_it_takes() {
        let dir = tempfile::tempdir().unwrap();
        let local = tools();
        let hosted = tools().with_uploads(
            Uploads::new(dir.path().join("uploads"), BundleLimits::new(1024, 4096)),
            "https://mcp.example/deploy/upload".into(),
        );
        for (tools, listed, unlisted) in
            [(local, "bundle_path", "bundle_upload"), (hosted, "bundle_upload", "bundle_path")]
        {
            let tools = tools.tools();
            let uploads = listed == "bundle_upload";
            assert_eq!(tools.iter().any(|t| &*t.name == UPLOAD_TOOL), uploads);
            let deploy = tools.iter().find(|t| &*t.name == DEPLOY_TOOL).expect("deploy");
            let schema = serde_json::to_value(&deploy.input_schema).unwrap();
            assert!(schema["properties"][listed].is_object(), "{schema}");
            assert!(schema["properties"][unlisted].is_null(), "{schema}");
            assert!(schema["properties"]["environment"].is_object(), "{schema}");
        }
    }

    // Two servers of one process — the hosted binary's two endpoints — on
    // one set of slots: the cap is across both, and so is the one deploy a
    // session runs.
    #[test]
    fn servers_sharing_slots_share_the_cap_and_the_sessions() {
        let slots = DeploySlots::new(2);
        let (one, other) = (tools().with_slots(slots.clone()), tools().with_slots(slots));
        assert_eq!((one.concurrency(), other.concurrency()), (2, 2));
        let mut first = one.claim().expect("a slot");
        let mut second = other.claim().expect("the other slot");
        assert!(one.claim().is_none() && other.claim().is_none(), "two in all, not two each");
        first.for_session("s").unwrap();
        assert!(second.for_session("s").is_err(), "one deploy per session, on either server");
        drop(first);
        assert!(other.claim().is_some(), "a slot freed on one is free on the other");
        second.for_session("s").unwrap();
    }

    // The deploy's stop follows whichever of its sources goes first, and
    // stops following once the deploy has returned.
    // What a deploy waits on before it runs — its identity, fetched over the
    // network — gives way to a stop, and to one already asked for at once.
    #[tokio::test]
    async fn a_wait_before_the_deploy_gives_way_to_a_stop() {
        let stop = CancellationToken::new();
        assert_eq!(until(&stop, async { 1 }).await, Some(1));
        let (stopper, waiting) = (stop.clone(), until(&stop, std::future::pending::<u8>()));
        let (out, ()) = tokio::join!(waiting, async move { stopper.cancel() });
        assert_eq!(out, None);
        assert_eq!(until(&stop, async { 1 }).await, None, "a stop already asked for comes first");
    }

    // A deploy stopped while its bundle was still being read is counted as
    // interrupted, like one stopped mid-run: only a request or bundle that
    // was itself refused is a rejection.
    #[test]
    fn a_stop_is_counted_as_an_interruption_whenever_it_comes() {
        let stopped_early = RequestError::interrupted();
        assert_eq!(how_it_ended(Err(&stopped_early)), Ended::Interrupted);
        let bad_bundle = RequestError("the archive carries no icp.yaml".into());
        assert_eq!(how_it_ended(Err(&bad_bundle)), Ended::Rejected);
        // What the server could not do is not held against the request.
        let no_room = RequestError::server_fault("cannot create a scratch directory: no space");
        assert_eq!(how_it_ended(Err(&no_room)), Ended::SetupFailed);
        assert_eq!(how_it_ended(Ok(Status::Interrupted)), Ended::Interrupted);
        assert_eq!(how_it_ended(Ok(Status::Failed)), Ended::Failed);
        assert_eq!(how_it_ended(Ok(Status::Deployed)), Ended::Succeeded);
        assert_eq!(how_it_ended(Ok(Status::NothingToDeploy)), Ended::Succeeded);
    }

    /// Counts what it is told.
    #[derive(Default)]
    struct Tally(Mutex<Vec<String>>);

    impl DeployObserver for Tally {
        fn refused(&self, why: Refused) {
            self.0.lock().unwrap().push(format!("refused:{}", why.as_str()));
        }
        fn ended(&self, how: Ended, _lasted: std::time::Duration) {
            self.0.lock().unwrap().push(format!("ended:{}", how.as_str()));
        }
    }

    // A deploy call that is dropped while it holds a slot — the transport
    // giving it up mid-run — is still counted, as interrupted: its slot goes
    // back, and it must not go missing from what the server ran. One that
    // returns is counted as what it returned, once.
    #[test]
    fn a_deploy_dropped_mid_run_is_counted_as_interrupted() {
        let tally = Arc::new(Tally::default());
        let tools = tools().observed_by(tally.clone());
        let telling =
            |told| Telling { tools: &tools, held_since: Instant::now(), told: Told::Ended(told) };
        // Dropped as it was made: the call never set what became of it.
        drop(telling(Ended::Interrupted));
        // Returned: set, then dropped.
        let mut returned = telling(Ended::Interrupted);
        returned.told = Told::Ended(Ended::Succeeded);
        drop(returned);
        let mut refused = telling(Ended::Interrupted);
        refused.told = Told::Refused(Refused::SessionBusy);
        drop(refused);
        let seen = tally.0.lock().unwrap().clone();
        assert_eq!(seen, ["ended:interrupted", "ended:succeeded", "refused:session_busy"]);
    }

    #[tokio::test]
    async fn a_server_can_wait_for_its_deploys_to_end() {
        let slots = DeploySlots::new(2);
        let tools = tools().with_slots(slots.clone());
        slots.idle().await;
        let running = tools.claim().unwrap();
        let other = tools.claim().unwrap();
        assert_eq!(slots.running(), 2);
        let waiting = slots.idle();
        tokio::pin!(waiting);
        let timed = tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting);
        assert!(timed.await.is_err(), "deploys are still running");
        // The count follows the deploys as they end, wait or no wait: one
        // gone is one fewer running, not a server that looks full.
        drop(other);
        assert_eq!(slots.running(), 1);
        let timed = tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting);
        assert!(timed.await.is_err(), "one is still running");
        assert_eq!(slots.running(), 1, "the wait holds no slot of its own");
        assert!(tools.claim().is_some(), "nor keeps one from being taken");
        drop(running);
        waiting.await;
        assert_eq!(slots.running(), 0);
    }

    #[tokio::test]
    async fn a_deploy_is_stopped_by_any_of_its_sources_until_it_returns() {
        let (gone, stopping) = (CancellationToken::new(), CancellationToken::new());
        let stop = CancellationToken::new();
        let link = link_stops([gone.clone(), stopping.clone()].into_iter(), &stop);
        tokio::task::yield_now().await;
        assert!(!stop.is_cancelled());
        stopping.cancel();
        stop.cancelled().await;
        drop(link);

        let (gone, stop) = (CancellationToken::new(), CancellationToken::new());
        let link = link_stops(std::iter::once(gone.clone()), &stop);
        drop(link);
        tokio::task::yield_now().await;
        gone.cancel();
        tokio::task::yield_now().await;
        assert!(!stop.is_cancelled(), "a returned deploy's stop is left alone");
    }

    // A relative deploy directory (a server started with a relative state
    // directory) is resolved when it is given, so a deploy's working
    // directory, and the paths it hands the library, are absolute.
    #[cfg(unix)]
    #[test]
    fn a_relative_deploy_directory_is_made_absolute() {
        // A directory of this test's own, made in the working directory and
        // removed with the guard: nothing that was already there is touched.
        let own = tempfile::Builder::new().prefix("relative-deploys-").tempdir_in(".").unwrap();
        let relative = std::path::Path::new(own.path().file_name().unwrap()).join("deploys");
        assert!(relative.is_relative(), "{}", relative.display());
        let tools = tools().deploys_in(&relative).unwrap();
        let dir = tools.deploys_dir.clone().unwrap();
        assert!(dir.is_absolute(), "{dir}");
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(dir.as_std_path(), cwd.join(&relative));
        assert!(dir.is_dir(), "made now, not on first use");
    }

    #[test]
    fn the_request_takes_the_defaults_and_parses_the_ids() {
        let request = by_path(serde_json::json!({
            "bundle_path": "/tmp/b.tar.gz",
            "environment": " ic ",
            "canister_ids": { "backend": "aaaaa-aa" },
            "mode": "Upgrade"
        }))
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
        let request =
            by_path(serde_json::json!({ "bundle_path": "  /b.tar.gz ", "environment": "ic" }))
                .unwrap();
        assert!(matches!(request.bundle, BundleSource::Path(ref p) if p == "/b.tar.gz"));
        for (path, needle) in [("relative/b.tar.gz", "absolute"), ("  ", "empty")] {
            let e = by_path(serde_json::json!({ "bundle_path": path, "environment": "ic" }))
                .unwrap_err();
            assert!(e.contains(needle), "{path:?}: {e}");
        }
    }

    #[test]
    fn bad_modes_ids_and_subnets_are_named_in_the_rejection() {
        let e = by_path(serde_json::json!({
            "bundle_path": "/b", "environment": "ic", "mode": "yolo"
        }))
        .unwrap_err();
        assert!(e.contains("mode") && e.contains("yolo"), "{e}");
        let e = by_path(serde_json::json!({
            "bundle_path": "/b", "environment": "ic", "canister_ids": { "backend": "nope" }
        }))
        .unwrap_err();
        assert!(e.contains("canister_ids[\"backend\"] is not a valid principal"), "{e}");
        let e = by_path(serde_json::json!({
            "bundle_path": "/b", "environment": "ic", "subnet": "nope"
        }))
        .unwrap_err();
        assert!(e.contains("subnet"), "{e}");
        let e =
            by_path(serde_json::json!({ "bundle_path": "/b", "environment": " " })).unwrap_err();
        assert!(e.contains("environment"), "{e}");
        // An upload's deploy is held to the same, before the upload is taken.
        let e = by_upload(serde_json::json!({
            "bundle_upload": "abc", "environment": "ic", "mode": "yolo"
        }))
        .unwrap_err();
        assert!(e.contains("mode") && e.contains("yolo"), "{e}");
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
