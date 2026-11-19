//! The deploy tools on the hosted server, for an embedder that turns them
//! on ([`McpServer::with_deploy`]; the bundled binary always does): the
//! core surface served with [`imcp2_core::deploy`]'s tools beside it, a bundle
//! upload route, and a transport that streams a deploy's progress and tells
//! it when the client has gone.
//!
//! Three things differ from the rest of the MCP endpoint:
//!
//!   * **The response framing of a deploy call.** The endpoint answers a POST
//!     with plain JSON, the one message the handler returns. A deploy reports
//!     each phase as a notification *before* its result, which plain JSON
//!     cannot carry — in rmcp's JSON mode the first message out would be
//!     taken for the result. So a `tools/call` of `icp_deploy_bundle` is
//!     handed to a second rmcp service configured for Server-Sent-Events
//!     responses, still stateless, whose stream carries every notification
//!     and then the result; every other request keeps the JSON service. The
//!     dispatch reads the JSON-RPC method and tool name off the buffered body.
//!   * **The client going away.** The SSE response body is wrapped so that
//!     its drop — the client disconnecting, or the stream ending — cancels a
//!     token the deploy tool watches ([`ClientGone`]): a deploy nobody will
//!     read the answer of stops at its next step. The same token is how a
//!     client's `notifications/cancelled` reaches the deploy it names, which
//!     the stateless transport would otherwise drop unread: the dispatch
//!     keeps each running deploy call's token by its session and JSON-RPC
//!     id, and cancels the one a cancellation from that session names.
//!   * **How the bundle arrives.** The agent's machine cannot hand this server
//!     a file, and a tool call carries only what the model writes, so an
//!     archive is `PUT` to `{mcp_path}/deploy/upload` on a one-time ticket that
//!     `icp_deploy_upload` mints inside an authenticated call (see
//!     [`imcp2_core::deploy::Uploads`] for the ticket's properties). The route is
//!     outside the bearer gate — the ticket is its authentication — and
//!     the body is extracted as it arrives, never kept, and stopped at the
//!     byte that takes the archive, or what it extracts to, past its limit.
//!     The upload is the only way in: the deploy tool here lists
//!     `bundle_upload` and refuses a `bundle_path`, so the server opens no
//!     file a caller names.
//!
//! The working directories and uploads live under the state directory
//! (`{state_dir}/deploys`), each readable by the server's user alone.
//!
//! What a process shares across the endpoints it serves the tools at — the
//! deploy slots, the upload store, the word that the server is stopping — is
//! one [`Deploys`], made once and handed to each [`McpServer`]: the caps are
//! on the process, whose memory and disk they protect. It also bounds what
//! the directory holds over time (see [`Deploys::new`] and
//! [`Deploys::spawn_sweeper`]).
//!
//! An embedder turns the tools on by making one [`Deploys`] as the process
//! starts and handing a clone to each server: everything it sets is a field
//! of [`DeployConfig`] (no environment variable is read here), and the
//! sweeper starts with [`McpServer::spawn_session_reaper`].
//!
//! Stopping is the one thing to get in the right order. An embedder that
//! drains in-flight requests calls [`Deploys::stop`] *before* the drain: a
//! deploy lasts minutes, so a drain that began first would wait on deploys
//! nothing had told to stop, and whatever cuts the drain short would cut
//! them off with their answers unsent. [`McpServer::shutdown`] stops them
//! too, which covers an embedder that does not drain and is the backstop
//! for one that does. And before shutting down or exiting, it waits for the
//! deploys to have ended ([`Deploys::stopped`], a bounded wait): one that is
//! waiting on a canister call in flight, its client gone, holds no
//! connection open for a drain to wait on.
//!
//! ```rust,no_run
//! # async fn serve(
//! #     config: imcp2::McpConfig,
//! #     signal: impl std::future::Future<Output = ()>,
//! # ) -> std::io::Result<()> {
//! use imcp2::deploy::{DeployConfig, Deploys};
//!
//! // Once per process, over the state directory the servers share. An
//! // error is a state directory another running server owns.
//! let config_for_deploys = DeployConfig { concurrent: 1, ..Default::default() };
//! let deploys = Deploys::new(&config_for_deploys, &config.state_dir)?;
//! let server = imcp2::McpServer::new(config).with_deploy(deploys.clone());
//! server.spawn_session_reaper(); // the deploy sweeper with it
//! // ... serve `server.mcp_router()` ...
//! signal.await;
//! deploys.stop(); // before draining in-flight requests
//! // ... drain ...
//! deploys.stopped().await; // each deploy has ended, or been given its time
//! server.shutdown();
//! # Ok(()) }
//! ```

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::put,
    Json, Router,
};
use futures_util::{StreamExt, TryStreamExt};
use imcp2_core::deploy::{
    ClientGone, DeploySlots, IcDeployTools, ReceiveError, Uploads, WithDeploy, TICKET_HEADER,
};
use rmcp::transport::{
    streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
    StreamableHttpServerConfig,
};
use tokio_util::sync::CancellationToken;

use crate::{
    auth,
    metrics::deploy::{DeployMetrics, Upload},
    tools::IcTools,
    McpServer,
};

/// What a hosted deployment configures of the deploy tools.
#[derive(Clone, Debug)]
pub struct DeployConfig {
    /// How many deploys run at once across every session (one per session
    /// either way); past it a deploy is refused, not queued. At least one: a
    /// zero is read as one.
    pub concurrent: usize,
    /// The cap on an uploaded archive, compressed, in bytes. No more than
    /// [`Self::max_extracted_bytes`]: more is read as that.
    pub max_upload_bytes: usize,
    /// The cap on what one bundle comes to on this server, in bytes: what
    /// its archive extracts to, and with that the copy of each canister's
    /// module its deploy keeps beside it. Counted as what the files and
    /// directories occupy ([`imcp2_core::deploy::occupies`]) — whole blocks, and
    /// an entry each — which is what they cost where the state directory is
    /// a RAM filesystem. An upload is extracted as it arrives and stopped at
    /// the byte that passes this.
    pub max_extracted_bytes: usize,
    /// The cap on every bundle the server has at once, extracted, in bytes:
    /// one that is arriving or being deployed counts as
    /// [`Self::max_extracted_bytes`], one that is waiting as what it came
    /// to. Past it an upload is refused, and a deploy that has no room to
    /// run in. `None` is one bundle for each deploy that runs at once and
    /// one more, arriving or waiting; less than one bundle is read as one.
    ///
    /// Together with [`Self::concurrent`] this is what the deploy tools
    /// keep under the state directory, and so — on a RAM filesystem — what
    /// they hold of the process's memory besides its heap.
    pub max_stored_bytes: Option<usize>,
    /// Sync plugins this server runs besides the ones it knows
    /// ([`imcp2_core::deploy::KNOWN_PLUGINS`]), each by the sha256 of its module,
    /// in hex: for a plugin release newer than this build. A sync plugin is
    /// a program the bundle brings and the server runs, inside its own
    /// process, so a bundle that carries one not listed is refused — on the
    /// upload, and again by the deploy. Adding a hash here is vouching for
    /// that program.
    pub allowed_plugins: Vec<String>,
}

impl Default for DeployConfig {
    /// Two deploys at once, archives of 64 MiB, bundles of 128 MiB, and
    /// three of those in all.
    fn default() -> Self {
        Self {
            concurrent: 2,
            max_upload_bytes: imcp2_core::deploy::DEFAULT_MAX_UPLOAD_BYTES,
            max_extracted_bytes: imcp2_core::deploy::DEFAULT_MAX_EXTRACTED_BYTES,
            max_stored_bytes: None,
            allowed_plugins: Vec::new(),
        }
    }
}

impl DeployConfig {
    /// How large a bundle this takes.
    pub fn limits(&self) -> imcp2_core::deploy::BundleLimits {
        imcp2_core::deploy::BundleLimits::new(
            self.max_upload_bytes as u64,
            self.max_extracted_bytes as u64,
        )
    }

    /// What the server holds of bundles in all, extracted:
    /// [`Self::max_stored_bytes`], or its default.
    pub fn stored_bytes(&self) -> u64 {
        let bundle = self.max_extracted_bytes as u64;
        match self.max_stored_bytes {
            Some(bytes) => (bytes as u64).max(bundle),
            None => bundle.saturating_mul(self.concurrent.max(1) as u64 + 1),
        }
    }
}

/// How long the record of a deploy (the ids it had created) is kept for
/// someone to come for: one that was interrupted, or that created canisters
/// and may not have got its answer to its client.
pub const DEPLOY_RECORD_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How often the sweeper looks for what has lapsed.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// What a process's deploy endpoints share: the slots deploys run in, the
/// store uploads are received into, and the word that the server is
/// stopping. Cheap to clone; made once per process and handed to every
/// [`McpServer`] that serves the tools ([`McpServer::with_deploy`]).
#[derive(Clone)]
pub struct Deploys {
    slots: DeploySlots,
    uploads: Uploads,
    /// `{state_dir}/deploys`: each deploy's working directory, and `uploads`.
    dir: std::path::PathBuf,
    stopping: CancellationToken,
    /// The lock on `dir` that makes this process its one owner; released
    /// when the last clone goes.
    _owned: Arc<std::fs::File>,
    /// Whether the sweeper has been started: one per process, however many
    /// instances ask for it.
    sweeping: Arc<AtomicBool>,
    /// Where deploys and uploads are counted, once a [`crate::metrics::Metrics`]
    /// has been made over a server with this state; until then, nowhere.
    metrics: Reporting,
}

/// The collectors a process's deploy state reports to, set once (see
/// [`crate::metrics::Metrics::new`]). It is the deploy tools' observer
/// itself, so the tools are built before the collectors exist and report to
/// them from the moment they do.
#[derive(Clone, Default)]
struct Reporting(Arc<OnceLock<DeployMetrics>>);

impl imcp2_core::deploy::DeployObserver for Reporting {
    fn refused(&self, why: imcp2_core::deploy::Refused) {
        if let Some(metrics) = self.0.get() {
            metrics.refused(why);
        }
    }

    fn ended(&self, how: imcp2_core::deploy::Ended, lasted: Duration) {
        if let Some(metrics) = self.0.get() {
            metrics.ended(how, lasted);
        }
    }
}

/// The file in the deploy directory whose lock says a process owns it.
const LOCK_FILE: &str = ".lock";

/// How long past [`imcp2_core::deploy::STOP_GRACE`] a stopping server waits for
/// its deploys to have ended: the grace is each deploy's own, and what comes
/// after it — reading the ids back, cutting the directory down, answering —
/// takes a moment more.
const STOP_MARGIN: Duration = Duration::from_secs(5);

impl Deploys {
    /// The deploy state under `state_dir` — the state directory of every
    /// [`McpServer`] this is handed to — as `config` bounds it.
    ///
    /// Made as the process starts, before a deploy runs, it clears what an
    /// earlier process left: uploads nothing can deploy any more are removed,
    /// and the directory of each deploy that was cut off — still holding its
    /// whole bundle — is cut down to the ids it recorded.
    ///
    /// That clearing is why the directory is locked first, for as long as
    /// this (or a clone) lives: to a second process started over the same
    /// state directory, the uploads and deploys of the first — alive, and
    /// in the middle of them — would look like what a dead one left. It is
    /// refused here instead, having touched nothing.
    ///
    /// Also an error: an entry of [`DeployConfig::allowed_plugins`] that is
    /// not a sha256 (a list read wrong is not run with), and a state
    /// directory whose path is not UTF-8, which the deploy tools could not
    /// work in.
    pub fn new(config: &DeployConfig, state_dir: &Path) -> std::io::Result<Self> {
        let plugins = imcp2_core::deploy::AllowedPlugins::known_and(&config.allowed_plugins)
            .map_err(|why| std::io::Error::new(std::io::ErrorKind::InvalidInput, why))?;
        let dir = state_dir.join("deploys");
        let owned = Arc::new(own_directory(&dir)?);
        // Named as every deploy will name it, and refused here — before
        // anything in it is cleared — if a deploy could not: the deploy
        // tools work with UTF-8 paths alone.
        let dir = dir.canonicalize()?;
        if dir.to_str().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("the deploy directory '{}' is not a UTF-8 path", dir.display()),
            ));
        }
        // The store holds the lock too, for as long as it or a thread
        // extracting a bundle into it lives: an upload outlives the request
        // that started it, and so may outlive every handle on this.
        let uploads =
            Uploads::with_budget(dir.join("uploads"), config.limits(), config.stored_bytes())
                .allowing(plugins)
                .held_with(owned.clone());
        let cut_off = imcp2_core::deploy::prune_abandoned_deploys(&dir);
        if cut_off > 0 {
            tracing::info!(
                dir = %dir.display(),
                cut_off,
                "kept the ids of deploys an earlier run was stopped in"
            );
        }
        Ok(Self {
            slots: DeploySlots::new(config.concurrent),
            uploads,
            dir,
            stopping: CancellationToken::new(),
            _owned: owned,
            sweeping: Arc::default(),
            metrics: Reporting::default(),
        })
    }

    /// Wait for the deploys that were running at [`Self::stop`] to have
    /// ended, and say whether they all did. Call it after the stop — and
    /// after draining in-flight requests, where a server does — and before
    /// [`McpServer::shutdown`] or exiting.
    ///
    /// A drain does not cover this. A stopped deploy with a canister call
    /// in flight waits for the answer (up to [`imcp2_core::deploy::STOP_GRACE`]),
    /// because the answer is what names a canister the call created; and
    /// one whose client has already gone has no connection for a drain to
    /// wait on. A process that exited then would lose that canister after
    /// all. The wait is bounded — the grace and a margin — so a deploy that
    /// will not end cannot hold the process: `false` says one was left.
    pub async fn stopped(&self) -> bool {
        let within = imcp2_core::deploy::STOP_GRACE + STOP_MARGIN;
        tokio::time::timeout(within, self.slots.idle()).await.is_ok()
    }

    /// Count this state's deploys and uploads in `metrics` from now on. The
    /// first call decides: a second set of collectors is left unfed rather
    /// than each event being split between two.
    pub(crate) fn report_to(&self, metrics: DeployMetrics) {
        let _ = self.metrics.0.set(metrics);
    }

    /// What is read rather than counted: the deploys running, the slots
    /// there are, and what the upload store holds.
    pub(crate) fn gauges(&self) -> (usize, usize, imcp2_core::deploy::Held) {
        (self.slots.running(), self.slots.total(), self.uploads.held())
    }

    /// Say that the server is stopping: every running deploy is interrupted
    /// at its next step and answers with the canisters it had created, and
    /// no new one begins. Call it when the shutdown signal arrives, *before*
    /// draining in-flight requests: a deploy lasts minutes, and a drain that
    /// waited one out would be cut short by whatever stops the process, the
    /// deploy with it and its answer unsent. Also ends the sweeper.
    ///
    /// Uploads are stopped with them: one asked for from now on is refused,
    /// and one still arriving is given up on, so that a slow body cannot
    /// hold the drain past what the process is given to stop.
    ///
    /// This only says so: it returns at once, and a deploy with a canister
    /// call in flight goes on until that call is answered. Await
    /// [`Self::stopped`] for the deploys to have ended, before exiting.
    ///
    /// [`McpServer::shutdown`] calls it as well, so no server is shut down
    /// with its deploys untold, whether or not its embedder drains; one
    /// that does drain calls this first, for the answers to be sent.
    pub fn stop(&self) {
        self.stopping.cancel();
        self.uploads.stop();
    }

    /// Start the periodic sweep that keeps the deploy directory bounded on
    /// an idle server: uploads past their time are removed (the store sweeps
    /// only when it is used), and so are the deploy records older than
    /// [`DEPLOY_RECORD_TTL`]. Ends with [`Self::stop`]. Must be
    /// called from within a tokio runtime.
    ///
    /// [`McpServer::spawn_session_reaper`] calls it, so an embedder has no
    /// second task to remember; the first call starts the one sweeper and
    /// later ones (another instance on the same state) do nothing.
    pub fn spawn_sweeper(&self) {
        if self.sweeping.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = this.stopping.cancelled() => break,
                    _ = tick.tick() => {
                        let this = this.clone();
                        let _ = tokio::task::spawn_blocking(move || this.sweep()).await;
                    }
                }
            }
        });
    }

    /// One sweep; see [`Self::spawn_sweeper`].
    fn sweep(&self) {
        self.uploads.sweep();
        let removed = imcp2_core::deploy::remove_old_deploy_records(&self.dir, DEPLOY_RECORD_TTL);
        if removed > 0 {
            tracing::info!(removed, "removed the records of old deploys");
        }
    }
}

/// Make `dir` and take the lock that says this process owns it, or say why
/// not: another process holds it.
fn own_directory(dir: &Path) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(LOCK_FILE);
    let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            format!(
                "the deploy directory '{}' belongs to another running server (it holds the \
                 lock '{}'): two servers cannot share a state directory, since each would \
                 clear the other's uploads and deploys as leftovers",
                dir.display(),
                path.display()
            ),
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

/// The path, under the MCP mount, an archive is `PUT` to.
pub const UPLOAD_PATH: &str = "/deploy/upload";

/// The most of a request body the dispatch buffers to read the method and
/// tool name: an MCP request is small JSON, and a bundle never rides inline
/// here. (The body cap in front of the endpoint, where there is one, holds
/// it lower still.)
const DISPATCH_MAX_BODY: usize = 4 * 1024 * 1024;

type McpService = StreamableHttpService<WithDeploy<IcTools>, LocalSessionManager>;

/// The two transports and the upload store behind the deploy-aware endpoint.
pub(crate) struct DeployMcp {
    json: McpService,
    sse: McpService,
    uploads: Uploads,
    /// The lock on the deploy directory, held for as long as a router made
    /// from this is: a router outlives the [`Deploys`] it was made from if
    /// its embedder lets it, and goes on receiving uploads and running
    /// deploys in the directory — which a second server, finding the lock
    /// free, would clear as leftovers.
    _owned: Arc<std::fs::File>,
    metrics: Reporting,
    /// The deploy calls running: see [`InFlight`].
    in_flight: InFlight,
}

/// The deploy calls whose response is still being sent, each by the session
/// that made it and the JSON-RPC id it was made under — what a
/// `notifications/cancelled` names — with the token that stops it.
/// Each entry carries the number its call was given, so that a call gives up
/// its own place and not one a later call under the same id took.
type InFlight = Arc<Mutex<HashMap<(String, String), (u64, CancellationToken)>>>;

/// Numbers the deploy calls [`InFlight`] keeps.
static NEXT_CALL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl McpServer {
    /// The MCP endpoint with the deploy tools, as two routers: the dispatch
    /// between the JSON and SSE transports, for the caller to put behind the
    /// bearer gate, and the upload route, which goes outside it (the ticket
    /// is its authentication). `transport` is the endpoint's configuration
    /// as the plain endpoint would use it.
    pub(crate) fn deploy_mcp_routers(
        &self,
        deploys: &Deploys,
        transport: StreamableHttpServerConfig,
    ) -> (Router, Router) {
        let uploads = deploys.uploads.clone();
        let upload_url = format!("{}{}{UPLOAD_PATH}", self.public_url, self.mcp_path);
        // The slots, the store and the stop are the process's, shared with
        // every other endpoint and every router built from this server.
        let deploy = IcDeployTools::new(self.identities.clone(), auth::bearer_session_resolver())
            .with_slots(deploys.slots.clone())
            .stopped_by(deploys.stopping.clone())
            .deploys_in(&deploys.dir)
            // `Deploys::new` made the directory and refused a path that is
            // not UTF-8, which is all this can fail on.
            .unwrap_or_else(|e| panic!("the deploy directory, checked as it was made: {e}"))
            .with_uploads(uploads.clone(), upload_url)
            .observed_by(Arc::new(deploys.metrics.clone()));
        let service = |transport: StreamableHttpServerConfig| {
            let (agent, identities, deploy) =
                (self.agent.clone(), self.identities.clone(), deploy.clone());
            StreamableHttpService::new(
                move || {
                    Ok(WithDeploy::new(
                        IcTools::new(
                            agent.clone(),
                            identities.clone(),
                            auth::bearer_session_resolver(),
                        ),
                        deploy.clone(),
                    ))
                },
                LocalSessionManager::default().into(),
                transport,
            )
        };
        let mcp = Arc::new(DeployMcp {
            json: service(transport.clone().with_json_response(true)),
            sse: service(transport.with_json_response(false)),
            uploads,
            _owned: deploys._owned.clone(),
            metrics: deploys.metrics.clone(),
            in_flight: InFlight::default(),
        });
        (
            Router::new().fallback(dispatch).with_state(mcp.clone()),
            Router::new().route(UPLOAD_PATH, put(upload)).with_state(mcp),
        )
    }
}

/// Hand a deploy call to the SSE transport, with its response body watched
/// for the client going away, and everything else to the JSON transport.
async fn dispatch(State(mcp): State<Arc<DeployMcp>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, DISPATCH_MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
    };
    let post = parts.method == Method::POST;
    let deploy_call = post && is_deploy_call(&bytes);
    // Who is asking, as the bearer gate in front of this established: a
    // cancellation reaches only the calls of the session that sends it.
    let session = parts.extensions.get::<auth::AuthedSession>().map(|s| s.session_id.clone());
    if post {
        // The transport acknowledges a notification and drops it, so the
        // deploy a cancellation names is stopped here, before it goes on.
        if let Some(session) = &session {
            cancel_named(&mcp.in_flight, session, &bytes);
        }
    }
    let mut request = Request::from_parts(parts, Body::from(bytes.clone()));
    if !deploy_call {
        return mcp.json.handle(request).await.into_response();
    }
    let gone = CancellationToken::new();
    request.extensions_mut().insert(ClientGone(gone.clone()));
    // Kept by session and request id while the call runs, for a
    // cancellation to find; a call without either can be stopped only by
    // its client going away.
    let registered = session.and_then(|session| register(&mcp.in_flight, session, &bytes, &gone));
    let response = mcp.sse.handle(request).await;
    cancel_on_drop(response.into_response(), gone, registered)
}

/// Keep the deploy call in `body`, made by `session`, in `in_flight` with
/// `stop`, for a cancellation to find; `None` for a call with no id.
fn register(
    in_flight: &InFlight,
    session: String,
    body: &[u8],
    stop: &CancellationToken,
) -> Option<Registered> {
    let key = (session, request_id(body)?);
    // A second call under an id still running is the client's mistake: a
    // cancellation naming the id then stops the later one.
    let call = NEXT_CALL.fetch_add(1, Ordering::Relaxed);
    in_flight.lock().unwrap_or_else(|e| e.into_inner()).insert(key.clone(), (call, stop.clone()));
    Some(Registered { in_flight: in_flight.clone(), key, call })
}

/// If `body` is a `notifications/cancelled` from `session`, stop the deploy
/// call of that session's it names, if one is running.
fn cancel_named(in_flight: &InFlight, session: &str, body: &[u8]) {
    let Some(id) = cancelled_request(body) else { return };
    let key = (session.to_string(), id);
    let stop =
        in_flight.lock().unwrap_or_else(|e| e.into_inner()).get(&key).map(|(_, stop)| stop.clone());
    if let Some(stop) = stop {
        tracing::info!(session, request = %key.1, "deploy cancelled by the client");
        stop.cancel();
    }
}

/// A deploy call's place in [`InFlight`], given up when its response body
/// goes — the call has answered, or its client is gone.
struct Registered {
    in_flight: InFlight,
    key: (String, String),
    /// The number this call was registered under: an entry a later call
    /// under the same id put in its place is that call's, and stays.
    call: u64,
}

impl Drop for Registered {
    fn drop(&mut self) {
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if in_flight.get(&self.key).is_some_and(|(call, _)| *call == self.call) {
            in_flight.remove(&self.key);
        }
    }
}

/// The JSON-RPC id of the request in `body`, as its JSON text (the form a
/// `notifications/cancelled` repeats it in), if it has one.
fn request_id(body: &[u8]) -> Option<String> {
    let message = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let id = message.get("id").filter(|id| id.is_string() || id.is_number())?;
    Some(id.to_string())
}

/// The id of the request `body` cancels, as its JSON text, when `body` is a
/// `notifications/cancelled`.
fn cancelled_request(body: &[u8]) -> Option<String> {
    let message = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    if message["method"] != "notifications/cancelled" {
        return None;
    }
    let id = &message["params"]["requestId"];
    (id.is_string() || id.is_number()).then(|| id.to_string())
}

/// Whether `body` is a JSON-RPC `tools/call` of `icp_deploy_bundle`.
fn is_deploy_call(body: &[u8]) -> bool {
    let Ok(message) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    message["method"] == "tools/call" && message["params"]["name"] == "icp_deploy_bundle"
}

/// `response` with its body wrapped so that dropping the body — the client
/// disconnecting, or the stream ending — cancels `gone`, and gives up the
/// call's place in [`InFlight`] if it has one.
fn cancel_on_drop(
    response: Response,
    gone: CancellationToken,
    registered: Option<Registered>,
) -> Response {
    let (parts, body) = response.into_parts();
    // Dropped in order: the token is cancelled, then the place given up.
    let guard = (gone.drop_guard(), registered);
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), guard),
        |(mut data, guard)| async move { data.next().await.map(|item| (item, (data, guard))) },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

/// What a successful `PUT` answers with: the id to deploy, what the bundle
/// extracted to and what its archive was, in bytes, and how long it is held.
#[derive(serde::Serialize)]
struct Uploaded {
    upload_id: String,
    bytes: u64,
    archive_bytes: u64,
    expires_in_secs: u64,
}

/// Counts an upload as a body that never arrived if it is dropped before
/// the receive has answered; see [`upload`].
struct Abandoned(Option<Reporting>);

impl Abandoned {
    /// The receive answered: its own outcome is the one to count.
    fn answered(mut self) {
        self.0 = None;
    }
}

impl Drop for Abandoned {
    fn drop(&mut self) {
        if let Some(metrics) = self.0.take().as_ref().and_then(|m| m.0.get()) {
            metrics.upload(Upload::BodyError);
        }
    }
}

/// Receive a bundle on the ticket in [`TICKET_HEADER`]: the body is
/// extracted as it arrives, and the answer may come before the body has
/// ended — at the byte that passes a limit, or the entry a bundle never
/// carries — with the rest unread.
async fn upload(State(mcp): State<Arc<DeployMcp>>, request: Request) -> Response {
    let count = |outcome: Upload| {
        if let Some(metrics) = mcp.metrics.0.get() {
            metrics.upload(outcome);
        }
    };
    let Some(ticket) = request.headers().get(TICKET_HEADER).and_then(|v| v.to_str().ok()) else {
        count(Upload::BadTicket);
        return (
            StatusCode::UNAUTHORIZED,
            format!("send the upload ticket in the {TICKET_HEADER} header"),
        )
            .into_response();
    };
    let ticket = ticket.trim().to_string();
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let reader = tokio_util::io::StreamReader::new(
        request.into_body().into_data_stream().map_err(std::io::Error::other),
    );
    // A request abandoned mid-body never returns from the receive: its
    // future is dropped where it waits. That is a body that did not arrive,
    // and is counted as one, by the guard, unless the receive answers.
    let abandoned = Abandoned(Some(mcp.metrics.clone()));
    let received = mcp.uploads.receive(&ticket, declared, reader).await;
    abandoned.answered();
    count(match &received {
        Ok(received) => {
            Upload::Accepted { archive_bytes: received.archive_bytes, bytes: received.bytes }
        }
        Err(ReceiveError::UnknownTicket) => Upload::BadTicket,
        Err(ReceiveError::TooLarge(_)) => Upload::TooLarge,
        Err(ReceiveError::ExtractsTooLarge(_)) => Upload::ExtractsTooLarge,
        Err(ReceiveError::Busy) => Upload::SessionBusy,
        Err(ReceiveError::Full) => Upload::StoreFull,
        Err(ReceiveError::Body(_)) => Upload::BodyError,
        Err(ReceiveError::NotABundle(_)) => Upload::NotABundle,
        Err(ReceiveError::PluginNotAllowed(_)) => Upload::PluginNotAllowed,
        Err(ReceiveError::Storage(_)) => Upload::StorageError,
        Err(ReceiveError::Stopping) => Upload::Stopping,
    });
    match received {
        Ok(received) => (
            StatusCode::CREATED,
            Json(Uploaded {
                upload_id: received.upload_id,
                bytes: received.bytes,
                archive_bytes: received.archive_bytes,
                expires_in_secs: received.expires_in.as_secs(),
            }),
        )
            .into_response(),
        Err(e @ ReceiveError::UnknownTicket) => {
            (StatusCode::FORBIDDEN, e.to_string()).into_response()
        }
        // Either size: the archive's own, or what it extracts to. The body
        // says which, and the count keeps them apart.
        Err(e @ (ReceiveError::TooLarge(_) | ReceiveError::ExtractsTooLarge(_))) => {
            (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response()
        }
        // Read, and not a bundle, or one with a sync plugin this server
        // does not run: nothing a retry of the same file changes.
        Err(e @ (ReceiveError::NotABundle(_) | ReceiveError::PluginNotAllowed(_))) => {
            (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response()
        }
        Err(e @ ReceiveError::Busy) => (StatusCode::CONFLICT, e.to_string()).into_response(),
        Err(e @ ReceiveError::Full) => {
            (StatusCode::INSUFFICIENT_STORAGE, e.to_string()).into_response()
        }
        Err(e @ ReceiveError::Body(_)) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        // The server's fault, and said so: a full disk or an unwritable
        // directory is not a request the client can correct.
        Err(e @ ReceiveError::Storage(_)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
        // Not the request's fault, and over once the server is back.
        Err(e @ ReceiveError::Stopping) => {
            (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, IiInstance, McpConfig, SharedClients, IC_URL};
    use axum::http::Request;
    use tower::ServiceExt;

    fn config() -> DeployConfig {
        DeployConfig {
            concurrent: 2,
            max_upload_bytes: 2048,
            max_extracted_bytes: 64 * 1024,
            max_stored_bytes: None,
            allowed_plugins: Vec::new(),
        }
    }

    /// The smallest bundle there is: an archive of a manifest. It extracts
    /// to [`BUNDLE_BYTES`].
    fn bundle() -> Vec<u8> {
        let manifest = b"canisters: []\n";
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "icp.yaml", &manifest[..]).unwrap();
        archive.into_inner().unwrap().finish().unwrap()
    }

    /// A bundle of one canister synced by a plugin nobody vouched for.
    fn bundle_with_plugin() -> Vec<u8> {
        // The loader does not check the module against its checksum (the
        // deploy does): any sha256 will do here.
        let canister = format!(
            "name: frontend\nbuild:\n  steps:\n    - type: pre-built\n      path: frontend.wasm\n      \
             sha256: {}\nsync:\n  steps:\n    - type: plugin\n      path: sync.wasm\n",
            "0".repeat(64)
        );
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, data) in [
            ("icp.yaml", &b"canisters:\n  - canisters/frontend\n"[..]),
            ("canisters/frontend/canister.yaml", canister.as_bytes()),
            ("canisters/frontend/frontend.wasm", &b"\0asm\x01\0\0\0"[..]),
            ("canisters/frontend/sync.wasm", &b"\0asm a plugin nobody vouched for"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, path, data).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    /// What [`bundle`] extracts to: one file, a block and an entry.
    const BUNDLE_BYTES: u64 = imcp2_core::deploy::BLOCK_BYTES + imcp2_core::deploy::ENTRY_BYTES;

    fn server() -> (tempfile::TempDir, McpServer) {
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let server = server_in(dir.path(), "/mcp", deploys);
        (dir, server)
    }

    fn server_in(state_dir: &Path, mcp_path: &str, deploys: Deploys) -> McpServer {
        server_at(state_dir, mcp_path, deploys, IC_URL)
    }

    /// [`server_in`], with the IC endpoint the server calls at `ic_url`.
    fn server_at(state_dir: &Path, mcp_path: &str, deploys: Deploys, ic_url: &str) -> McpServer {
        let state_dir = state_dir.to_path_buf();
        McpServer::new(McpConfig {
            agent: Agent::builder().with_url(ic_url).build().expect("agent"),
            instance: IiInstance::prod().expect("prod instance"),
            public_url: "https://mcp.example.com".into(),
            mcp_path: mcp_path.into(),
            clients: SharedClients::load(&state_dir),
            state_dir,
            require_resource: true,
            cimd_enabled: false,
        })
        .with_deploy(deploys)
    }

    fn rpc(method: &str, params: serde_json::Value) -> String {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string()
    }

    async fn post(app: &Router, bearer: &str, body: String) -> Response {
        app.clone()
            .oneshot(
                Request::post("/")
                    .header("host", "mcp.example.com")
                    .header("authorization", bearer)
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn content_type(resp: &Response) -> String {
        resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap().to_string()
    }

    /// The whole loop over the composed router: the deploy tools are listed,
    /// a ticket is minted inside an authenticated call, the archive is PUT on
    /// it, and the deploy call — and only it — is answered as an event stream
    /// that carries the result.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_hosted_endpoint_serves_the_deploy_loop() {
        let (_dir, server) = server();
        let bearer = format!("Bearer {}", server.store.test_bearer().await);
        // The made-up session's grant has lapsed, so the identity a deploy
        // signs with is refused here, before anything is asked of Internet
        // Identity: the test stays on this machine.
        server.identities.set_grant_expiration("test-session", 1).await;
        let app = server.mcp_router();

        // tools/list stays plain JSON, and lists the deploy tools.
        let resp = post(&app, &bearer, rpc("tools/list", serde_json::json!({}))).await;
        let status = resp.status();
        let kind = content_type(&resp);
        if status != StatusCode::OK {
            panic!("tools/list: {status}: {}", text(resp).await);
        }
        assert!(kind.starts_with("application/json"), "{kind}");
        let listed: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for tool in ["open_app", "icp_deploy_bundle", "icp_deploy_upload", "icp_cycles_balance"] {
            assert!(names.contains(&tool), "{tool} must be listed: {names:?}");
        }
        assert!(!names.contains(&"authenticate"), "no login tool on the hosted server");
        // The bundle is an upload here, and the deploy tool lists it so.
        let deploy = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "icp_deploy_bundle")
            .unwrap();
        let properties = &deploy["inputSchema"]["properties"];
        assert!(properties["bundle_upload"].is_object(), "{properties}");
        assert!(properties["bundle_path"].is_null(), "{properties}");

        // A ticket, minted inside the authenticated call.
        let resp = post(
            &app,
            &bearer,
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_upload", "arguments": {} })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let answer: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let result = &answer["result"];
        assert_ne!(result["isError"], true, "{result}");
        let ticket = result["structuredContent"]["ticket"].as_str().unwrap().to_string();
        assert_eq!(
            result["structuredContent"]["upload_url"],
            "https://mcp.example.com/mcp/deploy/upload"
        );
        assert!(result["structuredContent"]["curl"].as_str().unwrap().contains(&ticket));

        // The PUT: refused without a ticket, with a wrong one, over the cap,
        // and for what is not a bundle; accepted on the ticket, once.
        let put = |ticket: Option<&str>, body: Vec<u8>| {
            let mut req = Request::put(UPLOAD_PATH);
            if let Some(t) = ticket {
                req = req.header(TICKET_HEADER, t);
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };
        assert_eq!(put(None, vec![1]).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(put(Some("bogus"), vec![1]).await.unwrap().status(), StatusCode::FORBIDDEN);
        let resp = put(Some(&ticket), vec![0; 2049]).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // The over-cap attempt spent the ticket: mint another.
        let resp = post(
            &app,
            &bearer,
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_upload", "arguments": {} })),
        )
        .await;
        let answer: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let ticket = answer["result"]["structuredContent"]["ticket"].as_str().unwrap().to_string();
        // The body is extracted as it arrives, so what is not a bundle is
        // refused here, on the upload, and that ticket is spent too.
        let resp = put(Some(&ticket), b"not a bundle".to_vec()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(text(resp).await.contains(".tar.gz"));
        let resp = post(
            &app,
            &bearer,
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_upload", "arguments": {} })),
        )
        .await;
        let answer: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let ticket = answer["result"]["structuredContent"]["ticket"].as_str().unwrap().to_string();
        let archive = bundle();
        let resp = put(Some(&ticket), archive.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let uploaded: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let upload_id = uploaded["upload_id"].as_str().unwrap().to_string();
        // What it extracted to, which is what the server keeps of it, and
        // what arrived.
        assert_eq!(uploaded["bytes"], BUNDLE_BYTES);
        assert_eq!(uploaded["archive_bytes"], archive.len());
        assert_eq!(put(Some(&ticket), vec![1]).await.unwrap().status(), StatusCode::FORBIDDEN);

        // A path is no way in: this server opens no file a caller names,
        // whether or not an upload comes with it, and the upload is not spent.
        for arguments in [
            serde_json::json!({ "bundle_path": "/etc/hostname", "environment": "ic" }),
            serde_json::json!({
                "bundle_path": "/etc/hostname", "bundle_upload": upload_id, "environment": "ic"
            }),
        ] {
            let call = serde_json::json!({ "name": "icp_deploy_bundle", "arguments": arguments });
            let stream = text(post(&app, &bearer, rpc("tools/call", call)).await).await;
            assert!(stream.contains("reads no bundle_path"), "{stream}");
        }

        // The deploy call is answered as an event stream carrying the result:
        // with a session whose grant has lapsed, the error that says to
        // reconnect — raised after the upload was found for this session,
        // which is what the next call shows.
        let resp = post(
            &app,
            &bearer,
            rpc(
                "tools/call",
                serde_json::json!({
                    "name": "icp_deploy_bundle",
                    "arguments": { "bundle_upload": upload_id, "environment": "ic" }
                }),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("text/event-stream"), "{}", content_type(&resp));
        let stream = text(resp).await;
        let data = stream
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|d| d.contains("\"result\""))
            .expect("the stream carries the result");
        let answer: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(answer["result"]["isError"], true, "{answer}");
        let said = answer["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!said.contains("no upload"), "the upload must be found: {said}");
        assert!(!said.contains("mcp_prepare_delegation"), "nothing is asked of II: {said}");
        // Spent with the deploy: a second deploy of the same upload finds none.
        let resp = post(
            &app,
            &bearer,
            rpc(
                "tools/call",
                serde_json::json!({
                    "name": "icp_deploy_bundle",
                    "arguments": { "bundle_upload": upload_id, "environment": "ic" }
                }),
            ),
        )
        .await;
        let stream = text(resp).await;
        assert!(stream.contains("no upload"), "{stream}");

        // Unauthenticated: the gate answers first, for the deploy call too.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/")
                    .header("host", "mcp.example.com")
                    .header("content-type", "application/json")
                    .body(Body::from(rpc(
                        "tools/call",
                        serde_json::json!({ "name": "icp_deploy_bundle", "arguments": {} }),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    async fn call(app: &Router, bearer: &str, tool: &str, arguments: serde_json::Value) -> String {
        let call = serde_json::json!({ "name": tool, "arguments": arguments });
        text(post(app, bearer, rpc("tools/call", call)).await).await
    }

    /// Two endpoints of one process, as the binary serves production and
    /// beta, and a router built twice from one of them: one upload store and
    /// one set of slots between them all, so the caps are the process's.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_endpoints_of_a_process_share_its_deploy_state() {
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let prod = server_in(dir.path(), "/mcp", deploys.clone());
        let beta = server_in(dir.path(), "/mcp-beta", deploys.clone());
        let bearer = format!("Bearer {}", prod.store.test_bearer().await);
        let (app, again) = (prod.mcp_router(), prod.mcp_router());

        // A ticket minted through one router is honoured by the other's
        // upload route: the store is not the router's own.
        let minted = call(&app, &bearer, "icp_deploy_upload", serde_json::json!({})).await;
        let minted: serde_json::Value = serde_json::from_str(&minted).unwrap();
        let ticket = minted["result"]["structuredContent"]["ticket"].as_str().unwrap();
        let put = Request::put(UPLOAD_PATH).header(TICKET_HEADER, ticket);
        let resp = again.oneshot(put.body(Body::from(bundle())).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Both slots held — by whichever endpoint — and neither has one left.
        let held = [deploys.slots.clone(), deploys.slots.clone()].map(|slots| {
            IcDeployTools::new(prod.identities.clone(), Arc::new(|_: &_| None))
                .with_slots(slots)
                .claim()
                .expect("a slot")
        });
        for (server, path) in [(&prod, "prod"), (&beta, "beta")] {
            let bearer = format!("Bearer {}", server.store.test_bearer().await);
            let said = call(
                &server.mcp_router(),
                &bearer,
                "icp_deploy_bundle",
                serde_json::json!({ "bundle_upload": "x", "environment": "ic" }),
            )
            .await;
            assert!(said.contains("as many deploys as it can"), "{path}: {said}");
        }
        drop(held);
    }

    /// The deploy series, fed by the real thing: uploads and deploy calls
    /// through the router, each landing in the one series that names what
    /// happened, with the gauges read off the state at a refresh. A handle
    /// made the way an embedder makes it — over the server, nothing more.
    #[tokio::test(flavor = "multi_thread")]
    async fn deploys_and_uploads_are_counted() {
        use prometheus::{Encoder, Registry, TextEncoder};
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let server = server_in(dir.path(), "/mcp", deploys.clone());
        let registry = Registry::new();
        let metrics = crate::metrics::Metrics::new(&registry, "0", "0", 0, &[&server]).unwrap();
        let scrape = || {
            let mut out = Vec::new();
            TextEncoder::new().encode(&registry.gather(), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let has = |out: &str, series: &str| {
            assert!(out.lines().any(|line| line == series), "no {series} in:\n{out}");
        };

        // Before anything happens every series is there, at zero, and the
        // cap is already known.
        let out = scrape();
        for series in [
            r#"imcp2_deploys_total{outcome="succeeded"} 0"#,
            r#"imcp2_deploys_total{outcome="interrupted"} 0"#,
            r#"imcp2_deploy_refusals_total{reason="busy"} 0"#,
            r#"imcp2_deploy_uploads_total{outcome="store_full"} 0"#,
            "imcp2_deploys_running 0",
            "imcp2_deploy_slots 2",
            // A bundle for each deploy at once, and one more.
            "imcp2_deploy_upload_store_capacity_bytes 196608",
        ] {
            has(&out, series);
        }

        let bearer = format!("Bearer {}", server.store.test_bearer().await);
        let app = server.mcp_router();
        // An upload with no ticket, and one with a ticket nobody minted.
        let put = |ticket: Option<&str>, body: Vec<u8>| {
            let mut put = Request::put(UPLOAD_PATH);
            if let Some(ticket) = ticket {
                put = put.header(TICKET_HEADER, ticket);
            }
            app.clone().oneshot(put.body(Body::from(body)).unwrap())
        };
        assert_eq!(put(None, vec![1]).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(put(Some("nope"), vec![1]).await.unwrap().status(), StatusCode::FORBIDDEN);
        // One that is received: extracted as it arrived, and held.
        let mint = || async {
            let minted = call(&app, &bearer, "icp_deploy_upload", serde_json::json!({})).await;
            let minted: serde_json::Value = serde_json::from_str(&minted).unwrap();
            minted["result"]["structuredContent"]["ticket"].as_str().unwrap().to_string()
        };
        let archive = bundle();
        let resp = put(Some(&mint().await), archive.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        metrics.refresh().await;
        let out = scrape();
        for series in [
            "imcp2_deploy_uploads_held 1".to_string(),
            // What the server keeps of it is what it extracted to.
            format!("imcp2_deploy_upload_store_bytes {BUNDLE_BYTES}"),
            "imcp2_deploy_upload_bytes_count 1".to_string(),
            format!("imcp2_deploy_upload_bytes_sum {}", archive.len()),
            "imcp2_deploy_bundle_extracted_bytes_count 1".to_string(),
            format!("imcp2_deploy_bundle_extracted_bytes_sum {BUNDLE_BYTES}"),
        ] {
            has(&out, &series);
        }

        // One that is read and is not a bundle, and one that extracts to
        // more than a bundle may: both refused on the upload, each counted
        // as what it was. (A megabyte of zeros is an archive of a kilobyte.)
        let resp = put(Some(&mint().await), b"not a bundle".to_vec()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let mut bomb = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::best(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(1 << 20);
        header.set_mode(0o644);
        header.set_cksum();
        bomb.append_data(&mut header, "icp.yaml", &vec![0u8; 1 << 20][..]).unwrap();
        let bomb = bomb.into_inner().unwrap().finish().unwrap();
        assert!(bomb.len() <= 1024 * 2, "{}", bomb.len());
        let resp = put(Some(&mint().await), bomb).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(text(resp).await.contains("extracts to more than"));

        // And a bundle with a sync plugin this server does not run: read,
        // a bundle, and refused for what it would have the server run.
        let resp = put(Some(&mint().await), bundle_with_plugin()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let said = text(resp).await;
        assert!(said.contains("is not one this server runs"), "{said}");
        assert!(said.contains("the static-site sync plugin, v1.0.0"), "{said}");

        // And one abandoned mid-body: the request is dropped while the
        // server waits for more, and no answer is ever made.
        let never_ends = futures_util::stream::once(async {
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"half"))
        })
        .chain(futures_util::stream::pending());
        let abandoned = Request::put(UPLOAD_PATH)
            .header(TICKET_HEADER, mint().await)
            .body(Body::from_stream(never_ends))
            .unwrap();
        let waited = Duration::from_millis(50);
        assert!(tokio::time::timeout(waited, app.clone().oneshot(abandoned)).await.is_err());

        // A deploy of an upload that does not exist holds a slot for as long
        // as it takes to say so: rejected, and timed.
        let deploy = serde_json::json!({ "bundle_upload": "x", "environment": "ic" });
        call(&app, &bearer, "icp_deploy_bundle", deploy.clone()).await;
        // With every slot held, the next is refused as busy; and once the
        // server is stopping, as that.
        let held = [(); 2].map(|()| {
            IcDeployTools::new(server.identities.clone(), Arc::new(|_: &_| None))
                .with_slots(deploys.slots.clone())
                .claim()
                .unwrap()
        });
        call(&app, &bearer, "icp_deploy_bundle", deploy.clone()).await;
        metrics.refresh().await;
        has(&scrape(), "imcp2_deploys_running 2");
        drop(held);
        deploys.stop();
        call(&app, &bearer, "icp_deploy_bundle", deploy).await;

        metrics.refresh().await;
        let out = scrape();
        for series in [
            r#"imcp2_deploy_uploads_total{outcome="bad_ticket"} 2"#,
            r#"imcp2_deploy_uploads_total{outcome="accepted"} 1"#,
            r#"imcp2_deploy_uploads_total{outcome="not_a_bundle"} 1"#,
            r#"imcp2_deploy_uploads_total{outcome="extracts_too_large"} 1"#,
            r#"imcp2_deploy_uploads_total{outcome="plugin_not_allowed"} 1"#,
            r#"imcp2_deploy_uploads_total{outcome="body_error"} 1"#,
            "imcp2_deploy_upload_bytes_count 1",
            r#"imcp2_deploys_total{outcome="rejected"} 1"#,
            "imcp2_deploy_duration_seconds_count 1",
            r#"imcp2_deploy_refusals_total{reason="busy"} 1"#,
            r#"imcp2_deploy_refusals_total{reason="stopping"} 1"#,
            r#"imcp2_deploy_refusals_total{reason="session_busy"} 0"#,
            "imcp2_deploys_running 0",
        ] {
            has(&out, series);
        }
    }

    /// A ticket for the made-up session, minted the way an agent gets one.
    async fn ticket(app: &Router, bearer: &str) -> String {
        let minted = call(app, bearer, "icp_deploy_upload", serde_json::json!({})).await;
        let answer: serde_json::Value = serde_json::from_str(&minted).unwrap();
        answer["result"]["structuredContent"]["ticket"].as_str().expect("a ticket").to_string()
    }

    /// `PUT` `body` on `ticket`.
    async fn put(app: &Router, ticket: &str, body: Vec<u8>) -> Response {
        let request = Request::put(UPLOAD_PATH).header(TICKET_HEADER, ticket);
        app.clone().oneshot(request.body(Body::from(body)).unwrap()).await.unwrap()
    }

    /// A deploy call in flight is cancelled by its client the way MCP has
    /// it: a `notifications/cancelled` naming the call's id, sent on its own
    /// request while the call's event stream stays open. Over the composed
    /// router — the bearer gate, the body cap, the dispatch and both
    /// transports — with nothing stubbed but the network: the server's IC
    /// endpoint is a listener that takes a connection and never answers, so
    /// the deploy is held at the first thing it asks of the network, the
    /// identity it would sign with.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancellation_notification_stops_the_deploy_call_in_flight() {
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ic_url = format!("http://{}", silent.local_addr().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let server = server_at(dir.path(), "/mcp", deploys.clone(), &ic_url);
        let bearer = format!("Bearer {}", server.store.test_bearer().await);
        let app = server.mcp_router();

        let uploaded = put(&app, &ticket(&app, &bearer).await, bundle()).await;
        assert_eq!(uploaded.status(), StatusCode::CREATED);
        let uploaded: serde_json::Value = serde_json::from_str(&text(uploaded).await).unwrap();

        // The deploy call, under an id of its own, left running.
        let deploy = serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {
                "name": "icp_deploy_bundle",
                "arguments": { "bundle_upload": uploaded["upload_id"], "environment": "ic" }
            }
        })
        .to_string();
        let mut deploying = tokio::spawn({
            let (app, bearer) = (app.clone(), bearer.clone());
            async move { text(post(&app, &bearer, deploy).await).await }
        });
        let began = std::time::Instant::now();
        while deploys.slots.running() == 0 {
            assert!(began.elapsed() < Duration::from_secs(30), "the deploy never began");
            assert!(!deploying.is_finished(), "the deploy ended before it could be cancelled");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let cancel = |id: u32| {
            serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": { "requestId": id, "reason": "the user stopped it" }
            })
            .to_string()
        };
        // A cancellation of some other call leaves this one running.
        let other = post(&app, &bearer, cancel(8)).await;
        assert_eq!(other.status(), StatusCode::ACCEPTED);
        let still = tokio::time::timeout(Duration::from_millis(300), &mut deploying).await;
        assert!(still.is_err(), "only the call named is cancelled");
        assert_eq!(deploys.slots.running(), 1);

        // Its own stops it: the call answers, on the stream it was given,
        // that it was interrupted, and its slot is free.
        let own = post(&app, &bearer, cancel(7)).await;
        assert_eq!(own.status(), StatusCode::ACCEPTED);
        let stream = tokio::time::timeout(Duration::from_secs(30), deploying)
            .await
            .expect("the cancelled deploy answers")
            .unwrap();
        let data = stream
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|d| d.contains("\"result\""))
            .unwrap_or_else(|| panic!("the stream carries the result: {stream}"));
        let answer: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(answer["id"], 7, "{answer}");
        assert_eq!(answer["result"]["isError"], true, "{answer}");
        let said = answer["result"]["content"][0]["text"].as_str().unwrap();
        assert!(said.contains("interrupted before it began"), "{said}");
        assert_eq!(deploys.slots.running(), 0, "the cancelled deploy gives its slot back");
        drop(silent);
    }

    /// A stopping server takes no upload: the `PUT` is refused as the
    /// server's doing, something to try again, and nothing of it is kept.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stopping_server_takes_no_upload() {
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let server = server_in(dir.path(), "/mcp", deploys.clone());
        let bearer = format!("Bearer {}", server.store.test_bearer().await);
        let app = server.mcp_router();
        let ticket = ticket(&app, &bearer).await;
        deploys.stop();
        let refused = put(&app, &ticket, bundle()).await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(text(refused).await.contains("restarting"));
        let (_, _, held) = deploys.gauges();
        assert_eq!((held.uploads, held.receiving, held.bytes), (0, 0, 0));
    }

    /// Once the server has said it is stopping, a deploy does not begin, and
    /// the upload it named is not spent on the refusal.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stopping_server_begins_no_deploy() {
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let server = server_in(dir.path(), "/mcp", deploys.clone());
        let bearer = format!("Bearer {}", server.store.test_bearer().await);
        let app = server.mcp_router();
        deploys.stop();
        let said = call(
            &app,
            &bearer,
            "icp_deploy_bundle",
            serde_json::json!({ "bundle_upload": "x", "environment": "ic" }),
        )
        .await;
        assert!(said.contains("restarting"), "{said}");
    }

    /// An embedder that only does what it did before the tools existed —
    /// start the reaper, shut the server down — has the sweeper running,
    /// once for the process, and its deploys stopped.
    #[tokio::test]
    async fn the_servers_own_lifecycle_runs_the_deploy_state() {
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let prod = server_in(dir.path(), "/mcp", deploys.clone());
        let beta = server_in(dir.path(), "/mcp-beta", deploys.clone());
        // Counted in tasks: nothing here yields, so on this one-thread
        // runtime every task spawned is still alive when it is counted.
        let tasks = || tokio::runtime::Handle::current().metrics().num_alive_tasks();
        let before = tasks();
        prod.spawn_session_reaper();
        assert_eq!(tasks() - before, 2, "the session reaper, and the sweeper with it");
        // A second instance on the same state starts no second sweeper.
        beta.spawn_session_reaper();
        assert_eq!(tasks() - before, 3, "its session reaper alone");
        assert!(!deploys.stopping.is_cancelled());
        prod.shutdown();
        assert!(deploys.stopping.is_cancelled(), "a shutdown stops the deploys");
    }

    /// What a start finds from the run before it: uploads nothing can deploy
    /// are gone, and a deploy that was cut off keeps its ids and nothing else.
    #[test]
    fn a_start_clears_what_the_run_before_left() {
        let dir = tempfile::tempdir().unwrap();
        let deploys_dir = dir.path().join("deploys");
        let upload = deploys_dir.join("uploads").join(format!("{}.tar.gz", "a".repeat(64)));
        let cut_off = deploys_dir.join("imcp2-deploy-abc123");
        let ids = cut_off.join(".icp/data/mappings/ic.ids.json");
        for (path, contents) in
            [(&upload, "archive"), (&cut_off.join("canisters/app.wasm"), "wasm"), (&ids, "{}")]
        {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        assert!(!upload.exists(), "an upload from the run before is removed");
        assert!(!cut_off.join("canisters").exists(), "the bundle's files are removed");
        assert!(ids.is_file(), "the ids are kept");
        // A sweep leaves a recent record where it is.
        deploys.sweep();
        assert!(ids.is_file());
    }

    /// A second server over a state directory in use is refused before it
    /// clears anything: what is there belongs to the first, which is alive.
    #[test]
    fn a_state_directory_has_one_server_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let first = Deploys::new(&config(), dir.path()).unwrap();
        let upload = dir.path().join("deploys/uploads").join(format!("{}.tar.gz", "a".repeat(64)));
        std::fs::write(&upload, "the first server's upload").unwrap();

        let Err(refused) = Deploys::new(&config(), dir.path()) else {
            panic!("a second server took a directory in use");
        };
        assert!(refused.to_string().contains("another running server"), "{refused}");
        assert!(upload.exists(), "the first server's upload is untouched");

        // A clone is the same server, and so is a router made from it, which
        // goes on serving after the handles it was made from have gone: the
        // directory is free once the last of them has.
        let clone = first.clone();
        let router = server_in(dir.path(), "/mcp", first.clone()).mcp_router();
        drop(first);
        assert!(Deploys::new(&config(), dir.path()).is_err());
        drop(clone);
        assert!(Deploys::new(&config(), dir.path()).is_err(), "a router is still serving");
        drop(router);
        Deploys::new(&config(), dir.path()).unwrap();
    }

    /// A stopping server waits for the deploy that is still ending.
    #[tokio::test(start_paused = true)]
    async fn a_stopping_server_waits_for_its_deploys_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let server = server_in(dir.path(), "/mcp", deploys.clone());
        let tools = IcDeployTools::new(server.identities.clone(), Arc::new(|_: &_| None))
            .with_slots(deploys.slots.clone());
        assert!(deploys.stopped().await, "nothing is running");

        let running = tools.claim().unwrap();
        let ending = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(running);
        });
        deploys.stop();
        assert!(deploys.stopped().await, "the deploy ended within the grace");
        ending.await.unwrap();

        // One that never ends is given the grace and a margin, no more.
        let _stuck = tools.claim().unwrap();
        let started = tokio::time::Instant::now();
        assert!(!deploys.stopped().await);
        assert_eq!(started.elapsed(), imcp2_core::deploy::STOP_GRACE + STOP_MARGIN);
    }

    /// Dropping the response body — what a disconnect does — fires the token.
    #[tokio::test]
    async fn dropping_the_response_body_says_the_client_has_gone() {
        let gone = CancellationToken::new();
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, axum::Error>>();
        let response = Response::new(Body::from_stream(pending));
        let watched = cancel_on_drop(response, gone.clone(), None);
        assert!(!gone.is_cancelled());
        drop(watched);
        assert!(gone.is_cancelled(), "the body's drop must cancel the token");
    }

    // A cancellation reaches the running deploy call it names — by its own
    // session and the call's JSON-RPC id, never another session's — and a
    // call gives up its place when its response goes.
    #[test]
    fn a_cancellation_stops_the_deploy_call_it_names() {
        let call = |id: serde_json::Value| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": "icp_deploy_bundle" }
            })
            .to_string()
        };
        let cancel = |id: serde_json::Value| {
            serde_json::json!({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": { "requestId": id, "reason": "user stopped it" }
            })
            .to_string()
        };
        let in_flight = InFlight::default();
        let stop = CancellationToken::new();
        let registered =
            register(&in_flight, "alice".into(), call(serde_json::json!(7)).as_bytes(), &stop);
        assert!(registered.is_some());

        cancel_named(&in_flight, "mallory", cancel(serde_json::json!(7)).as_bytes());
        assert!(!stop.is_cancelled(), "another session's cancellation is ignored");
        cancel_named(&in_flight, "alice", cancel(serde_json::json!(8)).as_bytes());
        cancel_named(&in_flight, "alice", cancel(serde_json::json!("7")).as_bytes());
        assert!(!stop.is_cancelled(), "another id, a string id is not a number");
        cancel_named(&in_flight, "alice", call(serde_json::json!(7)).as_bytes());
        assert!(!stop.is_cancelled(), "only a cancellation cancels");
        cancel_named(&in_flight, "alice", cancel(serde_json::json!(7)).as_bytes());
        assert!(stop.is_cancelled());

        drop(registered);
        assert!(in_flight.lock().unwrap().is_empty(), "the place is given up");

        // A later call under the same id keeps its place when the earlier
        // one's goes, and is the one a cancellation stops.
        let (first, second) = (CancellationToken::new(), CancellationToken::new());
        let body = call(serde_json::json!("a"));
        let earlier = register(&in_flight, "alice".into(), body.as_bytes(), &first);
        let later = register(&in_flight, "alice".into(), body.as_bytes(), &second);
        drop(earlier);
        cancel_named(&in_flight, "alice", cancel(serde_json::json!("a")).as_bytes());
        assert!(second.is_cancelled() && !first.is_cancelled());
        drop(later);
        assert!(in_flight.lock().unwrap().is_empty());

        assert!(register(&in_flight, "alice".into(), b"{\"method\":\"x\"}", &first).is_none());
    }

    // The deploy tools work in UTF-8 paths alone: a state directory whose
    // path is not one is refused as the state is made, with an error the
    // embedder can handle, and nothing in it is cleared.
    #[cfg(unix)]
    #[test]
    fn a_state_directory_that_is_not_utf8_is_refused_up_front() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(std::ffi::OsStr::from_bytes(b"state-\xff"));
        let leftover = state.join("deploys").join("uploads").join("a".repeat(64));
        if std::fs::create_dir_all(&leftover).is_err() {
            // A filesystem that takes UTF-8 names alone cannot hold one.
            return;
        }
        let err = Deploys::new(&config(), &state).err().expect("refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(leftover.exists(), "nothing cleared");
    }

    #[test]
    fn only_a_deploy_call_is_dispatched_to_the_event_stream() {
        assert!(is_deploy_call(
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_bundle" })).as_bytes()
        ));
        assert!(!is_deploy_call(
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_upload" })).as_bytes()
        ));
        assert!(!is_deploy_call(rpc("tools/list", serde_json::json!({})).as_bytes()));
        assert!(!is_deploy_call(b"not json"));
    }
}
