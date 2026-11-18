//! The deploy tools on the hosted server, behind the `deploy` feature: the
//! core surface served with [`imcp2_deploy`]'s tools beside it, a bundle
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
//!     read the answer of stops at its next step.
//!   * **How the bundle arrives.** The agent's machine cannot hand this server
//!     a file, and a tool call carries only what the model writes, so an
//!     archive is `PUT` to `{mcp_path}/deploy/upload` on a one-time ticket that
//!     `icp_deploy_upload` mints inside an authenticated call (see
//!     [`imcp2_deploy::Uploads`] for the ticket's properties). The route is
//!     outside the bearer gate — the ticket is its authentication — and
//!     streams the body to disk under its own cap. The upload is the only
//!     way in: the deploy tool here lists `bundle_upload` and refuses a
//!     `bundle_path`, so the server opens no file a caller names.
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
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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
use imcp2_deploy::{
    ClientGone, DeploySlots, IcDeployTools, ReceiveError, Uploads, WithDeploy, TICKET_HEADER,
};
use rmcp::transport::{
    streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
    StreamableHttpServerConfig,
};
use tokio_util::sync::CancellationToken;

use crate::{auth, tools::IcTools, McpServer};

/// What a hosted deployment configures of the deploy tools.
#[derive(Clone, Debug)]
pub struct DeployConfig {
    /// How many deploys run at once across every session (one per session
    /// either way); past it a deploy is refused, not queued. At least one: a
    /// zero is read as one.
    pub concurrent: usize,
    /// The cap on an uploaded archive, in bytes.
    pub max_upload_bytes: usize,
    /// The cap on every uploaded archive the server has at once — arriving,
    /// waiting for its deploy, or being deployed — in bytes; an upload past
    /// it is refused. At least one archive's worth: less is read as one.
    pub max_stored_upload_bytes: usize,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self::with_max_upload_bytes(imcp2_deploy::DEFAULT_MAX_UPLOAD_BYTES)
    }
}

impl DeployConfig {
    /// The defaults, around a cap of `max_upload_bytes` on one archive: two
    /// deploys at once, and [`imcp2_deploy::DEFAULT_STORED_UPLOADS`] archives'
    /// worth of uploads in all.
    pub fn with_max_upload_bytes(max_upload_bytes: usize) -> Self {
        Self {
            concurrent: 2,
            max_upload_bytes,
            max_stored_upload_bytes: max_upload_bytes
                .saturating_mul(imcp2_deploy::DEFAULT_STORED_UPLOADS),
        }
    }
}

/// How long the record of an interrupted deploy (the ids it had created) is
/// kept for someone to come for.
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
}

/// The file in the deploy directory whose lock says a process owns it.
const LOCK_FILE: &str = ".lock";

/// How long past [`imcp2_deploy::STOP_GRACE`] a stopping server waits for
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
    pub fn new(config: &DeployConfig, state_dir: &Path) -> std::io::Result<Self> {
        let dir = state_dir.join("deploys");
        let owned = own_directory(&dir)?;
        let uploads = Uploads::with_budget(
            dir.join("uploads"),
            config.max_upload_bytes,
            config.max_stored_upload_bytes,
        );
        let cut_off = imcp2_deploy::prune_abandoned_deploys(&dir);
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
            _owned: Arc::new(owned),
            sweeping: Arc::default(),
        })
    }

    /// Wait for the deploys that were running at [`Self::stop`] to have
    /// ended, and say whether they all did. Call it after the stop — and
    /// after draining in-flight requests, where a server does — and before
    /// [`McpServer::shutdown`] or exiting.
    ///
    /// A drain does not cover this. A stopped deploy with a canister call
    /// in flight waits for the answer (up to [`imcp2_deploy::STOP_GRACE`]),
    /// because the answer is what names a canister the call created; and
    /// one whose client has already gone has no connection for a drain to
    /// wait on. A process that exited then would lose that canister after
    /// all. The wait is bounded — the grace and a margin — so a deploy that
    /// will not end cannot hold the process: `false` says one was left.
    pub async fn stopped(&self) -> bool {
        let within = imcp2_deploy::STOP_GRACE + STOP_MARGIN;
        tokio::time::timeout(within, self.slots.idle()).await.is_ok()
    }

    /// Say that the server is stopping: every running deploy is interrupted
    /// at its next step and answers with the canisters it had created, and
    /// no new one begins. Call it when the shutdown signal arrives, *before*
    /// draining in-flight requests: a deploy lasts minutes, and a drain that
    /// waited one out would be cut short by whatever stops the process, the
    /// deploy with it and its answer unsent. Also ends the sweeper.
    ///
    /// [`McpServer::shutdown`] calls it as well, so a server that is shut
    /// down leaves no deploy running whether or not its embedder drains; one
    /// that does drain calls this first, for the answers to be sent.
    pub fn stop(&self) {
        self.stopping.cancel();
    }

    /// Start the periodic sweep that keeps the deploy directory bounded on
    /// an idle server: uploads past their time are removed (the store sweeps
    /// only when it is used), and so are the records of interrupted deploys
    /// older than [`DEPLOY_RECORD_TTL`]. Ends with [`Self::stop`]. Must be
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
        let removed = imcp2_deploy::remove_old_deploy_records(&self.dir, DEPLOY_RECORD_TTL);
        if removed > 0 {
            tracing::info!(removed, "removed the records of old interrupted deploys");
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
}

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
            .unwrap_or_else(|e| panic!("the state directory must be a UTF-8 path: {e}"))
            .with_uploads(uploads.clone(), upload_url);
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
    let deploy_call = parts.method == Method::POST && is_deploy_call(&bytes);
    let mut request = Request::from_parts(parts, Body::from(bytes));
    if !deploy_call {
        return mcp.json.handle(request).await.into_response();
    }
    let gone = CancellationToken::new();
    request.extensions_mut().insert(ClientGone(gone.clone()));
    let response = mcp.sse.handle(request).await;
    cancel_on_drop(response.into_response(), gone)
}

/// Whether `body` is a JSON-RPC `tools/call` of `icp_deploy_bundle`.
fn is_deploy_call(body: &[u8]) -> bool {
    let Ok(message) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    message["method"] == "tools/call" && message["params"]["name"] == "icp_deploy_bundle"
}

/// `response` with its body wrapped so that dropping the body — the client
/// disconnecting, or the stream ending — cancels `gone`.
fn cancel_on_drop(response: Response, gone: CancellationToken) -> Response {
    let (parts, body) = response.into_parts();
    let guard = gone.drop_guard();
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), guard),
        |(mut data, guard)| async move { data.next().await.map(|item| (item, (data, guard))) },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

/// What a successful `PUT` answers with.
#[derive(serde::Serialize)]
struct Uploaded {
    upload_id: String,
    bytes: usize,
    expires_in_secs: u64,
}

/// Receive an archive on the ticket in [`TICKET_HEADER`].
async fn upload(State(mcp): State<Arc<DeployMcp>>, request: Request) -> Response {
    let Some(ticket) = request.headers().get(TICKET_HEADER).and_then(|v| v.to_str().ok()) else {
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
    match mcp.uploads.receive(&ticket, declared, reader).await {
        Ok(received) => (
            StatusCode::CREATED,
            Json(Uploaded {
                upload_id: received.upload_id,
                bytes: received.bytes,
                expires_in_secs: received.expires_in.as_secs(),
            }),
        )
            .into_response(),
        Err(e @ ReceiveError::UnknownTicket) => {
            (StatusCode::FORBIDDEN, e.to_string()).into_response()
        }
        Err(e @ ReceiveError::TooLarge(_)) => {
            (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response()
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, IiInstance, McpConfig, SharedClients, IC_URL};
    use axum::http::Request;
    use tower::ServiceExt;

    fn config() -> DeployConfig {
        DeployConfig { concurrent: 2, ..DeployConfig::with_max_upload_bytes(1024) }
    }

    fn server() -> (tempfile::TempDir, McpServer) {
        let dir = tempfile::tempdir().unwrap();
        let deploys = Deploys::new(&config(), dir.path()).unwrap();
        let server = server_in(dir.path(), "/mcp", deploys);
        (dir, server)
    }

    fn server_in(state_dir: &Path, mcp_path: &str, deploys: Deploys) -> McpServer {
        let state_dir = state_dir.to_path_buf();
        McpServer::new(McpConfig {
            agent: Agent::builder().with_url(IC_URL).build().expect("agent"),
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

        // The PUT: refused without a ticket, with a wrong one, and over the cap;
        // accepted on the ticket, once.
        let put = |ticket: Option<&str>, body: Vec<u8>| {
            let mut req = Request::put(UPLOAD_PATH);
            if let Some(t) = ticket {
                req = req.header(TICKET_HEADER, t);
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };
        assert_eq!(put(None, vec![1]).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(put(Some("bogus"), vec![1]).await.unwrap().status(), StatusCode::FORBIDDEN);
        let resp = put(Some(&ticket), vec![0; 1025]).await.unwrap();
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
        let resp = put(Some(&ticket), b"not a bundle".to_vec()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let uploaded: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let upload_id = uploaded["upload_id"].as_str().unwrap().to_string();
        assert_eq!(uploaded["bytes"], 12);
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
        let resp = again.oneshot(put.body(Body::from("bundle")).unwrap()).await.unwrap();
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
        assert_eq!(started.elapsed(), imcp2_deploy::STOP_GRACE + STOP_MARGIN);
    }

    /// Dropping the response body — what a disconnect does — fires the token.
    #[tokio::test]
    async fn dropping_the_response_body_says_the_client_has_gone() {
        let gone = CancellationToken::new();
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, axum::Error>>();
        let response = Response::new(Body::from_stream(pending));
        let watched = cancel_on_drop(response, gone.clone());
        assert!(!gone.is_cancelled());
        drop(watched);
        assert!(gone.is_cancelled(), "the body's drop must cancel the token");
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
