//! IMCP2 — Internet Computer MCP server as an embeddable axum library.
//!
//! The server exposes MCP tools over streamable HTTP that talk to the Internet
//! Computer via `ic-agent` (discover the canisters behind an app, read/write
//! canisters as the user's Internet Identity account, OQL reads, canister
//! management, …), gated by an OAuth 2.1 authorization server whose login
//! mechanism is Internet Identity's `/mcp` connect handshake.
//!
//! One [`McpServer`] serves one Internet Identity instance ([`IiInstance`]) and
//! packages everything as two [`axum::Router`]s:
//!
//!   * [`McpServer::mcp_router`] — the MCP endpoint plus the OAuth
//!     authorization server under `/oauth`, nested at [`McpServer::mcp_path`].
//!   * [`McpServer::well_known_router`] — the OAuth discovery documents.
//!     Well-known URIs are origin-scoped (RFC 8615), so this router is merged
//!     at the application root; its handlers are parametric on the path the
//!     mcp router is nested at (the RFC 8414 / RFC 9728 *path-inserted*
//!     locations). [`McpServer::root_well_known_router`] adds the plain-root
//!     fallback documents for the origin's default instance, and
//!     [`auth_callbacks_router`] the origin-global II auth-callback allow-list
//!     covering every instance.
//!
//! The IC [`Agent`] is **inherited from the embedding application**, not built
//! here: a host (an API boundary node, a gateway, or the bundled binary)
//! passes in its own agent, so anonymous canister calls go through the host's
//! boundary-node client and the whole process links a single `ic-agent`.
//!
//! ```rust,no_run
//! use imcp2::{auth_callbacks_router, Agent, IiInstance, McpConfig, McpServer, IC_URL};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Or hand in the host's own agent instead of building a default one.
//!     let agent = Agent::builder().with_url(IC_URL).build()?;
//!     let server = McpServer::new(McpConfig {
//!         agent,
//!         instance: IiInstance::beta().map_err(anyhow::Error::msg)?,
//!         public_url: "https://mcp.example.com".into(),
//!         mcp_path: "/mcp".into(),
//!         // Where imcp2 keeps operational state (the client-registration store,
//!         // and the deploy tools' uploads and records).
//!         state_dir: "/var/lib/imcp2".into(),
//!         require_resource: true, // strict RFC 8707 (reject a missing `resource`)
//!         cimd_enabled: true, // Client ID Metadata Documents (URL client_ids); false turns them off
//!         deploy: Default::default(), // the deploy tools' caps (see `imcp2::deploy`)
//!     })?;
//!     server.spawn_session_reaper();
//!     let app = axum::Router::new()
//!         // nest_service (not nest): it also forwards the bare
//!         // trailing-slash form (`/mcp/`) into the router.
//!         .nest_service(server.mcp_path(), server.mcp_router())
//!         .merge(server.well_known_router())
//!         // Exactly one instance per origin also answers the root probes
//!         // and serves the origin-global II auth-callback allow-list.
//!         .merge(server.root_well_known_router())
//!         .merge(auth_callbacks_router(&[&server]));
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
//!     axum::serve(listener, app).await?;
//!     Ok(())
//! }
//! ```
//!
//! Several instances can share one origin (e.g. production II at `/mcp`, beta
//! II at `/mcp-beta`): build the first with [`McpServer::new`] and each other
//! from it with [`McpServer::sibling`]. Each is its own `McpServer` (sessions
//! and tokens never cross instances) over the one state directory: dynamic
//! client registrations (II-agnostic) persist to a single snapshot, and the
//! deploy tools' caps hold across the process. Pass every instance to
//! [`auth_callbacks_router`] so the one allow-list document declares all
//! callbacks.
//!
//! The operational-files location is [`McpConfig::state_dir`] (the embedder
//! supplies it; the `imcp2` binary reads `$IMCP2_STATE_DIR`). Remaining knobs are
//! environment variables read where they are used: `II_URL` / `II_CANISTER_ID`
//! and `II_URL_PROD` / `II_CANISTER_ID_PROD` (the Internet Identity instances).

mod auth;
mod body_limit;
mod branding;
pub mod deploy;
// Docs live in the module itself (`//!` in src/metrics.rs): an outer doc
// comment here would resolve its intra-doc links in *this* scope rather than
// the module's, silently breaking the links to `Registry` and `MatchedPath`.
pub mod metrics;

// The transport/OAuth-agnostic components — the tool surface, the II session
// engine, and the connect-handshake primitives — live in the `imcp2-core`
// crate; this crate composes them with the OAuth 2.1 authorization server and
// the streamable-HTTP transport.
use imcp2_core::{identities, tools};

// Real II<>MCP handshake test against a live Internet Identity canister in
// PocketIC. In-crate (not tests/) so it can use the feature-gated optional
// `pocket-ic` dependency and the crate internals; gated so the default build
// compiles neither it nor `pocket-ic`. See the module docs to run it.
#[cfg(all(test, feature = "e2e"))]
mod e2e_handshake;

use std::path::{Path, PathBuf};

use axum::{
    middleware,
    routing::{get, post},
    Json, Router,
};
use rmcp::transport::StreamableHttpServerConfig;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use auth::SharedClients;
pub use body_limit::DEFAULT_MAX_REQUEST_BODY;
/// The components this server is composed from, re-exported so embedders keep
/// importing everything from `imcp2` (the types are `imcp2-core`'s — one
/// defining crate, so type identity is preserved).
pub use imcp2_core::{ic_agent, Agent, IiInstance, SessionGauges, IC_URL};

/// Everything an [`McpServer`] is built from.
pub struct McpConfig {
    /// The IC agent anonymous canister calls are signed with — inherited from
    /// the embedding application so the host controls boundary-node routing
    /// and the process links one `ic-agent`. For a standalone deployment:
    /// `Agent::builder().with_url(imcp2::IC_URL).build()`.
    pub agent: Agent,
    /// Which Internet Identity instance this server connects users against.
    pub instance: IiInstance,
    /// Public base URL (origin) clients use to reach the deployment, e.g.
    /// `https://mcp.example.com` — baked into the OAuth discovery documents,
    /// the II handshake URLs, and the transport's DNS-rebinding allowlist.
    pub public_url: String,
    /// The path [`McpServer::mcp_router`] is nested at (e.g. `"/mcp"`). The
    /// single source of truth every absolute URL derives from: the AS issuer
    /// is `{public_url}{mcp_path}` (an RFC 8414 path issuer), the OAuth
    /// endpoints live at `{issuer}/oauth/*`, and the discovery documents at
    /// the matching path-inserted well-known locations.
    pub mcp_path: String,
    /// Directory in which imcp2 creates its operational files — the persistent
    /// state a restart must survive: the dynamic-client-registration store
    /// (`{state_dir}/oauth-clients.json`) and, with the deploy tools on, their
    /// uploads and deploy records (`{state_dir}/deploys`). The embedding
    /// application owns this location (it is not read from the environment); the
    /// `imcp2` binary sets it from `$IMCP2_STATE_DIR`.
    pub state_dir: PathBuf,
    /// Strict RFC 8707 resource indicators: when `true`, both OAuth legs REQUIRE
    /// a `resource` naming this instance, refusing a request that omits it (not
    /// just one that names a foreign server). This closes the confused-deputy
    /// token-theft path even for clients that never send `resource`, at the cost
    /// of turning away any client predating RFC 8707. When `false`, a missing
    /// `resource` is tolerated (a present one must still match).
    pub require_resource: bool,
    /// Client ID Metadata Documents: when `true`, the AS metadata advertises
    /// `client_id_metadata_document_supported` and a URL `client_id` on a vetted
    /// vendor origin is accepted by fetching its document; when `false`, a URL
    /// `client_id` is an unknown client. Claude and ChatGPT select CIMD the
    /// moment it is advertised, so a deployment normally sets `true`. Set by the
    /// embedding application; the `imcp2` binary has it on unless
    /// `$OAUTH_CIMD_ENABLED` switches it off.
    pub cimd_enabled: bool,
    /// The deploy tools on the MCP endpoint (see [`deploy`]), which every
    /// server serves: the caps on deploys and bundles, the sync plugins run
    /// and what each is held to. `DeployConfig::default()` for the defaults.
    /// Their files go under `{state_dir}/deploys`.
    ///
    /// Running the tools asks nothing more: [`McpServer::spawn_session_reaper`]
    /// starts the deploy sweeper too. Stopping them does, of an embedder that
    /// drains in-flight requests: call [`deploy::Deploys::stop`] (on
    /// [`McpServer::deploys`]) *before* the drain (a drain begun first waits
    /// on deploys nothing has told to stop, until whatever bounds it cuts
    /// their answers off) and [`deploy::Deploys::stopped`] after it, before
    /// [`McpServer::shutdown`]. `shutdown` stops the deploys as well, but only
    /// as a backstop: by then it is too late for them to answer.
    pub deploy: deploy::DeployConfig,
}

/// One MCP server instance: the shared state behind [`Self::mcp_router`] and
/// [`Self::well_known_router`]. Cheap to clone (everything inside is shared).
#[derive(Clone)]
pub struct McpServer {
    agent: Agent,
    identities: identities::Identities,
    store: auth::AuthStore,
    public_url: String,
    mcp_path: String,
    /// The deploy tools' state (see [`McpConfig::deploy`]), and with it the
    /// lock that makes this server the state directory's one owner.
    deploy: deploy::Deploys,
    /// The largest MCP request body the endpoint reads, in bytes (see
    /// [`Self::with_max_request_body`]).
    max_request_body: usize,
    /// Cancels the streamable-HTTP sessions and the session reaper on
    /// [`Self::shutdown`].
    ct: CancellationToken,
}

impl McpServer {
    /// Build the server, and with it what it keeps under
    /// [`McpConfig::state_dir`], which it takes as its own: the deploy
    /// directory is locked and cleared of what an earlier run left (see
    /// [`deploy`]), and the client registrations are loaded.
    ///
    /// An error is a state directory another running server owns, one that
    /// cannot be written or whose path is not UTF-8, or an entry of
    /// [`deploy::DeployConfig::allowed_plugins`] that is not a sha256. So a
    /// second instance in the same process is not a second `new` over the
    /// same directory, which is refused — two servers there would each clear
    /// the other's uploads and overwrite the other's client registrations —
    /// but a [`Self::sibling`] of the first.
    pub fn new(config: McpConfig) -> std::io::Result<Self> {
        let deploys = deploy::Deploys::new(&config.deploy, &config.state_dir)?;
        Ok(Self::with_deploys(config, deploys))
    }

    /// [`Self::new`], on deploy state already made over the state directory
    /// (and [`McpConfig::deploy`] not looked at).
    pub(crate) fn with_deploys(config: McpConfig, deploys: deploy::Deploys) -> Self {
        let public_url = normalize_public_url(&config.public_url);
        let mcp_path = normalize_mount_path(&config.mcp_path);
        let identities =
            identities::Identities::new(config.instance, public_url.clone(), config.agent.clone());
        let store = auth::AuthStore::new(
            identities.clone(),
            SharedClients::load(&config.state_dir),
            public_url.clone(),
            mcp_path.clone(),
            config.require_resource,
            config.cimd_enabled,
        );
        Self {
            agent: config.agent,
            identities,
            store,
            public_url,
            mcp_path,
            deploy: deploys,
            max_request_body: DEFAULT_MAX_REQUEST_BODY,
            ct: CancellationToken::new(),
        }
    }

    /// Another instance of this server in the same process: a different
    /// Internet Identity (`instance`) served at a different path
    /// (`mcp_path`) of the same origin, e.g. beta II at `/mcp-beta` beside
    /// production at `/mcp`. Everything else is this server's: the agent,
    /// the public URL, the OAuth settings and the request-body cap as they
    /// are now, and — shared, not copied — the client registrations and the
    /// deploy state, so a client registered at one is known to both and the
    /// deploy caps hold across them. Sessions and tokens are each
    /// instance's own, and so is its [`Self::shutdown`].
    pub fn sibling(&self, instance: IiInstance, mcp_path: &str) -> Self {
        let mcp_path = normalize_mount_path(mcp_path);
        let identities =
            identities::Identities::new(instance, self.public_url.clone(), self.agent.clone());
        Self {
            agent: self.agent.clone(),
            store: self.store.for_instance(identities.clone(), mcp_path.clone()),
            identities,
            public_url: self.public_url.clone(),
            mcp_path,
            deploy: self.deploy.clone(),
            max_request_body: self.max_request_body,
            ct: CancellationToken::new(),
        }
    }

    /// The deploy tools' state: for an embedder to stop the running deploys
    /// before it drains requests ([`deploy::Deploys::stop`]) and wait for
    /// them after ([`deploy::Deploys::stopped`]). The same state on every
    /// [`Self::sibling`].
    pub fn deploys(&self) -> &deploy::Deploys {
        &self.deploy
    }

    /// Cap the MCP request body at `bytes` instead of the default
    /// [`DEFAULT_MAX_REQUEST_BODY`]. The streamable-HTTP transport buffers each
    /// request body whole before parsing it, so the cap is what bounds the
    /// memory one authenticated request can take; a body over it is refused
    /// with `413` before more than the cap is read. The `imcp2` binary sets
    /// it from `$MCP_MAX_REQUEST_BODY`.
    pub fn with_max_request_body(mut self, bytes: usize) -> Self {
        self.max_request_body = bytes;
        self
    }

    /// The operational-files directory this instance uses — where imcp2 creates
    /// the state a restart must survive (today, the client-registration store).
    /// This is [`McpConfig::state_dir`], reported from the client store.
    /// Exposed so an embedder can place its own operational files under the same
    /// home.
    pub fn state_dir(&self) -> &Path {
        self.store.state_dir()
    }

    /// The path this instance's [`Self::mcp_router`] must be nested at — the
    /// normalized [`McpConfig::mcp_path`]:
    /// `.nest_service(server.mcp_path(), server.mcp_router())`.
    pub fn mcp_path(&self) -> &str {
        &self.mcp_path
    }

    /// Which Internet Identity this instance connects users against (the
    /// [`McpConfig::instance`] it was built with).
    ///
    /// Exposed so a deployment can *advertise* its II pairing — see the
    /// `instances` array on `main.rs`'s `/version`. Without that, an external
    /// monitor can only guess which II a given origin hands off to, and the
    /// obvious guess (strip the `mcp.` label off the host) is wrong for any
    /// deployment whose MCP origin is not a subdomain of its II.
    pub fn instance(&self) -> &IiInstance {
        self.identities.instance()
    }

    /// The MCP API and its OAuth authorization server, as one router to nest
    /// at [`Self::mcp_path`]:
    ///
    ///   * `/oauth/{authorize,connect/callback,connect/redeem,token,register}`
    ///     — the OAuth AS (login via Internet Identity's connect handshake),
    ///     CORS-open;
    ///   * `/.well-known/oauth-authorization-server` — the OIDC-style
    ///     alternate location of the AS metadata (some clients derive
    ///     `<issuer>/.well-known/…` instead of RFC 8414 path insertion);
    ///   * `/branding?state=…` and `/branding/{slug}/logo` — verified-connector
    ///     branding for Internet Identity's consent screen, CORS-open: the
    ///     first answers for one pending connect (from its validated
    ///     `redirect_uri`, `no-store`, `404` otherwise), the second serves a
    ///     curated connector's static logo;
    ///   * every other path — the MCP streamable-HTTP endpoint (the router
    ///     fallback, so the bare mount path, its trailing-slash form, and
    ///     unmatched sub-paths all reach it), bearer-token gated, with the CORS
    ///     preflight answered before authentication and `WWW-Authenticate`
    ///     exposed cross-origin, and its request body capped behind the gate
    ///     (see [`Self::with_max_request_body`]).
    ///
    /// Nest with `nest_service` (which forwards the bare trailing-slash form
    /// too, unlike `nest`). Nesting at the application root is the one axum
    /// won't allow; for a root-mounted instance `.merge` this router instead
    /// and set `mcp_path: "".into()`.
    pub fn mcp_router(&self) -> Router {
        // Stateless + plain-JSON responses: our tools are pure
        // request/response with no server-initiated messages, and this is
        // the most compatible mode across MCP clients (ChatGPT's connector
        // does not complete the stateful SSE/session handshake the rmcp
        // defaults require). The one exception is a deploy call, which
        // reports progress before its result (see [`deploy`]).
        let transport = StreamableHttpServerConfig::default()
            .with_stateful_mode(false)
            .with_json_response(true)
            .with_cancellation_token(self.ct.child_token())
            .with_allowed_hosts(self.allowed_hosts());
        // The endpoint has an open route next to the gated one: the bundle
        // upload, authenticated by its ticket.
        let (mcp_service, open_routes) = self.deploy_mcp_routers(&self.deploy, transport);

        // The MCP resource is gated by a bearer token issued after Internet
        // Identity login. Browser-based MCP clients (e.g. the Grok/ChatGPT
        // connector UIs) call the resource via `fetch()`, so it needs CORS —
        // applied OUTSIDE the bearer gate so the OPTIONS preflight is answered
        // (2xx) BEFORE authentication, and the 401's `WWW-Authenticate` (the
        // auth-discovery hint) is exposed cross-origin. `Authorization` must be
        // listed explicitly: the `*` wildcard for `Access-Control-Allow-Headers`
        // does NOT cover it per the Fetch spec.
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
        // Layers run outermost-last: CORS, then the bearer gate, then the body
        // cap — so an unauthenticated request is refused on its headers without
        // its body being read, and an authenticated one is read only up to the
        // cap before the transport buffers it. (The deploy dispatch reads the
        // body again for its method; the bundle upload is a route of its own,
        // outside both, with its own limits.)
        let gated_mcp = mcp_service
            .layer(middleware::from_fn_with_state(
                self.max_request_body,
                body_limit::limit_request_body,
            ))
            .layer(middleware::from_fn_with_state(self.store.clone(), auth::require_token))
            .layer(mcp_cors);

        let oauth = Router::new()
            .route("/authorize", get(auth::authorize))
            // The pinned callback PAGE (GET): II navigates the consenting
            // browser here with the delegation in the URL fragment; the page is
            // the sole fragment reader.
            .route("/connect/callback", get(auth::connect_callback_page))
            // The pinned page POSTs the fragment delegation here to be redeemed.
            .route("/connect/redeem", post(auth::connect_redeem))
            .route("/token", post(auth::token))
            .route("/register", post(auth::register))
            .with_state(self.store.clone())
            .layer(permissive_cors());

        // The OIDC-style AS-metadata alternate `<issuer>/.well-known/…` lives
        // INSIDE the mount (the issuer is `{public_url}{mcp_path}`), so it is a
        // route of this router, not of `well_known_router`.
        let oidc_alternate = Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(auth::authorization_server_metadata),
            )
            .with_state(self.store.clone())
            .layer(permissive_cors());

        // Verified-connector branding (see [`branding`]), rooted at the issuer so
        // II reaches it same-origin with the #4091-validated callback: the
        // session-bound metadata (`/branding?state=…`, answered from that pending
        // connect's validated redirect) and the static per-connector logo.
        // CORS-open, like the other endpoints II fetches cross-origin.
        let branding = Router::new()
            .route("/branding", get(branding::branding_metadata))
            .route("/branding/{slug}/logo", get(branding::branding_logo))
            .with_state(self.store.clone())
            .layer(permissive_cors());

        Router::new()
            .nest("/oauth", oauth)
            .merge(oidc_alternate)
            .merge(branding)
            .merge(open_routes)
            // Everything else is the MCP endpoint: the bare mount path, its
            // trailing-slash form, and any sub-path (the streamable service
            // dispatches on method, not path) — same breadth `nest_service`
            // used to give the endpoint.
            .fallback_service(gated_mcp)
    }

    /// This instance's OAuth discovery documents at their **path-inserted**
    /// well-known locations, to be merged at the application **root**
    /// (well-known URIs are origin-scoped). Parametric on [`Self::mcp_path`]:
    ///
    ///   * `/.well-known/oauth-authorization-server{mcp_path}` — RFC 8414 for
    ///     the path issuer `{public_url}{mcp_path}`;
    ///   * `/.well-known/oauth-protected-resource{mcp_path}` — RFC 9728 §3.1
    ///     for the resource `{public_url}{mcp_path}` (the URL the 401
    ///     challenge's `resource_metadata` points at).
    ///
    /// For an instance mounted at the root (`mcp_path: ""`) these ARE the root
    /// documents — don't also add [`Self::root_well_known_router`].
    pub fn well_known_router(&self) -> Router {
        Router::new()
            .route(
                &format!("/.well-known/oauth-authorization-server{}", self.mcp_path),
                get(auth::authorization_server_metadata),
            )
            .route(
                &format!("/.well-known/oauth-protected-resource{}", self.mcp_path),
                get(auth::protected_resource_metadata),
            )
            .with_state(self.store.clone())
            .layer(permissive_cors())
    }

    /// The plain **root** discovery documents (`/.well-known/oauth-authorization-server`
    /// and `/.well-known/oauth-protected-resource`), answering clients and
    /// monitors that probe the root without doing path-inserted discovery.
    /// Serve this for exactly ONE instance per origin — the default one. (The
    /// documents describe this instance: a strict RFC 8414 client would reject
    /// the root AS document on issuer mismatch, but such a client performs
    /// path insertion and never fetches it.)
    pub fn root_well_known_router(&self) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(auth::authorization_server_metadata),
            )
            .route("/.well-known/oauth-protected-resource", get(auth::protected_resource_metadata))
            .with_state(self.store.clone())
            .layer(permissive_cors())
    }

    /// Spawn this instance's state reaper: sweeps once shortly after startup
    /// and then every 60s (tokio's interval fires its first tick immediately;
    /// the startup sweep is harmless, the maps are empty then). Each sweep
    /// evicts:
    ///
    ///   * expired-grant sessions, emitting a "session closed" log each so the
    ///     journal has a close event to reconcile against "session opened",
    ///     plus connects abandoned mid-handshake (a session that never redeemed
    ///     a grant);
    ///   * the matching short-lived OAuth state — pending connects past their
    ///     TTL, authorization codes never exchanged, and expired access tokens.
    ///
    /// Reaping is what RETURNS the memory; the per-insert admission bounds (see
    /// `identities::make_room` / `auth::make_room`) are what cap these maps
    /// between sweeps, since the connect endpoints are unauthenticated. Running
    /// this is therefore expected, not optional, for a long-lived deployment.
    /// Tied to [`Self::shutdown`] so the task stops cleanly on drain. Must be
    /// called from within a tokio runtime.
    pub fn spawn_session_reaper(&self) {
        // The deploy tools' own periodic work rides the same call, so that
        // they add nothing to what an embedder must run.
        self.deploy.spawn_sweeper();
        let ids = self.identities.clone();
        let store = self.store.clone();
        let reap_ct = self.ct.child_token();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            // Skip missed ticks rather than the default Burst: if the runtime
            // stalls, resume with a single sweep at the next slot instead of
            // firing several back-to-back catch-up sweeps.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = reap_ct.cancelled() => break,
                    _ = tick.tick() => {
                        ids.reap_expired_sessions().await;
                        store.reap_expired().await;
                    }
                }
            }
        });
    }

    /// This instance's live/active session gauges ([`SessionGauges`]) — for a
    /// deployment's `/version`-style observability probe. One pass over the
    /// session map, so the pair is consistent.
    pub async fn session_gauges(&self) -> SessionGauges {
        self.identities.session_gauges().await
    }

    /// Cancel the MCP transport's live sessions and the session reaper; call
    /// AFTER draining in-flight requests on graceful shutdown (cancelling
    /// first would cut the very requests the drain is waiting on).
    ///
    /// This also stops the deploys that are
    /// running and the deploy sweeper ([`deploy::Deploys::stop`]), on every
    /// instance sharing that state: a process that is shutting one instance
    /// down is stopping. A deploy lasts minutes, so a drain does not wait one
    /// out — call [`deploy::Deploys::stop`] BEFORE the drain for each running
    /// deploy to answer with what it created.
    pub fn shutdown(&self) {
        self.deploy.stop();
        self.ct.cancel();
    }

    /// Hosts allowed in the `Host` header by rmcp's DNS-rebinding protection:
    /// loopback (local dev) plus the `public_url` host. Without the latter,
    /// every request via the public URL is rejected before the bearer token is
    /// even checked.
    fn allowed_hosts(&self) -> Vec<String> {
        allowed_hosts_for(&self.public_url)
    }
}

/// The `Host`-header allow-list derived from `public_url`: loopback (local
/// dev) plus the public host, in both its bare and `host:port` forms — clients
/// send whichever their URL implies. Parsed as a URL (assuming an `https`
/// scheme when none is given) rather than string-split, so a bare host, an
/// explicit port, or an IPv6 literal all land correctly — a mis-parse here
/// would reject every public request before the bearer token is even checked.
fn allowed_hosts_for(public_url: &str) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        // IPv6 loopback in BOTH spellings: a real `Host` header serializes it
        // bracketed (`[::1]`, matching the `host_str()` form the public-host
        // branch below emits), while the bare `::1` is kept for readers/tools
        // that use it. (rmcp normalizes brackets on both sides before matching,
        // so either would match today — carrying both keeps the list
        // self-consistent and independent of that normalization.)
        "::1".to_string(),
        "[::1]".to_string(),
    ];
    let public_url = public_url.trim();
    let candidate = if public_url.contains("://") {
        public_url.to_string()
    } else {
        format!("https://{public_url}")
    };
    if let Ok(url) = url::Url::parse(&candidate) {
        // `host_str` keeps IPv6 brackets ("[::1]"), matching the Host header's
        // own serialization.
        if let Some(host) = url.host_str() {
            if !hosts.iter().any(|h| h == host) {
                hosts.push(host.to_string());
            }
            if let Some(port) = url.port() {
                hosts.push(format!("{host}:{port}"));
            }
        }
    }
    hosts
}

/// The origin-global II **auth-callback allow-list** (II #4091): before
/// contacting the connect callback named in the (attacker-craftable) link
/// fragment, II fetches this origin's `/.well-known/ii-auth-callbacks` and
/// requires the callback to be EXACTLY one of the declared entries —
/// fail-closed, so serving it is mandatory once #4091 ships. The path carries
/// no instance prefix, so ONE document must declare every instance's callback:
/// pass all of an origin's `McpServer`s and merge the router at the
/// application root. CORS-open (II's frontend fetches it cross-origin).
pub fn auth_callbacks_router(servers: &[&McpServer]) -> Router {
    let stores: Vec<auth::AuthStore> = servers.iter().map(|s| s.store.clone()).collect();
    Router::new()
        .route(auth::AUTH_CALLBACKS_WELL_KNOWN, get(auth::auth_callbacks))
        .with_state(stores)
        .layer(permissive_cors())
}

/// This deployment's display name on Internet Identity's screens, and the legal
/// documents it links there — the product's own pages on `internetcomputer.org`,
/// not this origin's `/privacy-policy` and `/terms`. II never fetches them (it
/// renders links the user opens), so they may live on any origin, but they must
/// be `https`: II rejects the whole document otherwise, which would cost the
/// name too.
const II_APP_NAME: &str = "ICP MCP";
const II_PRIVACY_POLICY_URL: &str = "https://internetcomputer.org/icp-mcp/privacy-policy";
const II_TERMS_OF_SERVICE_URL: &str = "https://internetcomputer.org/icp-mcp/terms";

/// The origin-global **II app metadata** document. Any origin can name itself
/// and link its own privacy policy and terms of service on Internet Identity's
/// screens — permissionlessly, with no involvement from the II team — by
/// serving them here; II reads the document when the user connects this server
/// and shows the name beside the origin it has verified. The metadata is only
/// as trustworthy as the origin serving it, so it identifies this deployment,
/// it does not authenticate it.
///
/// Validation is all-or-nothing: a field II rejects discards the document
/// whole, so a bad URL costs the name as well. Like the auth-callback
/// allow-list, the path carries no instance prefix (well-known URIs are
/// origin-scoped), so ONE document covers every instance — merge this router at
/// the application root. CORS-open (II's frontend fetches it cross-origin).
///
/// The document names THIS deployment: an embedder serving imcp2 on its own
/// origin publishes its own metadata rather than merging this router, which is
/// why the crate's usage example leaves it out.
///
/// <https://github.com/dfinity/internet-identity/blob/main/docs/ii-spec.mdx#app-metadata>
pub fn ii_app_metadata_router() -> Router {
    Router::new()
        .route(
            "/.well-known/ii-app-metadata",
            get(|| async {
                Json(json!({
                    "name": II_APP_NAME,
                    "privacyPolicyUrl": II_PRIVACY_POLICY_URL,
                    "termsOfServiceUrl": II_TERMS_OF_SERVICE_URL,
                }))
            }),
        )
        .layer(permissive_cors())
}

/// The OAuth and discovery endpoints are called cross-origin by browser-based
/// MCP clients, so they are CORS-open (they are public API, gated by their own
/// semantics, not by origin).
fn permissive_cors() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}

/// Normalize a mount path to `""` (root) or `/segment[/…]` — leading slash,
/// no trailing slash — so it can be interpolated into URLs and route paths.
fn normalize_mount_path(path: &str) -> String {
    let path = path.trim().trim_end_matches('/');
    if path.is_empty() {
        String::new()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Canonicalize [`McpConfig::public_url`] to a clean **origin** — `scheme://host[:port]`,
/// with a lowercase scheme, the default port dropped, and any path/query/fragment
/// removed. `public_url` is the single source of truth for every absolute URL the
/// server emits (the AS issuer, the discovery documents, the II callback), for the
/// `Secure`-cookie decision, and for the DNS-rebinding host allow-list, so a
/// scheme-less host (`mcp.example.com`), an uppercase scheme (`HTTPS://…`), or a
/// stray path (`https://mcp.example.com/mcp`) would otherwise produce malformed
/// issuers/callbacks or a wrongly-dropped `Secure` flag. Self-corrects rather than
/// failing: an `https` scheme is assumed when none is given, and if parsing can't
/// yield a host the trimmed input is returned unchanged (best effort).
fn normalize_public_url(raw: &str) -> String {
    let raw = raw.trim();
    // Give `Url::parse` a scheme to work with; a bare host isn't a valid URL.
    let candidate = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    if let Ok(url) = url::Url::parse(&candidate) {
        // `scheme()` is lowercased by the parser; `host_str()` keeps IPv6
        // brackets; `port()` is `None` for an absent or default port (so the
        // origin omits `:443`/`:80`).
        if let Some(host) = url.host_str() {
            let scheme = url.scheme();
            return match url.port() {
                Some(port) => format!("{scheme}://{host}:{port}"),
                None => format!("{scheme}://{host}"),
            };
        }
    }
    raw.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod lib_tests {
    use super::{
        allowed_hosts_for, normalize_mount_path, normalize_public_url, Agent, IiInstance,
        McpConfig, McpServer, IC_URL,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::path::PathBuf;
    use tower::ServiceExt;

    fn config(dir: PathBuf, instance: IiInstance, mcp_path: &str) -> McpConfig {
        McpConfig {
            agent: Agent::builder().with_url(IC_URL).build().expect("agent"),
            instance,
            public_url: "https://mcp.example.com".into(),
            mcp_path: mcp_path.into(),
            state_dir: dir,
            require_resource: true,
            cimd_enabled: false,
            deploy: Default::default(),
        }
    }

    /// A server over a state directory of its own, which lasts as long as
    /// the handle returned with it. Construction touches no network.
    fn server() -> (tempfile::TempDir, McpServer) {
        let dir = tempfile::tempdir().unwrap();
        let prod = IiInstance::prod().expect("prod instance");
        let server = McpServer::new(config(dir.path().to_path_buf(), prod, "/mcp")).unwrap();
        (dir, server)
    }

    /// `state_dir()` reports the directory the server was configured with.
    #[test]
    fn state_dir_reports_the_store_directory() {
        let (dir, server) = server();
        assert_eq!(server.state_dir(), dir.path());
    }

    /// A sibling serves another Internet Identity at another path over the
    /// same state, the deploy tools' included; a second server built over
    /// the directory is not one, and is refused.
    #[test]
    fn a_sibling_shares_the_state_and_serves_its_own_instance() {
        let (dir, prod) = server();
        let prod = prod.with_max_request_body(1234);
        let beta = prod.sibling(IiInstance::beta().expect("beta instance"), "mcp-beta/");
        assert_eq!(beta.mcp_path(), "/mcp-beta");
        assert_eq!(beta.instance().name, IiInstance::beta().unwrap().name);
        assert_eq!(prod.instance().name, IiInstance::prod().unwrap().name);
        assert_eq!(beta.state_dir(), prod.state_dir());
        assert_eq!(beta.max_request_body, 1234);

        let again = |path: &str| {
            let beta = IiInstance::beta().expect("beta instance");
            McpServer::new(config(dir.path().to_path_buf(), beta, path))
        };
        let Err(refused) = again("/mcp-beta") else { panic!("two servers over one directory") };
        assert!(refused.to_string().contains("another running server"), "{refused}");
        // The directory is free once every instance over it has gone.
        drop((prod, beta));
        again("/mcp").unwrap();
    }

    /// `public_url` canonicalizes to a clean origin regardless of the shape the
    /// caller passes: a scheme is added when absent, an uppercase scheme is
    /// lowercased (so the `Secure`-cookie check sees `https://`), a trailing
    /// slash or a stray path is dropped, and a default port is omitted while a
    /// non-default one is kept.
    #[test]
    fn public_url_normalizes_to_an_origin() {
        assert_eq!(normalize_public_url("https://mcp.example.com"), "https://mcp.example.com");
        assert_eq!(normalize_public_url("https://mcp.example.com/"), "https://mcp.example.com");
        // Stray path dropped (would otherwise double up under {public_url}{mcp_path}).
        assert_eq!(normalize_public_url("https://mcp.example.com/mcp"), "https://mcp.example.com");
        // Scheme-less host gets https.
        assert_eq!(normalize_public_url("mcp.example.com"), "https://mcp.example.com");
        // Uppercase scheme lowercased (fixes the Secure-cookie check).
        assert_eq!(normalize_public_url("HTTPS://mcp.example.com"), "https://mcp.example.com");
        // Default port dropped; non-default kept; local http preserved.
        assert_eq!(normalize_public_url("https://mcp.example.com:443"), "https://mcp.example.com");
        assert_eq!(
            normalize_public_url("https://mcp.example.com:8443"),
            "https://mcp.example.com:8443"
        );
        assert_eq!(normalize_public_url("http://localhost:8000"), "http://localhost:8000");
        // IPv6 literal stays bracketed.
        assert_eq!(normalize_public_url("http://[::1]:8080"), "http://[::1]:8080");
    }

    #[test]
    fn mount_paths_are_normalized() {
        assert_eq!(normalize_mount_path("/mcp"), "/mcp");
        assert_eq!(normalize_mount_path("mcp"), "/mcp");
        assert_eq!(normalize_mount_path("/mcp/"), "/mcp");
        assert_eq!(normalize_mount_path("/api/v1/mcp"), "/api/v1/mcp");
        assert_eq!(normalize_mount_path("/"), "");
        assert_eq!(normalize_mount_path(""), "");
    }

    /// The DNS-rebinding allow-list must survive every plausible `public_url`
    /// shape: with/without a scheme, with an explicit port (the Host header
    /// then carries `host:port`), and IPv6 literals (bracketed, as in the Host
    /// header). A mis-parse would reject all public traffic pre-auth.
    #[test]
    fn allowed_hosts_cover_public_url_shapes() {
        let has = |hosts: &[String], h: &str| hosts.iter().any(|x| x == h);

        let hosts = allowed_hosts_for("https://mcp.example.com");
        assert!(has(&hosts, "mcp.example.com"), "{hosts:?}");
        assert!(has(&hosts, "localhost") && has(&hosts, "127.0.0.1"));
        // IPv6 loopback in both the bare and the bracketed (Host-header) form.
        assert!(has(&hosts, "::1") && has(&hosts, "[::1]"), "{hosts:?}");

        // Explicit port: both forms are allowed (the Host header carries the
        // port for non-default ports).
        let hosts = allowed_hosts_for("https://mcp.example.com:8443");
        assert!(has(&hosts, "mcp.example.com") && has(&hosts, "mcp.example.com:8443"), "{hosts:?}");

        // Scheme-less input (the old string-split produced nothing here).
        let hosts = allowed_hosts_for("mcp.example.com");
        assert!(has(&hosts, "mcp.example.com"), "{hosts:?}");

        // IPv6 literal, bracketed like the Host header serializes it.
        let hosts = allowed_hosts_for("http://[2001:db8::1]:8080");
        assert!(has(&hosts, "[2001:db8::1]") && has(&hosts, "[2001:db8::1]:8080"), "{hosts:?}");

        // The local-dev default: no duplicate entry for an already-loopback host.
        let hosts = allowed_hosts_for("http://localhost:8000");
        assert_eq!(hosts.iter().filter(|h| *h == "localhost").count(), 1);
        assert!(has(&hosts, "localhost:8000"), "{hosts:?}");
    }

    /// The body cap guards the MCP endpoint from behind the bearer gate: an
    /// authenticated oversized request gets `413`, an unauthenticated one still
    /// gets the `401` challenge with its body left unread.
    #[tokio::test]
    async fn the_mcp_endpoint_caps_authenticated_request_bodies() {
        let (_dir, server) = server();
        let server = server.with_max_request_body(64);
        let bearer = format!("Bearer {}", server.store.test_bearer().await);
        let oversized = || Body::from(vec![b'x'; 65]);

        let resp = server
            .mcp_router()
            .oneshot(Request::post("/").header("authorization", &bearer).body(oversized()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let resp = server
            .mcp_router()
            .oneshot(Request::post("/").body(oversized()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "the gate comes first");

        // Within the cap and authenticated: the body reaches the transport
        // whole, and the transport answers the JSON-RPC request it carries. The
        // `Host` is one the transport allows (it turns any other away before
        // reading a body), and the `id` in the reply exists nowhere but in the
        // request body, so a body the cap dropped or cut short could not
        // produce it.
        let resp = server
            .mcp_router()
            .oneshot(
                Request::post("/")
                    .header("host", "mcp.example.com")
                    .header("authorization", &bearer)
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":4242,"method":"ping"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let reply: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC reply");
        assert_eq!(reply, serde_json::json!({ "jsonrpc": "2.0", "id": 4242, "result": {} }));
    }
}
