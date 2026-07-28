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
//! use imcp2::{auth_callbacks_router, Agent, IiInstance, McpConfig, McpServer, SharedClients, IC_URL};
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
//!         clients: SharedClients::load(),
//!     });
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
//! II at `/mcp-beta`): give each its own `McpServer` (sessions and tokens
//! never cross instances), share ONE [`SharedClients`] between them so dynamic
//! client registrations (II-agnostic) persist to a single snapshot, and pass
//! every instance to [`auth_callbacks_router`] so the one allow-list document
//! declares all callbacks.
//!
//! Remaining knobs are environment variables read where they are used:
//! `II_URL` / `II_CANISTER_ID` and `II_URL_PROD` / `II_CANISTER_ID_PROD` (the
//! Internet Identity instances), `OAUTH_CLIENTS_FILE` (where dynamic client
//! registrations persist) and `SKILLS_URL` (the IC skills registry).

mod auth;
mod calls;
mod discover;
mod identities;
mod management;
mod skills;
mod tools;

// Real II<>MCP handshake test against a live Internet Identity canister in
// PocketIC. In-crate (not tests/) so it can use the feature-gated optional
// `pocket-ic` dependency and the crate internals; gated so the default build
// compiles neither it nor `pocket-ic`. See the module docs to run it.
#[cfg(all(test, feature = "e2e"))]
mod e2e_handshake;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use rmcp::transport::{
    streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
    StreamableHttpServerConfig,
};
use tokio_util::sync::CancellationToken;

pub use auth::SharedClients;
pub use identities::{IiInstance, SessionGauges};
/// The IC [`Agent`] type the server is built around, re-exported so callers
/// construct the injected agent from the exact `ic-agent` version this crate
/// links.
pub use ic_agent::{self, Agent};

/// A sensible default IC API boundary node (the public mainnet endpoint) for
/// callers that just want `Agent::builder().with_url(IC_URL).build()`. A host
/// with its own boundary-node routing supplies an agent built against that
/// instead.
pub const IC_URL: &str = "https://icp-api.io";

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
    /// The dynamic-client-registration store. Share ONE across every instance
    /// on an origin (registrations are II-agnostic and persist to one file).
    pub clients: SharedClients,
}

/// One MCP server instance: the shared state behind [`Self::mcp_router`] and
/// [`Self::well_known_router`]. Cheap to clone (everything inside is shared).
#[derive(Clone)]
pub struct McpServer {
    agent: Agent,
    identities: identities::Identities,
    skills: skills::SkillsCatalog,
    store: auth::AuthStore,
    public_url: String,
    mcp_path: String,
    /// Cancels the streamable-HTTP sessions and the session reaper on
    /// [`Self::shutdown`].
    ct: CancellationToken,
}

impl McpServer {
    pub fn new(config: McpConfig) -> Self {
        let public_url = normalize_public_url(&config.public_url);
        let mcp_path = normalize_mount_path(&config.mcp_path);
        let identities =
            identities::Identities::new(config.instance, public_url.clone(), config.agent.clone());
        let store = auth::AuthStore::new(
            identities.clone(),
            config.clients,
            public_url.clone(),
            mcp_path.clone(),
        );
        Self {
            agent: config.agent,
            identities,
            skills: skills::SkillsCatalog::new(),
            store,
            public_url,
            mcp_path,
            ct: CancellationToken::new(),
        }
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
    ///   * everything else — the MCP streamable-HTTP endpoint (the router
    ///     fallback, so the bare mount path, its trailing-slash form, and
    ///     sub-paths all reach it), bearer-token gated, with the CORS
    ///     preflight answered before authentication and `WWW-Authenticate`
    ///     exposed cross-origin.
    ///
    /// Nest with `nest_service` (which forwards the bare trailing-slash form
    /// too, unlike `nest`). Nesting at the application root is the one axum
    /// won't allow; for a root-mounted instance `.merge` this router instead
    /// and set `mcp_path: "".into()`.
    pub fn mcp_router(&self) -> Router {
        let mcp_service = {
            let (agent, identities, skills) =
                (self.agent.clone(), self.identities.clone(), self.skills.clone());
            StreamableHttpService::new(
                move || Ok(tools::IcTools::new(agent.clone(), identities.clone(), skills.clone())),
                LocalSessionManager::default().into(),
                // Stateless + plain-JSON responses: our tools are pure
                // request/response with no server-initiated messages, and this
                // is the most compatible mode across MCP clients (ChatGPT's
                // connector does not complete the stateful SSE/session
                // handshake the rmcp defaults require).
                StreamableHttpServerConfig::default()
                    .with_stateful_mode(false)
                    .with_json_response(true)
                    .with_cancellation_token(self.ct.child_token())
                    .with_allowed_hosts(self.allowed_hosts()),
            )
        };

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
        let gated_mcp = Router::new()
            .fallback_service(mcp_service)
            .layer(middleware::from_fn_with_state(
                self.store.clone(),
                auth::require_token,
            ))
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

        Router::new()
            .nest("/oauth", oauth)
            .merge(oidc_alternate)
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
            .route(
                "/.well-known/oauth-protected-resource",
                get(auth::protected_resource_metadata),
            )
            .with_state(self.store.clone())
            .layer(permissive_cors())
    }

    /// Spawn this instance's session reaper: sweeps once shortly after startup
    /// and then every 60s (tokio's interval fires its first tick immediately;
    /// the startup sweep is harmless, the map is empty then), evicting
    /// expired-grant sessions (emitting a "session closed" log each) and giving
    /// the journal a close event to reconcile against "session opened". This
    /// caps growth from expired grants (the common case: every authenticated
    /// session eventually expires); sessions with no recorded expiry
    /// (mid-connect) are deliberately kept and so are NOT bounded by this.
    /// Tied to [`Self::shutdown`] so the task stops cleanly on drain. Must be
    /// called from within a tokio runtime.
    pub fn spawn_session_reaper(&self) {
        let ids = self.identities.clone();
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
                    }
                }
            }
        });
    }

    /// This instance's live/active session gauges (see
    /// [`identities::Identities::session_gauges`]) — for a deployment's
    /// `/version`-style observability probe.
    pub async fn session_gauges(&self) -> SessionGauges {
        self.identities.session_gauges().await
    }

    /// Cancel the MCP transport's live sessions and the session reaper; call
    /// AFTER draining in-flight requests on graceful shutdown (cancelling
    /// first would cut the very requests the drain is waiting on).
    pub fn shutdown(&self) {
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
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
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
    use super::{allowed_hosts_for, normalize_mount_path, normalize_public_url};

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
        assert_eq!(normalize_public_url("https://mcp.example.com:8443"), "https://mcp.example.com:8443");
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
}
