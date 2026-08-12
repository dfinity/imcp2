//! Deployment binary for the [`imcp2`] library: serves the production Internet
//! Identity instance at `/mcp` and adds the deployment niceties (the landing
//! page, a `/version` probe with live-session gauges, request logging,
//! env-driven config, drained graceful shutdown).
//!
//!   * `/mcp`: the MCP endpoint against **production** Internet Identity, with
//!     its OAuth AS at `/mcp/oauth/*` (issuer `<PUBLIC_URL>/mcp`). Always
//!     served, and the origin's default instance (it answers the plain-root
//!     probes).
//!   * `/mcp-beta`: the same against **beta** Internet Identity, served ONLY
//!     when `$MCP_SERVE_BETA` is set (the staging deployment). Off by default,
//!     so a production deployment serves `/mcp` alone.
//!   * `/.well-known/*`: the OAuth discovery documents (path-inserted per
//!     served instance, plus the plain-root fallbacks for the default `/mcp`
//!     instance) and the origin-global II auth-callback allow-list
//!
//! Honours `$PORT` (bind port, default 8000), `$PUBLIC_URL` (the public base
//! URL baked into the discovery documents and the II handshake),
//! `$MCP_SERVE_BETA` (opt in to the `/mcp-beta` staging instance),
//! `$MCP_SERVE_METRICS` (opt in to the Prometheus exposition at `/metrics`; off
//! by default because nothing here can know whether a proxy is hiding it), and
//! `$OPENAI_APPS_CHALLENGE_TOKEN` (serve the OpenAI Apps domain-verification
//! token at `/.well-known/openai-apps-challenge`; 404 while unset).
//!
//! Also serves `/sitemap.xml` and `/robots.txt`, both built from `$PUBLIC_URL`
//! so each deployment advertises its own origin.

use axum::{response::Html, routing::get, Json, Router};
use imcp2::{auth_callbacks_router, Agent, IiInstance, McpConfig, McpServer, SharedClients, IC_URL};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Bind address. Honours `$PORT` (set by most PaaS), defaulting to 8000.
fn bind_address() -> String {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    format!("0.0.0.0:{port}")
}

/// Public base URL clients use to reach this server. Override with PUBLIC_URL.
fn public_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}

/// Whether to enforce strict RFC 8707 resource indicators: require a `resource`
/// naming this instance on both OAuth legs, refusing a request that omits it.
/// **On by default** — the confused-deputy token-theft path is only fully closed
/// when a missing `resource` is refused. Set `OAUTH_REQUIRE_RESOURCE` to a falsey
/// value (`0`/`false`/`no`/`off`) to fall back to lenient (tolerate a missing
/// `resource` for clients predating RFC 8707); any other value, or unset, is
/// strict.
fn require_resource() -> bool {
    match std::env::var("OAUTH_REQUIRE_RESOURCE") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
        Err(_) => true,
    }
}

/// Whether to also serve the beta Internet Identity instance at `/mcp-beta`.
/// Off unless `$MCP_SERVE_BETA` is truthy (`1`/`true`/`yes`/`on`), so a
/// production deployment serves only `/mcp` (production II) and the staging
/// deployment opts in to the extra beta endpoint.
fn serve_beta() -> bool {
    std::env::var("MCP_SERVE_BETA")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Whether to serve the Prometheus exposition at `/metrics`. Off unless
/// `$MCP_SERVE_METRICS` is truthy (`1`/`true`/`yes`/`on`).
///
/// **Off by default because the default is the exposed case.** On the native
/// deployment a reverse proxy sits in front and answers `/metrics` itself, so a
/// scraper reaches the app directly on the host's private address over the VPN
/// and the endpoint is never published; that path sets this to `1`. But the
/// Dockerfile is a documented, supported deployment (README: Render, Fly, Cloud
/// Run, Koyeb) and there is no proxy in it — the platform routes the public
/// hostname straight at this process, so every path the router registers is on
/// the internet. An unconditional `/metrics` would therefore be public on a
/// deployment we ship, which is how a "not published" endpoint ends up
/// published. Gating it means the exposure requires a deliberate opt-in on the
/// host that has a proxy to hide it, rather than requiring every other operator
/// to notice and remove it.
///
/// What is at stake if it is public: request volumes and error rates by route,
/// live session counts and process memory — reconnaissance for anyone probing
/// the service — plus an amplification lever, since each scrape makes the
/// process gather and encode the whole registry.
fn serve_metrics() -> bool {
    std::env::var("MCP_SERVE_METRICS")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// The landing page served at `/`: a self-contained design bundle exported from
/// Claude Design (`assets/index.html`, compiled in via `include_str!`, no
/// runtime file I/O). It is a single HTML document that inlines its own fonts,
/// images, styles, and render runtime as an embedded resource bundle and unpacks
/// itself client-side — so it stays self-contained (no external fonts, scripts,
/// or images) despite the richer look. It shares the connect flow's ICP identity
/// — parchment grid, editorial serif, rust accent, "Hosted by DFINITY" mark — so
/// the root page and the connect screens read as one product, and walks through
/// what an agent can do: discovery, identity, on-network queries, actions, skills.
const INDEX_HTML: &str = include_str!("assets/index.html");

/// `GET /metrics` — the Prometheus exposition for `registry`.
///
/// Its own router so the decision to serve it stays one line at the call site (see
/// [`serve_metrics`]) and the handler can be exercised without standing up the
/// whole app. Unauthenticated, like `/version`: whatever fronts this process is
/// what keeps it off the public internet.
fn metrics_router(registry: prometheus::Registry, metrics: imcp2::metrics::Metrics) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            // Clone per request so the handler stays `Fn` while the async body owns
            // what it needs; both handles are `Arc`-backed.
            let (registry, metrics) = (registry.clone(), metrics.clone());
            async move {
                // Pull the derived session gauges immediately before encoding, so
                // what is reported is exact as of this scrape rather than as of
                // whenever it was last pushed. Which servers get refreshed was
                // decided by the `track` calls at startup; an embedder calls
                // refresh from its own exposition path, or on a timer, instead.
                metrics.refresh().await;

                let started = std::time::Instant::now();
                let encoded = {
                    use prometheus::Encoder;
                    let mut buf = Vec::new();
                    prometheus::TextEncoder::new()
                        .encode(&registry.gather(), &mut buf)
                        .map_err(|e| e.to_string())
                        .and_then(|()| String::from_utf8(buf).map_err(|e| e.to_string()))
                };
                // After the gather, so this response reports the *previous* scrape's
                // cost. A scrape cannot time itself and also contain the timing.
                metrics.observe_scrape(started.elapsed().as_secs_f64());
                match encoded {
                    Ok(body) => (
                        axum::http::StatusCode::OK,
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain; version=0.0.4; charset=utf-8",
                        )],
                        body,
                    ),
                    // A scrape failure must not be silent: Prometheus reads a
                    // non-200 as the target being down, which is the honest reading.
                    Err(e) => {
                        tracing::error!(error = %e, "failed to encode metrics");
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                            String::from("failed to encode metrics\n"),
                        )
                    }
                }
            }
        }),
    )
}

/// The public, human-facing pages this origin serves, as absolute-path
/// suffixes. This is the sitemap's and robots.txt's shared idea of "content":
/// every other route is machine surface that a crawler has no use for and that
/// we do not want indexed — `/mcp` (+ `/mcp-beta`) answer 401 to an
/// unauthenticated fetch, `/version` is an operations probe, `/status/` is the
/// dashboard, and `/.well-known/*` documents are for clients, not readers.
/// Keep in step with the page routes registered in `main`.
const PUBLIC_PAGES: &[&str] = &["/", "/privacy-policy", "/terms", "/support"];

/// Escape the five XML metacharacters. `PUBLIC_URL` is operator-supplied, so a
/// stray `&` in it must not produce a malformed sitemap that a crawler rejects
/// wholesale.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// `GET /sitemap.xml` — a [sitemaps.org] 0.9 urlset naming the public pages.
///
/// The entries must be absolute, so they are built from `PUBLIC_URL` at
/// startup rather than baked in: staging and production then each advertise
/// their own origin instead of both claiming production's. A trailing slash on
/// the configured value is trimmed so the joins can't yield `//privacy-policy`.
///
/// Deliberately `<loc>`-only: `<lastmod>` would have to come from build time,
/// which changes on every redeploy whether or not a page did, and `changefreq`
/// and `priority` are ignored by the major crawlers.
///
/// [sitemaps.org]: https://www.sitemaps.org/protocol.html
fn sitemap_xml(public_url: &str) -> String {
    let origin = xml_escape(public_url.trim_end_matches('/'));
    let urls: String = PUBLIC_PAGES
        .iter()
        .map(|p| format!("  <url><loc>{origin}{}</loc></url>\n", if *p == "/" { "/" } else { p }))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n\
         {urls}</urlset>\n"
    )
}

/// `GET /robots.txt` — points crawlers at the sitemap (its only discovery
/// path, short of submitting it to each search console by hand) and keeps them
/// off the machine surface. Nothing here is a security control: the paths it
/// names are already either authenticated or harmless, and robots.txt is
/// advisory. It exists so crawl budget goes to the four pages that are worth
/// reading and so the MCP and probe endpoints stay out of search results.
fn robots_txt(public_url: &str) -> String {
    let origin = public_url.trim_end_matches('/');
    format!(
        "User-agent: *\n\
         Allow: /\n\
         Disallow: /mcp\n\
         Disallow: /mcp-beta\n\
         Disallow: /version\n\
         Disallow: /status/\n\
         Disallow: /.well-known/\n\
         \n\
         Sitemap: {origin}/sitemap.xml\n"
    )
}

/// Serve `/sitemap.xml` and `/robots.txt` for the given public origin, each
/// with the content type its consumers expect (`application/xml` and
/// `text/plain`).
fn site_metadata_router(public_url: &str) -> Router {
    let sitemap = sitemap_xml(public_url);
    let robots = robots_txt(public_url);
    Router::new()
        .route(
            "/sitemap.xml",
            get(move || {
                let sitemap = sitemap.clone();
                async move { ([(axum::http::header::CONTENT_TYPE, "application/xml")], sitemap) }
            }),
        )
        .route(
            "/robots.txt",
            get(move || {
                let robots = robots.clone();
                async move {
                    ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], robots)
                }
            }),
        )
}

/// The OpenAI Apps domain-verification endpoint. During a ChatGPT-directory
/// submission the portal reveals a token that
/// `GET /.well-known/openai-apps-challenge` must return VERBATIM as the whole
/// body — plain text, exactly one token, no JSON ("do not return JSON, a list
/// of tokens, or multiple tokens from the same URL"). The token is public by
/// design (the endpoint is world-readable proof of domain control); it
/// arrives as the env var `$OPENAI_APPS_CHALLENGE_TOKEN`, substituted into
/// the unit by `deploy.sh` from the repository secret of the same name, and
/// the route serves 404 while the value is unset or blank, keeping the
/// endpoint inert until a submission is actually in flight. The value is
/// trimmed so unit-file whitespace can't corrupt the exact-match comparison
/// OpenAI performs.
fn openai_apps_challenge_router(token: Option<String>) -> Router {
    let token = token.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    Router::new().route(
        "/.well-known/openai-apps-challenge",
        get(move || {
            let token = token.clone();
            async move {
                use axum::response::IntoResponse;
                match token {
                    Some(t) => (axum::http::StatusCode::OK, t).into_response(),
                    None => axum::http::StatusCode::NOT_FOUND.into_response(),
                }
            }
        }),
    )
}

/// The privacy policy served at `/privacy-policy` — the URL the Anthropic
/// connectors-directory listing points at, and the target of the landing
/// page's footer link. The markup lives in
/// `assets/privacy-policy.html` (compiled in via `include_str!`, no runtime
/// file I/O) and shares the connect flow's ICP identity so it reads as the
/// same product. Its one substitution is the shared DFINITY wordmark
/// (`assets/dfinity-logo.svg`), inlined once on first use so the served page
/// stays fully self-contained (no external fonts, scripts, or images).
const PRIVACY_POLICY_HTML: &str = include_str!("assets/privacy-policy.html");
const DFINITY_LOGO_SVG: &str = include_str!("assets/dfinity-logo.svg");

fn privacy_policy_page() -> &'static str {
    static PAGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| PRIVACY_POLICY_HTML.replace("__LOGO__", DFINITY_LOGO_SVG))
}

/// The support page served at `/support` — the customer-support URL the
/// directory listings (OpenAI requires a URL, not just an address) point at.
/// Same construction as `/privacy-policy`: a self-contained document sharing
/// the connect flow's ICP identity, with the DFINITY wordmark as its one
/// substitution. It routes users to mcp@dfinity.org, the status dashboard,
/// id.ai's access management, GitHub issues, and the security policy.
const SUPPORT_HTML: &str = include_str!("assets/support.html");

fn support_page() -> &'static str {
    static PAGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| SUPPORT_HTML.replace("__LOGO__", DFINITY_LOGO_SVG))
}

/// The Terms of Service served at `/terms` — the terms URL the directory
/// listings point at, and the usage contract the privacy policy's
/// performance-of-service legal basis rests on. Same construction as
/// `/privacy-policy` and `/support`.
const TERMS_HTML: &str = include_str!("assets/terms.html");

fn terms_page() -> &'static str {
    static PAGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| TERMS_HTML.replace("__LOGO__", DFINITY_LOGO_SVG))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    // The boundary-node agent is built HERE (the deployment owns this choice)
    // and injected; a host embedding the library would pass its own instead.
    let agent = Agent::builder().with_url(IC_URL).build()?;
    tracing::info!("built ic-agent against {IC_URL}");
    let public_url = public_url();

    // Dynamic client registrations are II-agnostic (redirect allow-list only),
    // so all instances share one store (and one persisted snapshot).
    let clients = SharedClients::load();

    // Production Internet Identity at `/mcp`: always served, and the origin's
    // default instance (it answers the plain-root discovery probes). A
    // self-contained McpServer whose sessions/tokens never cross instances.
    let prod = McpServer::new(McpConfig {
        agent: agent.clone(),
        instance: IiInstance::prod().map_err(anyhow::Error::msg)?,
        public_url: public_url.clone(),
        mcp_path: "/mcp".into(),
        clients: clients.clone(),
        require_resource: require_resource(),
    });
    prod.spawn_session_reaper();

    // Beta Internet Identity at `/mcp-beta`: opt in via `$MCP_SERVE_BETA`, so
    // only the staging deployment exposes it; production serves `/mcp` alone.
    let beta = if serve_beta() {
        let beta = McpServer::new(McpConfig {
            agent,
            instance: IiInstance::beta().map_err(anyhow::Error::msg)?,
            public_url: public_url.clone(),
            mcp_path: "/mcp-beta".into(),
            clients,
            require_resource: require_resource(),
        });
        beta.spawn_session_reaper();
        Some(beta)
    } else {
        None
    };

    // When this process started — i.e. when the deployment last (re)started.
    // Every deploy restarts the service, so this is the "last redeployment" time.
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Handles for the /version live-session gauges (Arc-backed, so cloning
    // shares the same session maps the tools mutate). Beta is `Option`: the
    // gauge reports zero for it when the staging instance isn't served.
    let (ver_prod, ver_beta) = (prod.clone(), beta.clone());

    // Metrics registry. Built once; the handle is cloned into the middleware and
    // the /metrics route. A failure here means duplicate collector names, i.e. a
    // programming error, so surface it at startup rather than serving a
    // half-registered endpoint.
    // This binary is the standalone case, so it owns the registry. An embedder
    // passes its own instead; see imcp2::metrics.
    let registry = prometheus::Registry::new();
    let metrics = imcp2::metrics::Metrics::new(
        &registry,
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_SHA").unwrap_or("unknown"),
        started_at,
    )?;
    // CPU / RSS / file descriptors. Registered here rather than by the library:
    // `process_*` describes the whole OS process, which belongs to the
    // application, and this binary *is* the application.
    imcp2::metrics::register_process_collector(&registry)?;
    // Register the served instances so `Metrics::refresh` knows what to publish.
    // An unserved instance is simply not tracked and has no series, which reads as
    // "no such instance here" rather than "exists, currently idle".
    metrics.track(&prod);
    if let Some(beta) = &beta {
        metrics.track(beta);
    }

    // Which II each served mount hands off to. Built once (fixed for the process)
    // and cloned per request. This is the only way an external monitor can learn
    // the pairing: neither the mount path nor the origin implies it —
    // `mcp.internetcomputer.org` pairs with `id.ai`, not with
    // `internetcomputer.org` — and `II_URL`/`II_URL_PROD` can move the origins at
    // runtime, so reporting the resolved value beats any list a monitor hardcodes.
    // Only served instances are listed, so `/mcp-beta` appears iff $MCP_SERVE_BETA
    // put it on the router.
    let instances = serde_json::Value::Array(
        std::iter::once(&prod)
            .chain(beta.as_ref())
            .map(|s| {
                let i = s.instance();
                serde_json::json!({
                    "name": i.name,
                    "mcp_path": s.mcp_path(),
                    "ii_origin": i.ii_url,
                    "ii_canister": i.ii_canister.to_text(),
                })
            })
            .collect(),
    );

    let mut app = Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .route("/privacy-policy", get(|| async { Html(privacy_policy_page()) }))
        .route("/support", get(|| async { Html(support_page()) }))
        .route("/terms", get(|| async { Html(terms_page()) }))
        // Unauthenticated build/version probe so operators and the status
        // dashboard can confirm exactly which deployment is live: the running
        // commit (baked in at build time via GIT_SHA), the build time
        // (BUILD_TIME), and when this process started (= last redeployment).
        // Timestamps are Unix epoch seconds (or null when unknown).
        .route(
            "/version",
            get(move || {
                // Clone the Arc-backed handles per request so the handler stays
                // `Fn` (reusable across requests) while the async body owns them.
                let ver_prod = ver_prod.clone();
                let ver_beta = ver_beta.clone();
                let instances = instances.clone();
                async move {
                    // Per-instance session gauges, each from one lock + iteration
                    // of the session map:
                    // - live_sessions: authenticated sessions whose II grant has
                    //   not yet expired. Tracks the grant lifecycle — an idle
                    //   session still counts; only expiry removes it.
                    // - active_sessions: the subset also seen requesting within the
                    //   activity window (~15 min) — a ballpark of who is working
                    //   right now, for timing a low-disruption redeploy.
                    // Beta reports zero when the staging instance isn't served.
                    let prod = ver_prod.session_gauges().await;
                    let beta = match &ver_beta {
                        Some(b) => Some(b.session_gauges().await),
                        None => None,
                    };
                    let (beta_live, beta_active) =
                        beta.map(|g| (g.live, g.active)).unwrap_or((0, 0));
                    Json(serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "commit": option_env!("GIT_SHA").unwrap_or("unknown"),
                        "built_at": option_env!("BUILD_TIME").and_then(|s| s.parse::<u64>().ok()),
                        "started_at": started_at,
                        // The II instances this origin actually serves: mount path,
                        // the II origin that mount hands off to, and that II's
                        // canister id. A status monitor needs this to probe the
                        // right II — the pairing is not derivable from the origin.
                        "instances": instances,
                        // Per-instance count of live sessions: authenticated
                        // sessions with a non-expired II grant. A session counts
                        // from grant redemption until its grant expires, idle or not.
                        "live_sessions": { "prod": prod.live, "beta": beta_live },
                        // Per-instance count of active sessions: the subset of live
                        // sessions that also made a request within the ~15-min
                        // activity window. Use this (not live_sessions) to time a
                        // redeploy for minimal disruption.
                        "active_sessions": { "prod": prod.active, "beta": beta_active },
                    }))
                }
            }),
        )
        // `nest_service`, not `nest`: it also forwards the bare trailing-slash
        // form (`/mcp/`), which axum's `nest` never routes into the nested router.
        .nest_service(prod.mcp_path(), prod.mcp_router())
        .merge(prod.well_known_router())
        // `/mcp` (production II) is the default instance: it owns the plain-root
        // documents that clients probing the bare origin fall back to.
        .merge(prod.root_well_known_router())
        // OpenAI Apps domain verification: inert (404) until
        // $OPENAI_APPS_CHALLENGE_TOKEN is set for a directory submission.
        .merge(openai_apps_challenge_router(
            std::env::var("OPENAI_APPS_CHALLENGE_TOKEN").ok(),
        ))
        // /sitemap.xml + /robots.txt, built from this deployment's PUBLIC_URL.
        .merge(site_metadata_router(&public_url));

    // Prometheus exposition, registered only when $MCP_SERVE_METRICS opts in —
    // see `serve_metrics()` for why the default is off. Unauthenticated like
    // /version when it is served, so whatever fronts this process is what keeps
    // it off the public internet.
    //
    // The request-metrics middleware below is NOT gated: it stays on so the
    // recorded state is the same whether or not anything can read it, and an
    // operator who flips this on gets counters that were already counting rather
    // than a registry that starts at zero mid-incident.
    if serve_metrics() {
        app = app.merge(metrics_router(registry, metrics.clone()));
    } else {
        // Say so once at startup. A silently absent endpoint is indistinguishable
        // from a broken one when a scrape 404s and someone has to work out why.
        tracing::info!(
            "/metrics not served; set MCP_SERVE_METRICS=1 to enable (do not expose it publicly)"
        );
    }

    // Staging additionally serves the beta II instance at `/mcp-beta`.
    if let Some(beta) = &beta {
        app = app
            .nest_service(beta.mcp_path(), beta.mcp_router())
            .merge(beta.well_known_router());
    }

    // The II auth-callback allow-list is origin-global: one document declares
    // every served instance's callbacks (prod always, beta only on staging).
    let servers: Vec<&McpServer> = std::iter::once(&prod).chain(beta.as_ref()).collect();
    let app = app
        .merge(auth_callbacks_router(&servers))
        // Log every inbound request (method, path, status, latency) so we can see
        // what external clients actually hit — discovery probes, unknown paths,
        // etc. Only the path is logged, never the query string, so single-use
        // secrets (`?code=`) don't land in logs.
        // Two layers rather than one. They have different constraints — metrics
        // must bound every label, a log line is more useful carrying the full
        // path — and splitting them lets an embedder take either independently.
        .layer(axum::middleware::from_fn_with_state(
            metrics.clone(),
            imcp2::metrics::write_request_metrics,
        ))
        .layer(axum::middleware::from_fn(
            imcp2::metrics::write_request_logs,
        ));

    let bind = bind_address();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    match beta.as_ref() {
        Some(beta) => tracing::info!(
            "listening on http://{bind}  (MCP at {} and {}, OAuth under each mount)",
            prod.mcp_path(),
            beta.mcp_path(),
        ),
        None => tracing::info!(
            "listening on http://{bind}  (MCP at {}, OAuth under it)",
            prod.mcp_path(),
        ),
    }
    // Drain-then-cancel, on ALL exit paths. `with_graceful_shutdown` stops
    // accepting new connections and drains the in-flight ones first; only then
    // do we cancel the rmcp services' tokens (via McpServer::shutdown). Ordering
    // matters: cancelling asks rmcp to terminate active sessions, so cancelling
    // before the drain would cut the very in-flight MCP requests we want to
    // finish. Capturing the result rather than `?`-ing it means an unexpected
    // serve error (accept failure, etc.) still cancels the tokens before the
    // error propagates. (Stateless, no long-lived SSE, so there's nothing for
    // the tokens to cut post-drain.)
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    prod.shutdown();
    if let Some(beta) = &beta {
        beta.shutdown();
    }
    serve_result?;
    Ok(())
}

/// Resolves when the process is asked to stop, so `axum` drains in-flight
/// requests before exit rather than being cut mid-response. The per-instance
/// cancellation tokens are cancelled by the caller *after* the drain completes,
/// not here (see the call site).
///
/// Handles BOTH signals: an interactive run is stopped with `SIGINT` (Ctrl-C),
/// but `systemctl stop`/`restart` sends **`SIGTERM`** — which this previously did
/// not catch, so a redeploy killed the process abruptly and severed in-flight
/// requests. We now wait on either.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // If the SIGTERM handler can't be installed, fall back to SIGINT only
        // rather than aborting startup.
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!("could not install SIGTERM handler ({e}); draining on SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

#[cfg(test)]
mod tests {
    use super::{
        metrics_router, openai_apps_challenge_router, serve_metrics, site_metadata_router,
        sitemap_xml, PUBLIC_PAGES,
    };
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// The exposition must be **off** unless asked for, and the ask must be
    /// explicit. This is the security-relevant half of the gate: the native host
    /// has a proxy answering `/metrics` with a 404, but the bundled `Dockerfile` on
    /// a PaaS has no proxy at all, so a default-on endpoint would publish request
    /// volumes, session counts and process memory — and hand out a registry-wide
    /// gather per request — on a deployment path we ship.
    ///
    /// Truthiness only, matching `MCP_SERVE_BETA`: anything else, including the
    /// plausible-looking `MCP_SERVE_METRICS=please`, leaves it off. `$MCP_SERVE_BETA`
    /// is untouched here — the two gates are independent and this is the only test
    /// that writes this process-global variable.
    #[test]
    fn the_metrics_endpoint_is_off_unless_explicitly_enabled() {
        std::env::remove_var("MCP_SERVE_METRICS");
        assert!(!serve_metrics(), "unset must mean off");
        for on in ["1", "true", "yes", "on", "TRUE", " on "] {
            std::env::set_var("MCP_SERVE_METRICS", on);
            assert!(serve_metrics(), "{on:?} should enable the endpoint");
        }
        for off in ["", "0", "false", "no", "off", "please", "2", "-1"] {
            std::env::set_var("MCP_SERVE_METRICS", off);
            assert!(!serve_metrics(), "{off:?} must not enable the endpoint");
        }
        std::env::remove_var("MCP_SERVE_METRICS");
    }

    /// When it *is* served: the exposition renders the caller's registry, carries
    /// the text format's version in its content type (Prometheus negotiates on it),
    /// and records its own cost — a scrape that quietly got slow is how a target
    /// starts being dropped for timing out, and the resulting gap looks like an
    /// outage that never happened.
    #[tokio::test]
    async fn metrics_endpoint_renders_the_registry_and_times_the_previous_scrape() {
        let registry = prometheus::Registry::new();
        let metrics =
            imcp2::metrics::Metrics::new(&registry, "1.2.3", "abc1234", 1_700_000_000).unwrap();
        let app = metrics_router(registry, metrics);

        let scrape = |app: axum::Router| async move {
            let resp = app
                .oneshot(Request::get("/metrics").body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let content_type =
                resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8(body.to_vec()).unwrap(), content_type)
        };

        let (status, body, content_type) = scrape(app.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("text/plain; version=0.0.4; charset=utf-8"));
        assert!(body.contains(r#"imcp2_build_info{commit="abc1234",version="1.2.3"} 1"#), "{body}");
        assert!(body.contains("imcp2_process_start_time_seconds 1700000000"), "{body}");
        // Its own timing cannot appear in the response that produced it.
        assert!(body.contains("imcp2_metrics_scrape_duration_seconds_count 0"), "{body}");

        // The next one reports the previous one's cost.
        let (_, body, _) = scrape(app).await;
        assert!(body.contains("imcp2_metrics_scrape_duration_seconds_count 1"), "{body}");
    }

    async fn fetch(public_url: &str, path: &str) -> (StatusCode, String, Option<String>) {
        let resp = site_metadata_router(public_url)
            .oneshot(Request::get(path).body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let content_type =
            resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap(), content_type)
    }

    // Every public page must appear exactly once, as an ABSOLUTE url on the
    // configured origin: a sitemap of relative paths, or one naming another
    // deployment's origin, is rejected or ignored by crawlers.
    #[tokio::test]
    async fn sitemap_lists_every_public_page_as_an_absolute_url() {
        let (status, body, content_type) =
            fetch("https://mcp.internetcomputer.org", "/sitemap.xml").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("application/xml"));
        for page in PUBLIC_PAGES {
            let loc = format!("<loc>https://mcp.internetcomputer.org{page}</loc>");
            assert_eq!(body.matches(&loc).count(), 1, "{page} should appear once in:\n{body}");
        }
        assert_eq!(body.matches("<loc>").count(), PUBLIC_PAGES.len());
        // The machine surface stays out: these must never be advertised.
        for hidden in ["/version", "/status/", "/.well-known", "/mcp<", "/mcp-beta"] {
            assert!(!body.contains(hidden), "sitemap must not list {hidden}:\n{body}");
        }
    }

    // A trailing slash on PUBLIC_URL must not produce `//privacy-policy`, and
    // the root entry must stay exactly one slash.
    #[tokio::test]
    async fn sitemap_normalizes_a_trailing_slash_on_the_public_url() {
        let body = sitemap_xml("https://example.test/");
        assert!(body.contains("<loc>https://example.test/</loc>"));
        assert!(body.contains("<loc>https://example.test/terms</loc>"));
        assert!(!body.contains("//terms"));
    }

    // An operator-supplied origin is escaped, so a stray metacharacter cannot
    // emit a malformed document that a crawler discards wholesale.
    #[tokio::test]
    async fn sitemap_escapes_xml_metacharacters_in_the_origin() {
        let body = sitemap_xml("https://example.test/?a=1&b=2");
        assert!(body.contains("&amp;b=2"), "{body}");
        assert!(!body.contains("&b=2"));
    }

    // robots.txt is the sitemap's only discovery path for a crawler that was
    // never handed the URL directly, so the absolute reference must be there.
    #[tokio::test]
    async fn robots_points_at_the_sitemap_and_excludes_the_machine_surface() {
        let (status, body, content_type) =
            fetch("https://mcp.internetcomputer.org/", "/robots.txt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("text/plain; charset=utf-8"));
        assert!(body.contains("Sitemap: https://mcp.internetcomputer.org/sitemap.xml"), "{body}");
        for path in ["/mcp", "/mcp-beta", "/version", "/status/", "/.well-known/"] {
            assert!(body.contains(&format!("Disallow: {path}\n")), "{path} missing:\n{body}");
        }
    }

    async fn challenge(token: Option<&str>) -> (StatusCode, String, Option<String>) {
        let app = openai_apps_challenge_router(token.map(str::to_string));
        let resp = app
            .oneshot(
                Request::get("/.well-known/openai-apps-challenge")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap(), content_type)
    }

    // The endpoint must return ONLY the token (plain text, no JSON wrapper):
    // OpenAI compares the whole body against the token it revealed in the
    // portal. Trimming guards against unit-file whitespace breaking that
    // exact match.
    #[tokio::test]
    async fn openai_challenge_serves_the_bare_token_when_configured() {
        let (status, body, content_type) = challenge(Some(" tok-123\n")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "tok-123");
        assert!(content_type.unwrap().starts_with("text/plain"));
    }

    // Unset or blank means no submission is in flight: the endpoint stays
    // inert rather than serving an empty body OpenAI would fail against.
    #[tokio::test]
    async fn openai_challenge_is_404_when_unset_or_blank() {
        for token in [None, Some(""), Some("   \n")] {
            let (status, body, _) = challenge(token).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "token {token:?}");
            assert_eq!(body, "", "token {token:?}");
        }
    }
}
