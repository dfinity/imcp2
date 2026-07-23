//! Deployment binary for the [`imcp2`] library: composes two Internet Identity
//! instances at their canonical paths and adds the deployment niceties (the
//! landing page, a `/version` probe with live-session gauges, request logging,
//! env-driven config, drained graceful shutdown).
//!
//!   * `/mcp` — MCP endpoint against **beta** Internet Identity, with its
//!     OAuth AS at `/mcp/oauth/*` (issuer `<PUBLIC_URL>/mcp`)
//!   * `/mcp-prod` — the same against **production** Internet Identity
//!     (`/mcp-prod/oauth/*`, issuer `<PUBLIC_URL>/mcp-prod`)
//!   * `/.well-known/*` — the OAuth discovery documents (path-inserted per
//!     instance, plus the plain-root fallbacks for the default beta instance)
//!     and the origin-global II auth-callback allow-list
//!
//! Honours `$PORT` (bind port, default 8000) and `$PUBLIC_URL` (the public
//! base URL baked into the discovery documents and the II handshake).

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

/// Log each inbound request: method, path, response status, and latency — gives
/// visibility into what external MCP clients probe (discovery URLs, unknown
/// paths) at `RUST_LOG=info`. The query string is never logged (defense in depth,
/// keeping any single-use `?code=` out of logs) — and request bodies are never
/// logged (the redeem POST carries the connection-scoped `state` and delegation).
async fn log_request(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let elapsed_ms = started.elapsed().as_millis() as u64;
    tracing::info!(%method, %path, status, elapsed_ms, "http request");
    resp
}

/// The landing page served at `/`. Markup, stylesheet, and the DFINITY mark
/// live in `assets/` (compiled in via `include_str!`, no runtime file I/O) so
/// the page is fully self-contained: no external fonts, scripts, or images.
/// It shares the connect flow's ICP look (parchment grid, editorial serif,
/// rust accent, foot-of-page "Hosted by" mark) so the root page and the connect
/// screens read as one product. Tools are grouped by what they do: service
/// discovery, user identity, OQL, actions, and skills.
const INDEX_HTML_TEMPLATE: &str = include_str!("assets/index.html");
const INDEX_PAGE_CSS: &str = include_str!("assets/index.css");
const DFINITY_LOGO_SVG: &str = include_str!("assets/dfinity-logo.svg");

/// The rendered landing page, built once on first request. Splicing the
/// stylesheet and logo into the template is a couple of string replacements;
/// doing it lazily keeps it off the hot path and out of a `const` (which can't
/// call `.replace`). `__CSS__`/`__LOGO__` are the same placeholder convention
/// the connect pages use; the sources carry no such tokens, so no ordering hazard.
static INDEX_HTML: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    INDEX_HTML_TEMPLATE
        .replace("__CSS__", INDEX_PAGE_CSS)
        .replace("__LOGO__", DFINITY_LOGO_SVG)
});

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
    // so both instances share one store — and one persisted snapshot.
    let clients = SharedClients::load();

    // Two Internet Identity instances, each a self-contained McpServer:
    // sessions/tokens never cross instances. Beta is the origin's default
    // instance (it also answers the plain-root discovery probes).
    let beta = McpServer::new(McpConfig {
        agent: agent.clone(),
        instance: IiInstance::beta().map_err(anyhow::Error::msg)?,
        public_url: public_url.clone(),
        mcp_path: "/mcp".into(),
        clients: clients.clone(),
    });
    let prod = McpServer::new(McpConfig {
        agent,
        instance: IiInstance::prod().map_err(anyhow::Error::msg)?,
        public_url: public_url.clone(),
        mcp_path: "/mcp-prod".into(),
        clients,
    });
    // Per-instance session reapers (expired-grant eviction + close-event logs).
    beta.spawn_session_reaper();
    prod.spawn_session_reaper();

    // When this process started — i.e. when the deployment last (re)started.
    // Every deploy restarts the service, so this is the "last redeployment" time.
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Per-instance handles for the /version live-session gauge (Arc-backed, so
    // cloning shares the same session maps the tools mutate).
    let (ver_beta, ver_prod) = (beta.clone(), prod.clone());

    let app = Router::new()
        .route("/", get(|| async { Html(INDEX_HTML.as_str()) }))
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
                let ver_beta = ver_beta.clone();
                let ver_prod = ver_prod.clone();
                async move {
                    // Two per-instance session gauges, each from one lock +
                    // iteration of the session map:
                    // - live_sessions: authenticated sessions whose II grant has
                    //   not yet expired. Tracks the grant lifecycle — an idle
                    //   session still counts; only expiry removes it.
                    // - active_sessions: the subset also seen requesting within the
                    //   activity window (~15 min) — a ballpark of who is working
                    //   right now, for timing a low-disruption redeploy.
                    let beta = ver_beta.session_gauges().await;
                    let prod = ver_prod.session_gauges().await;
                    Json(serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "commit": option_env!("GIT_SHA").unwrap_or("unknown"),
                        "built_at": option_env!("BUILD_TIME").and_then(|s| s.parse::<u64>().ok()),
                        "started_at": started_at,
                        // Per-instance count of live sessions: authenticated
                        // sessions with a non-expired II grant. A session counts
                        // from grant redemption until its grant expires, idle or not.
                        "live_sessions": { "beta": beta.live, "prod": prod.live },
                        // Per-instance count of active sessions: the subset of live
                        // sessions that also made a request within the ~15-min
                        // activity window. Use this (not live_sessions) to time a
                        // redeploy for minimal disruption.
                        "active_sessions": { "beta": beta.active, "prod": prod.active },
                    }))
                }
            }),
        )
        // `nest_service`, not `nest`: it also forwards the bare trailing-slash
        // form (`/mcp/`), which axum's `nest` never routes into the nested router.
        .nest_service(beta.mcp_path(), beta.mcp_router())
        .nest_service(prod.mcp_path(), prod.mcp_router())
        .merge(beta.well_known_router())
        .merge(prod.well_known_router())
        // Beta is the default instance: it also owns the plain-root documents.
        .merge(beta.root_well_known_router())
        // The II auth-callback allow-list is origin-global: one document
        // declares BOTH instances' callbacks.
        .merge(auth_callbacks_router(&[&beta, &prod]))
        // Log every inbound request (method, path, status, latency) so we can see
        // what external clients actually hit — discovery probes, unknown paths,
        // etc. Only the path is logged, never the query string, so single-use
        // secrets (`?code=`) don't land in logs.
        .layer(axum::middleware::from_fn(log_request));

    let bind = bind_address();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(
        "listening on http://{bind}  (MCP at {} and {}, OAuth under each mount)",
        beta.mcp_path(),
        prod.mcp_path(),
    );
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
    beta.shutdown();
    prod.shutdown();
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
