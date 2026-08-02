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
//! `$MCP_SERVE_BETA` (opt in to the `/mcp-beta` staging instance), and
//! `$OPENAI_APPS_CHALLENGE_TOKEN` (serve the OpenAI Apps domain-verification
//! token at `/.well-known/openai-apps-challenge`; 404 while unset).

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

/// Whether to also serve the beta Internet Identity instance at `/mcp-beta`.
/// Off unless `$MCP_SERVE_BETA` is truthy (`1`/`true`/`yes`/`on`), so a
/// production deployment serves only `/mcp` (production II) and the staging
/// deployment opts in to the extra beta endpoint.
fn serve_beta() -> bool {
    std::env::var("MCP_SERVE_BETA")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
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

/// The OpenAI Apps domain-verification endpoint. During a ChatGPT-directory
/// submission the portal reveals a token that
/// `GET /.well-known/openai-apps-challenge` must return VERBATIM as the whole
/// body — plain text, exactly one token, no JSON ("do not return JSON, a list
/// of tokens, or multiple tokens from the same URL"). The token is public by
/// design (the endpoint is world-readable proof of domain control), so it
/// arrives as the ordinary env var `$OPENAI_APPS_CHALLENGE_TOKEN` — a
/// repository *variable*, not a secret, substituted into the unit by
/// `deploy.sh` — and the route serves 404 while the variable is unset or
/// blank, keeping the endpoint inert until a submission is actually in
/// flight. The value is trimmed so unit-file whitespace can't corrupt the
/// exact-match comparison OpenAI performs.
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
        ));

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
        .layer(axum::middleware::from_fn(log_request));

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
    use super::openai_apps_challenge_router;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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
