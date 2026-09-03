//! Deployment binary for the [`imcp2`] library: serves the production Internet
//! Identity instance at `/mcp` and adds the deployment niceties (permanent
//! redirects to the landing site's home on internetcomputer.org, a `/version`
//! probe with live-session gauges, request logging, env-driven config, drained
//! graceful shutdown).
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
//! Also serves `/robots.txt` (keeping crawlers off the machine surface) and
//! `/favicon.svg` (the tab icon the connect screens link).

use axum::{routing::get, Json, Router};
use imcp2::{
    auth_callbacks_router, ii_app_metadata_router, Agent, IiInstance, McpConfig, McpServer,
    SharedClients, IC_URL,
};
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

/// Directory imcp2 creates its operational files in (today: the persisted
/// client-registration store). Set with `IMCP2_STATE_DIR`; defaults to the
/// process's current working directory, so a bare local run keeps
/// `oauth-clients.json` under the directory it was launched from, as before. The
/// native deployment points it at the unit's `StateDirectory` (`/var/lib/imcp2`).
fn state_dir() -> std::path::PathBuf {
    std::env::var_os("IMCP2_STATE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
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
/// Off by default because the default deployment shape is the exposed one: the
/// bundled Dockerfile has no proxy in front, so every registered route is on the
/// public internet. The native host opts in — its Caddy answers `/metrics` with a
/// 404, so the endpoint exists only on the app's own port. Public exposition
/// would hand out request/session/process data and a whole-registry gather per
/// request.
fn serve_metrics() -> bool {
    std::env::var("MCP_SERVE_METRICS")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// The landing site's home. The human-facing pages this origin used to serve
/// itself — the landing page and its `/privacy-policy`, `/support` and
/// `/terms` subpages — are maintained in one place, dfinity/internetcomputer-org
/// (`public/icp-mcp/`), and served at internetcomputer.org under this prefix.
/// This origin answers their old paths with permanent redirects instead of
/// copies, so every published link keeps working — the directory listings'
/// policy URLs, old bookmarks, search results — while the content exists
/// exactly once. `/status/` is unaffected: the live dashboard is this
/// deployment's own monitoring surface, published by the fronting proxy.
const LANDING_SITE: &str = "https://internetcomputer.org/icp-mcp";

/// The page paths this origin used to serve, each answered with a permanent
/// redirect (308) to its home under [`LANDING_SITE`]. The targets carry the
/// trailing slash the static site canonicalizes to, so a client lands in one
/// hop.
fn landing_redirects_router() -> Router {
    const PAGES: &[(&str, &str)] = &[
        ("/", "/"),
        ("/privacy-policy", "/privacy-policy/"),
        ("/support", "/support/"),
        ("/terms", "/terms/"),
    ];
    let mut router = Router::new();
    for (path, target) in PAGES {
        router = router.route(
            path,
            get(move || async move {
                axum::response::Redirect::permanent(&format!("{LANDING_SITE}{target}"))
            }),
        );
    }
    router
}

/// `GET /metrics` — the Prometheus exposition for `registry`. Its own router so
/// the gate stays one line at the call site (see [`serve_metrics`]) and the
/// handler is testable alone. Unauthenticated, like `/version`: whatever fronts
/// this process is what keeps it off the public internet.
fn metrics_router(registry: prometheus::Registry, metrics: imcp2::metrics::Metrics) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            // Clone per request so the handler stays `Fn`; both are Arc-backed.
            let (registry, metrics) = (registry.clone(), metrics.clone());
            async move {
                // Timed from the top, refresh included — the refresh is the part
                // of a scrape that can get slow.
                let started = std::time::Instant::now();

                // Recompute the session gauges just before gathering, so they are
                // exact as of this scrape.
                metrics.refresh().await;

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

/// The tab icon, from forumic.com: the ICP infinity mark on transparency, so it
/// reads against both the light and dark browser chrome.
const FAVICON_SVG: &str = include_str!("assets/favicon.svg");

/// `GET /robots.txt` — keeps crawlers off the machine surface. Nothing here is
/// a security control: the paths it names are already either authenticated or
/// harmless, and robots.txt is advisory. There is no sitemap any more — the
/// human-facing pages moved to [`LANDING_SITE`] and this origin answers their
/// paths with redirects a crawler may follow — so this exists purely so the
/// MCP and probe endpoints stay out of search results.
const ROBOTS_TXT: &str = "User-agent: *\n\
    Allow: /\n\
    Disallow: /mcp\n\
    Disallow: /mcp-beta\n\
    Disallow: /version\n\
    Disallow: /status/\n\
    Disallow: /.well-known/\n";

/// Serve `/robots.txt` and `/favicon.svg`, each with the content type its
/// consumers expect (`text/plain` and `image/svg+xml`). The favicon stays
/// served with the landing pages gone: the connect and error screens link
/// `/favicon.svg` for their tab icon.
fn site_metadata_router() -> Router {
    Router::new()
        .route(
            "/favicon.svg",
            get(|| async {
                (
                    [
                        (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
                        (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
                    ],
                    FAVICON_SVG,
                )
            }),
        )
        .route(
            "/robots.txt",
            get(|| async {
                ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], ROBOTS_TXT)
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // When this process started — i.e. when the deployment last (re)started.
    // Read as the very first statement of main so it means what `/version` and
    // `imcp2_process_start_time_seconds` say it means.
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

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

    // The directory all operational files live in (the client-registration
    // store today). One place, injected into every instance's McpConfig.
    let state_dir = state_dir();

    // Dynamic client registrations are II-agnostic (redirect allow-list only),
    // so all instances share one store (and one persisted snapshot), loaded from
    // the operational directory.
    let clients = SharedClients::load(&state_dir);

    // Production Internet Identity at `/mcp`: always served, and the origin's
    // default instance (it answers the plain-root discovery probes). A
    // self-contained McpServer whose sessions/tokens never cross instances.
    let prod = McpServer::new(McpConfig {
        agent: agent.clone(),
        instance: IiInstance::prod().map_err(anyhow::Error::msg)?,
        public_url: public_url.clone(),
        mcp_path: "/mcp".into(),
        clients: clients.clone(),
        state_dir: state_dir.clone(),
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
            state_dir,
            require_resource: require_resource(),
        });
        beta.spawn_session_reaper();
        Some(beta)
    } else {
        None
    };

    // Handles for the /version live-session gauges (Arc-backed, so cloning
    // shares the same session maps the tools mutate). Beta is `Option`: the
    // gauge reports zero for it when the staging instance isn't served.
    let (ver_prod, ver_beta) = (prod.clone(), beta.clone());

    // Every served instance, in one list — the metrics constructor and the
    // origin-global auth-callback allow-list both want it.
    let servers: Vec<&McpServer> = std::iter::once(&prod).chain(beta.as_ref()).collect();

    // Metrics. This binary is the standalone case, so it owns the registry; an
    // embedder passes its own instead (see imcp2::metrics). The process collector
    // is registered here rather than by the library because un-namespaced
    // `process_*` belongs to the application, and this binary is the application.
    let registry = prometheus::Registry::new();
    let metrics = imcp2::metrics::Metrics::new(
        &registry,
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_SHA").unwrap_or("unknown"),
        started_at,
        &servers,
    )?;
    imcp2::metrics::register_process_collector(&registry)?;

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
        // The old landing-site paths: permanent redirects to their one home.
        .merge(landing_redirects_router())
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
        .merge(openai_apps_challenge_router(std::env::var("OPENAI_APPS_CHALLENGE_TOKEN").ok()))
        // /robots.txt + /favicon.svg (the icon the connect screens link).
        .merge(site_metadata_router());

    // Prometheus exposition, only when $MCP_SERVE_METRICS opts in — see
    // `serve_metrics()`. The recording middleware below stays on either way, so
    // every deployment runs the same request path; the cost is a few atomic
    // increments per request.
    if serve_metrics() {
        app = app.merge(metrics_router(registry, metrics.clone()));
    } else {
        // Say so once, or an absent endpoint looks like a broken one.
        tracing::info!(
            "/metrics not served; set MCP_SERVE_METRICS=1 to enable (do not expose it publicly)"
        );
    }

    // Staging additionally serves the beta II instance at `/mcp-beta`.
    if let Some(beta) = &beta {
        app = app.nest_service(beta.mcp_path(), beta.mcp_router()).merge(beta.well_known_router());
    }

    // The II auth-callback allow-list is origin-global: one document declares
    // every served instance's callbacks (prod always, beta only on staging).
    // So is the app-metadata document, which names this origin on II's screens.
    let app = app
        .merge(auth_callbacks_router(&servers))
        .merge(ii_app_metadata_router())
        // Request metrics and a per-request debug log line, as separate layers so
        // an embedder can take either alone. The log keeps the full path (never
        // the query string); the metrics bound every label — see imcp2::metrics.
        .layer(axum::middleware::from_fn_with_state(
            metrics.clone(),
            imcp2::metrics::write_request_metrics,
        ))
        .layer(axum::middleware::from_fn(imcp2::metrics::write_request_logs));

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
    let serve_result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await;
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
        landing_redirects_router, metrics_router, openai_apps_challenge_router, serve_metrics,
        site_metadata_router,
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
            imcp2::metrics::Metrics::new(&registry, "1.2.3", "abc1234", 1_700_000_000, &[])
                .unwrap();
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

    async fn fetch(path: &str) -> (StatusCode, String, Option<String>) {
        let resp = site_metadata_router()
            .oneshot(Request::get(path).body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let content_type =
            resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap(), content_type)
    }

    // With the pages moved out, robots.txt only keeps crawlers off the machine
    // surface — and must no longer advertise a sitemap this origin doesn't
    // serve.
    #[tokio::test]
    async fn robots_excludes_the_machine_surface_and_names_no_sitemap() {
        let (status, body, content_type) = fetch("/robots.txt").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("text/plain; charset=utf-8"));
        for path in ["/mcp", "/mcp-beta", "/version", "/status/", "/.well-known/"] {
            assert!(body.contains(&format!("Disallow: {path}\n")), "{path} missing:\n{body}");
        }
        assert!(!body.contains("Sitemap:"), "no sitemap is served any more:\n{body}");
    }

    // Every page this origin used to serve itself answers with a permanent
    // redirect to its one home on the landing site — canonical trailing-slash
    // form, so a client lands in one hop. The absolute targets are pinned: a
    // typo'd LANDING_SITE would otherwise ship a working-looking 308 to
    // nowhere.
    #[tokio::test]
    async fn old_page_paths_redirect_permanently_to_the_landing_site() {
        for (path, target) in [
            ("/", "https://internetcomputer.org/icp-mcp/"),
            ("/privacy-policy", "https://internetcomputer.org/icp-mcp/privacy-policy/"),
            ("/support", "https://internetcomputer.org/icp-mcp/support/"),
            ("/terms", "https://internetcomputer.org/icp-mcp/terms/"),
        ] {
            let resp = landing_redirects_router()
                .oneshot(Request::get(path).body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            let location =
                resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
            assert_eq!(location, target, "{path}");
        }
    }

    #[tokio::test]
    async fn favicon_is_served_as_a_cacheable_svg() {
        let resp = site_metadata_router()
            .oneshot(Request::get("/favicon.svg").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let header = |n: &str| resp.headers().get(n).map(|v| v.to_str().unwrap().to_string());
        assert_eq!(header("content-type").as_deref(), Some("image/svg+xml"));
        assert_eq!(header("cache-control").as_deref(), Some("public, max-age=86400"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let svg = String::from_utf8(body.to_vec()).unwrap();
        assert!(svg.contains("<svg"), "{svg}");
        // Transparent, so the browser's own chrome shows through in either theme.
        assert!(!svg.contains("<rect"), "the mark must stay transparent: {svg}");
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
        let content_type =
            resp.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
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
