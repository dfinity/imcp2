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
//! by default because nothing here can know whether a proxy is hiding it),
//! `$MCP_MAX_REQUEST_BODY` (the cap on an MCP request body in bytes, default
//! 4 MiB), and
//! `$OPENAI_APPS_CHALLENGE_TOKEN` (serve the OpenAI Apps domain-verification
//! token at `/.well-known/openai-apps-challenge`; 404 while unset).
//!
//! Also serves `/robots.txt` (keeping crawlers off the machine surface) and
//! `/favicon.svg` (the tab icon the connect screens link).

use axum::{routing::get, Json, Router};
use imcp2::{
    auth_callbacks_router, ii_app_metadata_router, Agent, IiInstance, McpConfig, McpServer, IC_URL,
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

/// Directory imcp2 creates its operational files in (the persisted
/// client-registration store, and the deploy tools' records and uploaded
/// bundles). Set with `IMCP2_STATE_DIR`; defaults to the process's
/// current working directory, so a bare local run keeps `oauth-clients.json`
/// under the directory it was launched from, as before. The native deployment
/// points it at the unit's `StateDirectory` (`/var/lib/imcp2`). A relative
/// path is resolved against the working directory here, once: every path
/// derived from it is absolute, which a deploy reading an uploaded bundle
/// requires. An empty value reads as unset (the working directory), as it did
/// before the path was resolved: an empty path is not one that resolves.
fn state_dir() -> std::path::PathBuf {
    resolve_state_dir(std::env::var_os("IMCP2_STATE_DIR"))
}

fn resolve_state_dir(configured: Option<std::ffi::OsString>) -> std::path::PathBuf {
    let dir = configured
        .filter(|dir| !dir.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    std::path::absolute(&dir)
        .unwrap_or_else(|e| panic!("cannot resolve IMCP2_STATE_DIR '{}': {e}", dir.display()))
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

/// The deploy tools' knobs:
///
///   * `$MCP_DEPLOY_MAX_CONCURRENT` deploys at once across sessions and
///     endpoints (default 2);
///   * `$MCP_DEPLOY_MAX_UPLOAD_BYTES` per uploaded archive, compressed
///     (default 64 MiB);
///   * `$MCP_DEPLOY_MAX_EXTRACTED_BYTES` per bundle as extracted, which is
///     what the server keeps of it (default 128 MiB);
///   * `$MCP_DEPLOY_MAX_STORED_BYTES` for every bundle the server has at
///     once, extracted (default: one bundle for each deploy at once, and one
///     more);
///   * `$MCP_DEPLOY_ALLOWED_PLUGINS`, the sha256 of each sync plugin the
///     server runs besides the ones it knows, in hex, separated by commas or
///     spaces (default: none besides);
///   * `$MCP_DEPLOY_PLUGIN_MAX_MEMORY_BYTES`, `$MCP_DEPLOY_PLUGIN_MAX_COMPUTE_SECS`
///     and `$MCP_DEPLOY_PLUGIN_MAX_WALL_CLOCK_SECS`, what each run of a sync
///     plugin is held to: its memory, its CPU time, and how long it may take
///     in all (default: the icp CLI's own, which are 4 GiB, 60 seconds and
///     no limit). Zero is refused: it would run no plugin.
///
/// A value that is not a whole number refuses to start, and so does one
/// that contradicts another rather than being quietly bent to fit: a count
/// of zero (the tools run at least one deploy), an archive cap over what a
/// bundle may extract to (an archive is never larger than its contents),
/// and a store too small for one bundle.
fn deploy_config() -> anyhow::Result<imcp2::deploy::DeployConfig> {
    let var = |name: &str| std::env::var(name).ok();
    deploy_config_from([
        var("MCP_DEPLOY_MAX_CONCURRENT").as_deref(),
        var("MCP_DEPLOY_MAX_UPLOAD_BYTES").as_deref(),
        var("MCP_DEPLOY_MAX_EXTRACTED_BYTES").as_deref(),
        var("MCP_DEPLOY_MAX_STORED_BYTES").as_deref(),
    ])
    .and_then(|config| {
        Ok(imcp2::deploy::DeployConfig {
            allowed_plugins: allowed_plugins(var("MCP_DEPLOY_ALLOWED_PLUGINS").as_deref()),
            plugin_limits: plugin_limits_from([
                var("MCP_DEPLOY_PLUGIN_MAX_MEMORY_BYTES").as_deref(),
                var("MCP_DEPLOY_PLUGIN_MAX_COMPUTE_SECS").as_deref(),
                var("MCP_DEPLOY_PLUGIN_MAX_WALL_CLOCK_SECS").as_deref(),
            ])?,
            ..config
        })
    })
}

/// The three `$MCP_DEPLOY_PLUGIN_MAX_*` variables' values, in the order
/// memory, compute, wall clock, as the limits a sync plugin runs under. One
/// that is unset leaves the icp CLI's default.
fn plugin_limits_from(
    [memory_bytes, compute_secs, wall_clock_secs]: [Option<&str>; 3],
) -> anyhow::Result<imcp2::deploy::PluginLimits> {
    let positive = |name: &str, value: Option<&str>| -> anyhow::Result<Option<u64>> {
        let Some(value) = value else { return Ok(None) };
        let n: u64 = value
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("{name} must be a whole number: {e}"))?;
        anyhow::ensure!(n > 0, "{name} must be at least 1: at zero no sync plugin could run");
        Ok(Some(n))
    };
    Ok(imcp2::deploy::PluginLimits {
        memory_bytes: positive("MCP_DEPLOY_PLUGIN_MAX_MEMORY_BYTES", memory_bytes)?,
        compute_secs: positive("MCP_DEPLOY_PLUGIN_MAX_COMPUTE_SECS", compute_secs)?,
        wall_clock: positive("MCP_DEPLOY_PLUGIN_MAX_WALL_CLOCK_SECS", wall_clock_secs)?
            .map(std::time::Duration::from_secs),
    })
}

/// `$MCP_DEPLOY_ALLOWED_PLUGINS` as its entries. Whether each is a sha256 is
/// for [`McpServer::new`] to say, which refuses to start on one
/// that is not: a list misread is a plugin wrongly refused, or wrongly run.
fn allowed_plugins(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

/// [`deploy_config`], from the four variables' values in the order above.
fn deploy_config_from(
    [concurrent, max_upload_bytes, max_extracted_bytes, max_stored_bytes]: [Option<&str>; 4],
) -> anyhow::Result<imcp2::deploy::DeployConfig> {
    let bytes = |name: &str, value: &str| {
        value
            .trim()
            .parse::<usize>()
            .map_err(|e| anyhow::anyhow!("{name} must be a byte count: {e}"))
    };
    let mut config = imcp2::deploy::DeployConfig::default();
    if let Some(v) = concurrent {
        config.concurrent = deploy_concurrency(v)?;
    }
    if let Some(v) = max_upload_bytes {
        config.max_upload_bytes = bytes("MCP_DEPLOY_MAX_UPLOAD_BYTES", v)?;
    }
    if let Some(v) = max_extracted_bytes {
        config.max_extracted_bytes = bytes("MCP_DEPLOY_MAX_EXTRACTED_BYTES", v)?;
    }
    anyhow::ensure!(
        config.max_upload_bytes <= config.max_extracted_bytes,
        "MCP_DEPLOY_MAX_UPLOAD_BYTES ({}) must be at most MCP_DEPLOY_MAX_EXTRACTED_BYTES ({}): \
         an archive is never larger than what it extracts to",
        config.max_upload_bytes,
        config.max_extracted_bytes
    );
    if let Some(v) = max_stored_bytes {
        let stored = bytes("MCP_DEPLOY_MAX_STORED_BYTES", v)?;
        anyhow::ensure!(
            stored >= config.max_extracted_bytes,
            "MCP_DEPLOY_MAX_STORED_BYTES ({stored}) must be at least \
             MCP_DEPLOY_MAX_EXTRACTED_BYTES ({}): a store smaller than one bundle takes none",
            config.max_extracted_bytes
        );
        config.max_stored_bytes = Some(stored);
    }
    Ok(config)
}

/// `$MCP_DEPLOY_MAX_CONCURRENT` as a count of at least one.
fn deploy_concurrency(value: &str) -> anyhow::Result<usize> {
    let count: usize = value
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("MCP_DEPLOY_MAX_CONCURRENT must be a count: {e}"))?;
    anyhow::ensure!(
        count > 0,
        "MCP_DEPLOY_MAX_CONCURRENT must be at least 1: the deploy tools cannot be capped at \
         zero deploys"
    );
    Ok(count)
}

/// The largest MCP request body the server reads, in bytes: `$MCP_MAX_REQUEST_BODY`
/// when set, else the library default ([`imcp2::DEFAULT_MAX_REQUEST_BODY`]). A
/// blank value reads as unset. Any other value that is not a whole number is a
/// configuration error and refuses to start, rather than silently running with
/// the default.
fn max_request_body() -> anyhow::Result<usize> {
    max_request_body_from(std::env::var("MCP_MAX_REQUEST_BODY"))
}

/// [`max_request_body`]'s reading of the variable. Unset means the default, and
/// so does blank: the native deploy renders a variable nobody set as `NAME=`
/// (see `deploy/native/imcp2.service`), and every variable templated there reads
/// that as unset, so this one does too rather than stop the service the day it
/// is templated. A value that is not Unicode is neither blank nor a byte count,
/// so it is refused like any other value that is not one.
fn max_request_body_from(value: Result<String, std::env::VarError>) -> anyhow::Result<usize> {
    use std::env::VarError;
    match value.as_deref().map(str::trim) {
        Err(VarError::NotPresent) | Ok("") => Ok(imcp2::DEFAULT_MAX_REQUEST_BODY),
        Ok(v) => v.parse().map_err(|e| {
            anyhow::anyhow!("MCP_MAX_REQUEST_BODY must be a byte count, got {v:?}: {e}")
        }),
        Err(VarError::NotUnicode(raw)) => {
            Err(anyhow::anyhow!("MCP_MAX_REQUEST_BODY must be a byte count, got {raw:?}"))
        }
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

/// Whether to advertise and accept Client ID Metadata Documents, the
/// registration mode Claude and ChatGPT prefer over DCR. **On by default**; a
/// falsey `$OAUTH_CIMD_ENABLED` (`0`/`false`/`no`/`off`) switches it off. Read
/// once and handed to every instance, so switching means setting it and
/// redeploying.
///
/// TODO: remove the variable (pass `true` to every instance) once CIMD has run
/// in production for a while; it exists only as a kill switch for the roll-out.
fn cimd_enabled() -> bool {
    cimd_enabled_by(std::env::var("OAUTH_CIMD_ENABLED").ok().as_deref())
}

fn cimd_enabled_by(value: Option<&str>) -> bool {
    !value.is_some_and(|v| {
        matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
    })
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
/// exactly once. `/status/` is not among them and is not redirected here: the
/// status dashboard is published by the fronting proxy on staging only (see
/// `SERVE_STATUS` in deploy/native); production's origin does not publish it,
/// and the public status surface is status.internetcomputer.org.
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

    // One request-body cap for every instance (see `max_request_body`).
    let max_request_body = max_request_body()?;

    // Client ID Metadata Documents: on for every instance unless the deploy says no.
    let cimd_on = cimd_enabled();
    if !cimd_on {
        tracing::warn!("OAUTH_CIMD_ENABLED is off: Client ID Metadata Documents are disabled");
    }

    // Production Internet Identity at `/mcp`: always served, and the origin's
    // default instance (it answers the plain-root discovery probes). It is
    // built over the directory all operational files live in, with the
    // deploy tools on: making it clears what the run before left behind.
    let prod = McpServer::new(McpConfig {
        agent,
        instance: IiInstance::prod().map_err(anyhow::Error::msg)?,
        public_url: public_url.clone(),
        mcp_path: "/mcp".into(),
        state_dir: state_dir(),
        require_resource: require_resource(),
        cimd_enabled: cimd_on,
        deploy: deploy_config()?,
    })?
    .with_max_request_body(max_request_body);
    prod.spawn_session_reaper();
    // The process's deploy state, for the shutdown below to stop.
    let deploys = prod.deploys().clone();

    // Beta Internet Identity at `/mcp-beta`: opt in via `$MCP_SERVE_BETA`, so
    // only the staging deployment exposes it; production serves `/mcp` alone.
    // A sibling of the production instance: sessions and tokens never cross
    // the two, while the client registrations (II-agnostic) and the deploy
    // tools' slots and upload store are the process's, shared by both.
    let beta = if serve_beta() {
        let beta = prod.sibling(IiInstance::beta().map_err(anyhow::Error::msg)?, "/mcp-beta");
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
    //
    // The one request a drain cannot wait out is a deploy: it lasts minutes,
    // and the unit is given seconds to stop (`TimeoutStopSec`). So deploys
    // are told to stop when the signal arrives, before the drain: each ends
    // at its next step and answers with the canisters it had created, and
    // the drain then waits for that answer like any other response.
    //
    // The drain is not the whole of the wait, though. A stopped deploy with
    // a canister call in flight waits for its answer, which is what names a
    // canister the call created — and if its client has gone, no connection
    // holds the drain open for it. So once the drain is done the deploys are
    // waited for too, for a bounded time, before anything is cancelled.
    let stopping = {
        let deploys = deploys.clone();
        async move {
            shutdown_signal().await;
            deploys.stop();
        }
    };
    let serve_result = axum::serve(listener, app).with_graceful_shutdown(stopping).await;
    if !deploys.stopped().await {
        tracing::warn!("a deploy had not ended when the server stopped waiting for it");
    }
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

    /// An empty `IMCP2_STATE_DIR` is the working directory, as an unset one
    /// is, and whatever is configured comes out absolute.
    #[test]
    fn an_empty_state_dir_reads_as_unset() {
        let cwd = std::path::absolute(".").unwrap();
        assert_eq!(super::resolve_state_dir(None), cwd);
        assert_eq!(super::resolve_state_dir(Some("".into())), cwd);
        let relative = super::resolve_state_dir(Some("state".into()));
        assert!(relative.is_absolute(), "{}", relative.display());
        assert!(relative.ends_with("state"), "{}", relative.display());
    }

    /// What the server holds follows from how many deploys it runs and how
    /// large a bundle may be, unless it is set; and values that contradict
    /// one another are refused, not bent to fit.
    #[test]
    fn the_deploy_limits_follow_one_another_unless_told_otherwise() {
        const MIB: usize = 1024 * 1024;
        let config = super::deploy_config_from([None; 4]).unwrap();
        assert_eq!(config.concurrent, 2);
        assert_eq!((config.max_upload_bytes, config.max_extracted_bytes), (64 * MIB, 128 * MIB));
        // Two running and one more.
        assert_eq!(config.stored_bytes(), 3 * 128 * MIB as u64);
        assert_eq!(config.limits().extracted_bytes, 128 * MIB as u64);

        let config =
            super::deploy_config_from([Some("3"), Some("1000"), Some(" 5000 "), None]).unwrap();
        assert_eq!((config.concurrent, config.max_upload_bytes), (3, 1000));
        assert_eq!(config.stored_bytes(), 4 * 5000);
        let config = super::deploy_config_from([None, None, None, Some("999999999")]).unwrap();
        assert_eq!(config.stored_bytes(), 999_999_999);

        let archive_over = super::deploy_config_from([None, Some("2000"), Some("1000"), None]);
        assert!(archive_over.unwrap_err().to_string().contains("at most"));
        let small = super::deploy_config_from([None, Some("10"), Some("1000"), Some("999")]);
        assert!(small.unwrap_err().to_string().contains("at least"));
        assert!(super::deploy_config_from([None, Some("lots"), None, None]).is_err());
        assert!(super::deploy_config_from([None, None, Some("-1"), None]).is_err());
    }

    /// What a sync plugin is held to is the icp CLI's own unless set, and a
    /// value that would run no plugin, or is no number, refuses to start.
    #[test]
    fn plugin_limits_are_read_from_the_environment() {
        use imcp2::deploy::PluginLimits;
        assert_eq!(super::plugin_limits_from([None; 3]).unwrap(), PluginLimits::default());
        let set = super::plugin_limits_from([Some("536870912"), Some(" 30 "), Some("600")]);
        assert_eq!(
            set.unwrap(),
            PluginLimits {
                memory_bytes: Some(512 << 20),
                compute_secs: Some(30),
                wall_clock: Some(std::time::Duration::from_secs(600)),
            }
        );
        assert!(super::plugin_limits_from([Some("0"), None, None]).is_err());
        assert!(super::plugin_limits_from([None, Some("soon"), None]).is_err());
        assert!(super::plugin_limits_from([None, None, Some("-1")]).is_err());
    }

    /// The plugins an operator adds are a list, however it is punctuated,
    /// and one that is not a hash stops the server from starting.
    #[test]
    fn the_plugins_an_operator_allows_are_read_as_a_list() {
        assert!(super::allowed_plugins(None).is_empty());
        assert!(super::allowed_plugins(Some("  , ")).is_empty());
        let (a, b) = ("a".repeat(64), "B".repeat(64));
        let listed = super::allowed_plugins(Some(&format!(" {a},{b}\n{a} ")));
        assert_eq!(listed, [a.clone(), b, a]);

        use super::{Agent, IiInstance, McpConfig, McpServer, IC_URL};
        let dir = tempfile::tempdir().unwrap();
        let server = |allowed_plugins| {
            McpServer::new(McpConfig {
                agent: Agent::builder().with_url(IC_URL).build().unwrap(),
                instance: IiInstance::prod().unwrap(),
                public_url: "https://mcp.example.com".into(),
                mcp_path: "/mcp".into(),
                state_dir: dir.path().to_path_buf(),
                require_resource: true,
                cimd_enabled: true,
                deploy: imcp2::deploy::DeployConfig { allowed_plugins, ..Default::default() },
            })
        };
        let Err(refused) = server(vec!["nope".into()]) else {
            panic!("a server started with a plugin list it could not read");
        };
        assert!(refused.to_string().contains("not the sha256 of a plugin"), "{refused}");
        server(listed).unwrap();
    }

    /// The deploy cap is a count of at least one: zero is refused at startup
    /// rather than quietly served as one.
    #[test]
    fn a_deploy_cap_of_zero_is_refused() {
        assert_eq!(super::deploy_concurrency(" 3 ").unwrap(), 3);
        let zero = super::deploy_concurrency("0").unwrap_err().to_string();
        assert!(zero.contains("at least 1"), "{zero}");
        assert!(super::deploy_concurrency("two").is_err());
    }

    /// `OAUTH_CIMD_ENABLED`'s reading: on unless it says off.
    #[test]
    fn cimd_opt_out_values() {
        use super::cimd_enabled_by;
        let on = [None, Some(""), Some(" "), Some("1"), Some("true"), Some("yes"), Some("on")];
        for value in on.into_iter().chain([Some("disabled"), Some("2")]) {
            assert!(cimd_enabled_by(value), "{value:?} should leave CIMD on");
        }
        for value in [Some("0"), Some("false"), Some("No"), Some("OFF"), Some(" 0 ")] {
            assert!(!cimd_enabled_by(value), "{value:?} should switch CIMD off");
        }
    }

    /// `MCP_MAX_REQUEST_BODY`'s reading: the default when it is unset or blank,
    /// and an error (which `main` refuses to start on) for anything else that is
    /// not a byte count. That includes a value that is not Unicode, which
    /// `std::env::var` reports as an error too and which must not be mistaken
    /// for the variable being absent.
    #[test]
    fn max_request_body_values() {
        use super::max_request_body_from;
        use std::env::VarError;

        let unset = max_request_body_from(Err(VarError::NotPresent));
        assert_eq!(unset.unwrap(), imcp2::DEFAULT_MAX_REQUEST_BODY);

        // Blank is how the deploy unit renders a variable nobody set.
        for blank in ["", " ", "\t", " \n"] {
            let read = max_request_body_from(Ok(blank.into()));
            assert_eq!(read.unwrap(), imcp2::DEFAULT_MAX_REQUEST_BODY, "{blank:?}");
        }

        for (value, bytes) in [("1048576", 1 << 20), (" 65536 ", 65536), ("1", 1)] {
            let read = max_request_body_from(Ok(value.into()));
            assert_eq!(read.unwrap(), bytes, "{value:?}");
        }

        for value in ["4MiB", "4 MiB", "-1", "1.5", "1e6", "0x400", "yes"] {
            let err = max_request_body_from(Ok(value.into())).expect_err(value);
            assert!(err.to_string().contains("MCP_MAX_REQUEST_BODY"), "{value:?}: {err}");
        }

        // Unix lets a variable hold any bytes; these are a number followed by
        // one that is not UTF-8.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let raw = std::ffi::OsString::from_vec(vec![b'6', b'4', 0xff]);
            let err = max_request_body_from(Err(VarError::NotUnicode(raw)))
                .expect_err("a value that is not Unicode is not a byte count");
            assert!(err.to_string().contains("MCP_MAX_REQUEST_BODY"), "{err}");
        }
    }

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
