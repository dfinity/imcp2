//! Prometheus instrumentation, usable by embedders as well as by the bundled
//! binary — it exports the [`Metrics`] handle and the two request middlewares.
//! Uses the `prometheus` crate at the version `dfinity/ic` pins, so these
//! series land in the same clusters without a second dialect.
//!
//! The registry belongs to the caller: [`Metrics::new`] registers into a
//! [`Registry`] you supply and keeps none of its own. Exposition is the
//! caller's job too — gather your own registry (the bundled binary's `/metrics`
//! handler is the standalone case).
//!
//! Gathering is ALL that is required: the derived session gauges recompute
//! themselves from the served instances as the registry is gathered (see
//! `SessionCollector`), so a host that merely exposes its registry publishes
//! current counts. [`Metrics::refresh`] remains as an optional exactness step,
//! not a prerequisite — the one thing a caller must get right is passing
//! [`Metrics::new`] the same [`crate::McpServer`] handles it serves.
//!
//! ## Label cardinality
//!
//! Every series is a row Prometheus keeps in memory, so a label whose value an
//! outsider chooses is a memory-exhaustion primitive — and this service is
//! internet-facing and continuously scanned. Hence:
//!
//!   * `route` is axum's [`MatchedPath`] — the matched route *template*, never
//!     the requested path. Everything unmatched shares one `other` series
//!     instead of minting one per probed path.
//!   * `method` is allow-listed to the standard nine. HTTP permits arbitrary
//!     extension tokens, and each would otherwise mint its own series plus a
//!     full set of histogram buckets (~14x the cost of one counter).
//!   * `status` needs no bound: the server picks it from a small closed set.

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use prometheus::{
    core::{Collector, Desc},
    proto::MetricFamily,
    Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

/// Prefix for every metric this crate publishes. A macro so the names stay
/// `&'static str` and greppable in full — searching `imcp2_http_requests_total`
/// lands here. Fixed rather than caller-configurable: one name meaning one
/// thing everywhere is what lets a single dashboard and alert rule work.
macro_rules! metric {
    ($suffix:literal) => {
        concat!("imcp2_", $suffix)
    };
}

/// The shared bucket for unmatched routes / non-standard methods.
const UNMATCHED_ROUTE: &str = "other";
const UNKNOWN_METHOD: &str = "other";

/// Methods that may appear as a label; anything unlisted collapses to `other`.
const KNOWN_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
];

/// Session-gauge label. NOT `instance`: Prometheus attaches its own `instance`
/// target label to every sample and renames a colliding exposed one to
/// `exported_instance`, so queries against `instance="prod"` would silently
/// match nothing.
const SESSION_LABEL: &str = "ii_instance";

/// Latency buckets in seconds. The static pages and `/version` answer in
/// single-digit milliseconds; MCP tool calls do IC round trips and land in the
/// hundreds. The crate defaults have no resolution below 5ms.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Handle for recording this crate's metrics. Cheap to clone: collectors are
/// `Arc`-backed, so clones share one set of series.
#[derive(Clone)]
pub struct Metrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    live_sessions: IntGaugeVec,
    active_sessions: IntGaugeVec,
    /// Shared with `SessionCollector`; see [`SessionSampling`].
    sampling: SessionSampling,
    scrapes: Histogram,
    /// Servers whose session gauges [`Metrics::refresh`] republishes. Fixed at
    /// construction.
    servers: Vec<crate::McpServer>,
}

/// Serializes everything that samples, writes, or reads the two session gauges,
/// so the exported pair always comes from ONE snapshot.
///
/// Both gauges live in their own independently-locked [`IntGaugeVec`], so
/// sample-set-set-collect is four separate operations on shared state. Two
/// concurrent gathers — the IC is scraped by more than one Prometheus — or a
/// gather racing [`Metrics::refresh`] can interleave them and encode `live` from
/// one snapshot with `active` from another: across an expiry that publishes
/// `live=0, active=1`, breaking the documented `active <= live` invariant and
/// tripping any alert written on it.
///
/// A `std` mutex, not an async one: the writer that matters is
/// [`Collector::collect`], a synchronous `fn`. The critical section is a session-map
/// pass plus two gauge writes — no I/O, no await — and it contends only with
/// another scrape, which is the case being made correct.
type SessionSampling = std::sync::Arc<std::sync::Mutex<()>>;

/// Take [`SessionSampling`], ignoring poisoning: the guarded data is `()`, so a
/// panic under the lock leaves nothing inconsistent behind, and refusing to
/// serve metrics afterwards would only hide whatever panicked.
fn sampling_guard(lock: &SessionSampling) -> std::sync::MutexGuard<'_, ()> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Metrics {
    /// Register this crate's collectors into `registry` and return the handle.
    ///
    /// `servers` are the instances whose session gauges this handle publishes —
    /// pass every served [`crate::McpServer`], one per Internet Identity
    /// instance (duplicate instance names overwrite each other). The gauges
    /// resample themselves from these servers on every gather, so they need no
    /// call of yours to stay current (see `SessionCollector` and
    /// [`Self::refresh`]); they read 0 from construction until the first gather,
    /// and an unserved instance is simply absent. Pass the SAME handles you
    /// serve: an `McpServer` is cheap to clone and shares its session map, but a
    /// separately constructed one has a map of its own and would read 0 forever.
    ///
    /// `version` and `commit` become the labels of a `build_info` gauge.
    ///
    /// Returns [`prometheus::Error::AlreadyReg`] when a name is already taken,
    /// e.g. when called twice against one registry — build one and clone it.
    /// Registration is not transactional: on error, collectors registered
    /// before the collision stay behind, so register into a fresh registry.
    pub fn new(
        registry: &Registry,
        version: &str,
        commit: &str,
        started_at: u64,
        servers: &[&crate::McpServer],
    ) -> prometheus::Result<Self> {
        let requests = IntCounterVec::new(
            Opts::new(
                metric!("http_requests_total"),
                "Total HTTP requests, by matched route template, method and status code.",
            ),
            &["route", "method", "status"],
        )?;
        registry.register(Box::new(requests.clone()))?;

        // No status label: a histogram multiplies series by bucket count, and
        // "how slow" is rarely a question about one status code.
        let duration = HistogramVec::new(
            HistogramOpts::new(
                metric!("http_request_duration_seconds"),
                "HTTP request latency in seconds, by matched route template and method.",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["route", "method"],
        )?;
        registry.register(Box::new(duration.clone()))?;

        let live_sessions = IntGaugeVec::new(
            Opts::new(
                metric!("live_sessions"),
                "Authenticated sessions holding a currently-valid Internet Identity grant, \
                 per instance. A session counts from grant redemption until expiry, idle or not.",
            ),
            &[SESSION_LABEL],
        )?;

        let active_sessions = IntGaugeVec::new(
            Opts::new(
                metric!("active_sessions"),
                "Live sessions that also made a request within the activity window (~15 min). \
                 Recomputed per scrape from the same snapshot as imcp2_live_sessions, so the \
                 pair is consistent (active <= live).",
            ),
            &[SESSION_LABEL],
        )?;

        // The two together, behind a collector that resamples them as the
        // registry gathers — see `SessionCollector`. Registering the collector
        // (not the two gauge vecs) is what makes the numbers self-maintaining;
        // the clones kept in `Self` share the same series.
        let sampling = SessionSampling::default();
        registry.register(Box::new(SessionCollector {
            live_sessions: live_sessions.clone(),
            active_sessions: active_sessions.clone(),
            servers: servers.iter().map(|s| (*s).clone()).collect(),
            sampling: sampling.clone(),
        }))?;

        // Self-observability: a scrape that quietly got slow is how a target
        // starts being dropped for timing out.
        let scrapes = Histogram::with_opts(
            HistogramOpts::new(
                metric!("metrics_scrape_duration_seconds"),
                "Time spent producing this endpoint's own response: refreshing the derived \
                 gauges, then gathering and encoding the registry.",
            )
            .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]),
        )?;
        registry.register(Box::new(scrapes.clone()))?;

        // Value always 1; the information is in the labels.
        let build_info = IntGaugeVec::new(
            Opts::new(
                metric!("build_info"),
                "Always 1. Carries the running version and commit as labels.",
            ),
            &["version", "commit"],
        )?;
        registry.register(Box::new(build_info.clone()))?;
        build_info.with_label_values(&[version, commit]).set(1);

        // Namespaced twin of the conventional `process_start_time_seconds`; the
        // bundled binary reads the value as the first statement of `main`, so the
        // two agree. Kept despite the overlap because an embedder gets only this
        // one — the library does not register the (Linux-only) process collector.
        let start_time = IntGauge::new(
            metric!("process_start_time_seconds"),
            "Unix epoch seconds at which this process started, i.e. when the deployment \
             last restarted. Every deploy restarts the service.",
        )?;
        registry.register(Box::new(start_time.clone()))?;
        start_time.set(started_at as i64);

        // Zero-fill each served instance so its series exist from startup
        // rather than appearing only after the first refresh.
        for server in servers {
            let name = server.instance().name;
            live_sessions.with_label_values(&[name]).set(0);
            active_sessions.with_label_values(&[name]).set(0);
        }

        Ok(Self {
            requests,
            duration,
            live_sessions,
            active_sessions,
            sampling,
            scrapes,
            servers: servers.iter().map(|s| (*s).clone()).collect(),
        })
    }

    /// Record one completed request. Not public: raw label strings would bypass
    /// the cardinality bounds — the supported entry point is
    /// [`write_request_metrics`], and `method` is normalised here as well.
    pub(crate) fn observe_request(&self, route: &str, method: &str, status: u16, elapsed: f64) {
        let method = method_label(method);
        // Exact code, not 4xx/5xx buckets: the set is small and closed, and
        // separating 401 from 404 from 500 is the point.
        let status = status.to_string();
        self.requests.with_label_values(&[route, method, &status]).inc();
        self.duration.with_label_values(&[route, method]).observe(elapsed);
    }

    /// Recompute the session gauges from each server's session map, awaiting the
    /// lock.
    ///
    /// OPTIONAL: the gauges resample themselves as the registry is gathered (see
    /// `SessionCollector`), so a host that just exposes its registry already
    /// publishes current numbers. Call this from an async exposition path (as the
    /// bundled binary's `/metrics` does) or on a timer to make a scrape exact
    /// even under lock contention, where the non-blocking in-collector sample
    /// falls back to the previous values.
    pub async fn refresh(&self) {
        for server in &self.servers {
            // Sample outside the guard (this one awaits), publish inside it: the
            // pair must not land half-written under a concurrent gather.
            let g = server.session_gauges().await;
            let name = server.instance().name;
            let _sampling = sampling_guard(&self.sampling);
            self.live_sessions.with_label_values(&[name]).set(g.live as i64);
            self.active_sessions.with_label_values(&[name]).set(g.active as i64);
        }
    }

    /// Record how long producing a scrape took. Time the whole handler,
    /// [`Self::refresh`] included — the refresh is the part that can get slow.
    pub fn observe_scrape(&self, seconds: f64) {
        self.scrapes.observe(seconds);
    }
}

/// The session gauges, wrapped so they RESAMPLE THEMSELVES whenever the
/// registry is gathered.
///
/// Registering the two [`IntGaugeVec`]s directly would make them inert state
/// that only [`Metrics::refresh`] ever moves — and an embedder registering into
/// a registry the host application gathers has no natural place to call it, so
/// the gauges sat at their startup zero-fill and a healthy service looked like
/// one with no sessions. That failure mode is silent (a zero is a plausible
/// reading), so the fix is to remove the coupling rather than document it:
/// gathering the registry is now sufficient, and [`Metrics::refresh`] is an
/// optional exactness step for a host that has an async hook.
///
/// [`Collector::collect`] is a synchronous `fn` the registry calls on whatever
/// thread gathers — typically a runtime worker — so this samples through
/// [`crate::McpServer::try_session_gauges`], which never blocks. A momentarily
/// contended session map leaves the previous values in place (one scrape stale
/// at worst), because the map was contended, not empty.
struct SessionCollector {
    live_sessions: IntGaugeVec,
    active_sessions: IntGaugeVec,
    servers: Vec<crate::McpServer>,
    sampling: SessionSampling,
}

impl Collector for SessionCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.live_sessions.desc().into_iter().chain(self.active_sessions.desc()).collect()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        // Held across the writes AND the reads below: a scrape that encoded
        // `live` before another gather's write and `active` after it would
        // publish a pair from two different snapshots. See [`SessionSampling`].
        let _sampling = sampling_guard(&self.sampling);
        for server in &self.servers {
            if let Some(g) = server.try_session_gauges() {
                let name = server.instance().name;
                self.live_sessions.with_label_values(&[name]).set(g.live as i64);
                self.active_sessions.with_label_values(&[name]).set(g.active as i64);
            }
        }
        self.live_sessions.collect().into_iter().chain(self.active_sessions.collect()).collect()
    }
}

/// Register the process collector — CPU, resident memory, open file
/// descriptors. Separate from [`Metrics::new`] because un-namespaced
/// `process_*` describes the whole OS process, which belongs to the
/// application: binaries call this, embedders generally should not (it would
/// collide with a host that already has one). A no-op off Linux.
pub fn register_process_collector(registry: &Registry) -> prometheus::Result<()> {
    #[cfg(target_os = "linux")]
    registry.register(Box::new(
        prometheus::process_collector::ProcessCollector::for_self(),
    ))?;
    #[cfg(not(target_os = "linux"))]
    let _ = registry;
    Ok(())
}

/// Middleware: record request count and latency, with both labels bounded (see
/// the module docs). Apply with the handle as state:
///
/// ```ignore
/// router.layer(axum::middleware::from_fn_with_state(
///     metrics.clone(),
///     imcp2::metrics::write_request_metrics,
/// ))
/// ```
pub async fn write_request_metrics(
    State(metrics): State<Metrics>,
    req: Request,
    next: Next,
) -> Response {
    // Read the matched template before `next.run` consumes the request.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string());
    let method = req.method().clone();
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    metrics.observe_request(
        route_label(route.as_deref()),
        method_label(method.as_str()),
        resp.status().as_u16(),
        started.elapsed().as_secs_f64(),
    );
    resp
}

/// Middleware: log one `debug` line per request — method, path, status,
/// elapsed. Unlike [`write_request_metrics`] it keeps the full path (unbounded
/// cardinality costs nothing in a log); the query string is never logged, so
/// single-use secrets (`?code=`) stay out. Apply with
/// `axum::middleware::from_fn(imcp2::metrics::write_request_logs)`.
pub async fn write_request_logs(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let elapsed_ms = started.elapsed().as_millis() as u64;
    tracing::debug!(%method, %path, status, elapsed_ms, "http request");
    resp
}

/// The `route` label: the matched route template, or the shared `other`
/// bucket when nothing matched.
pub fn route_label(matched: Option<&str>) -> &str {
    match matched {
        Some(t) if !t.is_empty() => t,
        _ => UNMATCHED_ROUTE,
    }
}

/// The `method` label: the method when standard, otherwise the shared `other`
/// bucket.
/// Returns `&'static str` so a borrowed request value cannot pass through.
pub fn method_label(method: &str) -> &'static str {
    match KNOWN_METHODS.iter().position(|m| *m == method) {
        Some(i) => KNOWN_METHODS[i],
        None => UNKNOWN_METHOD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request as HttpRequest, routing::get, Router};
    use prometheus::{Encoder, TextEncoder};
    use tower::ServiceExt;

    /// What a host does at scrape time: gather its registry and encode.
    fn encode(registry: &Registry) -> String {
        let mut buf = Vec::new();
        TextEncoder::new().encode(&registry.gather(), &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn fixture() -> (Registry, Metrics) {
        let r = Registry::new();
        let m = Metrics::new(&r, "1.2.3", "abc1234", 1_700_000_000, &[]).unwrap();
        (r, m)
    }

    /// A real production-instance server. Construction is pure — no network.
    fn server() -> crate::McpServer {
        crate::McpServer::new(crate::McpConfig {
            agent: crate::Agent::builder()
                .with_url(crate::IC_URL)
                .build()
                .expect("build agent"),
            instance: crate::IiInstance::prod().expect("prod instance"),
            public_url: "https://mcp.example.com".into(),
            mcp_path: "/mcp".into(),
            clients: crate::SharedClients::load(std::env::temp_dir()),
            state_dir: std::env::temp_dir(),
            require_resource: true,
        })
    }

    /// A router shaped like a host's. The cardinality tests drive real requests
    /// through the exported middleware — calling the recorder with pre-computed
    /// labels would only prove the recorder is deterministic.
    fn app(m: Metrics) -> Router {
        Router::new()
            .route("/version", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(m, write_request_metrics))
    }

    fn request_series(out: &str) -> Vec<&str> {
        out.lines()
            .filter(|l| l.starts_with(metric!("http_requests_total")) && l.contains('{'))
            .collect()
    }

    #[test]
    fn unmatched_requests_share_one_label() {
        assert_eq!(route_label(None), UNMATCHED_ROUTE);
        assert_eq!(route_label(Some("")), UNMATCHED_ROUTE);
    }

    #[test]
    fn matched_requests_keep_their_template() {
        assert_eq!(route_label(Some("/version")), "/version");
    }

    #[test]
    fn standard_methods_pass_through_and_the_rest_collapse() {
        for m in KNOWN_METHODS {
            assert_eq!(method_label(m), m);
        }
        for m in ["WIBBLE", "get", "", "GET ", "X-CUSTOM"] {
            assert_eq!(method_label(m), UNKNOWN_METHOD, "{m:?} should collapse");
        }
    }

    #[test]
    fn collectors_land_in_the_callers_registry() {
        let (r, _m) = fixture();
        let out = encode(&r);
        assert!(out.contains(metric!("build_info")), "{out}");
        assert!(out.contains(r#"version="1.2.3""#), "{out}");
        assert!(out.contains(r#"commit="abc1234""#), "{out}");
        assert!(
            out.contains(concat!(metric!("process_start_time_seconds"), " 1700000000")),
            "{out}"
        );
    }

    /// `process_*` is un-namespaced and belongs to the embedding application.
    #[test]
    fn new_does_not_register_the_process_collector() {
        let (r, _m) = fixture();
        assert!(
            !encode(&r).contains("process_cpu_seconds_total"),
            "Metrics::new must not register process_* series"
        );
        register_process_collector(&r).unwrap();
        #[cfg(target_os = "linux")]
        assert!(encode(&r).contains("process_cpu_seconds_total"));
    }

    /// A second registration is an error, not a panic. Build one and clone.
    #[test]
    fn double_registration_is_an_error_not_a_panic() {
        let (r, _m) = fixture();
        match Metrics::new(&r, "1.2.3", "abc1234", 0, &[]) {
            Err(prometheus::Error::AlreadyReg) => {}
            Err(e) => panic!("expected AlreadyReg, got {e:?}"),
            Ok(_) => panic!("expected the second registration to fail"),
        }
    }

    #[test]
    fn records_requests_and_sessions() {
        let (r, m) = fixture();
        m.observe_request("/version", "GET", 200, 0.002);
        m.observe_request("/version", "GET", 200, 0.003);
        m.live_sessions.with_label_values(&["prod"]).set(7);
        m.active_sessions.with_label_values(&["prod"]).set(3);
        let out = encode(&r);
        assert!(
            out.contains(concat!(
                metric!("http_requests_total"),
                r#"{method="GET",route="/version",status="200"} 2"#
            )),
            "{out}"
        );
        assert!(
            out.contains(concat!(metric!("live_sessions"), r#"{ii_instance="prod"} 7"#)),
            "{out}"
        );
        assert!(
            out.contains(concat!(metric!("active_sessions"), r#"{ii_instance="prod"} 3"#)),
            "{out}"
        );
    }

    #[test]
    fn scrape_duration_is_recordable_by_the_host() {
        let (r, m) = fixture();
        m.observe_scrape(0.004);
        assert!(
            encode(&r).contains(concat!(metric!("metrics_scrape_duration_seconds"), "_count 1")),
            "{}",
            encode(&r)
        );
    }

    #[tokio::test]
    async fn a_flood_of_distinct_paths_yields_one_series() {
        let (r, m) = fixture();
        for i in 0..200 {
            let req = HttpRequest::builder()
                .uri(format!("/scan-{i}-{}", "x".repeat(i % 13)))
                .body(Body::empty())
                .unwrap();
            app(m.clone()).oneshot(req).await.unwrap();
        }
        let out = encode(&r);
        let series = request_series(&out);
        assert_eq!(series.len(), 1, "expected one series, got:\n{out}");
        assert!(series[0].contains(r#"route="other""#), "{}", series[0]);
        assert!(series[0].ends_with(" 200"), "{}", series[0]);
    }

    #[tokio::test]
    async fn a_flood_of_extension_methods_yields_one_series() {
        let (r, m) = fixture();
        for i in 0..100 {
            let req = HttpRequest::builder()
                .method(format!("WIBBLE{i}").as_str())
                .uri("/version")
                .body(Body::empty())
                .unwrap();
            app(m.clone()).oneshot(req).await.unwrap();
        }
        let out = encode(&r);
        let series = request_series(&out);
        assert_eq!(series.len(), 1, "expected one series, got:\n{out}");
        assert!(series[0].contains(r#"method="other""#), "{}", series[0]);

        // The histogram is where a cardinality bug actually hurts: one label
        // set means one bucket family (+Inf).
        let buckets = out
            .lines()
            .filter(|l| l.starts_with(concat!(metric!("http_request_duration_seconds"), "_bucket")))
            .count();
        assert_eq!(buckets, LATENCY_BUCKETS.len() + 1, "{out}");
    }

    #[tokio::test]
    async fn real_routes_keep_their_identity() {
        let (r, m) = fixture();
        let req = HttpRequest::builder().uri("/version").body(Body::empty()).unwrap();
        app(m.clone()).oneshot(req).await.unwrap();
        assert!(
            encode(&r).contains(concat!(
                metric!("http_requests_total"),
                r#"{method="GET",route="/version",status="200"} 1"#
            )),
            "{}",
            encode(&r)
        );
    }

    /// A served instance has zero-valued series from construction, not only
    /// after the first refresh.
    #[test]
    fn construction_zero_fills_served_instances() {
        let r = Registry::new();
        let _m = Metrics::new(&r, "1.2.3", "abc1234", 0, &[&server()]).unwrap();
        let out = encode(&r);
        assert!(
            out.contains(concat!(metric!("live_sessions"), r#"{ii_instance="prod"} 0"#)),
            "{out}"
        );
        assert!(
            out.contains(concat!(metric!("active_sessions"), r#"{ii_instance="prod"} 0"#)),
            "{out}"
        );
    }

    /// `refresh` reads through to the server's session map. The gauges are
    /// poisoned first — a fresh server has no sessions, so only a refresh that
    /// actually reached it can restore the zeros. Read straight off the gauges,
    /// not through `encode`: gathering resamples them too, which would let this
    /// pass with no refresh at all.
    #[tokio::test]
    async fn refresh_reads_through_to_a_server() {
        let r = Registry::new();
        let m = Metrics::new(&r, "1.2.3", "abc1234", 0, &[&server()]).unwrap();
        m.live_sessions.with_label_values(&["prod"]).set(99);
        m.active_sessions.with_label_values(&["prod"]).set(42);
        m.refresh().await;
        assert_eq!(m.live_sessions.with_label_values(&["prod"]).get(), 0);
        assert_eq!(m.active_sessions.with_label_values(&["prod"]).get(), 0);
    }

    /// The regression this exists for: a host that only GATHERS its registry —
    /// no `refresh` call anywhere, which is every embedder registering into a
    /// registry the host application owns — must still see real session counts.
    /// Before the gauges resampled themselves in `Collector::collect`, such a
    /// deployment published the startup zero-fill forever, so a busy server was
    /// indistinguishable from an idle one.
    #[tokio::test]
    async fn gathering_alone_publishes_the_session_counts() {
        let r = Registry::new();
        let s = server();
        // Deliberately NOT kept as a `Metrics` the test could refresh through:
        // gathering is the only thing that happens below.
        let _m = Metrics::new(&r, "1.2.3", "abc1234", 0, &[&s]).unwrap();

        // One redeemed grant, an hour out: live, and active because redeeming
        // stamps `last_seen`.
        let hour_out = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            + 3_600_000_000_000;
        s.identities.set_grant_expiration("sess", hour_out).await;

        let out = encode(&r);
        assert!(
            out.contains(concat!(metric!("live_sessions"), r#"{ii_instance="prod"} 1"#)),
            "{out}"
        );
        assert!(
            out.contains(concat!(metric!("active_sessions"), r#"{ii_instance="prod"} 1"#)),
            "{out}"
        );
    }

    /// Two gathers in a row keep reporting the same live session: the collector
    /// resamples rather than draining anything.
    #[tokio::test]
    async fn repeated_gathers_stay_correct() {
        let r = Registry::new();
        let s = server();
        let _m = Metrics::new(&r, "1.2.3", "abc1234", 0, &[&s]).unwrap();
        let hour_out = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            + 3_600_000_000_000;
        s.identities.set_grant_expiration("sess", hour_out).await;
        let (first, second) = (encode(&r), encode(&r));
        for out in [&first, &second] {
            assert!(
                out.contains(concat!(metric!("live_sessions"), r#"{ii_instance="prod"} 1"#)),
                "{out}"
            );
        }
    }

    /// The pair a scrape publishes must come from ONE snapshot: `active <= live`
    /// is in the metric's own help text, so an alert may be written on it, and
    /// the two gauges are separately-locked shared state that a second gather (the
    /// IC is scraped by more than one Prometheus) or a concurrent `refresh` could
    /// otherwise interleave — across an expiry, publishing `live=0, active=1`.
    ///
    /// A torn read is a nanoseconds-wide window that hammering does not reliably
    /// reproduce, so this asserts the property that closes it instead: a gather
    /// cannot proceed while the sampling guard is held, and completes once it is
    /// released.
    // Holding the guard across an await is precisely what is under test here.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gather_waits_for_the_sampling_guard() {
        let r = std::sync::Arc::new(Registry::new());
        let m = Metrics::new(&r, "1.2.3", "abc1234", 0, &[&server()]).unwrap();
        let sampling = sampling_guard(&m.sampling);

        // `spawn_blocking`: this gather is meant to block, which is what a
        // registry gather on a runtime worker would do.
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let gather = {
            let r = r.clone();
            tokio::task::spawn_blocking(move || {
                started_tx.send(()).expect("receiver alive");
                r.gather();
            })
        };
        started.await.expect("gather task started");
        // Give the blocked gather every chance to finish if it were not waiting.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !gather.is_finished(),
            "a gather completed while the sampling guard was held: the collector \
             is not serializing, so a scrape can mix two snapshots"
        );

        drop(sampling);
        gather.await.expect("gather completes once the guard is released");
    }

    /// With no servers, refresh is a harmless no-op.
    #[tokio::test]
    async fn refresh_with_no_servers_is_a_noop() {
        let (r, m) = fixture();
        m.refresh().await;
        assert!(!encode(&r).contains(concat!(metric!("live_sessions"), "{")));
    }
}
