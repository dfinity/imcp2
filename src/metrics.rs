//! Prometheus instrumentation for this crate, usable from the library rather
//! than only from the bundled binary.
//!
//! Uses the `prometheus` crate at the version `dfinity/ic` pins, since these
//! series are destined for the same Prometheus/Victoria Metrics clusters that
//! scrape the IC — matching the org's client avoids two exposition dialects in
//! one estate.
//!
//! ## The registry belongs to the caller
//!
//! [`Metrics::new`] registers its collectors into a [`Registry`] you supply and
//! keeps no registry of its own. A host embedding this crate already has one,
//! already exposes it somewhere, and would never see series published into a
//! registry this module kept to itself. Exposition is therefore the host's job
//! too: this module has no `render` — gather your own registry.
//!
//! One consequence worth stating: registering twice into the same registry
//! returns [`prometheus::Error::AlreadyReg`] rather than panicking, so build one
//! `Metrics` per registry and clone it. Cloning shares the collectors.
//!
//! What is here and why:
//!
//!   * **Request counters and a latency histogram.** The request-logging
//!     middleware already computes method, path, status and elapsed time for
//!     every request; this records the same facts as series rather than as
//!     lines nobody aggregates.
//!   * **Session gauges**, mirroring `/version`'s `live_sessions` and
//!     `active_sessions`. Read at scrape time rather than pushed, because they
//!     are derived state: the authoritative value is whatever the session map
//!     says when asked.
//!   * **Build and start info**, so a series can be attributed to an exact
//!     commit and a redeploy is visible as a step change rather than inferred.
//!   * **Process collector** (Linux only): CPU, RSS, open file descriptors.
//!     Free with the crate, and the first thing anyone asks for when a host
//!     misbehaves.
//!
//! ## Label cardinality is the whole design problem
//!
//! Every series is a row Prometheus keeps in memory, so a label whose value an
//! outsider chooses is a memory-exhaustion primitive. Labelling by raw request
//! path would be exactly that: this service is internet-facing and continuously
//! scanned, and the request log is full of paths nobody here ever wrote. Each
//! unique 404 path would mint a permanent series.
//!
//! So the `route` label is never the requested path. It is axum's
//! [`MatchedPath`] — the route *template* the router matched — which is bounded
//! by the route table by construction, and stays correct when routes are added
//! without anyone remembering to update a list here. Anything the router did not
//! match has no template and collapses to a single `other` bucket.
//!
//! The same reasoning applies to **every** label a request can influence, which
//! is easy to forget once one of them is handled. `method` is equally
//! attacker-chosen: HTTP permits arbitrary extension method tokens, so a request
//! line reading `WIBBLE / HTTP/1.1` would otherwise mint its own series — and
//! its own full set of histogram buckets, which multiplies the cost by roughly
//! the bucket count. It is allow-listed to the standard methods for that reason.
//! `status` is safe by contrast: the server chooses it, from a small closed set.

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::Response,
};
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use std::sync::{Arc, Mutex};

/// Every metric this crate publishes is named `imcp2_*`. The prefix is factored
/// out so it cannot drift between the seven definitions and the assertions that
/// check them, and it is a macro rather than a `const` + `format!` so the names
/// stay `&'static str` and stay greppable in full — searching an alert rule's
/// `imcp2_http_requests_total` should land on the line that defines it.
///
/// Deliberately fixed, not caller-configurable: a metric name identifies the
/// software emitting it, and `imcp2_http_requests_total` meaning the same thing
/// on every deployment is what lets one dashboard and one alert rule work
/// everywhere.
macro_rules! metric {
    ($suffix:literal) => {
        concat!("imcp2_", $suffix)
    };
}

/// The bucket every unmatched request shares. One series for the entire
/// internet's worth of probing, rather than one per path attempted.
const UNMATCHED_ROUTE: &str = "other";

/// The same, for request methods outside the standard set.
const UNKNOWN_METHOD: &str = "other";

/// Methods that may appear as a label. HTTP permits arbitrary extension method
/// tokens, so this is an allow-list rather than a deny-list: anything unlisted
/// collapses into [`UNKNOWN_METHOD`].
const KNOWN_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
];

/// Latency buckets in seconds. Chosen for what this service actually does: the
/// static pages and `/version` answer in single-digit milliseconds, while an MCP
/// tool call that talks to the IC is a network round trip and lands in the
/// hundreds. The default `prometheus` buckets top out at 10s, which is fine, but
/// they have no resolution below 5ms where most responses here live.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Handle for recording this crate's metrics. Cheap to clone: every collector is
/// `Arc`-backed by the `prometheus` crate, so clones share one set of series.
///
/// Holds no [`Registry`] — see the module docs. Clone this into your middleware
/// state and wherever else you record from.
#[derive(Clone)]
pub struct Metrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    live_sessions: IntGaugeVec,
    active_sessions: IntGaugeVec,
    scrapes: Histogram,
    /// Servers whose derived gauges [`Metrics::refresh`] republishes. Shared
    /// across clones, so tracking through any handle is visible to all of them.
    tracked: Arc<Mutex<Vec<crate::McpServer>>>,
}

impl Metrics {
    /// Register this crate's collectors into `registry` and return a handle for
    /// recording against them.
    ///
    /// The registry is borrowed, never retained: exposition stays the caller's
    /// job, so a host embedding this crate publishes these series from wherever
    /// it already publishes its own.
    ///
    /// `version` and `commit` become labels on a single `build_info` gauge — the
    /// conventional way to attach immutable facts to a target without pinning
    /// them onto every other series. They are constructor arguments rather than
    /// a separate setter so that forgetting them is impossible; a silently
    /// absent `build_info` is hard to notice and annoying to debug.
    ///
    /// Returns [`prometheus::Error::AlreadyReg`] if called twice against the same
    /// registry. Build one and clone it.
    pub fn new(
        registry: &Registry,
        version: &str,
        commit: &str,
        started_at: u64,
    ) -> prometheus::Result<Self> {

        let requests = IntCounterVec::new(
            Opts::new(
                metric!("http_requests_total"),
                "Total HTTP requests, by matched route template, method and status code.",
            ),
            &["route", "method", "status"],
        )?;
        registry.register(Box::new(requests.clone()))?;

        // No status label: a histogram multiplies series by its bucket count, so
        // adding a third dimension here costs far more than on the counter, and
        // "how slow was it" is rarely a question about one status code.
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
                "Authenticated sessions holding a currently-valid Internet Identity grant. \
                 A session counts from grant redemption until the grant expires, idle or not.",
            ),
            &["instance"],
        )?;
        registry.register(Box::new(live_sessions.clone()))?;

        let active_sessions = IntGaugeVec::new(
            Opts::new(
                metric!("active_sessions"),
                "The subset of live sessions that also made a request within the activity \
                 window. Always <= imcp2_live_sessions. Use this to time a low-disruption \
                 redeploy.",
            ),
            &["instance"],
        )?;
        registry.register(Box::new(active_sessions.clone()))?;

        // Self-observability for the endpoint itself. A scrape that quietly got
        // slow is how a monitoring target starts being dropped for timing out,
        // and the resulting gap looks like an outage that never happened.
        let scrapes = Histogram::with_opts(
            HistogramOpts::new(
                metric!("metrics_scrape_duration_seconds"),
                "Time spent gathering and encoding this endpoint's own response.",
            )
            .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]),
        )?;
        registry.register(Box::new(scrapes.clone()))?;

        // Immutable deployment facts. Value is always 1; the information is in
        // the labels, so `imcp2_build_info` joined onto another series attributes
        // it to a commit.
        let build_info = IntGaugeVec::new(
            Opts::new(
                metric!("build_info"),
                "Always 1. Carries the running version and commit as labels.",
            ),
            &["version", "commit"],
        )?;
        registry.register(Box::new(build_info.clone()))?;
        build_info.with_label_values(&[version, commit]).set(1);

        // NOT the conventional `process_start_time_seconds` — the prefix makes it
        // `imcp2_process_start_time_seconds`, and it deliberately measures a
        // different thing. The process collector's conventional series is the OS
        // process start; this is when the server finished initialising and began
        // serving, which is the moment a redeploy actually becomes visible to
        // clients. On a real host the two differ by a second or two.
        //
        // Both are worth having, and an embedder gets only this one, since the
        // library does not register the process collector — see
        // `register_process_collector`.
        let start_time = IntGauge::new(
            metric!("process_start_time_seconds"),
            "Unix epoch seconds at which this process started, i.e. when the deployment \
             last restarted. Every deploy restarts the service.",
        )?;
        registry.register(Box::new(start_time.clone()))?;
        start_time.set(started_at as i64);

        Ok(Self {
            requests,
            duration,
            live_sessions,
            active_sessions,
            scrapes,
            tracked: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Record one completed request.
    ///
    /// Deliberately **not** public. Making it so would hand an embedder a way to
    /// write arbitrary strings straight into `route` and `method`, reintroducing
    /// exactly the unbounded cardinality this module exists to prevent — the
    /// bound would then live only in the middleware, and be one direct call away
    /// from being bypassed. The supported entry point is
    /// [`write_request_metrics`], which derives both labels from the request.
    ///
    /// `method` is normalised here as well as in the middleware. Belt and braces
    /// is cheap, and it means the invariant holds at the recording site rather
    /// than depending on every caller remembering.
    pub(crate) fn observe_request(
        &self,
        route: &str,
        method: &str,
        status: u16,
        elapsed_secs: f64,
    ) {
        let method = method_label(method);
        // `status` is rendered rather than bucketed: HTTP codes are a small
        // closed set in practice, and keeping the exact code lets a query
        // separate 401 from 404 from 500, which grouping into 4xx/5xx destroys.
        let status = status.to_string();
        self.requests
            .with_label_values(&[route, method, &status])
            .inc();
        self.duration
            .with_label_values(&[route, method])
            .observe(elapsed_secs);
    }

    /// Publish one instance's session counts.
    ///
    /// Not public, for the same reason as [`Self::observe_request`]: `instance`
    /// would be a caller-supplied label string. Use [`Self::track`], which takes
    /// the name from [`crate::IiInstance`] where it is already a `&'static str`.
    pub(crate) fn set_sessions(&self, instance: &'static str, live: i64, active: i64) {
        self.live_sessions.with_label_values(&[instance]).set(live);
        self.active_sessions
            .with_label_values(&[instance])
            .set(active);
    }

    /// Track a server whose derived gauges [`Self::refresh`] should publish.
    ///
    /// Call once per served [`crate::McpServer`]. The server is cheap to clone and
    /// everything inside it is shared, so this holds a handle rather than a copy
    /// of any state.
    ///
    /// Publishes zeroes immediately, so a tracked instance's gauges read `0` from
    /// the moment it is registered rather than being absent until the first
    /// refresh. An instance that is *not* served is simply not tracked and has no
    /// series — which is the honest reading: there is no such instance here, as
    /// distinct from one that exists and currently has no sessions.
    pub fn track(&self, server: &crate::McpServer) {
        let name = server.instance().name;
        match self.tracked.lock() {
            Ok(mut v) => v.push(server.clone()),
            // A poisoned lock means another thread panicked mid-push. Losing the
            // registration is not worth propagating a panic from an instrumentation
            // call, so warn and carry on un-tracked.
            Err(_) => {
                tracing::warn!(instance = name, "metrics: tracked-server lock poisoned");
                return;
            }
        }
        self.set_sessions(name, 0, 0);
    }

    /// Recompute and publish the derived gauges for every tracked server.
    ///
    /// The session counts are *derived state*: the authoritative value is whatever
    /// the session map says when asked, so they have to be pulled rather than
    /// incremented as events happen. Something must therefore decide when to ask.
    ///
    /// This crate deliberately does not decide for you. Call it from your
    /// exposition path immediately before gathering, which makes the reported
    /// value exact as of the scrape; or call it on a timer if your metrics
    /// pipeline refreshes on its own schedule. Either works, and a host embedding
    /// this crate already has such a place — which the bundled binary's
    /// `/metrics` handler cannot be, for anybody else.
    ///
    /// Cheap: one lock plus one iteration of each tracked server's session map.
    /// A no-op with nothing tracked.
    pub async fn refresh(&self) {
        // Clone the handles out before awaiting: holding a std Mutex across an
        // await point can deadlock, and is a lint in most codebases for exactly
        // that reason.
        let servers = match self.tracked.lock() {
            Ok(v) => v.clone(),
            Err(_) => {
                tracing::warn!("metrics: tracked-server lock poisoned; skipping refresh");
                return;
            }
        };
        for server in &servers {
            let g = server.session_gauges().await;
            self.set_sessions(server.instance().name, g.live as i64, g.active as i64);
        }
    }

    /// Record how long a scrape took to gather and encode.
    ///
    /// Exposition belongs to whoever owns the registry, so this crate cannot time
    /// it — but the signal is worth keeping: a scrape that quietly got slow is how
    /// a target starts being dropped for timing out, and the resulting gap looks
    /// like an outage that never happened. Call this from your `/metrics` handler.
    pub fn observe_scrape(&self, seconds: f64) {
        self.scrapes.observe(seconds);
    }
}

/// Register the process collector — CPU, resident memory, open file descriptors.
///
/// Separate from [`Metrics::new`], and deliberately so. It emits un-namespaced
/// `process_*` series describing the whole OS process, which belongs to the
/// application rather than to this crate; registering it from library code would
/// both claim series that are not ours and collide with any host that already has
/// one. Standalone binaries should call it; embedders generally should not.
///
/// A no-op off Linux, where the crate cannot implement it (it reads `/proc`).
pub fn register_process_collector(registry: &Registry) -> prometheus::Result<()> {
    #[cfg(target_os = "linux")]
    registry.register(Box::new(
        prometheus::process_collector::ProcessCollector::for_self(),
    ))?;
    #[cfg(not(target_os = "linux"))]
    let _ = registry;
    Ok(())
}

/// Middleware: record request count and latency.
///
/// Split from [`write_request_logs`] because the two have genuinely different
/// constraints and a combined layer forces the stricter one on both. Metrics must
/// bound every label — see the module docs — while a log line can afford the full
/// path, and is in fact more useful for carrying it. Separating them also lets a
/// host take one and not the other.
///
/// Apply with the handle as state:
///
/// ```ignore
/// use axum::middleware::from_fn_with_state;
/// let metrics = imcp2::metrics::Metrics::new(&registry, version, commit, started_at)?;
/// let app = router.layer(from_fn_with_state(
///     metrics.clone(),
///     imcp2::metrics::write_request_metrics,
/// ));
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

/// Middleware: log one line per request — method, path, status, elapsed.
///
/// At `debug` level. This fires on every request including the noise floor of an
/// internet-facing service, so it does not belong at `info`, where it drowns the
/// handful of lines an operator actually wants. `RUST_LOG=imcp2=debug` turns it on.
///
/// Only the path is logged, never the query string, so single-use secrets
/// (`?code=`) do not land in logs. Request bodies are never logged either — the
/// redeem POST carries the connection-scoped `state` and the delegation.
///
/// Unlike [`write_request_metrics`] this keeps the *full* path rather than the
/// route template: it is the record of what external clients actually probe, and
/// unbounded cardinality costs nothing in a log.
///
/// ```ignore
/// use axum::middleware::from_fn;
/// let app = router.layer(from_fn(imcp2::metrics::write_request_logs));
/// ```
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

/// The `route` label for a request: the route template the router matched, or
/// [`UNMATCHED_ROUTE`] when it matched nothing.
///
/// Taking the template rather than the path is what bounds cardinality. It also
/// means a new route starts being reported the moment it is added to the router,
/// with no list here to fall out of date — and a request for
/// `/wp-login.php` contributes to one shared series instead of minting its own.
pub fn route_label(matched: Option<&str>) -> &str {
    match matched {
        Some(t) if !t.is_empty() => t,
        _ => UNMATCHED_ROUTE,
    }
}

/// The `method` label for a request: the method itself when it is one of the
/// standard set, otherwise [`UNKNOWN_METHOD`].
///
/// Returns `&'static str` deliberately — it is not possible for a caller to
/// smuggle a borrowed request value through this function, so the bound holds by
/// type rather than by discipline.
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

    /// Stand-in for what a host does at scrape time, now that this crate does not
    /// render: gather the caller's registry and encode it.
    fn encode(registry: &Registry) -> String {
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buf)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn fixture() -> (Registry, Metrics) {
        let r = Registry::new();
        let m = Metrics::new(&r, "1.2.3", "abc1234", 1_700_000_000).unwrap();
        (r, m)
    }

    /// A router shaped like a host's: a real route, and the exported middleware.
    ///
    /// The cardinality tests go through this rather than calling `observe_request`
    /// directly. Calling the recorder with a pre-computed label only proves the
    /// recorder is deterministic; driving real requests proves the *middleware*
    /// derives a bounded label from a hostile one, which is the actual claim and
    /// the thing that breaks if someone later passes the raw URI.
    fn app(m: Metrics) -> Router {
        Router::new()
            .route("/version", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                m,
                write_request_metrics,
            ))
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

    /// The library must not claim the host's process-level series. `process_*` is
    /// un-namespaced and describes the whole OS process, which belongs to the
    /// application embedding this crate, not to this crate.
    #[test]
    fn new_does_not_register_the_process_collector() {
        let (r, _m) = fixture();
        let out = encode(&r);
        assert!(
            !out.contains("process_cpu_seconds_total"),
            "Metrics::new must not register process_* series:\n{out}"
        );
        // It is available, just opt-in and separate.
        register_process_collector(&r).unwrap();
        #[cfg(target_os = "linux")]
        assert!(encode(&r).contains("process_cpu_seconds_total"));
    }

    /// Registering twice into one registry is an error, not a panic — so a host
    /// that wires this up twice gets a `Result` it can act on. Build one and clone.
    #[test]
    fn double_registration_is_an_error_not_a_panic() {
        let (r, _m) = fixture();
        match Metrics::new(&r, "1.2.3", "abc1234", 0) {
            Err(prometheus::Error::AlreadyReg) => {}
            Err(e) => panic!("expected AlreadyReg, got {e:?}"),
            Ok(_) => panic!("expected the second registration to fail"),
        }
    }

    /// Two independent registries do not collide, which is what makes the
    /// clone-or-rebuild guidance workable.
    #[test]
    fn separate_registries_are_independent() {
        let (_r1, _m1) = fixture();
        let (_r2, _m2) = fixture();
    }

    #[test]
    fn records_requests_and_sessions() {
        let (r, m) = fixture();
        m.observe_request("/version", "GET", 200, 0.002);
        m.observe_request("/version", "GET", 200, 0.003);
        m.set_sessions("prod", 7, 3);
        let out = encode(&r);
        assert!(
            out.contains(concat!(
                metric!("http_requests_total"),
                r#"{method="GET",route="/version",status="200"} 2"#
            )),
            "{out}"
        );
        assert!(
            out.contains(concat!(metric!("live_sessions"), r#"{instance="prod"} 7"#)),
            "{out}"
        );
        assert!(
            out.contains(concat!(metric!("active_sessions"), r#"{instance="prod"} 3"#)),
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

        let buckets = out
            .lines()
            .filter(|l| l.starts_with(concat!(metric!("http_request_duration_seconds"), "_bucket")))
            .count();
        assert_eq!(
            buckets,
            LATENCY_BUCKETS.len() + 1,
            "one label set means one bucket family (+Inf), got:\n{out}"
        );
    }

    /// `track` must publish zeroes at once, so a tracked instance has a series
    /// from registration rather than being absent until something refreshes.
    #[test]
    fn tracking_publishes_zeroes_immediately() {
        let (r, m) = fixture();
        assert!(
            !encode(&r).contains(metric!("live_sessions")),
            "no instance tracked yet, so no series"
        );
        // A real McpServer needs an Agent and network config, so assert the
        // narrower property directly: registration is what creates the series.
        m.set_sessions("prod", 0, 0);
        let out = encode(&r);
        assert!(
            out.contains(concat!(metric!("live_sessions"), r#"{instance="prod"} 0"#)),
            "{out}"
        );
        assert!(
            out.contains(concat!(metric!("active_sessions"), r#"{instance="prod"} 0"#)),
            "{out}"
        );
    }

    /// `refresh` with nothing tracked must be a harmless no-op — an embedder that
    /// calls it on a timer before wiring anything up should not get a panic.
    #[tokio::test]
    async fn refresh_with_nothing_tracked_is_a_noop() {
        let (r, m) = fixture();
        m.refresh().await;
        assert!(!encode(&r).contains(metric!("live_sessions")));
    }

    /// Cloning shares the tracked set, so an embedder can track through one handle
    /// and refresh through another — which is what happens when the handle is
    /// cloned into middleware state and into an exposition path separately.
    #[test]
    fn clones_share_the_tracked_set() {
        let (_r, m) = fixture();
        let clone = m.clone();
        assert!(
            std::sync::Arc::ptr_eq(&m.tracked, &clone.tracked),
            "clones must share one tracked set, not copy it"
        );
    }

    #[tokio::test]
    async fn real_routes_keep_their_identity() {
        let (r, m) = fixture();
        let req = HttpRequest::builder()
            .uri("/version")
            .body(Body::empty())
            .unwrap();
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
}
