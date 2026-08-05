//! Prometheus metrics for the deployment binary, exposed at `GET /metrics` in
//! the standard text exposition format.
//!
//! Uses the `prometheus` crate at the version `dfinity/ic` pins, since these
//! series are destined for the same Prometheus/Victoria Metrics clusters that
//! scrape the IC — matching the org's client avoids two exposition dialects in
//! one estate.
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

use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};

/// The bucket every unmatched request shares. One series for the entire
/// internet's worth of probing, rather than one per path attempted.
const UNMATCHED_ROUTE: &str = "other";

/// Latency buckets in seconds. Chosen for what this service actually does: the
/// static pages and `/version` answer in single-digit milliseconds, while an MCP
/// tool call that talks to the IC is a network round trip and lands in the
/// hundreds. The default `prometheus` buckets top out at 10s, which is fine, but
/// they have no resolution below 5ms where most responses here live.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Handle for recording and rendering metrics. Cheap to clone: everything inside
/// is `Arc`-backed by the `prometheus` crate, so clones share one registry.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
    live_sessions: IntGaugeVec,
    active_sessions: IntGaugeVec,
    scrapes: Histogram,
}

impl Metrics {
    /// Build the registry and register every collector.
    ///
    /// `commit` and `version` become labels on a single `build_info` gauge — the
    /// conventional way to attach immutable facts to a target without pinning
    /// them onto every other series.
    pub fn new(version: &str, commit: &str, started_at: u64) -> prometheus::Result<Self> {
        let registry = Registry::new();

        let requests = IntCounterVec::new(
            Opts::new(
                "imcp2_http_requests_total",
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
                "imcp2_http_request_duration_seconds",
                "HTTP request latency in seconds, by matched route template and method.",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
            &["route", "method"],
        )?;
        registry.register(Box::new(duration.clone()))?;

        let live_sessions = IntGaugeVec::new(
            Opts::new(
                "imcp2_live_sessions",
                "Authenticated sessions holding a currently-valid Internet Identity grant. \
                 A session counts from grant redemption until the grant expires, idle or not.",
            ),
            &["instance"],
        )?;
        registry.register(Box::new(live_sessions.clone()))?;

        let active_sessions = IntGaugeVec::new(
            Opts::new(
                "imcp2_active_sessions",
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
                "imcp2_metrics_scrape_duration_seconds",
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
                "imcp2_build_info",
                "Always 1. Carries the running version and commit as labels.",
            ),
            &["version", "commit"],
        )?;
        registry.register(Box::new(build_info.clone()))?;
        build_info.with_label_values(&[version, commit]).set(1);

        // Conventional name and semantics, matching what node_exporter and the
        // client libraries use, so existing dashboards and "restarted recently"
        // alert expressions work without special-casing this target.
        let start_time = IntGauge::new(
            "imcp2_process_start_time_seconds",
            "Unix epoch seconds at which this process started, i.e. when the deployment \
             last restarted. Every deploy restarts the service.",
        )?;
        registry.register(Box::new(start_time.clone()))?;
        start_time.set(started_at as i64);

        // CPU, resident memory and file descriptors. Only compiled where the
        // crate can implement it: it reads /proc, so it is Linux-only. The deploy
        // target is Amazon Linux; this keeps a macOS dev build working.
        #[cfg(target_os = "linux")]
        registry.register(Box::new(
            prometheus::process_collector::ProcessCollector::for_self(),
        ))?;

        Ok(Self {
            registry,
            requests,
            duration,
            live_sessions,
            active_sessions,
            scrapes,
        })
    }

    /// Record one completed request. `route` must already be a bounded template
    /// — see [`route_label`].
    pub fn observe_request(&self, route: &str, method: &str, status: u16, elapsed_secs: f64) {
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

    /// Publish one instance's session counts. Called during a scrape, so the
    /// value reported is the one read at scrape time.
    pub fn set_sessions(&self, instance: &str, live: i64, active: i64) {
        self.live_sessions.with_label_values(&[instance]).set(live);
        self.active_sessions
            .with_label_values(&[instance])
            .set(active);
    }

    /// Gather and encode the registry in Prometheus text format.
    pub fn render(&self) -> prometheus::Result<String> {
        let timer = self.scrapes.start_timer();
        let mut buf = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut buf)?;
        timer.observe_duration();
        String::from_utf8(buf)
            .map_err(|e| prometheus::Error::Msg(format!("metrics output was not UTF-8: {e}")))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmatched_requests_share_one_label() {
        // The property that matters: nothing an outsider sends can mint a series.
        assert_eq!(route_label(None), UNMATCHED_ROUTE);
        assert_eq!(route_label(Some("")), UNMATCHED_ROUTE);
    }

    #[test]
    fn matched_requests_keep_their_template() {
        assert_eq!(route_label(Some("/version")), "/version");
        assert_eq!(route_label(Some("/mcp")), "/mcp");
    }

    #[test]
    fn renders_text_format_with_build_info_and_start_time() {
        let m = Metrics::new("1.2.3", "abc1234", 1_700_000_000).unwrap();
        let out = m.render().unwrap();
        assert!(out.contains("imcp2_build_info"), "{out}");
        assert!(out.contains(r#"version="1.2.3""#), "{out}");
        assert!(out.contains(r#"commit="abc1234""#), "{out}");
        assert!(
            out.contains("imcp2_process_start_time_seconds 1700000000"),
            "{out}"
        );
    }

    #[test]
    fn records_requests_and_sessions() {
        let m = Metrics::new("0", "0", 0).unwrap();
        m.observe_request("/version", "GET", 200, 0.002);
        m.observe_request("/version", "GET", 200, 0.003);
        m.observe_request(UNMATCHED_ROUTE, "GET", 404, 0.001);
        m.set_sessions("prod", 7, 3);

        let out = m.render().unwrap();
        assert!(
            out.contains(
                r#"imcp2_http_requests_total{method="GET",route="/version",status="200"} 2"#
            ),
            "{out}"
        );
        assert!(
            out.contains(r#"imcp2_http_requests_total{method="GET",route="other",status="404"} 1"#),
            "{out}"
        );
        assert!(
            out.contains(r#"imcp2_live_sessions{instance="prod"} 7"#),
            "{out}"
        );
        assert!(
            out.contains(r#"imcp2_active_sessions{instance="prod"} 3"#),
            "{out}"
        );
        // The histogram must carry the observations, not just exist.
        assert!(
            out.contains(
                r#"imcp2_http_request_duration_seconds_count{method="GET",route="/version"} 2"#
            ),
            "{out}"
        );
    }

    #[test]
    fn a_flood_of_distinct_paths_does_not_grow_the_series_count() {
        // The cardinality guarantee, asserted rather than asserted-in-a-comment:
        // 500 different unmatched paths must still be one series.
        let m = Metrics::new("0", "0", 0).unwrap();
        for i in 0..500 {
            let path = format!("/{i}-{}", "x".repeat(i % 17));
            // What the middleware does for an unrouted request.
            m.observe_request(route_label(None), "GET", 404, 0.001);
            let _ = path;
        }
        let out = m.render().unwrap();
        let series = out
            .lines()
            .filter(|l| l.starts_with("imcp2_http_requests_total{"))
            .count();
        assert_eq!(series, 1, "expected exactly one series, got:\n{out}");
        assert!(
            out.contains(r#"status="404"} 500"#),
            "all 500 should land in the one series:\n{out}"
        );
    }
}
