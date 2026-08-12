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
//!     `active_sessions`. Recomputed on [`Metrics::refresh`] rather than pushed as
//!     events happen, because they are derived state: the authoritative value is
//!     whatever the session map says when asked. Both come from one collector over
//!     one snapshot, so `active <= live` holds of what a scrape *exports* and not
//!     merely of what the writer intended — see [`SessionCollector`].
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
    core::{Collector, Desc},
    proto::{Gauge, LabelPair, Metric, MetricFamily, MetricType},
    Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use std::collections::{BTreeMap, HashMap};
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

/// Registers a group of collectors into a caller-owned [`Registry`] as a unit,
/// unwinding on the first failure.
///
/// `prometheus::Registry` offers no transactional registration, and a plain
/// sequence of `registry.register(…)?` calls is not one: a collision on the fifth
/// collector leaves the first four registered and returns `Err`. The caller then
/// holds no handle while its registry keeps a partial set of this crate's
/// descriptors that nothing can ever write to — and once the caller fixes the
/// collision, the retry fails with [`prometheus::Error::AlreadyReg`] on the
/// *first* collector, reporting a cause that has nothing to do with the problem.
/// All or nothing avoids both.
///
/// What the unwind restores, precisely: the registered collectors and their
/// descriptor ids, which is what a retry needs and what leaving them behind
/// breaks. It does **not** restore the registry's `fq_name -> dim_hash` table —
/// `Registry::unregister` deliberately keeps those "consistent throughout the
/// lifetime of a program", so once this constructor has *attempted* a name, a
/// differently-shaped collector claiming that same name can no longer be
/// registered even after the rollback. Nothing here can undo that, and an
/// aggregate collector would not either: `Registry::register` records each
/// descriptor's dim hash as it validates them, before it commits anything. It also
/// costs nothing real — the names are ours, and the shape they are reserved with is
/// the shape we use.
struct Registration<'a> {
    registry: &'a Registry,
    /// Registered so far, kept for the rollback.
    done: Vec<Box<dyn Collector>>,
    /// The first failure. Once set, [`Self::add`] stops registering.
    failure: Option<prometheus::Error>,
}

impl<'a> Registration<'a> {
    fn new(registry: &'a Registry) -> Self {
        Self {
            registry,
            done: Vec::new(),
            failure: None,
        }
    }

    /// Register one collector, or record the first failure and stop.
    ///
    /// Takes the collector by reference and clones it twice: `register` consumes
    /// its `Box` and `unregister` needs another one, while `Box<dyn Collector>` is
    /// not itself cloneable. Cloning a `prometheus` collector is an `Arc` bump, so
    /// both boxes address the same series.
    fn add<C: Collector + Clone + 'static>(mut self, c: &C) -> Self {
        if self.failure.is_some() {
            return self;
        }
        match self.registry.register(Box::new(c.clone())) {
            Ok(()) => self.done.push(Box::new(c.clone())),
            Err(e) => self.failure = Some(e),
        }
        self
    }

    /// Commit the group, or roll it back and return the failure.
    fn finish(mut self) -> prometheus::Result<()> {
        match self.failure.take() {
            None => Ok(()),
            Some(e) => {
                for c in self.done.drain(..) {
                    // A failed removal can only mean something else already
                    // unregistered it, and the caller is getting the original,
                    // more informative error either way.
                    let _ = self.registry.unregister(c);
                }
                Err(e)
            }
        }
    }
}

/// One instance's session counts, as a pair that is only ever read or written
/// together: `(live, active)`.
type Counts = (i64, i64);

/// Publishes `imcp2_live_sessions` and `imcp2_active_sessions` from a single
/// snapshot, so `active <= live` holds in the exposition and not merely in the
/// writer.
///
/// Two `IntGaugeVec`s cannot give that guarantee, and no amount of care at the
/// write site fixes it, because the *reader* is not taking an instantaneous
/// observation either: [`Registry::gather`] calls each registered collector in
/// turn, so it reads `live` at one instant and `active` at another with nothing
/// held in between. A refresh landing between those two reads exports a pair that
/// was never simultaneously true — `live` from before it and `active` from after —
/// and with counts falling that is exactly `active > live`, the one thing the help
/// text promises cannot happen and the reason an alert may divide the two.
///
/// Ordering the two writes narrows the window but cannot close it; only making the
/// pair inseparable does. So both counts live in one map behind one mutex, and
/// [`Collector::collect`] takes that lock once and builds both families from the
/// same snapshot. Every exported pair is then a pair that existed.
///
/// Instances are keyed by `&'static str` — see [`Metrics::set_sessions`] on why
/// that, and not a `String`, is what bounds this label.
///
/// `Clone` shares the map and copies the descriptors, which is what lets
/// [`Registration`] hold a second handle for its rollback.
#[derive(Clone)]
struct SessionCollector {
    counts: Arc<Mutex<BTreeMap<&'static str, Counts>>>,
    live: Desc,
    active: Desc,
}

impl SessionCollector {
    fn new(counts: Arc<Mutex<BTreeMap<&'static str, Counts>>>) -> prometheus::Result<Self> {
        Ok(Self {
            counts,
            live: Desc::new(
                metric!("live_sessions").to_string(),
                "Authenticated sessions holding a currently-valid Internet Identity grant, \
                 summed over every tracked server serving this instance. A session counts \
                 from grant redemption until the grant expires, idle or not."
                    .to_string(),
                vec!["instance".to_string()],
                HashMap::new(),
            )?,
            active: Desc::new(
                metric!("active_sessions").to_string(),
                "The subset of live sessions that also made a request within the activity \
                 window, summed the same way. Always <= imcp2_live_sessions, in the \
                 exposition and not just in the writer. Use this to time a low-disruption \
                 redeploy."
                    .to_string(),
                vec!["instance".to_string()],
                HashMap::new(),
            )?,
        })
    }
}

impl Collector for SessionCollector {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.live, &self.active]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        // One lock, both families. This single line is the entire reason this type
        // exists rather than a pair of `IntGaugeVec`s.
        let snapshot: Vec<(&'static str, Counts)> = match self.counts.lock() {
            Ok(m) => m.iter().map(|(k, v)| (*k, *v)).collect(),
            // A poisoned lock means a writer panicked. Reporting nothing is the
            // honest option: a stale pair would be indistinguishable from a real
            // one, and panicking inside `gather` would take out the whole scrape.
            Err(_) => {
                tracing::warn!("metrics: session-counts lock poisoned; reporting no sessions");
                return Vec::new();
            }
        };
        vec![
            gauge_family(&self.live, snapshot.iter().map(|(n, (live, _))| (*n, *live))),
            gauge_family(
                &self.active,
                snapshot.iter().map(|(n, (_, active))| (*n, *active)),
            ),
        ]
    }
}

/// One gauge `MetricFamily` from a descriptor and its `instance`-labelled values.
///
/// Hand-built because a custom collector returns the wire types directly; there is
/// no `IntGaugeVec` in the middle to do it. An empty family is fine to return —
/// [`Registry::gather`] prunes those, which is what makes an untracked instance
/// absent rather than reported as zero.
fn gauge_family<'a>(desc: &Desc, values: impl Iterator<Item = (&'a str, i64)>) -> MetricFamily {
    let mut family = MetricFamily::default();
    family.set_name(desc.fq_name.clone());
    family.set_help(desc.help.clone());
    family.set_field_type(MetricType::GAUGE);
    family.set_metric(
        values
            .map(|(instance, value)| {
                let mut label = LabelPair::default();
                label.set_name("instance".to_string());
                label.set_value(instance.to_string());
                let mut gauge = Gauge::default();
                gauge.set_value(value as f64);
                let mut metric = Metric::default();
                metric.set_label(vec![label]);
                metric.set_gauge(gauge);
                metric
            })
            .collect(),
    );
    family
}

/// Sum per-server counts into per-instance counts, so several servers sharing an
/// instance name produce one total rather than overwriting each other.
///
/// The `instance` label names an Internet Identity instance, not a mount path, and
/// nothing stops an embedder serving one instance at two mounts — two `McpServer`s
/// whose `IiInstance::prod()` both carry the name `prod`. Writing each in turn made
/// the last one win, so the exported gauge silently reported one server's sessions
/// as if it were the whole instance's: an under-report with no symptom, which is the
/// worst shape a metric bug can take. Summing makes the number mean what the label
/// says, for one server or five.
///
/// A free function over an iterator so the aggregation can be checked directly.
/// Testing it through `refresh` would need authenticated sessions to distinguish
/// summing from overwriting, since every count a unit test can produce is zero.
fn totals(counts: impl IntoIterator<Item = (&'static str, Counts)>) -> BTreeMap<&'static str, Counts>
{
    let mut out: BTreeMap<&'static str, Counts> = BTreeMap::new();
    for (instance, (live, active)) in counts {
        let entry = out.entry(instance).or_insert((0, 0));
        entry.0 += live;
        entry.1 += active;
    }
    out
}

/// Handle for recording this crate's metrics. Cheap to clone: every collector is
/// `Arc`-backed by the `prometheus` crate, so clones share one set of series.
///
/// Holds no [`Registry`] — see the module docs. Clone this into your middleware
/// state and wherever else you record from.
#[derive(Clone)]
pub struct Metrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    /// The session counts, written here and read by [`SessionCollector`] — which is
    /// what makes each instance's `(live, active)` inseparable on both sides.
    sessions: Arc<Mutex<BTreeMap<&'static str, Counts>>>,
    scrapes: Histogram,
    /// Servers whose derived gauges [`Metrics::refresh`] republishes. Shared
    /// across clones, so tracking through any handle is visible to all of them.
    tracked: Arc<Mutex<Vec<crate::McpServer>>>,
    /// Serializes [`Metrics::refresh`] against itself — see there for why. A
    /// `tokio` mutex because it is held across the awaits that read each tracked
    /// server's session map.
    refreshing: Arc<tokio::sync::Mutex<()>>,
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
    ///
    /// On **any** failure no collector of ours stays registered: every collector is
    /// built before the first registration and the group is registered as a unit
    /// that unwinds, so a collision partway through does not strand half a metric
    /// set in a registry whose owner was handed an error and no handle, and a retry
    /// after the caller resolves the collision works. What a rollback cannot undo —
    /// the registry's name-to-shape table — is spelled out on [`Registration`].
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

        // Both session gauges, from one collector over one map — see
        // `SessionCollector` for why they cannot be two.
        let sessions = Arc::new(Mutex::new(BTreeMap::new()));
        let session_collector = SessionCollector::new(Arc::clone(&sessions))?;

        // Self-observability for the endpoint itself. A scrape that quietly got
        // slow is how a monitoring target starts being dropped for timing out,
        // and the resulting gap looks like an outage that never happened.
        let scrapes = Histogram::with_opts(
            HistogramOpts::new(
                metric!("metrics_scrape_duration_seconds"),
                "Time spent producing this endpoint's own response: recomputing the derived \
                 gauges, then gathering and encoding the registry.",
            )
            .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]),
        )?;

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

        // The namespaced twin of the conventional `process_start_time_seconds` — the
        // prefix means it cannot BE that series, so it agrees with it instead:
        // `started_at` is read as the first statement of `main`, which is process
        // start to within microseconds.
        //
        // It used to be justified as measuring something deliberately different
        // ("when the server began serving"). That was not true of the value it was
        // given, which was captured mid-initialisation — neither process start nor
        // ready-to-serve — so the series disagreed with the conventional one by a
        // couple of seconds for a reason no consumer could discover. A metric whose
        // name says one thing and whose value means another is worse than not having
        // it. The reading moved; the name and help text were already right.
        //
        // Kept despite the overlap because an embedder gets only this one: the
        // library does not register the process collector (see
        // `register_process_collector`), and that collector is Linux-only besides.
        let start_time = IntGauge::new(
            metric!("process_start_time_seconds"),
            "Unix epoch seconds at which this process started, i.e. when the deployment \
             last restarted. Every deploy restarts the service.",
        )?;

        // Nothing above touched the registry: every collector is built first so
        // that the only fallible step left is registration, which then either
        // takes the whole group or leaves the registry untouched.
        Registration::new(registry)
            .add(&requests)
            .add(&duration)
            .add(&session_collector)
            .add(&scrapes)
            .add(&build_info)
            .add(&start_time)
            .finish()?;

        // Only once the group is committed. Setting these earlier would write
        // values into collectors a rollback then removes — harmless, but it would
        // put the constructor's observable effects out of step with its result.
        build_info.with_label_values(&[version, commit]).set(1);
        start_time.set(started_at as i64);

        Ok(Self {
            requests,
            duration,
            sessions,
            scrapes,
            tracked: Arc::new(Mutex::new(Vec::new())),
            refreshing: Arc::new(tokio::sync::Mutex::new(())),
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
    ///
    /// The pair is written as a pair, under one lock, because it is read as a pair
    /// under the same lock — see [`SessionCollector`]. That is what makes
    /// `active <= live` true of the exposition and not merely of the writer.
    pub(crate) fn set_sessions(&self, instance: &'static str, live: i64, active: i64) {
        match self.sessions.lock() {
            Ok(mut m) => {
                m.insert(instance, (live, active));
            }
            // Losing one instance's counts is not worth propagating a panic out of
            // an instrumentation call; the collector reports the same poisoning.
            Err(_) => tracing::warn!(instance, "metrics: session-counts lock poisoned"),
        }
    }

    /// Track a server whose derived gauges [`Self::refresh`] should publish.
    ///
    /// Call once per served [`crate::McpServer`]. The server is cheap to clone and
    /// everything inside it is shared, so this holds a handle rather than a copy
    /// of any state.
    ///
    /// Tracking several servers that share an instance name is allowed and adds
    /// their counts together — the label names an Internet Identity instance, not a
    /// mount, so one instance served at two mounts is one instance's worth of
    /// sessions. See [`totals`].
    ///
    /// Publishes zeroes immediately, so a tracked instance's gauges read `0` from
    /// the moment it is registered rather than being absent until the first
    /// refresh. An instance that is *not* served is simply not tracked and has no
    /// series — which is the honest reading: there is no such instance here, as
    /// distinct from one that exists and currently has no sessions.
    pub fn track(&self, server: &crate::McpServer) {
        let name = server.instance().name;
        match self.tracked.lock() {
            Ok(mut v) => {
                // Zero-fill and publish the server under ONE hold of this lock. Do
                // it after releasing and a [`Self::refresh`] racing in between can
                // publish the server's real counts, which the zero-fill then
                // overwrites — the instance would read 0 until the next refresh.
                // `refresh` only ever takes this lock to clone the list out, and
                // never takes it while holding the session-counts lock, so nesting
                // in this direction cannot deadlock.
                self.set_sessions(name, 0, 0);
                v.push(server.clone());
            }
            // A poisoned lock means another thread panicked mid-push. Losing the
            // registration is not worth propagating a panic from an instrumentation
            // call, so warn and carry on un-tracked — publishing nothing, rather
            // than a zero series for an instance nothing will ever refresh.
            Err(_) => tracing::warn!(instance = name, "metrics: tracked-server lock poisoned"),
        }
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
    /// Concurrent calls are **serialized** rather than interleaved, and that is a
    /// correctness property, not tidiness. Each instance's counts are read and
    /// then written, so two overlapping refreshes can commit in the order they
    /// finish rather than the order they read: the one that read *first* writes
    /// last and leaves stale numbers standing until the next refresh — a whole
    /// scrape interval of a value that was never true. Overlap is not hypothetical:
    /// two scrapers, or a scrape arriving while an embedder's timer fires, is
    /// enough. (What a *scrape* sees is a separate matter, handled at the read side
    /// by [`SessionCollector`] rather than by anything this method does.)
    ///
    /// Cheap: one lock plus one iteration of each tracked server's session map.
    /// A no-op with nothing tracked.
    pub async fn refresh(&self) {
        // Held across the whole read-then-write pass, so a refresh either happens
        // entirely before or entirely after another one.
        let _serialized = self.refreshing.lock().await;
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
        let mut read = Vec::with_capacity(servers.len());
        for server in &servers {
            let g = server.session_gauges().await;
            read.push((server.instance().name, (g.live as i64, g.active as i64)));
        }
        for (instance, (live, active)) in totals(read) {
            self.set_sessions(instance, live, active);
        }
    }

    /// Record how long producing a scrape took.
    ///
    /// Exposition belongs to whoever owns the registry, so this crate cannot time
    /// it — but the signal is worth keeping: a scrape that quietly got slow is how
    /// a target starts being dropped for timing out, and the resulting gap looks
    /// like an outage that never happened.
    ///
    /// Time the **whole** handler, [`Self::refresh`] included, not just the gather
    /// and encode. Refresh scans every tracked server's session map and waits on any
    /// refresh already in flight; excluded from the measurement, it is latency this
    /// metric cannot see, which defeats the one thing it is for.
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

    /// A real production-instance [`crate::McpServer`], for the tests that must go
    /// through [`Metrics::track`] rather than the private setter.
    ///
    /// Construction is pure — `McpServer::new` wires up handles and touches the
    /// network for nothing — so this needs no server, no runtime and no fixture
    /// scaffolding beyond an `Agent` pointed at mainnet. `SharedClients::load()`
    /// reads the OAuth registration store, which these assertions never consult;
    /// it is left alone rather than redirected, since `$OAUTH_CLIENTS_FILE` is
    /// process-global and this test binary shares it with every other unit test.
    fn server() -> crate::McpServer {
        server_at("/mcp")
    }

    /// The same, at a chosen mount — for the case of one Internet Identity instance
    /// served at more than one path.
    fn server_at(mcp_path: &str) -> crate::McpServer {
        crate::McpServer::new(crate::McpConfig {
            agent: crate::Agent::builder()
                .with_url(crate::IC_URL)
                .build()
                .expect("build agent"),
            instance: crate::IiInstance::prod().expect("prod instance"),
            public_url: "https://mcp.example.com".into(),
            mcp_path: mcp_path.into(),
            clients: crate::SharedClients::load(),
            require_resource: true,
        })
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

    /// The `(instance, live, active)` triples one `gather()` exported, read out of
    /// the wire types rather than the encoded text — the concurrency test below
    /// compares the two families against each other, which the text form makes
    /// needlessly fiddly.
    fn gathered_pairs(registry: &Registry) -> Vec<(String, i64, i64)> {
        let families = registry.gather();
        let values = |name: &str| -> Vec<(String, i64)> {
            families
                .iter()
                .filter(|f| f.name() == name)
                .flat_map(|f| {
                    f.get_metric().iter().map(|m| {
                        let instance = m
                            .get_label()
                            .iter()
                            .find(|l| l.name() == "instance")
                            .map(|l| l.value().to_string())
                            .unwrap_or_default();
                        (instance, m.get_gauge().value() as i64)
                    })
                })
                .collect()
        };
        let active: HashMap<String, i64> = values(metric!("active_sessions")).into_iter().collect();
        values(metric!("live_sessions"))
            .into_iter()
            .map(|(instance, live)| {
                let a = active.get(&instance).copied().unwrap_or(0);
                (instance, live, a)
            })
            .collect()
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

    /// A collision *partway through* must leave the caller's registry as it was.
    ///
    /// This is the case a sequence of `register(…)?` calls gets wrong, and
    /// `double_registration_is_an_error_not_a_panic` cannot catch it: a second
    /// `Metrics::new` fails on the very first collector, so nothing is ever
    /// half-registered. Colliding on the sixth of seven is what exercises the
    /// unwind — the proof being that the retry succeeds, which it cannot do if any
    /// collector from the abandoned attempt is still registered.
    ///
    /// The squatter mirrors `build_info`'s help and labels deliberately. A
    /// same-name collector is refused whatever its shape, but `Registry` keeps
    /// `fq_name -> dim_hash` for the lifetime of the process even across
    /// `unregister`, so only an identical descriptor can be cleared out of the way
    /// again. If the real help text drifts from this copy, the retry below fails
    /// with that mismatch rather than passing silently.
    #[test]
    fn a_failed_registration_rolls_back_the_earlier_collectors() {
        let r = Registry::new();
        let squatter = IntGaugeVec::new(
            Opts::new(
                metric!("build_info"),
                "Always 1. Carries the running version and commit as labels.",
            ),
            &["version", "commit"],
        )
        .unwrap();
        r.register(Box::new(squatter.clone())).unwrap();

        match Metrics::new(&r, "1.2.3", "abc1234", 0) {
            Err(prometheus::Error::AlreadyReg) => {}
            Err(e) => panic!("expected AlreadyReg on the host's collector, got {e:?}"),
            Ok(_) => panic!("expected the collision to fail the constructor"),
        }

        // The host resolves the collision; the constructor must now work. Without
        // the rollback this fails with AlreadyReg on `imcp2_http_requests_total`,
        // reporting a cause with nothing to do with the actual problem.
        r.unregister(Box::new(squatter)).unwrap();
        let m = Metrics::new(&r, "1.2.3", "abc1234", 1_700_000_000)
            .expect("retry once the collision is cleared");

        // And the handle from the successful attempt records into that registry —
        // i.e. the retry registered live collectors, not descriptors left over from
        // the attempt that failed.
        m.observe_request("/version", "GET", 200, 0.002);
        assert!(
            encode(&r).contains(concat!(
                metric!("http_requests_total"),
                r#"{method="GET",route="/version",status="200"} 1"#
            )),
            "{}",
            encode(&r)
        );
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
    ///
    /// Goes through the public `track` with a real server, not through
    /// `set_sessions`. Calling the private setter would assert only that writing a
    /// gauge writes a gauge: the test would keep passing if `track` stopped
    /// retaining the server, stopped zero-filling, or read the instance name from
    /// somewhere else. What is being claimed is that *handing `track` a server*
    /// produces the series, so a server is what it gets handed.
    #[test]
    fn tracking_publishes_zeroes_immediately() {
        let (r, m) = fixture();
        assert!(
            !encode(&r).contains(metric!("live_sessions")),
            "no instance tracked yet, so no series"
        );
        m.track(&server());
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

    /// The `(live, active)` pair each `gather()` exports must be a pair that
    /// actually existed — in particular never `active > live`, which the help text
    /// promises and an alert dividing the two depends on.
    ///
    /// This is the property two separate collectors cannot have, and it is a
    /// *reader*-side property, so it has to be tested by reading concurrently with a
    /// writer rather than by reasoning about write order. A background task flips
    /// the counts between two valid pairs while this one gathers as fast as it can;
    /// with both families built from one locked snapshot, no interleaving can
    /// produce a mixed pair. Have `collect` take the lock once per family instead
    /// and this fails within a few thousand gathers.
    ///
    /// The writer runs until the *reader* is done, rather than the reader looping
    /// until a fixed number of writes finish. That direction matters: a writer with
    /// a fixed workload can complete it before the reader is ever scheduled, which
    /// on a loaded runner would fail a "did the loop actually run" assertion while
    /// the collector was perfectly correct. Here the reader always performs the same
    /// number of gathers and the writer cannot end early, so nothing about CI speed
    /// can change the verdict. A barrier makes both sides live before the first
    /// gather, and the writer's own count is asserted so a writer that never ran
    /// cannot pass this quietly.
    ///
    /// It also has to *fail* properly, which took two goes. Asserting inside the
    /// read loop unwound the test before clearing the stop flag, leaving the writer
    /// spinning — and dropping a runtime waits for its blocking tasks, so a
    /// detected violation hung the run instead of reporting it. A hanging test is
    /// worse than a flaky one: it eats the job timeout and says nothing. So the
    /// violation is recorded and asserted after the writer is released, and the
    /// writer carries its own bound in case the reader dies some other way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_gather_never_exports_a_pair_that_never_existed() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Barrier;

        const GATHERS: u32 = 2_000;
        /// Liveness guard, not a workload — roughly 3x what the reader's gathers
        /// take, so reaching it means the reader is gone rather than slow. Hitting
        /// it early cannot change the verdict: the reader's iteration count is
        /// fixed and only `writes > 0` is asserted of the writer.
        const WRITE_CAP: u64 = 5_000_000;

        let (r, m) = fixture();
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(Barrier::new(2));
        let writer = tokio::task::spawn_blocking({
            let (m, stop, ready) = (m.clone(), Arc::clone(&stop), Arc::clone(&ready));
            move || {
                ready.wait();
                let mut writes = 0u64;
                while !stop.load(Ordering::Relaxed) && writes < WRITE_CAP {
                    // Both pairs are valid on their own; only a mixed read of the
                    // two families can yield active > live.
                    if writes.is_multiple_of(2) {
                        m.set_sessions("prod", 10, 5);
                    } else {
                        m.set_sessions("prod", 3, 1);
                    }
                    writes += 1;
                }
                writes
            }
        });
        ready.wait();

        let mut violation = None;
        for gather in 0..GATHERS {
            if let Some((instance, live, active)) = gathered_pairs(&r)
                .into_iter()
                .find(|(_, live, active)| active > live)
            {
                violation =
                    Some(format!("gather {gather}: {instance} active={active} > live={live}"));
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
        let writes = writer.await.unwrap();

        assert!(violation.is_none(), "{}", violation.unwrap_or_default());
        assert!(writes > 0, "the writer never ran, so the race was not exercised");
    }

    /// The values a scrape reports must be the ones that were written. Building the
    /// families by hand means nothing checks the wiring but a test: swap the two and
    /// every invariant above still holds while both numbers are wrong.
    #[test]
    fn the_exposition_reports_the_values_that_were_written() {
        let (r, m) = fixture();
        for (live, active) in [(10, 5), (3, 1), (7, 7), (0, 0), (4, 2)] {
            m.set_sessions("prod", live, active);
            let out = encode(&r);
            let want_live = format!(concat!(metric!("live_sessions"), r#"{{instance="prod"}} {}"#), live);
            let want_active =
                format!(concat!(metric!("active_sessions"), r#"{{instance="prod"}} {}"#), active);
            assert!(out.contains(&want_live), "missing {want_live}:\n{out}");
            assert!(out.contains(&want_active), "missing {want_active}:\n{out}");
        }
    }

    /// Several servers serving one instance must **add up**, not overwrite. Writing
    /// each in turn made the last one win, so the gauge reported one server's
    /// sessions as the whole instance's — an under-report with no symptom.
    ///
    /// Tested on the aggregation directly, because no unit test can tell summing
    /// from overwriting through `refresh`: every count a test can produce without
    /// authenticated sessions is zero, and 0 + 0 = 0 either way.
    #[test]
    fn servers_sharing_an_instance_name_are_summed() {
        assert_eq!(
            totals([("prod", (7, 3)), ("beta", (2, 1)), ("prod", (5, 2))]),
            BTreeMap::from([("prod", (12, 5)), ("beta", (2, 1))]),
            "counts for one instance must add, and other instances stay separate"
        );
        // The invariant survives aggregation: summing two pairs that each satisfy
        // active <= live cannot produce one that does not.
        let summed = totals([("prod", (10, 10)), ("prod", (1, 0))]);
        let (live, active) = summed["prod"];
        assert!(active <= live, "({live},{active})");
        assert!(totals([]).is_empty(), "nothing tracked, nothing published");
    }

    /// And through the public API: two distinct servers on the same instance must
    /// leave one series, not two competing ones.
    #[tokio::test]
    async fn two_servers_on_one_instance_expose_one_series() {
        let (r, m) = fixture();
        m.track(&server());
        m.track(&server_at("/mcp-alt"));
        m.refresh().await;
        let live: Vec<_> = encode(&r)
            .lines()
            .filter(|l| l.starts_with(concat!(metric!("live_sessions"), "{")))
            .map(str::to_string)
            .collect();
        assert_eq!(live.len(), 1, "expected one series for one instance, got {live:?}");
        assert!(live[0].contains(r#"instance="prod""#), "{}", live[0]);
    }

    /// `refresh` with nothing tracked must be a harmless no-op — an embedder that
    /// calls it on a timer before wiring anything up should not get a panic.
    #[tokio::test]
    async fn refresh_with_nothing_tracked_is_a_noop() {
        let (r, m) = fixture();
        m.refresh().await;
        assert!(!encode(&r).contains(metric!("live_sessions")));
    }

    /// `refresh` must reach a tracked server's session map, and overlapping calls
    /// must serialize rather than deadlock.
    ///
    /// A fresh server has no sessions, so a refresh publishes zeroes — which is
    /// also what `track` already wrote, and asserting on them directly would prove
    /// nothing about `refresh` at all. So the gauges are first set to values no
    /// session map would produce: only a refresh that actually reached the tracked
    /// server can clear them. Stop `track` retaining the server, or `refresh`
    /// iterating what it retained, and this fails.
    ///
    /// Two refreshes are driven concurrently because that is the ordering that
    /// hangs if the serialization lock or the tracked-set lock is ever held across
    /// the wrong await.
    #[tokio::test]
    async fn refresh_reads_through_to_a_tracked_server() {
        let (r, m) = fixture();
        m.track(&server());
        m.set_sessions("prod", 99, 42);
        let other = m.clone();
        tokio::join!(m.refresh(), other.refresh());
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
