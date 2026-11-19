//! The deploy tools' series, behind the `deploy` feature.
//!
//! The request metrics cannot see a deploy: it is a `tools/call` inside a
//! `POST` to the MCP endpoint, answered `200` whether it succeeded, failed
//! or was refused for want of a slot. So the deploy tools say how each call
//! went ([`imcp2_deploy::DeployObserver`]), and the upload route — whose
//! status codes fold several reasons into one — says why it refused.
//!
//! Every label value is one of a fixed few named in code (the variants of
//! [`imcp2_deploy::Refused`], [`imcp2_deploy::Ended`] and [`Upload`]):
//! nothing a client sends becomes a label, so the series are bounded by this
//! file, as the module docs of [`super`] require. They are totals for the
//! process, with no instance label: the endpoints of a process share one set
//! of slots and one upload store.

use std::time::Duration;

use imcp2_deploy::{DeployObserver, Ended, Refused};
use prometheus::{Histogram, HistogramOpts, IntCounterVec, IntGauge, Opts, Registry};

use crate::deploy::Deploys;

/// How long a deploy holds its slot, in seconds: from a bundle refused in
/// its first second to an asset sync of many minutes.
const DEPLOY_SECONDS: &[f64] =
    &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0, 1800.0, 3600.0];

/// How large an uploaded archive is, in bytes: 64 KiB to 256 MiB by fours.
const UPLOAD_BYTES: &[f64] =
    &[65_536.0, 262_144.0, 1_048_576.0, 4_194_304.0, 16_777_216.0, 67_108_864.0, 268_435_456.0];

/// What became of a `PUT` to the upload route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Upload {
    /// Received whole, and held for its deploy.
    Accepted,
    /// No ticket was sent, or one that is spent, expired or unknown.
    BadTicket,
    /// The archive is over the cap on one archive.
    TooLarge,
    /// The store had no room: the budget for every archive was spent.
    StoreFull,
    /// Another upload was arriving for the same session.
    SessionBusy,
    /// The body could not be read to its end, or was longer than declared.
    BodyError,
    /// The archive could not be written: the server's fault.
    StorageError,
}

impl Upload {
    const ALL: [Self; 7] = [
        Self::Accepted,
        Self::BadTicket,
        Self::TooLarge,
        Self::StoreFull,
        Self::SessionBusy,
        Self::BodyError,
        Self::StorageError,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::BadTicket => "bad_ticket",
            Self::TooLarge => "too_large",
            Self::StoreFull => "store_full",
            Self::SessionBusy => "session_busy",
            Self::BodyError => "body_error",
            Self::StorageError => "storage_error",
        }
    }
}

/// The deploy collectors. Cheap to clone: clones share the series.
#[derive(Clone)]
pub(crate) struct DeployMetrics {
    running: IntGauge,
    slots: IntGauge,
    deploys: IntCounterVec,
    refusals: IntCounterVec,
    duration: Histogram,
    uploads: IntCounterVec,
    upload_bytes: Histogram,
    store_bytes: IntGauge,
    store_capacity: IntGauge,
    uploads_held: IntGauge,
    uploads_arriving: IntGauge,
}

impl DeployMetrics {
    /// Register the collectors into `registry`, every series at zero: a
    /// rate over a counter that first appears with its first event misses
    /// that event.
    pub(crate) fn register(registry: &Registry) -> prometheus::Result<Self> {
        let gauge = |name: &str, help: &str| -> prometheus::Result<IntGauge> {
            let gauge = IntGauge::new(name, help)?;
            registry.register(Box::new(gauge.clone()))?;
            Ok(gauge)
        };
        let counters = |name: &str, help: &str, label: &str| -> prometheus::Result<IntCounterVec> {
            let counters = IntCounterVec::new(Opts::new(name, help), &[label])?;
            registry.register(Box::new(counters.clone()))?;
            Ok(counters)
        };
        let histogram =
            |name: &str, help: &str, buckets: &[f64]| -> prometheus::Result<Histogram> {
                let histogram =
                    Histogram::with_opts(HistogramOpts::new(name, help).buckets(buckets.to_vec()))?;
                registry.register(Box::new(histogram.clone()))?;
                Ok(histogram)
            };

        let this = Self {
            running: gauge(
                metric!("deploys_running"),
                "Deploys holding a slot now, across every endpoint of the process.",
            )?,
            slots: gauge(
                metric!("deploy_slots"),
                "How many deploys the process runs at once (the configured cap). \
                 imcp2_deploys_running against this is how full the server is.",
            )?,
            deploys: counters(
                metric!("deploys_total"),
                "Deploys that held a slot, by how they ended: succeeded, failed (a phase \
                 failed; canisters may exist), rejected (the request or bundle was refused \
                 before anything was created), interrupted (cancelled, client gone, or the \
                 server stopping).",
                "outcome",
            )?,
            refusals: counters(
                metric!("deploy_refusals_total"),
                "Deploys asked for and not begun, by reason: busy (every slot was held — a \
                 sustained rate means the cap is too low), session_busy (the session already \
                 had one running), stopping (the server was shutting down).",
                "reason",
            )?,
            duration: histogram(
                metric!("deploy_duration_seconds"),
                "How long a deploy held its slot, in seconds, whatever its outcome.",
                DEPLOY_SECONDS,
            )?,
            uploads: counters(
                metric!("deploy_uploads_total"),
                "Bundle uploads, by outcome: accepted, bad_ticket, too_large (over the cap on \
                 one archive), store_full (no room in the budget for all of them), \
                 session_busy (another was arriving for the session), body_error, \
                 storage_error (the server could not write it).",
                "outcome",
            )?,
            upload_bytes: histogram(
                metric!("deploy_upload_bytes"),
                "The size of each accepted bundle archive, in bytes.",
                UPLOAD_BYTES,
            )?,
            store_bytes: gauge(
                metric!("deploy_upload_store_bytes"),
                "Bytes counted against the upload store's budget: the reservation of each \
                 archive arriving, and the size of each waiting or being deployed.",
            )?,
            store_capacity: gauge(
                metric!("deploy_upload_store_capacity_bytes"),
                "The upload store's budget, in bytes.",
            )?,
            uploads_held: gauge(
                metric!("deploy_uploads_held"),
                "Uploaded bundles waiting for their deploy.",
            )?,
            uploads_arriving: gauge(
                metric!("deploy_uploads_arriving"),
                "Bundle uploads being received now.",
            )?,
        };
        for how in Ended::ALL {
            this.deploys.with_label_values(&[how.as_str()]).inc_by(0);
        }
        for why in Refused::ALL {
            this.refusals.with_label_values(&[why.as_str()]).inc_by(0);
        }
        for outcome in Upload::ALL {
            this.uploads.with_label_values(&[outcome.as_str()]).inc_by(0);
        }
        Ok(this)
    }

    /// Count one `PUT` to the upload route; `bytes` is an accepted archive's
    /// size.
    pub(crate) fn upload(&self, outcome: Upload, bytes: Option<usize>) {
        self.uploads.with_label_values(&[outcome.as_str()]).inc();
        if let Some(bytes) = bytes {
            self.upload_bytes.observe(bytes as f64);
        }
    }

    /// Republish the gauges from the deploy state: what is running and what
    /// the store holds are read, not counted.
    pub(crate) fn refresh(&self, deploys: &Deploys) {
        let (running, slots, held) = deploys.gauges();
        self.running.set(running as i64);
        self.slots.set(slots as i64);
        self.store_bytes.set(held.bytes as i64);
        self.store_capacity.set(held.max_bytes as i64);
        self.uploads_held.set(held.uploads as i64);
        self.uploads_arriving.set(held.receiving as i64);
    }
}

impl DeployObserver for DeployMetrics {
    fn refused(&self, why: Refused) {
        self.refusals.with_label_values(&[why.as_str()]).inc();
    }

    fn ended(&self, how: Ended, lasted: Duration) {
        self.deploys.with_label_values(&[how.as_str()]).inc();
        self.duration.observe(lasted.as_secs_f64());
    }
}
