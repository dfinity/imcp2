//! The Candid contract of the imcp2 session canister: the store through which
//! interchangeable imcp2 backends share their granted OAuth / Internet Identity
//! sessions.
//!
//! This crate is **types only**, like ic-bn-lib's custom-domains API crate: the
//! canister (`imcp2-session-canister`) and the backends' client (imcp2's
//! `src/shared`) both depend on it, and neither depends on the other. The
//! canister never links ic-agent, and the backends never link ic-cdk.
//!
//! It holds:
//!   * [`CANDID`] — the hand-written `imcp2_session.did`, the contract itself.
//!     Every Rust type here is checked against it (field and variant names, and
//!     structure), and so are the method names in [`method`].
//!   * the Rust side of every `.did` type ([`SessionRecord`], [`ChangesPage`],
//!     [`PutSessionError`], ...), with a `Result` alias per `*Result` variant
//!     (Rust's `Result` encodes as Candid `variant { Ok; Err }`);
//!   * the lengths, timings, limits and defaults both sides must agree on
//!     ([`KEY_LEN`], [`CONSUME_WINDOW`], [`MAX_PAGE_LIMIT`], ...);
//!   * the rules both sides evaluate — when a session counts as idle, when
//!     touching it is worth an update call, when evicting it is safe
//!     ([`idle_deadline`], [`touches_effective`], [`evictable`], ...) — and
//!     [`Config::apply`], the one validation of the canister configuration.
//!
//! **Time.** Every `Seconds` value is Unix seconds of IC time (the canister's
//! clock), unless its name ends in `_ns`. Backends compare them against their own
//! clocks only with [`CLOCK_SKEW`] of tolerance.
//!
//! **Evolution rules**, pinned by this crate's wire tests:
//!   * records only gain `opt` fields — an older payload without them still
//!     decodes, and Candid skips record fields a reader does not know;
//!   * variants a method **returns** never gain cases: a reader rejects a case it
//!     does not know, so a new case would fail the whole reply on every older
//!     backend. New conditions travel in the existing `Other(ErrorInfo)` cases;
//!   * methods are only ever added, never changed or removed.

mod config;
mod constants;
mod errors;
mod rules;
mod types;

pub mod method;

#[cfg(test)]
mod tests;

pub use config::{Config, ConfigPatch, InstallArg};
pub use constants::*;
pub use errors::{CommonError, ConsumeCodeError, ErrorInfo, PutSessionError};
pub use rules::{
    evictable, idle_deadline, idle_purge_cutoff, idle_purge_enabled, namespace_of,
    reporting_matters, touch_granularity, touches_effective,
};
pub use types::*;

/// The canister's Candid interface (`imcp2_session.did`), verbatim.
///
/// It is the contract: the canister checks its exported interface against it,
/// and this crate's tests check every Rust type and method name against it.
pub const CANDID: &str = include_str!("../imcp2_session.did");
