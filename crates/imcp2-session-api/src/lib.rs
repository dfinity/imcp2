//! The Candid contract of the imcp2 session canister: the store through which
//! interchangeable imcp2 backends share their granted OAuth / Internet Identity
//! sessions.
//!
//! This crate is **types only**: the canister (`imcp2-session-canister`) and
//! the backends' client (imcp2's `src/shared`) both depend on it, and neither
//! depends on the other. The canister never links ic-agent, and the backends
//! never link ic-cdk.
//!
//! It holds:
//!   * [`CANDID`] — the hand-written `imcp2_session.did`, the contract itself.
//!     Every Rust type here is checked against it (field and variant names, and
//!     structure); the canister checks the interface it exports against it.
//!   * the Rust side of every `.did` type ([`SessionRecord`], [`ChangesPage`],
//!     [`PutSessionError`], ...), with a `Result` alias per `*Result` variant
//!     (Rust's `Result` encodes as Candid `variant { Ok; Err }`);
//!   * the lengths, timings, limits and defaults both sides must agree on
//!     ([`KEY_LEN`], [`CONSUME_WINDOW`], [`MAX_PAGE_LIMIT`], ...);
//!   * the rules both sides evaluate — when a session counts as idle, when a
//!     backend should report its activity, when evicting it is safe
//!     ([`idle_deadline`], [`should_report_session_activity`], [`evictable`],
//!     ...) — and [`Config::apply`], the one validation of the canister
//!     configuration.
//!
//! **Time.** Every `Seconds` value is Unix seconds of IC time (the canister's
//! clock), unless its name ends in `_ns`. Backends compare them against their own
//! clocks only with [`CLOCK_SKEW`] of tolerance.
//!
//! **Interface conventions.** Every method takes one record and returns
//! `variant { Ok : …; Err : … }`, so that arguments and replies can grow. A
//! method whose answer a backend acts on is an update (agreed by consensus);
//! where a cheap single-replica answer is useful as a hint, it has a separate
//! `*_non_replicated` query twin, so that no caller gets a hint by mistake. A
//! backend may only use a hint to add a record it can verify (it opens under
//! the keyring and is consumed), never to drop one, and never for a key whose
//! deletion it has already read from an update: a stale replica can then delay
//! a deletion until the backend's next replicated read, but never undo one.
//!
//! **Evolution rules**, pinned by this crate's wire tests:
//!   * records only gain `opt` fields — an older payload without them still
//!     decodes, and Candid skips record fields a reader does not know;
//!   * errors are records whose case sits in an `opt` ([`PutSessionError`],
//!     ...): a newer canister may add a case, which an older reader decodes as
//!     `err_case = None`, keeping the stable [`error_code`] and the message;
//!   * every other variant a method returns never gains cases: a reader
//!     rejects a case it does not know, and with it the whole reply;
//!   * methods are only ever added, never changed or removed.

mod config;
mod constants;
mod errors;
mod rules;
mod types;

#[cfg(test)]
mod tests;

pub use config::{Config, ConfigPatch, InstallArg};
pub use constants::*;
pub use errors::{
    error_code, CommonError, CommonErrorCase, ConsumeCodeError, ConsumeCodeErrorCase,
    PutSessionError, PutSessionErrorCase,
};
pub use rules::{
    evictable, eviction_idle, idle_deadline, idle_purge_cutoff, idle_purge_enabled, namespace_of,
    should_report_session_activity, should_report_session_activity_promptly, touch_granularity,
    touches_effective,
};
pub use types::*;

/// The canister's Candid interface (`imcp2_session.did`), verbatim.
///
/// It is the contract: the canister checks the interface it exports against it,
/// and this crate's tests check every Rust type against it.
pub const CANDID: &str = include_str!("../imcp2_session.did");
