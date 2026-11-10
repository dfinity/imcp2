//! The records and variants of the canister's interface, and a `Result` alias
//! per `*Result` variant.
//!
//! `blob` fields are `Vec<u8>` with `#[serde(with = "serde_bytes")]`, which both
//! Candid and serde encode as one byte string instead of element by element.
//! (`vec Key` and `opt Namespace` are plain `Vec<Vec<u8>>` / `Option<Vec<u8>>`:
//! the attribute does not reach inside a container, and the wire bytes are the
//! same either way.) Lengths are not enforced by the types; the canister checks
//! them against [`KEY_LEN`](crate::KEY_LEN) and friends and answers
//! `InvalidArgument`.

use std::fmt;

use candid::{CandidType, Nat, Principal};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::errors::{CommonError, ConsumeCodeError, PutSessionError};

/// A record key (`Key`), [`KEY_LEN`](crate::KEY_LEN) bytes:
/// `namespace ‖ SHA-256("imcp2/rk/v1\0" ‖ namespace ‖ sid_uuid)[..16]`. See
/// [`namespace_of`](crate::namespace_of).
pub type Key = Vec<u8>;
/// A namespace (`Namespace`), [`NAMESPACE_LEN`](crate::NAMESPACE_LEN) bytes.
pub type Namespace = Vec<u8>;
/// An operation id (`OpId`), [`ID_LEN`](crate::ID_LEN) bytes.
pub type OpId = Vec<u8>;
/// Unix seconds of IC time (`Seconds`).
pub type Seconds = u64;
/// A change-feed position (`Seq`): strictly increasing, assigned as
/// `max(head + 1, IC time in ns)`, so new positions keep increasing even after a
/// snapshot load rewinds `head`.
pub type Seq = u64;

/// `Debug` stand-in for a byte string that must not reach logs: only its length
/// is printed.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes redacted>", self.0)
    }
}

/// A granted session (`SessionRecord`).
///
/// `Debug` leaves `sealed` out: it is the session key `S` under the deployment
/// key, and a log line holding it would turn "key plus logs" into every logged
/// session.
#[derive(CandidType, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    #[serde(with = "serde_bytes")]
    pub key: Key,
    /// The record's change-feed position; 0 until its authorization code is
    /// consumed, which is when it enters the feed (abandoned sign-ins never do).
    pub seq: Seq,
    /// The `op_id` it was stored under; a repeated put with the same one is
    /// idempotent.
    #[serde(with = "serde_bytes")]
    pub op_id: OpId,
    pub created_at: Seconds,
    pub grant_expires_at: Seconds,
    /// The latest reported activity (see [`idle_deadline`](crate::idle_deadline));
    /// `created_at` until the first touch.
    pub last_active_at: Seconds,
    /// When the authorization code was consumed; `None` until then.
    pub consumed_at: Option<Seconds>,
    /// The XChaCha20-Poly1305 envelope the backends seal under their shared
    /// keyring, [`MIN_SEALED_LEN`](crate::MIN_SEALED_LEN) to
    /// [`MAX_SEALED_LEN`](crate::MAX_SEALED_LEN) bytes. The canister never sees
    /// inside it, except the key id at
    /// [`SEALED_KID_OFFSET`](crate::SEALED_KID_OFFSET).
    #[serde(with = "serde_bytes")]
    pub sealed: Vec<u8>,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("key", &self.key)
            .field("seq", &self.seq)
            .field("op_id", &self.op_id)
            .field("created_at", &self.created_at)
            .field("grant_expires_at", &self.grant_expires_at)
            .field("last_active_at", &self.last_active_at)
            .field("consumed_at", &self.consumed_at)
            .field("sealed", &Redacted(self.sealed.len()))
            .finish()
    }
}

/// What remains of a deleted session until `grant_expires_at +
/// TOMBSTONE_GRACE` (`Tombstone`). Records removed at grant expiry or abandoned
/// unconsumed leave none: no backend can still be using them.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    #[serde(with = "serde_bytes")]
    pub key: Key,
    pub seq: Seq,
    pub deleted_at: Seconds,
    pub grant_expires_at: Seconds,
    /// [`REASON_IDLE`](crate::REASON_IDLE),
    /// [`REASON_EVICTED`](crate::REASON_EVICTED) or
    /// [`REASON_ADMIN_PURGE`](crate::REASON_ADMIN_PURGE). Text rather than a
    /// variant so a new reason never breaks an older reader.
    pub reason: String,
}

/// One entry of the change feed (`Change`): the current state of a key.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Live(SessionRecord),
    Deleted(Tombstone),
}

/// The state of one key in a `get_sessions` reply (`Lookup`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Live(SessionRecord),
    Deleted(Tombstone),
    /// No record and no tombstone. Authoritative only from a replicated call.
    Absent,
}

/// The argument of `put_session` (`PutSessionArg`).
///
/// `Debug` leaves `sealed` out, as for [`SessionRecord`].
#[derive(CandidType, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct PutSessionArg {
    #[serde(with = "serde_bytes")]
    pub key: Key,
    /// Derived from the connect, so a redeem retried on any node puts the same
    /// record idempotently.
    #[serde(with = "serde_bytes")]
    pub op_id: OpId,
    /// In `(now, now + MAX_GRANT_ACCEPTED]`.
    pub grant_expires_at: Seconds,
    /// [`MIN_SEALED_LEN`](crate::MIN_SEALED_LEN) ..=
    /// [`MAX_SEALED_LEN`](crate::MAX_SEALED_LEN) bytes, the key id at
    /// [`SEALED_KID_OFFSET`](crate::SEALED_KID_OFFSET); any other length is
    /// refused with `InvalidArgument`.
    #[serde(with = "serde_bytes")]
    pub sealed: Vec<u8>,
    /// [`CODE_LOCK_LEN`](crate::CODE_LOCK_LEN) bytes, `SHA-256(code_proof)[..16]`.
    #[serde(with = "serde_bytes")]
    pub code_lock: Vec<u8>,
}

impl fmt::Debug for PutSessionArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PutSessionArg")
            .field("key", &self.key)
            .field("op_id", &self.op_id)
            .field("grant_expires_at", &self.grant_expires_at)
            .field("sealed", &Redacted(self.sealed.len()))
            .field("code_lock", &self.code_lock)
            .finish()
    }
}

/// The argument of `consume_code` (`ConsumeCodeArg`).
///
/// `Debug` leaves `code_proof` out: it is what lets a caller consume the code.
#[derive(CandidType, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ConsumeCodeArg {
    #[serde(with = "serde_bytes")]
    pub key: Key,
    /// Derived from the code and its PKCE verifier, so a token request retried on
    /// any node is the same exchange and gets the same answer.
    #[serde(with = "serde_bytes")]
    pub exchange_id: OpId,
    /// [`CODE_PROOF_LEN`](crate::CODE_PROOF_LEN) bytes, checked against the
    /// record's code lock.
    #[serde(with = "serde_bytes")]
    pub code_proof: Vec<u8>,
}

impl fmt::Debug for ConsumeCodeArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsumeCodeArg")
            .field("key", &self.key)
            .field("exchange_id", &self.exchange_id)
            .field("code_proof", &Redacted(self.code_proof.len()))
            .finish()
    }
}

/// One reported activity (`Touch`). The canister clamps `last_active_at` to its
/// own `now` and only ever raises a record's value.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Touch {
    #[serde(with = "serde_bytes")]
    pub key: Key,
    pub last_active_at: Seconds,
}

/// The `Ok` of `touch_sessions`.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct TouchOk {
    /// How many records were updated.
    pub updated: u32,
    /// Keys with no live record to update (deleted, expired or never stored);
    /// the backend stops touching them.
    pub unknown: Vec<Key>,
}

/// The `Ok` of `get_sessions`.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct GetSessionsOk {
    /// One entry per requested key, in request order.
    pub items: Vec<Lookup>,
    pub epoch: u64,
    pub now_ns: u64,
}

/// The argument of `list_changes` (`ListChangesArg`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ListChangesArg {
    /// Return changes with `seq > after`.
    pub after: Seq,
    /// Page size; [`DEFAULT_PAGE_LIMIT`](crate::DEFAULT_PAGE_LIMIT) when `None`,
    /// clamped to `1 ..=` [`MAX_PAGE_LIMIT`](crate::MAX_PAGE_LIMIT). A limit of
    /// 0 counts as 1, so that a page with changes left always ends at a change
    /// and its `next_after` makes progress.
    pub limit: Option<u32>,
}

/// A page of the compacted change feed (`ChangesPage`): the current state of
/// each key that changed after `after`, in `seq` order.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ChangesPage {
    /// `seq > after`, ascending.
    pub changes: Vec<Change>,
    /// Nothing exists after `next_after`.
    pub complete: bool,
    /// Where to continue: `complete ? max(after, head) : seq of the last change`.
    pub next_after: Seq,
    /// The highest `seq` ever assigned; never lowered.
    pub head: Seq,
    /// Bumped when the canister history shows a snapshot load; a backend
    /// seeing a new epoch discards its mirror and resyncs.
    pub epoch: u64,
    pub now_ns: u64,
    pub idle_timeout_secs: u64,
    /// The floor under every `last_active_at` (see
    /// [`idle_deadline`](crate::idle_deadline)).
    pub idle_floor_at: Seconds,
    /// Bumped whenever the key checks change; a backend then refetches them.
    pub key_checks_version: u64,
}

/// A published key check (`KeyCheck`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyCheck {
    pub kid: u8,
    /// [`KEY_CHECK_LEN`](crate::KEY_CHECK_LEN) bytes, `HKDF(K[kid], info =
    /// KEY_CHECK_INFO)[..16]`. A PRF output, safe to publish.
    #[serde(with = "serde_bytes")]
    pub check: Vec<u8>,
}

/// The key checks and retired key ids (`KeyChecks`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyChecks {
    pub version: u64,
    pub checks: Vec<KeyCheck>,
    /// Retired key ids, one byte each, ascending. Values sealed under them are
    /// invalid everywhere.
    #[serde(with = "serde_bytes")]
    pub retired: Vec<u8>,
    pub now_ns: u64,
}

/// Which sessions `admin_purge_sessions` removes (`PurgeFilter`): those matching
/// every field that is set. The default filter matches everything.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeFilter {
    pub namespace: Option<Namespace>,
    /// Matched against the sealed envelope's key id (its byte at
    /// [`SEALED_KID_OFFSET`](crate::SEALED_KID_OFFSET)), to purge everything
    /// sealed under a leaked key.
    pub kid: Option<u8>,
    /// The node identity that stored the session, to purge what a compromised
    /// node created.
    pub opened_by: Option<Principal>,
    pub created_from: Option<Seconds>,
    pub created_to: Option<Seconds>,
}

/// The progress of an admin purge (`PurgeJob`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PurgeJob {
    pub filter: PurgeFilter,
    pub started_at: Seconds,
    pub scanned: u64,
    pub purged: u64,
    pub done: bool,
}

/// Per-namespace counts in [`Status`] (`NamespaceCount`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NamespaceCount {
    #[serde(with = "serde_bytes")]
    pub namespace: Namespace,
    pub sessions: u64,
    pub tombstones: u64,
}

/// Per-caller statistics in [`Status`] (`CallerStats`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CallerStats {
    pub caller: Principal,
    /// Whether the caller is currently in `Config.authorized`.
    pub authorized: bool,
    pub opened: u64,
    pub consumed: u64,
    pub last_seen_at: Seconds,
}

/// Lifetime event counters in [`Status`] (`Counters`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub opened: u64,
    pub consumed: u64,
    pub abandoned: u64,
    pub expired: u64,
    pub idle_purged: u64,
    pub evicted: u64,
    pub admin_purged: u64,
    pub tombstones_collected: u64,
    pub restores_detected: u64,
}

/// The canister's state for operators and the backends' gauges (`Status`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub version: String,
    pub git_commit: String,
    pub config: Config,
    pub sessions: u64,
    pub tombstones: u64,
    pub per_namespace: Vec<NamespaceCount>,
    pub head: Seq,
    pub epoch: u64,
    pub idle_floor_at: Seconds,
    pub key_checks: KeyChecks,
    pub callers: Vec<CallerStats>,
    pub purge_job: Option<PurgeJob>,
    pub counters: Counters,
    pub last_purge_at: Seconds,
    /// Age of the oldest record overdue for removal; growth means the purge
    /// timer is falling behind.
    pub purge_backlog_secs: u64,
    pub cycle_balance: Nat,
    pub stable_memory_bytes: u64,
    pub now_ns: u64,
}

/// The reply of `put_session` (`PutSessionResult`).
pub type PutSessionResult = Result<SessionRecord, PutSessionError>;
/// The reply of `consume_code` (`ConsumeCodeResult`).
pub type ConsumeCodeResult = Result<SessionRecord, ConsumeCodeError>;
/// The reply of `touch_sessions` (`TouchResult`).
pub type TouchResult = Result<TouchOk, CommonError>;
/// The reply of `get_sessions` (`GetSessionsResult`).
pub type GetSessionsResult = Result<GetSessionsOk, CommonError>;
/// The reply of `list_changes` (`ListChangesResult`).
pub type ListChangesResult = Result<ChangesPage, CommonError>;
/// The reply of `get_key_checks`, `admin_set_key_check` and `admin_retire_kid`
/// (`KeyChecksResult`).
pub type KeyChecksResult = Result<KeyChecks, CommonError>;
/// The reply of `admin_purge_sessions` (`PurgeJobResult`).
pub type PurgeJobResult = Result<PurgeJob, CommonError>;
/// The reply of `get_status` (`StatusResult`).
pub type StatusResult = Result<Status, CommonError>;
/// The reply of `admin_update_config` (`ConfigResult`).
pub type ConfigResult = Result<Config, CommonError>;
