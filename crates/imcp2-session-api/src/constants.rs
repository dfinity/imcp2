//! Lengths, timings, limits and defaults the canister and the backends share.
//!
//! Times are seconds. The relations between them (a code is always consumable
//! while a backend still honours it, a session cannot be purged as idle while
//! its activity may still be in flight, ...) are asserted at compile time in
//! `rules.rs`, next to the functions that depend on them.

// --- Lengths (bytes) --------------------------------------------------------

/// Length of a record [`Key`](crate::Key):
/// `namespace ‖ SHA-256("imcp2/rk/v1\0" ‖ namespace ‖ sid_uuid)[..16]`.
///
/// The key is derived without any secret, so a record keeps its key across a
/// rotation of the deployment keyring; the session id it hides travels sealed.
pub const KEY_LEN: usize = 32;

/// Length of a namespace, the leading bytes of every key:
/// `SHA-256("imcp2/ns/v1\0" ‖ ii_canister ‖ "\0" ‖ issuer)[..16]`.
///
/// One namespace per (II instance, MCP issuer) pair, so a prod and a beta server
/// sharing one canister never see each other's sessions. Capacity caps and
/// eviction are per namespace.
pub const NAMESPACE_LEN: usize = 16;

/// Length of an operation id: `op_id` (makes a redeem idempotent across nodes)
/// and `exchange_id` (makes a code exchange idempotent across nodes).
pub const ID_LEN: usize = 16;

/// Length of a published key check, `HKDF(K[kid], info = KEY_CHECK_INFO)[..16]`.
pub const KEY_CHECK_LEN: usize = 16;

/// Length of a code proof, the secret a backend presents to `consume_code`. It
/// is derived from the session key `S`, so the deployment key alone cannot
/// produce it.
pub const CODE_PROOF_LEN: usize = 16;

/// Length of a code lock, `SHA-256(code_proof)[..16]`, stored at `put_session`
/// so the canister can check a proof it never saw.
pub const CODE_LOCK_LEN: usize = 16;

/// Upper bound on a sealed session envelope. Bounds a record's encoded size, and
/// with it [`MAX_PAGE_LIMIT`] and [`MAX_GET_KEYS`] under the 2 MiB reply limit.
pub const MAX_SEALED_LEN: usize = 1024;

// --- Sign-in timings (seconds) ------------------------------------------------

/// How long a backend accepts an authorization code after issuing it (OAuth
/// recommends at most 10 minutes; a client exchanges it within seconds).
pub const CODE_TTL: u64 = 120;

/// Tolerated difference between a backend's clock and IC time, applied wherever
/// one side checks a time the other side set.
pub const CLOCK_SKEW: u64 = 60;

/// `consume_code` is refused after `created_at + CONSUME_WINDOW` (canister
/// clock). It must outlast any code a backend still accepts: the code is issued
/// up to 15 s after `put_session` (its retries), lives [`CODE_TTL`] by the
/// backend's clock, and that clock may lag IC time by [`CLOCK_SKEW`].
pub const CONSUME_WINDOW: u64 = 300;

/// An unconsumed record is removed (silently: it never entered the change feed,
/// and no token can exist for it) at `created_at + ABANDON_AFTER`. Past
/// [`CONSUME_WINDOW`], so a consume still inside its window always finds its
/// record and gets a precise answer instead of `NotFound`.
pub const ABANDON_AFTER: u64 = 360;

// --- Grants (seconds) ---------------------------------------------------------

/// Internet Identity's cap on a session grant (30 days). No grant, and so no
/// record, lives longer, which is why the default idle timeout never fires (see
/// [`touches_effective`](crate::touches_effective)).
pub const MAX_GRANT: u64 = 2_592_000;

/// The longest grant `put_session` accepts, `now < grant_expires_at <= now +
/// MAX_GRANT_ACCEPTED` (31 days): a day above [`MAX_GRANT`], so a grant II issued
/// is never refused over clock skew, while a garbage expiry still is.
pub const MAX_GRANT_ACCEPTED: u64 = 2_678_400;

/// A tombstone is kept until `grant_expires_at + TOMBSTONE_GRACE`. A token dies
/// on every backend at its grant expiry (± [`CLOCK_SKEW`]), so past that point
/// nothing can still be honouring the deleted session and the tombstone has
/// nothing left to tell anyone.
pub const TOMBSTONE_GRACE: u64 = 600;

// --- Idle purge and touches (seconds) ------------------------------------------

/// Slack added to every idle deadline on top of the touch granularity: room for
/// a touch batch to be flushed, retried and land, and for clock skew.
pub const IDLE_SLACK: u64 = 300;

/// How often a backend flushes its pending touches (`touch_sessions`).
pub const TOUCH_FLUSH_INTERVAL: u64 = 60;

/// The minimum idleness, beyond everything that may still be in flight, before a
/// session can be evicted to make room (see [`evictable`](crate::evictable)).
pub const MIN_EVICT_IDLE: u64 = 3_600;

/// The default idle timeout: 30 days, which equals [`MAX_GRANT`], so by default
/// grant expiry always comes first and backends send no touches at all.
pub const DEFAULT_IDLE_TIMEOUT: u64 = 2_592_000;

/// The shortest configurable idle timeout (1 hour). Above every sign-in timing,
/// so a sign-in's record is consumed or abandoned long before anything could
/// call it idle, and above the granularity and slack it implies, so the
/// configured timeout and not the bookkeeping margins dominates the deadline.
pub const MIN_IDLE_TIMEOUT: u64 = 3_600;

/// The longest configurable idle timeout (365 days).
pub const MAX_IDLE_TIMEOUT: u64 = 31_536_000;

/// The finest [`touch_granularity`](crate::touch_granularity) (5 minutes).
pub const MIN_TOUCH_GRANULARITY: u64 = 300;

/// The coarsest [`touch_granularity`](crate::touch_granularity) (6 hours).
pub const MAX_TOUCH_GRANULARITY: u64 = 21_600;

// --- Per-call limits ----------------------------------------------------------

/// The most keys one `get_sessions` call may look up.
pub const MAX_GET_KEYS: usize = 100;

/// The page size `list_changes` uses when `limit` is null.
pub const DEFAULT_PAGE_LIMIT: u32 = 500;

/// The largest page `list_changes` returns; a larger `limit` is clamped. Sized so
/// a page of maximum-size records stays under the 2 MiB reply limit.
pub const MAX_PAGE_LIMIT: u32 = 1_000;

/// The most touches one `touch_sessions` call may carry.
pub const MAX_TOUCH_BATCH: usize = 2_000;

// --- Purge timer ----------------------------------------------------------------

/// Default seconds between purge timer firings.
pub const DEFAULT_PURGE_INTERVAL_SECS: u32 = 60;
/// Shortest configurable purge interval.
pub const MIN_PURGE_INTERVAL_SECS: u32 = 10;
/// Longest configurable purge interval. Short next to [`ABANDON_AFTER`] and the
/// idle slack, so removals never lag far behind their deadlines.
pub const MAX_PURGE_INTERVAL_SECS: u32 = 3_600;

/// Default number of removals per purge firing (bounds its instruction count).
pub const DEFAULT_PURGE_BATCH: u32 = 2_000;
/// Smallest configurable purge batch.
pub const MIN_PURGE_BATCH: u32 = 100;
/// Largest configurable purge batch, bounding the instructions one firing may
/// spend.
pub const MAX_PURGE_BATCH: u32 = 20_000;

// --- Capacity -------------------------------------------------------------------

/// The most principals `Config.authorized` may hold: one identity per backend
/// node, so a compromised node can be removed (and its sessions purged by
/// `opened_by`) on its own.
pub const MAX_AUTHORIZED: usize = 32;

/// Default cap on live records across all namespaces. A memory tripwire (about
/// 450 B per record with its indexes), not a planned operating point.
pub const DEFAULT_MAX_SESSIONS: u64 = 2_000_000;

/// Default cap on live records in one namespace, so one server cannot take the
/// whole store.
pub const DEFAULT_MAX_SESSIONS_PER_NAMESPACE: u64 = 1_000_000;

/// The most namespaces the canister holds; `put_session` refuses a new one past
/// this. Bounds the per-namespace work of the purge timer and of `get_status`.
pub const MAX_NAMESPACES: usize = 64;

/// How many of a namespace's least recently active records `put_session`
/// examines for an [`evictable`](crate::evictable) one when the namespace is at
/// its cap, bounding the cost of a put.
pub const EVICTION_SCAN: usize = 16;

// --- Key checks -------------------------------------------------------------------

/// HKDF `info` of a key check: `check = HKDF-SHA256(ikm = K[kid], info =
/// KEY_CHECK_INFO)[..KEY_CHECK_LEN]`. Published per kid so every backend can tell
/// whether its key for a kid is the fleet's before sealing anything with it.
pub const KEY_CHECK_INFO: &[u8] = b"imcp2/keycheck/v1";

// --- Tombstone reasons --------------------------------------------------------------

/// `Tombstone.reason` of a session purged by the idle timeout.
pub const REASON_IDLE: &str = "idle";
/// `Tombstone.reason` of a session evicted to make room for a new one.
pub const REASON_EVICTED: &str = "evicted";
/// `Tombstone.reason` of a session removed by `admin_purge_sessions`.
pub const REASON_ADMIN_PURGE: &str = "admin_purge";
