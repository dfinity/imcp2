//! The canister's method names, one constant per method of the `.did` service.
//!
//! Methods are only ever added. The tests check this list against the service in
//! [`CANDID`](crate::CANDID), in both directions.

/// `(PutSessionArg) -> (PutSessionResult)`, update, authorized backends. Stores a
/// new, unconsumed record at redeem; idempotent per `op_id`.
pub const PUT_SESSION: &str = "put_session";

/// `(ConsumeCodeArg) -> (ConsumeCodeResult)`, update, authorized backends.
/// Checks the code proof, marks the record consumed (it enters the change feed)
/// and returns it; idempotent per `exchange_id`.
pub const CONSUME_CODE: &str = "consume_code";

/// `(vec Touch) -> (TouchResult)`, update, authorized backends. At most
/// [`MAX_TOUCH_BATCH`](crate::MAX_TOUCH_BATCH) touches.
pub const TOUCH_SESSIONS: &str = "touch_sessions";

/// `(vec Key) -> (GetSessionsResult)`, query, authorized backends. At most
/// [`MAX_GET_KEYS`](crate::MAX_GET_KEYS) keys. Also called as an update when the
/// answer must be authoritative.
pub const GET_SESSIONS: &str = "get_sessions";

/// `(ListChangesArg) -> (ListChangesResult)`, query, authorized backends. Also
/// called as an update when the answer must be authoritative.
pub const LIST_CHANGES: &str = "list_changes";

/// `() -> (KeyChecksResult)`, query, authorized backends and controllers.
pub const GET_KEY_CHECKS: &str = "get_key_checks";

/// `() -> (StatusResult)`, query, authorized backends and controllers.
pub const GET_STATUS: &str = "get_status";

/// `(ConfigPatch) -> (ConfigResult)`, update, controllers. Also re-arms the
/// purge timer, even for an empty patch, and schedules an immediate timer run,
/// which probes the canister history for a snapshot load.
pub const ADMIN_UPDATE_CONFIG: &str = "admin_update_config";

/// `(KeyCheck, bool) -> (KeyChecksResult)`, update, controllers. The `bool`
/// allows replacing an existing, different check for the kid.
pub const ADMIN_SET_KEY_CHECK: &str = "admin_set_key_check";

/// `(nat8) -> (KeyChecksResult)`, update, controllers.
pub const ADMIN_RETIRE_KID: &str = "admin_retire_kid";

/// `(PurgeFilter) -> (PurgeJobResult)`, update, controllers. Starts a resumable
/// purge the timer works through.
pub const ADMIN_PURGE_SESSIONS: &str = "admin_purge_sessions";

/// Every method, in `.did` order: for allow-lists such as the canister's
/// `inspect_message` filter.
pub const ALL: [&str; 11] = [
    PUT_SESSION,
    CONSUME_CODE,
    TOUCH_SESSIONS,
    GET_SESSIONS,
    LIST_CHANGES,
    GET_KEY_CHECKS,
    GET_STATUS,
    ADMIN_UPDATE_CONFIG,
    ADMIN_SET_KEY_CHECK,
    ADMIN_RETIRE_KID,
    ADMIN_PURGE_SESSIONS,
];
