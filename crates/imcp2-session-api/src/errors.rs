//! The error variants the canister returns.
//!
//! Returned variants never gain cases (see the crate docs): a condition that
//! does not fit an existing case travels as `Other(ErrorInfo)` with a new `code`,
//! which an older backend still decodes and can treat as a generic failure.

use std::fmt;

use candid::CandidType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Details of an `Other` error (`ErrorInfo`): a stable machine-readable `code`
/// and a human-readable `message`.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorInfo {
    pub code: String,
    pub message: String,
}

impl fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// The error of every method without a dedicated one (`CommonError`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Error)]
pub enum CommonError {
    /// The caller is not allowed to call this method: not in `Config.authorized`
    /// (data methods), or not a controller (`admin_*`).
    #[error("the caller is not authorized to call this method")]
    Unauthorized,
    /// The argument breaks a documented limit or format.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Any other failure, identified by its code.
    #[error("{0}")]
    Other(ErrorInfo),
}

/// Why `put_session` stored nothing (`PutSessionError`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Error)]
pub enum PutSessionError {
    /// The caller is not in `Config.authorized`.
    #[error("the caller is not authorized to store sessions")]
    Unauthorized,
    /// A record with this key exists under a different `op_id`. The same
    /// `op_id` is not an error: the put is idempotent and returns the record.
    #[error("a session with this key already exists under a different op_id")]
    AlreadyExists,
    /// The key is tombstoned: the session was purged and keys are never reused.
    #[error("the session with this key was deleted")]
    Deleted,
    /// `grant_expires_at` is not in the future.
    #[error("the grant has already expired")]
    GrantExpired,
    /// The store or the key's namespace is at its cap and no record could safely
    /// be evicted (see [`evictable`](crate::evictable)), or the namespace would
    /// be one too many.
    #[error("the session store is at capacity")]
    CapacityExceeded,
    /// A length, size or expiry bound is violated.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Any other failure, identified by its code.
    #[error("{0}")]
    Other(ErrorInfo),
}

/// Why `consume_code` did not hand out the record (`ConsumeCodeError`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Error)]
pub enum ConsumeCodeError {
    /// The caller is not in `Config.authorized`.
    #[error("the caller is not authorized to consume codes")]
    Unauthorized,
    /// The code was already exchanged under a different `exchange_id`. The same
    /// `exchange_id` is not an error: the consume is idempotent.
    #[error("the authorization code was already exchanged")]
    AlreadyConsumed,
    /// The code proof does not match the record's code lock. The record is left
    /// unconsumed.
    #[error("the authorization code proof does not match")]
    BadProof,
    /// No record has this key (never stored, abandoned, or expired).
    #[error("no session has this key")]
    NotFound,
    /// The key is tombstoned.
    #[error("the session with this key was deleted")]
    Deleted,
    /// The record is past its [`CONSUME_WINDOW`](crate::CONSUME_WINDOW).
    #[error("the authorization code has expired")]
    CodeExpired,
    /// A length or format bound is violated.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Any other failure, identified by its code.
    #[error("{0}")]
    Other(ErrorInfo),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_render_their_details() {
        let info = ErrorInfo { code: "rate_limited".into(), message: "slow down".into() };
        assert_eq!(CommonError::Other(info.clone()).to_string(), "rate_limited: slow down");
        assert_eq!(
            PutSessionError::InvalidArgument("key: expected 32 bytes".into()).to_string(),
            "invalid argument: key: expected 32 bytes"
        );
        assert_eq!(ConsumeCodeError::Other(info).to_string(), "rate_limited: slow down");
        assert_eq!(ConsumeCodeError::CodeExpired.to_string(), "the authorization code has expired");
        // Usable as a boxed error.
        let boxed: Box<dyn std::error::Error> = Box::new(CommonError::Unauthorized);
        assert!(boxed.to_string().contains("not authorized"));
    }
}
