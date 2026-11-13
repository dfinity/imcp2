//! The errors the canister returns.
//!
//! Each error is a record, `{ err_code; err_case : opt <Case>; err_str }`,
//! rather than a variant. A variant a method returns cannot gain cases: an
//! older reader rejects a case it does not know, and with it the whole reply.
//! Inside an `opt` it can, because Candid decodes a value an older reader does
//! not understand there as `null`. So a newer canister can add a case: newer
//! backends match on it, older ones see `err_case = None` and still have the
//! stable numeric [`err_code`](error_code) and the message.

use candid::CandidType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The `err_code` of every error case. One space shared by every error type,
/// so a code means the same thing whichever method returned it; codes are never
/// reused.
pub mod error_code {
    /// The caller may not call this method: not in `Config.authorized` (data
    /// methods), or not a controller (`admin_*`).
    pub const UNAUTHORIZED: u64 = 1;
    /// The argument breaks a documented limit or format; `err_str` says which.
    pub const INVALID_ARGUMENT: u64 = 2;
    /// `put_session`: a record with this key exists under a different `op_id`.
    pub const ALREADY_EXISTS: u64 = 10;
    /// The key is tombstoned: the session was purged, and keys are never reused.
    pub const DELETED: u64 = 11;
    /// `put_session`: `grant_expires_at` is not in the future.
    pub const GRANT_EXPIRED: u64 = 12;
    /// `put_session`: the store or the namespace is at its cap and nothing could
    /// safely be evicted, or the namespace would be one too many.
    pub const CAPACITY_EXCEEDED: u64 = 13;
    /// `consume_code`: the code was already exchanged under a different
    /// `exchange_id`.
    pub const ALREADY_CONSUMED: u64 = 20;
    /// `consume_code`: the code proof does not match the record's code lock.
    pub const BAD_PROOF: u64 = 21;
    /// `consume_code`: no record has this key (never stored, abandoned, or
    /// expired).
    pub const NOT_FOUND: u64 = 22;
    /// `consume_code`: the record is past its consume window.
    pub const CODE_EXPIRED: u64 = 23;
    /// `admin_purge_sessions`: another purge job is still running.
    pub const PURGE_IN_PROGRESS: u64 = 30;
}

/// Declares one error type: its case variant (with each case's code and default
/// message), the record, and its constructors.
macro_rules! error_type {
    (
        $(#[$error_doc:meta])*
        $error:ident,
        $(#[$case_doc:meta])*
        $case:ident {
            $( $(#[$variant_doc:meta])* $variant:ident = $code:ident, $message:literal; )+
        }
    ) => {
        $(#[$case_doc])*
        #[derive(CandidType, Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $case {
            $( $(#[$variant_doc])* $variant, )+
        }

        impl $case {
            /// This case's [`error_code`].
            pub const fn code(self) -> u64 {
                match self {
                    $( $case::$variant => error_code::$code, )+
                }
            }

            /// What this case means, for an error that carries no detail.
            pub const fn message(self) -> &'static str {
                match self {
                    $( $case::$variant => $message, )+
                }
            }
        }

        $(#[$error_doc])*
        #[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Error)]
        #[error("{err_str}")]
        pub struct $error {
            /// The case's [`error_code`], which an older reader still has when it
            /// does not know the case.
            pub err_code: u64,
            /// The case, or `None` when this reader does not know it (a newer
            /// canister added it).
            pub err_case: Option<$case>,
            /// A human-readable description, with any detail.
            pub err_str: String,
        }

        impl $error {
            /// The error of `case`, described by `err_str`.
            pub fn new(case: $case, err_str: impl Into<String>) -> Self {
                Self { err_code: case.code(), err_case: Some(case), err_str: err_str.into() }
            }

            /// The error of `case`, with its default description.
            pub fn of(case: $case) -> Self {
                Self::new(case, case.message())
            }

            /// An `InvalidArgument` error, with `detail` saying which bound or
            /// format the argument breaks.
            pub fn invalid_argument(detail: impl Into<String>) -> Self {
                Self::new($case::InvalidArgument, format!("invalid argument: {}", detail.into()))
            }

            /// Whether this is the error of `case`.
            pub fn is(&self, case: $case) -> bool {
                self.err_case == Some(case)
            }
        }

        impl From<$case> for $error {
            fn from(case: $case) -> Self {
                Self::of(case)
            }
        }
    };
}

error_type! {
    /// The error of every method without a dedicated one (`CommonError`).
    CommonError,
    /// The cases of a [`CommonError`] (`CommonErrorCase`).
    CommonErrorCase {
        /// See [`error_code::UNAUTHORIZED`].
        Unauthorized = UNAUTHORIZED, "the caller is not authorized to call this method";
        /// See [`error_code::INVALID_ARGUMENT`].
        InvalidArgument = INVALID_ARGUMENT, "invalid argument";
        /// See [`error_code::PURGE_IN_PROGRESS`].
        PurgeInProgress = PURGE_IN_PROGRESS, "a purge job is still running";
    }
}

error_type! {
    /// Why `put_session` stored nothing (`PutSessionError`).
    PutSessionError,
    /// The cases of a [`PutSessionError`] (`PutSessionErrorCase`).
    PutSessionErrorCase {
        /// See [`error_code::UNAUTHORIZED`].
        Unauthorized = UNAUTHORIZED, "the caller is not authorized to store sessions";
        /// See [`error_code::INVALID_ARGUMENT`].
        InvalidArgument = INVALID_ARGUMENT, "invalid argument";
        /// See [`error_code::ALREADY_EXISTS`]. The same `op_id` is not an error:
        /// the put is idempotent and returns the record.
        AlreadyExists = ALREADY_EXISTS, "a session with this key already exists under a different op_id";
        /// See [`error_code::DELETED`].
        Deleted = DELETED, "the session with this key was deleted";
        /// See [`error_code::GRANT_EXPIRED`].
        GrantExpired = GRANT_EXPIRED, "the grant has already expired";
        /// See [`error_code::CAPACITY_EXCEEDED`] and
        /// [`evictable`](crate::evictable).
        CapacityExceeded = CAPACITY_EXCEEDED, "the session store is at capacity";
    }
}

error_type! {
    /// Why `consume_code` did not hand out the record (`ConsumeCodeError`).
    ConsumeCodeError,
    /// The cases of a [`ConsumeCodeError`] (`ConsumeCodeErrorCase`).
    ConsumeCodeErrorCase {
        /// See [`error_code::UNAUTHORIZED`].
        Unauthorized = UNAUTHORIZED, "the caller is not authorized to consume codes";
        /// See [`error_code::INVALID_ARGUMENT`].
        InvalidArgument = INVALID_ARGUMENT, "invalid argument";
        /// See [`error_code::ALREADY_CONSUMED`]. The same `exchange_id` is not an
        /// error: the consume is idempotent.
        AlreadyConsumed = ALREADY_CONSUMED, "the authorization code was already exchanged";
        /// See [`error_code::BAD_PROOF`]. The record is left unconsumed.
        BadProof = BAD_PROOF, "the authorization code proof does not match";
        /// See [`error_code::NOT_FOUND`].
        NotFound = NOT_FOUND, "no session has this key";
        /// See [`error_code::DELETED`].
        Deleted = DELETED, "the session with this key was deleted";
        /// See [`error_code::CODE_EXPIRED`] and
        /// [`CONSUME_WINDOW`](crate::CONSUME_WINDOW).
        CodeExpired = CODE_EXPIRED, "the authorization code has expired";
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn errors_carry_their_code_case_and_description() {
        let e = PutSessionError::of(PutSessionErrorCase::CapacityExceeded);
        assert_eq!(e.err_code, error_code::CAPACITY_EXCEEDED);
        assert!(e.is(PutSessionErrorCase::CapacityExceeded));
        assert_eq!(e.to_string(), "the session store is at capacity");
        let e = ConsumeCodeError::invalid_argument("key: expected 32 bytes");
        assert_eq!(e.err_code, error_code::INVALID_ARGUMENT);
        assert_eq!(e.to_string(), "invalid argument: key: expected 32 bytes");
        assert_eq!(CommonError::from(CommonErrorCase::PurgeInProgress).err_code, 30);
        // Usable as a boxed error.
        let boxed: Box<dyn std::error::Error> =
            Box::new(CommonError::of(CommonErrorCase::Unauthorized));
        assert!(boxed.to_string().contains("not authorized"));
    }

    // A code means one thing whichever error type carries it.
    #[test]
    fn codes_are_shared_across_error_types() {
        let mut meaning: HashMap<u64, &str> = HashMap::new();
        let mut check = |code: u64, name: &'static str| {
            let seen = *meaning.entry(code).or_insert(name);
            assert_eq!(seen, name, "code {code} means both {seen} and {name}");
        };
        for case in [
            CommonErrorCase::Unauthorized,
            CommonErrorCase::InvalidArgument,
            CommonErrorCase::PurgeInProgress,
        ] {
            check(case.code(), &format!("{case:?}").leak()[..]);
        }
        for case in [
            PutSessionErrorCase::Unauthorized,
            PutSessionErrorCase::InvalidArgument,
            PutSessionErrorCase::AlreadyExists,
            PutSessionErrorCase::Deleted,
            PutSessionErrorCase::GrantExpired,
            PutSessionErrorCase::CapacityExceeded,
        ] {
            check(case.code(), &format!("{case:?}").leak()[..]);
        }
        for case in [
            ConsumeCodeErrorCase::Unauthorized,
            ConsumeCodeErrorCase::InvalidArgument,
            ConsumeCodeErrorCase::AlreadyConsumed,
            ConsumeCodeErrorCase::BadProof,
            ConsumeCodeErrorCase::NotFound,
            ConsumeCodeErrorCase::Deleted,
            ConsumeCodeErrorCase::CodeExpired,
        ] {
            check(case.code(), &format!("{case:?}").leak()[..]);
        }
    }
}
