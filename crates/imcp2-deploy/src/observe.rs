//! What a server can be told about the deploys it runs, for it to count: a
//! deploy call is one MCP request among many to the transport that carries
//! it — answered `200` whether the deploy succeeded, failed or never began —
//! so how deploys go is known here and nowhere else.
//!
//! Every event is one of a fixed few ([`Refused`], [`Ended`]), each with a
//! fixed name: nothing a caller sends (a session, a canister, a bundle)
//! reaches an observer, so what it counts is bounded by this file.

use std::time::Duration;

/// Told of each deploy call's fate. Called on the request's own task, so an
/// implementation only counts.
pub trait DeployObserver: Send + Sync {
    /// A deploy was asked for and not begun, for a reason that is the
    /// server's or the session's state rather than the request's.
    fn refused(&self, why: Refused);
    /// A deploy that held a slot gave it back, `lasted` after it took it.
    fn ended(&self, how: Ended, lasted: Duration);
}

/// Why a deploy was not begun.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Every slot was held: the server was running as many deploys as it
    /// allows. How often this happens is what says whether the cap is right.
    Busy,
    /// The session already had a deploy running.
    SessionBusy,
    /// The server was stopping.
    Stopping,
}

impl Refused {
    pub const ALL: [Self; 3] = [Self::Busy, Self::SessionBusy, Self::Stopping];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::SessionBusy => "session_busy",
            Self::Stopping => "stopping",
        }
    }
}

/// How a deploy that held a slot ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// Every phase succeeded, or there was nothing to deploy.
    Succeeded,
    /// A phase failed; canisters may have been created.
    Failed,
    /// The request or its bundle was refused before anything was created:
    /// bad arguments, no such upload, a bundle outside the rule.
    Rejected,
    /// Stopped before it finished: the call cancelled, the client gone, or
    /// the server stopping.
    Interrupted,
}

impl Ended {
    pub const ALL: [Self; 4] = [Self::Succeeded, Self::Failed, Self::Rejected, Self::Interrupted];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::Interrupted => "interrupted",
        }
    }
}
