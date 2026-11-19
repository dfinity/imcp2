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
    /// The upload store had no room for the deploy to run in: a running
    /// deploy is charged the most its directory may come to.
    NoRoom,
}

impl Refused {
    pub const ALL: [Self; 4] = [Self::Busy, Self::SessionBusy, Self::Stopping, Self::NoRoom];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::SessionBusy => "session_busy",
            Self::Stopping => "stopping",
            Self::NoRoom => "no_room",
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
    /// Refused before anything was created, for what the caller sent or
    /// holds: bad arguments, no such upload, a bundle outside the rule, or
    /// an identity that could not be derived for the session (a grant that
    /// has lapsed, which is the session's; or Internet Identity not
    /// answering, which is not — the two are not told apart here).
    Rejected,
    /// Not begun because the server could not prepare it: its directory
    /// could not be made, or a step of its own failed. Nothing was created,
    /// and nothing was wrong with the request. A rate of these is the
    /// server's trouble, not its users'.
    SetupFailed,
    /// Stopped before it finished: the call cancelled, the client gone, or
    /// the server stopping.
    Interrupted,
}

impl Ended {
    pub const ALL: [Self; 5] =
        [Self::Succeeded, Self::Failed, Self::Rejected, Self::SetupFailed, Self::Interrupted];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::SetupFailed => "setup_failed",
            Self::Interrupted => "interrupted",
        }
    }
}
