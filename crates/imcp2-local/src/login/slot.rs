//! The [`SessionSlot`] — the local binary's whole authentication state: one
//! shared, replaceable holder for the signed-in session, read by core
//! through the injected resolver and written by the login flow.

use std::sync::Arc;

use super::now_ns;

/// The single-user session holder — a shared, **replaceable**,
/// **expiry-aware** slot rather than a fixed id. The Internet Identity
/// contract requires a FRESH session key after an `Unauthorized` (a reused id
/// would reuse its keys), so each successful login writes a fresh session id
/// here — same-process reauthentication after grant expiry or revocation,
/// with no client restart. Clones share the slot: the login flow holds a
/// writing handle, and the slot answers `IcTools`' session lookups through
/// [`SessionSlot::resolver`] — the local binary's whole authentication layer,
/// living here rather than in core, which only asks the injected resolver.
/// Starts empty (signed out).
///
/// Expiry-aware: the slot stores the grant's expiration alongside the id and
/// reports **no session** the moment the grant lapses — so tools return their
/// "needs an authenticated session" sign-in guidance instead of acting on a
/// dead session (whose server-side state the reaper also removes, on its own
/// 60-second cadence, which must not be what gates authentication).
#[derive(Clone, Debug, Default)]
pub struct SessionSlot(Arc<std::sync::RwLock<Option<Entry>>>);

#[derive(Debug)]
struct Entry {
    session_id: String,
    /// Grant expiration, ns since the Unix epoch (from `mcp_register_v2`).
    expiration_ns: u64,
}

impl SessionSlot {
    /// A fresh, empty slot (no session — every session-needing tool reports
    /// "needs an authenticated session" until the login flow fills it).
    pub fn new() -> Self {
        Self::default()
    }

    /// The current session id, while its grant is live; `None` once it
    /// expires. The critical section is a clone — never held across an await.
    pub fn get(&self) -> Option<String> {
        self.0
            .read()
            .expect("session slot poisoned")
            .as_ref()
            .filter(|entry| entry.expiration_ns > now_ns())
            .map(|entry| entry.session_id.clone())
    }

    /// Replace the session after a successful login (a fresh id per the II
    /// fresh-session-key contract), with the grant expiration II returned.
    pub fn set(&self, session_id: String, expiration_ns: u64) {
        *self.0.write().expect("session slot poisoned") = Some(Entry {
            session_id,
            expiration_ns,
        });
    }

    /// This slot as the [`imcp2_core::SessionResolver`] the local binary
    /// injects into `IcTools`: every call acts as the one signed-in session,
    /// or as unauthenticated once the grant lapses.
    pub fn resolver(&self) -> imcp2_core::SessionResolver {
        let slot = self.clone();
        Arc::new(move |_ctx| slot.get())
    }
}
