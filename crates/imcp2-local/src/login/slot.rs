//! The [`SessionSlot`] — the local binary's whole authentication state: one
//! shared, replaceable holder for the signed-in session id, read by core
//! through the injected resolver and written by the login flow.

use std::sync::Arc;

/// The single-user session holder — a shared, **replaceable** slot rather
/// than a fixed id. The Internet Identity contract requires a FRESH session
/// key after an `Unauthorized` (a reused id would reuse its keys), so each
/// successful login writes a fresh session id here — same-process
/// reauthentication after grant expiry or revocation, with no client restart.
/// Clones share the slot: the login flow holds a writing handle, and the slot
/// answers `IcTools`' session lookups through [`SessionSlot::resolver`] — the
/// local binary's whole authentication layer, living here rather than in
/// core, which only asks the injected resolver. Starts empty (signed out).
#[derive(Clone, Debug, Default)]
pub struct SessionSlot(Arc<std::sync::RwLock<Option<String>>>);

impl SessionSlot {
    /// A fresh, empty slot (no session — every session-needing tool reports
    /// "needs an authenticated session" until the login flow fills it).
    pub fn new() -> Self {
        Self::default()
    }

    /// The current session id, if a login has completed. The critical section
    /// is a clone — never held across an await.
    pub fn get(&self) -> Option<String> {
        self.0.read().expect("session slot poisoned").clone()
    }

    /// Replace the session id after a successful login (a fresh id per the II
    /// fresh-session-key contract).
    pub fn set(&self, session_id: String) {
        *self.0.write().expect("session slot poisoned") = Some(session_id);
    }

    /// This slot as the [`imcp2_core::SessionResolver`] the local binary
    /// injects into `IcTools`: every call acts as the one signed-in session.
    pub fn resolver(&self) -> imcp2_core::SessionResolver {
        let slot = self.clone();
        Arc::new(move |_ctx| slot.get())
    }
}
