//! The **browser Internet Identity login** for the local binary: mint a fresh
//! session, stand up a transient loopback listener, hand the user an id.ai
//! sign-in link, and redeem the delegation II navigates back with. On success
//! the shared [`SessionSlot`] is filled and every tool call acts as the user;
//! the listener is torn down (redeem or timeout) and the grant lives in memory
//! only.
//!
//! The listener is the unavoidable minimum, not a design slip: II delivers the
//! delegation by *navigating the browser* to the callback, in a URL fragment
//! only a served page can read and POST back — which takes a real HTTP origin.
//! This is the standard native-app loopback redirect (RFC 8252 §7.3), the same
//! shape as the ICP CLI's `icp identity link web`. It serves two routes for one
//! handshake and never serves the MCP tool surface, which rides stdio.
//!
//! The user has to trust a local connector in II Settings first; II stores that
//! as a port-less `http://127.0.0.1`, precisely because the port below is
//! chosen per handshake and can't be promised in advance.
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use imcp2_core::identities::Identities;
use imcp2_core::iiconnect;
use tokio::sync::{Mutex, Notify};

mod routes;
mod slot;
#[cfg(test)]
mod tests;

pub use slot::SessionSlot;

/// How long one sign-in handshake may take, from the `authenticate` call to
/// the browser's redeem, before the pending flow and its listener are torn
/// down. Matches the hosted server's pending-connect TTL.
const HANDSHAKE_TTL: Duration = Duration::from_secs(600);

/// `ttl` (seconds) requested for the II grant in the connect link, matching
/// the hosted server. II clamps it to [600, 2592000], and the effective
/// session duration is whatever the user picks on II's consent screen.
const GRANT_TTL_SECS: u64 = 3600;

/// Where the pinned callback page's error state points users ("contact us to
/// report it") — DFINITY ships this binary, so failures report to the same
/// address as the hosted server's.
const CONTACT_EMAIL: &str = "mcp@dfinity.org";

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// The login flow's shared handle: the `authenticate`/`auth_status` tools call
/// [`begin`](Self::begin)/[`status`](Self::status), and the loopback redeem
/// route completes the flow through a clone. Single-user by construction — one
/// pending handshake at a time, serialized by the state lock.
#[derive(Clone)]
pub struct LoginDriver {
    inner: Arc<Inner>,
}

struct Inner {
    identities: Identities,
    /// The shared, replaceable session slot `IcTools` reads through
    /// [`SessionSlot::resolver`]: each successful redeem writes the fresh
    /// session id here (the II contract requires a fresh session key after
    /// `Unauthorized`, and a fresh id gets fresh keys).
    slot: SessionSlot,
    /// Best-effort `open::that` on the sign-in link. The flow never depends on
    /// it succeeding — the link is always returned in-band by `authenticate`.
    auto_open: bool,
    state: Mutex<LoginState>,
    /// Serializes each redeem's `mcp_register_v2` **and** its local commit,
    /// across flows. II's register REPLACES the anchor's previous grant (the
    /// last registration to settle at II is the live one), so the local slot
    /// must be committed in the same order the registrations settle: without
    /// this, a timed-out flow's slow register could land at II *after* a
    /// newer flow's — II would then honor the old session while the slot
    /// named the new one, and every tool call would come back `Unauthorized`.
    registration: Mutex<()>,
}

#[derive(Default)]
struct LoginState {
    pending: Option<Pending>,
    /// The most recent successful login, kept (even past expiry) so
    /// `auth_status` can say *whose* session expired.
    grant: Option<Grant>,
}

struct Pending {
    /// Doubles as the connect `state` in the II link — II echoes it to the
    /// callback, and the redeem accepts only this value.
    ///
    /// Unguessable on purpose (a v4 UUID), and load-bearing in a way a hosted
    /// server's `state` is not: a hosted callback sits on a domain a random
    /// page can't reach, while this listener is reachable by any page in the
    /// browser and any process on the machine. `state` is what stops a forged
    /// POST to `/redeem` from injecting an identity the user never chose. II
    /// treats it as opaque and only echoes it, so keeping it unpredictable is
    /// entirely this side's job.
    session_id: String,
    url: String,
    /// This flow's loopback callback (`http://127.0.0.1:<port>/callback`) —
    /// the origin the listener serves on.
    callback_url: String,
    started: Instant,
    /// Single-flight marker: `true` while a redemption attempt (the
    /// `mcp_register_v2` network call) is mid-flight, so a page double-submit
    /// can't fire two. Cleared on failure so a genuine retry can proceed.
    redeeming: bool,
    /// Tears the transient listener down (graceful): notified on redeem
    /// success, on handshake timeout, and when a fresh flow replaces this one.
    shutdown: Arc<Notify>,
}

impl Pending {
    fn expired(&self) -> bool {
        self.started.elapsed() >= HANDSHAKE_TTL
    }
}

/// A completed login, as `auth_status` reports it.
#[derive(Clone)]
pub struct Grant {
    pub session_id: String,
    /// The session principal (`self_authenticating(pub(S))`) — attribution,
    /// not the user's per-app principal.
    pub principal: Option<String>,
    /// II's recorded access level: `"queries"` (read-only) or `"all"`.
    pub permissions: &'static str,
    /// Grant expiration, ns since the Unix epoch (the user's consent-time
    /// session choice).
    pub expiration_ns: u64,
}

impl Grant {
    pub fn expired(&self) -> bool {
        self.expiration_ns <= now_ns()
    }

    /// Whole minutes until expiry (0 when expired).
    pub fn minutes_left(&self) -> u64 {
        self.expiration_ns.saturating_sub(now_ns()) / 60_000_000_000
    }
}

/// What [`LoginDriver::status`] reports — the states `auth_status` renders.
pub enum LoginStatus {
    SignedIn(Grant),
    /// A handshake is waiting for the browser.
    Pending {
        url: String,
    },
    /// A previous grant ran out (or was revoked and then expired here); a new
    /// `authenticate` gets a fresh session.
    Expired(Grant),
    SignedOut,
}

/// What [`LoginDriver::begin`] returns to the `authenticate` tool.
pub enum BeginOutcome {
    /// A live grant exists and `refresh` was not requested.
    AlreadySignedIn(Grant),
    /// A sign-in link is ready. `fresh` distinguishes a newly started flow
    /// from an already-pending one being returned again (single-flight).
    Pending { url: String, fresh: bool },
}

impl LoginDriver {
    pub fn new(identities: Identities, slot: SessionSlot, auto_open: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                identities,
                slot,
                auto_open,
                state: Mutex::new(LoginState::default()),
                registration: Mutex::new(()),
            }),
        }
    }

    /// Start (or return the already-pending) sign-in: mint a **fresh** session
    /// id + registration key, bind the loopback listener, and build the id.ai
    /// link — returned immediately, never blocking on the browser. With a live
    /// grant and `refresh: false`, reports the grant instead of starting over.
    pub async fn begin(&self, refresh: bool) -> Result<BeginOutcome, String> {
        // The lock is held across the (local, network-free) setup, so
        // concurrent `authenticate` calls serialize into one flow.
        let mut state = self.inner.state.lock().await;

        if let Some(p) = &state.pending {
            if !p.expired() {
                return Ok(BeginOutcome::Pending {
                    url: p.url.clone(),
                    fresh: false,
                });
            }
            // Expired while nobody was looking: tear it down, then start fresh.
            if let Some(p) = state.pending.take() {
                p.shutdown.notify_one();
            }
        }
        if !refresh {
            if let Some(g) = &state.grant {
                if !g.expired() {
                    return Ok(BeginOutcome::AlreadySignedIn(g.clone()));
                }
            }
        }

        // A FRESH session id per flow: fresh id ⇒ fresh session + registration
        // keys in `Identities`, per the II fresh-session-key contract.
        let session_id = uuid::Uuid::new_v4().to_string();
        let reg_pubkey = self
            .inner
            .identities
            .registration_pubkey_b64(&session_id)
            .await?;

        // Port 0: the OS picks a free port. II trusts a local server by
        // loopback host rather than by exact origin, so a fresh port per
        // handshake is expected rather than something to keep stable.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| format!("could not bind the login callback listener: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("could not read the listener address: {e}"))?
            .port();
        let authority = format!("127.0.0.1:{port}");
        let callback_url = format!("http://{authority}/callback");

        let url = iiconnect::ii_mcp_url(
            &self.inner.identities.instance().ii_url,
            &callback_url,
            &session_id,
            GRANT_TTL_SECS,
            &reg_pubkey,
        );

        let shutdown = Arc::new(Notify::new());
        let app = routes::login_router(self.clone(), authority);
        let sd = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(async move { sd.notified().await })
                .await
            {
                tracing::warn!("login listener error: {e}");
            }
        });

        // Watchdog: when the handshake window closes, drop the pending flow
        // and the listener (if a redeem didn't already).
        let driver = self.clone();
        let sid = session_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(HANDSHAKE_TTL).await;
            let mut state = driver.inner.state.lock().await;
            let ours = matches!(&state.pending, Some(p) if p.session_id == sid);
            if ours {
                if let Some(p) = state.pending.take() {
                    p.shutdown.notify_one();
                    tracing::info!(
                        callback = %p.callback_url,
                        "sign-in window expired; login listener closed"
                    );
                }
            }
        });

        state.pending = Some(Pending {
            session_id,
            url: url.clone(),
            callback_url,
            started: Instant::now(),
            redeeming: false,
            shutdown,
        });
        drop(state);

        if self.inner.auto_open {
            // Detached: the launcher runs with stdin/stdout/stderr nulled and
            // (off macOS) double-forked away, so it can never touch this
            // process's stdio — stdout is the MCP JSON-RPC channel — nor hold
            // a thread. Best-effort either way: the link is in the tool
            // result. (A rare launcher can still block briefly at spawn, so
            // it stays off the async workers.)
            let link = url.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = open::that_detached(&link) {
                    tracing::debug!("could not auto-open the browser: {e}");
                }
            });
        }

        Ok(BeginOutcome::Pending { url, fresh: true })
    }

    /// The pending flow's `(session_id, callback_url)`, for the tests that
    /// play the browser against the live listener.
    #[cfg(test)]
    pub(crate) async fn pending_handshake(&self) -> Option<(String, String)> {
        let state = self.inner.state.lock().await;
        state
            .pending
            .as_ref()
            .map(|p| (p.session_id.clone(), p.callback_url.clone()))
    }

    pub async fn status(&self) -> LoginStatus {
        let state = self.inner.state.lock().await;
        // A live pending handshake outranks a live grant, matching `begin`'s
        // precedence: after `authenticate(refresh: true)` the old session may
        // still be valid, but the truthful answer is "a replacement sign-in is
        // waiting for the browser", not "signed in" — otherwise the client
        // reads the refresh as already complete.
        if let Some(p) = &state.pending {
            if !p.expired() {
                return LoginStatus::Pending { url: p.url.clone() };
            }
        }
        if let Some(g) = &state.grant {
            if !g.expired() {
                return LoginStatus::SignedIn(g.clone());
            }
        }
        match &state.grant {
            Some(g) => LoginStatus::Expired(g.clone()),
            None => LoginStatus::SignedOut,
        }
    }
}
