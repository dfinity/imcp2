//! The **browser Internet Identity login** for the local binary: mint a fresh
//! session, stand up a transient loopback listener, hand the user an id.ai
//! sign-in link, and redeem the delegation II navigates back with. On success
//! the shared [`SessionSlot`] is filled and every tool call acts as the user;
//! the listener is torn down (redeem or timeout) and the grant lives in memory
//! only.
//!
//! The listener is the unavoidable minimum, not a design slip: II delivers the
//! delegation by *navigating the browser* to the callback (a URL fragment only
//! a served page can read and POST back), and II's #4091 check fetches
//! `/.well-known/ii-auth-callbacks` from the callback's origin before honoring
//! it — both require a real HTTP origin. This is the standard native-app
//! loopback redirect (RFC 8252 §7.3), the same shape as the ICP CLI's
//! `icp identity link web`. It serves exactly three routes for one handshake
//! and never serves the MCP tool surface, which rides stdio.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use imcp2_core::identities::Identities;
use imcp2_core::iiconnect::{self, RedeemBody, AUTH_CALLBACKS_WELL_KNOWN};
use imcp2_core::SessionSlot;
use serde_json::json;
use tokio::sync::{Mutex, Notify};

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
const CONTACT: &str = "mcp@dfinity.org";

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
    /// The shared, replaceable session slot `IcTools` reads under
    /// `SessionSource::Singleton`: each successful redeem writes the fresh
    /// session id here (the II contract requires a fresh session key after
    /// `Unauthorized`, and a fresh id gets fresh keys).
    slot: SessionSlot,
    /// Best-effort `open::that` on the sign-in link. The flow never depends on
    /// it succeeding — the link is always returned in-band by `authenticate`.
    auto_open: bool,
    state: Mutex<LoginState>,
}

#[derive(Default)]
struct LoginState {
    pending: Option<Pending>,
    /// The most recent successful login, kept (even past expiry) so
    /// `auth_status` can say *whose* session expired.
    grant: Option<Grant>,
    /// Flow counter: each `begin`-started flow gets the next number, so a
    /// redeem that raced a replacement can tell whether something NEWER
    /// exists (see [`superseded_by_newer`]).
    epoch: u64,
}

/// Whether a flow newer than `epoch` exists — a pending handshake or a
/// completed grant started after the flow that is asking. A stale redeem
/// (claimed, then outlived by the watchdog while its `mcp_register_v2` call
/// was in flight) must not overwrite a newer sign-in.
fn superseded_by_newer(state: &LoginState, epoch: u64) -> bool {
    state.pending.as_ref().is_some_and(|p| p.epoch > epoch)
        || state.grant.as_ref().is_some_and(|g| g.epoch > epoch)
}

struct Pending {
    /// Doubles as the connect `state` in the II link — II echoes it to the
    /// callback, and the redeem accepts only this value.
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
    /// This flow's number (see [`LoginState::epoch`]).
    epoch: u64,
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
    /// The number of the flow that produced this grant (see
    /// [`LoginState::epoch`]).
    epoch: u64,
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

        // Port 0: the OS picks a free port; both the II link's `callback` and
        // the #4091 allow-list entry derive from the ONE resulting origin, so
        // they cannot drift (II matches by exact string equality).
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| format!("could not bind the login callback listener: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("could not read the listener address: {e}"))?
            .port();
        let callback_url = format!("http://127.0.0.1:{port}/callback");

        let url = iiconnect::ii_mcp_url(
            &self.inner.identities.instance().ii_url,
            &callback_url,
            &session_id,
            GRANT_TTL_SECS,
            &reg_pubkey,
        );

        let shutdown = Arc::new(Notify::new());
        let app = login_router(self.clone(), callback_url.clone());
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

        state.epoch += 1;
        state.pending = Some(Pending {
            session_id,
            url: url.clone(),
            callback_url,
            started: Instant::now(),
            redeeming: false,
            shutdown,
            epoch: state.epoch,
        });
        drop(state);

        if self.inner.auto_open {
            // `open::that` can block on the launcher, so it runs off the
            // async workers — and only best-effort: the link is in the tool
            // result either way.
            let link = url.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = open::that(&link) {
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

/// The three transient loopback routes — the login handshake's whole HTTP
/// surface. `callback_url` is this listener's own callback, echoed verbatim in
/// the allow-list document.
fn login_router(driver: LoginDriver, callback_url: String) -> Router {
    Router::new()
        .route("/callback", get(callback_page))
        .route("/redeem", post(redeem))
        .route(AUTH_CALLBACKS_WELL_KNOWN, get(auth_callbacks))
        .with_state(RouteCtx {
            driver,
            callback_url,
        })
}

#[derive(Clone)]
struct RouteCtx {
    driver: LoginDriver,
    callback_url: String,
}

/// GET /callback — the pinned fragment-reading page (shared with the hosted
/// server), pointed at this listener's `/redeem`, with the same non-CSP
/// hardening headers the hosted server adds.
async fn callback_page() -> Response {
    let page = iiconnect::pinned_callback_page("/redeem", CONTACT);
    let mut resp = Html(page.html).into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_str(&page.csp).expect("valid CSP"),
    );
    h.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    resp
}

/// GET /.well-known/ii-auth-callbacks — the #4091 allow-list: exactly this
/// listener's callback. II fetches it cross-origin (hence the one CORS
/// header) and fail-closed before honoring the callback; `no-store` keeps an
/// intermediary from serving a stale document for a past listener's port.
async fn auth_callbacks(State(ctx): State<RouteCtx>) -> Response {
    let mut resp = Json(json!({ "callbacks": [ctx.callback_url] })).into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        axum::http::HeaderValue::from_static("*"),
    );
    resp
}

fn redeem_err(msg: &str) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg })),
    )
        .into_response()
}

/// The local success answer: no OAuth continuation to redirect into, so the
/// pinned page renders its terminal "Signed in — you can close this tab"
/// state in place (the page script's `done` arm).
fn done() -> Response {
    Json(json!({ "done": true })).into_response()
}

/// POST /redeem — the pinned page POSTs the fragment here. The hosted redeem
/// minus its OAuth tail: no initiator cookie (there is no public initiate
/// endpoint to confuse a deputy through — the binary itself mints `X` and this
/// listener is loopback-only), no PKCE code, and no redirect — success answers
/// `{"done": true}` and the page renders its terminal state. Parse before
/// claiming, single-flight claim, one `mcp_register_v2` call, then fill the
/// session slot and tear the listener down.
async fn redeem(State(ctx): State<RouteCtx>, Json(body): Json<RedeemBody>) -> Response {
    let driver = &ctx.driver;

    // Validate the delivery against the pending flow first (NOT claiming yet),
    // so an unknown/expired `state` gets its accurate refusal without parsing.
    {
        let state = driver.inner.state.lock().await;
        if state
            .grant
            .as_ref()
            .is_some_and(|g| g.session_id == body.state)
        {
            // A retry of an already-successful redeem (II's delegation redeems
            // repeatedly within its lifetime): idempotent success.
            return done();
        }
        match &state.pending {
            Some(p) if p.session_id == body.state => {
                if p.expired() {
                    return redeem_err(
                        "This sign-in expired. Ask the agent to authenticate again.",
                    );
                }
            }
            _ => {
                return redeem_err(
                    "This sign-in is unknown or already used. Ask the agent to authenticate again.",
                )
            }
        }
    }

    // Decode the fragment delegation (pure, size-bounded) BEFORE claiming, so
    // a malformed delivery never occupies the single-flight slot.
    let (user_key, chain) = match iiconnect::parse_registration_delegation(&body.delegation) {
        Ok(v) => v,
        Err(e) => {
            return redeem_err(&format!(
                "We couldn't read the sign-in response. Ask the agent to authenticate again. ({e})"
            ))
        }
    };

    // Claim atomically (re-checking: the flow may have moved while parsing),
    // remembering the claimed flow's number for the commit-time check below.
    let epoch =
        {
            let mut state = driver.inner.state.lock().await;
            if state
                .grant
                .as_ref()
                .is_some_and(|g| g.session_id == body.state)
            {
                return done();
            }
            match state.pending.as_mut() {
                Some(p) if p.session_id == body.state => {
                    if p.expired() {
                        return redeem_err(
                            "This sign-in expired. Ask the agent to authenticate again.",
                        );
                    }
                    if p.redeeming {
                        return redeem_err(
                            "This sign-in is already being processed. Wait a moment; \
                         if nothing happens, ask the agent to authenticate again.",
                        );
                    }
                    p.redeeming = true;
                    p.epoch
                }
                _ => return redeem_err(
                    "This sign-in is unknown or already used. Ask the agent to authenticate again.",
                ),
            }
        };

    // The one network call, outside the lock.
    match driver
        .inner
        .identities
        .redeem_registration_delegation(&body.state, user_key, chain)
        .await
    {
        Err(e) => {
            let mut state = driver.inner.state.lock().await;
            if let Some(p) = state.pending.as_mut() {
                if p.session_id == body.state {
                    p.redeeming = false; // free the claim for a genuine retry
                }
            }
            redeem_err(&e)
        }
        Ok(outcome) => {
            let principal = driver.inner.identities.session_principal(&body.state).await;
            let mut state = driver.inner.state.lock().await;
            // Commit-time check: this flow was claimed before the network
            // call, but the watchdog may have expired it and a NEWER sign-in
            // (pending or already completed) may exist by now — a stale
            // success must not overwrite that. A late success with nothing
            // newer around still lands (II did bind the grant; the watchdog
            // alone is no reason to make the user redo it).
            if superseded_by_newer(&state, epoch) {
                drop(state);
                return redeem_err(
                    "This sign-in was superseded by a newer one. Use the most recent \
                     sign-in tab, or ask the agent to authenticate again.",
                );
            }
            driver.inner.slot.set(body.state.clone());
            state.grant = Some(Grant {
                session_id: body.state.clone(),
                principal,
                permissions: outcome.permissions,
                expiration_ns: outcome.expiration_ns,
                epoch,
            });
            let ours = matches!(&state.pending, Some(p) if p.session_id == body.state);
            if ours {
                if let Some(p) = state.pending.take() {
                    p.shutdown.notify_one();
                }
            }
            drop(state);
            tracing::info!(
                permissions = outcome.permissions,
                expiration_ns = outcome.expiration_ns,
                "signed in: registration delegation redeemed; login listener closing"
            );
            done()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imcp2_core::IiInstance;

    /// A driver against the real mainnet/prod-II config — nothing here touches
    /// the network (agent construction, key minting, and the loopback listener
    /// are all local), which is exactly what these tests rely on.
    fn test_driver() -> (LoginDriver, SessionSlot) {
        let agent = imcp2_core::Agent::builder()
            .with_url(imcp2_core::IC_URL)
            .build()
            .expect("agent");
        let identities = Identities::new(
            IiInstance::prod().expect("prod II instance"),
            "https://mcp.internetcomputer.org".into(),
            agent,
        );
        let slot = SessionSlot::new();
        (
            LoginDriver::new(identities, slot.clone(), /* auto_open */ false),
            slot,
        )
    }

    /// A shape-valid two-hop chain (the same wire shape as iiconnect's parser
    /// tests) whose signatures are garbage: it must get PAST parsing and be
    /// rejected by the redeem path itself — offline, before any network call.
    fn fake_chain_json() -> String {
        serde_json::json!({
            "delegations": [
                {
                    "delegation": { "pubkey": "070707", "expiration": "66", "targets": ["aaaaa-aa"] },
                    "signature": "040506",
                },
                {
                    "delegation": { "pubkey": "09080706", "expiration": "66" },
                    "signature": "010909",
                },
            ],
            "publicKey": "010203",
        })
        .to_string()
    }

    // One `authenticate` = one flow: a fresh id.ai link over a fresh loopback
    // callback; a second call while it is pending returns the SAME link
    // (single-flight) rather than racing a second listener. The session slot
    // stays empty until a redeem succeeds — starting a login signs nobody in.
    #[tokio::test]
    async fn begin_mints_one_flow_and_repeats_it_while_pending() {
        let (driver, slot) = test_driver();
        let BeginOutcome::Pending { url, fresh } = driver.begin(false).await.expect("begin") else {
            panic!("a fresh driver must start a flow, not report a session")
        };
        assert!(fresh);
        assert!(url.starts_with("https://id.ai/mcp#callback="), "{url}");
        assert!(
            url.contains("http%3A%2F%2F127.0.0.1%3A"),
            "loopback callback in the fragment: {url}"
        );
        assert!(url.contains("&ttl=3600&registration_key="), "{url}");

        let BeginOutcome::Pending { url: again, fresh } = driver.begin(false).await.expect("begin")
        else {
            panic!("a pending flow must be returned, not replaced")
        };
        assert!(!fresh, "the second call must join the pending flow");
        assert_eq!(again, url, "same link while the handshake is pending");

        assert_eq!(slot.get(), None, "no session until a redeem succeeds");
        assert!(matches!(driver.status().await, LoginStatus::Pending { .. }));
    }

    // The transient listener's whole surface, driven like the browser: the
    // pinned page (strict CSP + the hosted server's hardening headers, script
    // pointed at /redeem), and the #4091 allow-list (this callback verbatim,
    // CORS-readable, never cached).
    #[tokio::test]
    async fn the_listener_serves_the_pinned_page_and_the_allow_list() {
        let (driver, _slot) = test_driver();
        driver.begin(false).await.expect("begin");
        let (_, callback_url) = driver.pending_handshake().await.expect("pending");
        let origin = callback_url.strip_suffix("/callback").unwrap().to_string();
        let http = reqwest::Client::new();

        let page = http.get(&callback_url).send().await.expect("GET /callback");
        assert_eq!(page.status(), 200);
        let csp = page
            .headers()
            .get("content-security-policy")
            .expect("pinned page ships a CSP")
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        for (name, want) in [
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
        ] {
            assert_eq!(
                page.headers().get(name).and_then(|v| v.to_str().ok()),
                Some(want)
            );
        }
        let html = page.text().await.unwrap();
        assert!(
            html.contains("/redeem"),
            "the script must POST to this listener's redeem"
        );
        assert!(
            html.contains("d.done"),
            "the local success arm must be in the shipped page"
        );

        let wk = http
            .get(format!("{origin}{AUTH_CALLBACKS_WELL_KNOWN}"))
            .send()
            .await
            .expect("GET allow-list");
        assert_eq!(wk.status(), 200);
        assert_eq!(
            wk.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("*"),
            "II fetches the allow-list cross-origin"
        );
        assert_eq!(
            wk.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "fail-closed infrastructure must never be served stale"
        );
        let doc: serde_json::Value = wk.json().await.unwrap();
        assert_eq!(
            doc,
            serde_json::json!({ "callbacks": [callback_url] }),
            "the declared callback must equal the link's callback VERBATIM (exact-match)"
        );
    }

    // The redeem's refusal paths, in order: an unknown `state` (or one from a
    // replaced flow), a delegation the parser rejects, and a shape-valid chain
    // with garbage signatures that the redeem itself rejects — all 400 with an
    // {"error"} body the pinned page renders, all offline, and none of them
    // consumes the pending flow (a genuine retry stays possible).
    #[tokio::test]
    async fn redeem_refuses_bad_deliveries_and_keeps_the_flow_retryable() {
        let (driver, slot) = test_driver();
        let BeginOutcome::Pending { url, .. } = driver.begin(false).await.expect("begin") else {
            panic!("fresh flow")
        };
        let (state, callback_url) = driver.pending_handshake().await.expect("pending");
        let origin = callback_url.strip_suffix("/callback").unwrap().to_string();
        let redeem_url = format!("{origin}/redeem");
        let http = reqwest::Client::new();

        let post = |body: serde_json::Value| {
            let http = http.clone();
            let redeem_url = redeem_url.clone();
            async move {
                http.post(&redeem_url)
                    .json(&body)
                    .send()
                    .await
                    .expect("POST /redeem")
            }
        };

        let r = post(serde_json::json!({ "state": "someone-else", "delegation": "" })).await;
        assert_eq!(r.status(), 400);
        let e: serde_json::Value = r.json().await.unwrap();
        assert!(
            e["error"]
                .as_str()
                .unwrap()
                .contains("unknown or already used"),
            "{e}"
        );

        let r = post(serde_json::json!({ "state": state, "delegation": "not json" })).await;
        assert_eq!(r.status(), 400);
        let e: serde_json::Value = r.json().await.unwrap();
        assert!(
            e["error"]
                .as_str()
                .unwrap()
                .contains("couldn't read the sign-in response"),
            "{e}"
        );

        let r = post(serde_json::json!({ "state": state, "delegation": fake_chain_json() })).await;
        assert_eq!(
            r.status(),
            400,
            "garbage signatures must be rejected by the redeem"
        );
        let e: serde_json::Value = r.json().await.unwrap();
        assert!(e["error"].is_string(), "{e}");

        assert_eq!(slot.get(), None, "no failure may fill the session slot");
        let BeginOutcome::Pending { url: still, fresh } = driver.begin(false).await.expect("begin")
        else {
            panic!("the flow must survive failed redeems")
        };
        assert!(!fresh, "failed redeems must not consume the pending flow");
        assert_eq!(still, url);
    }

    // The status lifecycle around a grant (injected directly — a real one
    // needs live II): live grant → SignedIn with the wallclock math; past
    // expiration → Expired, still naming the principal; a fresh driver is
    // simply SignedOut.
    #[tokio::test]
    async fn status_reports_the_grant_lifecycle() {
        let (driver, _slot) = test_driver();
        assert!(matches!(driver.status().await, LoginStatus::SignedOut));

        let grant = |expiration_ns: u64| Grant {
            session_id: "sess".into(),
            principal: Some("aaaaa-aa".into()),
            permissions: "queries",
            expiration_ns,
            epoch: 1,
        };
        driver.inner.state.lock().await.grant = Some(grant(now_ns() + 30 * 60_000_000_000));
        match driver.status().await {
            LoginStatus::SignedIn(g) => {
                assert!(
                    (25..=30).contains(&g.minutes_left()),
                    "{}",
                    g.minutes_left()
                );
            }
            _ => panic!("a live grant must report SignedIn"),
        }

        driver.inner.state.lock().await.grant = Some(grant(now_ns() - 1));
        match driver.status().await {
            LoginStatus::Expired(g) => assert_eq!(g.principal.as_deref(), Some("aaaaa-aa")),
            _ => panic!("a past-expiry grant must report Expired"),
        }
    }

    // `authenticate(refresh: true)` while a live grant exists: the truthful
    // status is the PENDING replacement handshake, not the old "signed in" —
    // otherwise the client reads the refresh as already complete (the same
    // precedence `begin` applies).
    #[tokio::test]
    async fn a_pending_refresh_outranks_the_live_grant_in_status() {
        let (driver, _slot) = test_driver();
        driver.inner.state.lock().await.grant = Some(Grant {
            session_id: "old".into(),
            principal: Some("aaaaa-aa".into()),
            permissions: "all",
            expiration_ns: now_ns() + 30 * 60_000_000_000,
            epoch: 1,
        });
        assert!(matches!(driver.status().await, LoginStatus::SignedIn(_)));

        let BeginOutcome::Pending { fresh, .. } = driver.begin(true).await.expect("refresh") else {
            panic!("refresh=true must start a replacement flow past a live grant")
        };
        assert!(fresh);
        assert!(
            matches!(driver.status().await, LoginStatus::Pending { .. }),
            "a live replacement handshake must outrank the old grant"
        );
    }

    // The stale-redeem guard: a flow that was claimed, then outlived by the
    // watchdog while its network call ran, must not overwrite a NEWER sign-in
    // (pending or completed) at commit time — but a late success with nothing
    // newer around still lands.
    #[test]
    fn a_stale_redeem_is_superseded_by_any_newer_flow() {
        let pending = |epoch: u64| Pending {
            session_id: "s".into(),
            url: "u".into(),
            callback_url: "c".into(),
            started: Instant::now(),
            redeeming: false,
            shutdown: Arc::new(Notify::new()),
            epoch,
        };
        let grant = |epoch: u64| Grant {
            session_id: "g".into(),
            principal: None,
            permissions: "queries",
            expiration_ns: u64::MAX,
            epoch,
        };
        let state = |p: Option<Pending>, g: Option<Grant>| LoginState {
            pending: p,
            grant: g,
            epoch: 9,
        };
        // Nothing newer: the late success lands (watchdog expiry alone is no
        // reason to make the user redo a login II already bound).
        assert!(!superseded_by_newer(&state(None, None), 3));
        assert!(!superseded_by_newer(&state(Some(pending(3)), None), 3));
        assert!(!superseded_by_newer(&state(None, Some(grant(2))), 3));
        // A newer pending handshake or completed grant wins over the stale one.
        assert!(superseded_by_newer(&state(Some(pending(4)), None), 3));
        assert!(superseded_by_newer(&state(None, Some(grant(4))), 3));
    }

    // The handshake window is exactly HANDSHAKE_TTL: a pending flow older than
    // that is expired (the watchdog and the redeem gate both read this).
    #[test]
    fn pending_expires_after_the_handshake_ttl() {
        let pending = |age: Duration| Pending {
            session_id: "s".into(),
            url: "u".into(),
            callback_url: "c".into(),
            started: Instant::now() - age,
            redeeming: false,
            shutdown: Arc::new(Notify::new()),
            epoch: 1,
        };
        assert!(!pending(Duration::from_secs(1)).expired());
        assert!(pending(HANDSHAKE_TTL + Duration::from_secs(1)).expired());
    }
}
