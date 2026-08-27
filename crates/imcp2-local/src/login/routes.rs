//! The transient loopback listener's HTTP surface — the three login-handshake
//! routes (pinned callback page, slim redeem, the #4091 allow-list) plus the
//! Host-validation middleware. Up only for the duration of one handshake; the
//! MCP tool surface never rides HTTP.

use axum::extract::State;
use axum::http::{HeaderName, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use imcp2_core::iiconnect::{self, RedeemBody, AUTH_CALLBACKS_WELL_KNOWN};
use serde_json::json;

use super::{Grant, LoginDriver, CONTACT_EMAIL};

/// The three transient loopback routes — the login handshake's whole HTTP
/// surface. `callback_url` is this listener's own callback, echoed verbatim in
/// the allow-list document; `authority` is its `127.0.0.1:<port>` host, the
/// only `Host` header the listener accepts.
pub(super) fn login_router(driver: LoginDriver, callback_url: String, authority: String) -> Router {
    Router::new()
        .route("/callback", get(callback_page).options(preflight))
        .route("/redeem", post(redeem).options(preflight))
        .route(
            AUTH_CALLBACKS_WELL_KNOWN,
            get(auth_callbacks).options(preflight),
        )
        // Anti-DNS-rebinding, per the design's loopback hardening (the local
        // analogue of the hosted server's Host allow-list): a page on an
        // attacker's hostname that rebinds to 127.0.0.1 reaches this port
        // with `Host: attacker.example` — every URL this flow hands out
        // carries exactly one authority, so anything else is rejected before
        // routing. (Even without this the routes are largely inert to a
        // rebinder — `/redeem` requires the connect `state` and a chain
        // targeting the in-process `X` — this closes the door outright.)
        .layer(axum::middleware::from_fn_with_state(
            authority,
            require_own_host,
        ))
        .with_state(RouteCtx {
            driver,
            callback_url,
        })
}

/// Reject any request whose `Host` header is not this listener's own
/// `127.0.0.1:<port>` authority (exact string match, like II's allow-list).
async fn require_own_host(
    State(expected): State<String>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let ok = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|host| host == expected);
    if !ok {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "wrong Host for this login listener",
        )
            .into_response();
    }
    next.run(req).await
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
    let page = iiconnect::pinned_callback_page("/redeem", CONTACT_EMAIL);
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

/// The header Chrome's Private Network Access check requires on a preflight
/// response before it will let a PUBLIC page touch a private (loopback) one.
const ALLOW_PRIVATE_NETWORK: &str = "access-control-allow-private-network";

/// CORS preflight for every route on this listener.
///
/// II's frontend runs on the public `https://id.ai` origin and fetches the
/// #4091 allow-list from `http://127.0.0.1:<port>` — a **private-network
/// request** in Chrome's Private Network Access rules. Those force an
/// `OPTIONS` preflight carrying `Access-Control-Request-Private-Network:
/// true` even though the GET is otherwise "simple", and block the fetch
/// unless the preflight answers `Access-Control-Allow-Private-Network: true`.
/// Without this the allow-list is unreachable *from a browser* — `curl` and
/// the e2e harness's HTTP client never preflight, which is exactly what made
/// the gap easy to miss — so II cannot validate the callback and rejects
/// every connect as "missing information". The same applies to the tab
/// navigation into `/callback` where Chrome enforces PNA for navigations,
/// hence the preflight on all three routes rather than the allow-list alone.
async fn preflight() -> Response {
    let mut resp = axum::http::StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    h.insert(
        HeaderName::from_static(ALLOW_PRIVATE_NETWORK),
        HeaderValue::from_static("true"),
    );
    h.insert(
        axum::http::header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
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

    // Claim atomically (re-checking: the flow may have moved while parsing).
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
            }
            _ => {
                return redeem_err(
                    "This sign-in is unknown or already used. Ask the agent to authenticate again.",
                )
            }
        }
    }

    // The network call + local commit, SERIALIZED across flows (see
    // `Inner::registration`): II's `mcp_register_v2` replaces the anchor's
    // previous grant, so whichever registration settles at II last is the
    // live one — and because every register-then-commit runs alone inside
    // this lock, the commit order equals the settle order, and the local
    // slot always names the session II actually honors. In particular a
    // flow that timed out locally while its register was in flight either
    // settles BEFORE a replacement (which then overwrites it, at II and
    // here) or AFTER it (and then the late registration is the live grant,
    // and committing it here is exactly right). The per-flow single-flight
    // claim above stays: it stops a page double-submit; this lock orders
    // DISTINCT flows.
    let _registration = driver.inner.registration.lock().await;
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
            driver
                .inner
                .slot
                .set(body.state.clone(), outcome.expiration_ns);
            state.grant = Some(Grant {
                session_id: body.state.clone(),
                principal,
                permissions: outcome.permissions,
                expiration_ns: outcome.expiration_ns,
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
