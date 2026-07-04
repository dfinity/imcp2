//! OAuth 2.1 authorization server for the MCP endpoint, with **Internet Identity**
//! as the login mechanism, using II's session-key registration handshake.
//!
//! II's `/mcp` handshake registers the session key under the user's own auth and,
//! if we ask, navigates the browser back to a `finish_url` on our origin (see
//! `docs/mcp-server-guide.md` §2a/§2c / dfinity/internet-identity#4086). We use
//! that hook to serve two flows, so any MCP client works:
//!
//!   * **Authorization code (finish redirect)** — for redirect-based clients
//!     (e.g. Claude.ai). `/oauth/authorize` redirects to II's handshake; the
//!     key-request response carries a `finish_url`, so after `mcp_register` II
//!     navigates the browser to `/oauth/finish`, which confirms registration,
//!     mints a PKCE-bound code, and 302s to the client's `redirect_uri`.
//!   * **Device authorization grant (RFC 8628)** — for clients that can poll the
//!     token endpoint: `/oauth/device_authorization` → `device_code` +
//!     `verification_uri`; the user opens it (launching the same II handshake, no
//!     `finish_url`); the client polls `/oauth/token` until the grant is live.
//!
//! Connect handshake (Phase 1b): `/oauth/connect/callback` serves the two
//! cross-origin JSON POSTs II makes — a key request `{state}` → `{public_key
//! [, finish_url]}` (a fresh session keypair minted per connection) and a
//! completion notification `{state, expiration}` → mark the grant live. We never
//! receive or verify a delegation chain, and never call `mcp_register` (II's
//! frontend does, under the user's own authentication).
//!
//! Implemented: dynamic client registration, PKCE (S256) enforced, short-lived
//! codes/device codes, 1h access tokens, session-key-bound principal.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Json, Response},
    Form,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::identities::Identities;

/// How long an authorization request (auth-code or device) and its pending II
/// handshake stay valid before the user must restart.
const CONNECT_TTL: Duration = Duration::from_secs(600);
/// Lifetime of a minted authorization code (auth-code flow).
const CODE_TTL: Duration = Duration::from_secs(120);
/// Minimum seconds a client should wait between token polls (RFC 8628 `interval`).
const POLL_INTERVAL_SECS: u64 = 5;
/// Access-token lifetime (also the II grant's default, 1h).
const TOKEN_TTL: Duration = Duration::from_secs(3600);
/// `ttl` (seconds) requested for the II grant. Clamped by II to [600, 2592000].
const GRANT_TTL_SECS: u64 = 3600;

/// RFC 8628 device-code grant type.
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Public base URL clients use to reach this server. Override with PUBLIC_URL.
pub fn base_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}

/// A registered OAuth client (RFC 7591): the redirect URIs it declared. The
/// auth-code flow only redirects a code to one of these (exact match), so the
/// server is not an open redirector and needs no hardcoded host allowlist.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientReg {
    #[serde(default)]
    redirect_uris: Vec<String>,
}

/// File the dynamic client registrations are persisted to. RFC 7591 clients are
/// long-lived (they cache their `client_id`), so registrations must survive a
/// restart — unlike codes/tokens/connects, which are short-lived and stay in
/// memory. Override with `OAUTH_CLIENTS_FILE`.
fn clients_file() -> String {
    std::env::var("OAUTH_CLIENTS_FILE").unwrap_or_else(|_| "oauth-clients.json".to_string())
}

fn load_clients() -> HashMap<String, ClientReg> {
    match std::fs::read(clients_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("could not parse {}: {e}; starting with no clients", clients_file());
            HashMap::new()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => {
            tracing::warn!("could not read {}: {e}; starting with no clients", clients_file());
            HashMap::new()
        }
    }
}

/// Best-effort write-through of the registration store. A failure (e.g. a
/// read-only filesystem) only means registrations don't survive a restart — the
/// client re-registers — so log and carry on.
fn persist_clients(clients: &HashMap<String, ClientReg>) {
    match serde_json::to_vec_pretty(clients) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(clients_file(), bytes) {
                tracing::warn!("could not persist {}: {e}", clients_file());
            }
        }
        Err(e) => tracing::warn!("could not serialize client registrations: {e}"),
    }
}

/// Acceptance rule for a redirect (OAuth 2.1): the client must be REGISTERED,
/// and the requested redirect must either exactly match a registered URI, or be
/// a loopback URI matching a registered loopback URI on everything but the
/// port. RFC 8252 §7.3 requires the any-port latitude — native clients bind an
/// ephemeral loopback port at runtime, so the exact port can't be registered —
/// but registration itself is still required, so every client that can receive
/// a code is on record (DCR is open, so this is an audit trail, not vetting).
fn redirect_allowed(reg: Option<&ClientReg>, redirect_uri: &str) -> bool {
    let Some(reg) = reg else { return false };
    reg.redirect_uris
        .iter()
        .any(|u| u == redirect_uri || loopback_match(u, redirect_uri))
}

/// Whether `requested` is a loopback redirect matching the registered loopback
/// URI `registered` on scheme, host, path, and query — any port (RFC 8252 §7.3).
/// Both sides must independently pass [`is_loopback_redirect`], so a registered
/// hosted URI grants no loopback latitude and look-alike hosts are rejected.
fn loopback_match(registered: &str, requested: &str) -> bool {
    if !is_loopback_redirect(registered) || !is_loopback_redirect(requested) {
        return false;
    }
    let (Ok(a), Ok(b)) = (url::Url::parse(registered), url::Url::parse(requested)) else {
        return false;
    };
    a.host_str() == b.host_str() && a.path() == b.path() && a.query() == b.query()
}

#[derive(Clone)]
pub struct AuthStore {
    clients: Arc<RwLock<HashMap<String, ClientReg>>>,
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    /// Auth-code connects in flight, keyed by `session_id` (= the II connect
    /// `state`). Serve the poll bridge for redirect-based clients.
    authz: Arc<RwLock<HashMap<String, AuthzPending>>>,
    /// Minted authorization codes awaiting exchange at `/oauth/token`.
    codes: Arc<RwLock<HashMap<String, CodeGrant>>>,
    /// Device-authorization grants in flight, keyed by `session_id`.
    devices: Arc<RwLock<HashMap<String, DeviceAuth>>>,
    /// Shared with the MCP tools: the session's backend key / grant expiration
    /// live here (keyed by `session_id`) for the tools to sign with.
    identities: Identities,
}

/// An auth-code connect awaiting the user's II handshake (poll bridge).
#[derive(Clone, Debug)]
struct AuthzPending {
    client_id: String,
    redirect_uri: String,
    /// The OAuth client's own `state`, echoed back on the final redirect.
    client_state: String,
    code_challenge: Option<String>,
    created: Instant,
    /// Grant confirmed live (completion POST or a signed-call fallback).
    live: bool,
    /// The authorization code minted once the grant is live (idempotent polls).
    code: Option<String>,
}

/// A minted authorization code awaiting exchange.
#[derive(Clone, Debug)]
struct CodeGrant {
    client_id: String,
    code_challenge: Option<String>,
    session_id: String,
    created: Instant,
}

/// A device-authorization grant awaiting the user's II handshake.
#[derive(Clone, Debug)]
struct DeviceAuth {
    device_code: String,
    user_code: String,
    session_id: String,
    #[allow(dead_code)]
    client_id: Option<String>,
    scope: Option<String>,
    code_challenge: Option<String>,
    created: Instant,
    live: bool,
    last_poll: Option<Instant>,
}

#[derive(Clone, Debug)]
struct TokenInfo {
    principal: String,
    session_id: String,
    created: Instant,
    ttl: Duration,
}

impl AuthStore {
    pub fn new(identities: Identities) -> Self {
        Self {
            clients: Arc::new(RwLock::new(load_clients())),
            tokens: Arc::default(),
            authz: Arc::default(),
            codes: Arc::default(),
            devices: Arc::default(),
            identities,
        }
    }

    /// Whether `redirect_uri` is acceptable for `client_id`: the client must be
    /// registered, and the redirect must match a registered URI (exactly, or
    /// port-agnostically for loopback per RFC 8252 §7.3).
    async fn validate_client(&self, client_id: &str, redirect_uri: &str) -> bool {
        redirect_allowed(self.clients.read().await.get(client_id), redirect_uri)
    }

    /// The verified principal + session id behind a bearer token, if valid.
    pub async fn session_for_token(&self, token: &str) -> Option<(String, String)> {
        let tokens = self.tokens.read().await;
        let info = tokens.get(token)?;
        (info.created.elapsed() < info.ttl).then(|| (info.principal.clone(), info.session_id.clone()))
    }

    /// Whether this connection's grant is live: the completion POST arrived, or
    /// (best-effort fallback) a signed `mcp_get_accounts` now succeeds. Takes no
    /// lock across the network call.
    async fn grant_live(&self, session_id: &str, flag: bool) -> bool {
        flag || self.identities.grant_is_live(session_id).await
    }
}

// ---- Authorization code (poll bridge) ----------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    #[serde(default)]
    response_type: Option<String>,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    scope: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    resource: Option<String>,
}

/// GET /oauth/authorize — the redirect-based entry point. Validates the client
/// and PKCE, records a pending connect, and redirects the browser to II's `/mcp`
/// handshake; II navigates back to our `finish_url` once it registers the key.
pub async fn authorize(State(store): State<AuthStore>, Query(q): Query<AuthorizeQuery>) -> Response {
    // Only the authorization-code response type is supported.
    match q.response_type.as_deref() {
        Some("code") => {}
        Some(_) => return oauth_err(StatusCode::BAD_REQUEST, "unsupported_response_type", "only response_type=code"),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "response_type=code required"),
    }
    if !store.validate_client(&q.client_id, &q.redirect_uri).await {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "unknown client_id / redirect_uri");
    }
    // OAuth 2.1: PKCE is required for public clients.
    let Some(code_challenge) = q.code_challenge.clone() else {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "code_challenge (PKCE S256) required");
    };
    if let Some(m) = &q.code_challenge_method {
        if m != "S256" {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "only code_challenge_method=S256 is supported");
        }
    }

    let session_id = format!("sess-{}", Uuid::new_v4());
    store.authz.write().await.insert(
        session_id.clone(),
        AuthzPending {
            client_id: q.client_id.clone(),
            redirect_uri: q.redirect_uri.clone(),
            client_state: q.state.clone().unwrap_or_default(),
            code_challenge: Some(code_challenge),
            created: Instant::now(),
            live: false,
            code: None,
        },
    );

    // Redirect the browser to II's handshake. II navigates back to our
    // `finish_url` (returned in the key-request response) once it registers.
    js_redirect(&ii_mcp_url(&session_id))
}

#[derive(Debug, Deserialize)]
pub struct FinishQuery {
    /// The pending-auth id (= session id) carried by `finish_url`.
    id: String,
    /// Retry counter, so the "finishing" reload is bounded.
    #[serde(default)]
    r: u32,
}

/// GET /oauth/finish — II navigates the browser here after registering the
/// session key (this is the `finish_url` returned in the key-request response).
/// Arrival is NOT proof of registration: confirm it (the completion POST flag, or
/// a signed `mcp_get_accounts` that returns `Ok`), then mint the authorization
/// code and 302 to the client's `redirect_uri` with `code` + the client's `state`.
pub async fn finish(State(store): State<AuthStore>, Query(q): Query<FinishQuery>) -> Response {
    // Snapshot without holding the lock across the network probe.
    let snap = {
        let authz = store.authz.read().await;
        authz.get(&q.id).map(|a| {
            (
                a.created.elapsed() >= CONNECT_TTL,
                a.live,
                a.code.clone(),
                a.client_id.clone(),
                a.redirect_uri.clone(),
                a.client_state.clone(),
                a.code_challenge.clone(),
            )
        })
    };
    let Some((expired, live_flag, existing_code, client_id, redirect_uri, client_state, code_challenge)) = snap else {
        return connect_error("unknown or already-used connect request — restart from your client");
    };
    if expired {
        return connect_error("connect request expired — restart from your client");
    }
    // Idempotent: if the code was already minted, just redirect again.
    if let Some(code) = existing_code {
        return redirect_302(&build_redirect(&redirect_uri, &code, &client_state));
    }
    // Confirm registration (best-effort signed-call fallback, no lock held). If it
    // isn't confirmable yet (a race with II's registration/propagation), reload
    // shortly — bounded so we don't loop forever.
    if !store.grant_live(&q.id, live_flag).await {
        if q.r >= 8 {
            return connect_error("could not confirm the connection with Internet Identity — reconnect and try again");
        }
        return finishing_page(&q.id, q.r + 1);
    }

    // Reserve the code under the `authz` lock, then insert into `codes` AFTER
    // releasing it — never hold one map's lock while awaiting the other's, so the
    // lock order is consistent with `token_authorization_code` (no deadlock).
    let fresh = format!("mcp-code-{}", Uuid::new_v4());
    let (code, newly_minted) = {
        let mut authz = store.authz.write().await;
        let Some(a) = authz.get_mut(&q.id) else {
            return connect_error("connect request vanished — restart from your client");
        };
        match &a.code {
            Some(existing) => (existing.clone(), false),
            None => {
                a.code = Some(fresh.clone());
                (fresh, true)
            }
        }
    };
    if newly_minted {
        store.codes.write().await.insert(
            code.clone(),
            CodeGrant {
                client_id,
                code_challenge,
                session_id: q.id.clone(),
                created: Instant::now(),
            },
        );
    }
    tracing::info!(session_id = %q.id, "grant confirmed; issued authorization code");
    redirect_302(&build_redirect(&redirect_uri, &code, &client_state))
}

/// A tiny self-reloading page shown while we wait for II's registration to become
/// confirmable, then it re-hits `/oauth/finish` (bounded by the retry counter).
fn finishing_page(id: &str, next_try: u32) -> Response {
    let url = js_escape(&format!("/oauth/finish?id={}&r={}", urlencoding::encode(id), next_try));
    Html(format!(
        "<!DOCTYPE html><meta charset=utf-8><title>Finishing…</title>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto\">\
         <p>Finishing sign-in…</p>\
         <script>setTimeout(function(){{location.replace(\"{url}\")}},1200)</script></body>"
    ))
    .into_response()
}

/// A 302 to an absolute URL (used for the top-level hop back to the OAuth client).
fn redirect_302(url: &str) -> Response {
    (StatusCode::FOUND, [(axum::http::header::LOCATION, url.to_string())]).into_response()
}

fn build_redirect(redirect_uri: &str, code: &str, client_state: &str) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut r = format!("{redirect_uri}{sep}code={}", urlencoding::encode(code));
    if !client_state.is_empty() {
        r.push_str(&format!("&state={}", urlencoding::encode(client_state)));
    }
    r
}

// ---- Device authorization: start the II handshake -----------------------

#[derive(Debug, Deserialize)]
pub struct DeviceAuthzForm {
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
}

/// POST /oauth/device_authorization (RFC 8628 §3.1–3.2) — mint a device code and
/// point the user at the verification URI that launches II's `/mcp` handshake.
pub async fn device_authorization(State(store): State<AuthStore>, Form(req): Form<DeviceAuthzForm>) -> Response {
    // We only verify PKCE with S256; reject any other method up front, and
    // require a challenge whenever a method is named.
    if let Some(method) = &req.code_challenge_method {
        if method != "S256" {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "only code_challenge_method=S256 is supported");
        }
        if req.code_challenge.is_none() {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "code_challenge required when code_challenge_method is set");
        }
    }

    let session_id = format!("sess-{}", Uuid::new_v4());
    let device_code = format!("dc-{}", Uuid::new_v4());
    let user_code = Uuid::new_v4().simple().to_string()[..8].to_uppercase();

    store.devices.write().await.insert(
        session_id.clone(),
        DeviceAuth {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            session_id: session_id.clone(),
            client_id: req.client_id.clone(),
            scope: req.scope.clone().filter(|s| !s.is_empty()),
            code_challenge: req.code_challenge.clone(),
            created: Instant::now(),
            live: false,
            last_poll: None,
        },
    );

    let base = base_url();
    let verification_uri = format!("{base}/oauth/device");
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
    Json(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": CONNECT_TTL.as_secs(),
        "interval": POLL_INTERVAL_SECS,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct DeviceVerifyQuery {
    #[serde(default)]
    user_code: Option<String>,
}

/// GET /oauth/device — the user opens this (via `verification_uri_complete`).
/// With a valid `user_code` it launches II's `/mcp` handshake; otherwise it
/// offers a minimal form to enter the code.
pub async fn device_verify(State(store): State<AuthStore>, Query(q): Query<DeviceVerifyQuery>) -> Response {
    let Some(user_code) = q.user_code.filter(|c| !c.is_empty()) else {
        return device_code_form();
    };
    let user_code = user_code.trim().to_uppercase();

    let session_id = {
        let devices = store.devices.read().await;
        devices
            .values()
            .find(|d| d.user_code == user_code && d.created.elapsed() < CONNECT_TTL)
            .map(|d| d.session_id.clone())
    };
    match session_id {
        Some(sid) => js_redirect(&ii_mcp_url(&sid)),
        None => connect_error("unknown or expired code — restart the connection from your client"),
    }
}

/// A minimal manual code-entry page for the bare `verification_uri`.
fn device_code_form() -> Response {
    Html(
        "<!DOCTYPE html><meta charset=utf-8><body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto\">\
         <h1>Connect Internet Identity</h1>\
         <form method=get action=\"/oauth/device\">\
         <p>Enter the code shown by your client:</p>\
         <input name=user_code autofocus style=\"font-size:1.2rem;padding:.4rem\">\
         <button type=submit style=\"font-size:1.2rem;padding:.4rem 1rem\">Continue</button>\
         </form></body>"
            .to_string(),
    )
    .into_response()
}

/// Build II's `/mcp` handshake URL for a connection. Everything is in the URL
/// fragment (never sent to II's servers): the callback on our origin, the
/// single-use `state` (= session id), and the requested grant `ttl` in SECONDS.
/// NO key material is put in the link.
fn ii_mcp_url(session_id: &str) -> String {
    let base = base_url();
    let callback = format!("{base}/oauth/connect/callback");
    format!(
        "{ii}/mcp#callback={cb}&state={st}&ttl={ttl}",
        ii = crate::identities::ii_url(),
        cb = urlencoding::encode(&callback),
        st = urlencoding::encode(session_id),
        ttl = GRANT_TTL_SECS,
    )
}

// ---- Connect callback: II's two cross-origin JSON POSTs -----------------

#[derive(Debug, Deserialize)]
pub struct ConnectCallback {
    /// The single-use connect state (= session id).
    state: String,
    /// Present only on the completion notification; a decimal string of ns since
    /// the epoch (u64 ns overflows JSON numbers, so it is a string on the wire).
    #[serde(default)]
    expiration: Option<String>,
}

/// POST /oauth/connect/callback — II's frontend makes TWO cross-origin JSON
/// POSTs here, distinguished by the `expiration` field:
///   (a) key request `{state}` → 200 `{public_key}` (fresh session keypair);
///   (b) completion `{state, expiration}` → mark the grant live; any 2xx.
/// Never returns a redirect (the response is consumed by `fetch()`), and never
/// receives or verifies a delegation chain.
pub async fn connect_callback(State(store): State<AuthStore>, Json(body): Json<ConnectCallback>) -> Response {
    match &body.expiration {
        // (a) Key request — require a valid, unexpired pending connection (reject
        // unknown/replayed/expired state with a non-2xx so II aborts), then
        // generate (lazily) this connection's session keypair and return its
        // public key for II's frontend to register. For the auth-code flow, also
        // return `finish_url` so II navigates the browser back to us to close the
        // OAuth loop; the device flow omits it (the II tab finishes on its own).
        None => {
            let is_authcode = store.connect_known_authz(&body.state).await;
            if !is_authcode && !store.connect_known_device(&body.state).await {
                return (StatusCode::FORBIDDEN, Json(json!({ "error": "invalid_state" }))).into_response();
            }
            let public_key = store.identities.session_pubkey_b64(&body.state).await;
            let mut resp = json!({ "public_key": public_key });
            if is_authcode {
                resp["finish_url"] =
                    json!(format!("{}/oauth/finish?id={}", base_url(), urlencoding::encode(&body.state)));
            }
            (StatusCode::OK, Json(resp)).into_response()
        }
        // (b) Completion notification — best-effort. Mark the grant live if the
        // connection is still known; tolerate a missing/expired state (e.g. the
        // grant was already consumed via the signed-call fallback) with a 2xx, so
        // a late completion POST doesn't make II treat an otherwise-successful
        // connect as failed. Never create a session for an unknown state.
        Some(exp) => {
            let known = store.mark_live(&body.state).await;
            if known {
                match exp.trim().parse::<u64>() {
                    Ok(exp_ns) => store.identities.set_grant_expiration(&body.state, exp_ns).await,
                    Err(_) => tracing::warn!("connect completion had unparseable expiration"),
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

impl AuthStore {
    /// Whether `state` names a known, unexpired auth-code pending connect.
    async fn connect_known_authz(&self, state: &str) -> bool {
        self.authz
            .read()
            .await
            .get(state)
            .is_some_and(|a| a.created.elapsed() < CONNECT_TTL)
    }

    /// Whether `state` names a known, unexpired device pending connect.
    async fn connect_known_device(&self, state: &str) -> bool {
        self.devices
            .read()
            .await
            .get(state)
            .is_some_and(|d| d.created.elapsed() < CONNECT_TTL)
    }

    /// Mark the pending connect live in whichever flow owns `state`; returns
    /// whether it was known.
    async fn mark_live(&self, state: &str) -> bool {
        let mut known = false;
        if let Some(a) = self.authz.write().await.get_mut(state) {
            a.live = true;
            known = true;
        }
        if let Some(d) = self.devices.write().await.get_mut(state) {
            d.live = true;
            known = true;
        }
        known
    }
}

/// Top-level redirect via a script-initiated navigation (`location.replace`)
/// rather than an HTTP `Location` header, so the II `/mcp` URL's fragment (`#…`)
/// is preserved (a `Location` redirect drops it in some clients).
fn js_redirect(url: &str) -> Response {
    Html(format!(
        "<!DOCTYPE html><meta charset=utf-8><script>location.replace(\"{}\")</script>",
        js_escape(url)
    ))
    .into_response()
}

/// Escape a string for embedding inside a double-quoted JS string literal.
fn js_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('<', "\\x3c")
}

fn connect_error(message: &str) -> Response {
    let safe = message.replace('<', "&lt;");
    (
        StatusCode::BAD_REQUEST,
        Html(format!(
            "<!DOCTYPE html><meta charset=utf-8><body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto\"><h1>Could not connect</h1><p>{safe}</p></body>"
        )),
    )
        .into_response()
}

// ---- Token: exchange a code, or poll a device grant ---------------------

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    device_code: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    code_verifier: Option<String>,
}

/// POST /oauth/token — `authorization_code` (poll-bridge clients) or the RFC 8628
/// `device_code` grant.
pub async fn token(State(store): State<AuthStore>, Form(req): Form<TokenForm>) -> Response {
    match req.grant_type.as_str() {
        "authorization_code" => token_authorization_code(store, req).await,
        g if g == DEVICE_GRANT_TYPE => token_device_code(store, req).await,
        _ => oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type", "authorization_code or device_code"),
    }
}

async fn token_authorization_code(store: AuthStore, req: TokenForm) -> Response {
    let grant = match store.codes.write().await.remove(&req.code) {
        Some(g) if g.created.elapsed() < CODE_TTL => g,
        Some(_) => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code expired"),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown or used code"),
    };
    if !req.client_id.is_empty() && req.client_id != grant.client_id {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "client_id mismatch");
    }
    // Enforce PKCE (a challenge is always stored by `authorize`).
    if let Some(challenge) = &grant.code_challenge {
        let verifier = match &req.code_verifier {
            Some(v) => v,
            None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code_verifier required"),
        };
        if &pkce_s256(verifier) != challenge {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
        }
    }
    store.authz.write().await.remove(&grant.session_id);
    issue_token(&store, &grant.session_id, None).await
}

async fn token_device_code(store: AuthStore, req: TokenForm) -> Response {
    if req.device_code.is_empty() {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "device_code required");
    }
    let (session_id, code_challenge, scope) = {
        let mut devices = store.devices.write().await;
        let Some(d) = devices.values_mut().find(|d| d.device_code == req.device_code) else {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown or used device_code");
        };
        if d.created.elapsed() >= CONNECT_TTL {
            return oauth_err(StatusCode::BAD_REQUEST, "expired_token", "device_code expired — restart");
        }
        if !req.client_id.is_empty() {
            if let Some(cid) = &d.client_id {
                if cid != &req.client_id {
                    return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "client_id mismatch");
                }
            }
        }
        if let Some(last) = d.last_poll {
            if last.elapsed() < Duration::from_secs(POLL_INTERVAL_SECS) {
                return oauth_err(StatusCode::BAD_REQUEST, "slow_down", "poll no faster than the interval");
            }
        }
        d.last_poll = Some(Instant::now());
        (d.session_id.clone(), d.code_challenge.clone(), d.scope.clone())
    };

    let live_flag = store
        .devices
        .read()
        .await
        .values()
        .find(|d| d.device_code == req.device_code)
        .map(|d| d.live)
        .unwrap_or(false);
    if !store.grant_live(&session_id, live_flag).await {
        return oauth_err(StatusCode::BAD_REQUEST, "authorization_pending", "waiting for Internet Identity");
    }

    if let Some(challenge) = &code_challenge {
        let verifier = match &req.code_verifier {
            Some(v) => v,
            None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code_verifier required"),
        };
        if &pkce_s256(verifier) != challenge {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
        }
    }

    store.devices.write().await.retain(|_, d| d.device_code != req.device_code);
    issue_token(&store, &session_id, scope).await
}

/// Mint + store an access token bound to the session key's principal.
async fn issue_token(store: &AuthStore, session_id: &str, scope: Option<String>) -> Response {
    let principal = store
        .identities
        .session_principal(session_id)
        .await
        .unwrap_or_else(|| "unknown".to_string());

    let access_token = format!("mcp-token-{}", Uuid::new_v4());
    store.tokens.write().await.insert(
        access_token.clone(),
        TokenInfo {
            principal: principal.clone(),
            session_id: session_id.to_string(),
            created: Instant::now(),
            ttl: TOKEN_TTL,
        },
    );
    tracing::info!(%principal, "issued MCP access token");

    let mut resp = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL.as_secs(),
    });
    if let Some(scope) = scope {
        resp["scope"] = json!(scope);
    }
    Json(resp).into_response()
}

fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ---- Dynamic client registration ---------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
}

/// POST /oauth/register (RFC 7591). `redirect_uris` are stored for the auth-code
/// flow; a device-only client may register without any.
pub async fn register(State(store): State<AuthStore>, Json(req): Json<RegisterRequest>) -> Response {
    let client_id = format!("client-{}", Uuid::new_v4());
    let snapshot = {
        let mut clients = store.clients.write().await;
        clients.insert(client_id.clone(), ClientReg { redirect_uris: req.redirect_uris.clone() });
        clients.clone()
    };
    tokio::task::spawn_blocking(move || persist_clients(&snapshot)).await.ok();

    // Honour the requested grant types (intersected with what we support); fall
    // back to both if the client didn't ask for any.
    let supported = ["authorization_code", DEVICE_GRANT_TYPE];
    let granted: Vec<String> = if req.grant_types.is_empty() {
        supported.iter().map(|s| s.to_string()).collect()
    } else {
        req.grant_types
            .iter()
            .filter(|g| supported.contains(&g.as_str()))
            .cloned()
            .collect()
    };

    // Public client (PKCE, no secret): OMIT client_secret entirely (returning
    // null breaks clients that validate it as a string).
    let mut resp = json!({
        "client_id": client_id,
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": granted,
        "response_types": ["code"],
    });
    if let Some(name) = req.client_name {
        resp["client_name"] = json!(name);
    }
    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---- Discovery metadata -------------------------------------------------

/// GET /.well-known/oauth-authorization-server
pub async fn authorization_server_metadata() -> Response {
    let base = base_url();
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "device_authorization_endpoint": format!("{base}/oauth/device_authorization"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", DEVICE_GRANT_TYPE],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
    .into_response()
}

/// GET /.well-known/oauth-protected-resource
pub async fn protected_resource_metadata() -> Response {
    let base = base_url();
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
    }))
    .into_response()
}

// ---- Bearer-token gate for /mcp -----------------------------------------

/// The verified principal + session id of the authenticated MCP session,
/// injected into request extensions so tools can attribute actions and bind
/// per-session delegated identities.
#[derive(Clone, Debug)]
pub struct AuthedSession {
    pub session_id: String,
}

pub async fn require_token(State(store): State<AuthStore>, mut request: Request<Body>, next: Next) -> Response {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_owned);

    let session = match token {
        Some(t) => store.session_for_token(&t).await,
        None => None,
    };

    match session {
        Some((principal, session_id)) => {
            tracing::debug!(%principal, %session_id, "authenticated MCP request");
            request.extensions_mut().insert(AuthedSession { session_id });
            next.run(request).await
        }
        None => {
            let challenge = format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                base_url()
            );
            (
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, challenge)],
                Json(json!({ "error": "invalid_token" })),
            )
                .into_response()
        }
    }
}

/// An `http://` loopback redirect (any port), matched on the parsed **host** so
/// look-alikes can't slip through. Parsing (not `strip_prefix`) is what defends
/// against authority tricks: `http://localhost.evil.com`, `http://localhost@evil.com`,
/// and the userinfo-with-port form `http://localhost:1234@evil.com` all parse to
/// host `evil.com` (or carry userinfo) and are rejected.
fn is_loopback_redirect(redirect_uri: &str) -> bool {
    let Ok(url) = url::Url::parse(redirect_uri) else {
        return false;
    };
    url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

fn oauth_err(status: StatusCode, error: &str, desc: &str) -> Response {
    (status, Json(json!({ "error": error, "error_description": desc }))).into_response()
}

/// Re-export for additional JSON fields.
pub type _JsonValue = Value;

#[cfg(test)]
mod tests {
    use super::{build_redirect, is_loopback_redirect, pkce_s256, redirect_allowed, ClientReg};

    /// RFC 7636 Appendix B test vector.
    #[test]
    fn pkce_s256_matches_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256(verifier), expected);
    }

    #[test]
    fn redirect_requires_registration() {
        let reg = ClientReg {
            redirect_uris: vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
        };
        // Hosted redirects: exact registered match only.
        assert!(redirect_allowed(Some(&reg), "https://claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_allowed(Some(&reg), "https://claude.ai/api/mcp/auth_callback/x"));
        // Unregistered clients get nothing — not even loopback.
        assert!(!redirect_allowed(None, "https://claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_allowed(None, "http://127.0.0.1:51000/callback"));
        assert!(!redirect_allowed(None, "http://[::1]:8080/cb"));
    }

    /// A registered loopback redirect matches at ANY port (RFC 8252 §7.3 — the
    /// client binds an ephemeral port each run), but host and path must match,
    /// and a registered hosted URI grants no loopback latitude.
    #[test]
    fn registered_loopback_matches_any_port() {
        let reg = ClientReg {
            redirect_uris: vec!["http://localhost:54321/callback".to_string()],
        };
        assert!(redirect_allowed(Some(&reg), "http://localhost:54321/callback"));
        assert!(redirect_allowed(Some(&reg), "http://localhost:61832/callback"));
        assert!(redirect_allowed(Some(&reg), "http://localhost/callback"));
        // Different path or host (even another loopback host): rejected.
        assert!(!redirect_allowed(Some(&reg), "http://localhost:61832/other"));
        assert!(!redirect_allowed(Some(&reg), "http://127.0.0.1:61832/callback"));
        // Look-alike hosts fail is_loopback_redirect on the requested side.
        assert!(!redirect_allowed(Some(&reg), "http://localhost.evil.com:54321/callback"));
        // A registered HOSTED uri gives no loopback latitude.
        let hosted = ClientReg {
            redirect_uris: vec!["https://claude.ai/cb".to_string()],
        };
        assert!(!redirect_allowed(Some(&hosted), "http://localhost:1234/cb"));
    }

    #[test]
    fn loopback_rejects_lookalikes() {
        assert!(is_loopback_redirect("http://127.0.0.1:51000/callback"));
        assert!(is_loopback_redirect("http://[::1]:8080/cb"));
        assert!(!is_loopback_redirect("http://localhost.evil.com/cb"));
        assert!(!is_loopback_redirect("http://localhost@evil.com/cb"));
        assert!(!is_loopback_redirect("http://localhost:1234@evil.com/cb"));
        assert!(!is_loopback_redirect("https://evil.com/cb"));
    }

    #[test]
    fn build_redirect_encodes_code_and_state() {
        let r = build_redirect("https://claude.ai/cb", "mcp-code-1", "abc/def");
        assert_eq!(r, "https://claude.ai/cb?code=mcp-code-1&state=abc%2Fdef");
        // Appends with & when the redirect already has a query.
        let r2 = build_redirect("https://x.test/cb?foo=1", "c", "");
        assert_eq!(r2, "https://x.test/cb?foo=1&code=c");
    }
}
