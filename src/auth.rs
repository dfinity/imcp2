//! OAuth 2.1 authorization server for the MCP endpoint, with **Internet Identity**
//! as the login mechanism, using II's session-key registration handshake.
//!
//! II's new `/mcp` handshake has NO redirect back to this server — the II tab
//! runs two background `fetch()` POSTs to our callback and then "finishes on its
//! own" (see `docs/mcp-server-guide.md` / dfinity/internet-identity#4086). A
//! classic auth-code `redirect_uri` therefore can't be delivered. We model the
//! MCP client's login as the **OAuth 2.0 Device Authorization Grant (RFC 8628)**:
//! the client asks `/oauth/device_authorization` for a `device_code` + a
//! `verification_uri`, the user opens that URI (which launches II's `/mcp`
//! handshake), and the client polls `/oauth/token` until the grant is live.
//!
//! Connect handshake (Phase 1b): our `/oauth/connect/callback` serves the two
//! cross-origin JSON POSTs II makes — a key request `{state}` → `{public_key}`
//! (a fresh session keypair minted per connection) and a completion notification
//! `{state, expiration}` → mark the grant live. We never receive or verify a
//! delegation chain, and never call `mcp_register` (II's frontend does, under the
//! user's own authentication).
//!
//! Implemented: dynamic client registration, PKCE (S256) bound to the poll,
//! short-lived device codes, 1h access tokens, session-key-bound principal.

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

/// How long a device-authorization request (and its pending II handshake) stays
/// valid before the user must restart.
const DEVICE_CODE_TTL: Duration = Duration::from_secs(600);
/// Minimum seconds a client should wait between token polls (RFC 8628 `interval`).
const POLL_INTERVAL_SECS: u64 = 5;
/// Access-token lifetime (also the II grant's default, 1h).
const TOKEN_TTL: Duration = Duration::from_secs(3600);
/// `ttl` (seconds) requested for the II grant. Omitting would default to 3600;
/// we send it explicitly. Clamped by II to [600, 2592000].
const GRANT_TTL_SECS: u64 = 3600;

/// RFC 8628 device-code grant type.
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Public base URL clients use to reach this server. Override with PUBLIC_URL.
pub fn base_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}

/// A registered OAuth client (RFC 7591). Redirect URIs are recorded for
/// completeness but unused: the device grant has no redirect.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientReg {
    #[serde(default)]
    redirect_uris: Vec<String>,
}

/// File the dynamic client registrations are persisted to. RFC 7591 clients are
/// long-lived (they cache their `client_id`), so registrations must survive a
/// restart — unlike device codes/tokens, which are short-lived and stay in
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

#[derive(Clone)]
pub struct AuthStore {
    clients: Arc<RwLock<HashMap<String, ClientReg>>>,
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    /// Device-authorization grants in flight, keyed by `session_id` (which is
    /// also the II connect `state`). Holds the `device_code`/`user_code` used by
    /// the token poll and verification page.
    devices: Arc<RwLock<HashMap<String, DeviceAuth>>>,
    /// Shared with the MCP tools: the session's backend key / grant expiration
    /// live here (keyed by `session_id`) for the tools to sign with.
    identities: Identities,
}

/// A device-authorization grant awaiting the user's II handshake.
#[derive(Clone, Debug)]
struct DeviceAuth {
    device_code: String,
    user_code: String,
    /// The connection's session id; also the II connect `state`.
    session_id: String,
    #[allow(dead_code)]
    client_id: Option<String>,
    scope: Option<String>,
    /// PKCE challenge (S256), if the client supplied one; verified at token time.
    code_challenge: Option<String>,
    created: Instant,
    /// Verification page visited and II launched.
    launched: bool,
    /// Grant confirmed live (completion POST or a signed-call fallback).
    live: bool,
    /// Last token poll, for RFC 8628 `slow_down` enforcement.
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
            devices: Arc::default(),
            identities,
        }
    }

    /// The verified principal + session id behind a bearer token, if valid.
    pub async fn session_for_token(&self, token: &str) -> Option<(String, String)> {
        let tokens = self.tokens.read().await;
        let info = tokens.get(token)?;
        (info.created.elapsed() < info.ttl).then(|| (info.principal.clone(), info.session_id.clone()))
    }
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
pub async fn device_authorization(
    State(store): State<AuthStore>,
    Form(req): Form<DeviceAuthzForm>,
) -> Response {
    // We only verify PKCE with S256; reject any other method up front (rather
    // than storing the challenge and failing confusingly with S256 at token
    // time), and require a challenge whenever a method is named.
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
    // A short, human-typable code for the verification page.
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
            launched: false,
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
        "expires_in": DEVICE_CODE_TTL.as_secs(),
        "interval": POLL_INTERVAL_SECS,
    }))
    .into_response()
}

// ---- Verification page: launch II's /mcp handshake ----------------------

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
        let mut devices = store.devices.write().await;
        let entry = devices
            .values_mut()
            .find(|d| d.user_code == user_code && d.created.elapsed() < DEVICE_CODE_TTL);
        match entry {
            Some(d) => {
                d.launched = true;
                d.session_id.clone()
            }
            None => return connect_error("unknown or expired code — restart the connection from your client"),
        }
    };

    // Launch II's `/mcp` handshake. Everything is in the URL fragment (never sent
    // to II's servers): the callback on our origin, the single-use `state` (= the
    // session id), and the requested grant `ttl` in SECONDS. NO key material is
    // put in the link — the session key is minted inside the key-request callback.
    let base = base_url();
    let callback = format!("{base}/oauth/connect/callback");
    let ii_mcp_url = format!(
        "{ii}/mcp#callback={cb}&state={st}&ttl={ttl}",
        ii = crate::identities::ii_url(),
        cb = urlencoding::encode(&callback),
        st = urlencoding::encode(&session_id),
        ttl = GRANT_TTL_SECS,
    );
    js_redirect(&ii_mcp_url)
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

// ---- Connect callback: II's two cross-origin JSON POSTs -----------------

#[derive(Debug, Deserialize)]
pub struct ConnectCallback {
    /// The single-use connect state (= session id) set at device-authorization.
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
        // public key for II's frontend to register.
        None => {
            {
                let devices = store.devices.read().await;
                match devices.get(&body.state) {
                    Some(d) if d.created.elapsed() < DEVICE_CODE_TTL => {}
                    _ => {
                        return (StatusCode::FORBIDDEN, Json(json!({ "error": "invalid_state" }))).into_response()
                    }
                }
            }
            let public_key = store.identities.session_pubkey_b64(&body.state).await;
            (StatusCode::OK, Json(json!({ "public_key": public_key }))).into_response()
        }
        // (b) Completion notification — best-effort. Update the grant if the
        // connection is still known; tolerate a missing/expired state (e.g. the
        // grant was already consumed via the signed-call fallback) with a 2xx, so
        // a late completion POST doesn't make II treat an otherwise-successful
        // connect as failed. Never create a session for an unknown state.
        Some(exp) => {
            let known = {
                let mut devices = store.devices.write().await;
                match devices.get_mut(&body.state) {
                    Some(d) => {
                        d.live = true;
                        true
                    }
                    None => false,
                }
            };
            if known {
                match exp.trim().parse::<u64>() {
                    Ok(exp_ns) => store.identities.set_grant_expiration(&body.state, exp_ns).await,
                    // A malformed expiration is non-fatal: the grant may still be
                    // live (registration happened under the user's auth); a signed
                    // call is the source of truth.
                    Err(_) => tracing::warn!("connect completion had unparseable expiration"),
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

/// Top-level redirect via a script-initiated navigation (`location.replace`)
/// rather than an HTTP `Location` header, so the II `/mcp` URL's fragment (`#…`)
/// is preserved (a `Location` redirect drops it in some clients).
fn js_redirect(url: &str) -> Response {
    let safe = url
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\x3c");
    Html(format!(
        "<!DOCTYPE html><meta charset=utf-8><script>location.replace(\"{safe}\")</script>"
    ))
    .into_response()
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

// ---- Token: poll for the device grant -----------------------------------

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: String,
    #[serde(default)]
    device_code: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    code_verifier: Option<String>,
}

/// POST /oauth/token (RFC 8628 §3.4–3.5) — the client polls here with the device
/// code until the user finishes the II handshake, then receives the access token.
pub async fn token(State(store): State<AuthStore>, Form(req): Form<TokenForm>) -> Response {
    if req.grant_type != DEVICE_GRANT_TYPE {
        return oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type", "only the device_code grant");
    }
    if req.device_code.is_empty() {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "device_code required");
    }

    // Locate the device grant, enforce expiry + slow_down, and snapshot what we
    // need. Done means: completion POST arrived, or a signed call now succeeds.
    let (session_id, code_challenge, scope) = {
        let mut devices = store.devices.write().await;
        let Some(d) = devices.values_mut().find(|d| d.device_code == req.device_code) else {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown or used device_code");
        };
        if d.created.elapsed() >= DEVICE_CODE_TTL {
            return oauth_err(StatusCode::BAD_REQUEST, "expired_token", "device_code expired — restart");
        }
        if !req.client_id.is_empty() {
            if let Some(cid) = &d.client_id {
                if cid != &req.client_id {
                    return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "client_id mismatch");
                }
            }
        }
        // slow_down if polling faster than the advertised interval.
        if let Some(last) = d.last_poll {
            if last.elapsed() < Duration::from_secs(POLL_INTERVAL_SECS) {
                return oauth_err(StatusCode::BAD_REQUEST, "slow_down", "poll no faster than the interval");
            }
        }
        d.last_poll = Some(Instant::now());
        (d.session_id.clone(), d.code_challenge.clone(), d.scope.clone())
    };

    // Determine liveness. Prefer the completion-POST flag; fall back to a cheap
    // signed call (the completion POST is best-effort and may never arrive).
    let live = {
        let flag = store
            .devices
            .read()
            .await
            .values()
            .find(|d| d.device_code == req.device_code)
            .map(|d| d.live)
            .unwrap_or(false);
        flag || store.identities.grant_is_live(&session_id).await
    };
    if !live {
        return oauth_err(StatusCode::BAD_REQUEST, "authorization_pending", "waiting for Internet Identity");
    }

    // Enforce PKCE if the client bound one at device-authorization time.
    if let Some(challenge) = &code_challenge {
        let verifier = match &req.code_verifier {
            Some(v) => v,
            None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code_verifier required"),
        };
        if &pkce_s256(verifier) != challenge {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
        }
    }

    // Consume the device grant (single use) and issue the token, bound to the
    // session key's principal (self_authenticating(session_pubkey)).
    store.devices.write().await.retain(|_, d| d.device_code != req.device_code);
    let principal = store
        .identities
        .session_principal(&session_id)
        .await
        .unwrap_or_else(|| "unknown".to_string());

    let access_token = format!("mcp-token-{}", Uuid::new_v4());
    store.tokens.write().await.insert(
        access_token.clone(),
        TokenInfo {
            principal: principal.clone(),
            session_id,
            created: Instant::now(),
            ttl: TOKEN_TTL,
        },
    );
    tracing::info!(%principal, "issued MCP access token (device grant)");

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
}

/// POST /oauth/register — the device grant needs no redirect, so `redirect_uris`
/// is optional; any supplied are recorded but unused.
pub async fn register(State(store): State<AuthStore>, Json(req): Json<RegisterRequest>) -> Response {
    let client_id = format!("client-{}", Uuid::new_v4());
    let snapshot = {
        let mut clients = store.clients.write().await;
        clients.insert(
            client_id.clone(),
            ClientReg {
                redirect_uris: req.redirect_uris.clone(),
            },
        );
        clients.clone()
    };
    tokio::task::spawn_blocking(move || persist_clients(&snapshot)).await.ok();

    // Public client (PKCE, no secret): OMIT client_secret entirely (returning
    // null breaks clients that validate it as a string).
    let mut resp = json!({
        "client_id": client_id,
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": [DEVICE_GRANT_TYPE],
        "response_types": [],
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
        "device_authorization_endpoint": format!("{base}/oauth/device_authorization"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "grant_types_supported": [DEVICE_GRANT_TYPE],
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

fn oauth_err(status: StatusCode, error: &str, desc: &str) -> Response {
    (status, Json(json!({ "error": error, "error_description": desc }))).into_response()
}

/// Re-export for additional JSON fields.
pub type _JsonValue = Value;

#[cfg(test)]
mod tests {
    use super::pkce_s256;

    /// RFC 7636 Appendix B test vector.
    #[test]
    fn pkce_s256_matches_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256(verifier), expected);
    }
}
