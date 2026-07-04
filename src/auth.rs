//! OAuth 2.1 authorization server for the MCP endpoint, with **Internet Identity**
//! as the login mechanism, using II's session-key registration handshake.
//!
//! II's `/mcp` handshake registers the session key under the user's own auth and,
//! if we ask, navigates the browser back to a `finish_url` on our origin (see
//! `docs/mcp-server-guide.md` §2a/§2c / dfinity/internet-identity#4086). We drive
//! one flow — **authorization code + PKCE** — so any OAuth 2.1 client works:
//!
//!   * `/oauth/authorize` sets a browser-binding cookie (H3) and redirects to
//!     II's handshake; the key-request response carries a `finish_url`, so after
//!     `mcp_register` II navigates the browser to `/oauth/finish`, which requires
//!     that cookie, confirms registration, mints a PKCE-bound code, and 302s to
//!     the client's `redirect_uri`.
//!
//! The RFC 8628 device grant was dropped (no listed client uses it, and it adds a
//! device-code phishing surface with none of the PKCE binding the rest of the flow
//! relies on).
//!
//! Connect handshake (Phase 1b): `/oauth/connect/callback` serves the two
//! cross-origin JSON POSTs II makes — a key request `{state}` → `{public_key,
//! finish_url}` (a fresh session keypair minted per connection) and a completion
//! notification `{state, expiration, permissions}` → mark the grant live and
//! record the session's access level. We never receive or verify a delegation
//! chain, and never call `mcp_register` (II's frontend does, under the user's own
//! authentication).
//!
//! Implemented: dynamic client registration, PKCE (S256) enforced, short-lived
//! codes, 1h access tokens, session-key-bound principal.
//!
//! ## Known residual risk (H3 is only a partial mitigation)
//!
//! The browser-binding cookie stops the *zero-click* session-fixation variant (a
//! phished victim's browser passively delivering the code to the attacker's
//! `redirect_uri`), but it does NOT fully prevent the account takeover. Because
//! `/oauth/authorize` requires no authentication, the ATTACKER can be the flow
//! initiator (open DCR + their own `redirect_uri`/PKCE): they call authorize,
//! keep both the cookie and the `state` from the II link, phish only the II link
//! to a victim, and after the victim consents (registering the session key under
//! the victim's anchor) they complete `/oauth/finish` themselves with their cookie
//! and redeem the code as the victim. This is structural: consent happens
//! cross-origin at II keyed by the shared `state`, so the server cannot tie "who
//! receives the code" to "who consented" — the cookie only proves initiator ==
//! finisher, and the attacker is the initiator. A complete fix needs an II-side
//! control that identifies the requesting client (not just the origin), which II
//! does not currently provide; reducing/vetting DCR shrinks but does not close it.

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

/// How long an authorization request and its pending II handshake stay valid
/// before the user must restart.
const CONNECT_TTL: Duration = Duration::from_secs(600);
/// Lifetime of a minted authorization code.
const CODE_TTL: Duration = Duration::from_secs(120);
/// Access-token lifetime (also the II grant's default, 1h).
const TOKEN_TTL: Duration = Duration::from_secs(3600);
/// `ttl` (seconds) requested for the II grant. Clamped by II to [600, 2592000].
const GRANT_TTL_SECS: u64 = 3600;

/// Name of the browser-session cookie that binds `/oauth/authorize` to
/// `/oauth/finish` (H3): only the browser that started the flow can complete it.
const CONNECT_COOKIE: &str = "mcp_connect";

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
    /// `state`).
    authz: Arc<RwLock<HashMap<String, AuthzPending>>>,
    /// Minted authorization codes awaiting exchange at `/oauth/token`.
    codes: Arc<RwLock<HashMap<String, CodeGrant>>>,
    /// Shared with the MCP tools: the session's backend key / grant expiration
    /// live here (keyed by `session_id`) for the tools to sign with.
    identities: Identities,
}

/// An auth-code connect awaiting the user's II handshake.
#[derive(Clone, Debug)]
struct AuthzPending {
    client_id: String,
    redirect_uri: String,
    /// The OAuth client's own `state`, echoed back on the final redirect.
    client_state: String,
    code_challenge: Option<String>,
    /// Unguessable value set as a browser cookie at `/oauth/authorize` and
    /// required (matched) at `/oauth/finish` (H3) — so only the browser that
    /// STARTED this flow can complete it. This is a PARTIAL mitigation of the
    /// session-fixation takeover: it stops the zero-click variant (a phished
    /// victim's browser auto-delivering the code to the attacker's redirect_uri),
    /// but NOT a variant where the attacker — being the flow initiator, since
    /// `/oauth/authorize` needs no auth — holds this cookie and completes finish
    /// themselves after the victim consents. A full fix needs an II-side control
    /// that identifies the client, not just the origin (see the module docs).
    cookie: String,
    created: Instant,
    /// Grant confirmed live (completion POST or a signed-call fallback).
    live: bool,
    /// The authorization code minted once the grant is live (idempotent finish).
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

#[derive(Clone, Debug)]
struct TokenInfo {
    principal: String,
    session_id: String,
    created: Instant,
    ttl: Duration,
}

/// The dynamic-client-registration store, shared by every instance's
/// [`AuthStore`]. Client registration is II-agnostic (it only pins redirect
/// URIs to a `client_id`), so a client registered against either instance's AS
/// is known to both — and, since both stores share one map, the persisted
/// snapshot never loses the other instance's entries.
#[derive(Clone)]
pub struct SharedClients(Arc<RwLock<HashMap<String, ClientReg>>>);

/// Load the persisted client registrations once, to be shared by all stores.
pub fn load_shared_clients() -> SharedClients {
    SharedClients(Arc::new(RwLock::new(load_clients())))
}

impl AuthStore {
    pub fn new(identities: Identities, clients: SharedClients) -> Self {
        Self {
            clients: clients.0,
            tokens: Arc::default(),
            authz: Arc::default(),
            codes: Arc::default(),
            identities,
        }
    }

    /// The II instance this store serves.
    fn instance(&self) -> &crate::identities::IiInstance {
        self.identities.instance()
    }

    /// This instance's protected-resource metadata URL (RFC 9728), advertised in
    /// the 401 challenge. The default instance keeps the root document; other
    /// instances use the path-inserted form for their resource path.
    fn resource_metadata_url(&self) -> String {
        let inst = self.instance();
        let base = base_url();
        if inst.oauth_prefix.is_empty() {
            format!("{base}/.well-known/oauth-protected-resource")
        } else {
            format!("{base}/.well-known/oauth-protected-resource{}", inst.mcp_path)
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
    // H3: bind this browser to the flow. The cookie is set now and required at
    // /oauth/finish; the `state` alone can't prove the finishing browser is the
    // initiator (it's echoed to the client). This blocks the zero-click takeover
    // variant (a phished victim's browser passively delivering the code) but is
    // only a PARTIAL mitigation — see `AuthzPending::cookie` and the module docs.
    let cookie = format!("bind-{}", Uuid::new_v4());
    store.authz.write().await.insert(
        session_id.clone(),
        AuthzPending {
            client_id: q.client_id.clone(),
            redirect_uri: q.redirect_uri.clone(),
            client_state: q.state.clone().unwrap_or_default(),
            code_challenge: Some(code_challenge),
            cookie: cookie.clone(),
            created: Instant::now(),
            live: false,
            code: None,
        },
    );

    // Redirect the browser to this instance's II handshake, setting the binding
    // cookie. II navigates back to our `finish_url` (from the key-request
    // response) once it registers; SameSite=Lax lets the cookie ride that
    // top-level cross-site GET back to us. Scoped to this instance's OAuth prefix.
    let set_cookie = format!(
        "{CONNECT_COOKIE}={cookie}; Path={}/oauth; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
        store.instance().oauth_prefix,
        CONNECT_TTL.as_secs(),
    );
    let mut resp = js_redirect(&ii_mcp_url(store.instance(), &session_id));
    resp.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&set_cookie).expect("valid cookie"),
    );
    resp
}

/// Extract our binding cookie's value from a request's `Cookie` header.
fn connect_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == CONNECT_COOKIE)
        .map(|(_, v)| v.to_string())
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
pub async fn finish(
    State(store): State<AuthStore>,
    headers: axum::http::HeaderMap,
    Query(q): Query<FinishQuery>,
) -> Response {
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
                a.cookie.clone(),
            )
        })
    };
    let Some((expired, live_flag, existing_code, client_id, redirect_uri, client_state, code_challenge, cookie)) = snap
    else {
        return connect_error("unknown or already-used connect request — restart from your client");
    };
    if expired {
        return connect_error("connect request expired — restart from your client");
    }
    // H3: only the browser that STARTED this flow (and holds the binding cookie)
    // may complete it. A constant-time compare isn't warranted — the value is a
    // fresh 122-bit UUID, unguessable and single-use. This blocks the zero-click
    // takeover (a phished victim's browser passively delivering the code) but does
    // NOT stop an initiator-attacker who holds the cookie and completes finish
    // themselves after the victim consents — a PARTIAL mitigation (see module docs).
    if connect_cookie(&headers).as_deref() != Some(cookie.as_str()) {
        return connect_error(
            "this sign-in was started in a different browser session — restart the connection from your client",
        );
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
            return connect_error(&format!(
                "could not confirm the connection with Internet Identity ({}) — it may not support \
                 MCP connect yet; reconnect and try again",
                store.instance().ii_url
            ));
        }
        return finishing_page(store.instance().oauth_prefix, &q.id, q.r + 1);
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
/// confirmable, then it re-hits this instance's `/oauth/finish` (bounded by the
/// retry counter).
fn finishing_page(prefix: &str, id: &str, next_try: u32) -> Response {
    let url = js_escape(&format!("{prefix}/oauth/finish?id={}&r={}", urlencoding::encode(id), next_try));
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

/// Build an instance's II `/mcp` handshake URL for a connection. Everything is in
/// the URL fragment (never sent to II's servers): this instance's callback on our
/// origin, the single-use `state` (= session id), and the requested grant `ttl`
/// in SECONDS. NO key material is put in the link.
fn ii_mcp_url(inst: &crate::identities::IiInstance, session_id: &str) -> String {
    let callback = format!("{}{}/oauth/connect/callback", base_url(), inst.oauth_prefix);
    format!(
        "{ii}/mcp#callback={cb}&state={st}&ttl={ttl}",
        ii = inst.ii_url,
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
    /// Present on the completion notification (§0): `"queries"` = read-only
    /// session, `"all"` = full access. Lets us learn the access level at connect
    /// without minting a probe delegation; best-effort like the rest of the POST.
    #[serde(default)]
    permissions: Option<String>,
}

/// POST /oauth/connect/callback — II's frontend makes TWO cross-origin JSON
/// POSTs here, distinguished by the `expiration` field:
///   (a) key request `{state}` → 200 `{public_key, finish_url}` (fresh keypair);
///   (b) completion `{state, expiration, permissions}` → mark the grant live and
///       record the access level; any 2xx.
/// Never returns a redirect (the response is consumed by `fetch()`), and never
/// receives or verifies a delegation chain.
pub async fn connect_callback(State(store): State<AuthStore>, Json(body): Json<ConnectCallback>) -> Response {
    match &body.expiration {
        // (a) Key request — require a valid, unexpired pending connection (reject
        // unknown/replayed/expired state with a non-2xx so II aborts), then
        // generate (lazily) this connection's session keypair and return its
        // public key for II's frontend to register. Return `finish_url` so II
        // navigates the browser back to us to close the OAuth loop.
        None => {
            if !store.connect_known_authz(&body.state).await {
                return (StatusCode::FORBIDDEN, Json(json!({ "error": "invalid_state" }))).into_response();
            }
            let public_key = store.identities.session_pubkey_b64(&body.state).await;
            let finish_url = format!(
                "{}{}/oauth/finish?id={}",
                base_url(),
                store.instance().oauth_prefix,
                urlencoding::encode(&body.state)
            );
            (StatusCode::OK, Json(json!({ "public_key": public_key, "finish_url": finish_url }))).into_response()
        }
        // (b) Completion notification — best-effort. Mark the grant live if the
        // connection is still known, and record the session's access level
        // (`permissions`, §0/H2) so tools can warn before attempting an update
        // under a read-only session. Tolerate a missing/expired state (e.g. the
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
                if let Some(permissions) = &body.permissions {
                    store.identities.set_permissions(&body.state, permissions).await;
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

    /// Mark the pending connect live; returns whether `state` was known.
    async fn mark_live(&self, state: &str) -> bool {
        if let Some(a) = self.authz.write().await.get_mut(state) {
            a.live = true;
            true
        } else {
            false
        }
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

// ---- Token: exchange an authorization code ------------------------------

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    code_verifier: Option<String>,
}

/// POST /oauth/token — the `authorization_code` grant (the only grant we support;
/// the RFC 8628 device grant was dropped).
pub async fn token(State(store): State<AuthStore>, Form(req): Form<TokenForm>) -> Response {
    match req.grant_type.as_str() {
        "authorization_code" => token_authorization_code(store, req).await,
        _ => oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type", "only authorization_code is supported"),
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
    issue_token(&store, &grant.session_id).await
}

/// Mint + store an access token bound to the session key's principal.
async fn issue_token(store: &AuthStore, session_id: &str) -> Response {
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

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL.as_secs(),
    }))
    .into_response()
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
/// flow — the only grant we support.
pub async fn register(State(store): State<AuthStore>, Json(req): Json<RegisterRequest>) -> Response {
    let client_id = format!("client-{}", Uuid::new_v4());
    let snapshot = {
        let mut clients = store.clients.write().await;
        clients.insert(client_id.clone(), ClientReg { redirect_uris: req.redirect_uris.clone() });
        clients.clone()
    };
    tokio::task::spawn_blocking(move || persist_clients(&snapshot)).await.ok();

    // Honour the requested grant types (intersected with what we support); fall
    // back to authorization_code if the client didn't ask for any.
    let supported = ["authorization_code"];
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

/// GET /.well-known/oauth-authorization-server (root for the default instance,
/// `…/prod` for the prod instance — RFC 8414 path issuer). The issuer is
/// `<PUBLIC_URL><oauth_prefix>`, and every endpoint lives under it.
pub async fn authorization_server_metadata(State(store): State<AuthStore>) -> Response {
    let issuer = format!("{}{}", base_url(), store.instance().oauth_prefix);
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
    .into_response()
}

/// GET /.well-known/oauth-protected-resource (and the path-inserted variants):
/// this instance's MCP resource and the AS that protects it.
pub async fn protected_resource_metadata(State(store): State<AuthStore>) -> Response {
    let base = base_url();
    let inst = store.instance();
    Json(json!({
        "resource": format!("{base}{}", inst.mcp_path),
        "authorization_servers": [format!("{base}{}", inst.oauth_prefix)],
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
    // The `Bearer` auth-scheme is case-insensitive (RFC 7235 §2.1), so match it
    // that way — an `Authorization: bearer <token>` must be recognized too.
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            let (scheme, rest) = h.split_once(' ')?;
            scheme.eq_ignore_ascii_case("Bearer").then(|| rest.trim().to_owned())
        });

    let had_token = token.is_some();
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
        None => (
            StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                bearer_challenge(had_token, &store.resource_metadata_url()),
            )],
            Json(json!({ "error": "invalid_token" })),
        )
            .into_response(),
    }
}

/// Build the `WWW-Authenticate` challenge for a 401 on an MCP resource. Always
/// points clients at that resource's metadata (RFC 9728); when a token WAS
/// presented but is invalid/expired (`had_token`), also carries
/// `error="invalid_token"` (RFC 6750 §3) so the client can tell "expired →
/// re-authorize" from "no token" and prompt an inline reconnect. A missing token
/// gets a bare challenge (RFC 6750: omit the error code when no credentials were
/// sent).
fn bearer_challenge(had_token: bool, resource_metadata_url: &str) -> String {
    let meta = format!("resource_metadata=\"{resource_metadata_url}\"");
    if had_token {
        format!("Bearer error=\"invalid_token\", error_description=\"The access token is invalid or expired\", {meta}")
    } else {
        format!("Bearer {meta}")
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

    /// RFC 6750 §3 / 9728: the `error` code appears only when a token was
    /// presented; the resource_metadata pointer is always present and carries the
    /// per-instance metadata URL verbatim.
    #[test]
    fn bearer_challenge_carries_error_only_for_presented_tokens() {
        let meta = "https://x.test/.well-known/oauth-protected-resource/mcp-prod";
        let with_token = super::bearer_challenge(true, meta);
        assert!(with_token.starts_with("Bearer "));
        assert!(with_token.contains("error=\"invalid_token\""));
        assert!(with_token.contains("error_description="));
        assert!(with_token.contains(&format!("resource_metadata=\"{meta}\"")));

        let no_token = super::bearer_challenge(false, meta);
        assert!(no_token.starts_with("Bearer "));
        assert!(!no_token.contains("error="), "a bare challenge must omit the error code: {no_token}");
        assert!(no_token.contains(&format!("resource_metadata=\"{meta}\"")));
    }

    /// H3: the binding cookie is extracted by name from the `Cookie` header
    /// (among other cookies), and its absence yields `None` — `finish` then
    /// refuses to complete a flow the browser didn't start.
    #[test]
    fn connect_cookie_extracts_named_value() {
        use axum::http::{header::COOKIE, HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        assert_eq!(super::connect_cookie(&h), None);
        h.insert(
            COOKIE,
            HeaderValue::from_static("other=1; mcp_connect=bind-xyz; last=2"),
        );
        assert_eq!(super::connect_cookie(&h).as_deref(), Some("bind-xyz"));
        // A different cookie name present but not ours -> None.
        let mut h2 = HeaderMap::new();
        h2.insert(COOKIE, HeaderValue::from_static("session=abc"));
        assert_eq!(super::connect_cookie(&h2), None);
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
