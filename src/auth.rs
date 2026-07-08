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
//! ## H3: Consent-Bound Completion (closes the split-browser code injection)
//!
//! `/oauth/finish` mints a code only when the requesting browser proves it is BOTH
//! the **initiator** and the **consenter**:
//!   1. *initiator* — the `sid` cookie ([`CONNECT_COOKIE`]) set at `/oauth/authorize`;
//!   2. *consenter* — a one-time `finish_secret` (≥128-bit) minted at the **single-use
//!      key request** and disclosed only in that response (embedded in `finish_url`),
//!      so only the browser that drove the II handshake holds it;
//!   3. plus a *proven* registration — a signed `mcp_get_accounts` returning `Ok`
//!      (not a bare, unauthenticated completion POST).
//!
//! Because the key request is strictly single-use per `connect_state` (an atomic
//! compare-and-set) and delivers BOTH `finish_secret` and the `public_key` a victim
//! would register, the two proofs can co-reside in one browser only in the
//! legitimate same-browser flow — so an attacker who initiates and then phishes the
//! II link to a victim cannot obtain a code (they hold `sid` but never
//! `finish_secret`; the victim holds `finish_secret` but never `sid`). This closes
//! the split-browser injection for all transports incl. loopback (a loopback
//! redirect resolves on the consenter's own machine).
//!
//! Not closed here (companion control): the *same-browser* variant where a victim
//! is socially engineered into running the whole flow toward an attacker-registered
//! **hosted** `redirect_uri`; that needs hosted-redirect allow-listing (loopback is
//! safe either way). "H3 fully closed" = Consent-Bound Completion + that allow-list.
//!
//! Load-bearing (see the `P?` markers below): the key request is single-use and
//! atomic (P1); `finish_secret` is disclosed only via `finish_url`'s query, never
//! logged, no `Referer` leak (P2); `registered` reflects a real grant, never a bare
//! completion POST (P3). P1 also assumes II's frontend issues exactly one key
//! request per connect and never auto-retries (a retry then fails as "restart",
//! never a takeover — the safe direction).
//!
//! ## Phase 2: the registration delegation (per-instance; beta on, prod off)
//!
//! A successor connect flow (the "registration delegation" design) replaces the
//! fetched-key registration — where II binds a key it was merely shown — with a
//! single-use, canister-signed delegation `P_reg -> X` that II mints under the
//! user's own authentication and delivers to a **pinned callback page** as a URL
//! fragment. The backend redeems it by signing ONE `mcp_register_v2` call as `X`
//! (see [`Identities::redeem_registration_delegation`]). The delegation, being
//! fragment-delivered only to the consenting browser and required to redeem,
//! subsumes `finish_secret` as the consenter proof; synchronous registration
//! removes the `grant_is_live` probe and the `finishing_page` poll.
//!
//! The server runs BOTH protocols side by side, selected **per II instance**
//! ([`crate::identities::IiInstance::registration_delegation`]): the beta
//! (staging) instance runs Phase 2 by default (`MCP_REGISTRATION_DELEGATION=0`
//! to disable), the production instance stays pinned to v1
//! (`MCP_REGISTRATION_DELEGATION_PROD=1` to opt in later). Enabling Phase 2 for
//! an instance is **outbound-compatible with v1**: it adds `regkey`/`flow` to
//! that instance's II link and turns on its pinned callback page + redeem
//! endpoint, while every v1 handler (the callback POSTs, `/oauth/finish`) stays
//! live — an II frontend that doesn't know the new flow ignores the extra params
//! and completes v1 unchanged. So beta keeps connecting via v1 until beta II
//! actually ships the new frontend and canister methods (`mcp_register_v2`,
//! `prepare_`/`get_mcp_registration_delegation`, the `mcp-registration` seed —
//! none exist yet), and switches over when it does. The fragment wire shape
//! ([`RegDelegationDto`]), the link params (`regkey`, `flow`), and the
//! `mcp_register_v2` candid are **PROVISIONAL** until reconciled with II's
//! published `.did`. Retiring v1 for a Phase-2 instance (the design's "v1
//! sunset") is a separate, later step — not this.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
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
use candid::Principal;
use ic_agent::identity::{Delegation, SignedDelegation};
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

/// Observability for the single-use key request (P1): number of key requests that
/// hit a still-valid but ALREADY-CONSUMED `connect_state` — i.e. a *repeat* key
/// request. Under strict single-use these are expected to be ~zero. An isolated
/// hit is a stray replay / attacker probe (harmless — it 403s); a sustained rise
/// means II's frontend started re-issuing the key request, which strict single-use
/// turns into failed connects (a benign-but-breaking regression to fix upstream —
/// never a takeover). Warn-logged with the instance name and surfaced on `/version`
/// so a silent regression is caught without log scraping. Process-wide.
static REPEAT_KEY_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Current value of the repeat-key-request counter (for the `/version` probe).
pub fn repeat_key_requests() -> u64 {
    REPEAT_KEY_REQUESTS.load(Ordering::Relaxed)
}

/// Public base URL clients use to reach this server. Override with PUBLIC_URL.
pub fn base_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}


/// A fresh consent secret: 256 bits from the OS CSPRNG, URL-safe (base64url, no
/// pad) so it can ride in a query string. Well above the ≥128-bit floor (P5).
fn fresh_secret() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("getrandom");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 digest of `s` (used to store `finish_secret` hashed at rest — P5).
fn sha256(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

/// Constant-time equality for two byte slices (P5) — no early-out on the first
/// differing byte, so a compare doesn't leak how much of a secret matched.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
    /// H3 clause 1 (*initiator* proof): unguessable value set as the `sid` browser
    /// cookie at `/oauth/authorize` and matched at `/oauth/finish` — only the
    /// browser that STARTED this flow presents it. On its own the cookie is a
    /// partial mitigation; combined with `finish_secret_hash` (the *consenter*
    /// proof) it closes the split-browser injection (see the module docs).
    cookie: String,
    created: Instant,
    /// H3 clause 2 (*consenter* proof), and the single-use marker for the key
    /// request (P1/P3): `None` until the FIRST key request for this connect
    /// atomically claims it and stores `H(finish_secret)`; any later key request
    /// then 403s. `/oauth/finish` requires a `finish_secret` hashing to this. Its
    /// presence also means "the key request happened" — the only way `registered`
    /// can legitimately become provable — so no alternate path materializes it.
    finish_secret_hash: Option<[u8; 32]>,
    /// The authorization code minted once the grant is confirmed (idempotent finish).
    code: Option<String>,
    /// Phase 2 single-flight marker: `true` while a redemption attempt (the
    /// `mcp_register_v2` network call) is mid-flight for this connect, so a
    /// concurrent double-submit can't fire a second one. Set atomically by
    /// [`claim_redemption`], cleared on failure so a genuine retry can proceed
    /// (a completed attempt leaves `code` set instead, the idempotent path).
    /// Redemption is ALSO idempotent-on-`S` at II by design, so this is about
    /// determinism and not double-spending update calls, not correctness.
    redeeming: bool,
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
    // H3 clause 1: bind this browser to the flow (the `sid` cookie, set now and
    // required at /oauth/finish). The `state` alone can't prove the finishing
    // browser is the initiator (it's echoed to the client). The cookie proves
    // *initiator*; the `finish_secret` minted at the key request proves
    // *consenter*; requiring both closes the split-browser injection.
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
            finish_secret_hash: None,
            code: None,
            redeeming: false,
        },
    );

    // Redirect the browser to this instance's II handshake, setting the binding
    // cookie. II navigates back to our `finish_url` (from the key-request
    // response) once it registers; SameSite=Lax lets the cookie ride that
    // top-level cross-site GET back to us. Scoped to this instance's OAuth prefix.
    // `Secure` only when served over HTTPS (production always is): a `Secure`
    // cookie is dropped by browsers over plain HTTP, which would break the
    // initiator check for local `http://localhost` development.
    let secure = if base_url().starts_with("https://") { "; Secure" } else { "" };
    let set_cookie = format!(
        "{CONNECT_COOKIE}={cookie}; Path={}/oauth; Max-Age={}; HttpOnly{secure}; SameSite=Lax",
        store.instance().oauth_prefix,
        CONNECT_TTL.as_secs(),
    );
    // Phase 2 (per-instance): mint this connect's registration key `X` and carry
    // `pub(X)` in the II link so II certifies `P_reg -> X`. An II frontend that
    // doesn't know the new flow ignores the extra params and completes v1 (whose
    // handlers are always live), so enabling this is outbound-compatible. A
    // v1-pinned instance (prod) emits the unmodified v1 link.
    let ii_url = if store.instance().registration_delegation {
        let reg_pubkey = store.identities.registration_pubkey_b64(&session_id).await;
        ii_mcp_url_v2(store.instance(), &session_id, &reg_pubkey)
    } else {
        ii_mcp_url(store.instance(), &session_id)
    };
    let mut resp = js_redirect(&ii_url);
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
    /// H3 clause 2: the one-time `finish_secret`, carried in `finish_url`'s QUERY
    /// (not a path segment) so path-only access logs don't capture it (P2).
    #[serde(default)]
    fs: Option<String>,
    /// Retry counter, so the "finishing" reload is bounded.
    #[serde(default)]
    r: u32,
}

/// GET /oauth/finish — II navigates the CONSENTING browser here after registering
/// the session key (this is the `finish_url` returned in the key-request response,
/// carrying the one-time `finish_secret` in its query). Mints a code only if all of
/// H3's predicate holds — (1) the `sid` cookie resolves to this PA, (2) `finish_secret`
/// matches, (3) registration is *proven* by a signed `mcp_get_accounts` that returns
/// `Ok`, (4) not expired / not already completed — then 302s to the client's
/// `redirect_uri` with `code` + the client's `state`.
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
                a.finish_secret_hash,
                a.code.clone(),
                a.client_id.clone(),
                a.redirect_uri.clone(),
                a.client_state.clone(),
                a.code_challenge.clone(),
                a.cookie.clone(),
            )
        })
    };
    let Some((expired, finish_secret_hash, existing_code, client_id, redirect_uri, client_state, code_challenge, cookie)) =
        snap
    else {
        return connect_error("unknown or already-used connect request — restart from your client");
    };
    if expired {
        return connect_error("connect request expired — restart from your client");
    }
    // H3 clause 1 (initiator): only the browser that STARTED this flow (holding the
    // `sid` cookie) may complete it.
    if connect_cookie(&headers).as_deref() != Some(cookie.as_str()) {
        return connect_error(
            "this sign-in was started in a different browser session — restart the connection from your client",
        );
    }
    // H3 clause 2 (consenter): the one-time `finish_secret`, disclosed only in the
    // single-use key-request response, proves this browser drove the II consent.
    // Requiring BOTH proofs forces initiator == consenter, closing the
    // split-browser injection. `finish_secret_hash` is `Some` only after the key
    // request ran (so this also gates on "the handshake happened"). Constant-time
    // compare of the hashes (P5).
    let secret_ok = match (q.fs.as_deref(), finish_secret_hash) {
        (Some(fs), Some(hash)) => ct_eq(&sha256(fs), &hash),
        _ => false,
    };
    if !secret_ok {
        return connect_error(
            "this sign-in can't be completed in this browser — restart the connection from your client",
        );
    }
    let fs = q.fs.as_deref().unwrap_or_default();
    // Idempotent: if the code was already minted, just redirect again.
    if let Some(code) = existing_code {
        return redirect_302(&build_redirect(&redirect_uri, &code, &client_state));
    }
    // H3 clause 3 (proven registration, P3): confirm the session key is actually
    // registered on-chain via a signed `mcp_get_accounts` returning `Ok` — NOT a
    // bare completion POST (which any `connect_state`-knower could forge). No lock
    // held across the network call. If not yet visible (a race with II's
    // registration/propagation), reload shortly — bounded so we don't loop forever.
    if !store.identities.grant_is_live(&q.id).await {
        if q.r >= 8 {
            return connect_error(&format!(
                "could not confirm the connection with Internet Identity ({}) — it may not support \
                 MCP connect yet; reconnect and try again",
                store.instance().ii_url
            ));
        }
        return finishing_page(store.instance().oauth_prefix, &q.id, fs, q.r + 1);
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
/// retry counter). Carries `finish_secret` across the reload (P6) and sets
/// `Referrer-Policy: no-referrer` so the secret-bearing URL never rides a `Referer`.
fn finishing_page(prefix: &str, id: &str, fs: &str, next_try: u32) -> Response {
    let url = js_escape(&format!(
        "{prefix}/oauth/finish?id={}&fs={}&r={}",
        urlencoding::encode(id),
        urlencoding::encode(fs),
        next_try
    ));
    let mut resp = Html(format!(
        "<!DOCTYPE html><meta charset=utf-8><title>Finishing…</title>\
         <meta name=referrer content=no-referrer>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto\">\
         <p>Finishing sign-in…</p>\
         <script>setTimeout(function(){{location.replace(\"{url}\")}},1200)</script></body>"
    ))
    .into_response();
    resp.headers_mut()
        .insert(axum::http::header::REFERRER_POLICY, axum::http::HeaderValue::from_static("no-referrer"));
    resp
}

/// A 302 to an absolute URL (used for the top-level hop back to the OAuth client).
/// Sets `Referrer-Policy: no-referrer` so the `finish_secret` in this request's URL
/// (query) is not leaked to `redirect_uri` via the `Referer` header (P2).
fn redirect_302(url: &str) -> Response {
    let mut resp = (StatusCode::FOUND, [(axum::http::header::LOCATION, url.to_string())]).into_response();
    resp.headers_mut()
        .insert(axum::http::header::REFERRER_POLICY, axum::http::HeaderValue::from_static("no-referrer"));
    resp
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

/// Build the **Phase-2** II `/mcp` link (for a registration-delegation
/// instance): the v1 fragment plus this
/// connect's registration public key `pub(X)` (`regkey`), toward which II
/// certifies the delegation `P_reg -> X`, and a `flow` marker selecting the
/// registration-delegation path. II navigates the tab to the pinned `callback`
/// with the delegation in the fragment; the callback is our sole fragment reader
/// ([`pinned_callback_page`]). The `regkey`/`flow` param names are **PROVISIONAL**
/// (the II frontend contract is not finalized). No `priv(X)` is ever put in the
/// link — only its public half.
fn ii_mcp_url_v2(inst: &crate::identities::IiInstance, session_id: &str, reg_pubkey_b64: &str) -> String {
    let callback = format!("{}{}/oauth/connect/callback", base_url(), inst.oauth_prefix);
    format!(
        "{ii}/mcp#callback={cb}&state={st}&ttl={ttl}&regkey={rk}&flow=registration_delegation",
        ii = inst.ii_url,
        cb = urlencoding::encode(&callback),
        st = urlencoding::encode(session_id),
        ttl = GRANT_TTL_SECS,
        rk = urlencoding::encode(reg_pubkey_b64),
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

/// Outcome of the atomic single-use claim on a key request's `connect_state`.
enum KeyClaim {
    /// Won the claim: mint the keypair + `finish_secret`.
    Claimed,
    /// Known + unexpired but already claimed — a repeat key request (observed).
    RepeatConsumed,
    /// Unknown or expired — an ordinary rejected replay/stale link.
    Reject,
}

/// POST /oauth/connect/callback — II's frontend makes TWO cross-origin JSON
/// POSTs here, distinguished by the `expiration` field:
///   (a) key request `{state}` → 200 `{public_key, finish_url}` (fresh keypair +
///       one-time `finish_secret` embedded in `finish_url`; STRICTLY single-use);
///   (b) completion `{state, expiration, permissions}` → record expiry + access
///       level only (a latency hint; never sets `registered`); any 2xx.
/// Never returns a redirect (the response is consumed by `fetch()`), and never
/// receives or verifies a delegation chain.
pub async fn connect_callback(State(store): State<AuthStore>, Json(body): Json<ConnectCallback>) -> Response {
    match &body.expiration {
        // (a) Key request — STRICTLY single-use per `connect_state` (P1). Atomically
        // (under one lock) require the PA is known/unexpired AND not yet claimed,
        // then claim it by storing `H(finish_secret)`; any later or racing key
        // request 403s (no keypair, no secret). This atomic compare-and-set is what
        // makes secret-disclosure and victim-registration mutually exclusive.
        None => {
            let secret = fresh_secret();
            let claim = {
                let mut authz = store.authz.write().await;
                match authz.get_mut(&body.state) {
                    // Known, unexpired, not yet claimed: win the single-use claim.
                    Some(a) if a.created.elapsed() < CONNECT_TTL && a.finish_secret_hash.is_none() => {
                        a.finish_secret_hash = Some(sha256(&secret));
                        KeyClaim::Claimed
                    }
                    // Known, unexpired, ALREADY claimed: a repeat key request — the
                    // signal we watch (II retry regression, or a stray probe).
                    Some(a) if a.created.elapsed() < CONNECT_TTL => KeyClaim::RepeatConsumed,
                    // Unknown or expired: an ordinary rejected replay/stale link.
                    _ => KeyClaim::Reject,
                }
            };
            match claim {
                KeyClaim::Claimed => {}
                KeyClaim::RepeatConsumed => {
                    let total = REPEAT_KEY_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::warn!(
                        instance = store.instance().name,
                        total,
                        "repeat key request on a consumed connect_state (single-use, P1) — \
                         a sustained rise means II is re-issuing the key request; an isolated hit \
                         is a stray replay/probe"
                    );
                    return (StatusCode::FORBIDDEN, Json(json!({ "error": "invalid_state" }))).into_response();
                }
                KeyClaim::Reject => {
                    return (StatusCode::FORBIDDEN, Json(json!({ "error": "invalid_state" }))).into_response();
                }
            }
            // Only the single winner mints the session keypair and gets the secret.
            let public_key = store.identities.session_pubkey_b64(&body.state).await;
            // `finish_secret` rides in the QUERY (P2): path-only access logs won't
            // capture it, and /oauth/finish sends no `Referer`. It reaches only this
            // (the consenting) browser, which II then navigates to `finish_url`.
            let finish_url = format!(
                "{}{}/oauth/finish?id={}&fs={}",
                base_url(),
                store.instance().oauth_prefix,
                urlencoding::encode(&body.state),
                urlencoding::encode(&secret),
            );
            (StatusCode::OK, Json(json!({ "public_key": public_key, "finish_url": finish_url }))).into_response()
        }
        // (b) Completion notification — a best-effort LATENCY HINT only (P3). Record
        // the grant expiration and access level (`permissions`, §0/H2) if the PA is
        // known, but NEVER set `registered`: this POST is unauthenticated (any
        // `connect_state`-knower can send it), so registration is proven separately
        // at /oauth/finish by a signed `mcp_get_accounts`. Tolerate a missing/expired
        // state with a 2xx so a late POST doesn't fail an otherwise-good connect.
        Some(exp) => {
            if store.authz_known(&body.state).await {
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
    /// Whether `state` names a known, unexpired pending connect (read-only; used by
    /// the completion POST to decide whether to record its expiry/permissions hint).
    async fn authz_known(&self, state: &str) -> bool {
        self.authz
            .read()
            .await
            .get(state)
            .is_some_and(|a| a.created.elapsed() < CONNECT_TTL)
    }
}

// ---- Phase 2: registration delegation (flag-gated) ----------------------

/// GET /oauth/connect/callback — the **pinned callback page** (Phase 2 only).
/// II navigates the consenting browser here with the canister-signed delegation
/// in the URL fragment. This page is the SOLE reader of that fragment: it reads
/// `location.hash` entirely client-side, POSTs it (with the connect cookie) to
/// [`connect_redeem`], strips it from the address bar, then navigates to the
/// redirect the backend returns. It never writes any fragment/query value into
/// the DOM (no reflection), and ships a strict CSP. On a v1-pinned instance this
/// path has no page role (v1 uses only the POST handler below), so GET 404s.
pub async fn connect_callback_page(State(store): State<AuthStore>) -> Response {
    if !store.instance().registration_delegation {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    pinned_callback_page(store.instance().oauth_prefix)
}

/// A fresh CSP nonce: 128 bits from the OS CSPRNG, **standard** base64. CSP3's
/// `base64-value` grammar also admits base64url, but CSP2's does not (`-`/`_`
/// absent), so use the standard alphabet for maximum parser compatibility — a
/// strict-CSP2 parser that rejected the nonce source would block the inline
/// script and break the callback page. `+`/`/`/`=` are all safe where the nonce
/// rides (a quoted HTML attribute and a header value).
fn csp_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom");
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The strict-CSP, non-reflecting pinned callback page. `nonce` is a fresh
/// per-response value bound into BOTH the CSP header and the inline `<script>`,
/// so no `'unsafe-inline'` is needed; `connect-src 'self'` limits the page's only
/// network reach to the same-origin redeem endpoint, and `default-src 'none'`
/// forbids loading anything else. No attacker-supplied value (fragment, query)
/// is ever interpolated into the HTML — the fragment is read client-side and sent
/// via `fetch`, never written to the DOM.
fn pinned_callback_page(prefix: &str) -> Response {
    let nonce = csp_nonce();
    let redeem = js_escape(&format!("{prefix}/oauth/connect/redeem"));
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>Finishing sign-in…</title></head>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto\">\
         <p id=m>Finishing sign-in…</p>\
         <script nonce=\"{nonce}\">(function(){{\
         function show(t){{document.getElementById('m').textContent=t;}}\
         var p=new URLSearchParams(location.hash.slice(1));\
         var body=JSON.stringify({{state:p.get('state')||'',user_key:p.get('user_key')||'',delegation:p.get('delegation')||''}});\
         try{{history.replaceState(null,'',location.pathname);}}catch(e){{}}\
         fetch(\"{redeem}\",{{method:'POST',headers:{{'content-type':'application/json'}},credentials:'same-origin',body:body}})\
         .then(function(r){{return r.json().catch(function(){{return {{}};}});}})\
         .then(function(d){{if(d&&d.redirect){{location.replace(d.redirect);}}else{{show((d&&d.error)||'Could not finish the connection — restart from your client.');}}}})\
         .catch(function(){{show('Could not reach the server — restart from your client.');}});\
         }})();</script></body></html>"
    );
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'"
    );
    let mut resp = Html(html).into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_str(&csp).expect("valid CSP"),
    );
    h.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    resp
}

/// POST /oauth/connect/redeem body — what [`pinned_callback_page`] sends after
/// parsing the fragment. `user_key` is base64url(DER(P_reg)); `delegation` is
/// base64url(JSON [`RegDelegationDto`]). **PROVISIONAL** shape (see module docs).
#[derive(Debug, Deserialize)]
pub struct RedeemBody {
    /// The single-use connect state (= session id).
    state: String,
    /// base64url(DER(P_reg)) — the delegation chain root.
    #[serde(default)]
    user_key: String,
    /// base64url(JSON [`RegDelegationDto`]) — the `P_reg -> X` delegation.
    #[serde(default)]
    delegation: String,
}

/// The canister-signed `P_reg -> X` delegation carried in the callback fragment
/// (base64url of this JSON). **PROVISIONAL** — the II frontend that produces it
/// is not written yet; reconcile before enabling the flag. Byte fields are
/// base64url; `expiration` is decimal ns as a string (u64 ns overflows JSON).
#[derive(Debug, Deserialize)]
struct RegDelegationDto {
    /// base64url(DER(X)) — the delegate (this connect's registration key).
    pubkey: String,
    /// Decimal ns since the Unix epoch.
    expiration: String,
    /// Principal texts the delegation targets (the II canister), or absent.
    #[serde(default)]
    targets: Option<Vec<String>>,
    /// `"queries"` (read-only) / `"all"` (full), or absent (unrestricted).
    #[serde(default)]
    permissions: Option<String>,
    /// base64url(canister signature).
    signature: String,
}

/// Decode a base64url (no pad) string, trimming surrounding whitespace.
fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| format!("not valid base64url: {e}"))
}

/// Decode the fragment payload into `(der(P_reg), [P_reg -> X])` as `ic-agent`
/// types, forwarding II's `permissions` verbatim so the reconstructed delegation
/// hashes to exactly what II's canister signed (the same discipline as the
/// account-delegation decode in `identities`). **PROVISIONAL** wire shape.
fn parse_registration_delegation(
    user_key_b64: &str,
    delegation_b64: &str,
) -> Result<(Vec<u8>, Vec<SignedDelegation>), String> {
    let user_key = b64url_decode(user_key_b64).map_err(|e| format!("user_key {e}"))?;
    let dto_bytes = b64url_decode(delegation_b64).map_err(|e| format!("delegation {e}"))?;
    let dto: RegDelegationDto =
        serde_json::from_slice(&dto_bytes).map_err(|e| format!("delegation JSON: {e}"))?;
    let pubkey = b64url_decode(&dto.pubkey).map_err(|e| format!("delegation pubkey {e}"))?;
    let signature = b64url_decode(&dto.signature).map_err(|e| format!("delegation signature {e}"))?;
    let expiration = dto
        .expiration
        .trim()
        .parse::<u64>()
        .map_err(|_| "delegation expiration is not a u64".to_string())?;
    let targets = match &dto.targets {
        None => None,
        Some(ts) => Some(
            ts.iter()
                .map(|t| Principal::from_text(t.trim()).map_err(|e| format!("delegation target principal: {e}")))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    let signed = SignedDelegation {
        delegation: Delegation {
            pubkey,
            expiration,
            targets,
            // Forward II's per-session permission verbatim (see the identical
            // reasoning on `IiDelegation::permissions`): the canister signature
            // covers this field, so an unrecognized value is a hard error rather
            // than a silent drop that would fail signature verification.
            permissions: crate::identities::permissions_from_text(dto.permissions.as_deref())?,
        },
        signature,
    };
    Ok((user_key, vec![signed]))
}

/// A JSON error the pinned page reads and displays.
fn redeem_err(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

/// Outcome of the atomic single-flight claim on a connect's redemption.
enum RedeemClaim {
    /// Won the claim: this request runs the (only) in-flight redemption attempt.
    Claimed,
    /// A previous attempt already finished — return its code again (idempotent).
    Existing(String),
    /// Another attempt is mid-flight right now (a double-submit lost the race).
    InProgress,
    /// The pending connect vanished (expiry sweep / restart).
    Vanished,
}

/// Atomically claim the right to run this connect's redemption: under one write
/// lock, return any already-minted code, refuse if an attempt is mid-flight, else
/// mark the entry as redeeming. This serializes the `mcp_register_v2` call per
/// connect — a page double-submit can't fire two concurrent redemptions (II's
/// idempotency-on-`S` would tolerate it, but one deterministic attempt is
/// strictly better than racing two).
async fn claim_redemption(store: &AuthStore, state: &str) -> RedeemClaim {
    let mut authz = store.authz.write().await;
    let Some(a) = authz.get_mut(state) else {
        return RedeemClaim::Vanished;
    };
    if let Some(code) = &a.code {
        return RedeemClaim::Existing(code.clone());
    }
    if a.redeeming {
        return RedeemClaim::InProgress;
    }
    a.redeeming = true;
    RedeemClaim::Claimed
}

/// Release a failed redemption claim so a genuine retry can proceed. (A
/// successful attempt leaves `code` set, which [`claim_redemption`] returns
/// directly — the `redeeming` marker no longer matters then.)
async fn release_redemption(store: &AuthStore, state: &str) {
    if let Some(a) = store.authz.write().await.get_mut(state) {
        a.redeeming = false;
    }
}

/// POST /oauth/connect/redeem — the pinned page POSTs the fragment here (Phase 2
/// only). Verifies the browser is the connect INITIATOR (the `sid` cookie), then
/// redeems the delegation via [`Identities::redeem_registration_delegation`] —
/// which is BOTH the consenter proof (fragment-delivered only to the consenting
/// browser) and proof of registration (synchronous, so no `grant_is_live` probe)
/// — and mints the PKCE-bound authorization code, returning the client redirect
/// for the page to navigate to. 404s on a v1-pinned instance.
pub async fn connect_redeem(
    State(store): State<AuthStore>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RedeemBody>,
) -> Response {
    if !store.instance().registration_delegation {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response();
    }
    // Snapshot the pending connect without holding the lock across the network.
    let snap = {
        let authz = store.authz.read().await;
        authz.get(&body.state).map(|a| {
            (
                a.created.elapsed() >= CONNECT_TTL,
                a.cookie.clone(),
                a.client_id.clone(),
                a.redirect_uri.clone(),
                a.client_state.clone(),
                a.code_challenge.clone(),
                a.code.clone(),
            )
        })
    };
    let Some((expired, cookie, client_id, redirect_uri, client_state, code_challenge, existing_code)) = snap else {
        return redeem_err("unknown or already-used connect request — restart from your client");
    };
    if expired {
        return redeem_err("connect request expired — restart from your client");
    }
    // Initiator proof: only the browser that STARTED this connect (holding the
    // `sid` cookie) may redeem. In the confused-deputy path the delegation lands
    // in the honest page in the VICTIM's browser, whose cookie does not match the
    // one `X` was bound to, so this aborts (see the design's security argument).
    if connect_cookie(&headers).as_deref() != Some(cookie.as_str()) {
        return redeem_err(
            "this sign-in was started in a different browser session — restart the connection from your client",
        );
    }
    // Idempotent: if a code was already minted for this connect, return it again.
    if let Some(code) = existing_code {
        return Json(json!({ "redirect": build_redirect(&redirect_uri, &code, &client_state) })).into_response();
    }
    // Decode the fragment delegation (PROVISIONAL wire shape).
    let (user_key, chain) = match parse_registration_delegation(&body.user_key, &body.delegation) {
        Ok(v) => v,
        Err(e) => return redeem_err(&format!("malformed registration delegation: {e}")),
    };
    // Single-flight: atomically claim this connect's redemption so a double-submit
    // can't fire two concurrent mcp_register_v2 calls (and a request racing a
    // just-finished attempt gets that attempt's code instead of redeeming again).
    match claim_redemption(&store, &body.state).await {
        RedeemClaim::Claimed => {}
        RedeemClaim::Existing(code) => {
            return Json(json!({ "redirect": build_redirect(&redirect_uri, &code, &client_state) }))
                .into_response()
        }
        RedeemClaim::InProgress => {
            return redeem_err(
                "another redemption attempt for this connect is already in progress — \
                 wait a moment; if it does not complete, restart from your client",
            )
        }
        RedeemClaim::Vanished => return redeem_err("connect request vanished — restart from your client"),
    }
    // Redeem: build a DelegatedIdentity from priv(X) + the chain and make one
    // authenticated mcp_register_v2 call. Success proves consent AND registration.
    match store
        .identities
        .redeem_registration_delegation(&body.state, user_key, chain)
        .await
    {
        Ok(outcome) => {
            tracing::info!(
                state = %body.state,
                expiration_ns = outcome.expiration_ns,
                permissions = ?outcome.permissions,
                "registration delegation redeemed"
            );
        }
        Err(e) => {
            // Free the claim so a genuine retry can attempt redemption again.
            release_redemption(&store, &body.state).await;
            return redeem_err(&e);
        }
    }
    // Mint the PKCE-bound code (idempotent), mirroring /oauth/finish's lock
    // discipline: reserve under the `authz` lock, insert into `codes` only after
    // releasing it (consistent lock order with `token_authorization_code`).
    let fresh = format!("mcp-code-{}", Uuid::new_v4());
    let (code, newly_minted) = {
        let mut authz = store.authz.write().await;
        let Some(a) = authz.get_mut(&body.state) else {
            return redeem_err("connect request vanished — restart from your client");
        };
        a.redeeming = false;
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
                session_id: body.state.clone(),
                created: Instant::now(),
            },
        );
    }
    tracing::info!(session_id = %body.state, "grant confirmed via registration delegation; issued authorization code");
    Json(json!({ "redirect": build_redirect(&redirect_uri, &code, &client_state) })).into_response()
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

    /// H3/P5: `finish_secret` hygiene helpers. `fresh_secret` is high-entropy and
    /// unique; `sha256` is deterministic; `ct_eq` matches equal inputs and rejects
    /// unequal ones (and differing lengths) without early-out.
    #[test]
    fn secret_helpers_behave() {
        let s1 = super::fresh_secret();
        let s2 = super::fresh_secret();
        assert_ne!(s1, s2, "secrets must be unique");
        assert!(s1.len() >= 43, "256-bit base64url is 43 chars (>=128-bit floor): {}", s1.len());
        // Deterministic hash; constant-time compare of equal vs. unequal.
        assert_eq!(super::sha256(&s1), super::sha256(&s1));
        assert!(super::ct_eq(&super::sha256(&s1), &super::sha256(&s1)));
        assert!(!super::ct_eq(&super::sha256(&s1), &super::sha256(&s2)));
        assert!(!super::ct_eq(b"abc", b"abcd"));
        assert!(super::ct_eq(b"", b""));
    }

    // Build an AuthStore over a dummy II instance (these tests never hit the
    // network — the key-request path is pure-local crypto/state). v1-pinned;
    // use `test_store_phase2` for a registration-delegation instance.
    fn test_store() -> super::AuthStore {
        test_store_with(false)
    }

    // An AuthStore whose instance runs the Phase-2 registration-delegation flow.
    fn test_store_phase2() -> super::AuthStore {
        test_store_with(true)
    }

    fn test_store_with(registration_delegation: bool) -> super::AuthStore {
        use crate::identities::{Identities, IiInstance};
        use candid::Principal;
        let ids = Identities::new(IiInstance {
            name: "test",
            ii_url: "https://ii.test".into(),
            ii_canister: Principal::anonymous(),
            oauth_prefix: "",
            mcp_path: "/mcp",
            registration_delegation,
        });
        super::AuthStore::new(ids, super::SharedClients(std::sync::Arc::default()))
    }

    async fn seed_pending(store: &super::AuthStore, id: &str, cookie: &str) {
        // Insert a pending authorization directly (bypasses the browser redirect).
        store.authz.write().await.insert(
            id.to_string(),
            super::AuthzPending {
                client_id: "c".into(),
                redirect_uri: "https://app.test/cb".into(),
                client_state: String::new(),
                code_challenge: Some("cc".into()),
                cookie: cookie.into(),
                created: std::time::Instant::now(),
                finish_secret_hash: None,
                code: None,
                redeeming: false,
            },
        );
    }

    /// H3/P1: the key request is STRICTLY single-use per `connect_state`. The first
    /// mints the keypair + `finish_secret` (embedded in `finish_url`'s query) and
    /// claims the PA (`finish_secret_hash` set); a second one 403s — no keypair, no
    /// secret. This is the atomic claim that makes secret-disclosure and
    /// victim-registration mutually exclusive.
    #[tokio::test]
    async fn key_request_is_single_use_and_mints_finish_secret() {
        use axum::extract::State;
        use axum::Json;
        let store = test_store();
        seed_pending(&store, "sess-x", "bind-1").await;

        let r1 = super::connect_callback(
            State(store.clone()),
            Json(super::ConnectCallback { state: "sess-x".into(), expiration: None, permissions: None }),
        )
        .await;
        assert_eq!(r1.status(), axum::http::StatusCode::OK);
        assert!(
            store.authz.read().await.get("sess-x").unwrap().finish_secret_hash.is_some(),
            "first key request must claim the PA"
        );
        let body = axum::body::to_bytes(r1.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let finish_url = v["finish_url"].as_str().unwrap();
        assert!(finish_url.contains("&fs="), "finish_url must carry the secret in the query: {finish_url}");
        assert!(!finish_url.contains("/fs/"), "secret must not be a path segment (P2)");
        assert!(v["public_key"].as_str().is_some());

        // Second key request for the same state (attacker race / replay) => 403,
        // and it bumps the repeat-key-request observability counter (P1 health).
        let before = super::repeat_key_requests();
        let r2 = super::connect_callback(
            State(store.clone()),
            Json(super::ConnectCallback { state: "sess-x".into(), expiration: None, permissions: None }),
        )
        .await;
        assert_eq!(r2.status(), axum::http::StatusCode::FORBIDDEN, "single-use: replay must 403");
        assert!(
            super::repeat_key_requests() > before,
            "a repeat key request on a consumed connect_state must be counted"
        );
    }

    /// P3: a completion POST must NOT materialize the connection — with no prior
    /// key request it records nothing that could let `/oauth/finish` proceed (it
    /// never sets a `finish_secret`, so the consenter proof can't be satisfied).
    #[tokio::test]
    async fn completion_post_does_not_materialize_finish_secret() {
        use axum::extract::State;
        use axum::Json;
        let store = test_store();
        seed_pending(&store, "sess-y", "bind-2").await;
        let r = super::connect_callback(
            State(store.clone()),
            Json(super::ConnectCallback {
                state: "sess-y".into(),
                expiration: Some("1000".into()),
                permissions: Some("all".into()),
            }),
        )
        .await;
        assert_eq!(r.status(), axum::http::StatusCode::NO_CONTENT);
        // No key request ran, so no finish_secret exists => finish can never pass clause 2.
        assert!(store.authz.read().await.get("sess-y").unwrap().finish_secret_hash.is_none());
    }

    // ---- Phase 2: registration delegation (flag-gated) ----------------------

    use base64::Engine as _;
    use ic_agent::identity::DelegationPermissions;

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    // The v2 II link carries `pub(X)` (`regkey`) and the flow marker in addition
    // to the v1 callback/state/ttl fragment, all still in the URL fragment.
    #[test]
    fn v2_link_carries_regkey_and_flow() {
        use crate::identities::IiInstance;
        use candid::Principal;
        let inst = IiInstance {
            name: "t",
            ii_url: "https://ii.test".into(),
            ii_canister: Principal::anonymous(),
            oauth_prefix: "",
            mcp_path: "/mcp",
            registration_delegation: true,
        };
        let url = super::ii_mcp_url_v2(&inst, "sess-1", "PUBX");
        assert!(url.starts_with("https://ii.test/mcp#"), "everything rides the fragment: {url}");
        assert!(url.contains("state=sess-1"));
        assert!(url.contains("regkey=PUBX"));
        assert!(url.contains("flow=registration_delegation"));
        assert!(url.contains("callback="));
    }

    // The pinned page ships a strict CSP whose script nonce MATCHES the inline
    // script (so no `'unsafe-inline'`), limits network reach to same-origin, and
    // reflects NO attacker input (it reads the fragment client-side via
    // `location.hash` and never writes it into the HTML).
    #[tokio::test]
    async fn pinned_page_has_strict_csp_matching_nonce_and_no_reflection() {
        let resp = super::pinned_callback_page("/prod");
        let csp = resp
            .headers()
            .get(axum::http::header::CONTENT_SECURITY_POLICY)
            .expect("CSP header present")
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        // Pull the nonce out of the CSP and confirm the inline <script> uses it.
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|s| s.split('\'').next())
            .expect("nonce in CSP")
            .to_string();
        assert!(!nonce.is_empty());
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains(&format!("<script nonce=\"{nonce}\">")),
            "the inline script nonce must match the CSP nonce"
        );
        assert!(html.contains("location.hash"), "the page reads the fragment client-side");
        assert!(html.contains("/prod/oauth/connect/redeem"), "posts to the instance's redeem path");
    }

    // A well-formed fragment payload decodes into `(der(P_reg), [P_reg -> X])`
    // with the delegate key, expiration, target principal, and permissions all
    // recovered — and the permission forwarded as the matching `ic-agent` variant
    // so the reconstructed delegation hashes to what II signed.
    #[test]
    fn parse_registration_delegation_round_trips() {
        let der_x = vec![9u8, 8, 7, 6];
        let der_preg = vec![1u8, 2, 3];
        let sig = vec![4u8, 5, 6];
        let dto = serde_json::json!({
            "pubkey": b64(&der_x),
            "expiration": "42",
            "targets": ["aaaaa-aa"],
            "permissions": "queries",
            "signature": b64(&sig),
        });
        let delegation = b64(&serde_json::to_vec(&dto).unwrap());
        let (uk, chain) =
            super::parse_registration_delegation(&b64(&der_preg), &delegation).expect("parse");
        assert_eq!(uk, der_preg);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].delegation.pubkey, der_x);
        assert_eq!(chain[0].delegation.expiration, 42);
        assert_eq!(chain[0].delegation.permissions, Some(DelegationPermissions::Queries));
        assert_eq!(chain[0].signature, sig);
        assert_eq!(
            chain[0].delegation.targets.as_ref().unwrap()[0],
            candid::Principal::management_canister()
        );
    }

    // Malformed base64, an unknown permission (which would fail signature
    // verification, so we fail fast), and a non-numeric expiration are rejected.
    #[test]
    fn parse_registration_delegation_rejects_bad_input() {
        assert!(super::parse_registration_delegation("!!!", "@@@").is_err());

        let unknown = b64(&serde_json::to_vec(&serde_json::json!({
            "pubkey": b64(&[1u8]),
            "expiration": "1",
            "permissions": "write-only",
            "signature": b64(&[2u8]),
        }))
        .unwrap());
        let err = super::parse_registration_delegation(&b64(&[3u8]), &unknown)
            .expect_err("unknown permission must fail fast");
        assert!(err.contains("unrecognized permission"), "got: {err}");

        let bad_exp = b64(&serde_json::to_vec(&serde_json::json!({
            "pubkey": b64(&[1u8]),
            "expiration": "notnum",
            "signature": b64(&[2u8]),
        }))
        .unwrap());
        assert!(super::parse_registration_delegation(&b64(&[3u8]), &bad_exp).is_err());
    }

    // The CSP nonce must use the STANDARD base64 alphabet: CSP2's base64-value
    // grammar has no `-`/`_`, so a base64url nonce risks a strict parser dropping
    // the source and blocking the inline script (breaking the callback page).
    #[test]
    fn csp_nonce_is_standard_base64() {
        for _ in 0..16 {
            let n = super::csp_nonce();
            assert!(
                !n.contains('-') && !n.contains('_'),
                "CSP nonce must not use base64url characters: {n}"
            );
            assert!(n.len() >= 22, "128-bit nonce floor: {n}");
        }
    }

    // Redemption is SINGLE-FLIGHT per connect: the first claim wins, a concurrent
    // claim is refused while mid-flight, a released (failed) claim can be retried,
    // and once a code exists every later claim returns it (idempotent) instead of
    // redeeming again.
    #[tokio::test]
    async fn redemption_claim_is_single_flight() {
        let store = test_store();
        seed_pending(&store, "sess-r", "bind-r").await;

        // First claim wins; a concurrent second claim is refused.
        assert!(matches!(super::claim_redemption(&store, "sess-r").await, super::RedeemClaim::Claimed));
        assert!(matches!(
            super::claim_redemption(&store, "sess-r").await,
            super::RedeemClaim::InProgress
        ));

        // A failed attempt releases the claim, so a genuine retry proceeds.
        super::release_redemption(&store, "sess-r").await;
        assert!(matches!(super::claim_redemption(&store, "sess-r").await, super::RedeemClaim::Claimed));

        // Once the code is minted, later claims return it rather than redeeming.
        store.authz.write().await.get_mut("sess-r").unwrap().code = Some("mcp-code-x".into());
        match super::claim_redemption(&store, "sess-r").await {
            super::RedeemClaim::Existing(code) => assert_eq!(code, "mcp-code-x"),
            _ => panic!("an existing code must be returned idempotently"),
        }

        // An unknown state is Vanished.
        assert!(matches!(
            super::claim_redemption(&store, "nope").await,
            super::RedeemClaim::Vanished
        ));
    }

    // Dual-flow, per instance: on a v1-PINNED instance (prod) the Phase-2
    // surface is absent — the GET callback page and the redeem endpoint both
    // 404, so its v1 flow is provably unchanged — while a Phase-2 instance
    // (beta) serves the pinned page from the same routes.
    #[tokio::test]
    async fn phase2_routes_are_per_instance() {
        use axum::extract::State;

        // v1-pinned instance: 404s.
        let v1 = test_store();
        let page = super::connect_callback_page(State(v1.clone())).await;
        assert_eq!(page.status(), axum::http::StatusCode::NOT_FOUND);
        let redeem = super::connect_redeem(
            State(v1),
            axum::http::HeaderMap::new(),
            axum::Json(super::RedeemBody {
                state: "sess-x".into(),
                user_key: String::new(),
                delegation: String::new(),
            }),
        )
        .await;
        assert_eq!(redeem.status(), axum::http::StatusCode::NOT_FOUND);

        // Phase-2 instance: the pinned page is served (with its CSP).
        let v2 = test_store_phase2();
        let page = super::connect_callback_page(State(v2.clone())).await;
        assert_eq!(page.status(), axum::http::StatusCode::OK);
        assert!(page.headers().contains_key(axum::http::header::CONTENT_SECURITY_POLICY));
        // And its redeem endpoint is live (an unknown state is a 400, not a 404).
        let redeem = super::connect_redeem(
            State(v2),
            axum::http::HeaderMap::new(),
            axum::Json(super::RedeemBody {
                state: "sess-x".into(),
                user_key: String::new(),
                delegation: String::new(),
            }),
        )
        .await;
        assert_eq!(redeem.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    // The v1 POST callback handlers stay live on a Phase-2 instance — that's what
    // makes enabling Phase 2 outbound-compatible (an II frontend that doesn't
    // know the new flow still completes v1 against the same instance).
    #[tokio::test]
    async fn v1_key_request_still_served_on_a_phase2_instance() {
        use axum::extract::State;
        use axum::Json;
        let store = test_store_phase2();
        seed_pending(&store, "sess-v1", "bind-v1").await;
        let r = super::connect_callback(
            State(store.clone()),
            Json(super::ConnectCallback { state: "sess-v1".into(), expiration: None, permissions: None }),
        )
        .await;
        assert_eq!(r.status(), axum::http::StatusCode::OK, "v1 key request must succeed");
        assert!(store.authz.read().await.get("sess-v1").unwrap().finish_secret_hash.is_some());
    }
}
