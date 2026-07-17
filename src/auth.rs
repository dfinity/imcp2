//! OAuth 2.1 authorization server for the MCP endpoint, with **Internet Identity**
//! as the login mechanism, using II's **registration-delegation** connect handshake.
//!
//! We drive one flow — **authorization code + PKCE** — so any OAuth 2.1 client works:
//!
//!   * `/oauth/authorize` sets a browser-binding cookie (the `sid` cookie) and
//!     redirects the browser to this instance's II `/mcp` handshake, carrying this
//!     connect's registration public key `pub(X)` in the link fragment.
//!   * II certifies a short-lived, two-hop delegation chain and navigates the
//!     browser back to our **pinned callback page** (`/oauth/connect/callback`,
//!     GET) with the chain in the URL fragment.
//!   * That page — the sole reader of the fragment — POSTs the chain (with the
//!     binding cookie) to `/oauth/connect/redeem`, which redeems it, mints a
//!     PKCE-bound code, and returns the client `redirect_uri` the page navigates to.
//!
//! The RFC 8628 device grant was dropped (no listed client uses it, and it adds a
//! device-code phishing surface with none of the PKCE binding the rest of the flow
//! relies on).
//!
//! Implemented: dynamic client registration, PKCE (S256) enforced, short-lived
//! codes, access tokens whose lifetime tracks the II grant, session-key-bound
//! principal.
//!
//! ## The registration delegation handshake
//!
//! Instead of II binding a session key it was merely SHOWN, the connect delivers a
//! short-lived (≈5 min), TWO-hop delegation chain `P_reg -> Y -> X` to the pinned
//! callback page as a URL fragment: II's canister signs `P_reg -> Y` toward an
//! ephemeral key `Y` held only by II's frontend (so the piece that transits the IC
//! — replicas, boundary nodes, the public state tree — is inert on its own), and
//! the frontend extends it browser-side with a `Y`-signed hop to our registration
//! key `X`, assembling the redeemable chain only in the consenting browser. The
//! backend redeems it by signing ONE `mcp_register_v2` call as `X` (see
//! [`Identities::redeem_registration_delegation`]), binding the long-lived session
//! key `S` to the anchor. II never binds a bare key it was shown.
//!
//! `/oauth/connect/redeem` mints a code only when the requesting browser proves it
//! is BOTH the **initiator** and the **consenter**:
//!   1. *initiator* — the `sid` cookie ([`CONNECT_COOKIE`]) set at `/oauth/authorize`;
//!   2. *consenter* — the delegation chain itself, fragment-delivered only to the
//!      consenting browser and required to redeem, so only the browser that drove
//!      the II consent holds it;
//!   3. plus a *proven* registration — redemption is a signed `mcp_register_v2`
//!      that succeeds synchronously, so no separate liveness probe is needed.
//!
//! In the confused-deputy path the delegation lands in the honest page in the
//! VICTIM's browser, whose cookie does not match the one `X` was bound to, so the
//! redeem aborts. This closes the split-browser injection for all transports incl.
//! loopback (a loopback redirect resolves on the consenter's own machine). Not
//! closed here (companion control): the *same-browser* variant where a victim is
//! socially engineered into running the whole flow toward an attacker-registered
//! **hosted** `redirect_uri`; that needs hosted-redirect allow-listing (loopback is
//! safe either way).
//!
//! The wire shapes match the merged II contract (verified against the beta II
//! canister's live `.did`, `fgte5-ciaaa-aaaad-aaatq-cai`): the connect link
//! carries `registration_key` = base64url(DER(`pub(X)`)); II navigates back to
//! the callback (validated against our [`AUTH_CALLBACKS_WELL_KNOWN`] allow-list)
//! with `#delegation=<DelegationChain JSON>&state=…` (the chain plus the
//! connect state, parsed by [`parse_registration_delegation`]); and the backend
//! redeems via `mcp_register_v2(session_key) -> variant { Ok : record {
//! expiration; permissions }; Err : text }` (the `Ok` payload carries the grant
//! expiry and access level). Consent (permissions, max_ttl) is NOT echoed: the user chose
//! it earlier at `prepare_mcp_registration_delegation`, which stored it keyed by
//! `P_reg`, so II recovers it (and the user's identity number) from
//! `caller() == P_reg`, and the server sends and sees neither.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
/// Fallback access-token lifetime, used only when the II grant's expiration is
/// unknown at issue time. In the normal flow the token's lifetime tracks the grant
/// instead (see [`token_ttl`]), so the session duration the user picked on II's
/// consent screen is honoured.
const TOKEN_TTL: Duration = Duration::from_secs(3600);
/// `ttl` (seconds) requested for the II grant. Clamped by II to [600, 2592000].
const GRANT_TTL_SECS: u64 = 3600;

/// Name of the browser-session cookie that binds `/oauth/authorize` to
/// `/oauth/connect/redeem`: only the browser that started the flow can complete it.
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
    /// *Initiator* proof: unguessable value set as the `sid` browser cookie at
    /// `/oauth/authorize` and matched at `/oauth/connect/redeem` — only the browser
    /// that STARTED this flow presents it. Combined with the fragment-delivered
    /// delegation (the *consenter* proof) it closes the split-browser injection
    /// (see the module docs).
    cookie: String,
    created: Instant,
    /// The authorization code minted once the grant is confirmed (idempotent redeem).
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
/// handshake; II navigates back to our pinned callback page with the delegation.
pub async fn authorize(State(store): State<AuthStore>, Query(q): Query<AuthorizeQuery>) -> Response {
    // Only the authorization-code response type is supported.
    match q.response_type.as_deref() {
        Some("code") => {}
        Some(_) => return oauth_err(StatusCode::BAD_REQUEST, "unsupported_response_type", "only response_type=code"),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "response_type=code required"),
    }
    if !store.validate_client(&q.client_id, &q.redirect_uri).await {
        // `invalid_client` (not `invalid_request`): the request is well-formed,
        // it's the CLIENT identification that failed — the AS error code the
        // MCP server guide (and RFC 6749's taxonomy) expects here. No redirect:
        // an unvalidated redirect_uri must never receive an error response.
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "unknown client_id / redirect_uri");
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
    // Bind this browser to the flow (the `sid` cookie, set now and required at
    // `/oauth/connect/redeem`). The `state` alone can't prove the redeeming
    // browser is the initiator (it's echoed to the client). The cookie proves
    // *initiator*; the fragment-delivered delegation proves *consenter*; requiring
    // both closes the split-browser injection.
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
            code: None,
            redeeming: false,
        },
    );

    // Redirect the browser to this instance's II handshake, setting the binding
    // cookie. II navigates back to our pinned callback page once it certifies the
    // delegation; SameSite=Lax lets the cookie ride that top-level cross-site GET
    // back to us. Scoped to this instance's OAuth prefix. `Secure` only when served
    // over HTTPS (production always is): a `Secure` cookie is dropped by browsers
    // over plain HTTP, which would break the initiator check for local
    // `http://localhost` development.
    let secure = if base_url().starts_with("https://") { "; Secure" } else { "" };
    let set_cookie = format!(
        "{CONNECT_COOKIE}={cookie}; Path={}/oauth; Max-Age={}; HttpOnly{secure}; SameSite=Lax",
        store.instance().oauth_prefix,
        CONNECT_TTL.as_secs(),
    );
    // Mint this connect's registration key `X` and carry `pub(X)` in the II link,
    // toward which II builds the registration chain (`P_reg -> Y -> X`, the last
    // hop browser-signed to `X`).
    let reg_pubkey = store.identities.registration_pubkey_b64(&session_id).await;
    let ii_url = ii_mcp_url(store.instance(), &session_id, &reg_pubkey);
    // Redirect the consenting browser to the II connect link with a real HTTP
    // 302 (`Location`). The link's params ride in the URL fragment
    // (`#callback=…&state=…&registration_key=…`); modern browsers preserve a
    // fragment present in a `Location` header (RFC 9110 §10.2.2), and the fragment
    // never goes on the wire, so II's frontend reads it from `location.hash`, with
    // one fewer interposition point than a script-driven hop, and this outbound 302
    // hop to II needs no JS (the pinned callback page that later reads the fragment
    // does). `redirect_302` also sets `Referrer-Policy: no-referrer` (the
    // authorize query carries only non-secret OAuth params, so that is tidiness,
    // not a leak fix).
    let mut resp = redirect_302(&ii_url);
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

/// A 302 to the II connect link — the outbound top-level hop from `authorize`. A
/// `Location` fragment (the link's `#callback=…`) is preserved by modern browsers
/// (RFC 9110 §10.2.2) and never sent on the wire, so II reads it from
/// `location.hash`. Sets `Referrer-Policy: no-referrer` (tidiness — the authorize
/// query carries only non-secret OAuth params).
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

/// Build an instance's II `/mcp` connect link for a connection. Everything is in
/// the URL fragment (never sent to II's servers): this instance's callback on our
/// origin, the single-use `state` (= session id), the requested grant `ttl` in
/// SECONDS, and `registration_key` — this connect's registration public key
/// `pub(X)` (DER, base64url), toward which II builds the registration chain
/// `P_reg -> Y -> X` (param name per dfinity/internet-identity#4093; its presence
/// selects the connect flow). II navigates the tab back to `callback` — validated
/// against our [`AUTH_CALLBACKS_WELL_KNOWN`] allow-list (#4091) — with the
/// delegation in the fragment; that callback page is our sole fragment reader
/// ([`connect_callback_page`]). No `priv(X)` is ever put in the link — only its
/// public half.
fn ii_mcp_url(inst: &crate::identities::IiInstance, session_id: &str, reg_pubkey_b64: &str) -> String {
    format!(
        "{ii}/mcp#callback={cb}&state={st}&ttl={ttl}&registration_key={rk}",
        ii = inst.ii_url,
        cb = urlencoding::encode(&connect_callback_url(inst)),
        st = urlencoding::encode(session_id),
        ttl = GRANT_TTL_SECS,
        rk = urlencoding::encode(reg_pubkey_b64),
    )
}
// ---- Callback allow-list (II #4091) ---------------------------------------

/// The well-known path Internet Identity fetches a server's **auth-callback
/// allow-list** from (dfinity/internet-identity#4091): before contacting the
/// connect callback named in the (attacker-craftable) link fragment, II fetches
/// `<callback origin>` + this path — `redirect: "error"`, no credentials,
/// `no-store`, 8 KB cap, `application/json` required — and rejects the connect
/// unless the callback URL is EXACTLY (string-equal) one of the declared
/// entries. **Fail-closed**: a missing/unfetchable file fails every connect for
/// this origin, so serving this document is mandatory once #4091 ships.
pub const AUTH_CALLBACKS_WELL_KNOWN: &str = "/.well-known/ii-auth-callbacks";

/// An instance's connect-callback URL — the single source of truth used BOTH in
/// the II link fragment and in the [`auth_callbacks`] allow-list, so the two
/// can never drift: II matches them by exact string equality (no
/// normalization, no case/slash slack).
fn connect_callback_url(inst: &crate::identities::IiInstance) -> String {
    format!("{}{}/oauth/connect/callback", base_url(), inst.oauth_prefix)
}

/// GET /.well-known/ii-auth-callbacks — declare every instance's connect
/// callback (II #4091 validates every connect against this list; the path is
/// origin-global, so one document covers both instances).
/// Served with CORS (II's frontend fetches it cross-origin) and well under
/// II's 8 KB cap.
pub async fn auth_callbacks(State(stores): State<Vec<AuthStore>>) -> Response {
    let callbacks: Vec<String> = stores.iter().map(|s| connect_callback_url(s.instance())).collect();
    let mut resp = Json(json!({ "callbacks": callbacks })).into_response();
    // Fail-closed, exact-match infrastructure must never be served stale: II's
    // fetch is `cache: no-store` on ITS side, but an intermediary (CDN/proxy)
    // could still cache our response — after a callback-path change that would
    // break every connect until the cache expired. Forbid caching explicitly.
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    resp
}

// ---- Connect callback page + redeem -------------------------------------

/// GET /oauth/connect/callback — the **pinned callback page**. II navigates the
/// consenting browser here with the canister-signed delegation in the URL
/// fragment. This page is the SOLE reader of that fragment: it reads
/// `location.hash` entirely client-side, POSTs it (with the connect cookie) to
/// [`connect_redeem`], strips it from the address bar, then navigates to the
/// redirect the backend returns. It never writes any fragment/query value into
/// the DOM (no reflection), and ships a strict CSP.
pub async fn connect_callback_page(State(store): State<AuthStore>) -> Response {
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

/// Styling for the pinned callback page, following the DFINITY brand guidelines
/// (Parchment/Ink/Rust palette, an editorial serif display over a UI sans, a
/// grid-paper surface, and the official gradient-infinity logo). A full-bleed
/// screen: the status stage (a spinner on a soft elevated tile plus an accessible
/// serif headline) fills and centres the viewport, with a foot-of-page "Hosted
/// by" mark; the spinner is CSS-only (disabled under `prefers-reduced-motion`).
/// Light/dark theming via `prefers-color-scheme` with a `data-theme` override,
/// using the brand's Bark/Bone/Ember dark palette. Fully self-contained (no
/// external fonts, images, or stylesheets; the logo is inlined into the served
/// HTML), so it renders identically under the pinned page's strict
/// `default-src 'none'` CSP. The stylesheet lives in `assets/connect.css` and is
/// compiled into the binary via `include_str!` (no runtime file I/O), so it is
/// authored as a real `.css` file rather than a Rust string literal. The pinned
/// page serves it in a `<style nonce>` block (with `style-src 'nonce-...'` added
/// to its CSP so the block is allowed WITHOUT `'unsafe-inline'`). The `.error`
/// modifier (added to `.screen` client-side) hides the spinner tile once a
/// terminal message is shown.
const CONNECT_PAGE_CSS: &str = include_str!("assets/connect.css");

/// The official DFINITY logo (gradient-infinity mark + wordmark), taken from
/// dfinity.org. It lives in `assets/dfinity-logo.svg` and is compiled into the
/// binary via `include_str!`, then inlined into the served HTML so it needs no
/// external fetch under the pinned page's strict CSP. The infinity keeps the
/// brand gradients; the wordmark is set to `currentColor` so it follows the
/// page's Ink/Bone text color across light and dark themes.
const CONNECT_LOGO_SVG: &str = include_str!("assets/dfinity-logo.svg");

/// HTML template for the pinned callback page, kept as a real `.html` asset file
/// (compiled in via `include_str!`, no runtime file I/O) rather than an inline
/// Rust string literal, so the markup reads and diffs as HTML. It is a self-
/// contained document with `__TOKEN__` placeholders spliced in at render time
/// (the stylesheet `__CSS__`, the logo `__LOGO__`, and the per-response
/// `__NONCE__`/`__SCRIPT__`). No user-influenced value is ever interpolated.
const PINNED_PAGE_HTML: &str = include_str!("assets/connect-callback.html");

/// The strict-CSP, non-reflecting pinned callback page. `nonce` is a fresh
/// per-response value bound into the CSP header and BOTH the inline `<script>`
/// and `<style>`, so no `'unsafe-inline'` is needed; `connect-src 'self'` limits
/// the page's only network reach to the same-origin redeem endpoint, and
/// `default-src 'none'` forbids loading anything else (all styling is inline and
/// self-contained; see [`CONNECT_PAGE_CSS`]). No attacker-supplied value
/// (fragment, query) is ever interpolated into the HTML; the fragment is read
/// client-side and sent via `fetch`, never written to the DOM.
///
/// The fragment shape matches II's frontend (merged contract): the delegation
/// chain plus the connect state only:
/// `#delegation=<JSON.stringify(DelegationChain.toJSON())>&state=<state>`,
/// percent-encoded by `URLSearchParams`. The script reads both fields and
/// forwards them to the redeem endpoint (the chain's JSON text and the state
/// echo). There is no `anchor`, and no `permissions`/`ttl`, in the fragment:
/// the consent was captured earlier at `prepare_mcp_registration_delegation`
/// (keyed by `P_reg`), and II recovers it (and the user's identity number)
/// from `caller() == P_reg`, so the server sees none of them.
///
/// The pinned page's inline script and stylesheet are kept as PLAIN strings,
/// not `format!` templates, so they read naturally (no doubled braces, room for
/// comments). The one dynamic value in the script, the redeem URL, is spliced in
/// by replacing `__REDEEM_URL__`, which sits inside a quoted JS string literal
/// below.
const PINNED_PAGE_JS: &str = r#"(function () {
  function show(t, err) {
    document.getElementById('m').textContent = t;
    if (err) {
      var c = document.querySelector('.screen');
      if (c) { c.classList.add('error'); }
    }
  }
  // II delivers #delegation=<chain JSON>&state=<state>: the two-hop chain plus
  // the connect state, percent-encoded by URLSearchParams and decoded again by
  // it here. Consent (permissions, max_ttl) is NOT in the fragment: the user
  // chose it earlier at II's prepare step, which stored it keyed by P_reg, and
  // mcp_register_v2 recovers it server-side. So the page forwards only the chain
  // and the state; the backend redeems with mcp_register_v2(session_key).
  var params = new URLSearchParams(location.hash.slice(1));
  var body = JSON.stringify({
    state: params.get('state') || '',
    delegation: params.get('delegation') || ''
  });
  // Scrub the delegation from the address bar, keeping the path and any query
  // string the declared callback carries. Best-effort: the POST below works
  // even if a browser refuses the history call.
  try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
  fetch("__REDEEM_URL__", {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: body
  })
    .then(function (r) { return r.json().catch(function () { return {}; }); })
    .then(function (d) {
      if (d && d.redirect) {
        location.replace(d.redirect);
      } else {
        show((d && d.error) || 'Could not finish the connection. Restart from your client.', true);
      }
    })
    .catch(function () {
      show('Could not reach the server. Restart from your client.', true);
    });
})();"#;

fn pinned_callback_page(prefix: &str) -> Response {
    let nonce = csp_nonce();
    let redeem = js_escape(&format!("{prefix}/oauth/connect/redeem"));
    let script = PINNED_PAGE_JS.replace("__REDEEM_URL__", &redeem);
    // The markup lives in `assets/connect-callback.html` (include_str!). The
    // status line is a `role=status` / `aria-live=polite` region so screen
    // readers announce both "Connecting agent to Internet Identity…" and any
    // terminal error the script swaps in. The DFINITY logo carries its own
    // `aria-label`; the spinner is decorative (`aria-hidden`). `__NONCE__` (both
    // the `<style>` and `<script>` tags), then the self-contained stylesheet,
    // logo, and redeem script are spliced in; none of those values contains a
    // placeholder token, so the order is immaterial.
    let html = PINNED_PAGE_HTML
        .replace("__NONCE__", &nonce)
        .replace("__CSS__", CONNECT_PAGE_CSS)
        .replace("__LOGO__", CONNECT_LOGO_SVG)
        .replace("__SCRIPT__", &script);
    // `style-src 'nonce-{nonce}'` admits ONLY the nonce'd `<style>` block above
    // (no `'unsafe-inline'`, so an injected `style=` attribute or stray `<style>`
    // still can't apply). Without it the block falls back to `default-src
    // 'none'` and the page renders unstyled.
    // `frame-ancestors 'none'`: II reaches this page only by top-level
    // navigation, so framing is never legitimate: deny it outright so the
    // delegation-bearing page can't be embedded for UI redress. X-Frame-Options
    // covers legacy browsers that predate CSP2 (modern ones ignore it when
    // frame-ancestors is present).
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
         connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
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
    h.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    resp
}

/// POST /oauth/connect/redeem body — what [`pinned_callback_page`] sends after
/// parsing the fragment: the `state` echo and the delegation chain's JSON text
/// exactly as II's frontend put it in the fragment
/// (`JSON.stringify(DelegationChain.toJSON())`, dfinity/internet-identity#4093).
/// **No consent values and no anchor are carried**: the user's chosen
/// permissions/TTL were captured earlier at `prepare_mcp_registration_delegation`
/// (keyed by `P_reg`), and II recovers them, and the user's identity number,
/// from `caller() == P_reg`, so the server never sees any of them.
#[derive(Deserialize)]
pub struct RedeemBody {
    /// The single-use connect state (= session id), echoed by II.
    state: String,
    /// The two-hop `P_reg -> Y -> X` chain as agent-js `DelegationChain` JSON
    /// ([`JsonDelegationChain`]); `der(P_reg)` rides inside as `publicKey`.
    #[serde(default)]
    delegation: String,
}

/// Size cap for the redeem body's `delegation` JSON text, checked BEFORE
/// parsing so oversized attacker-controlled input is rejected without large
/// allocations (same posture as the discovery-buffering bound, CWE-770). A
/// legitimate chain — one delegation plus a canister signature with its
/// certificate — is a few KB of hex/JSON, so this is generous while staying
/// far under axum's 2 MB body default. Defense-in-depth: the cookie gate
/// already means only the connect's own initiator can reach the parse at all.
const MAX_REG_DELEGATION_JSON: usize = 64 * 1024;

/// agent-js `DelegationChain.toJSON()`, the wire shape II's frontend delivers
/// in the callback fragment (dfinity/internet-identity#4093): byte fields are
/// HEX strings, `expiration` is a HEX string of ns since the epoch
/// (`BigInt.toString(16)`), `targets` are principal texts, and `publicKey` is
/// the chain root `der(P_reg)`. `delegations` carries TWO hops — the
/// canister-signed `P_reg -> Y` toward II's ephemeral browser-held `Y`, and
/// the `Y`-signed `Y -> X` toward our registration key (the split keeps the
/// canister-signed piece, which transits the IC, inert on its own).
///
/// `deny_unknown_fields` on purpose: every field of a delegation is covered by
/// its canister signature, so a field this parser does not carry (e.g. a future
/// `permissions`) could never re-hash to what II signed — dropping it silently
/// would resurface the opaque "sig not found in the signature tree" replica
/// error (the #40 read-only outage). Failing fast names the real problem.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDelegationChain {
    delegations: Vec<JsonSignedDelegation>,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSignedDelegation {
    delegation: JsonDelegation,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDelegation {
    pubkey: String,
    /// Hex string of ns since the Unix epoch (agent-js `BigInt.toString(16)`).
    expiration: String,
    #[serde(default)]
    targets: Option<Vec<String>>,
}

/// Decode a hex string field of the chain JSON.
fn hex_decode(field: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|e| format!("{field} is not valid hex: {e}"))
}

/// Parse the fragment's `DelegationChain` JSON into `(der(P_reg), chain)` as
/// `ic-agent` types — hop count is preserved verbatim (two hops per rev3 of the
/// guide; the redeem path only requires that the FINAL hop targets our `X`, and
/// the replica verifies every hop authoritatively). The chain carries no
/// `permissions` field: the access level isn't stored in the delegation at all.
/// The user chose it at consent, II stored it under `P_reg` at
/// `prepare_mcp_registration_delegation`, and it never touches the server. So a
/// `permissions` field appearing here would be unexpected, and
/// [`JsonDelegationChain`] fails fast if one ever does.
fn parse_registration_delegation(delegation_json: &str) -> Result<(Vec<u8>, Vec<SignedDelegation>), String> {
    // Bound the size BEFORE parsing (see MAX_REG_DELEGATION_JSON): reject
    // oversized input without allocating for it. This also inherently bounds
    // every field inside the JSON (pubkeys, signatures, targets).
    if delegation_json.len() > MAX_REG_DELEGATION_JSON {
        return Err(format!("delegation exceeds {MAX_REG_DELEGATION_JSON} bytes"));
    }
    let chain: JsonDelegationChain =
        serde_json::from_str(delegation_json).map_err(|e| format!("delegation JSON: {e}"))?;
    let user_key = hex_decode("publicKey", &chain.public_key)?;
    let delegations = chain
        .delegations
        .iter()
        .map(|d| {
            let targets = match &d.delegation.targets {
                None => None,
                Some(ts) => Some(
                    ts.iter()
                        .map(|t| {
                            Principal::from_text(t.trim())
                                .map_err(|e| format!("delegation target principal: {e}"))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            };
            Ok(SignedDelegation {
                delegation: Delegation {
                    pubkey: hex_decode("delegation pubkey", &d.delegation.pubkey)?,
                    expiration: u64::from_str_radix(d.delegation.expiration.trim(), 16)
                        .map_err(|_| "delegation expiration is not a hex u64".to_string())?,
                    targets,
                    permissions: None,
                },
                signature: hex_decode("delegation signature", &d.signature)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((user_key, delegations))
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
/// connect — a page double-submit can't fire two concurrent redemptions. (II
/// would tolerate the race — within its 5-minute lifetime the delegation
/// redeems repeatedly, and a retry with the same `S` just re-binds it — but one
/// deterministic attempt is strictly better than racing two.)
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

/// POST /oauth/connect/redeem — the pinned page POSTs the fragment here. Verifies
/// the browser is the connect INITIATOR (the `sid` cookie), then redeems the
/// delegation via [`Identities::redeem_registration_delegation`] — which is BOTH
/// the consenter proof (fragment-delivered only to the consenting browser) and
/// proof of registration (synchronous, so no separate liveness probe is needed) —
/// and mints the PKCE-bound authorization code, returning the client redirect for
/// the page to navigate to.
pub async fn connect_redeem(
    State(store): State<AuthStore>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RedeemBody>,
) -> Response {
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
    // Decode the fragment delegation (agent-js DelegationChain JSON, II #4093)
    // before claiming, so a malformed delivery never occupies the single-flight
    // slot. No consent values are parsed: they're not in the fragment (II
    // captured them at prepare and recovers them from caller() == P_reg).
    let (user_key, chain) = match parse_registration_delegation(&body.delegation) {
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
    // Mint the PKCE-bound code (idempotent): reserve under the `authz` lock,
    // insert into `codes` only after releasing it (consistent lock order with
    // `token_authorization_code`).
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

/// Escape a string for embedding inside a double-quoted JS string literal.
fn js_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('<', "\\x3c")
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

/// The access-token lifetime, matched to the II grant ("never issue a token that
/// outlives the grant"): the token expires exactly when the grant does, so the
/// session duration the user picks on II's consent screen (10 minutes up to 30
/// days) is how long the client's token stays valid — there is no separate fixed
/// cap. Keeping the client's view aligned with the grant means it re-auths right
/// when the grant lapses (a 401 `invalid_token` + inline re-auth) instead of
/// hitting opaque tool errors on a live-looking token, and an already-expired
/// grant yields a zero TTL (the token is born invalid). When the expiration is
/// unknown at issue time (e.g. the connect completion POST didn't land) we fall
/// back to `default`; the grant is still the hard ceiling at II either way.
fn token_ttl(default: Duration, grant_expiration_ns: Option<u64>, now_ns: u64) -> Duration {
    match grant_expiration_ns {
        Some(exp_ns) => Duration::from_nanos(exp_ns.saturating_sub(now_ns)),
        None => default,
    }
}

/// Mint + store an access token bound to the session key's principal, its
/// lifetime matched to the II grant's expiration (see [`token_ttl`]).
async fn issue_token(store: &AuthStore, session_id: &str) -> Response {
    let principal = store
        .identities
        .session_principal(session_id)
        .await
        .unwrap_or_else(|| "unknown".to_string());
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let ttl = token_ttl(
        TOKEN_TTL,
        store.identities.grant_expiration_ns(session_id).await,
        now_ns,
    );

    let access_token = format!("mcp-token-{}", Uuid::new_v4());
    store.tokens.write().await.insert(
        access_token.clone(),
        TokenInfo {
            principal: principal.clone(),
            session_id: session_id.to_string(),
            created: Instant::now(),
            ttl,
        },
    );
    tracing::info!(%principal, ttl_secs = ttl.as_secs(), "issued MCP access token");

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ttl.as_secs(),
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

/// The grant types to register for a DCR request: the intersection of the
/// requested types with what we implement, with an empty request defaulting to
/// the full supported set (RFC 7591 makes the RESPONSE authoritative — a
/// client that asked for `refresh_token` sees it wasn't granted). `None` means
/// the intersection lost `authorization_code` — the only flow we run — so the
/// registration must be refused with `invalid_client_metadata` rather than
/// minting a client that could never complete any flow.
fn granted_grant_types(requested: &[String]) -> Option<Vec<String>> {
    const SUPPORTED: [&str; 1] = ["authorization_code"];
    let granted: Vec<String> = if requested.is_empty() {
        SUPPORTED.iter().map(|s| s.to_string()).collect()
    } else {
        let mut g: Vec<String> = requested
            .iter()
            .filter(|g| SUPPORTED.contains(&g.as_str()))
            .cloned()
            .collect();
        g.dedup();
        g
    };
    granted.iter().any(|g| g == "authorization_code").then_some(granted)
}

/// POST /oauth/register (RFC 7591). `redirect_uris` are stored for the auth-code
/// flow — the only grant we support. Requested `grant_types` are intersected
/// with the supported set ([`granted_grant_types`]); a request whose
/// intersection loses `authorization_code` is refused with
/// `invalid_client_metadata` BEFORE anything is stored.
pub async fn register(State(store): State<AuthStore>, Json(req): Json<RegisterRequest>) -> Response {
    let Some(granted) = granted_grant_types(&req.grant_types) else {
        return oauth_err(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "this server only supports the authorization_code grant; request it (or omit grant_types)",
        );
    };

    let client_id = format!("client-{}", Uuid::new_v4());
    let snapshot = {
        let mut clients = store.clients.write().await;
        clients.insert(client_id.clone(), ClientReg { redirect_uris: req.redirect_uris.clone() });
        clients.clone()
    };
    tokio::task::spawn_blocking(move || persist_clients(&snapshot)).await.ok();

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
            // Refresh the session's activity window so it counts on /version's
            // `active_sessions` gauge; a client that stops sending requests drops
            // off after the activity window (the only proxy for a disconnect in
            // stateless mode). This does NOT affect `live_sessions`, which tracks
            // the grant lifecycle independently of activity.
            store.identities.touch_session(&session_id).await;
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

    /// Guide: "never issue a token that outlives the grant." The token TTL is
    /// the grant's remaining lifetime when known — so a long session (e.g. the
    /// user picked a week) mints a correspondingly long token, with no fixed 1h
    /// cap — falling back to the default only when the expiration is unknown; an
    /// already-expired grant yields a zero TTL (the token is born invalid,
    /// steering the client to re-auth).
    #[test]
    fn token_ttl_tracks_grant_expiration() {
        use std::time::Duration;
        let default = Duration::from_secs(3600);
        let now_ns: u64 = 1_000_000_000_000_000_000;
        // No known expiration → the fallback default.
        assert_eq!(super::token_ttl(default, None, now_ns), default);
        // Grant known and longer than the default → the FULL remaining grant
        // (the old fixed 1h cap is gone: a 1-day grant mints a 1-day token).
        let far = now_ns + 86_400 * 1_000_000_000;
        assert_eq!(
            super::token_ttl(default, Some(far), now_ns),
            Duration::from_secs(86_400)
        );
        // Grant known and shorter than the default (user picked 10 min) → that.
        let soon = now_ns + 600 * 1_000_000_000;
        assert_eq!(
            super::token_ttl(default, Some(soon), now_ns),
            Duration::from_secs(600)
        );
        // Grant already expired → zero (never a negative-wrap).
        assert_eq!(
            super::token_ttl(default, Some(now_ns - 1), now_ns),
            Duration::ZERO
        );
    }

    /// RFC 7591 / guide: requested grant types are INTERSECTED with the
    /// supported set and the result returned (authoritative response); an empty
    /// request defaults to authorization_code; an intersection that loses
    /// authorization_code refuses the registration (None → the handler answers
    /// invalid_client_metadata) instead of minting a client that can't run any
    /// flow.
    #[test]
    fn granted_grant_types_intersects_and_refuses_codeless() {
        let g = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Empty request → the supported default.
        assert_eq!(super::granted_grant_types(&[]), Some(g(&["authorization_code"])));
        // Optimistic request → intersected, refresh_token visibly not granted.
        assert_eq!(
            super::granted_grant_types(&g(&["authorization_code", "refresh_token"])),
            Some(g(&["authorization_code"]))
        );
        // Requests whose intersection loses authorization_code are refused.
        assert_eq!(super::granted_grant_types(&g(&["refresh_token"])), None);
        assert_eq!(super::granted_grant_types(&g(&["client_credentials"])), None);
    }

    #[test]
    fn build_redirect_encodes_code_and_state() {
        let r = build_redirect("https://claude.ai/cb", "mcp-code-1", "abc/def");
        assert_eq!(r, "https://claude.ai/cb?code=mcp-code-1&state=abc%2Fdef");
        // Appends with & when the redirect already has a query.
        let r2 = build_redirect("https://x.test/cb?foo=1", "c", "");
        assert_eq!(r2, "https://x.test/cb?foo=1&code=c");
    }

    // Build an AuthStore over a dummy II instance (these tests never hit the
    // network — the connect paths are pure-local crypto/state).
    fn test_store() -> super::AuthStore {
        use crate::identities::{Identities, IiInstance};
        use candid::Principal;
        let ids = Identities::new(IiInstance {
            name: "test",
            ii_url: "https://ii.test".into(),
            ii_canister: Principal::anonymous(),
            oauth_prefix: "",
            mcp_path: "/mcp",
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
                code: None,
                redeeming: false,
            },
        );
    }

    // ---- Connect: link + redeem ---------------------------------------------

    // The II link carries `registration_key` = base64url(DER(pub(X))) (the
    // param II's #4093 frontend parses; its presence selects the flow) in
    // addition to the callback/state/ttl fragment, all in the URL fragment.
    #[test]
    fn v2_link_carries_registration_key() {
        use crate::identities::IiInstance;
        use candid::Principal;
        let inst = IiInstance {
            name: "t",
            ii_url: "https://ii.test".into(),
            ii_canister: Principal::anonymous(),
            oauth_prefix: "",
            mcp_path: "/mcp",
        };
        let url = super::ii_mcp_url(&inst, "sess-1", "PUBX");
        assert!(url.starts_with("https://ii.test/mcp#"), "everything rides the fragment: {url}");
        assert!(url.contains("state=sess-1"));
        assert!(url.contains("registration_key=PUBX"));
        assert!(url.contains("callback="));
    }

    // The allow-list invariant (II #4091 matches by EXACT string equality): the
    // /.well-known/ii-auth-callbacks document must declare, verbatim, the same
    // callback URLs the II links embed — for every instance. Built from one
    // helper (`connect_callback_url`) so they cannot drift; this test locks
    // that in end to end.
    #[tokio::test]
    async fn auth_callbacks_declares_link_callbacks_verbatim() {
        use axum::extract::State;
        use crate::identities::{Identities, IiInstance};
        use candid::Principal;
        let make = |prefix: &'static str, mcp_path: &'static str| {
            super::AuthStore::new(
                Identities::new(IiInstance {
                    name: "t",
                    ii_url: "https://ii.test".into(),
                    ii_canister: Principal::anonymous(),
                    oauth_prefix: prefix,
                    mcp_path,
                }),
                super::SharedClients(std::sync::Arc::default()),
            )
        };
        // Both instances, so the allow-list covers each prefix.
        let beta = make("", "/mcp");
        let prod = make("/prod", "/mcp-prod");

        let r = super::auth_callbacks(State(vec![beta.clone(), prod.clone()])).await;
        assert_eq!(r.status(), axum::http::StatusCode::OK);
        assert!(
            r.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.starts_with("application/json")),
            "II requires an application/json content type"
        );
        // Fail-closed infrastructure must not be servable stale by an
        // intermediary cache: the response itself forbids storing.
        assert_eq!(
            r.headers().get(axum::http::header::CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "the allow-list must be non-cacheable"
        );
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let declared: Vec<String> = v["callbacks"]
            .as_array()
            .expect("callbacks array")
            .iter()
            .map(|e| e.as_str().unwrap().to_string())
            .collect();
        assert_eq!(declared.len(), 2, "one entry per instance");

        // Each declared entry must equal the callback embedded in that
        // instance's II link, byte for byte.
        for (store, link) in [
            (&beta, super::ii_mcp_url(beta.instance(), "s", "K")),
            (&prod, super::ii_mcp_url(prod.instance(), "s", "K")),
        ] {
            let expected = super::connect_callback_url(store.instance());
            assert!(declared.contains(&expected), "{expected} must be declared: {declared:?}");
            let encoded = format!("callback={}", urlencoding::encode(&expected));
            assert!(link.contains(&encoded), "the II link must embed the declared URL: {link}");
        }
        // Both entries share the origin II fetches the document from, and no
        // entry carries a fragment (II rejects both).
        for d in &declared {
            assert!(d.starts_with(&super::base_url()), "same-origin entries only: {d}");
            assert!(!d.contains('#'), "no fragments in declared callbacks: {d}");
        }
    }

    // /oauth/authorize hands the browser to II with a real HTTP 302 (not a 200 +
    // JS page): lock in the status, the `Location` (the II link with its fragment
    // params intact), `Referrer-Policy: no-referrer`, and the binding cookie, so a
    // regression to a script-driven hop or a dropped header is caught.
    #[tokio::test]
    async fn authorize_redirects_302_with_fragment_cookie_and_no_referrer() {
        use axum::extract::{Query, State};
        let store = test_store();
        // Register a client so `validate_client` passes and we reach the redirect.
        store.clients.write().await.insert(
            "client-x".into(),
            super::ClientReg { redirect_uris: vec!["https://app.example/cb".into()] },
        );
        let resp = super::authorize(
            State(store.clone()),
            Query(super::AuthorizeQuery {
                response_type: Some("code".into()),
                client_id: "client-x".into(),
                redirect_uri: "https://app.example/cb".into(),
                state: Some("xyz".into()),
                code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
                code_challenge_method: Some("S256".into()),
                scope: None,
                resource: None,
            }),
        )
        .await;

        assert_eq!(resp.status(), axum::http::StatusCode::FOUND, "authorize must 302, not render a page");
        let h = resp.headers();
        let location = h.get(axum::http::header::LOCATION).unwrap().to_str().unwrap();
        // The II link, with the connect params carried in the URL FRAGMENT.
        assert!(location.starts_with("https://ii.test/mcp#"), "redirects to the II /mcp link: {location}");
        for needle in ["callback=", "state=", "registration_key="] {
            assert!(location.contains(needle), "fragment must carry `{needle}`: {location}");
        }
        assert_eq!(
            h.get(axum::http::header::REFERRER_POLICY).unwrap().to_str().unwrap(),
            "no-referrer",
            "the redirect must set Referrer-Policy: no-referrer"
        );
        let cookie = h.get(axum::http::header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(
            cookie.contains(&format!("{}=", super::CONNECT_COOKIE)),
            "the binding cookie must be set: {cookie}"
        );
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
        // Never legitimately framed (II top-level-navigates here): deny UI redress.
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
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
        // The stylesheet is nonce'd too, and the CSP admits it via style-src;
        // without it the strict `default-src 'none'` would drop the styles and
        // the page would render unstyled (the bug that motivated this work).
        assert!(
            csp.contains(&format!("style-src 'nonce-{nonce}'")),
            "style-src must carry the same nonce: {csp}"
        );
        assert!(
            html.contains(&format!("<style nonce=\"{nonce}\">")),
            "the inline style nonce must match the CSP nonce"
        );
        assert!(html.contains("location.hash"), "the page reads the fragment client-side");
        assert!(html.contains("/prod/oauth/connect/redeem"), "posts to the instance's redeem path");
        assert!(!html.contains("__REDEEM_URL__"), "the redeem-URL placeholder must be substituted");
        // Merged contract: the page forwards ONLY the chain and the connect
        // state. It reads neither the consent values (captured earlier at
        // prepare, recovered by II from caller() == P_reg) nor an anchor.
        for param in ["state", "delegation"] {
            assert!(
                html.contains(&format!("params.get('{param}')")),
                "the page must forward `{param}`"
            );
        }
        for param in ["permissions", "ttl", "anchor"] {
            assert!(
                !html.contains(&format!("params.get('{param}')")),
                "the page must NOT read `{param}` from the fragment (merged contract)"
            );
        }
    }

    // A well-formed fragment payload — agent-js `DelegationChain.toJSON()`
    // exactly as II's #4093 frontend emits it (hex byte fields, HEX-string
    // expiration, principal-text targets, top-level `publicKey` = der(P_reg)),
    // carrying rev3's TWO hops (`P_reg -> Y` canister-signed, `Y -> X`
    // browser-signed) — decodes into `(der(P_reg), [both hops in order])`.
    #[test]
    fn parse_registration_delegation_round_trips_two_hops() {
        let der_preg = vec![1u8, 2, 3];
        let der_y = vec![7u8, 7, 7]; // II's ephemeral browser-held key
        let der_x = vec![9u8, 8, 7, 6]; // our registration key
        let sig_canister = vec![4u8, 5, 6];
        let sig_y = vec![1u8, 9, 9];
        let chain_json = serde_json::json!({
            "delegations": [
                {
                    "delegation": {
                        "pubkey": hex::encode(&der_y),
                        "expiration": format!("{:x}", 66_u64), // BigInt.toString(16)
                        "targets": ["aaaaa-aa"],
                    },
                    "signature": hex::encode(&sig_canister),
                },
                {
                    "delegation": {
                        "pubkey": hex::encode(&der_x),
                        "expiration": format!("{:x}", 66_u64),
                    },
                    "signature": hex::encode(&sig_y),
                },
            ],
            "publicKey": hex::encode(&der_preg),
        })
        .to_string();
        let (uk, chain) = super::parse_registration_delegation(&chain_json).expect("parse");
        assert_eq!(uk, der_preg);
        assert_eq!(chain.len(), 2, "both hops preserved, in order");
        // Hop 1: canister-signed P_reg -> Y. Its `targets` round-trips from
        // principal text (`aaaaa-aa` here as a stand-in; live chains carry the
        // II canister id).
        assert_eq!(chain[0].delegation.pubkey, der_y);
        assert_eq!(chain[0].delegation.expiration, 66);
        assert_eq!(chain[0].signature, sig_canister);
        assert_eq!(
            chain[0].delegation.targets.as_ref().unwrap()[0],
            candid::Principal::management_canister()
        );
        // Hop 2: browser-signed Y -> X.
        assert_eq!(chain[1].delegation.pubkey, der_x);
        assert_eq!(chain[1].signature, sig_y);
        assert_eq!(chain[1].delegation.targets, None);
        // Neither hop carries a permissions field; the access level was chosen
        // at consent and stored by II under P_reg (recovered from caller()), so
        // it never rides the delegation or the fragment.
        assert!(chain.iter().all(|d| d.delegation.permissions.is_none()));
    }

    // Malformed input fails with a clear error: non-JSON, bad hex, a
    // non-hex expiration — and, critically, an UNKNOWN field inside the
    // delegation (deny_unknown_fields): every delegation field is covered by
    // the canister signature, so silently dropping one could never re-hash to
    // what II signed (the #40 outage class) — fail fast instead.
    #[test]
    fn parse_registration_delegation_rejects_bad_input() {
        assert!(super::parse_registration_delegation("not json").is_err());

        let bad_hex = serde_json::json!({
            "delegations": [{
                "delegation": { "pubkey": "zz", "expiration": "1" },
                "signature": "0102",
            }],
            "publicKey": "010203",
        })
        .to_string();
        let err = super::parse_registration_delegation(&bad_hex).expect_err("bad hex must fail");
        assert!(err.contains("not valid hex"), "got: {err}");

        let bad_exp = serde_json::json!({
            "delegations": [{
                "delegation": { "pubkey": "0102", "expiration": "not-hex" },
                "signature": "0102",
            }],
            "publicKey": "010203",
        })
        .to_string();
        let err = super::parse_registration_delegation(&bad_exp).expect_err("bad expiration must fail");
        assert!(err.contains("expiration"), "got: {err}");

        // A field this parser does not carry (e.g. a future `permissions`)
        // must fail fast rather than be silently dropped.
        let unknown_field = serde_json::json!({
            "delegations": [{
                "delegation": { "pubkey": "0102", "expiration": "1", "permissions": "queries" },
                "signature": "0102",
            }],
            "publicKey": "010203",
        })
        .to_string();
        let err = super::parse_registration_delegation(&unknown_field)
            .expect_err("an unknown delegation field must fail fast, not silently drop");
        assert!(err.contains("permissions"), "got: {err}");
    }

    // CWE-770 guard: an oversized delegation payload is rejected BEFORE any
    // JSON parse, so an attacker-sized payload can't force large allocations.
    // A legit chain is a few KB, far below the cap.
    #[test]
    fn parse_registration_delegation_bounds_input_size() {
        let huge = "A".repeat(super::MAX_REG_DELEGATION_JSON + 1);
        let err = super::parse_registration_delegation(&huge).expect_err("oversized delegation rejected");
        assert!(err.contains("exceeds"), "got: {err}");

        // At-cap input proceeds past the size check (and fails on content,
        // not on size) — the bound doesn't clip legitimate-shaped requests.
        let at_cap = "A".repeat(super::MAX_REG_DELEGATION_JSON);
        let err = super::parse_registration_delegation(&at_cap).expect_err("fails on content, not size");
        assert!(!err.contains("exceeds"), "at-cap input must pass the size check: {err}");
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

    // The pinned callback page is served (with its strict CSP) and the redeem
    // endpoint is live.
    #[tokio::test]
    async fn connect_routes_are_served() {
        use axum::extract::State;

        let store = test_store();
        let page = super::connect_callback_page(State(store.clone())).await;
        assert_eq!(page.status(), axum::http::StatusCode::OK);
        assert!(page.headers().contains_key(axum::http::header::CONTENT_SECURITY_POLICY));
        // The redeem endpoint is live: an unknown state is a 400, not a 404.
        let redeem = super::connect_redeem(
            State(store),
            axum::http::HeaderMap::new(),
            axum::Json(super::RedeemBody {
                state: "sess-x".into(),
                delegation: String::new(),
            }),
        )
        .await;
        assert_eq!(redeem.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
