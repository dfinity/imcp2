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
//! loopback (a loopback redirect resolves on the consenter's own machine). The
//! *same-browser* variant (a victim socially engineered into running the whole
//! flow toward an attacker-registered **hosted** `redirect_uri`) is closed by a
//! **hosted-redirect allow-list** ([`redirect_uri_permitted`]): open DCR may
//! register only loopback, or a hosted redirect on an allow-listed domain UNDER
//! that vendor's pinned OAuth-callback path, so an attacker cannot register a
//! hosted destination it controls, not even a user-content path (`/page/…`,
//! `/g/…`) on an allow-listed origin (loopback is safe either way).
//! A client turned away by the allow-list is pointed at [`CONTACT`] to
//! request approval: `/oauth/register` says so in its JSON `error_description`,
//! and a browser that reaches `/oauth/authorize` gets the on-brand
//! [`not_allowlisted_page`] instead of a raw error.
//!
//! ## Browser-facing error screens
//!
//! `/oauth/authorize` and the pinned connect callback are FRONT-CHANNEL endpoints
//! the user reaches in a browser, so any error they stumble upon must render as a
//! friendly on-brand screen — a headline, a best-effort diagnostic, and always a
//! "contact [`CONTACT`] to report it" line — rather than a raw JSON blob. The
//! shared shell lives in `assets/connect-error.html` + `assets/connect.css` and is
//! rendered by [`error_screen`]. Authorize errors content-negotiate ([`accepts_html`]):
//! a browser gets the screen ([`signin_error`]), a programmatic OAuth caller keeps
//! the RFC-style JSON. Handshake/redeem failures surface on the pinned callback
//! page, which reveals the same contact line once it enters its error state. The
//! back-channel endpoints (`/oauth/token`, `/oauth/register`, the `/mcp` bearer
//! gate) stay JSON — no browser ever lands on them.
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
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use imcp2_core::identities::Identities;
pub use imcp2_core::iiconnect::AUTH_CALLBACKS_WELL_KNOWN;
use imcp2_core::iiconnect::{self, RedeemBody};

/// The verified session id of an authenticated MCP session: [`require_token`]
/// validates the bearer token and stashes this on the request; the
/// [`bearer_session_resolver`] hands it to the tool layer. The whole
/// authentication step lives HERE, in the hosted binary — `imcp2-core` only
/// asks its injected [`imcp2_core::SessionResolver`] for the outcome.
#[derive(Clone, Debug)]
pub struct AuthedSession {
    pub session_id: String,
}

/// The hosted binary's [`imcp2_core::SessionResolver`]: read back the
/// [`AuthedSession`] that [`require_token`] injected into the request
/// extensions (rmcp surfaces the HTTP request's `Parts` in the tool context).
pub fn bearer_session_resolver() -> imcp2_core::SessionResolver {
    std::sync::Arc::new(|ctx| {
        ctx.extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<AuthedSession>())
            .map(|session| session.session_id.clone())
    })
}

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

/// Ceiling on the dynamic-client-registration store. `POST /oauth/register` is
/// UNAUTHENTICATED (open DCR, as MCP clients require), so without a cap a bare
/// POST loop grows the map — and the file it is persisted to — without limit
/// (CWE-770). Eviction is least-recently-used ([`make_room_for_client`]): far
/// above any plausible legitimate population (a handful of vendors plus one
/// registration per desktop install), and a client evicted anyway just
/// re-registers, since DCR is automatic.
const MAX_CLIENTS: usize = 10_000;

/// Bounds on a SINGLE dynamic-client-registration request's `redirect_uris`.
/// `POST /oauth/register` is unauthenticated, and [`MAX_CLIENTS`] bounds only the
/// NUMBER of registrations, not the size of any one: without these a lone POST
/// could store a huge array of long strings, and MAX_CLIENTS of them would bloat
/// both memory and the persisted file (CWE-770). With the caps the store is
/// bounded at roughly `MAX_CLIENTS × MAX_REDIRECT_URIS × MAX_REDIRECT_URI_LEN`.
/// A real client registers a few short redirect URLs, so the ceilings are
/// generous: 16 URIs, each within the 2 KB URL length most stacks already impose.
const MAX_REDIRECT_URIS: usize = 16;
const MAX_REDIRECT_URI_LEN: usize = 2_048;

/// Floor on the interval between write-throughs of the registration store. The
/// store is re-serialized in full on every write, so writing once per
/// registration made N unauthenticated registrations cost O(N²) disk I/O; a
/// burst now coalesces into one write per interval (see
/// [`ClientStore::persist_soon`]). Short enough that a registration is on disk
/// long before the client comes back to use it.
const PERSIST_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Ceiling on minted-but-unexchanged authorization codes. Inserting one requires
/// a COMPLETED II consent, so this is a backstop rather than an attacker-reachable
/// limit; expired codes are dropped first ([`make_room`]).
const MAX_CODES: usize = 4_096;

/// Ceiling on live access tokens. Like [`MAX_CODES`], only a completed connect
/// can add one; expired tokens are dropped first, and only then the oldest.
const MAX_TOKENS: usize = 20_000;

/// Name of the browser-session cookie that binds `/oauth/authorize` to
/// `/oauth/connect/redeem`: only the browser that started the flow can complete it.
pub(crate) const CONNECT_COOKIE: &str = "mcp_connect";

/// A registered OAuth client (RFC 7591): the redirect URIs it declared. The
/// auth-code flow only redirects a code to one of these (exact match), so the
/// server is not an open redirector and needs no hardcoded host allowlist.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientReg {
    #[serde(default)]
    redirect_uris: Vec<String>,
    /// Unix seconds this registration was last USED — set at registration and
    /// refreshed whenever `/oauth/authorize` names it
    /// ([`ClientStore::redirect_allowed_for`]). Read only by the LRU eviction
    /// that bounds the store at [`MAX_CLIENTS`], so that a flood of never-used
    /// registrations churns itself out before touching clients in active use.
    /// Not persisted on every use (only registrations write through), so after a
    /// restart the order is as of the last registration — good enough for an
    /// eviction heuristic. An entry from a store written before this field
    /// existed defaults to the load time, i.e. as if just used.
    #[serde(default = "now_secs")]
    last_used: u64,
}

impl ClientReg {
    /// A registration for `redirect_uris`, used as of now.
    fn new(redirect_uris: Vec<String>) -> Self {
        Self { redirect_uris, last_used: now_secs() }
    }
}

/// Wall-clock seconds since the Unix epoch (0 if the clock is before it).
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Basename of the dynamic-client-registration store within the operational
/// directory ([`McpConfig::state_dir`](crate::McpConfig)). RFC 7591 clients are
/// long-lived (they cache their `client_id`), so registrations must survive a
/// restart — unlike codes/tokens/connects, which are short-lived and stay in
/// memory. The directory is injected via config, not read from the environment,
/// so the embedding application owns where operational files live.
const CLIENTS_FILENAME: &str = "oauth-clients.json";

/// The temp path a client-store write stages to before the atomic rename: the
/// target with a `.tmp` suffix, in the same directory (so the rename stays on one
/// filesystem). Built on `OsString` so a non-UTF-8 path is preserved.
fn clients_tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn load_clients_from(path: &Path) -> HashMap<String, ClientReg> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("could not parse {}: {e}; starting with no clients", path.display());
            HashMap::new()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => {
            tracing::warn!("could not read {}: {e}; starting with no clients", path.display());
            HashMap::new()
        }
    }
}

/// Best-effort write-through of the registration store to `path`. A failure (e.g.
/// a read-only filesystem) only means registrations don't survive a restart —
/// the client re-registers — so log and carry on.
///
/// Atomic replace: `std::fs::write` truncates the target in place, so a crash or
/// a concurrent [`load_clients_from`] mid-write could observe a half-written,
/// unparseable file and drop EVERY registration on the next load. Instead
/// serialize to a sibling temp file and `rename` it over the target — atomic on
/// POSIX, so a reader always sees either the old file or the complete new one.
/// Only one writer runs at a time ([`ClientStore::persist_soon`]), so the fixed
/// `.tmp` name cannot be raced.
fn persist_clients_to(path: &Path, clients: &HashMap<String, ClientReg>) {
    let bytes = match serde_json::to_vec_pretty(clients) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("could not serialize client registrations: {e}");
            return;
        }
    };
    let tmp = clients_tmp_path(path);
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        tracing::warn!("could not write {}: {e}", tmp.display());
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        tracing::warn!("could not replace {}: {e}", path.display());
        let _ = std::fs::remove_file(&tmp);
    }
}

/// The dynamic-client-registration store: the registrations plus the state that
/// keeps writing them to disk cheap. Two bounds live here, both because
/// `POST /oauth/register` is unauthenticated:
///
///   * **size** — capped at [`MAX_CLIENTS`], evicting the least-recently-used
///     registration ([`make_room_for_client`]);
///   * **disk I/O** — write-throughs are coalesced to at most one per
///     [`PERSIST_MIN_INTERVAL`] ([`Self::persist_soon`]), since each one
///     re-serializes the whole store.
struct ClientStore {
    registrations: RwLock<HashMap<String, ClientReg>>,
    /// The operational directory this store lives in — the SINGLE source of truth
    /// for where registrations persist (its file is `state_dir/{CLIENTS_FILENAME}`,
    /// derived in [`Self::file`]). Owned by the store so the coalesced writer
    /// ([`Self::persist_soon`]) needs no global/env lookup, and surfaced upward via
    /// [`SharedClients::state_dir`] so `McpServer` reports the true location rather
    /// than a possibly-diverging second copy.
    state_dir: PathBuf,
    /// Set when the store holds registrations not yet written to disk. Cleared
    /// by the persist task before it snapshots, so a registration landing
    /// mid-write sets it again and gets its own pass (no lost updates).
    dirty: AtomicBool,
    /// Set while a persist task is running, so concurrent registrations only
    /// mark the store dirty instead of each spawning their own writer.
    writing: AtomicBool,
}

impl ClientStore {
    /// Load the persisted registrations from `state_dir/{CLIENTS_FILENAME}`,
    /// binding the store to `state_dir` for later write-throughs.
    fn load(state_dir: PathBuf) -> Arc<Self> {
        let registrations = load_clients_from(&state_dir.join(CLIENTS_FILENAME));
        Self::with(registrations, state_dir)
    }

    /// A store over `registrations` as given, bound to `state_dir` for
    /// write-throughs (the seam tests use to start from a known set without
    /// reading the deployment's file — pass a throwaway dir when persistence is
    /// irrelevant).
    fn with(registrations: HashMap<String, ClientReg>, state_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            registrations: RwLock::new(registrations),
            state_dir,
            dirty: AtomicBool::new(false),
            writing: AtomicBool::new(false),
        })
    }

    /// The file registrations persist to: `state_dir/{CLIENTS_FILENAME}`.
    fn file(&self) -> PathBuf {
        self.state_dir.join(CLIENTS_FILENAME)
    }

    /// Whether `redirect_uri` is acceptable for `client_id` ([`redirect_allowed`]),
    /// marking the registration as used when it is so the LRU eviction keeps
    /// clients that are actually signing users in.
    async fn redirect_allowed_for(&self, client_id: &str, redirect_uri: &str) -> bool {
        let mut clients = self.registrations.write().await;
        if !redirect_allowed(clients.get(client_id), redirect_uri) {
            return false;
        }
        if let Some(reg) = clients.get_mut(client_id) {
            reg.last_used = now_secs();
        }
        true
    }

    /// Register `redirect_uris` under `client_id` directly, with no bound check
    /// and no write-through — the seam tests use to set up a known client
    /// without touching the disk.
    #[cfg(test)]
    async fn seed(&self, client_id: &str, redirect_uris: Vec<&str>) {
        let reg = ClientReg::new(redirect_uris.into_iter().map(str::to_string).collect());
        self.registrations.write().await.insert(client_id.to_string(), reg);
    }

    /// Store a registration, bounding the store first, then scheduling a
    /// (coalesced) write-through.
    async fn register(self: &Arc<Self>, client_id: String, reg: ClientReg) {
        {
            let mut clients = self.registrations.write().await;
            make_room_for_client(&mut clients);
            clients.insert(client_id, reg);
        }
        self.persist_soon();
    }

    /// Schedule a write-through of the registration store, **coalesced**: the
    /// first caller spawns the writer, later callers only mark the store dirty
    /// and the running writer picks their changes up on its next pass, at most
    /// one write per [`PERSIST_MIN_INTERVAL`]. Without this each
    /// `POST /oauth/register` re-serialized and rewrote the entire store, so N
    /// unauthenticated registrations cost O(N²) disk writes (CWE-770
    /// amplification). The trade is that up to one interval of registrations can
    /// be lost to a hard restart; persistence was already best-effort (a client
    /// whose registration didn't survive simply re-registers).
    fn persist_soon(self: &Arc<Self>) {
        self.dirty.store(true, Ordering::SeqCst);
        if self.writing.swap(true, Ordering::SeqCst) {
            return; // a writer is already running and will see `dirty`
        }
        let store = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                // Clear `dirty` BEFORE snapshotting, so a registration landing
                // during the write is guaranteed another pass.
                while store.dirty.swap(false, Ordering::SeqCst) {
                    let snapshot = store.registrations.read().await.clone();
                    let file = store.file();
                    tokio::task::spawn_blocking(move || persist_clients_to(&file, &snapshot))
                        .await
                        .ok();
                    tokio::time::sleep(PERSIST_MIN_INTERVAL).await;
                }
                store.writing.store(false, Ordering::SeqCst);
                // A registration may have landed between that last check and
                // releasing the writer slot: re-take it if so (unless another
                // caller already did), else this writer is done.
                if !store.dirty.load(Ordering::SeqCst) || store.writing.swap(true, Ordering::SeqCst)
                {
                    break;
                }
            }
        });
    }
}

/// Evict registrations until there is room for one more, bounding the store at
/// [`MAX_CLIENTS`] (CWE-770: open DCR means anyone can add entries). The
/// least-recently-used entry goes first — every `/oauth/authorize` marks its
/// client used, so an unauthenticated registration flood evicts its own unused
/// entries well before it reaches a client that is actively signing users in, and
/// an evicted client re-registers automatically.
fn make_room_for_client(clients: &mut HashMap<String, ClientReg>) {
    while clients.len() >= MAX_CLIENTS {
        let Some(victim) =
            clients.iter().min_by_key(|(_, c)| c.last_used).map(|(id, _)| id.clone())
        else {
            break;
        };
        clients.remove(&victim);
    }
}

/// Make room for one more entry in a bounded, self-expiring map, ordering
/// everything by each entry's REMAINING lifetime (zero = already expired, see the
/// `remaining` methods on [`AuthzPending`], [`CodeGrant`], and [`TokenInfo`]):
/// expired entries go first, then whatever expires soonest, down to `cap - 1`.
/// Never refuses the caller's insert, so a full map degrades by dropping its
/// closest-to-dead entries instead of by turning users away. Shared by the
/// pending connects, the authorization codes, and the access tokens; only pending
/// connects are reachable without authentication, but all three are capped.
fn make_room<K, V>(map: &mut HashMap<K, V>, cap: usize, remaining: impl Fn(&V) -> Duration)
where
    K: Clone + Eq + std::hash::Hash,
{
    if map.len() < cap {
        return;
    }
    map.retain(|_, v| !remaining(v).is_zero());
    while map.len() >= cap {
        let Some(victim) = map.iter().min_by_key(|(_, v)| remaining(v)).map(|(k, _)| k.clone())
        else {
            break;
        };
        map.remove(&victim);
    }
}

/// How an allow-list entry's pinned path is matched against a `redirect_uri` path.
/// A vendor whose callback path carries a per-connection id needs `Prefix`; one whose
/// callback is a single fixed endpoint gets `Exact`, so no descendant of it is
/// registrable either.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PathPin {
    /// Only this exact path.
    Exact,
    /// This path, or a descendant of it at a segment boundary ([`path_within_prefix`]).
    Prefix,
}

/// (registrable domain, redirect path, how to match that path) triples whose hosts
/// (and subdomains) may register a **hosted** (non-loopback) OAuth `redirect_uri`. Open dynamic
/// client registration means that without this an attacker could register a hosted
/// redirect it controls and phish an authorization code to it (the same-browser
/// variant Consent-Bound Completion does not close, CWE-601).
///
/// Matching the DOMAIN alone is NOT enough: several allow-listed origins also
/// serve third-party, potentially script-executing content on the SAME origin
/// (e.g. `perplexity.ai/page/…`, `chatgpt.com/g/…` and `/share/…`). A domain-only
/// rule would let an attacker register a `redirect_uri` on such a path; via the
/// same-browser flow the victim's browser lands there with `?code=…` and on-origin
/// JS exfiltrates it. So each entry also pins the PATH to the vendor's dedicated
/// OAuth-callback endpoint (see [`path_within_prefix`]): a registered redirect
/// always lands on a vendor-controlled, non-user-content path. (`claude.ai` runs
/// artifacts on a separate sandboxed `claudeusercontent.com` origin, off this list.)
///
/// Loopback redirects are exempt (a loopback code resolves on the consenter's own
/// machine). Seeded from the connector vendors' real callback paths; widen at
/// deploy time with `OAUTH_ALLOWED_REDIRECT_PREFIXES` (comma/space-separated full
/// `https://host/path` URL prefixes, each pinning a host + path prefix), additive, no
/// rebuild; a bare-domain (root-path) entry is refused so ops can't reopen the
/// domain-wide hole (env entries are prefixes, [`PathPin::Prefix`]).
///
/// Each entry says HOW its path is matched ([`PathPin`]). `Prefix` admits the path
/// and any segment-boundary descendant, which a vendor whose callback carries an id
/// (`/connector/oauth/{callback_id}`) needs; `Exact` admits only the path itself.
/// The vendors seeded as `Prefix` are left that way deliberately: tightening one to
/// `Exact` would reject an already-registered client of that vendor that appends a
/// segment, so it wants checking vendor by vendor rather than in bulk here.
const DEFAULT_ALLOWED_REDIRECTS: &[(&str, &str, PathPin)] = &[
    ("antigravity.google", "/oauth-callback", PathPin::Prefix), // Google Antigravity
    ("chatgpt.com", "/connector/oauth/", PathPin::Prefix),      // OpenAI ChatGPT connectors
    // OpenAI ChatGPT connectors, issuer-identification form. ChatGPT sends this
    // stable path — not the `{callback_id}` one above — to an authorization server
    // whose metadata advertises `authorization_response_iss_parameter_supported`,
    // which ours does, so this is the path a ChatGPT connection actually registers.
    // One fixed endpoint with nothing appended, so it is pinned as `Exact`: unlike a
    // `Prefix` entry, no descendant of it is registrable either.
    ("chatgpt.com", "/connector_platform_oauth_redirect", PathPin::Exact),
    ("claude.ai", "/api/mcp/auth_callback", PathPin::Prefix), // Anthropic Claude
    // Cursor (registered as www.cursor.com)
    ("cursor.com", "/agents/mcp/oauth/callback", PathPin::Prefix),
    ("grok.com", "/connector/oauth/", PathPin::Prefix), // xAI Grok
    ("grok.com", "/connectors-oauth-exchange-code/", PathPin::Prefix),
    ("grok.com", "/mcp/callback", PathPin::Prefix),
    // Perplexity (any subdomain)
    ("perplexity.ai", "/rest/connections/oauth_callback", PathPin::Prefix),
    ("perplexity.com", "/rest/connections/oauth_callback", PathPin::Prefix),
];

/// The effective hosted-redirect allow-list: the compiled-in defaults plus any
/// entries in `OAUTH_ALLOWED_REDIRECT_PREFIXES`. Each env entry is a bare
/// `https://host/path` value pinning a host + path prefix; an entry that is not
/// https, has no host, carries only the root path (`/`), or specifies a non-default
/// port (explicit `:443` is fine, being the same origin), query, fragment, or
/// userinfo is dropped with a warning (a domain-wide entry is exactly the hole this
/// closes; the others would be silently ignored since only `(host, path)` is
/// stored). Additive: the
/// shipped binary is safe by default and ops can only widen the set. Computed ONCE
/// (the env is process-static) via `OnceLock`, so `/oauth/register` and
/// `/oauth/authorize` neither re-parse the env nor re-log its warnings per call.
fn allowed_redirects() -> &'static [(String, String, PathPin)] {
    static CACHE: std::sync::OnceLock<Vec<(String, String, PathPin)>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out: Vec<(String, String, PathPin)> = DEFAULT_ALLOWED_REDIRECTS
            .iter()
            .map(|(d, p, pin)| (d.to_string(), p.to_string(), *pin))
            .collect();
        if let Ok(extra) = std::env::var("OAUTH_ALLOWED_REDIRECT_PREFIXES") {
            for raw in extra.split([',', ' ', '\t', '\n']).map(str::trim).filter(|s| !s.is_empty())
            {
                match parse_redirect_prefix(raw) {
                    // `…_PREFIXES`, so an ops entry matches as a prefix.
                    Some((host, path)) => out.push((host, path, PathPin::Prefix)),
                    None => tracing::warn!(
                        "ignoring OAUTH_ALLOWED_REDIRECT_PREFIXES entry `{raw}`: must be a bare \
                         `https://host/path` with a non-root path prefix and no non-default port \
                         (`:443` is fine), query, fragment, or userinfo (domain-wide entries are \
                         refused)"
                    ),
                }
            }
        }
        out
    })
}

/// Parse one `OAUTH_ALLOWED_REDIRECT_PREFIXES` entry into the `(host, path)` pair
/// the matcher stores. Returns `None` (drop + warn) unless the entry is a bare
/// `https://host/path` with a non-root path and no non-default port (explicit
/// `:443` is accepted as the same origin), query, fragment, or userinfo: only
/// `(host, path)` is matched, so anything else would be silently ignored and give
/// the operator a false sense of what they pinned.
fn parse_redirect_prefix(raw: &str) -> Option<(String, String)> {
    let u = url::Url::parse(raw).ok().filter(|u| u.scheme() == "https")?;
    if u.port().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return None;
    }
    let host = u.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let path = u.path().to_string();
    (!host.is_empty() && path != "/" && !path.is_empty()).then_some((host, path))
}

/// Whether `path` equals `prefix` or is a descendant of it at a SEGMENT boundary,
/// so a pinned `/api/mcp/auth_callback` admits `/api/mcp/auth_callback` and
/// `/api/mcp/auth_callback/…` but NOT `/api/mcp/auth_callbackEVIL`.
fn path_within_prefix(path: &str, prefix: &str) -> bool {
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || prefix.ends_with('/') || rest.starts_with('/'),
        None => false,
    }
}

/// Whether `path` contains ANY percent-encoding (a literal `%`). A legitimate hosted
/// vendor callback path is plain ASCII with no percent-encoding, so rather than
/// enumerate the dangerous sequences we reject percent-encoding wholesale: it is the
/// only way an encoded path separator or dot-segment can hide from the pinned-prefix
/// check, and refusing all of it means never having to reason about which sequences a
/// given downstream server/CDN happens to decode.
///
/// The concrete break it closes (CWE-601): url::Url does not decode `%2f` on parse, so
/// `/connector/oauth/%2e%2e%2f%2e%2e%2fg%2fx` rides through [`path_within_prefix`] as
/// one opaque segment under the pinned prefix, yet a vendor that later decodes `%2f`
/// (and resolves the `..`) routes the appended `?code=…` to `/g/x` on the trusted
/// origin, an attacker-controlled, script-capable path. A single byte scan, so no
/// allocation on the unauthenticated front-channel (`/oauth/register`,
/// `/oauth/authorize`).
fn path_has_percent_encoding(path: &str) -> bool {
    path.contains('%')
}

/// Whether a `redirect_uri` may be registered or receive an authorization code.
/// No redirect (loopback or hosted) may carry a query or fragment component: the
/// authorization endpoint appends `?code=…&state=…`, so a pre-existing query would
/// risk `code=…&code=…` parameter pollution (MCP05), and a fragment is meaningless
/// on a redirect target. Loopback (`http://localhost` / `127.0.0.1` / `[::1]`, any
/// port) is otherwise always allowed. A hosted redirect must be `https`, carry no
/// userinfo, name no
/// off-origin port (only the implicit/`:443` default is allowed), its host must
/// equal (or be a subdomain of) an allow-listed registrable domain, AND its path
/// must match that entry's pinned callback path — exactly or as a prefix, per the
/// entry's [`PathPin`] (see
/// [`DEFAULT_ALLOWED_REDIRECTS`]), so a user-content path on an allow-listed
/// origin (`perplexity.ai/page/…`, `chatgpt.com/g/…`) is refused even though the
/// host matches. The host is read from the PARSED URL, not the raw string, so
/// authority tricks such as `https://claude.ai@evil.com` or
/// `https://claude.ai.evil.com` resolve to their real host and are refused; a bare
/// `https://user@claude.ai` is refused too (userinfo serves no purpose in a
/// redirect target, only muddies which host is addressed, and loopback rejects it).
fn redirect_uri_permitted(redirect_uri: &str) -> bool {
    let Ok(url) = url::Url::parse(redirect_uri) else {
        return false;
    };
    // Reject any query or fragment component (MCP05), on loopback and hosted alike.
    // `/oauth/authorize` appends `?code=…&state=…` to the redirect, so a redirect
    // that already carries a query invites `code=123&code=456` parameter pollution
    // a lax downstream parser could resolve to an attacker-seeded value; a fragment
    // serves no purpose in a redirect target. Every seeded vendor callback and every
    // registered loopback URI is already query/fragment-free, so this rejects nothing
    // legitimate while keeping the code-appending redirect unambiguous.
    if url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    // Loopback is checked on the already-parsed `url` (not a re-parse of the raw
    // string), since this runs on the `/oauth/register` and `/oauth/authorize` path.
    if is_loopback_url(&url) {
        return true;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    // Allowlist the redirect's SHAPE rather than denylisting each disallowed part: a
    // permitted hosted redirect serialises to exactly `https://<host><path>` (https,
    // no userinfo, no port, no query, no fragment). Rebuild that canonical form from
    // the parts we allow and require an exact match, so any unexpected component is
    // refused in one comparison. url::Url drops the https-default `:443` (so it still
    // matches), while an off-origin `:444`, a userinfo prefix, or an `http` scheme
    // makes the two differ; query and fragment were already refused above.
    let Ok(canonical) = url::Url::parse(&format!("https://{host}{}", url.path())) else {
        return false;
    };
    if url != canonical {
        return false;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let path = url.path();
    // url::Url collapses only LITERAL `.`/`..` segments (raw or `%2e`-encoded whole
    // segments), so a real-slash traversal `/connector/oauth/../../g/evil` arrives
    // here already normalized to `/g/evil` and fails the prefix check. It does NOT
    // decode `%2f`, though, so an ENCODED-slash traversal
    // (`/connector/oauth/%2e%2e%2f%2e%2e%2fg%2fx`) would otherwise ride through as one
    // opaque segment under the prefix and later decode to `/g/x` on the vendor origin.
    // A vendor callback path is plain ASCII, so reject ANY percent-encoding in the
    // path first (CWE-601), which holds the pin under every encoding without having to
    // enumerate the dangerous sequences (see [`path_has_percent_encoding`]).
    if path_has_percent_encoding(path) {
        return false;
    }
    // host == domain (or a dot-boundary subdomain) AND the path matches the vendor's
    // pinned callback path the way that entry says to ([`PathPin`]: its own path only,
    // or descendants too). The path pin is what keeps a registration off
    // third-party/user-content paths (e.g. `/page/…`, `/g/…`) on the same origin;
    // without it, domain-only matching would let those capture the code.
    allowed_redirects().iter().any(|(domain, prefix, pin)| {
        (host == *domain || host.strip_suffix(domain.as_str()).is_some_and(|p| p.ends_with('.')))
            && match pin {
                PathPin::Exact => path == prefix,
                PathPin::Prefix => path_within_prefix(path, prefix),
            }
    })
}

/// Whether `redirect_uri` is a **well-formed hosted** redirect: it parses, is
/// `https`, carries no userinfo, has a host, and has no query or fragment. This is the shape that could
/// legitimately be allow-listed and that [`redirect_uri_permitted`] rejects only
/// because its host isn't on the list. It lets `/oauth/authorize` tell "a real
/// client whose redirect just isn't approved yet" (→ the [`not_allowlisted_page`])
/// apart from a genuinely **malformed or ineligible** `redirect_uri`
/// (unparseable, non-`https`, userinfo-bearing, or query/fragment-carrying), which
/// is a client-side request error, not an approval gap. Loopback is intentionally NOT counted here: a
/// loopback redirect is always permitted, so it never reaches the not-permitted
/// branch this distinction guards.
fn is_wellformed_hosted_redirect(redirect_uri: &str) -> bool {
    match url::Url::parse(redirect_uri) {
        Ok(url) => {
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.host_str().is_some_and(|h| !h.is_empty())
                // A query or fragment makes it ineligible (MCP05), not merely
                // unapproved, so it is classified `invalid_request` rather than
                // routed to the "request access" page.
                && url.query().is_none()
                && url.fragment().is_none()
                // Percent-encoding in the path is likewise ineligible (CWE-601 pin
                // bypass), not a real client awaiting approval, so it is classified
                // `invalid_request` rather than offered "request access".
                && !path_has_percent_encoding(url.path())
        }
        Err(_) => false,
    }
}

/// Acceptance rule for a redirect (OAuth 2.1): the client must be REGISTERED,
/// the redirect must pass the hosted-redirect allow-list
/// ([`redirect_uri_permitted`]), and it must either exactly match a registered
/// URI or be a loopback URI matching a registered loopback URI on everything but
/// the port. RFC 8252 §7.3 requires the any-port latitude, since native clients
/// bind an ephemeral loopback port at runtime, so the exact port can't be
/// registered. The allow-list is re-checked here (not only at registration) so a
/// pre-existing registration whose domain is no longer allowed can't be used.
fn redirect_allowed(reg: Option<&ClientReg>, redirect_uri: &str) -> bool {
    let Some(reg) = reg else { return false };
    if !redirect_uri_permitted(redirect_uri) {
        return false;
    }
    reg.redirect_uris.iter().any(|u| u == redirect_uri || loopback_match(u, redirect_uri))
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
    clients: Arc<ClientStore>,
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    /// Auth-code connects in flight, keyed by `session_id` (= the II connect
    /// `state`). Bounded at [`imcp2_core::identities::MAX_PENDING_CONNECTS`] (one
    /// entry per pending connect, same as the session map) and swept of expired
    /// entries by [`AuthStore::reap_expired`].
    authz: Arc<RwLock<HashMap<String, AuthzPending>>>,
    /// Minted authorization codes awaiting exchange at `/oauth/token`.
    codes: Arc<RwLock<HashMap<String, CodeGrant>>>,
    /// Shared with the MCP tools: the session's backend key / grant expiration
    /// live here (keyed by `session_id`) for the tools to sign with.
    identities: Identities,
    /// Public base URL (origin, no trailing slash) clients use to reach this
    /// server — injected by the embedding application, never read from the
    /// environment here.
    public_url: String,
    /// The path this instance's mcp router is nested at ("" for the root, else
    /// `/mcp`-like: leading slash, no trailing slash). Everything an absolute
    /// URL is built from — the AS issuer `{public_url}{mcp_path}`, the OAuth
    /// endpoints `{issuer}/oauth/*`, the II callback URL, and the
    /// path-inserted discovery documents — derives from this one value.
    mcp_path: String,
    /// Strict RFC 8707: when set, both OAuth legs REQUIRE a `resource` naming
    /// this instance — a request that omits it is refused (`invalid_request`),
    /// not just one that names a foreign server. Closes the confused-deputy path
    /// for clients that never send `resource` at all, at the cost of turning away
    /// any client predating RFC 8707. Injected by the embedding application (see
    /// [`crate::McpConfig::require_resource`]); when clear, a missing `resource`
    /// is tolerated.
    require_resource: bool,
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

impl AuthzPending {
    /// How long this connect may still be redeemed for — zero once it is past
    /// [`CONNECT_TTL`]. The single definition of "expired" for a pending connect:
    /// the redeem gate, the reaper, and the bound ([`make_room`]) all read it.
    fn remaining(&self) -> Duration {
        CONNECT_TTL.saturating_sub(self.created.elapsed())
    }
}

/// A minted authorization code awaiting exchange.
#[derive(Clone, Debug)]
struct CodeGrant {
    client_id: String,
    code_challenge: Option<String>,
    session_id: String,
    created: Instant,
}

impl CodeGrant {
    /// How long this code may still be exchanged for — zero once it is past
    /// [`CODE_TTL`].
    fn remaining(&self) -> Duration {
        CODE_TTL.saturating_sub(self.created.elapsed())
    }
}

#[derive(Clone, Debug)]
struct TokenInfo {
    principal: String,
    session_id: String,
    created: Instant,
    ttl: Duration,
}

impl TokenInfo {
    /// How long this access token is still valid for — zero once it has expired.
    /// Its `ttl` tracks the II grant (see [`token_ttl`]), so an expiring token and
    /// an expiring session go together.
    fn remaining(&self) -> Duration {
        self.ttl.saturating_sub(self.created.elapsed())
    }
}

/// The dynamic-client-registration store, shared by every instance's
/// `AuthStore`. Client registration is II-agnostic (it only pins redirect
/// URIs to a `client_id`), so a client registered against either instance's AS
/// is known to both — and, since both stores share one map, the persisted
/// snapshot never loses the other instance's entries.
#[derive(Clone)]
pub struct SharedClients(Arc<ClientStore>);

impl SharedClients {
    /// Load the persisted client registrations from `state_dir` once, to be shared
    /// by every instance on the origin (the store lives at
    /// `{state_dir}/oauth-clients.json`). `state_dir` is the operational-files
    /// directory the embedder configures as [`McpConfig::state_dir`](crate::McpConfig);
    /// build ONE `SharedClients` from it and hand a clone to each instance so a
    /// registration made against either instance's AS is known to both and the
    /// persisted snapshot never loses the other's entries.
    pub fn load(state_dir: impl AsRef<Path>) -> Self {
        Self(ClientStore::load(state_dir.as_ref().to_path_buf()))
    }

    /// The operational directory this store loads from and persists to — the
    /// authoritative location, so [`McpServer::state_dir`](crate::McpServer::state_dir)
    /// reports where files actually go rather than a separately-stored copy that
    /// could drift from the one passed to [`Self::load`].
    pub fn state_dir(&self) -> &Path {
        &self.0.state_dir
    }
}

impl AuthStore {
    pub fn new(
        identities: Identities,
        clients: SharedClients,
        public_url: String,
        mcp_path: String,
        require_resource: bool,
    ) -> Self {
        Self {
            clients: clients.0,
            tokens: Arc::default(),
            authz: Arc::default(),
            codes: Arc::default(),
            identities,
            public_url,
            mcp_path,
            require_resource,
        }
    }

    /// The II instance this store serves.
    fn instance(&self) -> &imcp2_core::identities::IiInstance {
        self.identities.instance()
    }

    /// The operational directory the client store persists to — the location
    /// `McpServer::state_dir` reports (single source of truth).
    pub(crate) fn state_dir(&self) -> &Path {
        &self.clients.state_dir
    }

    /// This instance's AS issuer: `{public_url}{mcp_path}` (an RFC 8414 *path
    /// issuer* whenever the router is nested below the root). Every OAuth
    /// endpoint lives under it, at `{issuer}/oauth/*`.
    fn issuer(&self) -> String {
        format!("{}{}", self.public_url, self.mcp_path)
    }

    /// This instance's protected-resource metadata URL (RFC 9728 §3.1),
    /// advertised in the 401 challenge: the path-inserted form for the
    /// resource `{public_url}{mcp_path}`.
    fn resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource{}", self.public_url, self.mcp_path)
    }

    /// Whether `redirect_uri` is acceptable for `client_id`: the client must be
    /// registered, and the redirect must match a registered URI (exactly, or
    /// port-agnostically for loopback per RFC 8252 §7.3). A match also marks the
    /// registration as recently used (it is about to sign a user in), which is
    /// what keeps it ahead of the store's LRU eviction.
    async fn validate_client(&self, client_id: &str, redirect_uri: &str) -> bool {
        self.clients.redirect_allowed_for(client_id, redirect_uri).await
    }

    /// The verified principal + session id behind a bearer token, if valid.
    pub async fn session_for_token(&self, token: &str) -> Option<(String, String)> {
        let tokens = self.tokens.read().await;
        let info = tokens.get(token)?;
        (!info.remaining().is_zero()).then(|| (info.principal.clone(), info.session_id.clone()))
    }

    /// Record a connect awaiting its II handshake, bounding the map first
    /// ([`make_room`]): `/oauth/authorize` is unauthenticated, so expired entries
    /// go and — if the map is still at the cap — the oldest pending connect is
    /// evicted, which makes an authorize flood churn its own entries out instead
    /// of growing the map (CWE-770). The cap is shared with the session map, whose
    /// entries pair 1:1 with these.
    async fn insert_pending(&self, session_id: String, pending: AuthzPending) {
        let mut authz = self.authz.write().await;
        make_room(
            &mut authz,
            imcp2_core::identities::MAX_PENDING_CONNECTS,
            AuthzPending::remaining,
        );
        authz.insert(session_id, pending);
    }

    /// Drop every expired entry from the short-lived OAuth maps, returning how
    /// many went from each. The admission bounds ([`make_room`]) cap these maps at
    /// all times; this is what returns the memory once a burst has passed, so an
    /// abandoned connect, an unexchanged code, or an expired token doesn't linger
    /// for the process's lifetime (CWE-770). Run on the same 60s timer as the
    /// session reaper (`McpServer::spawn_session_reaper`).
    pub(crate) async fn reap_expired(&self) -> ReapedOauthState {
        let mut reaped = ReapedOauthState::default();
        {
            let mut authz = self.authz.write().await;
            let before = authz.len();
            authz.retain(|_, a| !a.remaining().is_zero());
            reaped.pending = before - authz.len();
        }
        {
            let mut codes = self.codes.write().await;
            let before = codes.len();
            codes.retain(|_, c| !c.remaining().is_zero());
            reaped.codes = before - codes.len();
        }
        {
            let mut tokens = self.tokens.write().await;
            let before = tokens.len();
            // A token's lifetime tracks its II grant, so this expires in step
            // with the session the grant belongs to.
            tokens.retain(|_, t| !t.remaining().is_zero());
            reaped.tokens = before - tokens.len();
        }
        if reaped.any() {
            tracing::debug!(
                pending_connects = reaped.pending,
                codes = reaped.codes,
                tokens = reaped.tokens,
                "reaped expired OAuth state"
            );
        }
        reaped
    }
}

/// What one [`AuthStore::reap_expired`] sweep dropped, per map.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ReapedOauthState {
    /// Pending connects past [`CONNECT_TTL`] (an abandoned `/oauth/authorize`).
    pending: usize,
    /// Authorization codes past [`CODE_TTL`], never exchanged.
    codes: usize,
    /// Access tokens past their grant-tracking TTL.
    tokens: usize,
}

impl ReapedOauthState {
    /// Whether the sweep dropped anything at all (worth a log line).
    fn any(&self) -> bool {
        self.pending + self.codes + self.tokens > 0
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
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    scope: Option<String>,
    /// RFC 8707 Resource Indicator: the MCP resource the client is requesting a
    /// token for. Enforced against this instance's issuer (see
    /// [`resource_matches_issuer`] and the check in [`authorize`]) per the MCP
    /// authorization spec, so a token is only ever issued for this resource.
    #[serde(default)]
    resource: Option<String>,
}

/// Whether a client-supplied RFC 8707 `resource` indicator names THIS instance's
/// own MCP resource — its AS issuer, `{public_url}{mcp_path}` (e.g.
/// `https://mcp.internetcomputer.org/mcp`), which is exactly the value published
/// as `resource` in the protected-resource metadata.
///
/// Compared by identifying URL components, so trivial variance still matches
/// (scheme/host case — already lowercased by `url::Url` — an explicit `:443`,
/// one trailing slash), while anything that is not the advertised identifier is
/// refused: a different host, a different instance path (`/mcp` vs `/mcp-beta`),
/// a non-default port, a doubled trailing slash, or a differing query. RFC 8707
/// permits a query, so it is part of the identifier and must match (the issuer
/// carries none); per RFC 8707 §2 a resource indicator is an absolute URI with
/// no fragment and no userinfo, so a fragment-bearing, userinfo-bearing, or
/// unparseable value is refused.
/// Whether `raw`'s authority carries a userinfo component — `user[:pass]@`, or
/// even a bare/empty `@`. `url` normalizes an empty userinfo away before parsing,
/// so [`resource_matches_issuer`] scans the raw string: the authority is the
/// slice between `://` and the first `/`, `?`, or `#`, and a `@` in it is
/// userinfo (a `@` in the path or query is not).
fn raw_authority_has_userinfo(raw: &str) -> bool {
    raw.split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(rest))
        .is_some_and(|authority| authority.contains('@'))
}

fn resource_matches_issuer(resource: &str, issuer: &str) -> bool {
    let (Ok(got), Ok(want)) = (url::Url::parse(resource), url::Url::parse(issuer)) else {
        return false;
    };
    // The advertised resource is a plain absolute URI: no fragment, no userinfo,
    // and none of the ASCII tab/newline/CR that `url` silently strips from
    // ANYWHERE in the input (WHATWG URL). Reject that whitespace first, so
    // stripping can't desync the raw scan from what `url` parsed — e.g.
    // `https:\t//user@host` parses WITH userinfo yet hides the `://` from a
    // literal scan. Then reject userinfo via BOTH the parsed username/password
    // (authoritative for any non-empty userinfo) AND the raw-authority scan (for
    // an EMPTY userinfo `url` erases: `https://@host` → `https://host`).
    if got.fragment().is_some()
        || resource.contains(['\t', '\n', '\r'])
        || !got.username().is_empty()
        || got.password().is_some()
        || raw_authority_has_userinfo(resource)
    {
        return false;
    }
    // Identifying components. Tolerate exactly one trailing slash (`/mcp` vs
    // `/mcp/`) so a doubled slash is still a distinct path; the query is part of
    // the RFC 8707 identifier, so it must match too.
    let norm = |u: &url::Url| {
        (
            u.scheme().to_owned(),
            u.host_str().map(str::to_owned),
            u.port_or_known_default(),
            u.path().strip_suffix('/').unwrap_or(u.path()).to_owned(),
            u.query().map(str::to_owned),
        )
    };
    norm(&got) == norm(&want)
}

/// GET /oauth/authorize — the redirect-based entry point. Validates the client
/// and PKCE, records a pending connect, and redirects the browser to II's `/mcp`
/// handshake; II navigates back to our pinned callback page with the delegation.
///
/// This is a FRONT-CHANNEL endpoint: the MCP client opens the user's browser
/// here to start sign-in, and any failure reached before a validated
/// `redirect_uri` cannot be redirected back to the client (OAuth 2.1 forbids
/// sending an error to an unvalidated redirect), so it surfaces to the user
/// directly. Rather than show a raw JSON blob, each such failure goes through
/// [`signin_error`], which serves the on-brand [`error_screen`] to a browser and
/// keeps the RFC-style JSON for a programmatic caller (see [`accepts_html`]). The
/// `headers` are read only for that content negotiation.
pub async fn authorize(
    State(store): State<AuthStore>,
    headers: axum::http::HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    // A single best-effort diagnostic for the "client sent a request we can't
    // process" family (wrong response_type, missing/unsupported PKCE): the cause
    // is almost always a client that is out of date or misconfigured.
    const MALFORMED_DIAGNOSTIC: &str = "Your MCP client sent a request this server can't process. \
        The client may be out of date. Try updating it. If that doesn't help, remove the connector \
        and add it again. Then sign in.";
    const SIGNIN_HEADLINE: &str = "We couldn't start your sign-in.";

    // Only the authorization-code response type is supported.
    match q.response_type.as_deref() {
        Some("code") => {}
        Some(_) => {
            return signin_error(
                &headers,
                StatusCode::BAD_REQUEST,
                "unsupported_response_type",
                "only response_type=code",
                SIGNIN_HEADLINE,
                MALFORMED_DIAGNOSTIC,
            )
        }
        None => {
            return signin_error(
                &headers,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "response_type=code required",
                SIGNIN_HEADLINE,
                MALFORMED_DIAGNOSTIC,
            )
        }
    }
    if !store.validate_client(&q.client_id, &q.redirect_uri).await {
        if !redirect_uri_permitted(&q.redirect_uri) {
            // Two distinct failures reach here. A WELL-FORMED hosted `redirect_uri`
            // that simply isn't on the allow-list is an approval gap, not a
            // malformed request: show the browser the dedicated "not approved" page
            // naming the cause and the concrete next step (request access). This
            // covers clients that skip DCR or use a stored-but-disallowed
            // registration (the standard flow is blocked earlier, at
            // `/oauth/register`). The page is static and reflects nothing, so naming
            // the cause leaks nothing. A programmatic caller (no `text/html`) gets
            // the machine-readable JSON.
            if is_wellformed_hosted_redirect(&q.redirect_uri) {
                return if accepts_html(&headers) {
                    not_allowlisted_page()
                } else {
                    oauth_err(StatusCode::FORBIDDEN, "invalid_client",
                        &format!("redirect_uri is not on the hosted-redirect allow-list; contact {CONTACT} to request access"))
                };
            }
            // Otherwise the `redirect_uri` is malformed or ineligible (unparseable,
            // non-https, or userinfo-bearing). That's a client-side request error,
            // not an approval gap, so classify it `invalid_request` and show the
            // generic sign-in error rather than a misleading "request access" page.
            return signin_error(
                &headers,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "redirect_uri must be a valid https or loopback URL",
                SIGNIN_HEADLINE,
                MALFORMED_DIAGNOSTIC,
            );
        }
        // `invalid_client` (not `invalid_request`): the request is well-formed,
        // it's the CLIENT identification that failed — the AS error code the
        // MCP server guide (and RFC 6749's taxonomy) expects here. No redirect:
        // an unvalidated redirect_uri must never receive an error response.
        return signin_error(
            &headers,
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "unknown client_id / redirect_uri",
            SIGNIN_HEADLINE,
            "This server doesn't recognize your MCP client. Its registration may have expired. \
             Remove the connector and add it again. Then sign in.",
        );
    }
    // OAuth 2.1: PKCE is required for public clients.
    let Some(code_challenge) = q.code_challenge.clone() else {
        return signin_error(&headers, StatusCode::BAD_REQUEST, "invalid_request",
            "code_challenge (PKCE S256) required", SIGNIN_HEADLINE,
            "Your MCP client's request was missing a required security check (PKCE). The client may \
             be out of date. Try updating it. If that doesn't help, remove the connector and add it again.");
    };
    // `token` only ever verifies S256, so require the method to say so
    // EXPLICITLY. Per RFC 7636 an *omitted* method defaults to `plain` —
    // accepting the omission and then verifying as S256 would hand a
    // spec-strict `plain` client a code it can never exchange.
    if q.code_challenge_method.as_deref() != Some("S256") {
        return signin_error(
            &headers,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method=S256 is required",
            SIGNIN_HEADLINE,
            "Your MCP client's request used an unsupported PKCE method (only S256 is supported). \
             The client may be out of date. Try updating it. If that doesn't help, remove the \
             connector and add it again.",
        );
    }
    // RFC 8707 Resource Indicators (MCP authorization): a token must only be
    // issued for THIS instance, so refuse a `resource` that names any other
    // server — the MCP spec requires the authorization server to bind tokens to
    // the requested resource. Each leg (here and /oauth/token) validates
    // independently against this instance's own issuer; with exactly one valid
    // resource per instance, that is equivalent to binding it into the code and
    // re-checking, without the extra state. Whether a MISSING `resource` is
    // tolerated is the `require_resource` policy: strict refuses it (closing the
    // confused-deputy for clients that never send one), lenient accepts it for
    // clients predating RFC 8707.
    match q.resource.as_deref() {
        Some(resource) if resource_matches_issuer(resource, &store.issuer()) => {}
        Some(_) => {
            return signin_error(&headers, StatusCode::BAD_REQUEST, "invalid_target",
                "the `resource` does not identify this MCP server (RFC 8707)", SIGNIN_HEADLINE,
                "Your MCP client requested sign-in for a different server than this one. Update your \
                 client or reconnect; if you were connecting a third-party tool, check that it's the \
                 one you intended.");
        }
        None if store.require_resource => {
            tracing::warn!("refusing an authorize with no RFC 8707 `resource` (strict mode)");
            return signin_error(&headers, StatusCode::BAD_REQUEST, "invalid_request",
                "the `resource` parameter is required (RFC 8707)", SIGNIN_HEADLINE,
                "Your MCP client didn't say which server it's signing in to (the RFC 8707 `resource` \
                 parameter). The client may be out of date. Try updating it, then reconnect.");
        }
        None => {}
    }

    let session_id = format!("sess-{}", Uuid::new_v4());
    // Mint this connect's registration key `X` FIRST (before recording anything):
    // it is the step that can be refused when the session map is at capacity, and
    // doing it first means a refusal leaves no pending connect behind. `pub(X)`
    // then rides the II link, toward which II builds the registration chain
    // (`P_reg -> Y -> X`, the last hop browser-signed to `X`).
    let reg_pubkey = match store.identities.registration_pubkey_b64(&session_id).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("refusing a connect: {e}");
            return signin_error(
                &headers,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "the server is at capacity for sessions; retry shortly",
                SIGNIN_HEADLINE,
                "This server is busy right now, so it couldn't start a new sign-in. Wait a moment \
                 and try again.",
            );
        }
    };
    // Bind this browser to the flow (the `sid` cookie, set now and required at
    // `/oauth/connect/redeem`). The `state` alone can't prove the redeeming
    // browser is the initiator (it's echoed to the client). The cookie proves
    // *initiator*; the fragment-delivered delegation proves *consenter*; requiring
    // both closes the split-browser injection.
    let cookie = format!("bind-{}", Uuid::new_v4());
    store
        .insert_pending(
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
        )
        .await;

    // Redirect the browser to this instance's II handshake, setting the binding
    // cookie. II navigates back to our pinned callback page once it certifies the
    // delegation; SameSite=Lax lets the cookie ride that top-level cross-site GET
    // back to us. Scoped to this instance's OAuth subtree (`{mcp_path}/oauth`).
    // `Secure` only when served over HTTPS (production always is): a `Secure`
    // cookie is dropped by browsers over plain HTTP, which would break the
    // initiator check for local `http://localhost` development. `McpServer::new`
    // normalizes `public_url` to a lowercase-scheme origin, but compare
    // case-insensitively so this stays correct for a directly-built store too.
    let is_https = store
        .public_url
        .split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"));
    let secure = if is_https { "; Secure" } else { "" };
    let set_cookie = format!(
        "{CONNECT_COOKIE}={cookie}; Path={}/oauth; Max-Age={}; HttpOnly{secure}; SameSite=Lax",
        store.mcp_path,
        CONNECT_TTL.as_secs(),
    );
    let ii_url = ii_mcp_url(&store, &session_id, &reg_pubkey);
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
    let mut resp =
        (StatusCode::FOUND, [(axum::http::header::LOCATION, url.to_string())]).into_response();
    resp.headers_mut().insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    resp
}

fn build_redirect(redirect_uri: &str, code: &str, client_state: &str, iss: &str) -> String {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut r = format!("{redirect_uri}{sep}code={}", urlencoding::encode(code));
    if !client_state.is_empty() {
        r.push_str(&format!("&state={}", urlencoding::encode(client_state)));
    }
    // RFC 9207: name the issuer on the authorization response so the client can
    // detect an authorization-server mix-up before redeeming the code. Emitted on
    // every success redirect and advertised via
    // `authorization_response_iss_parameter_supported` in the AS metadata; the value
    // is byte-for-byte the metadata `issuer` (clients compare it by exact string).
    r.push_str(&format!("&iss={}", urlencoding::encode(iss)));
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
fn ii_mcp_url(store: &AuthStore, session_id: &str, reg_pubkey_b64: &str) -> String {
    iiconnect::ii_mcp_url(
        &store.instance().ii_url,
        &connect_callback_url(store),
        session_id,
        GRANT_TTL_SECS,
        reg_pubkey_b64,
    )
}
// ---- Callback allow-list (II #4091) ---------------------------------------

/// An instance's connect-callback URL — the single source of truth used BOTH in
/// the II link fragment and in the [`auth_callbacks`] allow-list, so the two
/// can never drift: II matches them by exact string equality (no
/// normalization, no case/slash slack).
fn connect_callback_url(store: &AuthStore) -> String {
    format!("{}/oauth/connect/callback", store.issuer())
}

/// GET /.well-known/ii-auth-callbacks — declare every instance's connect
/// callback (II #4091 validates every connect against this list; the path is
/// origin-global, so one document covers both instances).
/// Served with CORS (II's frontend fetches it cross-origin) and well under
/// II's 8 KB cap.
pub async fn auth_callbacks(State(stores): State<Vec<AuthStore>>) -> Response {
    let callbacks: Vec<String> = stores.iter().map(connect_callback_url).collect();
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
    pinned_callback_page(&store.mcp_path)
}

/// The strict-CSP pinned callback page (rendered by
/// [`iiconnect::pinned_callback_page`], which binds a fresh nonce into the CSP
/// and both inline blocks), wrapped into a Response with this deployment's
/// redeem URL and the non-CSP hardening headers.
fn pinned_callback_page(prefix: &str) -> Response {
    let page = iiconnect::pinned_callback_page(&format!("{prefix}/oauth/connect/redeem"), CONTACT);
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
    h.insert(axum::http::header::X_FRAME_OPTIONS, axum::http::HeaderValue::from_static("DENY"));
    resp
}

/// Where users are pointed for a sign-in problem: rejected MCP clients are told
/// here to request allow-listing (`/oauth/register` JSON `error_description` and
/// the [`not_allowlisted_page`]), and every other browser-facing sign-in/handshake
/// error asks the user to report it here (via [`error_screen`] and the pinned
/// callback page's contact line). One address, so a user always has a clear next
/// step rather than an opaque failure.
const CONTACT: &str = "mcp@dfinity.org";

/// HTML shell for the browser-facing error screens, a real `.html` asset (compiled
/// in via `include_str!`, no runtime file I/O). It reuses the pinned callback
/// page's self-contained shell (`assets/connect.css`, the inlined logo) but
/// carries no script. Rendered by [`error_screen`], which splices in
/// `__NONCE__`/`__CSS__`/`__LOGO__` plus the `__TITLE__`/`__HEADLINE__`/`__DETAIL__`/
/// `__HINT__` text; every text value is a compiled-in constant at the call site
/// (never a request value), so no request input is ever reflected into the markup.
const CONNECT_ERROR_HTML: &str = include_str!("assets/connect-error.html");

/// The tab title used by every generic `/oauth/authorize` error screen.
const SIGNIN_ERROR_TITLE: &str = "Sign-in error";

/// Whether the request explicitly accepts an HTML response — i.e. it comes from a
/// browser. This is a coarse browser-vs-machine split, NOT a full preference
/// ranking: it does not weigh `text/html`'s q-value against JSON's, only whether
/// `text/html` is an acceptable type at all. That is deliberate — a browser always
/// lists `text/html` as acceptable, so treating any acceptable `text/html` as "serve
/// the screen" is enough. `/oauth/authorize` is a front-channel endpoint reached by
/// top-level navigation, so a browser gets the friendly [`error_screen`], while a
/// programmatic OAuth caller (`Accept: application/json`, `*/*`, or no `Accept` at
/// all) keeps the machine-readable JSON: the machine default is JSON.
///
/// The `Accept` header is parsed as media ranges rather than substring-matched:
/// media types are case-insensitive (RFC 9110 §12.5.1), and a `;q=0` parameter
/// marks a type as *not* acceptable (§12.4.2), so `text/html;q=0, application/json`
/// correctly stays on JSON and `TEXT/HTML` is still recognized. A wildcard
/// (`text/*`, `*/*`) does NOT opt into HTML — only an explicit `text/html` does,
/// keeping the JSON default for anything that isn't unambiguously a browser.
fn accepts_html(headers: &axum::http::HeaderMap) -> bool {
    let Some(accept) = headers.get(axum::http::header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    accept.split(',').any(|range| {
        let mut parts = range.split(';').map(str::trim);
        if !parts.next().is_some_and(|media| media.eq_ignore_ascii_case("text/html")) {
            return false;
        }
        // Acceptable unless an explicit `q=0` (any spelling: `0`, `0.0`, `0.000`).
        // A malformed or absent q-value leaves the range acceptable.
        !parts.any(|param| {
            param.split_once('=').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("q")
                    && v.trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
            })
        })
    })
}

/// The always-present "report it" line for a sign-in/handshake error screen. The
/// contact renders as a `mailto:` link (a top-level navigation, unaffected by the
/// page's strict resource CSP). The address is the compiled-in [`CONTACT`], never
/// a request value.
fn contact_report_hint() -> String {
    format!("If this error is unexpected, please contact <a href=\"mailto:{CONTACT}\">{CONTACT}</a> to report it.")
}

/// Render one of the shared browser-facing error screens
/// (`assets/connect-error.html`). Every text slot — the tab `title`, the
/// `headline`, the `detail` (a best-effort diagnostic), and the `hint` (typically
/// the [`contact_report_hint`]) — is a compiled-in constant at the call site, so
/// the page reflects nothing and can't be turned into a content-injection surface;
/// `detail`/`hint` may carry trusted inline markup (e.g. the `mailto:` link). No
/// script on the page, so no `script-src`; the only inline is the nonce'd
/// `<style>`, everything else is denied (`default-src 'none'`), and framing is
/// refused so the page can't be embedded for UI redress.
fn error_screen(
    status: StatusCode,
    title: &str,
    headline: &str,
    detail: &str,
    hint: &str,
) -> Response {
    let nonce = iiconnect::csp_nonce();
    let html = CONNECT_ERROR_HTML
        .replace("__NONCE__", &nonce)
        .replace("__CSS__", iiconnect::CONNECT_PAGE_CSS)
        .replace("__LOGO__", iiconnect::CONNECT_LOGO_SVG)
        .replace("__TITLE__", title)
        .replace("__HEADLINE__", headline)
        .replace("__DETAIL__", detail)
        .replace("__HINT__", hint);
    let csp = format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; img-src 'self'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'"
    );
    let mut resp = (status, Html(html)).into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_str(&csp).expect("valid CSP"),
    );
    h.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(axum::http::header::X_FRAME_OPTIONS, axum::http::HeaderValue::from_static("DENY"));
    resp
}

/// A browser-facing `/oauth/authorize` failure: serve the on-brand [`error_screen`]
/// (headline + best-effort `diagnostic` + the [`contact_report_hint`]) to a browser,
/// or the RFC-style JSON (`error`/`desc`) to a programmatic caller (see
/// [`accepts_html`]). Used for every authorize error that can't be redirected back
/// to the client.
fn signin_error(
    headers: &axum::http::HeaderMap,
    status: StatusCode,
    error: &str,
    desc: &str,
    headline: &str,
    diagnostic: &str,
) -> Response {
    if accepts_html(headers) {
        error_screen(status, SIGNIN_ERROR_TITLE, headline, diagnostic, &contact_report_hint())
    } else {
        oauth_err(status, error, desc)
    }
}

/// The friendly, browser-facing rejection for a client whose `redirect_uri` is
/// not on the hosted-redirect allow-list ([`redirect_uri_permitted`]). A real
/// browser reaches `/oauth/authorize` by top-level navigation, so a terse JSON
/// `invalid_client` renders as a raw error blob; this serves an on-brand page
/// that names the cause and points the vendor at [`CONTACT`]. Static and
/// non-reflecting: no query or redirect value is interpolated, so it can't be
/// turned into a content-injection or open-redirect surface. `403 Forbidden`: the
/// request is understood but refused by policy. Unlike the generic sign-in error,
/// this is an EXPECTED, actionable rejection, so its hint gives the concrete next
/// step (request access) rather than the "report it" line.
fn not_allowlisted_page() -> Response {
    error_screen(
        StatusCode::FORBIDDEN,
        "MCP client not approved",
        "This MCP client isn't approved yet.",
        "This server only accepts approved MCP clients. Yours isn't on the allow-list yet.",
        &format!(
            "To request access, email <a href=\"mailto:{CONTACT}\">{CONTACT}</a>. Tell us the name \
             of your MCP client or AI chatbot."
        ),
    )
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
                a.remaining().is_zero(),
                a.cookie.clone(),
                a.client_id.clone(),
                a.redirect_uri.clone(),
                a.client_state.clone(),
                a.code_challenge.clone(),
                a.code.clone(),
            )
        })
    };
    let Some((
        expired,
        cookie,
        client_id,
        redirect_uri,
        client_state,
        code_challenge,
        existing_code,
    )) = snap
    else {
        return redeem_err(
            "This connect request is unknown or already used. Restart from your client.",
        );
    };
    if expired {
        return redeem_err("This connect request has expired. Restart from your client.");
    }
    // Initiator proof: only the browser that STARTED this connect (holding the
    // `sid` cookie) may redeem. In the confused-deputy path the delegation lands
    // in the honest page in the VICTIM's browser, whose cookie does not match the
    // one `X` was bound to, so this aborts (see the design's security argument).
    if connect_cookie(&headers).as_deref() != Some(cookie.as_str()) {
        return redeem_err(
            "This sign-in started in a different browser. Restart from your client.",
        );
    }
    // Issuer for the RFC 9207 `iss` on every redirect below (byte-identical to the
    // AS metadata `issuer`).
    let iss = store.issuer();
    // Idempotent: if a code was already minted for this connect, return it again.
    if let Some(code) = existing_code {
        return Json(
            json!({ "redirect": build_redirect(&redirect_uri, &code, &client_state, &iss) }),
        )
        .into_response();
    }
    // Decode the fragment delegation (agent-js DelegationChain JSON, II #4093)
    // before claiming, so a malformed delivery never occupies the single-flight
    // slot. No consent values are parsed: they're not in the fragment (II
    // captured them at prepare and recovers them from caller() == P_reg).
    let (user_key, chain) = match iiconnect::parse_registration_delegation(&body.delegation) {
        Ok(v) => v,
        Err(e) => {
            return redeem_err(&format!(
                "We couldn't read the sign-in response. Restart from your client. ({e})"
            ))
        }
    };
    // Single-flight: atomically claim this connect's redemption so a double-submit
    // can't fire two concurrent mcp_register_v2 calls (and a request racing a
    // just-finished attempt gets that attempt's code instead of redeeming again).
    match claim_redemption(&store, &body.state).await {
        RedeemClaim::Claimed => {}
        RedeemClaim::Existing(code) => {
            return Json(
                json!({ "redirect": build_redirect(&redirect_uri, &code, &client_state, &iss) }),
            )
            .into_response()
        }
        RedeemClaim::InProgress => {
            return redeem_err(
                "This connect request is already being processed. Wait a moment. \
                 If nothing happens, restart from your client.",
            )
        }
        RedeemClaim::Vanished => {
            return redeem_err(
                "This connect request is no longer available. Restart from your client.",
            )
        }
    }
    // Redeem: build a DelegatedIdentity from priv(X) + the chain and make one
    // authenticated mcp_register_v2 call. Success proves consent AND registration.
    match store.identities.redeem_registration_delegation(&body.state, user_key, chain).await {
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
            return redeem_err(
                "This connect request is no longer available. Restart from your client.",
            );
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
        let mut codes = store.codes.write().await;
        make_room(&mut codes, MAX_CODES, CodeGrant::remaining);
        codes.insert(
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
    Json(json!({ "redirect": build_redirect(&redirect_uri, &code, &client_state, &iss) }))
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
    /// RFC 8707 Resource Indicator, repeated from the authorization request and
    /// enforced in [`token_authorization_code`] against this instance's issuer,
    /// so the issued token is bound to this resource.
    #[serde(default)]
    resource: Option<String>,
}

/// POST /oauth/token — the `authorization_code` grant (the only grant we support;
/// the RFC 8628 device grant was dropped).
pub async fn token(State(store): State<AuthStore>, Form(req): Form<TokenForm>) -> Response {
    match req.grant_type.as_str() {
        "authorization_code" => token_authorization_code(store, req).await,
        _ => oauth_err(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code is supported",
        ),
    }
}

async fn token_authorization_code(store: AuthStore, req: TokenForm) -> Response {
    // RFC 8707: refuse a token request whose `resource` names a different MCP
    // server than this one (mirrors the check in `authorize`). Done before the
    // code is consumed below, so a spurious/foreign request can't burn a valid
    // pending code. A missing `resource` is refused under the strict
    // `require_resource` policy, else accepted (clients predating RFC 8707).
    match req.resource.as_deref() {
        Some(resource) if resource_matches_issuer(resource, &store.issuer()) => {}
        Some(_) => {
            return oauth_err(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "the `resource` does not identify this MCP server (RFC 8707)",
            );
        }
        None if store.require_resource => {
            tracing::warn!("refusing a token request with no RFC 8707 `resource` (strict mode)");
            return oauth_err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the `resource` parameter is required (RFC 8707)",
            );
        }
        None => {}
    }
    let grant = match store.codes.write().await.remove(&req.code) {
        Some(g) if !g.remaining().is_zero() => g,
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
            None => {
                return oauth_err(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "code_verifier required",
                )
            }
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
    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let ttl = token_ttl(TOKEN_TTL, store.identities.grant_expiration_ns(session_id).await, now_ns);

    let access_token = format!("mcp-token-{}", Uuid::new_v4());
    {
        let mut tokens = store.tokens.write().await;
        make_room(&mut tokens, MAX_TOKENS, TokenInfo::remaining);
        tokens.insert(
            access_token.clone(),
            TokenInfo {
                principal: principal.clone(),
                session_id: session_id.to_string(),
                created: Instant::now(),
                ttl,
            },
        );
    }
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
        let mut g: Vec<String> =
            requested.iter().filter(|g| SUPPORTED.contains(&g.as_str())).cloned().collect();
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
pub async fn register(
    State(store): State<AuthStore>,
    Json(req): Json<RegisterRequest>,
) -> Response {
    // Bound the redirect_uris array (count + per-URI length) FIRST — before grant
    // validation and before anything is stored. Open DCR is unauthenticated, so a
    // single request must not be able to pin unbounded memory or bloat the
    // persisted store (CWE-770). Running this ahead of the grant-type check also
    // makes the error deterministic: an oversized array is always reported as
    // `invalid_redirect_uri`, never masked by an `invalid_client_metadata` from a
    // request that happens to also carry unsupported grant types.
    if req.redirect_uris.len() > MAX_REDIRECT_URIS {
        return oauth_err(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!(
                "too many redirect_uris ({}, max {MAX_REDIRECT_URIS})",
                req.redirect_uris.len()
            ),
        );
    }
    if let Some(bad) = req.redirect_uris.iter().find(|u| u.len() > MAX_REDIRECT_URI_LEN) {
        return oauth_err(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!(
                "a redirect_uri is too long ({} bytes, max {MAX_REDIRECT_URI_LEN})",
                bad.len()
            ),
        );
    }

    let Some(granted) = granted_grant_types(&req.grant_types) else {
        return oauth_err(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "this server only supports the authorization_code grant; request it (or omit grant_types)",
        );
    };

    // Hosted-redirect allow-list (auth-code phishing, same-browser variant):
    // open DCR must not let a caller register a hosted redirect it controls.
    // Loopback is exempt. Reject BEFORE anything is stored.
    if let Some(bad) = req.redirect_uris.iter().find(|u| !redirect_uri_permitted(u.as_str())) {
        return oauth_err(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            &format!(
                "redirect_uri {bad} is not permitted: a hosted redirect must be https on an \
                 allow-listed domain AND under that vendor's registered OAuth-callback path \
                 (loopback redirects are always allowed). To have this MCP client added to the \
                 allow-list, contact {CONTACT}."
            ),
        );
    }

    let client_id = format!("client-{}", Uuid::new_v4());
    // Bounded + coalesced-persistence insert (see [`ClientStore`]): the store is
    // capped at MAX_CLIENTS by LRU, and the write-through is scheduled rather
    // than done inline, so an unauthenticated registration flood can neither grow
    // the map without limit nor amplify into a full re-serialization per request.
    store.clients.register(client_id.clone(), ClientReg::new(req.redirect_uris.clone())).await;

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

/// GET `/.well-known/oauth-authorization-server{mcp_path}` — RFC 8414 metadata
/// for this instance's AS. The issuer is `{public_url}{mcp_path}` (a *path
/// issuer* when the instance is nested below the root), and every endpoint
/// lives under it. Also served at the OIDC-style alternate location inside the
/// mount (`{issuer}/.well-known/oauth-authorization-server`) and, for the
/// origin's default instance, at the plain root as a courtesy for clients that
/// probe there without doing RFC 8414 path insertion.
pub async fn authorization_server_metadata(State(store): State<AuthStore>) -> Response {
    let issuer = store.issuer();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        // RFC 9207: we emit `iss` on every authorization response, so we MUST
        // advertise it here (a client that sees this flag rejects any response
        // missing `iss`). See `build_redirect`.
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

/// GET `/.well-known/oauth-protected-resource{mcp_path}` (RFC 9728 §3.1; also
/// the root variant for the default instance): this instance's MCP resource
/// and the AS that protects it — both `{public_url}{mcp_path}`.
pub async fn protected_resource_metadata(State(store): State<AuthStore>) -> Response {
    let issuer = store.issuer();
    Json(json!({
        "resource": issuer,
        "authorization_servers": [issuer],
    }))
    .into_response()
}

// ---- Bearer-token gate for /mcp -----------------------------------------

pub async fn require_token(
    State(store): State<AuthStore>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // The `Bearer` auth-scheme is case-insensitive (RFC 7235 §2.1), so match it
    // that way — an `Authorization: bearer <token>` must be recognized too.
    let token =
        request.headers().get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| {
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
    url::Url::parse(redirect_uri).map(|u| is_loopback_url(&u)).unwrap_or(false)
}

/// Loopback test on an already-parsed URL, so a caller that has parsed the
/// `redirect_uri` (e.g. [`redirect_uri_permitted`]) need not parse it again.
fn is_loopback_url(url: &url::Url) -> bool {
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
    use std::{collections::HashMap, time::Duration};

    use super::{
        build_redirect, is_loopback_redirect, pkce_s256, redirect_allowed, redirect_uri_permitted,
        ClientReg,
    };

    /// RFC 7636 Appendix B test vector.
    #[test]
    fn pkce_s256_matches_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256(verifier), expected);
    }

    /// The registration store persists via a temp-file + atomic rename, so a
    /// concurrent reader (or a crash) never observes a half-written file. The
    /// production case is REPLACING an existing snapshot — the behavior this
    /// change introduces — so the test pre-writes an old snapshot, persists a new
    /// one over it, and checks that the swap is total (only the new entries load,
    /// the target is always a complete json document, and no `.tmp` is left).
    #[test]
    fn client_store_persists_atomically() {
        use super::{clients_tmp_path, load_clients_from, persist_clients_to};

        let path = std::env::temp_dir().join(format!("imcp2-clients-{}.json", std::process::id()));
        let tmp = clients_tmp_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp);

        // Pre-existing snapshot at the target: persisting must REPLACE this, which
        // is the real-world path (the file already holds prior registrations).
        let mut old = HashMap::new();
        old.insert(
            "client-old".to_string(),
            ClientReg::new(vec!["http://127.0.0.1:1111/old".to_string()]),
        );
        persist_clients_to(&path, &old);
        assert!(path.exists(), "old snapshot must exist first");

        // Persist a DIFFERENT set over the existing file.
        let mut clients = HashMap::new();
        clients.insert(
            "client-abc".to_string(),
            ClientReg::new(vec!["http://127.0.0.1:4321/cb".to_string()]),
        );
        persist_clients_to(&path, &clients);

        // The replace is total: only the new entry loads (the rename swapped the
        // whole file — it did not merge or append to the old snapshot), and the
        // rename consumed the sibling temp file.
        let loaded = load_clients_from(&path);
        assert_eq!(loaded.len(), 1, "replace swaps the whole snapshot");
        assert!(loaded.contains_key("client-abc"), "new entry present");
        assert!(!loaded.contains_key("client-old"), "old entry replaced, not kept");
        assert_eq!(
            loaded["client-abc"].redirect_uris,
            vec!["http://127.0.0.1:4321/cb".to_string()]
        );
        assert!(!tmp.exists(), "no leftover .tmp file");

        // The persisted target is always a COMPLETE json document.
        let raw = std::fs::read(&path).unwrap();
        assert!(serde_json::from_slice::<HashMap<String, ClientReg>>(&raw).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn redirect_requires_registration() {
        let reg = ClientReg::new(vec!["https://claude.ai/api/mcp/auth_callback".to_string()]);
        // Hosted redirects: exact registered match only.
        assert!(redirect_allowed(Some(&reg), "https://claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_allowed(Some(&reg), "https://claude.ai/api/mcp/auth_callback/x"));
        // Unregistered clients get nothing — not even loopback.
        assert!(!redirect_allowed(None, "https://claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_allowed(None, "http://127.0.0.1:51000/callback"));
        assert!(!redirect_allowed(None, "http://[::1]:8080/cb"));
    }

    /// Hosted-redirect allow-list (auth-code phishing, same-browser variant): an
    /// allow-listed vendor domain (or subdomain) passes ONLY under that vendor's
    /// pinned callback path; loopback always passes; everything else (a
    /// user-content path on an allow-listed origin, a wrong path, an unlisted
    /// domain, or an authority-trick look-alike) is refused.
    #[test]
    fn hosted_redirect_allow_list() {
        // Allow-listed vendor domains/subdomains UNDER their pinned callback path.
        assert!(redirect_uri_permitted("https://claude.ai/api/mcp/auth_callback"));
        assert!(redirect_uri_permitted("https://chatgpt.com/connector/oauth/abc"));
        // ChatGPT's issuer-identification callback: one stable path, no `{callback_id}`
        // segment. This is the form it sends us, since our AS metadata advertises
        // `authorization_response_iss_parameter_supported`.
        assert!(redirect_uri_permitted("https://chatgpt.com/connector_platform_oauth_redirect"));
        // …and being `PathPin::Exact`, ONLY that path: a descendant is refused, unlike
        // under a `PathPin::Prefix` entry (the `{callback_id}` one above).
        assert!(!redirect_uri_permitted(
            "https://chatgpt.com/connector_platform_oauth_redirect/anything"
        ));
        assert!(redirect_uri_permitted("https://grok.com/mcp/callback"));
        assert!(redirect_uri_permitted("https://grok.com/connectors-oauth-exchange-code/x"));
        assert!(redirect_uri_permitted(
            "https://www.perplexity.ai/rest/connections/oauth_callback"
        ));
        // Subdomain + the pinned path (Perplexity uses www/staging/enterprise/n).
        assert!(redirect_uri_permitted(
            "https://staging.perplexity.com/rest/connections/oauth_callback"
        ));
        assert!(redirect_uri_permitted("https://antigravity.google/oauth-callback"));
        // Loopback is always allowed (any port), no allow-list entry needed.
        assert!(redirect_uri_permitted("http://127.0.0.1:6112/cb"));
        assert!(redirect_uri_permitted("http://localhost/callback"));
        assert!(redirect_uri_permitted("http://[::1]:8080/cb"));
        // PATH PIN (the core of the CWE-601 finding): an allow-listed origin on a
        // third-party/user-content path is refused, even though the host matches.
        assert!(!redirect_uri_permitted("https://perplexity.ai/page/attacker"));
        assert!(!redirect_uri_permitted("https://www.perplexity.ai/page/attacker"));
        assert!(!redirect_uri_permitted("https://chatgpt.com/g/evil-gpt"));
        assert!(!redirect_uri_permitted("https://chatgpt.com/share/abcd"));
        // Right domain, wrong path, plus a non-segment-boundary near-miss of the pin.
        assert!(!redirect_uri_permitted("https://claude.ai/foo"));
        assert!(!redirect_uri_permitted("https://claude.ai/api/mcp/auth_callbackEVIL"));
        assert!(!redirect_uri_permitted(
            "https://chatgpt.com/connector_platform_oauth_redirectEVIL"
        ));
        // Dot-segment traversal (raw and percent-encoded): url::Url normalizes these
        // to `/g/evil` on parse (WHATWG), which then fails the pinned-prefix check.
        assert!(!redirect_uri_permitted("https://chatgpt.com/connector/oauth/../../g/evil"));
        assert!(!redirect_uri_permitted(
            "https://chatgpt.com/connector/oauth/%2e%2e/%2e%2e/g/evil"
        ));
        assert!(!redirect_uri_permitted(
            "https://chatgpt.com/connector/oauth/%2E%2E/%2E%2E/g/evil"
        ));
        // A dot-segment that normalizes to WITHIN the vendor's pinned prefix is fine
        // (it lands in the vendor's own callback space, not an escape).
        assert!(redirect_uri_permitted("https://chatgpt.com/connector/oauth/x/../y"));
        // ENCODED-slash traversal (CWE-601): url::Url does NOT decode `%2f`, so
        // `%2e%2e%2f%2e%2e%2fg%2f…` stays one opaque segment under the pinned prefix
        // and slips past the prefix check, yet a vendor CDN that later decodes `%2f`
        // routes the appended `?code=…` to `/g/…` on the trusted origin. A vendor
        // callback path is plain ASCII, so ANY percent-encoding in the path is refused
        // outright (upper/lower, separators AND otherwise-harmless escapes alike).
        assert!(!redirect_uri_permitted(
            "https://chatgpt.com/connector/oauth/%2e%2e%2f%2e%2e%2fg%2fattacker"
        ));
        assert!(!redirect_uri_permitted("https://chatgpt.com/connector/oauth/%2E%2E%2Fg%2Fevil"));
        // Even an encoded slash that would decode to WITHIN the prefix is refused (we
        // reject percent-encoding outright rather than decode-and-renormalize).
        assert!(!redirect_uri_permitted("https://chatgpt.com/connector/oauth/x%2fy"));
        assert!(!redirect_uri_permitted("https://chatgpt.com/connector/oauth/x%5cy"));
        assert!(!redirect_uri_permitted("https://claude.ai/api/mcp/auth_callback%2f%2e%2e"));
        // A non-separator escape (e.g. `%20`, `%41`) is refused too: the whole point is
        // to avoid reasoning about which encodings a given downstream decodes.
        assert!(!redirect_uri_permitted("https://chatgpt.com/connector/oauth/a%20b"));
        assert!(!redirect_uri_permitted("https://chatgpt.com/connector/oauth/%41"));
        // Such a payload is ineligible (invalid_request), not a client awaiting approval.
        assert!(!super::is_wellformed_hosted_redirect(
            "https://chatgpt.com/connector/oauth/%2e%2e%2f%2e%2e%2fg%2fattacker"
        ));
        // Cursor: allowed at its real hosted callback path (registered as
        // www.cursor.com), refused on any other path.
        assert!(redirect_uri_permitted("https://www.cursor.com/agents/mcp/oauth/callback"));
        assert!(!redirect_uri_permitted("https://cursor.com/oauth/callback")); // wrong path
                                                                               // vscode.dev is deliberately NOT allow-listed: its only registered path is
                                                                               // `/redirect`, a web-to-desktop forwarding endpoint (see the PR discussion).
        assert!(!redirect_uri_permitted("https://vscode.dev/redirect"));
        assert!(!redirect_uri_permitted("https://insiders.vscode.dev/redirect"));
        // Attacker-controlled hosted redirects: refused (the finding's payloads).
        assert!(!redirect_uri_permitted("https://example.com/cb"));
        assert!(!redirect_uri_permitted("https://attacker.example/cb"));
        // Look-alikes and authority tricks resolve to the real (non-allowed) host,
        // tested with an OTHERWISE-valid path so only the host/userinfo is at fault.
        assert!(!redirect_uri_permitted("https://claude.ai.evil.com/api/mcp/auth_callback"));
        assert!(!redirect_uri_permitted("https://evilclaude.ai/api/mcp/auth_callback"));
        assert!(!redirect_uri_permitted("https://claude.ai@evil.com/api/mcp/auth_callback"));
        // Userinfo is refused even when host + path are otherwise valid.
        assert!(!redirect_uri_permitted("https://user@claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_uri_permitted("https://user:pass@claude.ai/api/mcp/auth_callback"));
        // An off-origin port is refused (different origin than the pinned host), but
        // the implicit / explicit default `:443` is the same origin and stays allowed.
        assert!(!redirect_uri_permitted("https://claude.ai:444/api/mcp/auth_callback"));
        assert!(redirect_uri_permitted("https://claude.ai:443/api/mcp/auth_callback"));
        // A hosted redirect must be https even to an allowed domain + path.
        assert!(!redirect_uri_permitted("http://claude.ai/api/mcp/auth_callback"));
        // A query or fragment is refused (MCP05: `?code=…` appended by the AS would
        // pollute a redirect that already carries one), on hosted AND loopback, even
        // when the host + path are otherwise valid. The same URI with no query passes.
        assert!(!redirect_uri_permitted("https://claude.ai/api/mcp/auth_callback?code=123"));
        assert!(!redirect_uri_permitted("https://claude.ai/api/mcp/auth_callback?x=1"));
        assert!(!redirect_uri_permitted("https://claude.ai/api/mcp/auth_callback#frag"));
        assert!(!redirect_uri_permitted("http://127.0.0.1:6112/cb?code=123"));
        assert!(!redirect_uri_permitted("http://localhost/callback#frag"));
        // Defense in depth: a client registered before the allow-list (or via a
        // now-removed domain) still can't receive a code at /oauth/authorize.
        let junk = ClientReg::new(vec!["https://example.com/cb".to_string()]);
        assert!(!redirect_allowed(Some(&junk), "https://example.com/cb"));
    }

    /// The two path-matching modes an allow-list entry can carry ([`PathPin`]): a
    /// `Prefix` entry admits segment-boundary descendants (a vendor callback that
    /// carries a per-connection id needs that), an `Exact` entry admits only its own
    /// path. Pinned here as well as through [`redirect_uri_permitted`] so a change to
    /// either mode fails loudly rather than quietly widening what DCR accepts.
    #[test]
    fn path_pin_modes() {
        use super::{path_within_prefix, PathPin};
        // `Prefix`: the path itself, and descendants at a segment boundary only.
        assert!(path_within_prefix("/connector/oauth/", "/connector/oauth/"));
        assert!(path_within_prefix("/connector/oauth/abc", "/connector/oauth/"));
        assert!(path_within_prefix("/mcp/callback", "/mcp/callback"));
        assert!(path_within_prefix("/mcp/callback/x", "/mcp/callback"));
        assert!(!path_within_prefix("/mcp/callbackEVIL", "/mcp/callback"));
        assert!(!path_within_prefix("/mcp", "/mcp/callback"));
        // ChatGPT's stable callback is pinned `Exact`, which is what stops
        // `/connector_platform_oauth_redirect/…` from being registrable.
        assert!(super::DEFAULT_ALLOWED_REDIRECTS.contains(&(
            "chatgpt.com",
            "/connector_platform_oauth_redirect",
            PathPin::Exact
        )));
        // A trailing slash means descendants are expected, so such an entry must be
        // `Prefix` — `Exact` there could match only a path ending in `/`, which no
        // vendor callback is, silently pinning nothing.
        for (domain, path, pin) in super::DEFAULT_ALLOWED_REDIRECTS {
            assert!(
                !path.ends_with('/') || *pin == PathPin::Prefix,
                "{domain}{path} ends in `/` but is not PathPin::Prefix"
            );
        }
    }

    /// `OAUTH_ALLOWED_REDIRECT_PREFIXES` entries parse to `(host, path)` only for a
    /// bare `https://host/path`; a port, query, fragment, or userinfo is refused
    /// (dropped) rather than silently discarded, and so is a non-https or root-path
    /// entry that would reopen the domain-wide hole.
    #[test]
    fn redirect_prefix_entry_parsing() {
        use super::parse_redirect_prefix;
        assert_eq!(
            parse_redirect_prefix("https://vendor.example/mcp/callback"),
            Some(("vendor.example".to_string(), "/mcp/callback".to_string()))
        );
        assert_eq!(
            parse_redirect_prefix("https://VENDOR.example/mcp/callback"),
            Some(("vendor.example".to_string(), "/mcp/callback".to_string()))
        );
        // The default `:443` is the same origin, so it is accepted and the port drops.
        assert_eq!(
            parse_redirect_prefix("https://vendor.example:443/mcp/callback"),
            Some(("vendor.example".to_string(), "/mcp/callback".to_string()))
        );
        // Silently-ignored components are refused rather than dropped.
        assert_eq!(parse_redirect_prefix("https://vendor.example:8443/mcp/callback"), None);
        assert_eq!(parse_redirect_prefix("https://vendor.example/mcp/callback?x=1"), None);
        assert_eq!(parse_redirect_prefix("https://vendor.example/mcp/callback#frag"), None);
        assert_eq!(parse_redirect_prefix("https://user@vendor.example/mcp/callback"), None);
        // Non-https and domain-wide (root or empty path) entries are refused.
        assert_eq!(parse_redirect_prefix("http://vendor.example/mcp/callback"), None);
        assert_eq!(parse_redirect_prefix("https://vendor.example/"), None);
        assert_eq!(parse_redirect_prefix("https://vendor.example"), None);
        assert_eq!(parse_redirect_prefix("not a url"), None);
    }

    /// A registered loopback redirect matches at ANY port (RFC 8252 §7.3 — the
    /// client binds an ephemeral port each run), but host and path must match,
    /// and a registered hosted URI grants no loopback latitude.
    #[test]
    fn registered_loopback_matches_any_port() {
        let reg = ClientReg::new(vec!["http://localhost:54321/callback".to_string()]);
        assert!(redirect_allowed(Some(&reg), "http://localhost:54321/callback"));
        assert!(redirect_allowed(Some(&reg), "http://localhost:61832/callback"));
        assert!(redirect_allowed(Some(&reg), "http://localhost/callback"));
        // Different path or host (even another loopback host): rejected.
        assert!(!redirect_allowed(Some(&reg), "http://localhost:61832/other"));
        assert!(!redirect_allowed(Some(&reg), "http://127.0.0.1:61832/callback"));
        // Look-alike hosts fail is_loopback_redirect on the requested side.
        assert!(!redirect_allowed(Some(&reg), "http://localhost.evil.com:54321/callback"));
        // A registered HOSTED uri gives no loopback latitude.
        let hosted = ClientReg::new(vec!["https://claude.ai/cb".to_string()]);
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
        let meta = "https://x.test/.well-known/oauth-protected-resource/mcp-beta";
        let with_token = super::bearer_challenge(true, meta);
        assert!(with_token.starts_with("Bearer "));
        assert!(with_token.contains("error=\"invalid_token\""));
        assert!(with_token.contains("error_description="));
        assert!(with_token.contains(&format!("resource_metadata=\"{meta}\"")));

        let no_token = super::bearer_challenge(false, meta);
        assert!(no_token.starts_with("Bearer "));
        assert!(
            !no_token.contains("error="),
            "a bare challenge must omit the error code: {no_token}"
        );
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
        h.insert(COOKIE, HeaderValue::from_static("other=1; mcp_connect=bind-xyz; last=2"));
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
        assert_eq!(super::token_ttl(default, Some(far), now_ns), Duration::from_secs(86_400));
        // Grant known and shorter than the default (user picked 10 min) → that.
        let soon = now_ns + 600 * 1_000_000_000;
        assert_eq!(super::token_ttl(default, Some(soon), now_ns), Duration::from_secs(600));
        // Grant already expired → zero (never a negative-wrap).
        assert_eq!(super::token_ttl(default, Some(now_ns - 1), now_ns), Duration::ZERO);
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
    fn build_redirect_encodes_code_state_and_iss() {
        let iss = "https://mcp.example/mcp";
        let r = build_redirect("https://claude.ai/cb", "mcp-code-1", "abc/def", iss);
        // code, then state (when present), then the RFC 9207 iss, all percent-encoded.
        assert_eq!(
            r,
            "https://claude.ai/cb?code=mcp-code-1&state=abc%2Fdef&iss=https%3A%2F%2Fmcp.example%2Fmcp"
        );
        // Appends with & when the redirect already has a query; iss is present even
        // when the client sent no state.
        let r2 = build_redirect("https://x.test/cb?foo=1", "c", "", iss);
        assert_eq!(r2, "https://x.test/cb?foo=1&code=c&iss=https%3A%2F%2Fmcp.example%2Fmcp");
    }

    // Build an AuthStore over a dummy II instance (these tests never hit the
    // network — the connect paths are pure-local crypto/state).
    // Build an AuthStore over a dummy II instance, as if its mcp router were
    // nested at `/mcp` on `https://mcp.test`.
    /// Lenient store (tolerates a missing `resource`) — the default the bulk of
    /// the OAuth tests exercise. Strict RFC 8707 is covered by [`test_store_cfg`].
    fn test_store() -> super::AuthStore {
        test_store_cfg(false)
    }

    fn test_store_cfg(require_resource: bool) -> super::AuthStore {
        use candid::Principal;
        use imcp2_core::identities::{Identities, IiInstance};
        let agent =
            crate::Agent::builder().with_url("https://ii.test").build().expect("test agent");
        let ids = Identities::new(
            IiInstance {
                name: "test",
                ii_url: "https://ii.test".into(),
                ii_canister: Principal::anonymous(),
            },
            "https://mcp.test".into(),
            agent,
        );
        super::AuthStore::new(
            ids,
            super::SharedClients(super::ClientStore::with(
                std::collections::HashMap::new(),
                std::env::temp_dir(),
            )),
            "https://mcp.test".into(),
            "/mcp".into(),
            require_resource,
        )
    }

    /// A request header map that accepts HTML — i.e. a browser hitting the
    /// front-channel `/oauth/authorize`.
    fn html_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("text/html,application/xhtml+xml,*/*"),
        );
        h
    }

    /// A request header map for a programmatic OAuth caller (no HTML).
    fn json_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json"),
        );
        h
    }

    async fn seed_pending(store: &super::AuthStore, id: &str, cookie: &str) {
        // Record a pending authorization the way `authorize` does — through the
        // bounded insert — just without the browser redirect around it.
        store
            .insert_pending(
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
            )
            .await;
    }

    // ---- Bounded state (CWE-770) --------------------------------------------

    // `make_room` frees a slot by dropping what has already EXPIRED (zero
    // remaining lifetime) and only then whatever expires soonest, so a bounded
    // map degrades by losing its deadest entries instead of refusing the caller.
    #[test]
    fn make_room_drops_expired_before_the_soonest_to_expire() {
        let mut map: HashMap<&str, Duration> = HashMap::new();
        map.insert("expired", Duration::ZERO);
        map.insert("expires-soon", Duration::from_secs(1));
        map.insert("expires-later", Duration::from_secs(60));

        super::make_room(&mut map, 3, |remaining| *remaining);
        assert_eq!(map.len(), 2, "one slot freed");
        assert!(!map.contains_key("expired"), "the expired entry goes first");

        // Nothing expired left: the one closest to expiry makes the room.
        super::make_room(&mut map, 2, |remaining| *remaining);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("expires-later") && !map.contains_key("expires-soon"));
    }

    // Pending connects are capped: `/oauth/authorize` is unauthenticated, so a
    // flood must churn its own entries out instead of growing the map. (WHICH
    // entry a full map gives up is the eviction policy, pinned by the two
    // `make_room` tests; here the invariant is that the map never grows past its
    // cap and that the connect just started is the one kept.)
    #[tokio::test]
    async fn pending_connects_are_capped() {
        let cap = imcp2_core::identities::MAX_PENDING_CONNECTS;
        let store = test_store();
        for i in 0..cap + 16 {
            seed_pending(&store, &format!("sess-{i}"), "bind").await;
        }

        let authz = store.authz.read().await;
        assert_eq!(authz.len(), cap, "the map never grows past its cap");
        assert!(
            authz.contains_key(&format!("sess-{}", cap + 15)),
            "the connect just started is never the one evicted"
        );
    }

    // The registration store is LRU-bounded: open (unauthenticated) DCR means the
    // map must be capped, and the entry unused for longest goes — every
    // `/oauth/authorize` refreshes its client's stamp, so registrations that are
    // actually signing users in outlive a flood of never-used ones.
    #[test]
    fn make_room_for_client_evicts_least_recently_used() {
        let mut clients: HashMap<String, ClientReg> = (0..super::MAX_CLIENTS)
            .map(|i| {
                let mut reg = ClientReg::new(vec!["http://localhost/cb".to_string()]);
                reg.last_used = 1_000 + i as u64; // client-0 is the least recently used
                (format!("client-{i}"), reg)
            })
            .collect();

        super::make_room_for_client(&mut clients);

        assert_eq!(clients.len(), super::MAX_CLIENTS - 1, "room for exactly one more client");
        assert!(!clients.contains_key("client-0"), "the least-recently-used registration goes");
        assert!(clients.contains_key(&format!("client-{}", super::MAX_CLIENTS - 1)));
    }

    // Using a client (an authorize that accepts its redirect) refreshes its LRU
    // stamp; a rejected redirect does not, so a probe can't keep a stale
    // registration alive.
    #[tokio::test]
    async fn a_used_client_is_marked_recently_used() {
        let store = test_store();
        let redirect = "https://claude.ai/api/mcp/auth_callback";
        store.clients.seed("client-x", vec![redirect]).await;
        let backdate = || async {
            store
                .clients
                .registrations
                .write()
                .await
                .get_mut("client-x")
                .expect("client")
                .last_used = 0;
        };
        let stamp = || async { store.clients.registrations.read().await["client-x"].last_used };

        backdate().await;
        assert!(store.validate_client("client-x", redirect).await);
        assert!(stamp().await > 0, "an accepted redirect refreshes the LRU stamp");

        backdate().await;
        assert!(
            !store
                .validate_client("client-x", "https://claude.ai/api/mcp/auth_callback/nope")
                .await
        );
        assert_eq!(stamp().await, 0, "a rejected redirect must not refresh the stamp");
    }

    // The periodic sweep returns the memory expired entries hold, and leaves live
    // state alone. A zero-TTL token is exactly what `token_ttl` mints for an
    // already-expired grant, so it stands in for "token whose grant has lapsed".
    #[tokio::test]
    async fn reap_expired_drops_dead_state_and_keeps_live_state() {
        let store = test_store();
        seed_pending(&store, "sess-live", "bind-live").await;
        let token = |ttl: Duration| super::TokenInfo {
            principal: "p".into(),
            session_id: "sess-live".into(),
            created: std::time::Instant::now(),
            ttl,
        };
        {
            let mut tokens = store.tokens.write().await;
            tokens.insert("dead".into(), token(Duration::ZERO));
            tokens.insert("live".into(), token(Duration::from_secs(3600)));
        }

        let reaped = store.reap_expired().await;

        assert_eq!(reaped.tokens, 1, "the lapsed token is dropped");
        assert_eq!(reaped.pending, 0, "a connect still inside its TTL is kept");
        assert_eq!(reaped.codes, 0);
        let tokens = store.tokens.read().await;
        assert!(tokens.contains_key("live") && !tokens.contains_key("dead"));
        assert!(store.authz.read().await.contains_key("sess-live"));
    }

    // ---- Connect: link + redeem ---------------------------------------------

    // The II link carries `registration_key` = base64url(DER(pub(X))) (the
    // param II's #4093 frontend parses; its presence selects the flow) in
    // addition to the callback/state/ttl fragment, all in the URL fragment.
    #[test]
    fn v2_link_carries_registration_key() {
        let store = test_store();
        let url = super::ii_mcp_url(&store, "sess-1", "PUBX");
        assert!(url.starts_with("https://ii.test/mcp#"), "everything rides the fragment: {url}");
        assert!(url.contains("state=sess-1"));
        assert!(url.contains("registration_key=PUBX"));
        // The callback lives under the instance's mount ({public_url}{mcp_path}).
        let encoded =
            urlencoding::encode("https://mcp.test/mcp/oauth/connect/callback").into_owned();
        assert!(url.contains(&format!("callback={encoded}")), "callback under the mount: {url}");
    }

    // The allow-list invariant (II #4091 matches by EXACT string equality): the
    // /.well-known/ii-auth-callbacks document must declare, verbatim, the same
    // callback URLs the II links embed — for every instance. Built from one
    // helper (`connect_callback_url`) so they cannot drift; this test locks
    // that in end to end.
    #[tokio::test]
    async fn auth_callbacks_declares_link_callbacks_verbatim() {
        use axum::extract::State;
        use candid::Principal;
        use imcp2_core::identities::{Identities, IiInstance};
        let make = |mcp_path: &'static str| {
            let agent =
                crate::Agent::builder().with_url("https://ii.test").build().expect("test agent");
            super::AuthStore::new(
                Identities::new(
                    IiInstance {
                        name: "t",
                        ii_url: "https://ii.test".into(),
                        ii_canister: Principal::anonymous(),
                    },
                    "https://mcp.test".into(),
                    agent,
                ),
                super::SharedClients(super::ClientStore::with(
                    std::collections::HashMap::new(),
                    std::env::temp_dir(),
                )),
                "https://mcp.test".into(),
                mcp_path.into(),
                false,
            )
        };
        // Both instances, so the allow-list covers each mount.
        let prod = make("/mcp");
        let beta = make("/mcp-beta");

        let r = super::auth_callbacks(State(vec![prod.clone(), beta.clone()])).await;
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
            (&prod, super::ii_mcp_url(&prod, "s", "K")),
            (&beta, super::ii_mcp_url(&beta, "s", "K")),
        ] {
            let expected = super::connect_callback_url(store);
            assert!(declared.contains(&expected), "{expected} must be declared: {declared:?}");
            let encoded = format!("callback={}", urlencoding::encode(&expected));
            assert!(link.contains(&encoded), "the II link must embed the declared URL: {link}");
        }
        // Both entries share the origin II fetches the document from, and no
        // entry carries a fragment (II rejects both).
        for d in &declared {
            assert!(d.starts_with("https://mcp.test"), "same-origin entries only: {d}");
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
        store.clients.seed("client-x", vec!["https://claude.ai/api/mcp/auth_callback"]).await;
        let resp = super::authorize(
            State(store.clone()),
            // The success path is Accept-agnostic; an empty header map is fine.
            axum::http::HeaderMap::new(),
            Query(super::AuthorizeQuery {
                response_type: Some("code".into()),
                client_id: "client-x".into(),
                redirect_uri: "https://claude.ai/api/mcp/auth_callback".into(),
                state: Some("xyz".into()),
                code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
                code_challenge_method: Some("S256".into()),
                scope: None,
                resource: None,
            }),
        )
        .await;

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::FOUND,
            "authorize must 302, not render a page"
        );
        let h = resp.headers();
        let location = h.get(axum::http::header::LOCATION).unwrap().to_str().unwrap();
        // The II link, with the connect params carried in the URL FRAGMENT.
        assert!(
            location.starts_with("https://ii.test/mcp#"),
            "redirects to the II /mcp link: {location}"
        );
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

    #[test]
    fn resource_matches_issuer_accepts_only_this_instance() {
        let issuer = "https://mcp.test/mcp";
        // Canonical, plus security-irrelevant variance that must still match.
        for ok in [
            "https://mcp.test/mcp",
            "https://mcp.test/mcp/",    // one trailing slash
            "https://MCP.test/mcp",     // host case
            "HTTPS://mcp.test/mcp",     // scheme case
            "https://mcp.test:443/mcp", // explicit default port
        ] {
            assert!(super::resource_matches_issuer(ok, issuer), "must accept {ok}");
        }
        // Anything that is not the advertised identifier is refused: foreign
        // host, sibling instance path, non-default port, fragment, userinfo,
        // a differing query, a doubled trailing slash, scheme downgrade, and
        // unparseable input.
        for bad in [
            "https://other.example/mcp",
            "https://mcp.test/mcp-beta",
            "https://mcp.test:8443/mcp",
            "https://mcp.test/mcp#x",
            "https://user@mcp.test/mcp", // userinfo is not part of the identifier
            "https://@mcp.test/mcp",     // empty userinfo (url erases it) — still refused
            "https://:@mcp.test/mcp",    // empty user:pass userinfo — still refused
            "https:\t//user@mcp.test/mcp", // tab hides `://`; url strips it, parsing userinfo
            "https://mcp.test\n/mcp",    // stripped newline must not smuggle content past the scan
            "https://mcp.test/mcp?tenant=other", // a query differs from the issuer's (none)
            "https://mcp.test/mcp//",    // doubled trailing slash is a distinct path
            "http://mcp.test/mcp",       // scheme downgrade
            "not-a-url",
        ] {
            assert!(!super::resource_matches_issuer(bad, issuer), "must refuse {bad}");
        }
    }

    // RFC 8707: `/oauth/authorize` refuses a `resource` that names a different
    // MCP server, while a matching or absent resource still reaches the II
    // redirect.
    #[tokio::test]
    async fn authorize_rejects_foreign_resource_indicator() {
        use axum::extract::{Query, State};
        let store = test_store();
        store.clients.seed("client-x", vec!["https://claude.ai/api/mcp/auth_callback"]).await;
        let mk = |resource: Option<&str>| super::AuthorizeQuery {
            response_type: Some("code".into()),
            client_id: "client-x".into(),
            redirect_uri: "https://claude.ai/api/mcp/auth_callback".into(),
            state: Some("xyz".into()),
            code_challenge: Some(super::pkce_s256("verifier")),
            code_challenge_method: Some("S256".into()),
            scope: None,
            resource: resource.map(str::to_owned),
        };

        // A foreign resource is refused with `invalid_target` and never reaches II.
        let foreign = super::authorize(
            State(store.clone()),
            json_headers(),
            Query(mk(Some("https://other.example/mcp"))),
        )
        .await;
        assert_eq!(
            foreign.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "a foreign resource must be refused"
        );
        let body = axum::body::to_bytes(foreign.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_target"
        );

        // A sibling instance's resource (same host, other path) is also foreign.
        let sibling = super::authorize(
            State(store.clone()),
            json_headers(),
            Query(mk(Some("https://mcp.test/mcp-beta"))),
        )
        .await;
        assert_eq!(
            sibling.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "a sibling instance's resource must be refused"
        );

        // This instance's own resource (and a trailing-slash variant) → 302 to II.
        for ok in ["https://mcp.test/mcp", "https://mcp.test/mcp/"] {
            let resp = super::authorize(
                State(store.clone()),
                axum::http::HeaderMap::new(),
                Query(mk(Some(ok))),
            )
            .await;
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::FOUND,
                "the canonical resource must be accepted: {ok}"
            );
        }

        // A missing resource stays accepted (pre-RFC-8707 clients).
        let none =
            super::authorize(State(store.clone()), axum::http::HeaderMap::new(), Query(mk(None)))
                .await;
        assert_eq!(
            none.status(),
            axum::http::StatusCode::FOUND,
            "a missing resource must remain accepted"
        );
    }

    // RFC 8707 end-to-end: a token request carrying a FOREIGN `resource` is
    // refused with `invalid_target`, so a token is only ever issued for this
    // instance. The canonical resource (or none) still mints a token the
    // protected /mcp accepts.
    #[tokio::test]
    async fn token_endpoint_enforces_resource_indicator() {
        use axum::{
            body::Body,
            http::{header, Request, StatusCode},
            middleware,
            routing::post,
            Router,
        };
        use tower::ServiceExt;

        let store = test_store();
        let make_app = |store: super::AuthStore| {
            let protected = Router::new()
                .route("/mcp", post(|| async { "authenticated" }))
                .route_layer(middleware::from_fn_with_state(store.clone(), super::require_token));
            Router::new()
                .route("/oauth/token", post(super::token))
                .merge(protected)
                .with_state(store)
        };
        // A pending code stands in for the successful II consent/redeem boundary.
        let seed_code = || super::CodeGrant {
            client_id: "mcp-client".into(),
            code_challenge: Some(super::pkce_s256("verifier")),
            session_id: "mcp-session".into(),
            created: std::time::Instant::now(),
        };
        let body_for = |code: &str, resource: Option<&str>| {
            let mut b = format!("grant_type=authorization_code&code={code}&client_id=mcp-client&code_verifier=verifier");
            if let Some(r) = resource {
                b.push_str(&format!("&resource={}", urlencoding::encode(r)));
            }
            b
        };

        // 1) Foreign resource → refused with `invalid_target`, and the code is NOT
        //    consumed (the check runs before the code is taken).
        store.codes.write().await.insert("proof-code".into(), seed_code());
        let refused = make_app(store.clone())
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body_for("proof-code", Some("https://other.example/mcp"))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            refused.status(),
            StatusCode::BAD_REQUEST,
            "a foreign resource must be refused at /oauth/token"
        );
        let body = axum::body::to_bytes(refused.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_target"
        );
        assert!(
            store.codes.read().await.contains_key("proof-code"),
            "a refused request must not consume the code"
        );

        // 2) Canonical resource → token minted and accepted by the protected /mcp.
        let exchange = make_app(store.clone())
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body_for("proof-code", Some("https://mcp.test/mcp"))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exchange.status(), StatusCode::OK, "the canonical resource must be accepted");
        let body = axum::body::to_bytes(exchange.into_body(), usize::MAX).await.unwrap();
        let token = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let authed = make_app(store.clone())
            .oneshot(
                Request::post("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            authed.status(),
            StatusCode::OK,
            "a token for this resource must be accepted at /mcp"
        );

        // 3) Missing resource → still accepted (pre-RFC-8707 clients).
        store.codes.write().await.insert("proof-code-2".into(), seed_code());
        let legacy = make_app(store.clone())
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body_for("proof-code-2", None)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy.status(), StatusCode::OK, "a missing resource must remain accepted");
    }

    // Strict RFC 8707 (`require_resource`): `/oauth/authorize` now REQUIRES a
    // `resource`. A missing one is refused with `invalid_request`; a foreign one
    // is still `invalid_target`; the canonical one still reaches II.
    #[tokio::test]
    async fn authorize_strict_requires_resource() {
        use axum::extract::{Query, State};
        let store = test_store_cfg(true);
        store.clients.seed("client-x", vec!["https://claude.ai/api/mcp/auth_callback"]).await;
        let mk = |resource: Option<&str>| super::AuthorizeQuery {
            response_type: Some("code".into()),
            client_id: "client-x".into(),
            redirect_uri: "https://claude.ai/api/mcp/auth_callback".into(),
            state: Some("xyz".into()),
            code_challenge: Some(super::pkce_s256("verifier")),
            code_challenge_method: Some("S256".into()),
            scope: None,
            resource: resource.map(str::to_owned),
        };

        // Missing resource → refused with `invalid_request` (the strict delta).
        let missing = super::authorize(State(store.clone()), json_headers(), Query(mk(None))).await;
        assert_eq!(
            missing.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "strict mode must refuse a missing resource"
        );
        let body = axum::body::to_bytes(missing.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_request"
        );

        // Foreign resource → still `invalid_target`.
        let foreign = super::authorize(
            State(store.clone()),
            json_headers(),
            Query(mk(Some("https://other.example/mcp"))),
        )
        .await;
        assert_eq!(foreign.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(foreign.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_target"
        );

        // Canonical resource → still reaches II.
        let ok = super::authorize(
            State(store.clone()),
            axum::http::HeaderMap::new(),
            Query(mk(Some("https://mcp.test/mcp"))),
        )
        .await;
        assert_eq!(
            ok.status(),
            axum::http::StatusCode::FOUND,
            "the canonical resource must still be accepted in strict mode"
        );
    }

    // Strict RFC 8707 at `/oauth/token`: a missing `resource` is refused with
    // `invalid_request` and does NOT consume the code; the canonical resource
    // still mints a token.
    #[tokio::test]
    async fn token_strict_requires_resource() {
        use axum::{
            body::Body,
            http::{header, Request, StatusCode},
            routing::post,
            Router,
        };
        use tower::ServiceExt;

        let store = test_store_cfg(true);
        let app =
            || Router::new().route("/oauth/token", post(super::token)).with_state(store.clone());
        let seed = || super::CodeGrant {
            client_id: "mcp-client".into(),
            code_challenge: Some(super::pkce_s256("verifier")),
            session_id: "mcp-session".into(),
            created: std::time::Instant::now(),
        };
        let body_for = |code: &str, resource: Option<&str>| {
            let mut b = format!("grant_type=authorization_code&code={code}&client_id=mcp-client&code_verifier=verifier");
            if let Some(r) = resource {
                b.push_str(&format!("&resource={}", urlencoding::encode(r)));
            }
            b
        };

        // Missing resource → refused with `invalid_request`, code untouched.
        store.codes.write().await.insert("proof-code".into(), seed());
        let refused = app()
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body_for("proof-code", None)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            refused.status(),
            StatusCode::BAD_REQUEST,
            "strict mode must refuse a missing resource at /oauth/token"
        );
        let body = axum::body::to_bytes(refused.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_request"
        );
        assert!(
            store.codes.read().await.contains_key("proof-code"),
            "a refused request must not consume the code"
        );

        // Canonical resource → token minted.
        let ok = app()
            .oneshot(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body_for("proof-code", Some("https://mcp.test/mcp"))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            ok.status(),
            StatusCode::OK,
            "the canonical resource must mint a token in strict mode"
        );
    }

    // A client turned away by the allow-list gets the on-brand HTML page, not a
    // raw JSON blob: 403, names the contact, ships a strict nonce'd CSP, carries
    // no script, and (taking no input) reflects nothing.
    #[tokio::test]
    async fn not_allowlisted_page_names_contact_and_reflects_nothing() {
        let resp = super::not_allowlisted_page();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        let csp = resp
            .headers()
            .get(axum::http::header::CONTENT_SECURITY_POLICY)
            .expect("CSP header present")
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("img-src 'self'"), "{csp}");
        // No script on this page: the CSP must not open a script-src.
        assert!(!csp.contains("script-src"), "the error page needs no script-src: {csp}");
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|s| s.split('\'').next())
            .expect("nonce in CSP")
            .to_string();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains(super::CONTACT), "the page must name the contact");
        // The contact renders as a mailto link, and no placeholder token leaks.
        assert!(
            html.contains(&format!("mailto:{}", super::CONTACT)),
            "the contact must be a mailto link"
        );
        assert!(!html.contains("__"), "every template placeholder must be substituted: {html}");
        assert!(!html.contains("<script"), "the error page carries no script");
        assert!(html.contains("rel=icon href=/favicon.svg"), "{html}");
        assert!(
            html.contains(&format!("<style nonce=\"{nonce}\">")),
            "the inline style nonce must match the CSP nonce"
        );
    }

    // `/oauth/authorize` content-negotiates every non-redirectable failure: a
    // browser (Accept: text/html) gets an on-brand error screen naming the
    // contact, while a programmatic OAuth caller keeps the RFC-style JSON. This
    // covers both the allow-list rejection (403) and an unknown client (400).
    #[tokio::test]
    async fn authorize_errors_are_friendly_for_browsers_and_json_for_machines() {
        use axum::extract::{Query, State};
        let store = test_store();
        // A stored-but-disallowed registration (a hosted redirect on a
        // non-allow-listed domain) plus a permitted-but-unregistered client.
        store.clients.seed("client-legacy", vec!["https://example.com/cb"]).await;
        let mk = |client_id: &str, redirect_uri: &str| super::AuthorizeQuery {
            response_type: Some("code".into()),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            state: Some("xyz".into()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            scope: None,
            resource: None,
        };
        let content_type = |resp: &axum::response::Response| {
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };

        // -- Browser (Accept: text/html): friendly on-brand HTML in both cases. --
        // Disallowed hosted redirect -> 403 HTML naming the contact.
        let resp = super::authorize(
            State(store.clone()),
            html_headers(),
            Query(mk("client-legacy", "https://example.com/cb")),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(
            content_type(&resp).starts_with("text/html"),
            "an allow-list rejection renders HTML for a browser"
        );
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(html.contains(super::CONTACT));

        // Unknown client but an allow-listed redirect -> 400 friendly HTML that
        // names the contact via the "report it" line.
        let resp = super::authorize(
            State(store.clone()),
            html_headers(),
            Query(mk("client-nope", "https://claude.ai/api/mcp/auth_callback")),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        assert!(
            content_type(&resp).starts_with("text/html"),
            "an unknown client renders HTML for a browser"
        );
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(html.contains(super::CONTACT), "the screen must name the contact");
        assert!(html.contains("report it"), "the screen must carry the report-it line");

        // -- Machine (Accept: application/json): RFC-style JSON in both cases. --
        for (client_id, redirect_uri, want_status) in [
            ("client-legacy", "https://example.com/cb", axum::http::StatusCode::FORBIDDEN),
            (
                "client-nope",
                "https://claude.ai/api/mcp/auth_callback",
                axum::http::StatusCode::BAD_REQUEST,
            ),
        ] {
            let resp = super::authorize(
                State(store.clone()),
                json_headers(),
                Query(mk(client_id, redirect_uri)),
            )
            .await;
            assert_eq!(resp.status(), want_status);
            assert!(
                content_type(&resp).contains("json"),
                "a machine caller keeps JSON for {client_id}"
            );
        }
    }

    // A malformed or ineligible redirect_uri (here: non-loopback http) is a
    // client request error, NOT an approval gap: it is classified invalid_request
    // and shows the generic sign-in error, never the "request access" allow-list
    // page. (`redirect_uri_permitted` rejects it, but it isn't a well-formed
    // hosted redirect, so it must not be funneled to the not-approved screen.)
    #[tokio::test]
    async fn authorize_malformed_redirect_is_invalid_request_not_allowlist() {
        use axum::extract::{Query, State};
        let store = test_store();
        // Registered directly (bypassing DCR, which would reject it) so the failure
        // is the redirect eligibility check, not an unknown client.
        store.clients.seed("client-x", vec!["http://other.example/cb"]).await;
        let mk = || super::AuthorizeQuery {
            response_type: Some("code".into()),
            client_id: "client-x".into(),
            redirect_uri: "http://other.example/cb".into(), // non-loopback http: ineligible AND not well-formed hosted
            state: Some("xyz".into()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            scope: None,
            resource: None,
        };

        // Browser: the generic sign-in error, NOT the allow-list "request access" page.
        let resp = super::authorize(State(store.clone()), html_headers(), Query(mk())).await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(html.contains("report it"), "shows the generic sign-in error with the report line");
        assert!(!html.contains("allow-list"), "must NOT be the allow-list rejection page: {html}");

        // Machine: invalid_request JSON, not invalid_client / 403.
        let resp = super::authorize(State(store.clone()), json_headers(), Query(mk())).await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(body.contains("invalid_request"), "machine gets invalid_request: {body}");
    }

    // A malformed sign-in request (here: PKCE missing) reached in a browser gets
    // the friendly screen with a best-effort diagnostic AND the report-it line,
    // while a machine keeps the RFC `invalid_request` JSON. The screen is the
    // strict, non-scripted, unframeable error shell.
    #[tokio::test]
    async fn authorize_missing_pkce_is_friendly_for_browsers() {
        use axum::extract::{Query, State};
        let store = test_store();
        store.clients.seed("client-x", vec!["https://claude.ai/api/mcp/auth_callback"]).await;
        let mk = || super::AuthorizeQuery {
            response_type: Some("code".into()),
            client_id: "client-x".into(),
            redirect_uri: "https://claude.ai/api/mcp/auth_callback".into(),
            state: Some("xyz".into()),
            code_challenge: None, // the failure under test
            code_challenge_method: None,
            scope: None,
            resource: None,
        };

        // Browser: a friendly 400 screen naming the cause and the contact.
        let resp = super::authorize(State(store.clone()), html_headers(), Query(mk())).await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let csp = resp
            .headers()
            .get(axum::http::header::CONTENT_SECURITY_POLICY)
            .expect("CSP header present")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"),
            "{csp}"
        );
        assert!(!csp.contains("script-src"), "the error screen needs no script-src: {csp}");
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(html.contains("PKCE"), "the diagnostic should name the missing security parameter");
        assert!(
            html.contains(&format!("mailto:{}", super::CONTACT)),
            "the screen names the contact"
        );
        assert!(!html.contains("__"), "every placeholder must be substituted: {html}");

        // Machine: the RFC-style JSON error is preserved.
        let resp = super::authorize(State(store.clone()), json_headers(), Query(mk())).await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let ctype = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ctype.contains("json"), "a machine caller keeps JSON: {ctype}");
    }

    // `accepts_html` keys on an explicit `text/html`, so browsers (which always
    // send it) get screens and machines default to JSON.
    #[test]
    fn accepts_html_detects_browsers_only() {
        use axum::http::{header::ACCEPT, HeaderMap, HeaderValue};
        let with = |v: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(ACCEPT, HeaderValue::from_static(v));
            h
        };
        assert!(super::accepts_html(&with("text/html,application/xhtml+xml,*/*")));
        assert!(super::accepts_html(&with("text/html")));
        assert!(super::accepts_html(&with("text/html;q=0.9,application/json")));
        // Media types are case-insensitive (RFC 9110 §12.5.1).
        assert!(super::accepts_html(&with("TEXT/HTML")));
        assert!(!super::accepts_html(&with("application/json")));
        assert!(!super::accepts_html(&with("*/*")));
        // A wildcard does not opt into HTML; only an explicit `text/html` does.
        assert!(!super::accepts_html(&with("text/*")));
        // `;q=0` explicitly marks text/html as NOT acceptable (§12.4.2), so a
        // caller that says so stays on JSON despite naming the type.
        assert!(!super::accepts_html(&with("text/html;q=0, application/json")));
        assert!(!super::accepts_html(&with("text/html;q=0.0")));
        // No Accept header at all → treated as a machine (JSON).
        assert!(!super::accepts_html(&HeaderMap::new()));
    }

    // The pinned page ships a strict CSP whose script nonce MATCHES the inline
    // script (so no `'unsafe-inline'`), limits network reach to same-origin, and
    // reflects NO attacker input (it reads the fragment client-side via
    // `location.hash` and never writes it into the HTML).
    #[tokio::test]
    async fn pinned_page_has_strict_csp_matching_nonce_and_no_reflection() {
        let resp = super::pinned_callback_page("/mcp-beta");
        let csp = resp
            .headers()
            .get(axum::http::header::CONTENT_SECURITY_POLICY)
            .expect("CSP header present")
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("connect-src 'self'"), "{csp}");
        assert!(csp.contains("img-src 'self'"), "{csp}");
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
        assert!(html.contains("rel=icon href=/favicon.svg"), "{html}");
        assert!(html.contains("location.hash"), "the page reads the fragment client-side");
        assert!(
            html.contains("/mcp-beta/oauth/connect/redeem"),
            "posts to the instance's redeem path"
        );
        assert!(!html.contains("__REDEEM_URL__"), "the redeem-URL placeholder must be substituted");
        // Every handshake/redeem failure lands on this page, so it carries the
        // "contact us to report it" line (hidden until the script adds `.error`),
        // and the contact placeholder must be substituted for a real mailto link.
        assert!(
            html.contains(&format!("mailto:{}", super::CONTACT)),
            "the callback page must carry the contact mailto link"
        );
        assert!(html.contains("contact-hint"), "the contact line uses the .contact-hint hook");
        assert!(!html.contains("__CONTACT__"), "the contact placeholder must be substituted");
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

    // Redemption is SINGLE-FLIGHT per connect: the first claim wins, a concurrent
    // claim is refused while mid-flight, a released (failed) claim can be retried,
    // and once a code exists every later claim returns it (idempotent) instead of
    // redeeming again.
    #[tokio::test]
    async fn redemption_claim_is_single_flight() {
        let store = test_store();
        seed_pending(&store, "sess-r", "bind-r").await;

        // First claim wins; a concurrent second claim is refused.
        assert!(matches!(
            super::claim_redemption(&store, "sess-r").await,
            super::RedeemClaim::Claimed
        ));
        assert!(matches!(
            super::claim_redemption(&store, "sess-r").await,
            super::RedeemClaim::InProgress
        ));

        // A failed attempt releases the claim, so a genuine retry proceeds.
        super::release_redemption(&store, "sess-r").await;
        assert!(matches!(
            super::claim_redemption(&store, "sess-r").await,
            super::RedeemClaim::Claimed
        ));

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
            axum::Json(super::RedeemBody { state: "sess-x".into(), delegation: String::new() }),
        )
        .await;
        assert_eq!(redeem.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
