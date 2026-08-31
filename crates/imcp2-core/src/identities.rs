//! On-demand per-app delegated identities.
//!
//! Session model (per the Internet Identity MCP server guide): at connect time
//! the server generates a fresh Ed25519 **session key `S` per user-connection**,
//! and II binds a time-boxed **grant** for it to the user's anchor — the session
//! key's principal `self_authenticating(session_pubkey)` IS the identity the
//! grant is bound to. It gets bound via the **registration-delegation** connect
//! flow (see `crate::auth`): the server also mints a per-connect **registration
//! key `X`**; II delivers a short-lived, TWO-hop chain `P_reg -> Y -> X` to the
//! pinned callback page — the canister-signed `P_reg -> Y` targets an ephemeral
//! key `Y` held only by II's frontend (so the piece that transits the IC is inert
//! on its own), and the browser-signed `Y -> X` extends it to our registration
//! key — and the server redeems it with ONE `mcp_register_v2(pub(S))` call signed
//! as `X`. The anchor and the consent values (permissions, max_ttl) are NOT sent:
//! the consent was captured earlier by II's frontend at
//! `prepare_mcp_registration_delegation` and stored server-side keyed by `P_reg`,
//! and II recovers both it and the anchor from `caller() == P_reg`
//! ([`Identities::redeem_registration_delegation`]).
//!
//! From registration on, the server signs II's `mcp_*` calls directly with `S`
//! until the grant expires or is revoked.
//!
//! To call a canister as the user's account for a given app (e.g. `oisy.com`)
//! the server mints a **short-lived per-app account delegation ON DEMAND**:
//! signing the II calls DIRECTLY with the session key, it calls II's
//! `mcp_get_accounts` / `mcp_prepare_delegation` / `mcp_get_delegation`, passing a
//! fresh **per-app key** as the `session_key` argument. The returned delegation
//! is issued to that per-app key, so the server acts as the user's app account
//! via a `DelegatedIdentity` over the chain `[user_key -> per-app key]`. There is
//! no per-app browser sign-in flow.
//!
//! The derived `(user_key, chain, expiration)` is cached per `(session_id,
//! domain, account_number)` with a margin under the delegation's expiration; it
//! is reused until near-expiry, then re-derived.
//!
//! ## Bounded state (CWE-770)
//!
//! Everything held here is capped, because the connect entry point is reachable
//! without authentication: `/oauth/authorize` mints one `Session` (two Ed25519
//! keypairs) per request, so an unauthenticated `GET` loop would otherwise grow
//! the map forever. Two mechanisms, working together:
//!
//!   * **Admission** ([`make_room`], on every session creation): prune what is
//!     stale, evict the oldest PENDING connects past [`MAX_PENDING_CONNECTS`],
//!     and refuse a new session outright past [`MAX_SESSIONS`] — never evicting a
//!     live grant to make room. This is what bounds the map *between* sweeps.
//!   * **Reaping** ([`Identities::reap_expired_sessions`], on a 60s timer):
//!     expired grants and abandoned connects (pending for more than
//!     [`PENDING_CONNECT_TTL_NS`]) leave the map.
//!
//! Per session, the delegation cache is capped at [`MAX_APP_DELEGATIONS`]
//! entries, evicted by nearest expiry — a session picks its own cache keys
//! (one per `(origin, account)` it asks for), so that map is caller-driven too.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::{
    identity::{BasicIdentity, DelegatedIdentity, Delegation, DelegationPermissions, SignedDelegation},
    Agent, Identity,
};
// rmcp re-exports schemars 1.x; the `#[tool]` output-schema machinery requires
// THAT version's `JsonSchema`, so derive the MCP output types against it.
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Re-derive once the cached delegation is within this margin of expiry, so a
/// call never goes out with an about-to-expire delegation.
const REDERIVE_MARGIN_NS: u64 = 30 * 1_000_000_000;

/// Ceiling on **connects in flight** — sessions minted by `/oauth/authorize`
/// that have not (yet) redeemed a grant. That endpoint is UNAUTHENTICATED, so
/// each request would otherwise add a permanent `Session` (holding two Ed25519
/// keypairs) to the map: a bare `GET` loop is an unbounded-growth primitive
/// (CWE-770). Once the cap is reached a new connect evicts the OLDEST pending
/// one ([`make_room`]) rather than being refused, so a flood churns its own
/// entries out instead of blocking sign-in, and granted sessions are never
/// touched. Also the cap on `AuthStore.authz`, which holds one entry per
/// pending connect (see `crate::auth`), so the two maps stay in step.
pub const MAX_PENDING_CONNECTS: usize = 1_024;

/// Hard ceiling on the session map. Only sessions holding a redeemed grant can
/// push toward it (pending ones are bounded far lower by
/// [`MAX_PENDING_CONNECTS`]), and each of those costs a real II consent, so this
/// is a backstop rather than an attacker-reachable limit: a live grant is never
/// evicted to make room, and a connect that would exceed the cap is refused with
/// [`AT_CAPACITY_MSG`].
const MAX_SESSIONS: usize = 20_000;

/// How long a session that never redeemed a grant is kept before the reaper
/// treats the connect as abandoned. Comfortably past `crate::auth`'s 10-minute
/// `CONNECT_TTL`, after which the connect can no longer be redeemed anyway, so
/// this only ever drops sessions that are already dead weight.
const PENDING_CONNECT_TTL_NS: u64 = 15 * 60 * 1_000_000_000;

/// Per-session ceiling on cached per-app delegations. `store` inserts one per
/// distinct `(derivation origin, account)` a session asks for, so a single
/// authenticated session could otherwise inflate its own map without limit by
/// requesting delegations at many origins. Generous next to real use (an agent
/// touches a handful of apps per session); eviction is by expiry, and an evicted
/// entry is simply re-derived on the next call.
const MAX_APP_DELEGATIONS: usize = 64;

/// Shown when a connect can't be started because the session map is at
/// [`MAX_SESSIONS`]. Actionable: the caller should retry, not re-register.
const AT_CAPACITY_MSG: &str = "This server is at capacity for Internet Identity sessions right now. \
     Wait a few minutes and start the sign-in again.";

/// Internet Identity instance, single source of truth. Default: **`beta.id.ai`**.
/// A real domain is required: the raw `<canister>.icp0.io` origin is rate-limited
/// (HTTP 429) for the browser login SPA, leaving the II popup blank. Used for the
/// connect-time `/mcp-beta` (staging) handshake (browser). Override with `II_URL`.
const II_URL_DEFAULT: &str = "https://beta.id.ai";

/// Canister id of that same II instance, used for the on-demand account
/// delegation calls (`mcp_get_accounts` / `mcp_prepare_delegation` /
/// `mcp_get_delegation`). Default is the `beta.id.ai` canister. Override with
/// `II_CANISTER_ID`.
const II_CANISTER_ID_DEFAULT: &str = "fgte5-ciaaa-aaaad-aaatq-cai";

/// Production Internet Identity origin, used by the `/mcp` (production) instance.
/// Override with `II_URL_PROD`.
const II_URL_PROD_DEFAULT: &str = "https://id.ai";

/// Canister id of production Internet Identity (the canonical II canister).
/// Override with `II_CANISTER_ID_PROD`.
const II_CANISTER_ID_PROD_DEFAULT: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";

/// Message shown whenever II reports the grant is gone (`Unauthorized`) or the
/// stored grant expiration has passed. Per the spec, any `Unauthorized` means the
/// session is over — the caller must start a fresh connect with a fresh session
/// key; it must NOT retry.
const RECONNECT_MSG: &str = "Your Internet Identity session is over (the grant expired, was revoked, \
     or was replaced by a newer connection). Reconnect with Internet Identity to continue — do not retry.";

/// Shown when a tool needs update (write) access but the II session is
/// query-only (`permissions = "queries"`). II's consent screen requires the user
/// to pick an access level — "Questions only" or "Actions & questions" — and this
/// is what the former grants; there is no read-only toggle to turn off, so the
/// message names the choice the user actually has to make. The IC rejects update
/// calls made through such a session's delegations at ingress, which would
/// otherwise surface as an opaque low-level rejection — so we stop early with an
/// actionable message (H2).
const READ_ONLY_MSG: &str = "This Internet Identity session was authorized for \"Questions only\", so it \
     can't make changes. Creating, installing, starting, stopping, or deleting canisters — and even \
     reading canister status — are update calls a Questions-only session can't make. Reconnect with \
     Internet Identity and choose \"Actions & questions\" on the consent screen, then try again.";

/// One Internet Identity instance this server can connect users against —
/// purely *which II* (origin + canister), nothing about where the instance is
/// mounted on this server: the mount path is deployment composition, chosen in
/// `McpConfig` when the instance's routers are built. Each instance gets its
/// own `Identities` + `AuthStore`, so sessions/tokens never cross instances;
/// II trust in the user's settings is by ORIGIN, which all instances share.
#[derive(Clone, Debug)]
pub struct IiInstance {
    /// Short name for logging ("beta", "prod").
    pub name: &'static str,
    /// Origin of the II instance (no trailing slash), e.g. <https://beta.id.ai>.
    pub ii_url: String,
    /// Canister id of that II instance — the target of the `mcp_*` calls.
    pub ii_canister: Principal,
}

impl IiInstance {
    /// The default instance: beta Internet Identity (`II_URL` / `II_CANISTER_ID`).
    pub fn beta() -> Result<Self, String> {
        Ok(Self {
            name: "beta",
            ii_url: env_origin("II_URL", II_URL_DEFAULT),
            ii_canister: env_principal("II_CANISTER_ID", II_CANISTER_ID_DEFAULT)?,
        })
    }

    /// The production instance (`II_URL_PROD` / `II_CANISTER_ID_PROD`).
    pub fn prod() -> Result<Self, String> {
        Ok(Self {
            name: "prod",
            ii_url: env_origin("II_URL_PROD", II_URL_PROD_DEFAULT),
            ii_canister: env_principal("II_CANISTER_ID_PROD", II_CANISTER_ID_PROD_DEFAULT)?,
        })
    }
}

/// An origin from the environment (no trailing slash), with a default.
fn env_origin(var: &str, default: &str) -> String {
    std::env::var(var)
        .unwrap_or_else(|_| default.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// A principal from the environment, with a default.
fn env_principal(var: &str, default: &str) -> Result<Principal, String> {
    let raw = std::env::var(var).unwrap_or_else(|_| default.to_string());
    Principal::from_text(&raw).map_err(|e| format!("invalid {var} '{raw}': {e}"))
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

/// A session counts as *active* on the `/version` `active_sessions` gauge if it
/// showed activity within this window. Activity is any authenticated MCP request
/// (bumped via [`Identities::touch_session`]) plus the connect that redeems the
/// grant (`set_grant_expiration` stamps the same field), so a freshly-connected
/// session is active from the start, before its first tool call. Unlike `live_sessions`
/// (open grants), this tracks who is USING the server right now, so operators
/// can time a redeploy for a low-traffic moment: a restart wipes the in-memory
/// session/token maps and forces every currently-connected client to reconnect,
/// so the disruption falls on whoever is active around the deploy. 15 minutes is
/// long enough to ride out the idle gaps between an agent's tool calls (so a
/// user mid-task doesn't flicker off — the bug that motivated splitting this
/// from `live_sessions`), short enough that a client gone quiet drops off well
/// before it would matter for deploy timing. In stateless mode a disconnect is
/// unobservable, so activity is the only available proxy for "still here".
const ACTIVE_SESSION_WINDOW_NS: u64 = 15 * 60 * 1_000_000_000;

/// The two `/version` session gauges, returned together by
/// [`McpServer::session_gauges`](crate::McpServer::session_gauges) so a scrape
/// locks and iterates the session map once and reports a consistent
/// `active <= live` pair.
#[derive(Debug, Clone, Copy)]
pub struct SessionGauges {
    /// Sessions holding a currently-valid II grant (the `live_sessions` gauge).
    pub live: usize,
    /// The subset also active within the last 15 minutes (the
    /// `active_sessions` gauge). Always `<= live`.
    pub active: usize,
}

/// Remap a domain to the `target_origin` II expects for account derivation.
/// IC gateway domains (`*.icp0.io`, `*.icp.net`) map to the canonical
/// `*.ic0.app` origin; any other domain is passed through as `https://<host>`.
///
/// II derives the app principal from an anchored regex on a bare origin, so we
/// first reduce the input to its authority (`host[:port]`): drop the scheme, then
/// anything from the first path/query/fragment separator, then a redundant `:443`
/// (the default HTTPS port). Without this, a `target_origin` carrying a path,
/// `:443`, or a trailing slash would fall through un-remapped and derive a
/// DIFFERENT principal (H1). Note this only replicates II's *domain-based*
/// derivation — a dapp declaring a custom derivation origin via
/// `/.well-known/ii-alternative-origins` is NOT handled here (a known limitation).
pub(crate) fn target_origin(domain: &str) -> String {
    let host = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split(['/', '?', '#']).next().unwrap_or(host);
    let host = host.strip_suffix(":443").unwrap_or(host);
    for gateway in [".icp0.io", ".icp.net"] {
        if let Some(label) = host.strip_suffix(gateway) {
            return format!("https://{label}.ic0.app");
        }
    }
    format!("https://{host}")
}

struct Session {
    /// Ed25519 session-key seed; rebuild a `BasicIdentity` from it on demand.
    /// This is the key generated for this connection and bound to the anchor by
    /// `mcp_register_v2` (which the backend signs during connect redemption); the
    /// server signs II's `mcp_*` calls directly with it. Its private half never
    /// leaves the backend — only its public key is ever sent to II.
    key_seed: [u8; 32],
    /// DER public key of the session key.
    pubkey_der: Vec<u8>,
    /// The grant's expiration (ns since the Unix epoch), from the `mcp_register_v2`
    /// reply recorded at connect redemption. `None` until redemption records it;
    /// a missing value is not treated as expired — an `Unauthorized` from a signed
    /// call is the authoritative "session over" signal.
    grant_expiration_ns: Option<u64>,
    /// Wall-clock (ns since the epoch) this session was created at, i.e. when
    /// `/oauth/authorize` started the connect. Never updated. Two bounds read
    /// it: the reaper drops a session that still holds no grant
    /// [`PENDING_CONNECT_TTL_NS`] after this (an abandoned connect), and
    /// [`make_room`] evicts the oldest pending connects first when the map hits
    /// [`MAX_PENDING_CONNECTS`].
    created_ns: u64,
    /// Wall-clock (ns since the epoch) of this session's most recent
    /// authenticated request, bumped per request via [`Identities::touch_session`]
    /// (and on connect). Drives ONLY the `/version` `active_sessions` gauge's
    /// activity window ([`ACTIVE_SESSION_WINDOW_NS`]): a session that goes quiet
    /// stops counting as *active* once it exceeds the window, even while its grant
    /// stays valid (so it still counts as *live*). Atomic so the per-request touch
    /// needs only a read lock on the session map.
    last_seen_ns: AtomicU64,
    /// **Registration keypair `X`** for the registration-delegation connect flow
    /// (see `crate::auth`). Minted once per connect, bound to this session (which
    /// is keyed by the connect `sid`); its private half NEVER leaves the backend.
    /// II certifies a short-lived, two-hop chain (`P_reg -> Y -> X`) whose final
    /// hop targets it, and the backend redeems it by signing an `mcp_register_v2`
    /// ingress AS `X` while presenting that chain. `None` until
    /// [`Identities::registration_pubkey_b64`] mints it. Distinct from the
    /// long-lived **session key `S`** (`key_seed`/`pubkey_der`), which is what
    /// `mcp_register_v2` registers.
    reg_key_seed: Option<[u8; 32]>,
    /// DER public key of the registration key `X` (mirrors `pubkey_der` for `S`).
    reg_pubkey_der: Option<Vec<u8>>,
    /// The session's access level from the `mcp_register_v2` reply's `permissions`
    /// field: `Some(true)` = read-only (`"queries"`), `Some(false)` = full
    /// (`"all"`), `None` = not yet learned. Update calls are rejected by the IC at
    /// ingress under a read-only session, so tools consult this to fail early with
    /// an actionable message.
    read_only: Option<bool>,
    /// `(domain, account_number)` -> most recently derived per-app delegation.
    /// Keyed by account too, since each account at an origin signs as a distinct
    /// principal (`account_number == None` is that origin's default account).
    app_delegations: HashMap<(String, Option<u64>), AppDelegation>,
}

/// A cached on-demand per-app account delegation. The chain ends at a per-app key
/// distinct from the session key; its seed is kept so the identity can be rebuilt.
struct AppDelegation {
    user_key: Vec<u8>,
    chain: Vec<SignedDelegation>,
    expiration_ns: u64,
    /// Ed25519 seed of the per-app key the delegation is issued to.
    app_key_seed: [u8; 32],
}

impl AppDelegation {
    /// Whether this cached delegation is still safe to reuse.
    fn fresh(&self) -> bool {
        self.expiration_ns > now_ns().saturating_add(REDERIVE_MARGIN_NS)
    }
}

/// One of the user's Internet Identity accounts at an app origin, as returned by
/// [`Identities::list_accounts`] (II's `mcp_get_accounts`). Each account is a
/// distinct per-origin principal; `account_number == None`/`name == None` selects
/// the anchor's current (user-controllable) default account at that origin.
pub struct AccountInfo {
    /// II account number — `None` for the origin's default account. Pass the
    /// account's `name` to the acting tools to use a non-default account; the
    /// server resolves it back to this number for the delegation.
    pub account_number: Option<u64>,
    /// User-given account name — `None` for the default account.
    pub name: Option<String>,
    /// When the account was last used (ns since the Unix epoch), if known.
    pub last_used: Option<u64>,
}

/// Arguments for `get_app_principal`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetPrincipalArgs {
    /// The app's derivation origin, from open_app or resolve_app. This is the origin Internet
    /// Identity derives the principal from, which is not always the app's website URL, and
    /// never an alternative-origins entry.
    #[serde(alias = "domain")]
    pub derivation_origin: String,
    /// Which of the user's accounts to resolve, by name (see list_app_accounts). Omit for the
    /// app's default account.
    #[serde(default)]
    pub account: Option<String>,
}

/// Structured output of `get_app_principal`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct PrincipalOutput {
    /// The effective Internet Identity derivation origin the principal was
    /// derived for (after canonicalization). Compare against `requested` to spot
    /// an origin mismatch.
    pub derived_for_origin: String,
    /// Exactly what you supplied as `derivation_origin`.
    pub requested: String,
    /// How `derived_for_origin` was determined.
    pub derivation_origin_source: String,
    /// The account name resolved, or null for the app's default account.
    pub account: Option<String>,
    /// The principal you act as at that app.
    pub principal: String,
    /// True if this session is query-only, so state-changing calls are rejected by the
    /// network. False also covers a session whose access level is not known.
    pub read_only: bool,
}

/// Arguments for `list_app_accounts`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListAccountsArgs {
    /// The app's derivation origin, from open_app or resolve_app. This is the origin Internet
    /// Identity derives the principal from, which is not always the app's website URL, and
    /// never an alternative-origins entry.
    #[serde(alias = "domain")]
    pub derivation_origin: String,
}

/// One account in the `list_app_accounts` MCP output.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AccountEntry {
    /// The user-given account name, or null for the default account.
    pub name: Option<String>,
    /// The II account number, or null for the default account.
    pub account_number: Option<u64>,
    /// When the account was last used (ns since the Unix epoch), if known.
    pub last_used: Option<u64>,
}

impl From<&AccountInfo> for AccountEntry {
    fn from(a: &AccountInfo) -> Self {
        Self {
            name: a.name.clone(),
            account_number: a.account_number,
            last_used: a.last_used,
        }
    }
}

/// Structured output of `list_app_accounts`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AccountsOutput {
    /// The effective Internet Identity derivation origin the accounts belong to.
    pub derived_for_origin: String,
    /// Exactly what you supplied as `derivation_origin`.
    pub requested: String,
    /// How `derived_for_origin` was determined.
    pub derivation_origin_source: String,
    /// The user's accounts at that origin (empty if none).
    pub accounts: Vec<AccountEntry>,
}

/// Arguments for `resolve_app`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ResolveAppArgs {
    /// The app's URL, e.g. "https://opencloud.org". When the derivation origin has to be
    /// assumed from this URL, an origin showing no sign of being an Internet Computer app is
    /// refused, so a lookalike domain does not resolve.
    pub app_url: String,
}

/// Structured output of `resolve_app`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ResolveAppOutput {
    /// The normalized application origin of `app_url`.
    pub application_origin: String,
    /// The Internet Identity derivation origin to use for this app — pass this
    /// as `derivation_origin` to the identity tools.
    pub derivation_origin: String,
    /// How `derivation_origin` was determined: "declared" (the app published it), "known"
    /// (from the built-in registry), or "app_url_default" (assumed to equal the app's own
    /// origin, correct only for apps that pin no custom one).
    pub derivation_origin_source: String,
    /// Origins that the resolved derivation origin permits to derive against it. This is the
    /// inverse relation, so the derivation origin does not follow from it. Read best-effort:
    /// an empty list means none were read.
    pub alternative_origins: Vec<String>,
    /// Whether the app's origin showed evidence of being served from the Internet Computer.
    /// Only probed when the derivation origin was assumed, and then always true, since an
    /// origin without that evidence is refused.
    pub application_is_ic: Option<bool>,
    /// A human note, e.g. flagging that the derivation origin was assumed.
    pub note: Option<String>,
}

#[derive(Clone)]
pub struct Identities {
    /// The II instance every session in this store is registered against.
    instance: IiInstance,
    /// This MCP server's own public origin — the `target_origin` the
    /// management identity is derived at (`target_origin()` reduces it to a
    /// bare origin either way). Injected by the embedding application, never
    /// read from the environment here.
    public_url: String,
    /// The injected base agent (see `McpConfig::agent`). Every identity-bearing
    /// agent is a clone of it with the identity swapped, so delegated and II
    /// calls inherit the host's boundary-node routing and transport.
    agent: Agent,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl Identities {
    pub fn new(instance: IiInstance, public_url: String, agent: Agent) -> Self {
        Self {
            instance,
            public_url,
            agent,
            sessions: Arc::default(),
        }
    }

    /// The injected base agent with `identity` swapped in: a clone shares the
    /// transport, route provider, and root key, so calls signed as `identity`
    /// go through the embedding application's boundary-node routing — never a
    /// second, hard-coded endpoint.
    pub(crate) fn agent_as<I: ic_agent::Identity + 'static>(&self, identity: I) -> Agent {
        let mut agent = self.agent.clone();
        agent.set_identity(identity);
        agent
    }

    /// The II instance this store connects against.
    pub fn instance(&self) -> &IiInstance {
        &self.instance
    }

    /// Create this session if it doesn't exist yet, enforcing the map's bounds
    /// on the way in (see [`make_room`]): stale entries are pruned, pending
    /// connects beyond [`MAX_PENDING_CONNECTS`] are evicted oldest-first, and a
    /// map already at [`MAX_SESSIONS`] live sessions refuses the new one with
    /// [`AT_CAPACITY_MSG`]. An EXISTING session is returned as-is, with no scan,
    /// so the authenticated hot path pays nothing.
    async fn ensure_session(&self, session_id: &str) -> Result<(), String> {
        let now = now_ns();
        let closed = {
            let mut sessions = self.sessions.write().await;
            if sessions.contains_key(session_id) {
                return Ok(());
            }
            let closed = make_room(&mut sessions, now)?;
            let (key_seed, pubkey_der) = fresh_ed25519();
            sessions.insert(
                session_id.to_string(),
                Session {
                    key_seed,
                    pubkey_der,
                    grant_expiration_ns: None,
                    created_ns: now,
                    last_seen_ns: AtomicU64::new(now),
                    reg_key_seed: None,
                    reg_pubkey_der: None,
                    read_only: None,
                    app_delegations: HashMap::new(),
                },
            );
            closed
        };
        // A grant that expired since the last sweep may have been reclaimed to
        // make room. Log it exactly as the reaper would (outside the lock), so
        // every "session opened" still gets its paired "session closed".
        for sid in &closed {
            tracing::info!(instance = self.instance.name, session_id = %sid, "session closed");
        }
        Ok(())
    }

    /// The backend session key seed and its DER pubkey.
    async fn session_key(&self, session_id: &str) -> Option<([u8; 32], Vec<u8>)> {
        let sessions = self.sessions.read().await;
        let s = sessions.get(session_id)?;
        Some((s.key_seed, s.pubkey_der.clone()))
    }

    /// Ensure a **registration key `X`** exists for this connect and return its
    /// public key (base64url, no pad, DER). This is what the connect link
    /// carries outbound to II (`pub(X)`); II certifies a two-hop chain
    /// `P_reg -> Y -> X` whose final hop targets it. `priv(X)` never leaves the
    /// backend — only this public half is
    /// ever exposed. Minting is idempotent per session, so the same `X` is used
    /// for the whole connect (a re-issued link reuses it). See
    /// [`Self::redeem_registration_delegation`] for the redemption that consumes
    /// `priv(X)`.
    ///
    /// Errors when the session map is at capacity ([`make_room`]) — the connect
    /// cannot be started, and `/oauth/authorize` surfaces that as a "try again in
    /// a moment" screen rather than handing II a key it isn't tracking.
    pub async fn registration_pubkey_b64(&self, session_id: &str) -> Result<String, String> {
        self.ensure_session(session_id).await?;
        let mut sessions = self.sessions.write().await;
        let s = sessions.get_mut(session_id).ok_or("no such session")?;
        if s.reg_key_seed.is_none() {
            let (seed, der) = fresh_ed25519();
            s.reg_key_seed = Some(seed);
            s.reg_pubkey_der = Some(der);
        }
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(s.reg_pubkey_der.as_ref().expect("just set")))
    }

    /// The session's principal (`self_authenticating(session_pubkey)`), the
    /// identity the II grant is bound to. Used for logging/attribution.
    pub async fn session_principal(&self, session_id: &str) -> Option<String> {
        let (_, der) = self.session_key(session_id).await?;
        Some(Principal::self_authenticating(&der).to_text())
    }

    /// Record the grant's expiration from the `mcp_register_v2` reply, at connect
    /// redemption. The value is nanoseconds since the epoch.
    pub async fn set_grant_expiration(&self, session_id: &str, expiration_ns: u64) {
        // Best effort: the redeem path ensured this session already, so a
        // capacity refusal here means it was reaped mid-flight — nothing to
        // record, and the client's next call gets the reconnect message.
        if let Err(e) = self.ensure_session(session_id).await {
            tracing::warn!(session_id = %session_id, "could not record the grant expiration: {e}");
            return;
        }
        // Read the clock once (before taking the lock), so the "was it live"
        // and "is it now live" checks use a single consistent instant and we
        // don't hold the write lock across a syscall.
        let now = now_ns();
        // Record whether this is a genuine not-live -> live transition inside the
        // lock, then log AFTER releasing it: a slow log sink must not stall other
        // readers/writers of the session map.
        let opened = {
            let mut sessions = self.sessions.write().await;
            match sessions.get_mut(session_id) {
                Some(s) => {
                    let was_live = s.grant_expiration_ns.is_some_and(|e| e > now);
                    s.grant_expiration_ns = Some(expiration_ns);
                    // Redeeming a grant is itself activity, so a freshly-opened
                    // session counts as active immediately (before its first tool
                    // call) on the `active_sessions` gauge.
                    s.last_seen_ns.store(now, Ordering::Relaxed);
                    !was_live && expiration_ns > now
                }
                None => false,
            }
        };
        // "session opened" pairs 1:1 with the reaper's "session closed", so the
        // two reconcile in the journal. A re-bind of an already-live grant (a
        // redeem retry within the delegation's lifetime) is not a new open.
        if opened {
            tracing::info!(
                instance = self.instance.name,
                session_id = %session_id,
                expiration_ns,
                "session opened"
            );
        }
    }

    /// Record the session's access level from the `mcp_register_v2` reply's
    /// `permissions` field: `"queries"` = read-only, `"all"` = full access (both
    /// case-insensitive). Any UNRECOGNIZED value leaves the level `None` (unknown)
    /// rather than assuming full access — so an unexpected/future value falls
    /// through to the ingress rejection fallback instead of the server wrongly
    /// considering the session writable.
    pub async fn set_permissions(&self, session_id: &str, permissions: &str) {
        let level = match permissions.trim().to_ascii_lowercase().as_str() {
            "queries" => Some(true),
            "all" => Some(false),
            other => {
                tracing::warn!("mcp_register_v2 reply had unrecognized permissions {other:?}; access level left unknown");
                return;
            }
        };
        // Same best-effort posture as `set_grant_expiration`: recorded on the
        // session the redeem path already created, or dropped with a warning.
        if let Err(e) = self.ensure_session(session_id).await {
            tracing::warn!(session_id = %session_id, "could not record the access level: {e}");
            return;
        }
        let mut sessions = self.sessions.write().await;
        if let Some(s) = sessions.get_mut(session_id) {
            s.read_only = level;
        }
    }

    /// The session's recorded grant expiration (ns since the epoch), if known —
    /// set authoritatively from the `mcp_register_v2` reply at connect redemption.
    /// Used to bound the OAuth access-token lifetime so a token never outlives the
    /// grant.
    pub async fn grant_expiration_ns(&self, session_id: &str) -> Option<u64> {
        self.sessions.read().await.get(session_id).and_then(|s| s.grant_expiration_ns)
    }

    /// Record that `session_id` just made an authenticated request, refreshing
    /// its activity window for the `/version` `active_sessions` gauge. Read-lock
    /// only: `last_seen_ns` is atomic, so this stays cheap on the per-request hot
    /// path. A no-op for an unknown session — this never creates one
    /// (`ensure_session` does that on the connect path).
    pub async fn touch_session(&self, session_id: &str) {
        // Read the clock BEFORE taking the lock: even a read lock blocks writers
        // (set_grant_expiration, the reaper), so keep the syscall off the lock on
        // this per-request hot path.
        let now = now_ns();
        let sessions = self.sessions.read().await;
        if let Some(s) = sessions.get(session_id) {
            s.last_seen_ns.store(now, Ordering::Relaxed);
        }
    }

    /// Both `/version` session gauges from a SINGLE lock + iteration:
    ///
    /// - **`live`**: sessions holding a currently-valid grant
    ///   (`grant_expiration_ns` in the future). Tracks the GRANT lifecycle — a
    ///   session counts from the moment its grant is redeemed ("session opened")
    ///   until it expires, no matter how long it sits quiet in between (an ongoing
    ///   MCP session is often idle between tool calls, and is still live the whole
    ///   time). The flip side: MCP runs statelessly here, so a client that
    ///   disconnects for good produces no server-side event and keeps counting
    ///   until its grant expires. Sessions mid-connect, and v1 sessions whose
    ///   completion POST never delivered an expiry (`None`), are not counted.
    ///   Brackets the "session opened"/"session closed" lifecycle logs modulo the
    ///   reaper's cadence: the count drops the instant a grant expires, whereas
    ///   the paired "closed" log lands on the reaper's next sweep (up to 60s
    ///   later), so `opened - closed` can momentarily exceed `live` by the
    ///   sessions expired since that last sweep.
    /// - **`active`**: the subset of `live` also seen making a request within
    ///   [`ACTIVE_SESSION_WINDOW_NS`] — a ballpark of who is working right now, so
    ///   a redeploy (which wipes the in-memory session/token maps and forces every
    ///   connected client to reconnect) can be timed for a quiet moment. Being
    ///   activity-based, it's a point-in-time reading; sample it over time (or read
    ///   request rate from the logs) to find a low-traffic window.
    ///
    /// Computing both in one pass keeps `/version` scrapes O(N) rather than 2·O(N)
    /// and, because both come from the same locked snapshot, guarantees the
    /// reported pair is consistent (`active <= live`) — two separate reads could
    /// straddle a grant expiry and momentarily report `active > live`. A cheap
    /// read-lock snapshot.
    pub async fn session_gauges(&self) -> SessionGauges {
        let now = now_ns();
        let sessions = self.sessions.read().await;
        let mut g = SessionGauges { live: 0, active: 0 };
        for s in sessions.values() {
            if s.grant_expiration_ns.is_some_and(|e| e > now) {
                g.live += 1;
                if now.saturating_sub(s.last_seen_ns.load(Ordering::Relaxed))
                    <= ACTIVE_SESSION_WINDOW_NS
                {
                    g.active += 1;
                }
            }
        }
        g
    }

    /// Single-gauge test conveniences over [`Self::session_gauges`] (which is what
    /// `/version` uses — it needs both counts, so production has no caller for
    /// these). Kept test-only so the non-test build doesn't flag them as dead.
    #[cfg(test)]
    pub async fn live_session_count(&self) -> usize {
        self.session_gauges().await.live
    }

    #[cfg(test)]
    pub async fn active_session_count(&self) -> usize {
        self.session_gauges().await.active
    }

    /// Evict every session that no longer serves anyone ([`prune_stale`]) and
    /// return how many went:
    ///
    ///   * grant EXPIRED — the same criterion as the live gauge, emitting a
    ///     "session closed" log per eviction so the journal has a
    ///     grant-lifecycle close event to pair with "session opened". A merely
    ///     idle (but still valid) session is KEPT: its token is still good, the
    ///     client may return and reuse it, and it still counts as live meanwhile.
    ///   * connect ABANDONED — a session that never redeemed a grant, older than
    ///     [`PENDING_CONNECT_TTL_NS`]. `/oauth/authorize` mints one of these per
    ///     request without authentication, so leaving them forever made the map
    ///     grow without bound (CWE-770); by that age the connect can no longer be
    ///     redeemed anyway. A YOUNGER pending session is kept — it is a sign-in in
    ///     progress, and evicting it would strand the registration key `X` II may
    ///     already have certified.
    ///
    /// Together with the admission bounds in [`make_room`] (which cap the map
    /// between sweeps) this is what keeps the session map bounded. Called on a
    /// timer from `McpServer::spawn_session_reaper`.
    pub async fn reap_expired_sessions(&self) -> usize {
        let now = now_ns();
        // Scope the write lock to the mutation only: release it BEFORE logging so
        // a slow log sink can't block other readers/writers of the session map.
        let (closed, abandoned) = {
            let mut sessions = self.sessions.write().await;
            prune_stale(&mut sessions, now)
        };
        for sid in &closed {
            tracing::info!(instance = self.instance.name, session_id = %sid, "session closed");
        }
        // Abandoned connects never opened a session, so they get no paired
        // "closed" line — one aggregate count keeps the journal readable under a
        // flood while still showing the sweep did something.
        if !abandoned.is_empty() {
            tracing::info!(
                instance = self.instance.name,
                count = abandoned.len(),
                "abandoned connects reaped"
            );
        }
        closed.len() + abandoned.len()
    }

    /// This session's known access level: `Some(true)` = read-only, `Some(false)`
    /// = full, `None` = not yet learned (the best-effort completion POST didn't
    /// arrive). Surfaced by `get_app_principal` so the agent can set expectations.
    pub async fn is_read_only(&self, session_id: &str) -> Option<bool> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).and_then(|s| s.read_only)
    }

    /// Guard a tool that needs update (write) access (H2): error early with an
    /// actionable "reconnect under Actions & questions" message if the session is
    /// KNOWN to be query-only. An unknown level (`None`) passes — we can't be sure the
    /// POST simply didn't arrive, so the call proceeds and the IC's ingress
    /// rejection (if any) surfaces as the fallback signal.
    pub async fn require_write(&self, session_id: &str) -> Result<(), String> {
        if self.is_read_only(session_id).await == Some(true) {
            return Err(READ_ONLY_MSG.to_string());
        }
        Ok(())
    }

    /// Build the plain session-key identity (`BasicIdentity`) the server signs
    /// II's `mcp_*` calls with. Errors early if the stored grant expiration has
    /// passed (a missing expiration is not treated as expired — the spec says to
    /// fall back to attempting the signed call, where an `Unauthorized` is the
    /// authoritative signal).
    async fn session_signer(&self, session_id: &str) -> Result<BasicIdentity, String> {
        self.ensure_session(session_id).await?;
        let sessions = self.sessions.read().await;
        let s = sessions.get(session_id).ok_or("no such session")?;
        if let Some(exp) = s.grant_expiration_ns {
            if exp <= now_ns() {
                return Err(RECONNECT_MSG.to_string());
            }
        }
        Ok(BasicIdentity::from_raw_key(&s.key_seed))
    }

    /// An `ic-agent` pointed at mainnet II, signing as this connection's session
    /// key. This is the caller II recovers the anchor from for the `mcp_*` calls.
    async fn session_agent(&self, session_id: &str) -> Result<Agent, String> {
        let signer = self.session_signer(session_id).await?;
        Ok(self.agent_as(signer))
    }

    /// A stable per-user identity for the canister-management tools — the user's
    /// default account at *this* MCP server's own origin, derived on demand like
    /// any other app. Its principal (`self_authenticating(user_key)`) is stable
    /// across reconnects (unlike the ephemeral session key), so it works as the
    /// user's controller/funder identity.
    pub async fn management_identity(&self, session_id: &str) -> Result<DelegatedIdentity, String> {
        let origin = self.public_url.clone();
        self.delegated_identity(session_id, &origin, None).await
    }

    /// List the user's Internet Identity accounts at an app `domain`, via II's
    /// `mcp_get_accounts(target_origin)` signed as the session key. II recovers
    /// the anchor from the caller (the registered session-key principal), so no
    /// anchor number is needed. Every user has a default account (`account_number
    /// == None`, no name) at any origin — the anchor's current, user-controllable
    /// default there — plus any named accounts they created; each is a distinct
    /// per-origin principal.
    pub async fn list_accounts(
        &self,
        session_id: &str,
        domain: &str,
    ) -> Result<Vec<AccountInfo>, String> {
        let agent = self.session_agent(session_id).await?;
        let canister = self.instance.ii_canister;
        let origin = target_origin(domain);

        // mcp_get_accounts(target_origin) -> variant { Ok: vec AccountInfo; Err }
        // A signed query: II recovers the anchor from the caller (the session key)
        // and returns that anchor's accounts at `target_origin`.
        let arg = Encode!(&origin).map_err(|e| format!("could not encode mcp_get_accounts args: {e}"))?;
        let reply = agent
            .query(&canister, "mcp_get_accounts")
            .with_arg(arg)
            .call()
            .await
            .map_err(|e| format!("mcp_get_accounts failed: {e}"))?;
        let accounts = Decode!(&reply, McpGetAccountsReply)
            .map_err(|e| format!("could not decode mcp_get_accounts reply: {e}"))?
            .map_err(map_delegation_error)?;

        Ok(accounts
            .into_iter()
            .map(|a| AccountInfo {
                account_number: a.account_number,
                name: a.name,
                last_used: a.last_used,
            })
            .collect())
    }

    /// **Redeem a registration delegation.** Given the TWO-hop chain
    /// `P_reg -> Y -> X` that II delivered to the pinned callback (decoded by
    /// `crate::auth` into `reg_user_key = der(P_reg)` and `chain`; `Y` is an
    /// ephemeral key held only by II's frontend — the canister-signed hop
    /// targets it so the piece that transits the IC is inert on its own, and
    /// the browser-signed `Y -> X` hop completes the chain only in the
    /// consenting browser), build a `DelegatedIdentity` from `priv(X)` + that
    /// chain and make ONE authenticated `mcp_register_v2(session_key)` update.
    /// **Consent is captured earlier, not echoed here** (merged II contract):
    /// the access level and lifetime were chosen at consent and passed to II's
    /// `prepare_mcp_registration_delegation`, which stores them server-side on an
    /// index entry keyed by `P_reg`. So `mcp_register_v2` takes ONLY `session_key`
    /// (= `pub(S)`): II recovers the anchor from `caller() == P_reg`, reads the
    /// consent it already stored under that key, and binds the session. The
    /// server can neither send nor alter the anchor, permissions, or TTL.
    /// Crucially, **we never send or see the anchor**: II recovers the user's
    /// identity number itself. On `Ok` II binds this session's long-lived key `S`
    /// to the anchor (replacing any previous grant for that identity) and
    /// returns `{expiration, permissions}`; we record both, so the grant-expiry
    /// check and the read-only guard have what they need. Within its 5-minute
    /// lifetime the delegation redeems repeatedly (a retry with the same `S` just
    /// re-binds it), so boundary timeouts are retry-safe.
    ///
    /// > **Verified against deployed beta II.** The `mcp_register_v2` argument
    /// > and return candid match the beta II canister's live `.did`
    /// > (`fgte5-ciaaa-aaaad-aaatq-cai`): one `session_key : blob` in, and
    /// > `variant { Ok : record { expiration; permissions }; Err : text }` out
    /// > (decoded as [`McpRegisterV2Reply`]; [`McpRegisterV2Ok`] is the `Ok`
    /// > payload). Re-verify the shapes if II's `.did` ever moves; the read-only
    /// > `opt text`/`variant` outage (#40) is the standing lesson against drift.
    pub async fn redeem_registration_delegation(
        &self,
        session_id: &str,
        reg_user_key: Vec<u8>,
        chain: Vec<SignedDelegation>,
    ) -> Result<RegistrationOutcome, String> {
        self.ensure_session(session_id).await?;

        // priv(X) to sign the ingress as, and pub(S) to register.
        let (reg_seed, reg_der, session_der) = {
            let sessions = self.sessions.read().await;
            let s = sessions.get(session_id).ok_or("no such session")?;
            let reg_seed = s
                .reg_key_seed
                .ok_or("no registration key was minted for this connect")?;
            let reg_der = s
                .reg_pubkey_der
                .clone()
                .ok_or("no registration key was minted for this connect")?;
            (reg_seed, reg_der, s.pubkey_der.clone())
        };

        // Sign `mcp_register_v2` AS X, presenting the `P_reg -> Y -> X` chain.
        // `reg_user_key` is `der(P_reg)`: the chain root II recovers `caller() ==
        // P_reg` from.
        // Verify the delivered chain against the injected agent's root key (the
        // network we are about to make the `mcp_register_v2` call to), not a
        // hard-coded mainnet key — so a host pointed at a non-mainnet IC verifies
        // and signs against the same trust anchor. In production the agent is
        // mainnet, so this is the mainnet root.
        let identity =
            registration_identity(reg_user_key, reg_seed, &reg_der, chain, &self.agent.read_root_key())?;
        let agent = self.agent_as(identity);

        // mcp_register_v2(session_key) -> variant { Ok : McpRegisterV2Ok; Err : text }
        // The ONLY argument is `session_key` (= `pub(S)`). Consent (permissions,
        // max_ttl) and the anchor are NOT sent: II stored the consent at
        // `prepare_mcp_registration_delegation` keyed by `P_reg`, and recovers
        // both it and the anchor from `caller() == P_reg`, so the server never
        // handles the user's identity number or their chosen access level.
        let arg = Encode!(&session_der)
            .map_err(|e| format!("could not encode mcp_register_v2 args: {e}"))?;
        let reply = agent
            .update(&self.instance.ii_canister, "mcp_register_v2")
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(|e| format!("mcp_register_v2 failed: {e}"))?;
        let outcome = Decode!(&reply, McpRegisterV2Reply)
            .map_err(|e| format!("could not decode mcp_register_v2 reply: {e}"))?
            .map_err(|e| format!("Internet Identity rejected registration: {e}"))?;

        // Record expiry + access level so the signer's expiry check and the
        // read-only guard have what they need.
        let permissions = outcome.permissions.as_text();
        self.set_grant_expiration(session_id, outcome.expiration).await;
        self.set_permissions(session_id, permissions).await;
        Ok(RegistrationOutcome {
            expiration_ns: outcome.expiration,
            permissions,
        })
    }

    /// Resolve an optional account `name` at `domain` to its account number
    /// (`None` = the default account, used when `name` is `None`). Looks the name
    /// up via [`Self::list_accounts`]; errors if no account (or more than one) at
    /// the origin carries that name.
    async fn resolve_account(
        &self,
        session_id: &str,
        domain: &str,
        name: Option<&str>,
    ) -> Result<Option<u64>, String> {
        let Some(name) = name else {
            return Ok(None); // the anchor's current (user-controllable) default account
        };
        let accounts = self.list_accounts(session_id, domain).await?;
        let mut matching = accounts.iter().filter(|a| a.name.as_deref() == Some(name));
        match (matching.next(), matching.next()) {
            (None, _) => Err(format!(
                "no account named \"{name}\" at {domain} — call `list_app_accounts` (with this app's \
                 `derivation_origin` or `app_url`) to see your accounts there, or omit `account` to \
                 use the default one"
            )),
            (Some(a), None) => Ok(a.account_number),
            (Some(_), Some(_)) => Err(format!(
                "more than one account named \"{name}\" at {domain}; cannot disambiguate"
            )),
        }
    }

    /// Build the `ic-agent` identity for the account named `account` at `domain`
    /// (omit `account` for the default account). The account name is resolved to
    /// its II account number, then the per-app delegation is derived/cached.
    pub async fn delegated_identity_for(
        &self,
        session_id: &str,
        domain: &str,
        account: Option<&str>,
    ) -> Result<DelegatedIdentity, String> {
        let account_number = self.resolve_account(session_id, domain, account).await?;
        self.delegated_identity(session_id, domain, account_number).await
    }

    /// Build the `ic-agent` identity for a domain + account number, deriving the
    /// per-app account delegation on demand (and caching it) if there is no fresh
    /// cached one. `account_number == None` is the origin's default account.
    pub async fn delegated_identity(
        &self,
        session_id: &str,
        domain: &str,
        account_number: Option<u64>,
    ) -> Result<DelegatedIdentity, String> {
        self.ensure_session(session_id).await?;

        // Reuse a cached, still-fresh delegation if present.
        if let Some(app) = self.cached_fresh(session_id, domain, account_number).await {
            return build_identity(&app);
        }

        // Otherwise derive a fresh one on demand against the II canister.
        let app = self.derive_app_delegation(session_id, domain, account_number).await?;
        let identity = build_identity(&app)?;
        self.store(session_id, domain, account_number, app).await;
        Ok(identity)
    }

    async fn cached_fresh(
        &self,
        session_id: &str,
        domain: &str,
        account_number: Option<u64>,
    ) -> Option<AppDelegation> {
        let sessions = self.sessions.read().await;
        let app = sessions
            .get(session_id)?
            .app_delegations
            .get(&(domain.to_string(), account_number))?;
        if !app.fresh() {
            return None;
        }
        Some(AppDelegation {
            user_key: app.user_key.clone(),
            chain: app.chain.clone(),
            expiration_ns: app.expiration_ns,
            app_key_seed: app.app_key_seed,
        })
    }

    async fn store(&self, session_id: &str, domain: &str, account_number: Option<u64>, app: AppDelegation) {
        let mut sessions = self.sessions.write().await;
        if let Some(s) = sessions.get_mut(session_id) {
            let key = (domain.to_string(), account_number);
            // Bound the per-session cache before growing it. Only a NEW key can
            // grow the map — refreshing an existing origin/account just replaces
            // its entry, so it needs no room made.
            if !s.app_delegations.contains_key(&key) {
                bound_app_delegations(&mut s.app_delegations);
            }
            s.app_delegations.insert(key, app);
        }
    }

    /// Derive a fresh per-app account delegation by calling II's
    /// `mcp_prepare_delegation` then `mcp_get_delegation`, SIGNED AS the session
    /// key, passing a fresh **per-app key** as the `session_key` argument.
    /// `account_number == None` selects the origin's default account.
    async fn derive_app_delegation(
        &self,
        session_id: &str,
        domain: &str,
        account_number: Option<u64>,
    ) -> Result<AppDelegation, String> {
        let origin = target_origin(domain);
        let canister = self.instance.ii_canister;

        // The per-app key B the delegation is issued to — distinct from the
        // session key. Its DER pubkey is the `session_key` argument to
        // prepare/get; the returned chain ends at B, so the server signs canister
        // calls at the app as B via a DelegatedIdentity over [user_key -> B].
        let (app_key_seed, app_key_der) = fresh_ed25519();

        // Call II SIGNED AS the session key (the registered grant principal) —
        // that's the caller II recovers the anchor from.
        let agent = self.session_agent(session_id).await?;

        // mcp_prepare_delegation(target_origin, opt account_number, session_key, opt max_ttl)
        //   -> variant { Ok: McpPrepareDelegation; Err: AccountDelegationError }
        // `session_key` is the PER-APP key's DER pubkey. `max_ttl = null` uses
        // II's default (<= 1 hour, and never past the grant). `account_number =
        // null` selects the anchor's default account at `target_origin`; `Some(n)`
        // selects a specific named account. The default is mutable, so II resolves
        // the request to a concrete account at prepare time and returns it; we
        // thread that resolved account into `mcp_get_delegation` so `get` reads the
        // same account `prepare` signed for.
        let prepare_arg = Encode!(&origin, &account_number, &app_key_der, &None::<u64>)
            .map_err(|e| format!("could not encode prepare args: {e}"))?;
        let prepared = agent
            .update(&canister, "mcp_prepare_delegation")
            .with_arg(prepare_arg)
            .call_and_wait()
            .await
            .map_err(|e| format!("mcp_prepare_delegation failed: {e}"))?;
        let prepared = Decode!(&prepared, PrepareReply)
            .map_err(|e| format!("could not decode prepare reply: {e}"))?
            .map_err(map_delegation_error)?;

        // mcp_get_delegation(target_origin, opt account_number, session_key, expiration)
        //   -> variant { Ok: SignedDelegation; Err: AccountDelegationError } query
        // Thread the account + expiration `prepare` returned VERBATIM, or II
        // returns NoSuchDelegation (the default account is mutable between calls).
        let get_arg = Encode!(&origin, &prepared.account_number, &app_key_der, &prepared.expiration)
            .map_err(|e| format!("could not encode get args: {e}"))?;
        let got = agent
            .query(&canister, "mcp_get_delegation")
            .with_arg(get_arg)
            .call()
            .await
            .map_err(|e| format!("mcp_get_delegation failed: {e}"))?;
        let signed = Decode!(&got, GetReply)
            .map_err(|e| format!("could not decode get reply: {e}"))?
            .map_err(map_delegation_error)?;

        let chain = vec![signed.into_agent(&app_key_der)?];
        Ok(AppDelegation {
            user_key: prepared.user_key,
            chain,
            expiration_ns: prepared.expiration,
            app_key_seed,
        })
    }
}

/// Drop every session that no longer serves anyone, returning the ids of each
/// kind so the caller can log them: sessions whose grant has EXPIRED (paired
/// with the "session opened" log by a "session closed" one), and ABANDONED
/// connects — sessions that never redeemed a grant and are older than
/// [`PENDING_CONNECT_TTL_NS`], long past the point where their connect could
/// still be redeemed. A pending connect younger than that is kept: it is a
/// sign-in in progress, and evicting it would strand the registration key `X`
/// that II may already have certified.
fn prune_stale(sessions: &mut HashMap<String, Session>, now: u64) -> (Vec<String>, Vec<String>) {
    let (mut closed, mut abandoned) = (Vec::new(), Vec::new());
    sessions.retain(|sid, s| match s.grant_expiration_ns {
        Some(exp) if exp <= now => {
            closed.push(sid.clone());
            false
        }
        None if now.saturating_sub(s.created_ns) >= PENDING_CONNECT_TTL_NS => {
            abandoned.push(sid.clone());
            false
        }
        _ => true,
    });
    (closed, abandoned)
}

/// Make room for one more session, bounding the map (CWE-770) without stalling
/// the common case: below [`MAX_PENDING_CONNECTS`] entries nothing is scanned at
/// all. Above it, stale entries go first ([`prune_stale`]), then — since
/// `/oauth/authorize` is unauthenticated and mints one session per request — the
/// oldest PENDING connects are evicted down to the cap. A live grant is never
/// evicted: if that leaves the map at [`MAX_SESSIONS`], the new session is
/// refused ([`AT_CAPACITY_MSG`]) rather than logging an authenticated user out.
///
/// Returns the ids of any EXPIRED-grant sessions it closed on the way, so the
/// caller can emit the same "session closed" log the reaper does — otherwise a
/// session closed here would leave its "session opened" without a pair. Pending
/// connects evicted to make room get no log line: they never opened a session.
fn make_room(sessions: &mut HashMap<String, Session>, now: u64) -> Result<Vec<String>, String> {
    if sessions.len() < MAX_PENDING_CONNECTS {
        return Ok(Vec::new());
    }
    let (closed, _abandoned) = prune_stale(sessions, now);
    let mut pending: Vec<(u64, String)> = sessions
        .iter()
        .filter(|(_, s)| s.grant_expiration_ns.is_none())
        .map(|(sid, s)| (s.created_ns, sid.clone()))
        .collect();
    // Leave room for the caller's own entry: evict down to cap - 1.
    if pending.len() >= MAX_PENDING_CONNECTS {
        pending.sort_unstable(); // oldest first
        let excess = pending.len() + 1 - MAX_PENDING_CONNECTS;
        for (_, sid) in pending.into_iter().take(excess) {
            sessions.remove(&sid);
        }
    }
    if sessions.len() >= MAX_SESSIONS {
        return Err(AT_CAPACITY_MSG.to_string());
    }
    Ok(closed)
}

/// Make room for one more cached per-app delegation, bounding a single session's
/// cache at [`MAX_APP_DELEGATIONS`] (a session picks its own `(origin, account)`
/// keys, so the map is caller-driven). Entries too close to expiry to be reused
/// go first — they would be re-derived anyway ([`AppDelegation::fresh`]) — then,
/// if the cache is still full, the entry nearest expiry.
fn bound_app_delegations(cache: &mut HashMap<(String, Option<u64>), AppDelegation>) {
    if cache.len() < MAX_APP_DELEGATIONS {
        return;
    }
    cache.retain(|_, a| a.fresh());
    while cache.len() >= MAX_APP_DELEGATIONS {
        let Some(victim) = cache
            .iter()
            .min_by_key(|(_, a)| a.expiration_ns)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        cache.remove(&victim);
    }
}

/// Generate a fresh Ed25519 keypair; return its seed and DER SubjectPublicKeyInfo.
fn fresh_ed25519() -> ([u8; 32], Vec<u8>) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom");
    let pubkey_der = BasicIdentity::from_raw_key(&seed)
        .public_key()
        .expect("ed25519 public key");
    (seed, pubkey_der)
}

/// Build a `DelegatedIdentity` for a derived app delegation: the chain ends at
/// the per-app key, so a `BasicIdentity` over that key's seed signs.
fn build_identity(app: &AppDelegation) -> Result<DelegatedIdentity, String> {
    let key = BasicIdentity::from_raw_key(&app.app_key_seed);
    DelegatedIdentity::new(app.user_key.clone(), Box::new(key), app.chain.clone())
        .map_err(|e| format!("invalid delegation chain: {e}"))
}

/// Build the identity that redeems a registration delegation: `priv(X)` signing
/// at the end of the delivered `P_reg -> Y -> X` chain, with `der(P_reg)` as
/// the chain root. Guards locally that the chain is non-empty and its FINAL hop
/// delegates to this connect's `X` — the only key we hold the private half of,
/// so a chain toward any other key is rejected before signing anything. Length
/// is otherwise not constrained here.
///
/// The chain is verified at construction by
/// [`DelegatedIdentity::new_with_root_key`] against `root_key` — the **injected
/// agent's** root key (`Agent::read_root_key`), which is the IC mainnet key in
/// production and whatever the agent targets otherwise (e.g. a local replica's
/// key after `fetch_root_key`). Using the agent's own trust anchor — rather than
/// hard-coding mainnet via [`DelegatedIdentity::new`] — keeps chain verification
/// consistent with the network the `mcp_register_v2` call itself goes to: the
/// canister signature on `P_reg -> Y` is BLS-verified against that root, and the
/// `Y -> X` hop against `Y`. The replica re-verifies every hop at redemption.
fn registration_identity(
    reg_user_key: Vec<u8>,
    reg_seed: [u8; 32],
    reg_der: &[u8],
    chain: Vec<SignedDelegation>,
    root_key: &[u8],
) -> Result<DelegatedIdentity, String> {
    match chain.last() {
        Some(last) if last.delegation.pubkey == reg_der => {}
        Some(_) => {
            return Err("registration delegation does not delegate to this connect's \
                        registration key"
                .to_string())
        }
        None => return Err("registration delegation chain is empty".to_string()),
    }
    DelegatedIdentity::new_with_root_key(
        reg_user_key,
        Box::new(BasicIdentity::from_raw_key(&reg_seed)),
        chain,
        root_key,
    )
    .map_err(|e| format!("invalid registration delegation chain: {e}"))
}

/// Render an `AccountDelegationError` as an actionable message. Any `Unauthorized`
/// means the grant is gone → reconnect (do not retry).
fn map_delegation_error(e: AccountDelegationError) -> String {
    match e {
        AccountDelegationError::Unauthorized(_) => RECONNECT_MSG.to_string(),
        AccountDelegationError::NoSuchDelegation => {
            "Internet Identity returned NoSuchDelegation — the prepared account/expiration were not \
             threaded through. Retry the request."
                .to_string()
        }
        AccountDelegationError::InternalCanisterError(t) => {
            format!("Internet Identity internal error: {t}")
        }
    }
}

/// Outcome of a successful [`Identities::redeem_registration_delegation`] —
/// what II returned from `mcp_register_v2`. Surfaced to the connect handler so
/// it can log the access level; the values are also recorded on the session.
#[derive(Debug)]
pub struct RegistrationOutcome {
    /// Grant expiration (ns since the Unix epoch).
    pub expiration_ns: u64,
    /// The recorded access level, in the delegation vocabulary: `"queries"` =
    /// read-only, `"all"` = full (always present — `McpRegistrationV2`'s
    /// `permissions` is non-optional).
    pub permissions: &'static str,
}

// ---- II candid contract for the mcp_* delegation methods --------------------

/// `Ok` payload of `mcp_prepare_delegation` (II `McpPrepareDelegation`).
#[derive(CandidType, Deserialize)]
struct PreparedDelegation {
    user_key: Vec<u8>,
    /// The account II resolved the request to (`opt AccountNumber`, `null` =
    /// the default account at `target_origin`). Threaded back into
    /// `mcp_get_delegation` so both calls sign for the same account.
    account_number: Option<u64>,
    expiration: u64,
}

/// II's `AccountDelegationError` — the `Err` arm of the delegation methods. We
/// only need to decode and act on it.
#[derive(CandidType, Deserialize, Debug)]
enum AccountDelegationError {
    InternalCanisterError(String),
    Unauthorized(Principal),
    NoSuchDelegation,
}

// The methods return `variant { Ok; Err }`, i.e. a Rust `Result`. Aliased so the
// `Decode!` macro doesn't choke on the comma inside the generic.
type PrepareReply = std::result::Result<PreparedDelegation, AccountDelegationError>;
type GetReply = std::result::Result<IiSignedDelegation, AccountDelegationError>;
type McpGetAccountsReply = std::result::Result<Vec<IiAccountInfo>, AccountDelegationError>;

/// II's named `Permissions` type: `variant { queries; all }`. Distinct from the
/// `Delegation` RECORD's `permissions : opt text` field (see
/// [`IiDelegation::permissions`] and the #40 outage): the named type is a real
/// candid variant, carried by `mcp_register_v2`'s reply (`McpRegistrationV2`) to
/// report the access level the user chose at consent. Decoded as a variant here;
/// this is NOT the opt-text case, because the field it appears in is not
/// `opt text`. The server no longer sends this value: consent is captured by
/// II's frontend at `prepare_mcp_registration_delegation` and recovered
/// server-side, so `mcp_register_v2` takes only `session_key`.
#[derive(CandidType, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IiPermissions {
    #[serde(rename = "queries")]
    Queries,
    #[serde(rename = "all")]
    All,
}

impl IiPermissions {
    /// The delegation-vocabulary text for this level ("queries"/"all"), as
    /// consumed by [`Identities::set_permissions`].
    fn as_text(&self) -> &'static str {
        match self {
            IiPermissions::Queries => "queries",
            IiPermissions::All => "all",
        }
    }
}

/// `Ok` payload of `mcp_register_v2` (Phase 2), `McpRegistrationV2`, matching
/// the beta II canister's live `.did` (`fgte5-ciaaa-aaaad-aaatq-cai`):
/// `record { expiration : Timestamp; permissions : Permissions }`. Re-verify
/// against II's published `.did` if the shape ever moves. See
/// [`Identities::redeem_registration_delegation`].
#[derive(CandidType, Deserialize)]
struct McpRegisterV2Ok {
    /// Grant expiration (ns since the Unix epoch).
    expiration: u64,
    /// The access level II confirms for the grant (the level chosen at consent,
    /// which II recovered from the consent it stored under `P_reg`): a
    /// NON-optional named variant, unlike the delegation record's `opt text`.
    permissions: IiPermissions,
}
/// `mcp_register_v2`'s reply — a `variant { Ok; Err : text }`, aliased so the
/// `Decode!` macro doesn't choke on the comma inside the generic.
type McpRegisterV2Reply = std::result::Result<McpRegisterV2Ok, String>;

/// One of an anchor's accounts at an origin (II `AccountInfo`). Decoded by name,
/// so field order is irrelevant and the wire record's `origin` field is skipped
/// (we already know the origin we queried).
#[derive(CandidType, Deserialize)]
struct IiAccountInfo {
    account_number: Option<u64>,
    last_used: Option<u64>,
    name: Option<String>,
}

/// One delegation as returned by II's `mcp_get_delegation`.
#[derive(CandidType, Deserialize)]
struct IiDelegation {
    pubkey: Vec<u8>,
    expiration: u64,
    targets: Option<Vec<Principal>>,
    /// Which request kinds this delegation authorizes — II's per-MCP-session
    /// access. On the wire this is **`opt text`** ("queries" = read-only,
    /// "all"/absent = unrestricted), NOT the `variant { queries; all }` named type
    /// that also appears in II's `.did`. It MUST be decoded as `text`: because the
    /// field is `opt`, decoding it as any other type triggers Candid's
    /// opt-mismatch rule and silently drops it to `None`. That would then omit it
    /// from the delegation we present, and the canister signature — which covers
    /// this field — would no longer verify ("sig not found in the signature
    /// tree"), breaking every read-only session. It is part of what II signs, so
    /// it must be carried verbatim.
    permissions: Option<String>,
}

/// Map II's on-the-wire permission (`opt text`) into `ic-agent`'s
/// `DelegationPermissions`, which re-serializes to the same `"queries"`/`"all"`
/// text so the reconstructed delegation hashes to exactly what II signed.
///
/// - **Absent** (`None`) → `None` (unrestricted; hashes like a pre-permissions
///   delegation).
/// - **`"queries"` / `"all"`** → the matching variant.
/// - **Present but unrecognized** → a hard error. The closed `DelegationPermissions`
///   enum can't represent a new value, and since the canister signature COVERS
///   this field, neither dropping nor guessing it could ever verify — it would
///   resurface the same opaque "sig not found in the signature tree" replica
///   error. Failing fast surfaces the real cause and forces a server update
///   instead of silently regressing.
pub(crate) fn permissions_from_text(permissions: Option<&str>) -> Result<Option<DelegationPermissions>, String> {
    match permissions {
        None => Ok(None),
        Some("queries") => Ok(Some(DelegationPermissions::Queries)),
        Some("all") => Ok(Some(DelegationPermissions::All)),
        Some(other) => Err(format!(
            "Internet Identity issued a delegation with an unrecognized permission {other:?}; \
             this server can't represent it faithfully, so the delegation's signature would not \
             verify. The server needs updating to handle this permission."
        )),
    }
}

/// `SignedDelegation` as returned by II's `mcp_get_delegation`.
#[derive(CandidType, Deserialize)]
struct IiSignedDelegation {
    delegation: IiDelegation,
    signature: Vec<u8>,
}

impl IiSignedDelegation {
    /// Convert into `ic-agent`'s `SignedDelegation`, checking that the delegation
    /// actually targets the per-app key (so the chain ends where we can sign).
    fn into_agent(self, app_key_der: &[u8]) -> Result<SignedDelegation, String> {
        if self.delegation.pubkey != app_key_der {
            return Err("II delegation does not delegate to this app's per-app key".to_string());
        }
        Ok(SignedDelegation {
            delegation: Delegation {
                pubkey: self.delegation.pubkey,
                expiration: self.delegation.expiration,
                targets: self.delegation.targets,
                // Forward II's per-MCP-session permission verbatim so the
                // reconstructed delegation hashes to exactly what II signed.
                // II sends this as `opt text`; an absent permission (`None`)
                // hashes identically to a pre-permissions delegation, so
                // unrestricted sessions are unaffected. A present-but-unknown
                // value is a hard error (see `permissions_from_text`).
                permissions: permissions_from_text(self.delegation.permissions.as_deref())?,
            },
            signature: self.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both built-in instance constructors must succeed: the fallible part is
    /// parsing the canister id (a compile-time default string, or its env
    /// override) into a `Principal`, so this guards those defaults against a
    /// typo. It deliberately does NOT assert the two instances differ — both
    /// read `II_URL*` / `II_CANISTER_ID*` from the environment, and a
    /// legitimate setup (e.g. local testing) may point both at the same II.
    #[test]
    fn instance_defaults_are_valid() {
        IiInstance::beta().expect("beta defaults");
        IiInstance::prod().expect("prod defaults");
    }

    #[test]
    fn remaps_gateway_domains_to_ic0_app() {
        assert_eq!(
            target_origin("rdmx6-jaaaa-aaaaa-aaadq-cai.icp0.io"),
            "https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app"
        );
        assert_eq!(target_origin("foo.icp.net"), "https://foo.ic0.app");
    }

    #[test]
    fn passes_through_custom_domains() {
        assert_eq!(target_origin("oisy.com"), "https://oisy.com");
        assert_eq!(target_origin("https://oisy.com/app"), "https://oisy.com");
        assert_eq!(target_origin("http://oisy.com"), "https://oisy.com");
    }

    /// H1a: a `target_origin` carrying `:443`, a path, a trailing slash, a query,
    /// or a fragment must normalize to the bare `https://<host>` origin — else II
    /// derives a DIFFERENT principal. The gateway remap still applies afterwards.
    #[test]
    fn target_origin_normalizes_port_path_and_slash() {
        assert_eq!(target_origin("https://oisy.com:443"), "https://oisy.com");
        assert_eq!(target_origin("https://oisy.com/"), "https://oisy.com");
        assert_eq!(target_origin("https://oisy.com/app/x"), "https://oisy.com");
        assert_eq!(target_origin("https://oisy.com?a=1"), "https://oisy.com");
        assert_eq!(target_origin("https://oisy.com#frag"), "https://oisy.com");
        assert_eq!(target_origin("https://oisy.com:443/app/x"), "https://oisy.com");
        // The gateway remap still fires once :443 / path is stripped.
        assert_eq!(target_origin("foo.icp0.io:443"), "https://foo.ic0.app");
        assert_eq!(target_origin("https://foo.icp0.io/app"), "https://foo.ic0.app");
        // A non-default port is part of the origin and is kept.
        assert_eq!(target_origin("https://localhost:8080"), "https://localhost:8080");
    }

    /// H2: `permissions` from the completion POST sets the read-only level, which
    /// `require_write` gates on. Unknown (POST not yet arrived) permits the write
    /// (we fall back to the IC's ingress rejection); `"queries"` refuses it.
    #[tokio::test]
    async fn permissions_set_read_only_and_gate_writes() {
        let ids = test_ids();
        ids.ensure_session("sess").await.expect("room for a session");
        assert_eq!(ids.is_read_only("sess").await, None);
        assert!(ids.require_write("sess").await.is_ok());
        ids.set_permissions("sess", "queries").await;
        assert_eq!(ids.is_read_only("sess").await, Some(true));
        assert!(ids.require_write("sess").await.is_err());
        // Case-insensitive, and "all" restores full access.
        ids.set_permissions("sess", "ALL").await;
        assert_eq!(ids.is_read_only("sess").await, Some(false));
        assert!(ids.require_write("sess").await.is_ok());
        // An UNRECOGNIZED value must NOT assume full access: it leaves the level
        // unknown (None) so the call falls through to the ingress-rejection path,
        // rather than the server wrongly reporting the session as writable.
        ids.ensure_session("sess2").await.expect("room for a session");
        ids.set_permissions("sess2", "something-new").await;
        assert_eq!(ids.is_read_only("sess2").await, None);
        assert!(ids.require_write("sess2").await.is_ok());
    }

    // An Identities store over a dummy II instance (tests never hit the network).
    fn test_ids() -> Identities {
        let agent = Agent::builder()
            .with_url("https://ii.test")
            .build()
            .expect("test agent");
        Identities::new(
            IiInstance {
                name: "test",
                ii_url: "https://ii.test".into(),
                ii_canister: Principal::anonymous(),
            },
            "https://mcp.test".into(),
            agent,
        )
    }

    // Seed a session with a live grant, bypassing the network connect flow.
    async fn seed_live(ids: &Identities, session_id: &str) {
        ids.ensure_session(session_id).await.expect("room for a session");
        let mut sessions = ids.sessions.write().await;
        let s = sessions.get_mut(session_id).expect("ensured session");
        s.grant_expiration_ns = Some(u64::MAX);
    }

    // Insert a cached app delegation for (domain, account_number) directly.
    async fn seed_app(ids: &Identities, session_id: &str, domain: &str, account: Option<u64>, exp: u64) {
        let mut sessions = ids.sessions.write().await;
        let s = sessions.get_mut(session_id).expect("session");
        s.app_delegations.insert(
            (domain.to_string(), account),
            AppDelegation {
                user_key: vec![account.unwrap_or(0) as u8],
                chain: vec![],
                expiration_ns: exp,
                app_key_seed: [account.unwrap_or(0) as u8; 32],
            },
        );
    }

    #[tokio::test]
    async fn resolve_account_defaults_to_none_without_network() {
        let ids = test_ids();
        seed_live(&ids, "sess").await;
        // No account name -> the default account, resolved with no network call.
        assert_eq!(ids.resolve_account("sess", "oisy.com", None).await.unwrap(), None);
    }

    #[tokio::test]
    async fn cached_delegations_are_keyed_by_account_number() {
        let ids = test_ids();
        seed_live(&ids, "sess").await;
        let future = now_ns() + REDERIVE_MARGIN_NS + 60 * 1_000_000_000;
        seed_app(&ids, "sess", "oisy.com", None, future).await;
        seed_app(&ids, "sess", "oisy.com", Some(7), future).await;

        // Each (domain, account) is cached independently.
        assert!(ids.cached_fresh("sess", "oisy.com", None).await.is_some());
        assert!(ids.cached_fresh("sess", "oisy.com", Some(7)).await.is_some());
        // An account we never derived is a cache miss.
        assert!(ids.cached_fresh("sess", "oisy.com", Some(9)).await.is_none());
        // A different domain is a cache miss.
        assert!(ids.cached_fresh("sess", "nns.ic0.app", None).await.is_none());
    }

    #[tokio::test]
    async fn cached_delegation_near_expiry_is_a_miss() {
        let ids = test_ids();
        seed_live(&ids, "sess").await;
        // Expiry within the re-derive margin -> treated as stale.
        seed_app(&ids, "sess", "oisy.com", None, now_ns() + 1).await;
        assert!(ids.cached_fresh("sess", "oisy.com", None).await.is_none());
    }

    #[tokio::test]
    async fn expired_grant_blocks_signing() {
        let ids = test_ids();
        ids.ensure_session("sess").await.expect("room for a session");
        ids.set_grant_expiration("sess", now_ns().saturating_sub(1)).await;
        // A past grant expiration short-circuits to the reconnect message.
        assert!(ids.session_signer("sess").await.is_err());
    }

    // The /version live-session gauge counts only sessions with a still-valid
    // grant: a future expiry counts, a past expiry does not, and a session that
    // never recorded an expiry (mid-connect / no completion POST) does not.
    #[tokio::test]
    async fn live_session_count_counts_only_valid_grants() {
        let ids = test_ids();
        assert_eq!(ids.live_session_count().await, 0);

        // Two live grants (well into the future).
        let future = now_ns() + 3_600_000_000_000;
        ids.set_grant_expiration("live1", future).await;
        ids.set_grant_expiration("live2", future).await;
        // An expired grant.
        ids.set_grant_expiration("expired", now_ns().saturating_sub(1)).await;
        // A session with no recorded expiry.
        ids.ensure_session("pending").await.expect("room for a session");

        assert_eq!(ids.live_session_count().await, 2);
    }

    // The reaper drops expired-grant sessions (returning how many), and leaves
    // valid grants and no-expiry sessions in place.
    #[tokio::test]
    async fn reap_expired_sessions_evicts_expired_only() {
        let ids = test_ids();
        let future = now_ns() + 3_600_000_000_000;
        ids.set_grant_expiration("live", future).await;
        ids.set_grant_expiration("expired", now_ns().saturating_sub(1)).await;
        ids.ensure_session("pending").await.expect("room for a session");

        assert_eq!(ids.reap_expired_sessions().await, 1);
        // The expired one is gone; the live and no-expiry ones remain.
        let sessions = ids.sessions.read().await;
        assert!(sessions.contains_key("live"));
        assert!(sessions.contains_key("pending"));
        assert!(!sessions.contains_key("expired"));
        drop(sessions);
        // Idempotent: a second sweep finds nothing new to reap.
        assert_eq!(ids.reap_expired_sessions().await, 0);
        assert_eq!(ids.live_session_count().await, 1);
    }

    // ---- Bounded state (CWE-770) --------------------------------------------

    // A bare `Session` with the given age/grant, for the bound tests — no key
    // material needed, since the bounds only read the timestamps and the grant.
    fn session_at(created_ns: u64, grant_expiration_ns: Option<u64>) -> Session {
        Session {
            key_seed: [0u8; 32],
            pubkey_der: Vec::new(),
            grant_expiration_ns,
            created_ns,
            last_seen_ns: AtomicU64::new(created_ns),
            reg_key_seed: None,
            reg_pubkey_der: None,
            read_only: None,
            app_delegations: HashMap::new(),
        }
    }

    fn app_delegation(expiration_ns: u64) -> AppDelegation {
        AppDelegation {
            user_key: Vec::new(),
            chain: Vec::new(),
            expiration_ns,
            app_key_seed: [0u8; 32],
        }
    }

    // `/oauth/authorize` is unauthenticated, so the connects in flight are
    // capped: making room evicts the OLDEST pending connect (a flood churns its
    // own entries out) and never touches a session holding a live grant.
    #[test]
    fn make_room_bounds_pending_connects_and_spares_grants() {
        let now = 1_700_000_000 * 1_000_000_000;
        let mut sessions = HashMap::new();
        sessions.insert("live".to_string(), session_at(now, Some(now + 3_600_000_000_000)));
        // `pending-i` is i milliseconds old, so `pending-{cap-1}` is the oldest.
        for i in 0..MAX_PENDING_CONNECTS as u64 {
            sessions.insert(format!("pending-{i}"), session_at(now - i * 1_000_000, None));
        }

        make_room(&mut sessions, now).expect("pending pressure must not refuse a connect");

        assert!(sessions.contains_key("live"), "a live grant is never evicted");
        let pending = sessions.values().filter(|s| s.grant_expiration_ns.is_none()).count();
        assert_eq!(pending, MAX_PENDING_CONNECTS - 1, "room made for exactly one more connect");
        assert!(
            !sessions.contains_key(&format!("pending-{}", MAX_PENDING_CONNECTS - 1)),
            "the oldest pending connect goes first"
        );
        assert!(sessions.contains_key("pending-0"), "recent connects in flight are kept");
    }

    // Stale entries are reclaimed before anything live is considered: an expired
    // grant and an abandoned connect free the room a new connect needs.
    #[test]
    fn make_room_reclaims_stale_entries_first() {
        let now = 1_700_000_000 * 1_000_000_000;
        let mut sessions = HashMap::new();
        sessions.insert("expired".to_string(), session_at(now, Some(now - 1)));
        sessions.insert(
            "abandoned".to_string(),
            session_at(now.saturating_sub(PENDING_CONNECT_TTL_NS + 1), None),
        );
        for i in 0..(MAX_PENDING_CONNECTS as u64 - 2) {
            sessions.insert(format!("pending-{i}"), session_at(now - i * 1_000_000, None));
        }

        let closed = make_room(&mut sessions, now).expect("room is available");

        assert_eq!(closed, vec!["expired".to_string()], "an expired grant is reported for logging");
        assert!(!sessions.contains_key("expired"));
        assert!(!sessions.contains_key("abandoned"));
        // Reclaiming those two was enough, so no live-ish connect was evicted.
        assert!(sessions.contains_key("pending-0"));
        assert_eq!(sessions.len(), MAX_PENDING_CONNECTS - 2);
    }

    // The hard ceiling refuses a new connect rather than evicting an
    // authenticated user's live grant to make room.
    #[test]
    fn make_room_refuses_rather_than_evicting_live_grants() {
        let now = 1_700_000_000 * 1_000_000_000;
        let mut sessions: HashMap<String, Session> = (0..MAX_SESSIONS)
            .map(|i| (format!("live-{i}"), session_at(now, Some(now + 3_600_000_000_000))))
            .collect();

        let err = make_room(&mut sessions, now).expect_err("a full map must refuse the connect");
        assert!(err.contains("at capacity"), "got: {err}");
        assert_eq!(sessions.len(), MAX_SESSIONS, "no live grant was evicted to make room");
    }

    // A connect that never redeems is reaped once it is past the point of being
    // redeemable; a connect still in flight is kept (evicting it would strand the
    // registration key `X` II may already have certified).
    #[tokio::test]
    async fn reap_drops_abandoned_connects_and_keeps_fresh_ones() {
        let ids = test_ids();
        ids.ensure_session("in-flight").await.expect("room for a session");
        ids.ensure_session("abandoned").await.expect("room for a session");
        {
            let mut sessions = ids.sessions.write().await;
            sessions.get_mut("abandoned").expect("session").created_ns =
                now_ns().saturating_sub(PENDING_CONNECT_TTL_NS + 1);
        }

        assert_eq!(ids.reap_expired_sessions().await, 1);
        let sessions = ids.sessions.read().await;
        assert!(sessions.contains_key("in-flight"), "a connect in flight survives the sweep");
        assert!(!sessions.contains_key("abandoned"), "an abandoned connect is reaped");
    }

    // A single session can't grow its delegation cache without bound by asking
    // for delegations at many origins: the cache is capped, and the entry nearest
    // expiry (the one that would be re-derived soonest anyway) is evicted.
    #[tokio::test]
    async fn app_delegation_cache_is_capped_per_session() {
        let ids = test_ids();
        seed_live(&ids, "sess").await;
        let base = now_ns() + REDERIVE_MARGIN_NS + 60 * 1_000_000_000;
        for i in 0..MAX_APP_DELEGATIONS as u64 {
            // Later `i` expires later, so `app0` is always the nearest expiry.
            ids.store("sess", &format!("app{i}.example"), None, app_delegation(base + i * 1_000_000_000))
                .await;
        }
        assert_eq!(
            ids.sessions.read().await.get("sess").expect("session").app_delegations.len(),
            MAX_APP_DELEGATIONS
        );

        ids.store("sess", "one-more.example", None, app_delegation(base + 9_999_000_000_000)).await;

        {
            let sessions = ids.sessions.read().await;
            let cache = &sessions.get("sess").expect("session").app_delegations;
            assert_eq!(cache.len(), MAX_APP_DELEGATIONS, "the cache stays at its cap");
            assert!(
                !cache.contains_key(&("app0.example".to_string(), None)),
                "the entry nearest expiry is evicted"
            );
            assert!(
                cache.contains_key(&("one-more.example".to_string(), None)),
                "the new entry is cached"
            );
        }

        // Refreshing an EXISTING origin/account replaces its entry, evicting nothing.
        ids.store("sess", "app1.example", None, app_delegation(base + 9_999_000_000_000)).await;
        assert_eq!(
            ids.sessions.read().await.get("sess").expect("session").app_delegations.len(),
            MAX_APP_DELEGATIONS
        );
    }

    // The live gauge tracks the grant lifecycle, NOT request activity: a session
    // that goes quiet keeps counting for as long as its grant is valid (an
    // ongoing MCP session is often idle between tool calls), and it leaves the
    // gauge exactly when its grant expires — before the reaper has swept it out.
    // Deterministic (no wall-clock sleep): the already-past grant stands in for
    // "after expiry", so the test can't flake under load or a clock shift.
    #[tokio::test]
    async fn live_session_count_keeps_idle_sessions_until_grant_expiry() {
        let ids = test_ids();
        let future = now_ns() + 3_600_000_000_000;
        ids.set_grant_expiration("idle", future).await;
        // Backdate "idle" far past the activity window — it has not made a request
        // in ages. This is the regression guard: live_session_count must STILL
        // count it (the old activity-windowed gauge would have dropped it here).
        {
            let stale = now_ns().saturating_sub(ACTIVE_SESSION_WINDOW_NS + 3_600_000_000_000);
            let sessions = ids.sessions.read().await;
            sessions.get("idle").unwrap().last_seen_ns.store(stale, Ordering::Relaxed);
        }
        // Live keys only on the grant, so the long-idle session counts; active
        // keys on the window, so it does not — the whole point of the split.
        assert_eq!(ids.live_session_count().await, 1);
        assert_eq!(ids.active_session_count().await, 0);

        // A grant in the past has already left the gauge (dropped at its expiry
        // instant), even though it stays in the map until the reaper sweeps it.
        ids.set_grant_expiration("expired", now_ns().saturating_sub(1)).await;
        assert_eq!(ids.live_session_count().await, 1);
        assert!(ids.sessions.read().await.contains_key("expired"));
        assert_eq!(ids.reap_expired_sessions().await, 1);
        assert_eq!(ids.live_session_count().await, 1);
    }

    // The active gauge is a SUBSET of the live gauge: it counts sessions with a
    // valid grant that were also seen requesting within the activity window. A
    // session gone quiet past the window drops off `active` but stays on `live`
    // (its grant is untouched); a fresh request (touch) brings it back. An
    // expired grant counts on neither, even with recent activity (grant gate).
    #[tokio::test]
    async fn active_session_count_tracks_the_activity_window() {
        let ids = test_ids();
        let future = now_ns() + 3_600_000_000_000;
        ids.set_grant_expiration("active", future).await;
        ids.set_grant_expiration("quiet", future).await;
        // Both just connected (set_grant_expiration stamps last_seen), so both are
        // active and live.
        assert_eq!(ids.active_session_count().await, 2);
        assert_eq!(ids.live_session_count().await, 2);

        // Backdate "quiet" past the activity window, leaving its grant untouched.
        {
            let stale = now_ns().saturating_sub(ACTIVE_SESSION_WINDOW_NS + 1_000_000_000);
            let sessions = ids.sessions.read().await;
            sessions.get("quiet").unwrap().last_seen_ns.store(stale, Ordering::Relaxed);
        }
        // Dropped from active, still on live (active ⊆ live).
        assert_eq!(ids.active_session_count().await, 1);
        assert_eq!(ids.live_session_count().await, 2);
        // session_gauges reports the same pair from one snapshot (what /version uses).
        let g = ids.session_gauges().await;
        assert_eq!((g.live, g.active), (2, 1));

        // A fresh authenticated request brings it back onto the active gauge.
        ids.touch_session("quiet").await;
        assert_eq!(ids.active_session_count().await, 2);

        // A recently-active session whose grant has expired counts on neither
        // gauge: the grant gate excludes it despite the fresh last_seen.
        ids.set_grant_expiration("expired", now_ns().saturating_sub(1)).await;
        ids.touch_session("expired").await;
        assert_eq!(ids.active_session_count().await, 2);
        assert_eq!(ids.live_session_count().await, 2);
    }

    // Lock in the mcp_get_accounts Candid contract: a `vec AccountInfo` (with the
    // full record incl. `origin`) decodes into our subset `IiAccountInfo` (origin
    // skipped), and the Ok/Err variant maps to a Rust Result over the error type.
    #[test]
    fn mcp_get_accounts_reply_decodes_account_records() {
        #[derive(CandidType)]
        struct WireAccount {
            account_number: Option<u64>,
            origin: String,
            last_used: Option<u64>,
            name: Option<String>,
        }
        let wire: std::result::Result<Vec<WireAccount>, AccountDelegationError> = Ok(vec![
            WireAccount { account_number: None, origin: "https://oisy.com".into(), last_used: None, name: None },
            WireAccount {
                account_number: Some(7),
                origin: "https://oisy.com".into(),
                last_used: Some(123),
                name: Some("savings".into()),
            },
        ]);
        let bytes = Encode!(&wire).expect("encode");
        let decoded = Decode!(&bytes, McpGetAccountsReply).expect("decode").expect("Ok arm");
        assert_eq!(decoded.len(), 2);
        // Default account (the anchor's current default): no number, no name.
        assert_eq!(decoded[0].account_number, None);
        assert_eq!(decoded[0].name, None);
        // Named account: number, name, and last_used recovered (origin ignored).
        assert_eq!(decoded[1].account_number, Some(7));
        assert_eq!(decoded[1].name.as_deref(), Some("savings"));
        assert_eq!(decoded[1].last_used, Some(123));
    }

    // II's `SignedDelegation` / `Delegation` Candid contract, mirrored so tests can
    // encode a reply exactly as II sends it and drive the real `Decode!` ->
    // `into_agent` path over it. II's `Delegation.permissions` is **`opt text`**
    // ("queries" / "all"), NOT the `variant { queries; all }` named type that also
    // appears in the `.did` — see `IiDelegation`. (An earlier version of this
    // mirror used a variant, which encoded the wrong wire shape and hid the
    // read-only decode bug.)
    #[derive(CandidType)]
    struct WireDelegation {
        pubkey: Vec<u8>,
        expiration: u64,
        targets: Option<Vec<Principal>>,
        permissions: Option<String>,
    }
    #[derive(CandidType)]
    struct WireSignedDelegation {
        delegation: WireDelegation,
        signature: Vec<u8>,
    }

    // A pre-0.48 II reply whose `Delegation` record has NO `permissions` field at
    // all — the older wire type, distinct from an `opt`-null field. Used to prove
    // Candid decodes the absent optional as `None`, so old replies keep working.
    #[derive(CandidType)]
    struct WireLegacyDelegation {
        pubkey: Vec<u8>,
        expiration: u64,
        targets: Option<Vec<Principal>>,
    }
    #[derive(CandidType)]
    struct WireLegacySignedDelegation {
        delegation: WireLegacyDelegation,
        signature: Vec<u8>,
    }

    // Lock in the mcp_get_delegation permission contract: II's `Delegation`
    // carries `permissions: opt text` ("queries"/"all"), and it must round-trip
    // through `into_agent` onto the `ic-agent` delegation so the reconstructed
    // hash matches what II signed. An absent permission stays `None`.
    #[test]
    fn signed_delegation_forwards_ii_permissions() {
        let app_key = vec![1u8, 2, 3, 4];
        // Decode a `queries`-scoped delegation and confirm it maps to Queries.
        let make = |permissions| WireSignedDelegation {
            delegation: WireDelegation {
                pubkey: app_key.clone(),
                expiration: 42,
                targets: None,
                permissions,
            },
            signature: vec![9, 9, 9],
        };

        let bytes = Encode!(&make(Some("queries".to_string()))).expect("encode");
        let agent = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(agent.delegation.permissions, Some(DelegationPermissions::Queries));

        let bytes = Encode!(&make(Some("all".to_string()))).expect("encode");
        let agent = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(agent.delegation.permissions, Some(DelegationPermissions::All));

        // An unrestricted (present-but-null) permission decodes and forwards as
        // None, hashing identically to a pre-0.48 delegation.
        let bytes = Encode!(&make(None)).expect("encode");
        let agent = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(agent.delegation.permissions, None);

        // Backward compatibility: a pre-0.48 reply omits the `permissions` field
        // from the record entirely (not `opt`-null as above). Candid's subtyping
        // decodes the absent optional as None, so old II replies keep working.
        let legacy = WireLegacySignedDelegation {
            delegation: WireLegacyDelegation {
                pubkey: app_key.clone(),
                expiration: 42,
                targets: None,
            },
            signature: vec![9, 9, 9],
        };
        let bytes = Encode!(&legacy).expect("encode legacy reply");
        let agent = Decode!(&bytes, IiSignedDelegation)
            .expect("decode legacy reply")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(agent.delegation.permissions, None);
    }

    // Regression guard for the read-only outage: II sends `permissions` as
    // `opt text`, so decoding it into an `opt variant { queries; all }` (which we
    // mistakenly did) hits Candid's `opt`-mismatch rule and SILENTLY drops it to
    // `None`. That omitted it from the presented delegation, so II's canister
    // signature (which covers `permissions`) no longer verified and every
    // read-only session failed with "sig not found in the signature tree". Prove
    // both halves: the variant decode loses II's text, and our `text` decode keeps
    // it — so nobody reintroduces the variant type.
    #[test]
    fn ii_opt_text_permissions_is_dropped_by_variant_decode_but_kept_by_text() {
        // A binding that (wrongly) models II's `opt text` field as an `opt variant`.
        #[derive(CandidType, Deserialize)]
        enum VariantPermissions {
            #[serde(rename = "queries")]
            Queries,
            #[serde(rename = "all")]
            All,
        }
        #[derive(CandidType, Deserialize)]
        struct VariantDelegation {
            pubkey: Vec<u8>,
            expiration: u64,
            targets: Option<Vec<Principal>>,
            permissions: Option<VariantPermissions>,
        }
        #[derive(CandidType, Deserialize)]
        struct VariantSigned {
            delegation: VariantDelegation,
            signature: Vec<u8>,
        }

        let app_key = vec![1u8, 2, 3, 4];
        // Encode II's ACTUAL wire shape: `permissions` as `opt text = "queries"`.
        let bytes = Encode!(&WireSignedDelegation {
            delegation: WireDelegation {
                pubkey: app_key.clone(),
                expiration: 42,
                targets: None,
                permissions: Some("queries".to_string()),
            },
            signature: vec![9, 9, 9],
        })
        .expect("encode II opt-text reply");

        // Decoded as an `opt variant`, the text is silently dropped → None (the bug).
        let dropped = Decode!(&bytes, VariantSigned).expect("decode as variant");
        assert!(
            dropped.delegation.permissions.is_none(),
            "opt text must NOT survive an opt-variant decode — it silently drops to None"
        );

        // Decoded as `opt text` (our fix) and mapped, it is preserved end to end.
        let kept = Decode!(&bytes, IiSignedDelegation)
            .expect("decode as text")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(kept.delegation.permissions, Some(DelegationPermissions::Queries));
    }

    // A present-but-unrecognized permission must FAIL FAST rather than silently
    // drop to None — otherwise a future II permission string would produce a
    // delegation whose signature can't verify, resurfacing the same opaque
    // "sig not found" replica error the text decode was meant to end.
    #[test]
    fn unknown_permission_fails_fast_rather_than_silently_dropping() {
        let app_key = vec![1u8, 2, 3, 4];
        let bytes = Encode!(&WireSignedDelegation {
            delegation: WireDelegation {
                pubkey: app_key.clone(),
                expiration: 42,
                targets: None,
                permissions: Some("write-only".to_string()), // not "queries"/"all"
            },
            signature: vec![9, 9, 9],
        })
        .expect("encode");
        let err = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_key)
            .expect_err("an unrecognized permission must error, not silently drop");
        assert!(err.contains("unrecognized permission"), "got: {err}");
    }

    // End-to-end: a read-only (`queries`) delegation from II must survive our full
    // decode -> DelegatedIdentity path and scope EVERY request the resulting
    // identity signs, so the replica allows reads but refuses update calls. This
    // drives the real path — `IiSignedDelegation::into_agent` -> `build_identity`
    // -> `Identity::sign` — with a genuinely anchor-signed chain, no network: the
    // replica enforces the scope because it is bound into the delegation signature
    // (proven by the tamper check at the end).
    #[test]
    fn read_only_delegation_scopes_signed_requests_end_to_end() {
        use ic_agent::agent::EnvelopeContent;

        // The anchor (II user) key that signs the delegation, and the per-app key
        // it is issued to (what the server ultimately signs canister calls as).
        let (user_seed, user_der) = fresh_ed25519();
        let (app_seed, app_der) = fresh_ed25519();
        let anchor = BasicIdentity::from_raw_key(&user_seed);
        let expiration = now_ns() + 3_600_000_000_000;

        // The exact `queries`-scoped delegation II would sign, signed as the
        // anchor. `signable()` covers `permissions`, so this signature is valid
        // ONLY for the read-only delegation.
        let delegation = Delegation {
            pubkey: app_der.clone(),
            expiration,
            targets: None,
            permissions: Some(DelegationPermissions::Queries),
        };
        let signature = anchor
            .sign_delegation(&delegation)
            .expect("anchor signs delegation")
            .signature
            .expect("ed25519 signature present");

        // Feed it back through the real II-reply -> decode -> into_agent path.
        let wire = WireSignedDelegation {
            delegation: WireDelegation {
                pubkey: app_der.clone(),
                expiration,
                targets: None,
                permissions: Some("queries".to_string()),
            },
            signature,
        };
        let bytes = Encode!(&wire).expect("encode II reply");
        let signed = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_der)
            .expect("into_agent");
        assert_eq!(
            signed.delegation.permissions,
            Some(DelegationPermissions::Queries),
            "read-only scope survives decoding"
        );

        // Build the delegated identity exactly as the server does; the chain
        // validates because the anchor's signature covers this read-only delegation.
        let app = AppDelegation {
            user_key: user_der.clone(),
            chain: vec![signed.clone()],
            expiration_ns: expiration,
            app_key_seed: app_seed,
        };
        let identity = build_identity(&app).expect("valid read-only chain builds an identity");
        let sender = identity.sender().expect("sender");

        // Every request this identity signs — an update AND a read — carries the
        // read-only delegation, so the replica scopes both to queries/read_state.
        let update = EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: expiration,
            sender,
            canister_id: Principal::management_canister(),
            method_name: "some_update".to_string(),
            arg: vec![],
            sender_info: None,
        };
        let read = EnvelopeContent::Query {
            ingress_expiry: expiration,
            sender,
            canister_id: Principal::management_canister(),
            method_name: "some_query".to_string(),
            arg: vec![],
            nonce: None,
            sender_info: None,
        };
        for content in [&update, &read] {
            let chain = identity
                .sign(content)
                .expect("sign request")
                .delegations
                .expect("delegation chain attached to the request");
            assert_eq!(chain.len(), 1);
            assert_eq!(
                chain[0].delegation.permissions,
                Some(DelegationPermissions::Queries),
                "the signed request carries the read-only scope the replica enforces"
            );
        }

        // The restriction is bound into the signature, not cosmetic: widening it to
        // an unrestricted delegation changes the signed bytes, so the anchor's
        // signature no longer verifies and the identity refuses to build. A client
        // cannot silently promote a read-only delegation to full access.
        let unrestricted = Delegation {
            permissions: None,
            ..delegation.clone()
        };
        assert_ne!(
            delegation.signable(),
            unrestricted.signable(),
            "the permission must change what is signed"
        );
        let mut tampered = signed;
        tampered.delegation.permissions = None;
        let tampered_app = AppDelegation {
            user_key: user_der,
            chain: vec![tampered],
            expiration_ns: expiration,
            app_key_seed: app_seed,
        };
        assert!(
            build_identity(&tampered_app).is_err(),
            "stripping the read-only scope must invalidate the delegation signature"
        );
    }

    // ---- Phase 2: registration delegation (flag-gated) ----------------------

    // The registration key `X` is minted once per connect (idempotent) and is a
    // DISTINCT keypair from the long-lived session key `S`: v2 signs the
    // `mcp_register_v2` ingress AS `X` while registering `S`. Only `pub(X)` is
    // ever exposed; `priv(X)` stays in the session.
    #[tokio::test]
    async fn registration_key_is_minted_once_and_distinct_from_session_key() {
        let ids = test_ids();
        let x1 = ids.registration_pubkey_b64("sess").await.expect("mint X");
        let x2 = ids.registration_pubkey_b64("sess").await.expect("mint X");
        assert_eq!(x1, x2, "the registration key is stable across a connect");
        // X's key material must differ from the session key S.
        let (s_der, x_der) = {
            let sessions = ids.sessions.read().await;
            let s = sessions.get("sess").expect("session");
            (s.pubkey_der.clone(), s.reg_pubkey_der.clone().expect("reg key minted"))
        };
        assert_ne!(x_der, s_der, "X (registration key) must differ from S (session key)");
    }

    // Lock the merged mcp_register_v2 arg shape: EXACTLY ONE argument,
    // `session_key : blob`. The server no longer echoes consent (permissions/
    // max_ttl): II captured it at `prepare_mcp_registration_delegation` and
    // recovers it from `caller() == P_reg`, so a regression to the old 3-arg
    // echo would desync from II's live 1-arg `.did`.
    #[test]
    fn mcp_register_v2_arg_encodes_session_key_only() {
        use candid::types::value::IDLArgs;

        let session_der = vec![1u8, 2, 3];
        let bytes = Encode!(&session_der).expect("encode");

        // Typed round-trip: the single blob comes back out.
        let k = Decode!(&bytes, Vec<u8>).expect("decode");
        assert_eq!(k, session_der);

        // Typeless: exactly one argument on the wire, guarding against silently
        // returning to the multi-arg echo.
        let args = IDLArgs::from_bytes(&bytes).expect("typeless-decode args").args;
        assert_eq!(args.len(), 1, "mcp_register_v2 takes exactly one arg (session_key)");
    }

    // Lock the on-wire `Permissions` variant labels our reply decode depends on
    // (`McpRegistrationV2.permissions`). Candid hashes variant labels one-way, so
    // a typed round-trip can't see a `queries`/`all` -> `Queries`/`All` rename;
    // yet II sends the lowercase labels and our `Decode!` of the reply would then
    // fail (the #40 read-only outage was exactly a shape drift). Compare a
    // TYPELESS decode of each encoded `IiPermissions` against the same round-trip
    // of a literal `variant { … }` parsed from text; the typeless form carries
    // only the hashed label, so it matches only when the labels agree.
    #[test]
    fn ii_permissions_variant_labels_match_ii() {
        use candid::types::value::IDLArgs;

        let literal = |v: &str| {
            let b = candid_parser::parse_idl_args(&format!("(variant {{ {v} }})"))
                .expect("parse literal")
                .to_bytes()
                .expect("encode literal");
            IDLArgs::from_bytes(&b).expect("typeless-decode literal").args[0].to_string()
        };
        let wire = |p: IiPermissions| {
            let b = Encode!(&p).expect("encode perm");
            IDLArgs::from_bytes(&b).expect("typeless-decode perm").args[0].to_string()
        };
        assert_eq!(wire(IiPermissions::Queries), literal("queries"), "on-wire label must be `queries`");
        assert_eq!(wire(IiPermissions::All), literal("all"), "on-wire label must be `all`");
        // Sanity: the two labels hash differently, so the checks above genuinely
        // pin each one and aren't matching everything.
        assert_ne!(wire(IiPermissions::Queries), literal("all"));
    }

    // Redemption refuses a delegation that does NOT terminate at this connect's
    // registration key `X`: we hold `priv(X)` and can only sign the ingress that
    // delegation authorizes, so a mismatch is rejected locally, BEFORE any
    // network call to II.
    #[tokio::test]
    async fn redeem_rejects_delegation_not_targeting_registration_key() {
        let ids = test_ids();
        // Mint X so the missing-key guard passes and we reach the target check.
        ids.registration_pubkey_b64("sess").await.expect("mint X");
        let wrong_target = SignedDelegation {
            delegation: Delegation {
                pubkey: vec![0xaa; 32], // not der(X)
                expiration: now_ns() + 60 * 1_000_000_000,
                targets: None,
                permissions: None,
            },
            signature: vec![],
        };
        let err = ids
            .redeem_registration_delegation("sess", vec![1, 2, 3], vec![wrong_target])
            .await
            .expect_err("a delegation to the wrong key must be rejected");
        assert!(err.contains("does not delegate"), "got: {err}");
    }

    // The rev3 chain is TWO hops — canister-signed `P_reg -> Y` (Y held only by
    // II's frontend) extended browser-side with `Y -> X`. Build the exact shape
    // with Ed25519 stand-ins (the replica, not the client, verifies the real
    // canister signature) and prove it yields a working signing identity whose
    // requests carry BOTH hops in order.
    #[test]
    fn two_hop_registration_chain_builds_a_signing_identity() {
        use ic_agent::agent::EnvelopeContent;

        let (preg_seed, preg_der) = fresh_ed25519(); // stands in for P_reg
        let (y_seed, y_der) = fresh_ed25519(); // II's ephemeral browser-held Y
        let (x_seed, x_der) = fresh_ed25519(); // our registration key X
        let exp = now_ns() + 300 * 1_000_000_000;

        let hop = |signer_seed: &[u8; 32], to_der: &[u8]| {
            let delegation = Delegation {
                pubkey: to_der.to_vec(),
                expiration: exp,
                targets: None,
                permissions: None,
            };
            let signature = BasicIdentity::from_raw_key(signer_seed)
                .sign_delegation(&delegation)
                .expect("sign delegation")
                .signature
                .expect("signature present");
            SignedDelegation { delegation, signature }
        };
        let chain = vec![hop(&preg_seed, &y_der), hop(&y_seed, &x_der)];

        // Verified against the agent's root key (mainnet default here); the
        // Ed25519 stand-in hops don't consult it — only a real canister-signed
        // hop would — so any root key builds this all-Ed25519 chain.
        let root = crate::Agent::builder()
            .with_url("https://ii.test")
            .build()
            .expect("agent")
            .read_root_key();
        let identity = registration_identity(preg_der.clone(), x_seed, &x_der, chain, &root)
            .expect("a two-hop chain ending at X must build");
        let sender = identity.sender().expect("sender");
        let content = EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: exp,
            sender,
            canister_id: Principal::management_canister(),
            method_name: "mcp_register_v2".to_string(),
            arg: vec![],
            sender_info: None,
        };
        let signed = identity.sign(&content).expect("sign");
        let attached = signed.delegations.expect("chain attached to the request");
        assert_eq!(attached.len(), 2, "both hops must ride the request");
        assert_eq!(attached[0].delegation.pubkey, y_der, "hop 1 targets Y");
        assert_eq!(attached[1].delegation.pubkey, x_der, "hop 2 targets X");

        // A chain whose FINAL hop targets some other key is rejected before any
        // signing — we don't hold that key's private half.
        let (_, other_der) = fresh_ed25519();
        let bad = vec![hop(&preg_seed, &y_der), hop(&y_seed, &other_der)];
        assert!(registration_identity(preg_der, x_seed, &x_der, bad, &root).is_err());
    }

    // Redemption with no registration key minted, or an empty chain, fails
    // locally with an actionable message rather than reaching II.
    #[tokio::test]
    async fn redeem_guards_missing_key_and_empty_chain() {
        let ids = test_ids();
        // No X minted yet: even a plausible user_key can't be redeemed.
        let err = ids
            .redeem_registration_delegation("sess", vec![1], vec![])
            .await
            .expect_err("no registration key => error");
        assert!(err.contains("no registration key"), "got: {err}");

        // With X minted, an EMPTY chain is rejected (nothing to present to II).
        ids.registration_pubkey_b64("sess").await.expect("mint X");
        let err = ids
            .redeem_registration_delegation("sess", vec![1], vec![])
            .await
            .expect_err("empty chain => error");
        assert!(err.contains("chain is empty"), "got: {err}");
    }
}
