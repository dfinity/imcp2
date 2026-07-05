//! On-demand per-app delegated identities — **session-key registration model**.
//!
//! Model (Internet Identity MCP connect, per `docs/mcp-server-guide.md` and
//! dfinity/internet-identity#4086): at connect time the server generates a fresh
//! Ed25519 **session key per user-connection** (inside the key-request callback)
//! and returns only its public key to II's frontend, which registers it with the
//! II canister via `mcp_register` — under the user's own authentication — as a
//! time-boxed **grant** bound to the user's anchor. The server never handles a
//! delegation chain that represents itself, and never calls `mcp_register`. The
//! session key's principal `self_authenticating(session_pubkey)` IS the identity
//! the grant is bound to.
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

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::{
    identity::{BasicIdentity, DelegatedIdentity, Delegation, DelegationPermissions, SignedDelegation},
    Agent, Identity,
};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Public IC API boundary node the II canister calls are made against.
const IC_URL: &str = "https://icp-api.io";

/// Re-derive once the cached delegation is within this margin of expiry, so a
/// call never goes out with an about-to-expire delegation.
const REDERIVE_MARGIN_NS: u64 = 30 * 1_000_000_000;

/// Internet Identity instance, single source of truth. Default: **`beta.id.ai`**.
/// A real domain is required: the raw `<canister>.icp0.io` origin is rate-limited
/// (HTTP 429) for the browser login SPA, leaving the II popup blank. Used for the
/// connect-time `/mcp` handshake (browser). Override with `II_URL`.
const II_URL_DEFAULT: &str = "https://beta.id.ai";

/// Canister id of that same II instance, used for the on-demand account
/// delegation calls (`mcp_get_accounts` / `mcp_prepare_delegation` /
/// `mcp_get_delegation`). Default is the `beta.id.ai` canister. Override with
/// `II_CANISTER_ID`.
const II_CANISTER_ID_DEFAULT: &str = "fgte5-ciaaa-aaaad-aaatq-cai";

/// Production Internet Identity origin, used by the `/mcp-prod` instance.
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

/// One Internet Identity instance this server can connect users against. The
/// default ("beta") instance serves `/mcp` with its OAuth AS at the root of
/// `PUBLIC_URL`; the "prod" instance serves `/mcp-prod` with a path-scoped AS
/// (issuer `<PUBLIC_URL>/prod`, RFC 8414 path issuer). Each instance gets its
/// own `Identities` + `AuthStore`, so sessions/tokens never cross instances;
/// II trust in the user's settings is by ORIGIN, which both instances share.
#[derive(Clone, Debug)]
pub struct IiInstance {
    /// Short name for logging ("beta", "prod").
    pub name: &'static str,
    /// Origin of the II instance (no trailing slash), e.g. "https://beta.id.ai".
    pub ii_url: String,
    /// Canister id of that II instance — the target of the `mcp_*` calls.
    pub ii_canister: Principal,
    /// This instance's OAuth path prefix on the server: "" (root) or "/prod".
    pub oauth_prefix: &'static str,
    /// The MCP resource path this instance gates: "/mcp" or "/mcp-prod".
    pub mcp_path: &'static str,
}

impl IiInstance {
    /// The default instance: beta Internet Identity (`II_URL` / `II_CANISTER_ID`).
    pub fn beta() -> Result<Self, String> {
        Ok(Self {
            name: "beta",
            ii_url: env_origin("II_URL", II_URL_DEFAULT),
            ii_canister: env_principal("II_CANISTER_ID", II_CANISTER_ID_DEFAULT)?,
            oauth_prefix: "",
            mcp_path: "/mcp",
        })
    }

    /// The production instance (`II_URL_PROD` / `II_CANISTER_ID_PROD`). Only
    /// useful once production II carries the #4086 MCP feature set.
    pub fn prod() -> Result<Self, String> {
        Ok(Self {
            name: "prod",
            ii_url: env_origin("II_URL_PROD", II_URL_PROD_DEFAULT),
            ii_canister: env_principal("II_CANISTER_ID_PROD", II_CANISTER_ID_PROD_DEFAULT)?,
            oauth_prefix: "/prod",
            mcp_path: "/mcp-prod",
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

/// Remap a domain to the `target_origin` II expects for account derivation.
/// IC gateway domains (`*.icp0.io`, `*.icp.net`) map to the canonical
/// `*.ic0.app` origin; any other domain is passed through as `https://<domain>`.
fn target_origin(domain: &str) -> String {
    let host = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    for gateway in [".icp0.io", ".icp.net"] {
        if let Some(label) = host.strip_suffix(gateway) {
            return format!("https://{label}.ic0.app");
        }
    }
    format!("https://{host}")
}

struct Session {
    /// Ed25519 session-key seed; rebuild a `BasicIdentity` from it on demand.
    /// This is the key generated for this connection and registered with II (via
    /// the frontend's `mcp_register`); the server signs II's `mcp_*` calls
    /// directly with it. Its private half never leaves the backend — only its
    /// public key is ever sent to II.
    key_seed: [u8; 32],
    /// DER public key of the session key.
    pubkey_der: Vec<u8>,
    /// The grant's expiration (ns since the Unix epoch), as reported by the
    /// completion-notification callback POST. `None` until (or unless) that
    /// best-effort POST arrives; a missing value is not treated as expired — an
    /// `Unauthorized` from a signed call is the authoritative "session over"
    /// signal.
    grant_expiration_ns: Option<u64>,
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
/// distinct per-origin principal; `account_number == None`/`name == None` is the
/// origin's default ("synthetic") account, which every user has automatically.
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

#[derive(Clone)]
pub struct Identities {
    /// The II instance every session in this store is registered against.
    instance: IiInstance,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl Identities {
    pub fn new(instance: IiInstance) -> Self {
        Self {
            instance,
            sessions: Arc::default(),
        }
    }

    /// The II instance this store connects against.
    pub fn instance(&self) -> &IiInstance {
        &self.instance
    }

    async fn ensure_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.entry(session_id.to_string()).or_insert_with(|| {
            let (key_seed, pubkey_der) = fresh_ed25519();
            Session {
                key_seed,
                pubkey_der,
                grant_expiration_ns: None,
                app_delegations: HashMap::new(),
            }
        });
    }

    /// The backend session key seed and its DER pubkey.
    async fn session_key(&self, session_id: &str) -> Option<([u8; 32], Vec<u8>)> {
        let sessions = self.sessions.read().await;
        let s = sessions.get(session_id)?;
        Some((s.key_seed, s.pubkey_der.clone()))
    }

    /// Ensure a session exists and return its session **public** key (base64url,
    /// no pad, DER). This is what the key-request callback POST returns to II's
    /// frontend, which registers it as the grant. Its private half never leaves
    /// the backend.
    pub async fn session_pubkey_b64(&self, session_id: &str) -> String {
        self.ensure_session(session_id).await;
        let sessions = self.sessions.read().await;
        let der = &sessions.get(session_id).expect("ensured session").pubkey_der;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der)
    }

    /// The session's principal (`self_authenticating(session_pubkey)`), the
    /// identity the II grant is bound to. Used for logging/attribution.
    pub async fn session_principal(&self, session_id: &str) -> Option<String> {
        let (_, der) = self.session_key(session_id).await?;
        Some(Principal::self_authenticating(&der).to_text())
    }

    /// Record the grant's expiration reported by the completion-notification
    /// callback POST (`{state, expiration}`). The value is nanoseconds since the
    /// epoch (a decimal string on the wire, parsed before it reaches here).
    pub async fn set_grant_expiration(&self, session_id: &str, expiration_ns: u64) {
        self.ensure_session(session_id).await;
        let mut sessions = self.sessions.write().await;
        if let Some(s) = sessions.get_mut(session_id) {
            s.grant_expiration_ns = Some(expiration_ns);
        }
    }

    /// Build the plain session-key identity (`BasicIdentity`) the server signs
    /// II's `mcp_*` calls with. Errors early if the stored grant expiration has
    /// passed (a missing expiration is not treated as expired — the spec says to
    /// fall back to attempting the signed call, where an `Unauthorized` is the
    /// authoritative signal).
    async fn session_signer(&self, session_id: &str) -> Result<BasicIdentity, String> {
        self.ensure_session(session_id).await;
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
        Agent::builder()
            .with_url(IC_URL)
            .with_identity(signer)
            .build()
            .map_err(|e| format!("could not build II agent: {e}"))
    }

    /// A stable per-user identity for the canister-management tools — the user's
    /// default account at *this* MCP server's own origin, derived on demand like
    /// any other app. Its principal (`self_authenticating(user_key)`) is stable
    /// across reconnects (unlike the ephemeral session key), so it works as the
    /// user's controller/funder identity.
    pub async fn management_identity(&self, session_id: &str) -> Result<DelegatedIdentity, String> {
        let origin = crate::auth::base_url();
        self.delegated_identity(session_id, &origin, None).await
    }

    /// List the user's Internet Identity accounts at an app `domain`, via II's
    /// `mcp_get_accounts(target_origin)` signed as the session key. II recovers
    /// the anchor from the caller (the registered session-key principal), so no
    /// anchor number is needed. Every user has a default ("synthetic") account
    /// (`account_number == None`, no name) at any origin, plus any named accounts
    /// they created there; each is a distinct per-origin principal.
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

    /// Whether the grant is currently usable: a signed `mcp_get_accounts` for the
    /// MCP origin succeeds. Used by the device-flow poll as a best-effort "the
    /// user has finished connecting" signal, since the completion-notification
    /// POST is best-effort and may never arrive.
    pub async fn grant_is_live(&self, session_id: &str) -> bool {
        self.list_accounts(session_id, &crate::auth::base_url())
            .await
            .is_ok()
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
            return Ok(None); // default ("synthetic") account
        };
        let accounts = self.list_accounts(session_id, domain).await?;
        let mut matching = accounts.iter().filter(|a| a.name.as_deref() == Some(name));
        match (matching.next(), matching.next()) {
            (None, _) => Err(format!(
                "no account named \"{name}\" at {domain} — call list_accounts(domain) to see your \
                 accounts there, or omit `account` to use the default one"
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
        self.ensure_session(session_id).await;

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
            s.app_delegations.insert((domain.to_string(), account_number), app);
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
    /// access, `opt Permissions` (`variant { queries; all }`). Absent/`None`
    /// means unrestricted. Part of what II signs, so it must be forwarded
    /// verbatim into the `ic-agent` delegation for the hash to match.
    permissions: Option<IiPermissions>,
}

/// II's `Permissions` variant on a delegation (`variant { queries; all }`),
/// mirrored for Candid decoding since `ic-agent`'s `DelegationPermissions`
/// isn't `CandidType`. Maps 1:1 into it, preserving the on-wire representation
/// (`queries`/`all`) II hashed over.
#[derive(CandidType, Deserialize)]
enum IiPermissions {
    #[serde(rename = "queries")]
    Queries,
    #[serde(rename = "all")]
    All,
}

impl From<IiPermissions> for DelegationPermissions {
    fn from(p: IiPermissions) -> Self {
        match p {
            IiPermissions::Queries => DelegationPermissions::Queries,
            IiPermissions::All => DelegationPermissions::All,
        }
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
                // An absent permission (`None`) hashes identically to a
                // pre-0.48 delegation, so unrestricted sessions are unaffected.
                permissions: self.delegation.permissions.map(Into::into),
            },
            signature: self.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The built-in instance defaults must parse (canister ids are compile-time
    /// strings) and carry the expected paths/prefixes.
    #[test]
    fn instance_defaults_are_valid() {
        let beta = IiInstance::beta().expect("beta defaults");
        assert_eq!(beta.oauth_prefix, "");
        assert_eq!(beta.mcp_path, "/mcp");
        let prod = IiInstance::prod().expect("prod defaults");
        assert_eq!(prod.oauth_prefix, "/prod");
        assert_eq!(prod.mcp_path, "/mcp-prod");
        assert_ne!(beta.ii_canister, prod.ii_canister);
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

    // An Identities store over a dummy II instance (tests never hit the network).
    fn test_ids() -> Identities {
        Identities::new(IiInstance {
            name: "test",
            ii_url: "https://ii.test".into(),
            ii_canister: Principal::anonymous(),
            oauth_prefix: "",
            mcp_path: "/mcp",
        })
    }

    // Seed a session with a live grant, bypassing the network connect flow.
    async fn seed_live(ids: &Identities, session_id: &str) {
        ids.ensure_session(session_id).await;
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
        ids.ensure_session("sess").await;
        ids.set_grant_expiration("sess", now_ns().saturating_sub(1)).await;
        // A past grant expiration short-circuits to the reconnect message.
        assert!(ids.session_signer("sess").await.is_err());
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
        // Default (synthetic) account: no number, no name.
        assert_eq!(decoded[0].account_number, None);
        assert_eq!(decoded[0].name, None);
        // Named account: number, name, and last_used recovered (origin ignored).
        assert_eq!(decoded[1].account_number, Some(7));
        assert_eq!(decoded[1].name.as_deref(), Some("savings"));
        assert_eq!(decoded[1].last_used, Some(123));
    }

    // II's `SignedDelegation` / `Delegation` / `Permissions` Candid contract,
    // mirrored so tests can encode a reply exactly as II would and then drive the
    // real `Decode!` -> `into_agent` path over it.
    #[derive(CandidType, Deserialize)]
    enum WirePermissions {
        #[serde(rename = "queries")]
        Queries,
        #[serde(rename = "all")]
        All,
    }
    #[derive(CandidType)]
    struct WireDelegation {
        pubkey: Vec<u8>,
        expiration: u64,
        targets: Option<Vec<Principal>>,
        permissions: Option<WirePermissions>,
    }
    #[derive(CandidType)]
    struct WireSignedDelegation {
        delegation: WireDelegation,
        signature: Vec<u8>,
    }

    // Lock in the mcp_get_delegation permission contract: II's `Delegation`
    // carries `permissions: opt variant { queries; all }`, and it must round-trip
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

        let bytes = Encode!(&make(Some(WirePermissions::Queries))).expect("encode");
        let agent = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(agent.delegation.permissions, Some(DelegationPermissions::Queries));

        let bytes = Encode!(&make(Some(WirePermissions::All))).expect("encode");
        let agent = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(agent.delegation.permissions, Some(DelegationPermissions::All));

        // An unrestricted (absent) permission decodes and forwards as None,
        // hashing identically to a pre-0.48 delegation.
        let bytes = Encode!(&make(None)).expect("encode");
        let agent = Decode!(&bytes, IiSignedDelegation)
            .expect("decode")
            .into_agent(&app_key)
            .expect("into_agent");
        assert_eq!(agent.delegation.permissions, None);
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
                permissions: Some(WirePermissions::Queries),
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
}
