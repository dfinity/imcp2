//! Real Internet-Identity ↔ MCP connect-handshake test, end to end against a
//! **live Internet Identity canister** running in PocketIC. Nothing is mocked:
//! II runs its production wasm, issues a genuine canister-signed registration
//! delegation, and the real [`crate::McpServer`] redeems it (`mcp_register_v2`)
//! through its own `ic-agent`, verifying the canister signature against
//! PocketIC's fetched root key — exactly the production redeem path.
//!
//! ## What it exercises for real
//! Register an II anchor → trust the MCP server (`mcp_set_config`) → the II
//! registration-delegation ceremony (`prepare_mcp_registration_delegation` +
//! `get_mcp_registration_delegation`, playing the browser/frontend) → feed the
//! **real** delegation to the server's `/oauth/connect/redeem` → the server
//! signs `mcp_register_v2` on the live II → `/oauth/token` → the minted bearer
//! token authenticates (`session_for_token`). Only the human's browser clicks
//! are stood in for; every canister interaction and every signature is genuine.
//!
//! ## Gating (default `cargo test` is untouched and offline)
//! Behind the `e2e` cargo feature (so `pocket-ic` is neither compiled nor
//! downloaded by the default build) AND a runtime guard that skips unless both
//! artifacts — which cargo does not fetch — are provided:
//!
//! ```text
//! II_WASM=/abs/internet_identity_backend.wasm.gz \   # release asset, gz as-is
//! POCKET_IC_BIN=/abs/pocket-ic \                      # pocket-ic v15 server
//!   cargo test --features e2e -- --nocapture
//! ```
//!
//! The candid types below are hand-rolled from `internet_identity.did` at tag
//! `release-2026-07-17` (rather than a git dependency) so the crate stays
//! self-contained. `InternetIdentityInit` is declared minimally — all its fields
//! are `opt`, so a record carrying only `captcha_config` is a valid candid
//! subtype and II fills the rest with `null`.

// The hand-rolled candid types mirror II's `.did` in full for wire fidelity, so
// some variants/fields are declared but never constructed on our send path.
#![allow(dead_code)]

use candid::{CandidType, Decode, Encode, Principal};
use http_body_util::BodyExt;
use serde::Deserialize;
use std::time::SystemTime;
use tower::ServiceExt;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};

// ---- II candid interface (subset), from internet_identity.did @ release-2026-07-17 ----

/// `type Permissions = variant { queries; all }`.
#[derive(CandidType, Deserialize, Clone, Copy)]
enum Permissions {
    #[serde(rename = "queries")]
    Queries,
    #[serde(rename = "all")]
    All,
}

/// `type McpConfig = record { enabled : bool; url : opt text }`.
#[derive(CandidType)]
struct McpConfig {
    enabled: bool,
    url: Option<String>,
}

/// `type Delegation = record { pubkey; expiration; targets : opt vec principal;
/// permissions : opt text }`. The delegation record's `permissions` is `opt
/// text` ("queries" = read-only, absent = unrestricted) — deliberately NOT the
/// named `Permissions` variant above (that variant is only the `prepare_…`
/// argument / `mcp_register_v2` reply). Mixing them up is the II #40 outage
/// class; the registration delegation returns this field absent (`None`).
#[derive(CandidType, Deserialize)]
struct Delegation {
    pubkey: Vec<u8>,
    expiration: u64,
    targets: Option<Vec<Principal>>,
    permissions: Option<String>,
}

/// `type SignedDelegation = record { delegation; signature }`.
#[derive(CandidType, Deserialize)]
struct SignedDelegation {
    delegation: Delegation,
    signature: Vec<u8>,
}

/// `Ok` payload of `prepare_mcp_registration_delegation`.
#[derive(CandidType, Deserialize)]
struct PrepareMcpRegistrationDelegation {
    user_key: Vec<u8>,
    expiration: u64,
}

/// `type Challenge = record { png_base64 : text; challenge_key : text }`.
#[derive(CandidType, Deserialize)]
struct Challenge {
    #[allow(dead_code)]
    png_base64: String,
    challenge_key: String,
}

/// `type ChallengeResult = record { key : text; chars : text }`.
#[derive(CandidType)]
struct ChallengeResult {
    key: String,
    chars: String,
}

#[derive(CandidType, Deserialize)]
enum Purpose {
    #[serde(rename = "recovery")]
    Recovery,
    #[serde(rename = "authentication")]
    Authentication,
}

#[derive(CandidType, Deserialize)]
enum KeyType {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross_platform")]
    CrossPlatform,
    #[serde(rename = "seed_phrase")]
    SeedPhrase,
    #[serde(rename = "browser_storage_key")]
    BrowserStorageKey,
}

#[derive(CandidType, Deserialize)]
enum DeviceProtection {
    #[serde(rename = "protected")]
    Protected,
    #[serde(rename = "unprotected")]
    Unprotected,
}

/// `type MetadataMap = vec record { text; variant { map; string; bytes } }` —
/// recursive; only needed so `DeviceData.metadata` has a type (we send `null`).
#[derive(CandidType, Deserialize)]
enum MetadataVal {
    #[serde(rename = "map")]
    Map(Vec<(String, MetadataVal)>),
    #[serde(rename = "string")]
    String(String),
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
}

/// `type DeviceData = record { ... }`.
#[derive(CandidType)]
struct DeviceData {
    pubkey: Vec<u8>,
    alias: String,
    credential_id: Option<Vec<u8>>,
    aaguid: Option<Vec<u8>>,
    purpose: Purpose,
    key_type: KeyType,
    protection: DeviceProtection,
    origin: Option<String>,
    metadata: Option<Vec<(String, MetadataVal)>>,
}

/// `type RegisterResponse = variant { registered : record { user_number }; canister_full; bad_challenge }`.
#[derive(CandidType, Deserialize)]
enum RegisterResponse {
    #[serde(rename = "registered")]
    Registered { user_number: u64 },
    #[serde(rename = "canister_full")]
    CanisterFull,
    #[serde(rename = "bad_challenge")]
    BadChallenge,
}

// -- Install init arg (captcha disabled). All II init fields are `opt`, so a
//    one-field record is a valid subtype. --

#[derive(CandidType)]
enum StaticCaptchaTrigger {
    CaptchaEnabled,
    CaptchaDisabled,
}

#[derive(CandidType)]
enum CaptchaTrigger {
    Dynamic {
        threshold_pct: u16,
        current_rate_sampling_interval_s: u64,
        reference_rate_sampling_interval_s: u64,
    },
    Static(StaticCaptchaTrigger),
}

#[derive(CandidType)]
struct CaptchaConfig {
    max_unsolved_captchas: u64,
    captcha_trigger: CaptchaTrigger,
}

#[derive(CandidType)]
struct InternetIdentityInit {
    captcha_config: Option<CaptchaConfig>,
}

// ---- II test-anchor helpers (mirroring canister_tests::framework) ----

/// The device pubkey II's test helpers use; not a real DER key, accepted only
/// because the registration captcha is disabled by the install arg.
const DEVICE_PUBKEY: &[u8] = b"test";

/// `principal_1()` = the device principal that authorizes anchor operations.
fn principal_1() -> Principal {
    Principal::self_authenticating(DEVICE_PUBKEY)
}

fn device_data_1() -> DeviceData {
    DeviceData {
        pubkey: DEVICE_PUBKEY.to_vec(),
        alias: "e2e device".to_string(),
        credential_id: None,
        aaguid: None,
        purpose: Purpose::Authentication,
        key_type: KeyType::CrossPlatform,
        protection: DeviceProtection::Unprotected,
        origin: None,
        metadata: None,
    }
}

/// Register a fresh anchor (captcha disabled ⇒ the accepted solution is "a").
async fn register_anchor(pic: &pocket_ic::nonblocking::PocketIc, ii: Principal) -> u64 {
    let bytes = pic
        .update_call(ii, Principal::anonymous(), "create_challenge", Encode!().unwrap())
        .await
        .expect("create_challenge");
    let challenge = Decode!(&bytes, Challenge).unwrap();
    let attempt = ChallengeResult {
        key: challenge.challenge_key,
        chars: "a".to_string(),
    };
    let bytes = pic
        .update_call(
            ii,
            principal_1(),
            "register",
            Encode!(&device_data_1(), &attempt, &Option::<Principal>::None).unwrap(),
        )
        .await
        .expect("register");
    match Decode!(&bytes, RegisterResponse).unwrap() {
        RegisterResponse::Registered { user_number } => user_number,
        RegisterResponse::CanisterFull => panic!("register: canister full"),
        RegisterResponse::BadChallenge => panic!("register: bad challenge (captcha not disabled?)"),
    }
}

// ---- HTTP helpers (drive the real router, like tests/routers.rs) ----

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Pull `key=value` out of a `&`-separated fragment/query (values are base64url
/// or plain text here — none contain `&`).
fn field<'a>(blob: &'a str, key: &str) -> Option<&'a str> {
    blob.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// Restores (or clears) the process-global `OAUTH_CLIENTS_FILE` on drop — even on
/// a panic-unwind — so this test's override can't leak into other test threads
/// running in parallel, and removes the temp file it pointed at.
struct ClientsFileEnvGuard {
    prev: Option<std::ffi::OsString>,
    path: std::path::PathBuf,
}

impl Drop for ClientsFileEnvGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => std::env::set_var("OAUTH_CLIENTS_FILE", v),
            None => std::env::remove_var("OAUTH_CLIENTS_FILE"),
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[tokio::test]
async fn registration_delegation_end_to_end() {
    // Runtime guard: skip cleanly unless the un-fetchable artifacts are provided.
    let (Ok(ii_wasm_path), Ok(_)) =
        (std::env::var("II_WASM"), std::env::var("POCKET_IC_BIN"))
    else {
        eprintln!(
            "skipping registration_delegation_end_to_end: set II_WASM (internet_identity \
             release .wasm.gz) and POCKET_IC_BIN (pocket-ic v15 server) to run it"
        );
        return;
    };
    let ii_wasm = std::fs::read(&ii_wasm_path).expect("read II_WASM (gz bytes; PocketIC gunzips)");

    // Isolate the OAuth client store: a UNIQUE temp file (so concurrent runs
    // never collide on a fixed name) plus a guard that restores/clears the
    // process-global `OAUTH_CLIENTS_FILE` on drop — even on a panic — so the
    // override can't leak into other test threads.
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut clients_file = std::env::temp_dir();
    clients_file.push(format!(
        "imcp2-e2e-oauth-clients-{}-{nanos}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&clients_file);
    let _clients_env = ClientsFileEnvGuard {
        prev: std::env::var_os("OAUTH_CLIENTS_FILE"),
        path: clients_file.clone(),
    };
    std::env::set_var("OAUTH_CLIENTS_FILE", &clients_file);

    // --- PocketIC + live II ---
    let mut pic = pocket_ic::PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    // Fresh instances boot at a 2021 mock clock; align to now BEFORE minting the
    // (~5-min) registration delegation, or it is already expired.
    pic.set_time(SystemTime::now().into()).await;
    pic.tick().await;

    let ii = pic.create_canister().await;
    pic.add_cycles(ii, 2_000_000_000_000).await;
    let init = InternetIdentityInit {
        captcha_config: Some(CaptchaConfig {
            max_unsolved_captchas: 500,
            captcha_trigger: CaptchaTrigger::Static(StaticCaptchaTrigger::CaptchaDisabled),
        }),
    };
    pic.install_canister(ii, ii_wasm, Encode!(&Some(init)).unwrap(), None)
        .await;

    // Expose the gateway and point the server's OWN injected agent at it.
    let gateway = pic.make_live(None).await;
    let agent = crate::Agent::builder()
        .with_url(gateway.as_str())
        .build()
        .expect("build agent");
    agent.fetch_root_key().await.expect("fetch PocketIC root key");

    // --- The real MCP server, injected with the PocketIC-backed agent ---
    let public_url = "http://localhost:8000"; // http ⇒ the sid cookie is not `Secure`
    let server = crate::McpServer::new(crate::McpConfig {
        agent,
        instance: crate::IiInstance {
            name: "e2e",
            ii_url: gateway.to_string(),
            ii_canister: ii,
        },
        public_url: public_url.into(),
        mcp_path: "/mcp".into(),
        clients: crate::SharedClients::load(),
        // The handshake under test carries no `resource`; keep it lenient.
        require_resource: false,
    });
    let app = axum::Router::new()
        .nest_service(server.mcp_path(), server.mcp_router())
        .merge(server.well_known_router());

    // --- 1. Register a loopback OAuth client (loopback is always permitted) ---
    let redirect_uri = "http://127.0.0.1:6112/cb";
    let resp = app
        .clone()
        .oneshot(
            Request::post("/mcp/oauth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "redirect_uris": [redirect_uri] }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "register status: {}", resp.status());
    let client_id = body_json(resp).await["client_id"].as_str().unwrap().to_string();

    // --- 2. Authorize: mints X for this connect; returns state + registration_key + cookie ---
    // RFC 7636 test vector (challenge = S256(verifier)); avoids hashing here.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let authorize_url = format!(
        "/mcp/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect_uri}&code_challenge={challenge}&code_challenge_method=S256"
    );
    let resp = app
        .clone()
        .oneshot(Request::get(&authorize_url).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND, "authorize should 302 to II");
    let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    let set_cookie = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
    // Everything the server put in the II connect link rides the fragment.
    let fragment = location.split_once('#').expect("connect link fragment").1;
    let state = field(fragment, "state").expect("state").to_string();
    let reg_key_b64 = field(fragment, "registration_key").expect("registration_key");
    // pub(X) as II expects it (DER). base64url no-pad, per registration_pubkey_b64.
    let reg_key_x = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        reg_key_b64,
    )
    .expect("decode registration_key");
    // The initiator cookie `mcp_connect=<value>` (not Secure over http).
    let cookie_val = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.trim().strip_prefix(&format!("{}=", crate::auth::CONNECT_COOKIE)))
        .expect("mcp_connect cookie")
        .to_string();

    // --- 3. The registration-delegation ceremony (browser/frontend role) ---
    let anchor = register_anchor(&pic, ii).await;
    // Trust this MCP server for the anchor (precondition for `prepare`).
    let set_cfg = pic
        .update_call(
            ii,
            principal_1(),
            "mcp_set_config",
            Encode!(
                &anchor,
                &McpConfig {
                    enabled: true,
                    url: Some(format!("{public_url}/mcp")),
                }
            )
            .unwrap(),
        )
        .await
        .expect("mcp_set_config call");
    Decode!(&set_cfg, Result<(), String>).unwrap().expect("mcp_set_config Ok");

    // prepare: consent (full access, 24h grant) is recorded server-side, keyed
    // by the P_reg the canister returns as `user_key`.
    const GRANT_TTL_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
    let prep_bytes = pic
        .update_call(
            ii,
            principal_1(),
            "prepare_mcp_registration_delegation",
            Encode!(
                &anchor,
                &reg_key_x,
                &Some(Permissions::All),
                &Some(GRANT_TTL_NS)
            )
            .unwrap(),
        )
        .await
        .expect("prepare call");
    let prepared = Decode!(&prep_bytes, Result<PrepareMcpRegistrationDelegation, String>)
        .unwrap()
        .expect("prepare Ok");

    // get: the single canister-signed hop P_reg -> X.
    let get_bytes = pic
        .query_call(
            ii,
            principal_1(),
            "get_mcp_registration_delegation",
            Encode!(&anchor, &reg_key_x, &prepared.user_key, &prepared.expiration).unwrap(),
        )
        .await
        .expect("get call");
    let signed = Decode!(&get_bytes, Result<SignedDelegation, String>)
        .unwrap()
        .expect("get Ok");
    assert_eq!(signed.delegation.pubkey, reg_key_x, "delegation targets our X");

    // Serialize into the agent-js DelegationChain JSON the server parses: hex
    // byte fields, HEX-string expiration, publicKey = der(P_reg). No permissions
    // field (parser is deny_unknown_fields); targets only if II set them.
    let mut delegation = serde_json::json!({
        "pubkey": hex::encode(&signed.delegation.pubkey),
        "expiration": format!("{:x}", signed.delegation.expiration),
    });
    if let Some(targets) = &signed.delegation.targets {
        delegation["targets"] =
            serde_json::Value::from(targets.iter().map(|p| p.to_text()).collect::<Vec<_>>());
    }
    let chain_json = serde_json::json!({
        "publicKey": hex::encode(&prepared.user_key),
        "delegations": [{ "delegation": delegation, "signature": hex::encode(&signed.signature) }],
    })
    .to_string();

    // --- 4. Redeem: the REAL server signs mcp_register_v2 on the live II ---
    let resp = app
        .clone()
        .oneshot(
            Request::post("/mcp/oauth/connect/redeem")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, format!("{}={cookie_val}", crate::auth::CONNECT_COOKIE))
                .body(Body::from(
                    serde_json::json!({ "state": state, "delegation": chain_json }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "redeem should succeed against live II");
    let redirect = body_json(resp).await["redirect"].as_str().unwrap().to_string();
    assert!(redirect.starts_with(redirect_uri), "redirect to the client: {redirect}");
    let query = redirect.split_once('?').expect("redirect query").1;
    let code = field(query, "code").expect("authorization code").to_string();

    // --- 5. Token: exchange the code (PKCE S256) for a bearer access token ---
    let resp = app
        .clone()
        .oneshot(
            Request::post("/mcp/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&client_id={client_id}&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token exchange should succeed");
    let tok = body_json(resp).await;
    let access_token = tok["access_token"].as_str().expect("access_token").to_string();
    assert_eq!(tok["token_type"], "Bearer");
    // TTL tracks the II grant (never outlives it): positive, ~24h.
    let expires_in = tok["expires_in"].as_u64().expect("expires_in");
    assert!(expires_in > 0 && expires_in <= GRANT_TTL_NS / 1_000_000_000, "TTL tracks grant: {expires_in}");

    // --- 6. The minted token authenticates and resolves to this connect ---
    let (principal, session_id) = server
        .store
        .session_for_token(&access_token)
        .await
        .expect("the minted token must authenticate");
    assert_eq!(session_id, state);
    assert_eq!(
        Some(principal),
        server.identities.session_principal(&state).await,
        "token principal == self_authenticating(session key S)"
    );

    // Bonus: a Bearer request clears the require_token gate (not 401).
    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED, "valid token must pass require_token");
}
