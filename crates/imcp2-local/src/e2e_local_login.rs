//! Real Internet-Identity ↔ **local login** test, end to end against a live
//! Internet Identity canister running in PocketIC — the local-replica test
//! configuration of the design's component 3, extending the hosted crate's
//! e2e harness (`imcp2/src/e2e_handshake.rs`) to this binary's browser
//! handshake. Nothing is mocked: II runs its production wasm and issues a
//! genuine canister-signed registration delegation; the login driver binds
//! its real loopback listener; this test plays the browser over **real HTTP**
//! (the pinned callback page, the redeem POST);
//! and the driver redeems via `mcp_register_v2` on the live II, verifying the
//! canister signature against PocketIC's fetched root key.
//!
//! ## What it exercises for real
//! `authenticate` (a fresh session + the id.ai-shaped link + the transient
//! listener) → the pinned page served over the wire → the
//! II registration-delegation ceremony (`prepare_mcp_registration_delegation`
//! + `get_mcp_registration_delegation`, playing II's frontend) → the **real**
//! delegation POSTed to the listener's `/redeem` → `{"done": true}` → the
//! session slot filled, `auth_status` signed in, and the listener torn down.
//! Only the human's browser clicks are stood in for.
//!
//! ## Gating (default `cargo test` is untouched and offline)
//! Behind the `e2e` cargo feature (so `pocket-ic` is neither compiled nor
//! downloaded by the default build) AND a runtime guard that skips unless
//! both artifacts — which cargo does not fetch — are provided:
//!
//! ```text
//! II_WASM=/abs/internet_identity_backend.wasm.gz \   # release asset, gz as-is
//! POCKET_IC_BIN=/abs/pocket-ic \                      # pocket-ic v15 server
//!   cargo test -p imcp2-local --features e2e -- --nocapture
//! ```
//!
//! The candid types below are hand-rolled from `internet_identity.did` (the
//! same subset, at the same tag, as the hosted harness) so the crate stays
//! self-contained.

// The hand-rolled candid types mirror II's `.did` in full for wire fidelity,
// so some variants/fields are declared but never constructed on our send path.
#![allow(dead_code)]

use candid::{CandidType, Decode, Encode, Principal};
use serde::Deserialize;
use std::time::SystemTime;

use crate::login::{BeginOutcome, LoginDriver, LoginStatus, SessionSlot};
use imcp2_core::identities::Identities;
use imcp2_core::IiInstance;

// ---- II candid interface (subset), as in the hosted harness ----------------

/// `type Permissions = variant { queries; all }`.
#[derive(CandidType, Deserialize, Clone, Copy)]
enum Permissions {
    #[serde(rename = "queries")]
    Queries,
    #[serde(rename = "all")]
    All,
}

/// `type McpConfig = record { enabled : bool; url : opt text }` — II's record
/// of the user's trusted MCP server, a precondition for `prepare_…`.
#[derive(CandidType)]
struct McpConfig {
    enabled: bool,
    url: Option<String>,
}

/// `type Delegation = record { pubkey; expiration; targets : opt vec principal;
/// permissions : opt text }` (the registration delegation returns
/// `permissions` absent).
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

/// `type MetadataMap` — recursive; only needed so `DeviceData.metadata` has a
/// type (we send `null`).
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

/// `type RegisterResponse = variant { registered : record { user_number };
/// canister_full; bad_challenge }`.
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

// ---- II test-anchor helpers (as in the hosted harness) ---------------------

/// The device pubkey II's test helpers use; not a real DER key, accepted only
/// because the registration captcha is disabled by the install arg.
const DEVICE_PUBKEY: &[u8] = b"test";

/// The device principal that authorizes anchor operations.
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
    let attempt = ChallengeResult { key: challenge.challenge_key, chars: "a".to_string() };
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

/// Pull `key=value` out of a `&`-separated fragment (values are base64url or
/// plain text here — none contain `&`).
fn field<'a>(blob: &'a str, key: &str) -> Option<&'a str> {
    blob.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v)
}

#[tokio::test]
async fn local_login_end_to_end() {
    // Runtime guard: skip cleanly unless the un-fetchable artifacts are provided.
    let (Ok(ii_wasm_path), Ok(_)) = (std::env::var("II_WASM"), std::env::var("POCKET_IC_BIN"))
    else {
        eprintln!(
            "skipping local_login_end_to_end: set II_WASM (internet_identity release \
             .wasm.gz) and POCKET_IC_BIN (pocket-ic v15 server) to run it"
        );
        return;
    };
    let ii_wasm = std::fs::read(&ii_wasm_path).expect("read II_WASM (gz bytes; PocketIC gunzips)");

    // --- PocketIC + live II ---
    let mut pic = pocket_ic::PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    // Fresh instances boot at a 2021 mock clock; align to now BEFORE minting
    // the registration delegation, or it is already expired.
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
    pic.install_canister(ii, ii_wasm, Encode!(&Some(init)).unwrap(), None).await;

    // --- The local binary's composition, exactly as `serve()` wires it, but
    //     pointed at PocketIC's gateway (the component-3 test configuration:
    //     endpoint override + fetch_root_key against a loopback replica). ---
    let gateway = pic.make_live(None).await;
    let agent =
        imcp2_core::Agent::builder().with_url(gateway.as_str()).build().expect("build agent");
    agent.fetch_root_key().await.expect("fetch PocketIC root key");
    let identities = Identities::new(
        IiInstance {
            name: "e2e",
            ii_url: gateway.to_string().trim_end_matches('/').to_string(),
            ii_canister: ii,
        },
        "http://localhost:8000".into(), // management-identity origin; any fixed value
        agent,
    );
    let slot = SessionSlot::new();
    let driver = LoginDriver::new(identities.clone(), slot.clone(), /* auto_open */ false);

    // --- 1. `authenticate`: fresh session, live listener, the connect link ---
    let BeginOutcome::Pending { url, fresh } = driver.begin(false).await.expect("begin") else {
        panic!("a fresh driver must start a login flow");
    };
    assert!(fresh);
    let fragment = url.split_once('#').expect("connect link fragment").1;
    let state = field(fragment, "state").expect("state").to_string();
    let reg_key_x = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        field(fragment, "registration_key").expect("registration_key"),
    )
    .expect("decode registration_key");
    let (pending_sid, callback_url) = driver.pending_handshake().await.expect("pending");
    assert_eq!(pending_sid, state, "the link's state IS the session id");
    // The link's percent-encoded callback is the listener's own callback.
    let encoded_callback = field(fragment, "callback").expect("callback");
    assert_eq!(
        encoded_callback.replace("%3A", ":").replace("%2F", "/"),
        callback_url,
        "the fragment's callback must be the listener's callback"
    );
    let origin = callback_url.strip_suffix("/callback").expect("callback path").to_string();
    let http = reqwest::Client::new();

    // --- 2. The browser lands on the pinned page ---
    let page = http.get(&callback_url).send().await.expect("GET /callback");
    assert_eq!(page.status(), 200);
    assert!(
        page.headers().get("content-security-policy").is_some(),
        "the pinned page ships its CSP"
    );

    // --- 3. The II-side ceremony (browser/frontend role) ---
    let anchor = register_anchor(&pic, ii).await;
    // Trust a local server for the anchor (precondition for `prepare`). II
    // stores a local connector port-less, because the listener above binds a
    // fresh port per handshake; the canister keeps the string as given and
    // hashes it onto the registration entry, and it is II's frontend that
    // matches a callback against it.
    let set_cfg = pic
        .update_call(
            ii,
            principal_1(),
            "mcp_set_config",
            Encode!(&anchor, &McpConfig { enabled: true, url: Some("http://127.0.0.1".into()) })
                .unwrap(),
        )
        .await
        .expect("mcp_set_config call");
    Decode!(&set_cfg, Result<(), String>).unwrap().expect("mcp_set_config Ok");

    // prepare: consent (full access, 24h grant) is recorded server-side,
    // keyed by the P_reg the canister returns as `user_key`.
    const GRANT_TTL_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
    let prep_bytes = pic
        .update_call(
            ii,
            principal_1(),
            "prepare_mcp_registration_delegation",
            Encode!(&anchor, &reg_key_x, &Some(Permissions::All), &Some(GRANT_TTL_NS)).unwrap(),
        )
        .await
        .expect("prepare call");
    let prepared = Decode!(&prep_bytes, Result<PrepareMcpRegistrationDelegation, String>)
        .unwrap()
        .expect("prepare Ok");

    // get: the canister-signed hop toward our X.
    let get_bytes = pic
        .query_call(
            ii,
            principal_1(),
            "get_mcp_registration_delegation",
            Encode!(&anchor, &reg_key_x, &prepared.user_key, &prepared.expiration).unwrap(),
        )
        .await
        .expect("get call");
    let signed = Decode!(&get_bytes, Result<SignedDelegation, String>).unwrap().expect("get Ok");
    assert_eq!(signed.delegation.pubkey, reg_key_x, "delegation targets our X");

    // Serialize into the agent-js DelegationChain JSON the redeem parses: hex
    // byte fields, HEX-string expiration, publicKey = der(P_reg).
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

    // --- 4. The browser's redeem POST → the LOCAL success contract ---
    let resp = http
        .post(format!("{origin}/redeem"))
        .json(&serde_json::json!({ "state": state, "delegation": chain_json }))
        .send()
        .await
        .expect("POST /redeem");
    assert_eq!(resp.status(), 200, "redeem should succeed against live II");
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({ "done": true }),
        "the local redeem answers done (the page renders its terminal state)"
    );

    // --- 5. Signed in: the slot holds this session; status + principal agree ---
    assert_eq!(slot.get(), Some(state.clone()), "the session slot is filled");
    match driver.status().await {
        LoginStatus::SignedIn(g) => {
            assert_eq!(g.session_id, state);
            assert_eq!(g.permissions, "all", "the consent-time access level was recorded");
            assert!(g.minutes_left() > 0, "the 24h grant is live");
            assert_eq!(
                g.principal,
                identities.session_principal(&state).await,
                "auth_status reports the real session principal"
            );
        }
        _ => panic!("a completed redeem must report SignedIn"),
    }
    // A repeat `authenticate` now reports the live session instead of a link.
    match driver.begin(false).await.expect("begin") {
        BeginOutcome::AlreadySignedIn(g) => assert_eq!(g.session_id, state),
        BeginOutcome::Pending { .. } => panic!("a live grant must be reported, not replaced"),
    }

    // --- 6. The transient listener is torn down after the redeem ---
    let mut listener_down = false;
    for _ in 0..50 {
        match http.get(&callback_url).send().await {
            Err(_) => {
                listener_down = true;
                break;
            }
            Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
        }
    }
    assert!(listener_down, "the login listener must shut down once the grant landed");
}
