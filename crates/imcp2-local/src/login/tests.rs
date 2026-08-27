//! Offline tests of the login flow: the driver's single-flight and status
//! lifecycle, and the listener driven like the browser (and like an
//! attacker) over real HTTP.

use super::*;
use imcp2_core::iiconnect::AUTH_CALLBACKS_WELL_KNOWN;
use imcp2_core::IiInstance;

/// A driver against the real mainnet/prod-II config — nothing here touches
/// the network (agent construction, key minting, and the loopback listener
/// are all local), which is exactly what these tests rely on.
fn test_driver() -> (LoginDriver, SessionSlot) {
    let agent = imcp2_core::Agent::builder()
        .with_url(imcp2_core::IC_URL)
        .build()
        .expect("agent");
    let identities = Identities::new(
        IiInstance::prod().expect("prod II instance"),
        "https://mcp.internetcomputer.org".into(),
        agent,
    );
    let slot = SessionSlot::new();
    (
        LoginDriver::new(identities, slot.clone(), /* auto_open */ false),
        slot,
    )
}

/// A shape-valid two-hop chain (the same wire shape as iiconnect's parser
/// tests) whose signatures are garbage: it must get PAST parsing and be
/// rejected by the redeem path itself — offline, before any network call.
fn fake_chain_json() -> String {
    serde_json::json!({
        "delegations": [
            {
                "delegation": { "pubkey": "070707", "expiration": "66", "targets": ["aaaaa-aa"] },
                "signature": "040506",
            },
            {
                "delegation": { "pubkey": "09080706", "expiration": "66" },
                "signature": "010909",
            },
        ],
        "publicKey": "010203",
    })
    .to_string()
}

// One `authenticate` = one flow: a fresh id.ai link over a fresh loopback
// callback; a second call while it is pending returns the SAME link
// (single-flight) rather than racing a second listener. The session slot
// stays empty until a redeem succeeds — starting a login signs nobody in.
#[tokio::test]
async fn begin_mints_one_flow_and_repeats_it_while_pending() {
    let (driver, slot) = test_driver();
    let BeginOutcome::Pending { url, fresh } = driver.begin(false).await.expect("begin") else {
        panic!("a fresh driver must start a flow, not report a session")
    };
    assert!(fresh);
    assert!(url.starts_with("https://id.ai/mcp#callback="), "{url}");
    assert!(
        url.contains("http%3A%2F%2F127.0.0.1%3A"),
        "loopback callback in the fragment: {url}"
    );
    assert!(url.contains("&ttl=3600&registration_key="), "{url}");

    let BeginOutcome::Pending { url: again, fresh } = driver.begin(false).await.expect("begin")
    else {
        panic!("a pending flow must be returned, not replaced")
    };
    assert!(!fresh, "the second call must join the pending flow");
    assert_eq!(again, url, "same link while the handshake is pending");

    assert_eq!(slot.get(), None, "no session until a redeem succeeds");
    assert!(matches!(driver.status().await, LoginStatus::Pending { .. }));
}

// The transient listener's whole surface, driven like the browser: the
// pinned page (strict CSP + the hosted server's hardening headers, script
// pointed at /redeem), and the #4091 allow-list (this callback verbatim,
// CORS-readable, never cached).
#[tokio::test]
async fn the_listener_serves_the_pinned_page_and_the_allow_list() {
    let (driver, _slot) = test_driver();
    driver.begin(false).await.expect("begin");
    let (_, callback_url) = driver.pending_handshake().await.expect("pending");
    let origin = callback_url.strip_suffix("/callback").unwrap().to_string();
    let http = reqwest::Client::new();

    let page = http.get(&callback_url).send().await.expect("GET /callback");
    assert_eq!(page.status(), 200);
    let csp = page
        .headers()
        .get("content-security-policy")
        .expect("pinned page ships a CSP")
        .to_str()
        .unwrap()
        .to_string();
    assert!(csp.contains("default-src 'none'"), "{csp}");
    for (name, want) in [
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ] {
        assert_eq!(
            page.headers().get(name).and_then(|v| v.to_str().ok()),
            Some(want)
        );
    }
    let html = page.text().await.unwrap();
    assert!(
        html.contains("/redeem"),
        "the script must POST to this listener's redeem"
    );
    assert!(
        html.contains("data.done"),
        "the local success arm must be in the shipped page"
    );

    let wk = http
        .get(format!("{origin}{AUTH_CALLBACKS_WELL_KNOWN}"))
        .send()
        .await
        .expect("GET allow-list");
    assert_eq!(wk.status(), 200);
    assert_eq!(
        wk.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "II fetches the allow-list cross-origin"
    );
    assert_eq!(
        wk.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "fail-closed infrastructure must never be served stale"
    );
    let doc: serde_json::Value = wk.json().await.unwrap();
    assert_eq!(
        doc,
        serde_json::json!({ "callbacks": [callback_url] }),
        "the declared callback must equal the link's callback VERBATIM (exact-match)"
    );
}

// The redeem's refusal paths, in order: an unknown `state` (or one from a
// replaced flow), a delegation the parser rejects, and a shape-valid chain
// with garbage signatures that the redeem itself rejects — all 400 with an
// {"error"} body the pinned page renders, all offline, and none of them
// consumes the pending flow (a genuine retry stays possible).
#[tokio::test]
async fn redeem_refuses_bad_deliveries_and_keeps_the_flow_retryable() {
    let (driver, slot) = test_driver();
    let BeginOutcome::Pending { url, .. } = driver.begin(false).await.expect("begin") else {
        panic!("fresh flow")
    };
    let (state, callback_url) = driver.pending_handshake().await.expect("pending");
    let origin = callback_url.strip_suffix("/callback").unwrap().to_string();
    let redeem_url = format!("{origin}/redeem");
    let http = reqwest::Client::new();

    let post = |body: serde_json::Value| {
        let http = http.clone();
        let redeem_url = redeem_url.clone();
        async move {
            http.post(&redeem_url)
                .json(&body)
                .send()
                .await
                .expect("POST /redeem")
        }
    };

    let r = post(serde_json::json!({ "state": "someone-else", "delegation": "" })).await;
    assert_eq!(r.status(), 400);
    let e: serde_json::Value = r.json().await.unwrap();
    assert!(
        e["error"]
            .as_str()
            .unwrap()
            .contains("unknown or already used"),
        "{e}"
    );

    let r = post(serde_json::json!({ "state": state, "delegation": "not json" })).await;
    assert_eq!(r.status(), 400);
    let e: serde_json::Value = r.json().await.unwrap();
    assert!(
        e["error"]
            .as_str()
            .unwrap()
            .contains("couldn't read the sign-in response"),
        "{e}"
    );

    let r = post(serde_json::json!({ "state": state, "delegation": fake_chain_json() })).await;
    assert_eq!(
        r.status(),
        400,
        "garbage signatures must be rejected by the redeem"
    );
    let e: serde_json::Value = r.json().await.unwrap();
    assert!(e["error"].is_string(), "{e}");

    assert_eq!(slot.get(), None, "no failure may fill the session slot");
    let BeginOutcome::Pending { url: still, fresh } = driver.begin(false).await.expect("begin")
    else {
        panic!("the flow must survive failed redeems")
    };
    assert!(!fresh, "failed redeems must not consume the pending flow");
    assert_eq!(still, url);
}

// The status lifecycle around a grant (injected directly — a real one
// needs live II): live grant → SignedIn with the wallclock math; past
// expiration → Expired, still naming the principal; a fresh driver is
// simply SignedOut.
#[tokio::test]
async fn status_reports_the_grant_lifecycle() {
    let (driver, _slot) = test_driver();
    assert!(matches!(driver.status().await, LoginStatus::SignedOut));

    let grant = |expiration_ns: u64| Grant {
        session_id: "sess".into(),
        principal: Some("aaaaa-aa".into()),
        permissions: "queries",
        expiration_ns,
    };
    driver.inner.state.lock().await.grant = Some(grant(now_ns() + 30 * 60_000_000_000));
    match driver.status().await {
        LoginStatus::SignedIn(g) => {
            assert!(
                (25..=30).contains(&g.minutes_left()),
                "{}",
                g.minutes_left()
            );
        }
        _ => panic!("a live grant must report SignedIn"),
    }

    driver.inner.state.lock().await.grant = Some(grant(now_ns() - 1));
    match driver.status().await {
        LoginStatus::Expired(g) => assert_eq!(g.principal.as_deref(), Some("aaaaa-aa")),
        _ => panic!("a past-expiry grant must report Expired"),
    }
}

// `authenticate(refresh: true)` while a live grant exists: the truthful
// status is the PENDING replacement handshake, not the old "signed in" —
// otherwise the client reads the refresh as already complete (the same
// precedence `begin` applies).
#[tokio::test]
async fn a_pending_refresh_outranks_the_live_grant_in_status() {
    let (driver, _slot) = test_driver();
    driver.inner.state.lock().await.grant = Some(Grant {
        session_id: "old".into(),
        principal: Some("aaaaa-aa".into()),
        permissions: "all",
        expiration_ns: now_ns() + 30 * 60_000_000_000,
    });
    assert!(matches!(driver.status().await, LoginStatus::SignedIn(_)));

    let BeginOutcome::Pending { fresh, .. } = driver.begin(true).await.expect("refresh") else {
        panic!("refresh=true must start a replacement flow past a live grant")
    };
    assert!(fresh);
    assert!(
        matches!(driver.status().await, LoginStatus::Pending { .. }),
        "a live replacement handshake must outrank the old grant"
    );
}

// Anti-DNS-rebinding (the design's loopback hardening): a request whose
// `Host` names anything but this listener's own `127.0.0.1:<port>` is
// rejected before routing — a rebinding page fetches this port with the
// attacker's hostname in `Host`, which is exactly what must bounce. The
// true authority (what every handed-out URL carries) passes untouched.
// II's frontend is a PUBLIC https origin fetching this listener on loopback,
// which Chrome treats as a private-network request: it preflights with
// `Access-Control-Request-Private-Network: true` and blocks the fetch unless
// the answer carries `Access-Control-Allow-Private-Network: true`. A 405 here
// (routes registered for GET/POST only) makes the #4091 allow-list unreadable
// from the browser and every connect fails as "missing information" — while
// curl and the e2e harness, which never preflight, see a healthy 200. Hence a
// RAW preflight, the only shape that reproduces it.
#[tokio::test]
async fn the_listener_answers_the_private_network_preflight() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (driver, _slot) = test_driver();
    driver.begin(false).await.expect("begin");
    let (_, callback_url) = driver.pending_handshake().await.expect("pending");
    let authority = callback_url
        .strip_prefix("http://")
        .and_then(|s| s.strip_suffix("/callback"))
        .expect("authority");
    let port: u16 = authority.split(':').nth(1).unwrap().parse().unwrap();

    for path in ["/.well-known/ii-auth-callbacks", "/callback"] {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        stream
            .write_all(
                format!(
                    "OPTIONS {path} HTTP/1.1\r\nHost: {authority}\r\n\
                     Origin: https://id.ai\r\nAccess-Control-Request-Method: GET\r\n\
                     Access-Control-Request-Private-Network: true\r\n\
                     Connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");
        let lowered = response.to_lowercase();
        assert!(
            response.contains("204") || response.contains("200"),
            "{path} preflight must succeed, got: {response}"
        );
        assert!(
            lowered.contains("access-control-allow-private-network: true"),
            "{path} preflight must grant private-network access, got: {response}"
        );
        assert!(
            lowered.contains("access-control-allow-origin: *"),
            "{path} preflight must allow II's origin, got: {response}"
        );
    }
}

#[tokio::test]
async fn the_listener_rejects_foreign_host_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (driver, _slot) = test_driver();
    driver.begin(false).await.expect("begin");
    let (_, callback_url) = driver.pending_handshake().await.expect("pending");
    let authority = callback_url
        .strip_prefix("http://")
        .and_then(|s| s.strip_suffix("/callback"))
        .expect("authority");
    let port: u16 = authority.split(':').nth(1).unwrap().parse().unwrap();

    let request = |host: String| async move {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        stream
            .write_all(
                format!("GET /callback HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).await.expect("read");
        response
            .split_whitespace()
            .nth(1)
            .expect("status code")
            .to_string()
    };

    assert_eq!(
        request("attacker.example".into()).await,
        "403",
        "rebound hostname"
    );
    assert_eq!(
        request(format!("localhost:{port}")).await,
        "403",
        "even localhost: only the one advertised authority is served"
    );
    assert_eq!(
        request(authority.to_string()).await,
        "200",
        "the true authority passes"
    );
}

// The session slot is shared and REPLACEABLE: it starts empty (signed
// out), a login fills it, and a re-login (fresh session id, per the II
// fresh-session-key contract) replaces it — through every clone and
// through the resolver handed to IcTools, since clones share the holder.
// This is what makes reauthentication after grant expiry a same-process
// step.
#[test]
fn the_session_slot_is_shared_and_replaceable() {
    let slot = SessionSlot::new();
    let reader = slot.clone();
    assert_eq!(reader.get(), None, "a fresh slot is signed out");
    let hour_from_now = now_ns() + 3_600_000_000_000;
    slot.set("sess-1".into(), hour_from_now);
    assert_eq!(reader.get(), Some("sess-1".into()), "clones share the slot");
    slot.set("sess-2".into(), hour_from_now);
    assert_eq!(
        reader.get(),
        Some("sess-2".into()),
        "a re-login replaces the id"
    );
    // Expiry-aware: the moment the grant lapses, the slot reports NO session
    // — tools return sign-in guidance instead of acting on a dead session,
    // regardless of when the 60-second reaper gets to the server-side state.
    slot.set("sess-3".into(), now_ns() - 1);
    assert_eq!(reader.get(), None, "an expired grant is signed out");
}

// The handshake window is exactly HANDSHAKE_TTL: a pending flow older than
// that is expired (the watchdog and the redeem gate both read this).
#[test]
fn pending_expires_after_the_handshake_ttl() {
    let pending = |age: Duration| Pending {
        session_id: "s".into(),
        url: "u".into(),
        callback_url: "c".into(),
        started: Instant::now() - age,
        redeeming: false,
        shutdown: Arc::new(Notify::new()),
    };
    assert!(!pending(Duration::from_secs(1)).expired());
    assert!(pending(HANDSHAKE_TTL + Duration::from_secs(1)).expired());
}
