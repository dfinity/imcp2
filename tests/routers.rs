//! Router-level contract tests: two `McpServer` instances compose into the
//! deployed app shape, and the discovery documents, the 401 challenge, the
//! auth-callback allow-list, and the OAuth endpoints all follow each
//! instance's mount path.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

const PUBLIC_URL: &str = "https://mcp.example.com";

/// A throwaway operational-files directory for these tests, so they neither read
/// nor write a developer's real `oauth-clients.json`. The authorize-path
/// assertions rely on an EMPTY registration set (unknown/unregistered clients are
/// rejected); a stray real registration for `client_id=unknown`/`x` would flip
/// them, so the store file is cleared once. `SharedClients::load` treats a
/// missing file as empty, giving a deterministic empty set. One fixed directory,
/// shared by every `app()` in this binary.
fn test_state_dir() -> std::path::PathBuf {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let dir = std::env::temp_dir().join("imcp2-router-tests");
    ONCE.call_once(|| {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("oauth-clients.json")); // drop any stale file
    });
    dir
}

fn server(instance: imcp2::IiInstance, mcp_path: &str) -> imcp2::McpServer {
    let state_dir = test_state_dir();
    let agent = imcp2::Agent::builder().with_url(imcp2::IC_URL).build().expect("build agent");
    imcp2::McpServer::new(imcp2::McpConfig {
        agent,
        instance,
        public_url: PUBLIC_URL.into(),
        mcp_path: mcp_path.into(),
        clients: imcp2::SharedClients::load(&state_dir),
        state_dir,
        // Lenient: these router contract tests drive flows that don't carry a
        // `resource`; strict RFC 8707 is covered by the auth unit tests.
        require_resource: false,
    })
}

/// The composed app, shaped like the STAGING deployment binary (which serves
/// both instances): prod (the default instance, owning the root discovery
/// documents and sharing the origin-global auth-callback allow-list) at `/mcp`,
/// beta at `/mcp-beta`. A production deployment serves `/mcp` alone; composing
/// both here exercises the multi-instance routing contract.
fn app() -> Router {
    let prod = server(imcp2::IiInstance::prod().expect("prod"), "/mcp");
    let beta = server(imcp2::IiInstance::beta().expect("beta"), "/mcp-beta");
    Router::new()
        .nest_service(prod.mcp_path(), prod.mcp_router())
        .nest_service(beta.mcp_path(), beta.mcp_router())
        .merge(prod.well_known_router())
        .merge(beta.well_known_router())
        .merge(prod.root_well_known_router())
        .merge(imcp2::auth_callbacks_router(&[&prod, &beta]))
        .merge(imcp2::ii_app_metadata_router())
}

async fn get_json(app: Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app.oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn protected_resource_metadata_follows_each_mount() {
    // Prod (the default `/mcp` instance): served path-inserted (RFC 9728 §3.1)
    // and, as the default instance, at the plain root.
    for path in
        ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]
    {
        let (status, doc) = get_json(app(), path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        assert_eq!(doc["resource"], format!("{PUBLIC_URL}/mcp"), "GET {path}");
        assert_eq!(doc["authorization_servers"][0], format!("{PUBLIC_URL}/mcp"));
    }
    // Beta (`/mcp-beta`): path-inserted only, with its own resource/AS.
    let (status, doc) = get_json(app(), "/.well-known/oauth-protected-resource/mcp-beta").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["resource"], format!("{PUBLIC_URL}/mcp-beta"));
    assert_eq!(doc["authorization_servers"][0], format!("{PUBLIC_URL}/mcp-beta"));
}

#[tokio::test]
async fn authorization_server_metadata_is_a_path_issuer_per_instance() {
    // RFC 8414 path-inserted location, the OIDC-style alternate inside the
    // mount, and (default instance) the root courtesy copy — all one document.
    for path in [
        "/.well-known/oauth-authorization-server/mcp",
        "/mcp/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server",
    ] {
        let (status, doc) = get_json(app(), path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        assert_eq!(doc["issuer"], format!("{PUBLIC_URL}/mcp"), "GET {path}");
        assert_eq!(doc["authorization_endpoint"], format!("{PUBLIC_URL}/mcp/oauth/authorize"));
        assert_eq!(doc["token_endpoint"], format!("{PUBLIC_URL}/mcp/oauth/token"));
        assert_eq!(doc["registration_endpoint"], format!("{PUBLIC_URL}/mcp/oauth/register"));
        // RFC 9207: we emit `iss` on authorization responses, so the AS metadata
        // MUST advertise the parameter.
        assert_eq!(doc["authorization_response_iss_parameter_supported"], true);
        // Optional fields absent per RFC 8414 must be OMITTED, not null.
        assert!(doc.get("scopes_supported").is_none());
    }
    for path in [
        "/.well-known/oauth-authorization-server/mcp-beta",
        "/mcp-beta/.well-known/oauth-authorization-server",
    ] {
        let (status, doc) = get_json(app(), path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        assert_eq!(doc["issuer"], format!("{PUBLIC_URL}/mcp-beta"), "GET {path}");
        assert_eq!(doc["authorization_endpoint"], format!("{PUBLIC_URL}/mcp-beta/oauth/authorize"));
    }
}

#[tokio::test]
async fn auth_callbacks_document_declares_every_mount() {
    let (status, doc) = get_json(app(), "/.well-known/ii-auth-callbacks").await;
    assert_eq!(status, StatusCode::OK);
    let declared: Vec<String> = doc["callbacks"]
        .as_array()
        .expect("callbacks array")
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        declared,
        vec![
            format!("{PUBLIC_URL}/mcp/oauth/connect/callback"),
            format!("{PUBLIC_URL}/mcp-beta/oauth/connect/callback"),
        ],
        "one entry per instance, under each mount"
    );
}

/// The app-metadata document has to meet Internet Identity's requirements or
/// it is discarded whole — silently, on a screen this server never sees.
#[tokio::test]
async fn ii_app_metadata_document_meets_ii_requirements() {
    let (status, doc) = get_json(app(), "/.well-known/ii-app-metadata").await;
    assert_eq!(status, StatusCode::OK);

    let name = doc["name"].as_str().expect("name is a string");
    assert!(!name.trim().is_empty(), "a blank name reads as absent to II");
    assert!(
        name.chars().count() <= 40,
        "name must fit II's 40-code-point cap, got {} in {name:?}",
        name.chars().count()
    );

    for field in ["privacyPolicyUrl", "termsOfServiceUrl"] {
        let url = doc[field].as_str().unwrap_or_else(|| panic!("{field} is a string"));
        // II takes `https` only, and refuses userinfo (which would let a URL
        // read as one host and resolve to another).
        assert!(url.starts_with("https://"), "{field} must be https, got {url}");
        let authority = url.trim_start_matches("https://").split('/').next().unwrap_or_default();
        assert!(!authority.contains('@'), "{field} must not carry userinfo, got {url}");
    }
}

#[tokio::test]
async fn unauthenticated_mcp_requests_get_the_path_aware_challenge() {
    // The MCP service is the mount's fallback, so the bare path, the
    // trailing-slash form, and sub-paths are all gated — same breadth
    // `nest_service` used to give it.
    for path in ["/mcp", "/mcp/", "/mcp/sub"] {
        let resp = app().oneshot(Request::post(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "POST {path}");
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            challenge.contains(&format!(
                "resource_metadata=\"{PUBLIC_URL}/.well-known/oauth-protected-resource/mcp\""
            )),
            "POST {path}: challenge should point at the path-aware metadata: {challenge}"
        );
        // RFC 6750: no token presented → the bare challenge, no error code.
        assert!(
            !challenge.contains("error="),
            "POST {path}: bare challenge must omit the error code: {challenge}"
        );
    }

    // Beta's challenge points at beta's document.
    let resp =
        app().oneshot(Request::post("/mcp-beta").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge =
        resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or_default();
    assert!(
        challenge.contains("/.well-known/oauth-protected-resource/mcp-beta\""),
        "beta challenge: {challenge}"
    );
}

/// Dynamic client registration round-trips through the **bounded** client store
/// (capped, LRU-evicted, with coalesced write-through): a loopback redirect
/// registers, that `client_id` is then accepted at `/oauth/authorize` (which also
/// marks it recently used, keeping it ahead of the LRU eviction), the
/// registration lands in the state directory's `oauth-clients.json` so it
/// survives a restart, and a redirect off the hosted allow-list is refused
/// before anything is stored.
///
/// It also drives verified-connector branding end to end over HTTP (authorize →
/// the `state` in II's link → `GET /branding?state=`), because this is the one
/// test that registers a client: a second accepting registration elsewhere would
/// race the persistence poll below on the shared store file.
#[tokio::test]
async fn dynamic_client_registration_round_trips_and_persists() {
    // One app, cloned per request, so both calls share the same client store.
    let app = app();
    let register = |body: &'static str| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::post("/mcp/oauth/register")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
        }
    };

    // Loopback first (asserted below); the two claude.ai spellings — plain and
    // with a trailing root dot, which validation accepts — are for branding.
    let (status, doc) = register(
        r#"{"redirect_uris":["http://127.0.0.1:4321/cb",
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.ai./api/mcp/auth_callback"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = doc["client_id"].as_str().expect("a client_id").to_string();
    assert_eq!(doc["redirect_uris"][0], "http://127.0.0.1:4321/cb");

    // The fresh registration is usable: authorize accepts it and hands the
    // browser to Internet Identity (302 + the binding cookie). Returns the
    // connect `state` (the pending session id) from the II link's fragment —
    // what II passes back to `/branding`.
    let authorize = |redirect: &'static str| {
        let app = app.clone();
        let client_id = client_id.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::get(format!(
                        "/mcp/oauth/authorize?response_type=code&client_id={client_id}\
                         &redirect_uri={redirect}&code_challenge=abc\
                         &code_challenge_method=S256"
                    ))
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FOUND, "a registered client can start a sign-in");
            assert!(resp.headers().contains_key("set-cookie"), "the binding cookie must be set");
            let location = resp.headers()["location"].to_str().unwrap().to_string();
            let (_, fragment) = location.split_once('#').expect("the II link carries a fragment");
            url::form_urlencoded::parse(fragment.as_bytes())
                .find(|(key, _)| key == "state")
                .map(|(_, state)| state.into_owned())
                .expect("the II link carries the connect state")
        }
    };
    let branding = |state: String| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::get(format!("/mcp/branding?state={state}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let cache = resp
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let doc = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, cache, doc)
        }
    };

    // Branding is answered per session, from that session's validated redirect:
    // a loopback (native-app) session stays anonymous ...
    let (status, _, _) = branding(authorize("http://127.0.0.1:4321/cb").await).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a loopback session gets no branding");
    // ... and both claude.ai spellings brand as Claude, uncached.
    for redirect in
        ["https://claude.ai/api/mcp/auth_callback", "https://claude.ai./api/mcp/auth_callback"]
    {
        let (status, cache, doc) = branding(authorize(redirect).await).await;
        assert_eq!(status, StatusCode::OK, "branding for {redirect}");
        assert_eq!(doc["name"], "Claude", "branding for {redirect}");
        assert_eq!(doc["verified"], true, "branding for {redirect}");
        assert_eq!(doc["logo"], format!("{PUBLIC_URL}/mcp/branding/claude/logo"));
        assert_eq!(cache.as_deref(), Some("no-store"), "a per-session answer must not be cached");
    }

    // A hosted redirect that isn't allow-listed is refused (nothing stored).
    let (status, doc) = register(r#"{"redirect_uris":["https://attacker.example/cb"]}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(doc["error"], "invalid_redirect_uri");

    // Registrations are persisted (coalesced, so on a background task): poll
    // briefly for the write rather than assuming it has already landed. The store
    // file is `{state_dir}/oauth-clients.json` (see `test_state_dir`).
    let path = test_state_dir().join("oauth-clients.json");
    let mut persisted = String::new();
    for _ in 0..100 {
        persisted = std::fs::read_to_string(&path).unwrap_or_default();
        if persisted.contains(&client_id) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        persisted.contains(&client_id),
        "the registration must reach {} so it survives a restart",
        path.display()
    );
    assert!(!persisted.contains("attacker.example"), "a refused registration must never be stored");
}

/// Open DCR is unauthenticated, so a single `POST /oauth/register` must not be
/// able to store an unbounded `redirect_uris` array (count or per-URI length):
/// both are rejected with `invalid_redirect_uri` before anything is validated or
/// stored, and — because the bounds run ahead of grant-type validation — an
/// over-count array is still `invalid_redirect_uri` even when the same request
/// also carries unsupported grant types (ICPBB-379).
///
/// Every assertion here is a REJECTION, which returns before the store is
/// touched, so this test schedules no persistence write and cannot race the
/// store-file assertions in `dynamic_client_registration_round_trips_and_persists`
/// (which already covers the accepting path — a small loopback registration
/// through these same caps).
#[tokio::test]
async fn registration_bounds_redirect_uris() {
    let app = app();
    let register = |body: String| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::post("/mcp/oauth/register")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
        }
    };

    // Too many redirect_uris (all individually valid loopback URLs) — refused.
    let many: Vec<String> = (0..64).map(|i| format!("http://127.0.0.1:4321/cb{i}")).collect();
    let body = serde_json::json!({ "redirect_uris": many.clone() }).to_string();
    let (status, doc) = register(body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an over-count array is refused");
    assert_eq!(doc["error"], "invalid_redirect_uri");

    // A single over-long redirect_uri — refused (length is checked before the
    // hosted allow-list, and before the store is touched).
    let long = format!("http://127.0.0.1:4321/{}", "a".repeat(4096));
    let body = serde_json::json!({ "redirect_uris": [long] }).to_string();
    let (status, doc) = register(body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an over-long uri is refused");
    assert_eq!(doc["error"], "invalid_redirect_uri");

    // Combined invalid input: an over-count array AND unsupported grant types.
    // Because the redirect bounds run FIRST, the deterministic answer is
    // `invalid_redirect_uri`, never `invalid_client_metadata` from the grant check.
    let body = serde_json::json!({
        "redirect_uris": many,
        "grant_types": ["client_credentials"],
    })
    .to_string();
    let (status, doc) = register(body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "combined-invalid input is refused");
    assert_eq!(
        doc["error"], "invalid_redirect_uri",
        "redirect overflow must win over the grant-type error"
    );
}

#[tokio::test]
async fn invalid_token_challenge_carries_rfc6750_error() {
    let resp = app()
        .oneshot(
            Request::post("/mcp")
                .header("authorization", "Bearer bogus")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge =
        resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or_default();
    assert!(
        challenge.contains("error=\"invalid_token\""),
        "presented-but-invalid token must carry the RFC 6750 error: {challenge}"
    );
}

#[tokio::test]
async fn authorize_validates_its_inputs() {
    // No response_type.
    let resp = app()
        .oneshot(
            Request::get("/mcp/oauth/authorize?client_id=x&redirect_uri=https://a.test/cb")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Unregistered client (loopback included — registration is always required).
    let resp = app()
        .oneshot(
            Request::get(
                "/mcp/oauth/authorize?response_type=code&client_id=unknown\
                 &redirect_uri=http://127.0.0.1:4321/cb&code_challenge=abc\
                 &code_challenge_method=S256",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // An omitted code_challenge_method defaults to `plain` per RFC 7636, which
    // this server does not support — rejected up front rather than handing out
    // a code the token endpoint (S256-only) could never redeem.
    let resp = app()
        .oneshot(
            Request::get(
                "/mcp/oauth/authorize?response_type=code&client_id=unknown\
                 &redirect_uri=http://127.0.0.1:4321/cb&code_challenge=abc",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oauth_endpoints_live_under_each_mount() {
    // Token: a bogus grant is rejected with a standards-shaped 400.
    for path in ["/mcp/oauth/token", "/mcp-beta/oauth/token"] {
        let resp = app()
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "grant_type=authorization_code&code=bogus&client_id=x&code_verifier=v",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "POST {path}");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["error"], "invalid_grant", "POST {path}");
    }

    // The pinned callback page is served per instance and posts to that
    // instance's redeem path.
    for (page, redeem) in [
        ("/mcp/oauth/connect/callback", "/mcp/oauth/connect/redeem"),
        ("/mcp-beta/oauth/connect/callback", "/mcp-beta/oauth/connect/redeem"),
    ] {
        let resp = app().oneshot(Request::get(page).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET {page}");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&bytes);
        assert!(
            html.contains(redeem),
            "GET {page}: the page must post to its own instance's redeem path"
        );
    }
}

/// Verified-connector branding routing (II fetches these from the issuer origin to
/// brand the consent screen). The metadata is SESSION-BOUND — answered only for a
/// pending connect's validated redirect (the 200 path over HTTP is driven by
/// `dynamic_client_registration_round_trips_and_persists`, and expiry by
/// `branding_is_bound_to_the_session` in `src/auth.rs`); here: no session → 404,
/// CORS-open for II's cross-origin fetch, the unbound per-slug metadata path is
/// gone, and the static logo serves.
#[tokio::test]
async fn branding_endpoints_are_session_bound_and_serve_logos() {
    // No such session, and no `state` at all: the same 404.
    for path in ["/mcp/branding?state=sess-does-not-exist", "/mcp/branding"] {
        let resp = app()
            .oneshot(
                Request::get(path).header("origin", "https://id.ai").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "GET {path}");
        assert!(
            resp.headers().contains_key("access-control-allow-origin"),
            "GET {path}: II fetches this cross-origin, so it must be CORS-open"
        );
        assert_eq!(
            resp.headers().get("cache-control").and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "GET {path}: the 404 is per-session too"
        );
    }

    // The old UNBOUND per-slug metadata endpoint (it returned `verified: true` for
    // any catalog slug) no longer exists: it must not answer with branding.
    let resp = app()
        .oneshot(Request::get("/mcp/branding/claude").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::OK, "no slug-keyed branding metadata");

    // The logo is an SVG with nosniff (II renders it via <img>, never inlined).
    let resp = app()
        .oneshot(Request::get("/mcp/branding/claude/logo").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("image/svg+xml")
    );
    assert_eq!(
        resp.headers().get("x-content-type-options").and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    // Opened top-level, the SVG is a document on the issuer origin: keep it inert.
    let csp = resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok());
    assert!(csp.is_some_and(|v| v.contains("sandbox") && v.contains("default-src 'none'")));

    // A slug outside the curated set 404s, so the path can't probe.
    let resp = app()
        .oneshot(Request::get("/mcp/branding/not-a-connector/logo").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
