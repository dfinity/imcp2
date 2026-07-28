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

/// Point the OAuth client-registration store at a throwaway temp path BEFORE
/// any `SharedClients::load()`, so these tests neither read nor write a
/// developer's real `oauth-clients.json`. The authorize-path assertions rely on
/// an EMPTY registration set (unknown/unregistered clients are rejected); a
/// stray real registration for `client_id=unknown`/`x` would otherwise flip
/// them. `load()` treats a missing file as empty, so a fresh, deleted path
/// gives a deterministic empty set. Set exactly once (env is process-global).
fn isolate_client_store() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let mut path = std::env::temp_dir();
        path.push("imcp2-router-tests-oauth-clients.json");
        let _ = std::fs::remove_file(&path); // drop any stale file from a prior run
        std::env::set_var("OAUTH_CLIENTS_FILE", &path);
    });
}

fn server(instance: imcp2::IiInstance, mcp_path: &str) -> imcp2::McpServer {
    isolate_client_store();
    let agent = imcp2::Agent::builder()
        .with_url(imcp2::IC_URL)
        .build()
        .expect("build agent");
    imcp2::McpServer::new(imcp2::McpConfig {
        agent,
        instance,
        public_url: PUBLIC_URL.into(),
        mcp_path: mcp_path.into(),
        clients: imcp2::SharedClients::load(),
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
}

async fn get_json(app: Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn protected_resource_metadata_follows_each_mount() {
    // Prod (the default `/mcp` instance): served path-inserted (RFC 9728 §3.1)
    // and, as the default instance, at the plain root.
    for path in [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
    ] {
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
        assert_eq!(
            doc["authorization_endpoint"],
            format!("{PUBLIC_URL}/mcp/oauth/authorize")
        );
        assert_eq!(doc["token_endpoint"], format!("{PUBLIC_URL}/mcp/oauth/token"));
        assert_eq!(
            doc["registration_endpoint"],
            format!("{PUBLIC_URL}/mcp/oauth/register")
        );
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
        assert_eq!(
            doc["authorization_endpoint"],
            format!("{PUBLIC_URL}/mcp-beta/oauth/authorize")
        );
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

#[tokio::test]
async fn unauthenticated_mcp_requests_get_the_path_aware_challenge() {
    // The MCP service is the mount's fallback, so the bare path, the
    // trailing-slash form, and sub-paths are all gated — same breadth
    // `nest_service` used to give it.
    for path in ["/mcp", "/mcp/", "/mcp/sub"] {
        let resp = app()
            .oneshot(Request::post(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
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
    let resp = app()
        .oneshot(Request::post("/mcp-beta").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        challenge.contains("/.well-known/oauth-protected-resource/mcp-beta\""),
        "beta challenge: {challenge}"
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
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
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
        let resp = app()
            .oneshot(Request::get(page).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET {page}");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&bytes);
        assert!(
            html.contains(redeem),
            "GET {page}: the page must post to its own instance's redeem path"
        );
    }
}
