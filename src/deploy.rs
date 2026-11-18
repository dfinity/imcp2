//! The deploy tools on the hosted server, behind the `deploy` feature: the
//! core surface served with [`imcp2_deploy`]'s tools beside it, a bundle
//! upload route, and a transport that streams a deploy's progress and tells
//! it when the client has gone.
//!
//! Three things differ from the rest of the MCP endpoint:
//!
//!   * **The response framing of a deploy call.** The endpoint answers a POST
//!     with plain JSON, the one message the handler returns. A deploy reports
//!     each phase as a notification *before* its result, which plain JSON
//!     cannot carry — in rmcp's JSON mode the first message out would be
//!     taken for the result. So a `tools/call` of `icp_deploy_bundle` is
//!     handed to a second rmcp service configured for Server-Sent-Events
//!     responses, still stateless, whose stream carries every notification
//!     and then the result; every other request keeps the JSON service. The
//!     dispatch reads the JSON-RPC method and tool name off the buffered body.
//!   * **The client going away.** The SSE response body is wrapped so that
//!     its drop — the client disconnecting, or the stream ending — cancels a
//!     token the deploy tool watches ([`ClientGone`]): a deploy nobody will
//!     read the answer of stops at its next step.
//!   * **How the bundle arrives.** The agent's machine cannot hand this server
//!     a file, and a tool call carries only what the model writes, so an
//!     archive is `PUT` to `{mcp_path}/deploy/upload` on a one-time ticket that
//!     `icp_deploy_upload` mints inside an authenticated call (see
//!     [`imcp2_deploy::Uploads`] for the ticket's properties). The route is
//!     outside the bearer gate — the ticket is its authentication — and
//!     streams the body to disk under its own cap. The upload is the only
//!     way in: the deploy tool here lists `bundle_upload` and refuses a
//!     `bundle_path`, so the server opens no file a caller names.
//!
//! The working directories and uploads live under the state directory
//! (`{state_dir}/deploys`), each readable by the server's user alone.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::put,
    Json, Router,
};
use futures_util::{StreamExt, TryStreamExt};
use imcp2_deploy::{ClientGone, IcDeployTools, ReceiveError, Uploads, WithDeploy, TICKET_HEADER};
use rmcp::transport::{
    streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
    StreamableHttpServerConfig,
};
use tokio_util::sync::CancellationToken;

use crate::{auth, tools::IcTools, McpServer};

/// What a hosted deployment configures of the deploy tools.
#[derive(Clone, Debug)]
pub struct DeployConfig {
    /// How many deploys run at once across every session (one per session
    /// either way); past it a deploy is refused, not queued.
    pub concurrent: usize,
    /// The cap on an uploaded archive, in bytes.
    pub max_upload_bytes: usize,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self { concurrent: 2, max_upload_bytes: imcp2_deploy::DEFAULT_MAX_UPLOAD_BYTES }
    }
}

/// The path, under the MCP mount, an archive is `PUT` to.
pub const UPLOAD_PATH: &str = "/deploy/upload";

/// The most of a request body the dispatch buffers to read the method and
/// tool name: an MCP request is small JSON, and a bundle never rides inline
/// here. (The body cap in front of the endpoint, where there is one, holds
/// it lower still.)
const DISPATCH_MAX_BODY: usize = 4 * 1024 * 1024;

type McpService = StreamableHttpService<WithDeploy<IcTools>, LocalSessionManager>;

/// The two transports and the upload store behind the deploy-aware endpoint.
pub(crate) struct DeployMcp {
    json: McpService,
    sse: McpService,
    uploads: Uploads,
}

impl McpServer {
    /// The MCP endpoint with the deploy tools, as two routers: the dispatch
    /// between the JSON and SSE transports, for the caller to put behind the
    /// bearer gate, and the upload route, which goes outside it (the ticket
    /// is its authentication). `transport` is the endpoint's configuration
    /// as the plain endpoint would use it.
    pub(crate) fn deploy_mcp_routers(
        &self,
        config: &DeployConfig,
        transport: StreamableHttpServerConfig,
    ) -> (Router, Router) {
        let deploys_dir = self.state_dir().join("deploys");
        let uploads = Uploads::new(deploys_dir.join("uploads"), config.max_upload_bytes);
        let upload_url = format!("{}{}{UPLOAD_PATH}", self.public_url, self.mcp_path);
        let deploy = IcDeployTools::new(self.identities.clone(), auth::bearer_session_resolver())
            .concurrent(config.concurrent)
            .deploys_in(&deploys_dir)
            .unwrap_or_else(|e| panic!("the state directory must be a UTF-8 path: {e}"))
            .with_uploads(uploads.clone(), upload_url);
        let service = |transport: StreamableHttpServerConfig| {
            let (agent, identities, deploy) =
                (self.agent.clone(), self.identities.clone(), deploy.clone());
            StreamableHttpService::new(
                move || {
                    Ok(WithDeploy::new(
                        IcTools::new(
                            agent.clone(),
                            identities.clone(),
                            auth::bearer_session_resolver(),
                        ),
                        deploy.clone(),
                    ))
                },
                LocalSessionManager::default().into(),
                transport,
            )
        };
        let mcp = Arc::new(DeployMcp {
            json: service(transport.clone().with_json_response(true)),
            sse: service(transport.with_json_response(false)),
            uploads,
        });
        (
            Router::new().fallback(dispatch).with_state(mcp.clone()),
            Router::new().route(UPLOAD_PATH, put(upload)).with_state(mcp),
        )
    }
}

/// Hand a deploy call to the SSE transport, with its response body watched
/// for the client going away, and everything else to the JSON transport.
async fn dispatch(State(mcp): State<Arc<DeployMcp>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, DISPATCH_MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
    };
    let deploy_call = parts.method == Method::POST && is_deploy_call(&bytes);
    let mut request = Request::from_parts(parts, Body::from(bytes));
    if !deploy_call {
        return mcp.json.handle(request).await.into_response();
    }
    let gone = CancellationToken::new();
    request.extensions_mut().insert(ClientGone(gone.clone()));
    let response = mcp.sse.handle(request).await;
    cancel_on_drop(response.into_response(), gone)
}

/// Whether `body` is a JSON-RPC `tools/call` of `icp_deploy_bundle`.
fn is_deploy_call(body: &[u8]) -> bool {
    let Ok(message) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    message["method"] == "tools/call" && message["params"]["name"] == "icp_deploy_bundle"
}

/// `response` with its body wrapped so that dropping the body — the client
/// disconnecting, or the stream ending — cancels `gone`.
fn cancel_on_drop(response: Response, gone: CancellationToken) -> Response {
    let (parts, body) = response.into_parts();
    let guard = gone.drop_guard();
    let stream = futures_util::stream::unfold(
        (body.into_data_stream(), guard),
        |(mut data, guard)| async move { data.next().await.map(|item| (item, (data, guard))) },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

/// What a successful `PUT` answers with.
#[derive(serde::Serialize)]
struct Uploaded {
    upload_id: String,
    bytes: usize,
    expires_in_secs: u64,
}

/// Receive an archive on the ticket in [`TICKET_HEADER`].
async fn upload(State(mcp): State<Arc<DeployMcp>>, request: Request) -> Response {
    let Some(ticket) = request.headers().get(TICKET_HEADER).and_then(|v| v.to_str().ok()) else {
        return (
            StatusCode::UNAUTHORIZED,
            format!("send the upload ticket in the {TICKET_HEADER} header"),
        )
            .into_response();
    };
    let ticket = ticket.trim().to_string();
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let reader = tokio_util::io::StreamReader::new(
        request.into_body().into_data_stream().map_err(std::io::Error::other),
    );
    match mcp.uploads.receive(&ticket, declared, reader).await {
        Ok(received) => (
            StatusCode::CREATED,
            Json(Uploaded {
                upload_id: received.upload_id,
                bytes: received.bytes,
                expires_in_secs: received.expires_in.as_secs(),
            }),
        )
            .into_response(),
        Err(e @ ReceiveError::UnknownTicket) => {
            (StatusCode::FORBIDDEN, e.to_string()).into_response()
        }
        Err(e @ ReceiveError::TooLarge(_)) => {
            (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()).into_response()
        }
        Err(e @ ReceiveError::Io(_)) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, IiInstance, McpConfig, SharedClients, IC_URL};
    use axum::http::Request;
    use tower::ServiceExt;

    fn server() -> (tempfile::TempDir, McpServer) {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_path_buf();
        let server = McpServer::new(McpConfig {
            agent: Agent::builder().with_url(IC_URL).build().expect("agent"),
            instance: IiInstance::prod().expect("prod instance"),
            public_url: "https://mcp.example.com".into(),
            mcp_path: "/mcp".into(),
            clients: SharedClients::load(&state_dir),
            state_dir,
            require_resource: true,
            cimd_enabled: false,
        })
        .with_deploy(DeployConfig { concurrent: 2, max_upload_bytes: 1024 });
        (dir, server)
    }

    fn rpc(method: &str, params: serde_json::Value) -> String {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string()
    }

    async fn post(app: &Router, bearer: &str, body: String) -> Response {
        app.clone()
            .oneshot(
                Request::post("/")
                    .header("host", "mcp.example.com")
                    .header("authorization", bearer)
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn content_type(resp: &Response) -> String {
        resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap().to_string()
    }

    /// The whole loop over the composed router: the deploy tools are listed,
    /// a ticket is minted inside an authenticated call, the archive is PUT on
    /// it, and the deploy call — and only it — is answered as an event stream
    /// that carries the result.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_hosted_endpoint_serves_the_deploy_loop() {
        let (_dir, server) = server();
        let bearer = format!("Bearer {}", server.store.test_bearer().await);
        // Built once, as a deployment does: the upload store lives in it.
        let app = server.mcp_router();

        // tools/list stays plain JSON, and lists the deploy tools.
        let resp = post(&app, &bearer, rpc("tools/list", serde_json::json!({}))).await;
        let status = resp.status();
        let kind = content_type(&resp);
        if status != StatusCode::OK {
            panic!("tools/list: {status}: {}", text(resp).await);
        }
        assert!(kind.starts_with("application/json"), "{kind}");
        let listed: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for tool in ["open_app", "icp_deploy_bundle", "icp_deploy_upload", "icp_cycles_balance"] {
            assert!(names.contains(&tool), "{tool} must be listed: {names:?}");
        }
        assert!(!names.contains(&"authenticate"), "no login tool on the hosted server");
        // The bundle is an upload here, and the deploy tool lists it so.
        let deploy = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "icp_deploy_bundle")
            .unwrap();
        let properties = &deploy["inputSchema"]["properties"];
        assert!(properties["bundle_upload"].is_object(), "{properties}");
        assert!(properties["bundle_path"].is_null(), "{properties}");

        // A ticket, minted inside the authenticated call.
        let resp = post(
            &app,
            &bearer,
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_upload", "arguments": {} })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let answer: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let result = &answer["result"];
        assert_ne!(result["isError"], true, "{result}");
        let ticket = result["structuredContent"]["ticket"].as_str().unwrap().to_string();
        assert_eq!(
            result["structuredContent"]["upload_url"],
            "https://mcp.example.com/mcp/deploy/upload"
        );
        assert!(result["structuredContent"]["curl"].as_str().unwrap().contains(&ticket));

        // The PUT: refused without a ticket, with a wrong one, and over the cap;
        // accepted on the ticket, once.
        let put = |ticket: Option<&str>, body: Vec<u8>| {
            let mut req = Request::put(UPLOAD_PATH);
            if let Some(t) = ticket {
                req = req.header(TICKET_HEADER, t);
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };
        assert_eq!(put(None, vec![1]).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(put(Some("bogus"), vec![1]).await.unwrap().status(), StatusCode::FORBIDDEN);
        let resp = put(Some(&ticket), vec![0; 1025]).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // The over-cap attempt spent the ticket: mint another.
        let resp = post(
            &app,
            &bearer,
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_upload", "arguments": {} })),
        )
        .await;
        let answer: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let ticket = answer["result"]["structuredContent"]["ticket"].as_str().unwrap().to_string();
        let resp = put(Some(&ticket), b"not a bundle".to_vec()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let uploaded: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
        let upload_id = uploaded["upload_id"].as_str().unwrap().to_string();
        assert_eq!(uploaded["bytes"], 12);
        assert_eq!(put(Some(&ticket), vec![1]).await.unwrap().status(), StatusCode::FORBIDDEN);

        // A path is no way in: this server opens no file a caller names,
        // whether or not an upload comes with it, and the upload is not spent.
        for arguments in [
            serde_json::json!({ "bundle_path": "/etc/hostname", "environment": "ic" }),
            serde_json::json!({
                "bundle_path": "/etc/hostname", "bundle_upload": upload_id, "environment": "ic"
            }),
        ] {
            let call = serde_json::json!({ "name": "icp_deploy_bundle", "arguments": arguments });
            let stream = text(post(&app, &bearer, rpc("tools/call", call)).await).await;
            assert!(stream.contains("reads no bundle_path"), "{stream}");
        }

        // The deploy call is answered as an event stream carrying the result:
        // offline, with a made-up session, the error that the identity cannot
        // be derived — raised after the upload was found for this session,
        // which is what the next call shows.
        let resp = post(
            &app,
            &bearer,
            rpc(
                "tools/call",
                serde_json::json!({
                    "name": "icp_deploy_bundle",
                    "arguments": { "bundle_upload": upload_id, "environment": "ic" }
                }),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("text/event-stream"), "{}", content_type(&resp));
        let stream = text(resp).await;
        let data = stream
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|d| d.contains("\"result\""))
            .expect("the stream carries the result");
        let answer: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(answer["result"]["isError"], true, "{answer}");
        let said = answer["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!said.contains("no upload"), "the upload must be found: {said}");
        // Spent with the deploy: a second deploy of the same upload finds none.
        let resp = post(
            &app,
            &bearer,
            rpc(
                "tools/call",
                serde_json::json!({
                    "name": "icp_deploy_bundle",
                    "arguments": { "bundle_upload": upload_id, "environment": "ic" }
                }),
            ),
        )
        .await;
        let stream = text(resp).await;
        assert!(stream.contains("no upload"), "{stream}");

        // Unauthenticated: the gate answers first, for the deploy call too.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/")
                    .header("host", "mcp.example.com")
                    .header("content-type", "application/json")
                    .body(Body::from(rpc(
                        "tools/call",
                        serde_json::json!({ "name": "icp_deploy_bundle", "arguments": {} }),
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Dropping the response body — what a disconnect does — fires the token.
    #[tokio::test]
    async fn dropping_the_response_body_says_the_client_has_gone() {
        let gone = CancellationToken::new();
        let pending = futures_util::stream::pending::<Result<axum::body::Bytes, axum::Error>>();
        let response = Response::new(Body::from_stream(pending));
        let watched = cancel_on_drop(response, gone.clone());
        assert!(!gone.is_cancelled());
        drop(watched);
        assert!(gone.is_cancelled(), "the body's drop must cancel the token");
    }

    #[test]
    fn only_a_deploy_call_is_dispatched_to_the_event_stream() {
        assert!(is_deploy_call(
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_bundle" })).as_bytes()
        ));
        assert!(!is_deploy_call(
            rpc("tools/call", serde_json::json!({ "name": "icp_deploy_upload" })).as_bytes()
        ));
        assert!(!is_deploy_call(rpc("tools/list", serde_json::json!({})).as_bytes()));
        assert!(!is_deploy_call(b"not json"));
    }
}
