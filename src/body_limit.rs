//! A cap on the size of an MCP request body.
//!
//! The streamable-HTTP transport reads each request body whole into memory
//! before parsing it as JSON-RPC, and axum's default extractor limit never
//! reaches it (the transport is a tower service, not an extractor), so without
//! this layer a token holder could send a body of any size and have the process
//! buffer all of it. The layer sits INSIDE the bearer gate: an unauthenticated
//! request is turned away on its headers alone, so only an authenticated
//! caller's body is read, and only up to the cap.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// The default cap on an MCP request body, in bytes. An IC ingress message
/// carries at most 2 MiB, so any one canister call fits well under this even
/// once its argument is spelled out as JSON.
pub const DEFAULT_MAX_REQUEST_BODY: usize = 4 * 1024 * 1024;

/// Refuse a request whose body is over `max` bytes with `413 Payload Too
/// Large`, before buffering more than that of it: a declared `Content-Length`
/// over the cap is refused unread, and an undeclared (chunked) body is read up
/// to the cap and no further. A body within the cap is handed on whole, which
/// costs nothing extra since the transport buffers it anyway.
pub(crate) async fn limit_request_body(
    State(max): State<usize>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|len| len > max as u64) {
        return too_large(max);
    }
    let bytes = match axum::body::to_bytes(body, max).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return if e.into_inner().is::<http_body_util::LengthLimitError>() {
                too_large(max)
            } else {
                (StatusCode::BAD_REQUEST, "could not read the request body").into_response()
            };
        }
    };
    next.run(Request::from_parts(parts, Body::from(bytes))).await
}

fn too_large(max: usize) -> Response {
    (StatusCode::PAYLOAD_TOO_LARGE, format!("request body exceeds the {max}-byte limit"))
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::{
        body::{Body, Bytes},
        http::{header, Request, StatusCode},
        middleware,
        routing::post,
        Router,
    };
    use tower::ServiceExt;

    const MAX: usize = 1024;

    /// A service behind the cap that answers with how many body bytes reached it.
    fn app() -> Router {
        Router::new()
            .route("/", post(|body: Bytes| async move { body.len().to_string() }))
            .layer(middleware::from_fn_with_state(MAX, super::limit_request_body))
    }

    /// A body streamed in `chunk`-byte pieces with no `Content-Length`, counting
    /// how many pieces the server pulled.
    fn chunked(total: usize, chunk: usize) -> (Body, Arc<AtomicUsize>) {
        let pulled = Arc::new(AtomicUsize::new(0));
        let counter = pulled.clone();
        let pieces = (0..total.div_ceil(chunk)).map(move |i| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(Bytes::from(vec![b'x'; chunk.min(total - i * chunk)]))
        });
        (Body::from_stream(futures_util::stream::iter(pieces)), pulled)
    }

    async fn text(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn a_body_up_to_the_cap_reaches_the_service_whole() {
        for len in [0, 1, MAX] {
            let resp = app()
                .oneshot(Request::post("/").body(Body::from(vec![b'x'; len])).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{len} bytes");
            assert_eq!(text(resp).await, len.to_string(), "{len} bytes");
        }
    }

    #[tokio::test]
    async fn a_declared_length_over_the_cap_is_refused_unread() {
        let (body, pulled) = chunked(MAX + 1, 16);
        let resp = app()
            .oneshot(
                Request::post("/")
                    .header(header::CONTENT_LENGTH, (MAX + 1).to_string())
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(pulled.load(Ordering::SeqCst), 0, "the body must not be read");
        assert!(text(resp).await.contains(&format!("{MAX}-byte limit")));
    }

    #[tokio::test]
    async fn an_undeclared_body_over_the_cap_is_refused_at_the_cap() {
        let (body, pulled) = chunked(8 * MAX, 16);
        let resp = app().oneshot(Request::post("/").body(body).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let read = pulled.load(Ordering::SeqCst) * 16;
        assert!(
            read > MAX && read <= MAX + 16,
            "reading must stop at the cap, not drain the body: {read} bytes pulled"
        );
    }

    #[tokio::test]
    async fn an_undeclared_body_within_the_cap_passes() {
        let (body, _) = chunked(MAX, 16);
        let resp = app().oneshot(Request::post("/").body(body).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(text(resp).await, MAX.to_string());
    }
}
