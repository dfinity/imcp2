//! One SSRF-guarded GET of a small public document, for callers outside the
//! discovery crawl that must fetch a URL a stranger handed them. Today that is
//! the hosted OAuth authorization server, fetching a client's *Client ID Metadata
//! Document* — the MCP authorization spec's preferred registration, where the
//! `client_id` an unauthenticated `/oauth/authorize` request carries IS an https
//! URL and the JSON at that URL is the client's registration.
//!
//! The guard is the discovery module's (CWE-918): https only; the host resolved
//! up front and refused if ANY address is loopback / private / link-local /
//! CGNAT / otherwise reserved; the validated addresses pinned into the client so
//! a re-resolution cannot rebind the connection (DNS rebinding); every redirect
//! hop re-checked; and the body read under a hard byte cap (CWE-770). On top of
//! that, this fetch is STRICT where the crawl is opportunistic — the document is
//! the URL's own statement about itself, so:
//!
//!   * a response served by a redirect target is refused (the shared redirect
//!     policy permits same-host different-port hops and hops to global IP
//!     literals, either of which would put another origin's bytes behind the URL);
//!   * a body over the cap, or one whose transfer failed part-way, is an error,
//!     never a shorter document.

use std::time::Duration;

use crate::discover::{read_capped_inner, resolve_public_url, ssrf_redirect_policy};

/// A small public document fetched under the SSRF guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicDocument {
    /// The complete body (it fit under the caller's cap).
    pub body: String,
    /// The `Content-Type` the origin sent, if any.
    pub content_type: Option<String>,
    /// The `max-age` of the origin's `Cache-Control`, if it sent one; `Some(0)`
    /// when it said `no-store` or `no-cache`. A hint for the caller's own cache,
    /// for the caller to bound — never binding.
    pub cache_max_age: Option<Duration>,
}

/// GET `url` and return its body, or the reason it was not fetched: the URL is
/// refused by the SSRF guard (not https, no host, or a host with a non-public
/// address), unreachable within `timeout`, answered by another origin, answered
/// with a non-success status, larger than `max_bytes`, or cut off mid-body.
pub async fn fetch_public_document(
    url: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<PublicDocument, String> {
    let (parsed, pinned) = resolve_public_url(url).await?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let client = reqwest::Client::builder()
        .user_agent(concat!("imcp2-core/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .redirect(ssrf_redirect_policy())
        .resolve_to_addrs(&host, &pinned)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(parsed.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("could not fetch {url}: {e}"))?;
    // The document is this URL's statement about itself, so only its own origin
    // may answer; a redirect target's answer is not that statement.
    let expected_origin = parsed.origin().ascii_serialization();
    let served_from = resp.url().origin().ascii_serialization();
    if served_from != expected_origin {
        return Err(format!("{url} was answered by {served_from}, not by its own origin"));
    }
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }
    let header = |name: reqwest::header::HeaderName| {
        resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
    };
    let content_type = header(reqwest::header::CONTENT_TYPE);
    let cache_max_age = header(reqwest::header::CACHE_CONTROL).and_then(|v| cache_max_age(&v));
    // Read ONE byte past the cap so overflow is detectable: a truncated body is
    // not a shorter document.
    let body = match read_capped_inner(resp, max_bytes + 1).await {
        Ok(body) if body.len() > max_bytes => {
            return Err(format!("{url} is larger than the {max_bytes}-byte cap"))
        }
        Ok(body) => body,
        Err((_, e)) => return Err(format!("reading {url} failed part-way: {e}")),
    };
    Ok(PublicDocument { body, content_type, cache_max_age })
}

/// The caching lifetime a `Cache-Control` value asks for: its `max-age`, or zero
/// when it forbids reuse (`no-store` / `no-cache`); `None` when it says neither.
fn cache_max_age(cache_control: &str) -> Option<Duration> {
    let directives: Vec<&str> = cache_control.split(',').map(str::trim).collect();
    if directives
        .iter()
        .any(|d| d.eq_ignore_ascii_case("no-store") || d.eq_ignore_ascii_case("no-cache"))
    {
        return Some(Duration::ZERO);
    }
    directives.iter().find_map(|d| {
        let (name, value) = d.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("max-age")
            .then(|| value.trim().trim_matches('"').parse::<u64>().ok())?
            .map(Duration::from_secs)
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{cache_max_age, fetch_public_document};

    /// The SSRF guard decides before any request: these never touch the network
    /// (IP-literal hosts need no DNS), and each is refused for the reason the
    /// guard names.
    #[tokio::test]
    async fn guard_refuses_before_fetching() {
        let fetch = |url: &'static str| fetch_public_document(url, 1024, Duration::from_secs(1));
        assert!(fetch("http://example.com/client.json").await.unwrap_err().contains("only https"));
        for internal in [
            "https://127.0.0.1/client.json",
            "https://10.0.0.7/client.json",
            "https://192.168.1.1/client.json",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/client.json",
            "https://[::ffff:127.0.0.1]/client.json",
        ] {
            let err = fetch(internal).await.unwrap_err();
            assert!(err.contains("non-public address"), "{internal}: {err}");
        }
        assert!(fetch("not a url").await.is_err());
    }

    #[test]
    fn cache_control_lifetime() {
        assert_eq!(cache_max_age("max-age=300"), Some(Duration::from_secs(300)));
        assert_eq!(
            cache_max_age("public, max-age=86400, immutable"),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(cache_max_age("Max-Age=\"60\""), Some(Duration::from_secs(60)));
        assert_eq!(cache_max_age("no-store"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age=300, no-cache"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("public"), None);
        assert_eq!(cache_max_age("max-age=soon"), None);
    }
}
