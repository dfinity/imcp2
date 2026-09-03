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
//! a re-resolution cannot rebind the connection (DNS rebinding); and the body
//! read under a hard byte cap (CWE-770). On top of that, this fetch is STRICT
//! where the crawl is opportunistic — the document is the URL's own statement
//! about itself, so:
//!
//!   * redirects are not followed at all: a 3xx is a non-success answer, so no
//!     other URL's bytes — on another host, another port, or another path of the
//!     same origin — can ever stand in for the document at this one;
//!   * a body over the cap, or one whose transfer failed part-way, is an error,
//!     never a shorter document;
//!   * the caller's timeout is ONE deadline over the whole operation, DNS
//!     resolution included, so a slow resolver cannot hold the caller past it —
//!     and it is the only deadline, so however far the fetch got when it ran out
//!     of time, the caller sees the same "did not complete" error.

use std::time::Duration;

use crate::discover::{read_capped_inner, resolve_public_url};

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
/// address); resolving, connecting, answering and delivering the body did not
/// all complete within `timeout`; the answer was anything but 2xx (a redirect
/// included); the body is larger than `max_bytes`; or the transfer was cut off.
pub async fn fetch_public_document(
    url: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<PublicDocument, String> {
    // One deadline over everything, resolution included: `resolve_public_url`
    // does the DNS lookup, and a resolver that never answers must not hold the
    // caller (and whatever it is holding, such as an in-flight permit) forever.
    // Deliberately the ONLY deadline — the client below sets none of its own —
    // so the error is the same wherever the time ran out, and dropping the
    // future on expiry is what aborts the connection.
    tokio::time::timeout(timeout, fetch(url, max_bytes))
        .await
        .map_err(|_| format!("fetching {url} did not complete within {timeout:?}"))?
}

async fn fetch(url: &str, max_bytes: usize) -> Result<PublicDocument, String> {
    let (parsed, pinned) = resolve_public_url(url).await?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let client = reqwest::Client::builder()
        .user_agent(concat!("imcp2-core/", env!("CARGO_PKG_VERSION")))
        // Never follow a redirect: the document is this URL's statement about
        // itself, and a 3xx is that URL declining to make it. Refusing here (rather
        // than following under the crawl's redirect guard and comparing origins
        // afterwards) also closes the same-origin case, where a redirect to another
        // path would have put a different document behind this URL.
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&host, &pinned)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(parsed.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("could not fetch {url}: {e}"))?;
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
    // not a shorter document. Saturating, so a caller passing `usize::MAX` (no
    // cap) reads everything rather than wrapping to a zero-byte read.
    let body = match read_capped_inner(resp, max_bytes.saturating_add(1)).await {
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
            "https://10.0.0.1/client.json",
            "https://192.168.1.1/client.json",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/client.json",
            "https://[::ffff:127.0.0.1]/client.json",
        ] {
            let err = fetch(internal).await.unwrap_err();
            assert!(err.contains("non-public address"), "{internal}: {err}");
        }
        assert!(fetch("not a url").await.is_err());
        // An uncapped read is a valid request, not an overflow.
        let uncapped = fetch_public_document("https://[::1]/x", usize::MAX, Duration::from_secs(1));
        assert!(uncapped.await.unwrap_err().contains("non-public address"));
    }

    /// One deadline over the whole fetch: with no time at all, the operation fails
    /// with the deadline's error whether it ran out during DNS resolution or after
    /// (on a fast resolver, during the connect) — never with a request error of its
    /// own, since the client sets no separate timeout.
    #[tokio::test]
    async fn one_deadline_covers_the_whole_fetch() {
        let err = fetch_public_document("https://example.com/client.json", 1024, Duration::ZERO)
            .await
            .unwrap_err();
        assert!(err.contains("did not complete within"), "{err}");
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
