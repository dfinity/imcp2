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
//! read under a hard byte cap (CWE-770). The connection is DIRECT: no proxy is
//! taken from the environment, since a proxy would resolve the host itself and
//! the pin would bind nothing. On top of that, this fetch is STRICT where the
//! crawl is opportunistic — the document is the URL's own statement about
//! itself, so:
//!
//!   * redirects are not followed at all: a 3xx is a non-success answer, so no
//!     other URL's bytes — on another host, another port, or another path of the
//!     same origin — can ever stand in for the document at this one;
//!   * a body over the cap, one whose transfer failed part-way, or one that is
//!     not valid UTF-8 is an error, never a shorter or a normalised document;
//!   * the caller's timeout is ONE deadline over the whole operation, DNS
//!     resolution included, so a slow resolver cannot hold the caller past it —
//!     and it is the only deadline, so however far the fetch got when it ran out
//!     of time, the caller sees the same "did not complete" error.
//!
//! Failures are typed ([`FetchError`]) so a caller can tell what is about the URL
//! (the guard refuses it; the origin answers 404 or a redirect; the body is too
//! large or not UTF-8) from what is about the moment (a resolver that did not
//! answer, a deadline, a connection that failed, a 5xx) — the first kind may be
//! remembered, the second may not.
//!
//! The origin's caching instruction is reported as the REMAINING freshness
//! lifetime, per HTTP: every `Cache-Control` field line is read (a `no-store` on
//! a second line counts), and the response's current age — the larger of its
//! `Age` and the time since its `Date` — is subtracted from `max-age`; where
//! `Cache-Control` grants no freshness, `Expires` relative to `Date` decides.

use std::{
    fmt,
    time::{Duration, SystemTime},
};

use reqwest::header::{HeaderMap, AGE, CACHE_CONTROL, CONTENT_TYPE, DATE, EXPIRES, VARY};

use crate::discover::{read_capped_bytes, resolve_public_url, ResolveError};

/// A small public document fetched under the SSRF guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicDocument {
    /// The complete body (it fit under the caller's cap), valid UTF-8.
    pub body: String,
    /// The `Content-Type` the origin sent, if any.
    pub content_type: Option<String>,
    /// How much longer a SHARED cache may reuse this, per HTTP caching (RFC
    /// 9111), as [`freshness`] computes it: the lifetime — `s-maxage`, else
    /// `max-age`, from every `Cache-Control` line combined, else `Expires` less
    /// `Date` — minus the response's current age (the larger of `Age` and the
    /// time since `Date`). `Some(0)` when the origin forbids reuse (`no-store`,
    /// `no-cache`, `private`, `Vary: *`), gives an invalid or already-spent
    /// lifetime, or the freshness has run out; `None` when it sent no freshness
    /// information at all. A hint for the caller's own cache, for the caller to
    /// bound — never binding.
    pub cache_max_age: Option<Duration>,
}

/// Why a document was not returned, split by what the failure is ABOUT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchError {
    /// The URL itself: it does not parse, is not https, names no host, or names
    /// one with a non-public address. No request was made.
    Refused(String),
    /// The moment: the host could not be resolved, the deadline passed, or the
    /// request could not be sent or its body not read. The same URL may work
    /// next time.
    Unreachable(String),
    /// The origin answered, but not 2xx — a redirect (never followed) included.
    /// `status` lets the caller tell a 404 (no document there) from a 503.
    Answered { status: u16, detail: String },
    /// The body is larger than the caller's cap.
    TooLarge(String),
    /// The body is not valid UTF-8.
    NotUtf8(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(s) | Self::Unreachable(s) | Self::TooLarge(s) | Self::NotUtf8(s) => {
                f.write_str(s)
            }
            Self::Answered { detail, .. } => f.write_str(detail),
        }
    }
}

impl std::error::Error for FetchError {}

/// GET `url` and return its body, or why not ([`FetchError`]): the URL is refused
/// by the SSRF guard; resolving, connecting, answering and delivering the body
/// did not all complete within `timeout`; the answer was anything but 2xx (a
/// redirect included); the body is larger than `max_bytes`, was cut off, or is
/// not UTF-8.
pub async fn fetch_public_document(
    url: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<PublicDocument, FetchError> {
    // One deadline over everything, resolution included: `resolve_public_url`
    // does the DNS lookup, and a resolver that never answers must not hold the
    // caller (and whatever it is holding, such as an in-flight permit) forever.
    // Deliberately the ONLY deadline — the client below sets none of its own —
    // so the error is the same wherever the time ran out, and dropping the
    // future on expiry is what aborts the connection.
    tokio::time::timeout(timeout, fetch(url, max_bytes)).await.map_err(|_| {
        FetchError::Unreachable(format!("fetching {url} did not complete within {timeout:?}"))
    })?
}

async fn fetch(url: &str, max_bytes: usize) -> Result<PublicDocument, FetchError> {
    let (parsed, pinned) = resolve_public_url(url).await.map_err(|e| match e {
        ResolveError::Refused(why) => FetchError::Refused(why),
        ResolveError::Unresolved(why) => FetchError::Unreachable(why),
    })?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let client = reqwest::Client::builder()
        .user_agent(concat!("imcp2-core/", env!("CARGO_PKG_VERSION")))
        // Never follow a redirect: the document is this URL's statement about
        // itself, and a 3xx is that URL declining to make it. Refusing here (rather
        // than following under the crawl's redirect guard and comparing origins
        // afterwards) also closes the same-origin case, where a redirect to another
        // path would have put a different document behind this URL.
        .redirect(reqwest::redirect::Policy::none())
        // Direct, whatever the environment says: the pin below binds only a
        // connection this client opens itself, and a proxy (reqwest takes one from
        // `HTTPS_PROXY` by default) would resolve the host on its own — past the
        // guard. A deployment that must egress through a proxy has that proxy do
        // the guard's job, as a deliberate choice, not one this fetch takes silently.
        .no_proxy()
        .resolve_to_addrs(&host, &pinned)
        .build()
        .map_err(|e| FetchError::Unreachable(format!("http client: {e}")))?;
    let resp = client
        .get(parsed.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| FetchError::Unreachable(format!("could not fetch {url}: {e}")))?;
    accept(url, resp, max_bytes).await
}

/// Turn the origin's answer into a [`PublicDocument`], or refuse it: anything
/// but 2xx (a redirect is named as such, since it is not followed), a body over
/// `max_bytes` or cut off mid-transfer, or one that is not valid UTF-8. Kept apart
/// from the sending so the acceptance rules are pinned by tests on synthetic
/// responses, with no network.
async fn accept(
    url: &str,
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<PublicDocument, FetchError> {
    let status = resp.status();
    if !status.is_success() {
        let redirect =
            if status.is_redirection() { ", a redirect, which is not followed" } else { "" };
        return Err(FetchError::Answered {
            status: status.as_u16(),
            detail: format!("{url} answered {status}{redirect}"),
        });
    }
    let content_type =
        resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let cache_max_age = freshness(resp.headers(), SystemTime::now());
    // Read ONE byte past the cap so overflow is detectable: a truncated body is
    // not a shorter document. Saturating, so a caller passing `usize::MAX` (no
    // cap) reads everything rather than wrapping to a zero-byte read.
    let bytes = match read_capped_bytes(resp, max_bytes.saturating_add(1)).await {
        Ok(bytes) if bytes.len() > max_bytes => {
            return Err(FetchError::TooLarge(format!(
                "{url} is larger than the {max_bytes}-byte cap"
            )))
        }
        Ok(bytes) => bytes,
        Err((_, e)) => {
            return Err(FetchError::Unreachable(format!("reading {url} failed part-way: {e}")))
        }
    };
    // Strict, not lossy: a byte that is not UTF-8 is refused rather than replaced,
    // so the document parsed is exactly the one served.
    let body = String::from_utf8(bytes)
        .map_err(|e| FetchError::NotUtf8(format!("{url} is not valid UTF-8: {e}")))?;
    Ok(PublicDocument { body, content_type, cache_max_age })
}

/// The remaining freshness lifetime the response's headers grant, per HTTP
/// caching (RFC 9111 §4.2). The lifetime is `max-age` (or `s-maxage`) from the
/// COMBINED `Cache-Control` fields (a header may be sent as several lines, and a
/// `no-store` on any of them wins); where those grant no freshness, it is
/// `Expires` less `Date` (less `now`, when there is no `Date`), an `Expires`
/// that is invalid — `0` is the classic — or already past meaning stale (§5.3).
/// From it the response's CURRENT AGE is subtracted — the larger of its `Age`
/// and its apparent age, `now` less its `Date`, so an answer some cache held for
/// an hour without saying so in `Age` is not given a new lifetime here. A `Date`
/// in the future (clock skew) is an apparent age of zero. A response that varies
/// on everything (`Vary: *`) has no freshness at all for a shared cache, whatever
/// else it says (§4.1: it can never match a later request). `None` when neither
/// a freshness directive nor `Expires` was sent.
fn freshness(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let varies_on_everything = headers
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|field| field.trim() == "*");
    if varies_on_everything {
        return Some(Duration::ZERO);
    }
    let header = |name| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim);
    let date = header(DATE).and_then(|v| httpdate::parse_http_date(v).ok());
    let cache_control: Vec<&str> =
        headers.get_all(CACHE_CONTROL).iter().filter_map(|v| v.to_str().ok()).collect();
    let from_cache_control =
        (!cache_control.is_empty()).then(|| cache_max_age(&cache_control.join(", "))).flatten();
    let lifetime = match from_cache_control {
        Some(lifetime) => lifetime,
        None => {
            let expires = header(EXPIRES)?;
            httpdate::parse_http_date(expires)
                .ok()
                .and_then(|expires| expires.duration_since(date.unwrap_or(now)).ok())
                .unwrap_or(Duration::ZERO)
        }
    };
    // Every `Age` line counts and the greatest wins; one that is sent but does not
    // parse — overflowing, not a number, not even ASCII — is taken as the largest
    // age, not as none (RFC 9111 §1.2.2 has oversized delta-seconds treated as the
    // greatest value): a response of unknowable age is not given a whole lifetime.
    let age = headers
        .get_all(AGE)
        .iter()
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map_or(Duration::MAX, Duration::from_secs)
        })
        .max()
        .unwrap_or(Duration::ZERO);
    let apparent_age =
        date.and_then(|date| now.duration_since(date).ok()).unwrap_or(Duration::ZERO);
    Some(lifetime.saturating_sub(age.max(apparent_age)))
}

/// The caching lifetime a `Cache-Control` value grants a SHARED cache — which the
/// caller's process-wide cache is: `s-maxage` if present, else `max-age`; zero
/// when the origin forbids shared reuse (`no-store`, `no-cache`, `private`);
/// `None` when it says none of these. Directives are recognised by NAME, so
/// `no-cache="set-cookie"` still counts. One given more than once is honoured at
/// its MOST RESTRICTIVE value, and one given without a valid number is ZERO —
/// stale, never a default lifetime (RFC 9111 §4.2.1: invalid or conflicting
/// freshness information must not extend freshness) — so `max-age=300,
/// max-age=0` is zero, not five minutes, and so is `max-age=soon`. A value that
/// cannot be parsed at all (an unterminated quoted-string) is zero too.
fn cache_max_age(cache_control: &str) -> Option<Duration> {
    let Some(directives) = cache_directives(cache_control) else {
        return Some(Duration::ZERO);
    };
    let has = |wanted: &str| directives.iter().any(|(name, _)| name.eq_ignore_ascii_case(wanted));
    if has("no-store") || has("no-cache") || has("private") {
        return Some(Duration::ZERO);
    }
    // A directive's lifetime: `None` when absent; else the most restrictive of
    // its values, an unparseable one counting as zero.
    let lifetime = |wanted: &str| {
        directives
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, arg)| {
                arg.as_deref()
                    .and_then(|a| a.parse::<u64>().ok())
                    .map_or(Duration::ZERO, Duration::from_secs)
            })
            .min()
    };
    lifetime("s-maxage").or_else(|| lifetime("max-age"))
}

/// The directives of a `Cache-Control` value, each as (name, argument), split at
/// the commas that are NOT inside a quoted-string: an argument may be quoted and
/// then contain commas and backslash-escaped characters (RFC 9110 §5.6.4), so
/// `foo="x,s-maxage=86400", max-age=60` is `foo` and `max-age`, not an
/// `s-maxage` of a day. Quotes and escapes are removed from the argument. `None`
/// when the value cannot be parsed (a quoted-string never closes).
fn cache_directives(value: &str) -> Option<Vec<(String, Option<String>)>> {
    let mut raw: Vec<String> = Vec::new();
    let mut current = String::new();
    let (mut in_quotes, mut escaped) = (false, false);
    for c in value.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => {
                escaped = true;
                current.push(c);
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => raw.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    if in_quotes || escaped {
        return None;
    }
    raw.push(current);
    let unquote = |arg: &str| -> String {
        let Some(inner) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) else {
            return arg.to_owned();
        };
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            out.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
        }
        out
    };
    Some(
        raw.iter()
            .map(|d| d.trim())
            .filter(|d| !d.is_empty())
            .map(|d| match d.split_once('=') {
                Some((name, arg)) => (name.trim().to_owned(), Some(unquote(arg.trim()))),
                None => (d.to_owned(), None),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{accept, cache_max_age, fetch_public_document, freshness, FetchError};

    /// A response as the origin might send it, for pinning the acceptance rules
    /// without a network: `status`, `headers` (repeatable), `body`.
    fn synthetic(status: u16, headers: &[(&str, &str)], body: &[u8]) -> reqwest::Response {
        let mut b = http::Response::builder().status(status);
        for (name, value) in headers {
            b = b.header(*name, *value);
        }
        reqwest::Response::from(b.body(body.to_vec()).expect("synthetic response"))
    }

    const URL: &str = "https://client.example/client.json";

    /// The SSRF guard decides before any request: these never touch the network
    /// (IP-literal hosts need no DNS), and each is refused for the reason the
    /// guard names — as `Refused`, the failure that is about the URL.
    #[tokio::test]
    async fn guard_refuses_before_fetching() {
        let fetch = |url: &'static str| fetch_public_document(url, 1024, Duration::from_secs(1));
        let Err(FetchError::Refused(why)) = fetch("http://example.com/client.json").await else {
            panic!("http must be refused by the guard");
        };
        assert!(why.contains("only https"), "{why}");
        for internal in [
            "https://127.0.0.1/client.json",
            "https://10.0.0.1/client.json",
            "https://192.168.1.1/client.json",
            "https://192.88.99.1/client.json",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/client.json",
            "https://[::ffff:127.0.0.1]/client.json",
            "https://[fec0::1]/client.json",
            "https://[fe80::1]/client.json",
            "https://[fd00::1]/client.json",
            "https://[100::1]/client.json",
            "https://[3fff::1]/client.json",
            "https://[5f00::1]/client.json",
            "https://[4000::1]/client.json",
            "https://[2001:1::4]/client.json",
        ] {
            let Err(FetchError::Refused(why)) = fetch(internal).await else {
                panic!("{internal} must be refused by the guard");
            };
            assert!(why.contains("non-public address"), "{internal}: {why}");
        }
        assert!(matches!(fetch("not a url").await, Err(FetchError::Refused(_))));
        // An uncapped read is a valid request, not an overflow.
        let uncapped = fetch_public_document("https://[::1]/x", usize::MAX, Duration::from_secs(1));
        assert!(matches!(uncapped.await, Err(FetchError::Refused(_))));
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
        let FetchError::Unreachable(why) = &err else { panic!("{err:?}") };
        assert!(why.contains("did not complete within"), "{why}");
    }

    /// A redirect is refused as such — its target is never requested, since the
    /// client follows none — and so is any other non-2xx answer, each carrying its
    /// status so the caller can tell "no document there" from "not right now".
    #[tokio::test]
    async fn accept_refuses_redirects_and_errors() {
        for status in [301u16, 302, 307, 308] {
            let resp = synthetic(status, &[("location", "https://client.example/other.json")], b"");
            let err = accept(URL, resp, 1024).await.unwrap_err();
            let FetchError::Answered { status: got, detail } = &err else { panic!("{err:?}") };
            assert_eq!(*got, status);
            assert!(detail.contains("not followed"), "{detail}");
        }
        for status in [404u16, 500, 503] {
            let err = accept(URL, synthetic(status, &[], b"nope"), 1024).await.unwrap_err();
            assert!(
                matches!(err, FetchError::Answered { status: got, .. } if got == status),
                "{err:?}"
            );
        }
    }

    /// The body is taken only complete and only as valid UTF-8; the media type and
    /// the remaining freshness ride along.
    #[tokio::test]
    async fn accept_takes_only_a_complete_valid_body() {
        let headers =
            [("content-type", "application/json; charset=utf-8"), ("cache-control", "max-age=300")];
        let doc =
            accept(URL, synthetic(200, &headers, br#"{"client_id":"x"}"#), 1024).await.unwrap();
        assert_eq!(doc.body, r#"{"client_id":"x"}"#);
        assert_eq!(doc.content_type.as_deref(), Some("application/json; charset=utf-8"));
        assert_eq!(doc.cache_max_age, Some(Duration::from_secs(300)));
        // Over the cap: an error, not a truncated document. The cap is exact.
        let body = br#"{"client_id":"x"}"#;
        assert!(accept(URL, synthetic(200, &[], body), body.len()).await.is_ok());
        let err = accept(URL, synthetic(200, &[], body), body.len() - 1).await.unwrap_err();
        assert!(matches!(err, FetchError::TooLarge(_)), "{err:?}");
        // A byte that is not UTF-8 is refused, not replaced.
        let err = accept(URL, synthetic(200, &[], b"{\"client_name\":\"\xff\"}"), 1024)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::NotUtf8(_)), "{err:?}");
    }

    /// Freshness follows HTTP: every `Cache-Control` line counts, and the current
    /// age — `Age`, or the time since `Date`, whichever is larger — is subtracted,
    /// so a CDN answer near the end of its life is not given a new one.
    #[test]
    fn freshness_honours_age_and_every_cache_control_line() {
        use std::time::{SystemTime, UNIX_EPOCH};
        // A whole-second "now", since an HTTP date has no finer resolution.
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let now = UNIX_EPOCH + Duration::from_secs(since_epoch);
        let headers = |pairs: &[(&str, &str)]| {
            let mut h = reqwest::header::HeaderMap::new();
            for (name, value) in pairs {
                h.append(
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            h
        };
        assert_eq!(freshness(&headers(&[]), now), None);
        assert_eq!(freshness(&headers(&[("age", "10")]), now), None);
        assert_eq!(
            freshness(&headers(&[("cache-control", "public, max-age=86400")]), now),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(
            freshness(&headers(&[("cache-control", "max-age=86400"), ("age", "86399")]), now),
            Some(Duration::from_secs(1))
        );
        // Freshness already spent: zero, not negative and not a fresh lifetime.
        assert_eq!(
            freshness(&headers(&[("cache-control", "max-age=300"), ("age", "301")]), now),
            Some(Duration::ZERO)
        );
        // An Age that overflows, or is no number, is the greatest age, not none.
        let overflowing = [("cache-control", "max-age=86400"), ("age", "99999999999999999999")];
        assert_eq!(freshness(&headers(&overflowing), now), Some(Duration::ZERO));
        let nonsense = [("cache-control", "max-age=86400"), ("age", "soon")];
        assert_eq!(freshness(&headers(&nonsense), now), Some(Duration::ZERO));
        // Every Age line counts, the greatest winning; one that is not even ASCII
        // is the greatest age too.
        let two_lines = [("cache-control", "max-age=300"), ("age", "10"), ("age", "400")];
        assert_eq!(freshness(&headers(&two_lines), now), Some(Duration::ZERO));
        let mut opaque = headers(&[("cache-control", "max-age=86400")]);
        opaque.append(
            reqwest::header::AGE,
            reqwest::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_eq!(freshness(&opaque, now), Some(Duration::ZERO));
        // Two Cache-Control lines: the no-store on the second is not missed.
        assert_eq!(
            freshness(
                &headers(&[("cache-control", "max-age=300"), ("cache-control", "no-store")]),
                now
            ),
            Some(Duration::ZERO)
        );
        // The apparent age counts too: a Date an hour old with no Age means the
        // answer has been held for an hour, and five fresh minutes are long gone.
        let dated = |secs_ago: u64| httpdate::fmt_http_date(now - Duration::from_secs(secs_ago));
        let stale = [("cache-control", "max-age=300"), ("date", &dated(3600))];
        assert_eq!(freshness(&headers(&stale), now), Some(Duration::ZERO));
        // The current age is the LARGER of Age and apparent age, either way round.
        let aged = [("cache-control", "max-age=300"), ("date", &dated(50)), ("age", "100")];
        assert_eq!(freshness(&headers(&aged), now), Some(Duration::from_secs(200)));
        let held = [("cache-control", "max-age=300"), ("date", &dated(100)), ("age", "50")];
        assert_eq!(freshness(&headers(&held), now), Some(Duration::from_secs(200)));
        // A Date in the future (clock skew) is an apparent age of zero, not a
        // negative one.
        let future = httpdate::fmt_http_date(now + Duration::from_secs(3600));
        let skewed = [("cache-control", "max-age=300"), ("date", &future)];
        assert_eq!(freshness(&headers(&skewed), now), Some(Duration::from_secs(300)));
        // Where Cache-Control grants no freshness, Expires decides — relative to
        // Date, or to now without one — so it comes to "Expires less now"; an
        // Expires already past, or invalid ("0" is the classic), is stale, never
        // the default lifetime.
        let ahead = |secs: u64| httpdate::fmt_http_date(now + Duration::from_secs(secs));
        assert_eq!(
            freshness(&headers(&[("expires", &ahead(120))]), now),
            Some(Duration::from_secs(120))
        );
        let (date, expires) = (dated(100), ahead(200));
        let with_date = [("date", date.as_str()), ("expires", expires.as_str())];
        assert_eq!(freshness(&headers(&with_date), now), Some(Duration::from_secs(200)));
        assert_eq!(freshness(&headers(&[("expires", &dated(3600))]), now), Some(Duration::ZERO));
        assert_eq!(freshness(&headers(&[("expires", "0")]), now), Some(Duration::ZERO));
        let public = [("cache-control", "public"), ("expires", &ahead(90))];
        assert_eq!(freshness(&headers(&public), now), Some(Duration::from_secs(90)));
        // A Cache-Control that does speak to freshness wins over Expires, either way.
        let both = [("cache-control", "max-age=60"), ("expires", &ahead(86400))];
        assert_eq!(freshness(&headers(&both), now), Some(Duration::from_secs(60)));
        let forbidden = [("cache-control", "no-store"), ("expires", &ahead(86400))];
        assert_eq!(freshness(&headers(&forbidden), now), Some(Duration::ZERO));
        // `Vary: *` can never match a later request: no freshness for a shared
        // cache, whatever the lifetime says — on its own or among other fields.
        let varies = [("cache-control", "max-age=86400"), ("vary", "*")];
        assert_eq!(freshness(&headers(&varies), now), Some(Duration::ZERO));
        let among = [("cache-control", "max-age=60"), ("vary", "Accept-Encoding, *")];
        assert_eq!(freshness(&headers(&among), now), Some(Duration::ZERO));
        let ordinary = [("cache-control", "max-age=60"), ("vary", "accept-encoding")];
        assert_eq!(freshness(&headers(&ordinary), now), Some(Duration::from_secs(60)));
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
        // Given but not a number: stale, never the default lifetime.
        assert_eq!(cache_max_age("max-age=soon"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age=300, max-age=soon"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("s-maxage=soon, max-age=300"), Some(Duration::ZERO));
        // A duplicated max-age is honoured at its most restrictive value, never
        // the one that happens to come first.
        assert_eq!(cache_max_age("max-age=300, max-age=0"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age=0, max-age=300"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age=300, public, max-age=60"), Some(Duration::from_secs(60)));
        // The caller is a SHARED cache: `private` forbids it reuse, and `s-maxage`
        // is its lifetime whenever present, over `max-age`.
        assert_eq!(cache_max_age("private, max-age=86400"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("s-maxage=0, max-age=86400"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age=600, s-maxage=60"), Some(Duration::from_secs(60)));
        assert_eq!(cache_max_age("s-maxage=600, max-age=60"), Some(Duration::from_secs(600)));
        // Directives are matched by name, however they are argued.
        assert_eq!(cache_max_age("max-age=300, no-cache=\"set-cookie\""), Some(Duration::ZERO));
        assert_eq!(cache_max_age("No-Store"), Some(Duration::ZERO));
        // A comma inside a quoted argument does not start a directive, so an
        // extension's argument cannot smuggle in a day of freshness; escapes are
        // honoured; a quoted-string that never closes is not reused at all.
        assert_eq!(
            cache_max_age("foo=\"x,s-maxage=86400\", max-age=60"),
            Some(Duration::from_secs(60))
        );
        assert_eq!(cache_max_age("ext=\"a\\\"b,c\", max-age=30"), Some(Duration::from_secs(30)));
        assert_eq!(cache_max_age("foo=\"x, max-age=60"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("max-age=\"45\""), Some(Duration::from_secs(45)));
    }

    /// A host that cannot be resolved is a failure of the MOMENT, not of the URL:
    /// `Unreachable`, never `Refused`, or a caller that remembers refusals would
    /// remember a resolver outage as "no document there".
    #[tokio::test]
    async fn unresolvable_host_is_unreachable_not_refused() {
        let err = fetch_public_document(
            "https://does-not-exist.invalid/client.json",
            1024,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FetchError::Unreachable(_)), "{err:?}");
    }
}
