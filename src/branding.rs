//! Verified-connector branding: surface a vetted MCP client's product name and
//! logo to Internet Identity's consent screen, so the user sees WHICH vetted
//! product is requesting the connect rather than granting their II accounts to an
//! anonymous "some bridge".
//!
//! **The server is the only source of branding, and it answers per session.** II
//! asks `GET {issuer}/branding?state={state}` — the `state` it already holds from
//! the connect link — and the server derives the connector from that pending,
//! unexpired connect's **validated** `redirect_uri` (see
//! [`AuthStore::pending_redirect_uri`]). Nothing in the connect-link fragment
//! asserts branding: the fragment is attacker-craftable (a native client drives
//! the navigation and sees the 302), so a client-supplied slug there would let
//! any valid session claim to be "verified Claude". Binding to the session's
//! validated redirect closes that at the root: a loopback (native-app) session,
//! or one on an unlisted host, reads as anonymous no matter what the fragment
//! says.
//!
//! Keyed on the **vetted redirect vendor**, never on the client-supplied
//! `client_name`/`logo_uri`: open DCR takes all callers, so client-supplied
//! identity is attacker-controlled. Anyone may *register* a vetted
//! `redirect_uri`, but the path-pinned allow-list means the authorization code
//! for it is delivered only to that vendor's own callback — so whoever completes
//! the connect is that vendor, and the redirect vendor is a sound,
//! server-curated proxy for product identity. (That holds for a conforming
//! browser; a user agent the attacker controls, such as an embedded webview, is
//! out of scope for branding as it is for the rest of the flow.) Host matching
//! reuses validation's own rule ([`crate::auth::host_key`],
//! [`crate::auth::host_is_or_under`]), and a redirect validation would refuse
//! never resolves, so branding and validation cannot disagree about a vendor.
//!
//! Endpoints, both issuer-rooted (same origin as the #4091-validated callback):
//! `GET /branding?state=…` (session-bound metadata: name, logo URL, `verified`)
//! and `GET /branding/{slug}/logo` (the bundled image — a static per-connector
//! asset, no trust decision). II-side coordination is required to render any of
//! this — including showing the `verified` badge only for imcp2 issuer origins II
//! itself trusts, and using the one `state` it parsed from the link for both the
//! lookup and the callback. Until that ships, the endpoints are inert.

use axum::{
    extract::{rejection::QueryRejection, Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{host_is_or_under, host_key, redirect_uri_permitted, AuthStore};

/// A vetted connector's server-curated branding.
pub(crate) struct Connector {
    /// Stable slug: the `/branding/{slug}/logo` path segment. Server-determined,
    /// never client-supplied.
    pub slug: &'static str,
    /// Human display name shown on the consent screen.
    pub name: &'static str,
    /// Apex domains identifying this vendor, matched against the validated
    /// `redirect_uri` host — the host itself or a dot-boundary subdomain of it.
    domains: &'static [&'static str],
    /// The bundled logo (SVG markup). A NEUTRAL PLACEHOLDER today
    /// ([`PLACEHOLDER_LOGO_SVG`]); swap this per-connector for the vendor's own
    /// licensed mark.
    logo: &'static str,
}

/// A neutral, generic "verified connector" mark — ORIGINAL artwork (a check in a
/// ring on a parchment tile), deliberately NOT a reproduction of any vendor's
/// logo, which would be a trademark/licensing matter this repo should not decide.
/// It is the placeholder for every connector until each vendor's own licensed
/// mark is dropped into its [`Connector::logo`]. II renders it via a fixed-size
/// `<img src>` (an `<img>`-loaded SVG cannot execute script), so it needs no
/// server-side sanitising.
pub(crate) const PLACEHOLDER_LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="Verified connector"><rect width="96" height="96" rx="20" fill="#ece7db"/><circle cx="48" cy="48" r="22" fill="none" stroke="#8a8574" stroke-width="6"/><path d="M38 48l7 8 14-16" fill="none" stroke="#8a8574" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

/// The vetted connectors and their curated branding. The domains are exactly the
/// vendor domains of the compiled-in `DEFAULT_ALLOWED_REDIRECTS` (a test holds
/// the two sets equal); a host ops adds via `OAUTH_ALLOWED_REDIRECT_PREFIXES` is
/// accepted for redirects but stays anonymous until it is curated here. v1
/// covers self-authenticating WEB connectors only; native/loopback apps stay
/// anonymous (their only identity signal is a spoofable `client_name`). Logos
/// are placeholders — see [`PLACEHOLDER_LOGO_SVG`].
pub(crate) const CONNECTORS: &[Connector] = &[
    Connector {
        slug: "chatgpt",
        name: "ChatGPT",
        domains: &["chatgpt.com"],
        logo: PLACEHOLDER_LOGO_SVG,
    },
    Connector {
        slug: "claude",
        name: "Claude",
        domains: &["claude.ai"],
        logo: PLACEHOLDER_LOGO_SVG,
    },
    Connector {
        slug: "cursor",
        name: "Cursor",
        domains: &["cursor.com"],
        logo: PLACEHOLDER_LOGO_SVG,
    },
    Connector { slug: "grok", name: "Grok", domains: &["grok.com"], logo: PLACEHOLDER_LOGO_SVG },
    Connector {
        slug: "perplexity",
        name: "Perplexity",
        domains: &["perplexity.ai", "perplexity.com"],
        logo: PLACEHOLDER_LOGO_SVG,
    },
    Connector {
        slug: "antigravity",
        name: "Google Antigravity",
        domains: &["antigravity.google"],
        logo: PLACEHOLDER_LOGO_SVG,
    },
];

/// The vetted connector a `redirect_uri` belongs to, if any. The redirect must
/// pass validation itself ([`redirect_uri_permitted`]: allow-listed path, no
/// port, userinfo, query, or percent-encoding) and be `https`, so this never
/// depends on its caller having validated; the host then matches exactly as
/// validation does — trailing root dots trimmed, lowercased, dot-boundary
/// subdomains. `None` for loopback or an unlisted host, which read as anonymous.
pub(crate) fn connector_for_redirect(redirect_uri: &str) -> Option<&'static Connector> {
    if !redirect_uri_permitted(redirect_uri) {
        return None;
    }
    let url = url::Url::parse(redirect_uri).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = host_key(url.host_str()?);
    CONNECTORS.iter().find(|c| c.domains.iter().any(|domain| host_is_or_under(&host, domain)))
}

/// The connector for a curated slug, or `None` for any slug outside the set (so a
/// `/branding/{slug}/logo` path segment can never probe arbitrary keys).
pub(crate) fn connector_by_slug(slug: &str) -> Option<&'static Connector> {
    CONNECTORS.iter().find(|c| c.slug == slug)
}

/// `?state=` of the session-bound metadata request: the connect `state` (= the
/// pending session id) II already holds from the connect link.
#[derive(Deserialize)]
pub(crate) struct BrandingQuery {
    pub(crate) state: Option<String>,
}

/// `GET {issuer}/branding?state={state}` — the connector branding for ONE pending
/// connect: the curated name, the absolute logo URL, and `verified`, derived from
/// that connect's validated redirect. `404` — identically — for a missing,
/// unknown, or expired `state` and for a session whose redirect is not a vetted
/// connector (loopback / unlisted), so the response is no oracle for which
/// sessions exist; a malformed query (e.g. a repeated `state`) gets that same
/// 404 rather than axum's 400. `no-store`: the answer is per-session.
pub(crate) async fn branding_metadata(
    State(store): State<AuthStore>,
    query: Result<Query<BrandingQuery>, QueryRejection>,
) -> Response {
    let Some(state) = query.ok().and_then(|Query(query)| query.state) else {
        return branding_not_found();
    };
    let Some(redirect) = store.pending_redirect_uri(&state).await else {
        return branding_not_found();
    };
    let Some(connector) = connector_for_redirect(&redirect) else {
        return branding_not_found();
    };
    let logo = format!("{}/branding/{}/logo", store.issuer(), connector.slug);
    let mut resp =
        Json(json!({ "name": connector.name, "logo": logo, "verified": true })).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `GET {issuer}/branding/{slug}/logo` — the bundled connector logo (SVG bytes),
/// with `nosniff` and a cache header. `404` outside the curated set. A static
/// per-connector asset: it makes no claim about any session (that is
/// [`branding_metadata`]'s job, whose `logo` URL points here). II MUST render it
/// via a fixed-size `<img src>`, never inline the SVG into the consent DOM: an
/// `<img>`-loaded SVG cannot execute script, an inlined one can.
pub(crate) async fn branding_logo(Path(slug): Path<String>) -> Response {
    let Some(connector) = connector_by_slug(&slug) else {
        return branding_not_found();
    };
    let mut resp = (StatusCode::OK, connector.logo).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    resp
}

/// No branding for this request: 404, the same for every reason.
fn branding_not_found() -> Response {
    (StatusCode::NOT_FOUND, "no connector branding").into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{connector_by_slug, connector_for_redirect, CONNECTORS};

    #[test]
    fn resolves_vetted_redirect_vendors_to_their_slug() {
        let cases = [
            ("https://chatgpt.com/connector/oauth/abc", "chatgpt"),
            ("https://claude.ai/api/mcp/auth_callback", "claude"),
            ("https://cursor.com/agents/mcp/oauth/callback", "cursor"),
            ("https://grok.com/mcp/callback", "grok"),
            ("https://perplexity.ai/rest/connections/oauth_callback", "perplexity"),
            ("https://antigravity.google/oauth-callback", "antigravity"),
            // Subdomains (Perplexity uses www/staging/…; Cursor registers www).
            ("https://www.perplexity.ai/rest/connections/oauth_callback", "perplexity"),
            ("https://www.cursor.com/agents/mcp/oauth/callback", "cursor"),
            // A trailing root dot names the same host; validation accepts it, so
            // branding must resolve it too.
            ("https://claude.ai./api/mcp/auth_callback", "claude"),
            // Host case never matters.
            ("https://CLAUDE.AI/api/mcp/auth_callback", "claude"),
        ];
        for (redirect, slug) in cases {
            assert_eq!(
                connector_for_redirect(redirect).map(|c| c.slug),
                Some(slug),
                "redirect {redirect}"
            );
        }
    }

    #[test]
    fn unvetted_and_lookalike_and_loopback_get_no_branding() {
        // Loopback (native app) → no branding, by design.
        assert!(connector_for_redirect("http://127.0.0.1:5173/cb").is_none());
        assert!(connector_for_redirect("http://[::1]:8080/cb").is_none());
        assert!(connector_for_redirect("http://localhost/cb").is_none());
        // An unlisted vendor → none.
        assert!(connector_for_redirect("https://attacker.example/cb").is_none());
        // Look-alikes must NOT match at a non-segment boundary.
        assert!(connector_for_redirect("https://evilchatgpt.com/cb").is_none());
        assert!(connector_for_redirect("https://claude.ai.attacker.example/cb").is_none());
        // A non-https vetted host never resolves (validation would refuse it).
        assert!(connector_for_redirect("http://claude.ai/api/mcp/auth_callback").is_none());
        // Not a URL at all → none, never a panic.
        assert!(connector_for_redirect("not a url").is_none());
    }

    #[test]
    fn a_redirect_validation_refuses_never_resolves() {
        // A vetted host, but a path off its pin, a port, userinfo, a query, or
        // percent-encoding: validation refuses each, so branding must too.
        for redirect in [
            "https://claude.ai/not/the/callback",
            "https://claude.ai:8443/api/mcp/auth_callback",
            "https://user@claude.ai/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth_callback?x=1",
            "https://claude.ai/api/mcp/auth_callback/%2e%2e",
        ] {
            assert!(connector_for_redirect(redirect).is_none(), "redirect {redirect}");
        }
    }

    #[test]
    fn connector_domains_are_the_compiled_in_allow_list_vendors() {
        // Every vetted vendor is curated, and nothing is curated that cannot
        // obtain a vetted redirect — so a new allow-list entry fails this test
        // until someone decides its branding.
        let curated: BTreeSet<&str> =
            CONNECTORS.iter().flat_map(|c| c.domains.iter().copied()).collect();
        assert_eq!(curated, crate::auth::default_redirect_domains());
    }

    #[test]
    fn slug_lookup_is_closed_to_the_curated_set() {
        assert!(connector_by_slug("claude").is_some());
        assert!(connector_by_slug("unknown").is_none());
        assert!(connector_by_slug("../secrets").is_none());
        assert!(connector_by_slug("").is_none());
        for c in CONNECTORS {
            assert!(!c.slug.is_empty() && !c.name.is_empty());
        }
    }
}
