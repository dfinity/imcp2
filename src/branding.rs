//! Verified-connector branding: surface a vetted MCP client's product name and
//! logo to Internet Identity's consent screen, so the user sees WHICH vetted
//! product is requesting the connect rather than granting their II accounts to an
//! anonymous "some bridge".
//!
//! Keyed on the **vetted redirect vendor** — the request's already-validated
//! `redirect_uri` host matched against the hosted-redirect allow-list — never on
//! the client-supplied `client_name`/`logo_uri`. Open DCR (`/oauth/register`)
//! takes all callers, so client-supplied identity is attacker-controlled;
//! rendering it would be a consent-phishing gift (a hostile client registering
//! `client_name: "Internet Identity"` with a lookalike mark). A client can only
//! obtain a vetted `redirect_uri` if it genuinely is that vendor (the path-pinned
//! allow-list, [`crate::auth`]), so the redirect vendor is a sound, server-curated
//! proxy for product identity. A connect that does not resolve to a vetted vendor
//! — including every loopback (native-app) redirect — gets the status-quo
//! anonymous consent screen; nothing regresses, it just gets no name/logo.
//!
//! II reads two GET endpoints from this origin (the SAME origin as the connect
//! callback it already validated via #4091): `/branding/{slug}` (name + logo URL +
//! `verified`) and `/branding/{slug}/logo` (the bundled image). Both 404 for any
//! slug outside the curated set, so the path segment can't be used to probe. The
//! slug rides the connect link as `&connector={slug}` (see
//! `iiconnect::ii_mcp_url`). Design: `docs/scoping-client-branding.md`.
//!
//! II-side coordination is required to actually render this (parse the slug, fetch
//! these endpoints from the validated callback origin, show a "verified connector"
//! treatment). Until it ships, these endpoints and the link param are inert and
//! harmless.

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::auth::AuthStore;

/// A vetted connector's server-curated branding.
pub(crate) struct Connector {
    /// Stable slug: the `&connector=<slug>` value in the connect link and the
    /// `/branding/{slug}` path segment. Server-determined, never client-supplied.
    pub slug: &'static str,
    /// Human display name shown on the consent screen.
    pub name: &'static str,
    /// Apex domains identifying this vendor, matched against the (already
    /// validated) `redirect_uri` host — the host itself or a subdomain of it.
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

/// The vetted connectors and their curated branding. The domains mirror the
/// vendor set in `DEFAULT_ALLOWED_REDIRECTS`: a product gets branding exactly when
/// it can obtain a vetted redirect. v1 covers self-authenticating WEB connectors
/// only; native/loopback apps stay anonymous (their only identity signal is a
/// spoofable `client_name`). Logos are placeholders — see [`PLACEHOLDER_LOGO_SVG`].
pub(crate) const CONNECTORS: &[Connector] = &[
    Connector { slug: "chatgpt", name: "ChatGPT", domains: &["chatgpt.com"], logo: PLACEHOLDER_LOGO_SVG },
    Connector { slug: "claude", name: "Claude", domains: &["claude.ai"], logo: PLACEHOLDER_LOGO_SVG },
    Connector { slug: "cursor", name: "Cursor", domains: &["cursor.com"], logo: PLACEHOLDER_LOGO_SVG },
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

/// Whether `host` is `domain` or a subdomain of it, matched at a segment boundary
/// so a look-alike apex (`evilchatgpt.com`) does NOT match `chatgpt.com`.
fn host_matches(host: &str, domain: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|prefix| prefix.ends_with('.'))
}

/// The vetted connector a request's already-validated `redirect_uri` identifies,
/// if any. Reads only the host (the redirect is validated by the caller). `None`
/// for a loopback or unlisted host → status-quo anonymous consent.
pub(crate) fn connector_for_redirect(redirect_uri: &str) -> Option<&'static Connector> {
    let host = url::Url::parse(redirect_uri).ok()?.host_str()?.to_ascii_lowercase();
    CONNECTORS.iter().find(|c| c.domains.iter().any(|d| host_matches(&host, d)))
}

/// The connector for a curated slug, or `None` for any slug outside the set (so a
/// `/branding/{slug}` path segment can never probe arbitrary keys).
pub(crate) fn connector_by_slug(slug: &str) -> Option<&'static Connector> {
    CONNECTORS.iter().find(|c| c.slug == slug)
}

/// `GET {issuer}/branding/{slug}` — the tiny metadata document II reads to brand
/// the consent screen: the curated name, the absolute logo URL, and `verified`.
/// `no-store` (II fetches it cross-origin under `permissive_cors`; an
/// intermediary must not serve it stale). `404` outside the curated set.
pub(crate) async fn branding_metadata(
    State(store): State<AuthStore>,
    Path(slug): Path<String>,
) -> Response {
    let Some(connector) = connector_by_slug(&slug) else {
        return branding_not_found();
    };
    let logo = format!("{}/branding/{}/logo", store.issuer(), connector.slug);
    let mut resp =
        Json(json!({ "name": connector.name, "logo": logo, "verified": true })).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `GET {issuer}/branding/{slug}/logo` — the bundled connector logo (SVG bytes),
/// with `nosniff` and a cache header. `404` outside the curated set. II MUST
/// render it via a fixed-size `<img src>`, never inline the SVG into the consent
/// DOM: an `<img>`-loaded SVG cannot execute script, an inlined one can.
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

/// A slug outside the curated set: 404, so the path can't be used to probe.
fn branding_not_found() -> Response {
    (StatusCode::NOT_FOUND, "not a branded connector").into_response()
}

#[cfg(test)]
mod tests {
    use super::{connector_by_slug, connector_for_redirect, CONNECTORS};

    #[test]
    fn resolves_vetted_redirect_vendors_to_their_slug() {
        // Each vetted vendor's own callback resolves to its curated slug.
        let cases = [
            ("https://chatgpt.com/connector/oauth/abc", "chatgpt"),
            ("https://claude.ai/api/mcp/auth_callback", "claude"),
            ("https://cursor.com/agents/mcp/oauth/callback", "cursor"),
            ("https://grok.com/mcp/callback", "grok"),
            ("https://perplexity.ai/rest/connections/oauth_callback", "perplexity"),
            ("https://antigravity.google/oauth-callback", "antigravity"),
        ];
        for (redirect, slug) in cases {
            assert_eq!(
                connector_for_redirect(redirect).map(|c| c.slug),
                Some(slug),
                "redirect {redirect}"
            );
        }
        // A subdomain of a vetted vendor still resolves (Perplexity uses www/etc.).
        assert_eq!(
            connector_for_redirect("https://www.perplexity.ai/rest/connections/oauth_callback")
                .map(|c| c.slug),
            Some("perplexity")
        );
        assert_eq!(
            connector_for_redirect("https://www.cursor.com/agents/mcp/oauth/callback")
                .map(|c| c.slug),
            Some("cursor")
        );
    }

    #[test]
    fn unvetted_and_lookalike_and_loopback_get_no_branding() {
        // Loopback (native app) → no branding, by design.
        assert!(connector_for_redirect("http://127.0.0.1:5173/cb").is_none());
        assert!(connector_for_redirect("http://[::1]:8080/cb").is_none());
        // An unlisted vendor → none.
        assert!(connector_for_redirect("https://attacker.example/cb").is_none());
        // A look-alike apex must NOT match at a non-segment boundary.
        assert!(connector_for_redirect("https://evilchatgpt.com/cb").is_none());
        assert!(connector_for_redirect("https://claude.ai.attacker.example/cb").is_none());
        // Not a URL at all → none, never a panic.
        assert!(connector_for_redirect("not a url").is_none());
    }

    #[test]
    fn slug_lookup_is_closed_to_the_curated_set() {
        assert!(connector_by_slug("claude").is_some());
        assert!(connector_by_slug("unknown").is_none());
        assert!(connector_by_slug("../secrets").is_none());
        assert!(connector_by_slug("").is_none());
        // Every connector has a non-empty slug and name.
        for c in CONNECTORS {
            assert!(!c.slug.is_empty() && !c.name.is_empty());
        }
    }
}
