//! Best-effort discovery of the canisters behind a web domain served from the
//! Internet Computer, folding together the patterns we've seen across apps:
//!
//!   1. **App-declared metadata** (most authoritative — the app says so):
//!      the `ic:canister-id` `<meta>` on `/ai-connect.html` (the App Connect
//!      bridge page, spec §4.7/§6.1 — the app's MAIN backend), and the
//!      `/.well-known/ic-app.json` manifest enumerating ALL the app's
//!      canisters with roles (our proposed convention for the spec's deferred
//!      §6.3 "multi-canister applications" — see README).
//!   2. `x-ic-canister-id` response header — the frontend/asset canister. This
//!      is the one universal signal (the HTTP gateway sets it).
//!   3. a runtime config asset (`/env.json`) carrying `*canister_id*` keys —
//!      e.g. Caffeine apps expose `backend_canister_id` here.
//!   4. canister-id literals in the JS bundle, preferring labelled
//!      `*_CANISTER_ID` constants — e.g. dfx/Vite apps like OISY bake
//!      `IC_BACKEND_CANISTER_ID`, `IC_SIGNER_CANISTER_ID`, etc.
//!
//! There is NO authoritative reverse lookup for "this site's backend" — (1)
//! is declared by the app itself and (2) is certain for the frontend; (3) and
//! (4) are mined from client code, so each result carries its provenance and
//! the caller decides (and should confirm with `get_canister_candid`).

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use candid::Principal;
use regex::Regex;
// rmcp re-exports schemars 1.x; the `#[tool]` output-schema machinery requires
// THAT version's `JsonSchema`, so derive the MCP output types against it.
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

#[derive(Serialize, Clone, Debug)]
pub struct Found {
    pub canister_id: String,
    /// A human label if one was attached (App Connect role, env.json key,
    /// bundle constant name, or "frontend"); None for a bare bundle literal.
    pub label: Option<String>,
    /// Where it was found: "ai-connect.html", "ic-app.json", "header",
    /// "env.json", "bundle:<LABEL>", "bundle".
    pub sources: Vec<String>,
    /// IC dashboard label (e.g. "ICP Ledger"), filled in when the id is a known
    /// canister; None otherwise. Set during dashboard enrichment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// IC dashboard classification (e.g. "ledger"), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// One canister discovered behind a web domain — the `discover_app_canisters` MCP
/// output shape (a serialization mirror of [`Found`]).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DiscoveredCanister {
    /// The canister's principal id.
    pub canister_id: String,
    /// A human label if one was attached (App Connect role, env.json key,
    /// bundle constant, or "frontend"); null for a bare bundle literal.
    pub label: Option<String>,
    /// IC dashboard label (e.g. "ICP Ledger"), when the id is a known canister.
    pub name: Option<String>,
    /// IC dashboard classification (e.g. "ledger"), when known.
    pub kind: Option<String>,
    /// Where it was found: "ai-connect.html" (the App Connect page's declared
    /// main canister), "ic-app.json" (the app's own canister manifest),
    /// "header", "env.json", "bundle:<LABEL>", or "bundle". The first two are
    /// declared by the app itself and are the most authoritative.
    pub sources: Vec<String>,
    /// Whether this canister exposes the OQL query surface — filled in for the
    /// app's OWN data canisters by a single Candid fetch during open_app /
    /// discover_app_canisters (#3). null when not probed (e.g. the frontend or a
    /// shared system canister) or the interface couldn't be read. When true, this
    /// is a caller-gated data backend: read it with the OQL tools, passing the app's
    /// derivation_origin to read as the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oql: Option<bool>,
    /// Whether this canister declares an API-doc method (`getApiDoc`/`get_api_doc`),
    /// from the same probe as `oql`. null when not probed / unreadable. When true,
    /// get_canister_api_doc returns a prose behavior guide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_doc_available: Option<bool>,
}

impl From<&Found> for DiscoveredCanister {
    fn from(f: &Found) -> Self {
        Self {
            canister_id: f.canister_id.clone(),
            label: f.label.clone(),
            name: f.name.clone(),
            kind: f.kind.clone(),
            sources: f.sources.clone(),
            // Capability flags are filled in post-discovery by enrich_capabilities.
            oql: None,
            api_doc_available: None,
        }
    }
}

/// Whether a discovered canister is one of the APP's OWN data canisters — an
/// app-declared or app-mined backend — as opposed to the gateway frontend / asset
/// canister or a shared system canister (a ledger, II, NNS…). Scopes the
/// per-canister capability probe and the caller-gated data-access handle (#3) so
/// they never attach to II/NNS/ledger/frontend, per the security guardrail.
pub fn is_app_data_candidate(c: &DiscoveredCanister) -> bool {
    // Declared or mined as the app's own backend (not merely the gateway header).
    let app_owned = c.sources.iter().any(|s| {
        s == "ai-connect.html" || s == "ic-app.json" || s == "env.json" || s.starts_with("bundle")
    });
    // The frontend / asset canister: an explicit "frontend" label, or found ONLY
    // via the gateway `x-ic-canister-id` header.
    let is_frontend =
        c.label.as_deref() == Some("frontend") || c.sources == ["header"];
    // A dashboard-classified shared system canister (ledger, governance, …).
    let is_system = c.kind.as_deref().is_some_and(|k| {
        let k = k.to_ascii_lowercase();
        ["ledger", "governance", "index", "archive", "root", "sns", "nns", "cycles", "cmc"]
            .iter()
            .any(|s| k.contains(s))
    });
    app_owned && !is_frontend && !is_system
}

/// Arguments for `discover_app_canisters`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DiscoverCanistersArgs {
    /// A web domain or URL served from the IC, e.g. "oisy.com".
    pub domain: String,
}

/// Structured output of `discover_app_canisters`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DiscoverOutput {
    /// The domain that was probed.
    pub domain: String,
    /// Canisters found behind the domain (empty if none).
    pub canisters: Vec<DiscoveredCanister>,
    /// How many additional findings were dropped by the output caps (see
    /// [`bound_findings`]). The list is authority-ordered and the cut takes the
    /// tail, so the dropped entries are always the least authoritative present:
    /// in practice unlabelled JS-bundle literals, though with a very large
    /// declared manifest the global cap can trim labelled entries too.
    /// 0 = nothing cut.
    pub omitted: usize,
}

/// The bounded result of [`discover`]: the canisters kept (authority-ordered)
/// plus how many findings the output caps dropped.
#[derive(Debug)]
pub struct Discovery {
    pub canisters: Vec<Found>,
    pub omitted: usize,
}

impl From<(String, Discovery)> for DiscoverOutput {
    /// `(domain, discovery)` → the structured `discover_app_canisters` reply.
    fn from((domain, d): (String, Discovery)) -> Self {
        Self {
            domain,
            canisters: d.canisters.iter().map(DiscoveredCanister::from).collect(),
            omitted: d.omitted,
        }
    }
}

/// Canister textual principals: four 5-char base32 groups + the `cai` suffix.
fn canister_re() -> Regex {
    Regex::new(r"[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-cai").unwrap()
}

/// Extract `(canister_id, key)` pairs from an `/env.json` body: any object key
/// whose name mentions "canister" with a string value.
fn canisters_from_env_json(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) {
        for (k, v) in map {
            if k.to_lowercase().contains("canister") {
                if let Some(s) = v.as_str() {
                    out.push((s.to_string(), k));
                }
            }
        }
    }
    out
}

/// Pull `content` out of the first `<meta name="…">` tag with the given name,
/// reading the RAW served markup — like an App Connect connector, we fetch the
/// page and parse it, never executing its JavaScript (spec §6.1). Tolerates
/// attribute order and single or double quotes.
fn parse_meta(html: &str, name: &str) -> Option<String> {
    let bytes = html.as_bytes();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        // Find the next `<meta` — tag names are ASCII-case-insensitive in HTML,
        // so `<META`/`<Meta` count too.
        if bytes[i] != b'<' || !bytes[i + 1..i + 5].eq_ignore_ascii_case(b"meta") {
            i += 1;
            continue;
        }
        let after = i + 5;
        // Tag-name boundary: `<metadata …` (or any longer name) is not <meta>.
        if !matches!(bytes.get(after), Some(b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>')) {
            i = after;
            continue;
        }
        let rest = &html[after..];
        let Some(end) = rest.find('>') else {
            // No '>' anywhere in the remainder — no complete tag can follow.
            break;
        };
        let tag = &rest[..end];
        if attr(tag, "name").as_deref() == Some(name) {
            if let Some(content) = attr(tag, "content") {
                return Some(content);
            }
        }
        i = after + end;
    }
    None
}

/// A `key="value"` (or `key='value'`) attribute inside a tag body. Scans the
/// tag left-to-right as a sequence of attributes, consuming each quoted value
/// whole — so a key can never be matched inside another attribute's VALUE
/// (e.g. `data="… name='x' …"`), `data-name` can never match `name` (names
/// compare whole, ASCII-case-insensitively per HTML), and whitespace is
/// tolerated around the `=`. Only quoted values are returned.
fn attr(tag: &str, key: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace between attributes.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Read one attribute name (stop at whitespace, '=', or a quote).
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'"'
            && bytes[i] != b'\''
        {
            i += 1;
        }
        let name = &tag[name_start..i];
        // Optional `= value`, with whitespace tolerated around the '='.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                // Quoted value: consume it whole (to the matching quote).
                let quote = bytes[i];
                let vstart = i + 1;
                let mut j = vstart;
                while j < bytes.len() && bytes[j] != quote {
                    j += 1;
                }
                if j >= bytes.len() {
                    return None; // unterminated quote — malformed tag, bail
                }
                if name.eq_ignore_ascii_case(key) {
                    return Some(tag[vstart..j].to_string());
                }
                i = j + 1;
            } else {
                // Unquoted value: consume the token; never returned.
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
            }
        }
        // Guarantee progress on stray bytes (e.g. a bare quote at name position).
        if i == name_start {
            i += 1;
        }
    }
    None
}

/// Cap on how many manifest entries we honour — an app-declared list is small;
/// this just bounds a hostile manifest.
const MAX_MANIFEST_CANISTERS: usize = 100;

/// The `/.well-known/ic-app.json` manifest — our proposed convention for App
/// Connect's deferred §6.3 (multi-canister applications): the app itself
/// enumerates ALL its canisters and their roles, so an agent doesn't have to
/// mine them out of the frontend bundle. Unknown fields are ignored
/// (forward-compatible); entries whose `id` isn't a valid principal are
/// dropped downstream by `add`.
///
/// ```json
/// { "derivation_origin": "https://<frontend-canister>.icp0.io",
///   "canisters": [
///     { "id": "aaaaa-…-cai", "role": "backend", "description": "orders API" },
///     { "id": "bbbbb-…-cai", "role": "ledger" } ] }
/// ```
///
/// The optional top-level `derivation_origin` is the app's own declaration of
/// the Internet Identity derivation origin its frontends pin (via
/// `derivationOrigin` + `/.well-known/ii-alternative-origins`). It is the ONLY
/// authoritative way to learn a custom derivation origin: there is no reverse
/// lookup from an app URL to it (the app's own alternative-origins file lists
/// the inverse relation, and the frontend's `derivationOrigin` config is
/// typically minified out of reach). When absent, a consumer must fall back to
/// the application origin and say so.
#[derive(Deserialize)]
struct AppManifest {
    #[serde(default)]
    canisters: Vec<AppManifestEntry>,
    #[serde(default)]
    derivation_origin: Option<String>,
}

#[derive(Deserialize)]
struct AppManifestEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// Extract `(canister_id, label)` pairs from an `/.well-known/ic-app.json`
/// body; the label is "role — description", whichever parts are present.
fn canisters_from_app_manifest(text: &str) -> Vec<(String, Option<String>)> {
    let Ok(m) = serde_json::from_str::<AppManifest>(text) else {
        return Vec::new();
    };
    m.canisters
        .into_iter()
        .filter(|e| !e.id.trim().is_empty())
        .take(MAX_MANIFEST_CANISTERS)
        .map(|e| {
            let role = e.role.as_deref().map(clean_label).filter(|s| !s.is_empty());
            let desc = e.description.as_deref().map(clean_label).filter(|s| !s.is_empty());
            let label = match (role, desc) {
                (Some(r), Some(d)) => Some(format!("{r} — {d}")),
                (Some(r), None) => Some(r),
                (None, Some(d)) => Some(d),
                (None, None) => None,
            };
            (e.id.trim().to_string(), label)
        })
        .collect()
}

/// Reduce a raw origin string to a canonical bare `https://host[:port]` origin,
/// accepting https with a real (tuple) host and no user-info. A scheme-less value
/// is treated as a bare host and gets `https://` prepended (so a good-faith
/// bare-host declaration resolves rather than being dropped) — this matches
/// `canonicalize_derivation_origin`, which the interactive `derivation_origin`
/// param uses. `None` for anything else — blank, an explicit non-https scheme
/// (incl. `http://`, which `target_origin` would silently upgrade downstream,
/// masking a wrong origin), user-info, host-less, or unparseable — so callers fail
/// closed with no hidden scheme rewrite.
fn normalize_origin(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Reject an explicit non-https scheme up front (a scheme-less bare host is fine —
    // https is prepended below). Without this, `http://x` would be silently upgraded.
    if let Some((scheme, _)) = raw.split_once("://") {
        if !scheme.eq_ignore_ascii_case("https") {
            return None;
        }
    }
    let candidate = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    let url = url::Url::parse(&candidate).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    // Reject user-info: `url.origin()` silently drops it, so `https://user@host` and
    // `https://host` would collapse to the same origin — fail closed instead of
    // masking the difference (consistent with the derivation-origin validation).
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let origin = url.origin();
    if !origin.is_tuple() {
        return None;
    }
    Some(origin.ascii_serialization())
}

/// The app's declared Internet Identity derivation origin, from the manifest's
/// optional top-level `derivation_origin`, reduced to a bare `https://host[:port]`
/// origin (a scheme-less bare host is accepted and gets `https://`). `None` if
/// absent, blank, an explicit non-https scheme, user-info, or not a parseable URL.
fn declared_derivation_origin(manifest_text: &str) -> Option<String> {
    let m = serde_json::from_str::<AppManifest>(manifest_text).ok()?;
    normalize_origin(m.derivation_origin?.as_str())
}

/// Which origins Internet Identity permits to derive from this origin, from its
/// `/.well-known/ii-alternative-origins` (`{ "alternativeOrigins": [...] }`).
/// Purely informational — this is the INVERSE of "what derivation origin does
/// this app use", so it must NOT be used to infer the derivation origin.
#[derive(Deserialize)]
struct AltOrigins {
    #[serde(default, rename = "alternativeOrigins")]
    alternative_origins: Vec<String>,
}

fn parse_alternative_origins(text: &str) -> Vec<String> {
    serde_json::from_str::<AltOrigins>(text)
        .map(|a| {
            // Fail-closed: normalize each entry to a bare origin (as the doc
            // promises) and drop anything that isn't a valid https origin,
            // rather than surfacing arbitrary sanitized strings.
            a.alternative_origins
                .iter()
                .filter_map(|s| normalize_origin(s))
                .take(MAX_MANIFEST_CANISTERS)
                .collect()
        })
        .unwrap_or_default()
}

/// Where a resolved derivation origin came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivationSource {
    /// The app declared it in `/.well-known/ic-app.json` (`derivation_origin`).
    Declared,
    /// Not declared by the app, but the app is in the built-in registry of
    /// well-known custom-derivation-origin apps ([`KNOWN_DERIVATION_ORIGINS`]).
    Known,
    /// No declaration found and not a known app — defaulted to the application
    /// origin (an ASSUMPTION, correct only for apps without a custom origin).
    AppUrlDefault,
}

impl DerivationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DerivationSource::Declared => "declared",
            DerivationSource::Known => "known",
            DerivationSource::AppUrlDefault => "app_url_default",
        }
    }
}

/// Built-in derivation origins for well-known apps that pin a CUSTOM Internet
/// Identity derivation origin (so the visible URL is NOT what II derives against)
/// but don't yet declare it in `/.well-known/ic-app.json`. Verified from each app's
/// frontend `derivationOrigin` and the derivation origin's own
/// `/.well-known/ii-alternative-origins`. This is a stopgap so an agent gets the
/// right principal from the app URL alone; an app's own manifest declaration ALWAYS
/// takes precedence (a table entry is superseded the moment the app ships a
/// declaration). Keyed by application host (lowercased, no port).
///
/// NOTE (MULTI/DEX): its frontend pins the gateway-domain canister origin, and
/// `identities::target_origin` remaps `*.icp0.io`/`*.icp.net` → `*.ic0.app` before
/// deriving. Whether Internet Identity derives the SAME principal for those gateway
/// variants (vs the literal pinned string) has not been confirmed against a live
/// authenticated derivation; if II keys on the literal origin, this entry (and the
/// remap) would need revisiting. NNS/Oisy/ICPSwap use plain domains and are exact.
///
/// Each app's ENTIRE set of frontends — the derivation origin plus every origin in
/// that origin's `/.well-known/ii-alternative-origins` — is listed, all mapping to
/// the SAME derivation origin, so `resolve_app` yields the same result for any of an
/// app's origins (not just its primary host). `known_apps_are_closed_over_their_alt_origins`
/// verifies this against the live lists (and flags drift when an app adds one).
const KNOWN_DERIVATION_ORIGINS: &[(&str, &str)] = &[
    // NNS dapp: served at nns.internetcomputer.org (canister mc7vh-…) but pins the
    // classic https://nns.ic0.app (canister qoctq-…) as its derivation origin. The
    // rest are nns.ic0.app's ii-alternative-origins.
    ("nns.ic0.app", "https://nns.ic0.app"),
    ("nns.internetcomputer.org", "https://nns.ic0.app"),
    ("beta.nns.internetcomputer.org", "https://nns.ic0.app"),
    ("beta.nns.ic0.app", "https://nns.ic0.app"),
    ("sns.internetcomputer.org", "https://nns.ic0.app"),
    // Oisy: oisy.com is its own derivation-origin hub; the rest are its
    // ii-alternative-origins (beta + canister + signer subdomains).
    ("oisy.com", "https://oisy.com"),
    ("beta.oisy.com", "https://oisy.com"),
    ("v7iq7-yiaaa-aaaan-qmrtq-cai.icp0.io", "https://oisy.com"),
    ("cha4i-riaaa-aaaan-qeccq-cai.icp0.io", "https://oisy.com"),
    ("signer.oisy.com", "https://oisy.com"),
    ("legacy-signer.oisy.com", "https://oisy.com"),
    ("beta.signer.oisy.com", "https://oisy.com"),
    ("beta.legacy-signer.oisy.com", "https://oisy.com"),
    // MULTI/DEX: frontend pins its frontend-canister origin (see NOTE above); the
    // gateway variants (.icp.net / .icp0.io) and multidex.ai all derive against it.
    ("multidex.ai", "https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io"),
    ("hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io", "https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io"),
    ("hcv4s-uaaaa-aaabq-qaaba-cai.icp.net", "https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io"),
    // ICPSwap: app.icpswap.com uses NO custom derivation origin (default = app
    // origin) — listed so resolution reports it as verified rather than assumed. It
    // serves no ii-alternative-origins, so there are no further origins to map.
    ("app.icpswap.com", "https://app.icpswap.com"),
];

/// The built-in derivation origin for a well-known app host, if any (see
/// [`KNOWN_DERIVATION_ORIGINS`]). `host` must be the lowercased host (no port).
fn known_derivation_origin(host: &str) -> Option<&'static str> {
    KNOWN_DERIVATION_ORIGINS
        .iter()
        .find(|(h, _)| *h == host)
        .map(|(_, origin)| *origin)
}

/// A well-known IC app, for NAME → app resolution by the `icp_find_app_by_name`
/// tool. There is no on-chain directory mapping an app name to its front-end URL,
/// so this covers only a small curated set; anything else is directed to a web
/// lookup. The derivation origin is NOT stored here — it's derived from the single
/// source of truth [`KNOWN_DERIVATION_ORIGINS`] via the `app_url`'s host, so the two
/// can't drift. (Every `app_url` host is a registry key — asserted by test.)
struct KnownApp {
    /// Display name.
    name: &'static str,
    /// Aliases (lowercase, no separators) matched by [`find_known_app`] against the
    /// concatenation of any contiguous run of query tokens — an alias equals a whole
    /// token (e.g. "oisy" in "the oisy wallet") or adjacent tokens joined (e.g.
    /// "multi dex" / "MULTI/DEX" → "multidex").
    aliases: &'static [&'static str],
    /// The app's canonical front-end URL (feed to `discover_app_canisters` /
    /// `resolve_app`). Its host keys the derivation origin in [`KNOWN_DERIVATION_ORIGINS`].
    app_url: &'static str,
}

// Name resolution writes nothing: it turns a name a user said into an app URL
// and derivation origin, so `open_app` can read interfaces, discover
// canisters, and derive the user's per-app principal. An entry here is
// therefore not itself a route to a transaction — a later update call is a
// separate request, and goes through [`crate::compliance`] like any other,
// under exactly the scope that module documents (the standardized
// value-moving methods everywhere, every update method on the canisters it
// lists, and its own note on what a static list cannot cover, such as an
// exchange's dynamically created pool canisters). So the criterion for an
// entry is only whether the name is one users say and the mapping is one this
// server can state correctly — the NNS included, per review: resolving its
// name yields a URL and a derivation origin for reads, and every update call
// to its canisters is refused by that guard regardless of how the URL was
// reached.
const KNOWN_APPS: &[KnownApp] = &[
    KnownApp { name: "NNS", aliases: &["nns", "nnsdapp"], app_url: "https://nns.internetcomputer.org" },
    KnownApp { name: "Oisy", aliases: &["oisy", "oisywallet"], app_url: "https://oisy.com" },
    KnownApp { name: "MULTI/DEX", aliases: &["multidex"], app_url: "https://multidex.ai" },
    KnownApp { name: "ICPSwap", aliases: &["icpswap"], app_url: "https://app.icpswap.com" },
];

/// The derivation origin for a well-known app, from the single source of truth
/// [`KNOWN_DERIVATION_ORIGINS`] (keyed by the `app_url`'s host). Falls back to the
/// app URL itself only if the host somehow isn't registered (a test rules that out
/// for every [`KNOWN_APPS`] entry).
fn known_app_derivation_origin(app: &KnownApp) -> &'static str {
    url::Url::parse(app.app_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .and_then(|h| known_derivation_origin(&h))
        .unwrap_or(app.app_url)
}

/// Find a well-known app by name. The query is split into lowercase alphanumeric
/// TOKENS (on any non-alphanumeric boundary); an alias matches if it equals the
/// concatenation of any contiguous run of tokens — a single token (e.g. "oisy" in
/// "the oisy wallet") or adjacent tokens joined (e.g. "multi dex" / "MULTI/DEX" /
/// "use the multi dex app" → "multidex"). Matching on whole-token boundaries — not
/// substrings — avoids false positives like "noisy" resolving to "oisy" while still
/// tolerating punctuation/spacing/casing variants.
fn find_known_app(query: &str) -> Option<&'static KnownApp> {
    // Reject an implausibly long query up front — O(1), before any allocation — so a
    // pathological input can't be copied into `tokens`/`acc` at all. A real app name
    // (even inside a short phrase) is well under this; anything larger isn't one.
    const MAX_QUERY_BYTES: usize = 256;
    if query.len() > MAX_QUERY_BYTES {
        return None;
    }
    // Cap the token count so a pathologically long query can't drive quadratic work;
    // an app name won't be buried past a handful of tokens.
    const MAX_TOKENS: usize = 64;
    let tokens: Vec<String> = query
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .take(MAX_TOKENS)
        .map(str::to_ascii_lowercase)
        .collect();
    if tokens.is_empty() {
        return None;
    }
    // Match an alias against the concatenation of any CONTIGUOUS token window, so a
    // multi-word name matches anywhere in a phrase ("use the multi dex app" → the
    // window "multi"+"dex" = "multidex"). Windows are built from whole tokens, so
    // boundaries are preserved and a substring inside one token never matches (e.g.
    // "oisy" in "noisy"). Bounded: a window is abandoned once it grows past the
    // longest alias (it — and every longer window — can't match), and it's checked
    // in place rather than materializing every window.
    let max_alias = KNOWN_APPS
        .iter()
        .flat_map(|app| app.aliases.iter())
        .map(|a| a.len())
        .max()
        .unwrap_or(0);
    for start in 0..tokens.len() {
        let mut acc = String::new();
        for t in &tokens[start..] {
            acc.push_str(t);
            if acc.len() > max_alias {
                break;
            }
            if let Some(app) = KNOWN_APPS.iter().find(|app| app.aliases.contains(&acc.as_str())) {
                return Some(app);
            }
        }
    }
    None
}

/// The Internet Identity derivation context an app URL resolves to. See
/// [`resolve_app_identity`].
pub struct AppIdentity {
    /// The normalized application origin (`scheme://host[:port]`) of `app_url`.
    pub application_origin: String,
    /// The derivation origin to feed Internet Identity: the app-declared one when
    /// present, else a built-in known-app origin, else the application origin.
    pub derivation_origin: String,
    /// Whether `derivation_origin` was declared, from the known-app registry, or
    /// defaulted.
    pub derivation_origin_source: DerivationSource,
    /// The derivation origin's `ii-alternative-origins` list — the frontends
    /// allowed to derive against it (informational; the INVERSE relation).
    pub alternative_origins: Vec<String>,
    /// Whether the application origin showed evidence of being served from the
    /// Internet Computer: the HTTP gateway's `x-ic-canister-id` response header
    /// carrying a value that parses as a canister principal (presence alone is not
    /// trusted — any site can echo a header name). Probed only when the derivation
    /// origin had to be ASSUMED ([`DerivationSource::AppUrlDefault`]) — that
    /// assumption is only plausible for a real IC app, and `Some(false)` is the
    /// signature of a domain GUESSED from an app name (a lookalike/squatted site).
    /// `Some(false)` is concluded only from a successful exchange with the origin —
    /// an unreachable origin is an `Err` from [`resolve_app_identity`], never a
    /// misclassification. `None` when the probe wasn't needed (a declared or known
    /// derivation origin).
    pub application_is_ic: Option<bool>,
}

/// Fetch and parse an origin's `/.well-known/ii-alternative-origins`, using an
/// SSRF-pinned client for THAT origin's own host (the origin is resolved and
/// address-pinned independently, since it may be a different host than the app
/// URL). Empty on any failure (unreachable, non-success, unparseable, or SSRF
/// refusal) — this list is informational, so it fails soft.
async fn fetch_alternative_origins(origin: &str) -> Vec<String> {
    let (url, pinned) = match resolve_public_url(origin).await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let client = match site_client(&host, &pinned) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let origin = url.origin().ascii_serialization();
    match client.get(format!("{origin}/.well-known/ii-alternative-origins")).send().await {
        Ok(resp) if resp.status().is_success() => {
            parse_alternative_origins(&read_capped(resp, MAX_META_BYTES).await)
        }
        _ => Vec::new(),
    }
}

/// Whether a header map carries the IC HTTP gateway's `x-ic-canister-id` with a
/// value that PARSES AS A CANISTER PRINCIPAL. Presence of the header name is not
/// enough evidence of IC hosting: any server can echo an arbitrary header, so a
/// lookalike/attacker-controlled origin could set an empty or junk `x-ic-canister-id`
/// to fake it. Requiring the value to be a real principal (the gateway always sets a
/// canister id) makes the guessed-domain guard rely on a signal an unrelated site
/// can't produce by accident. (This is a heuristic, not a security boundary — a
/// determined attacker can still serve a valid principal; the explicit
/// `derivation_origin` escape hatch and the fundamentally forgeable nature of
/// response headers mean this only has to defeat accidental and lazy false positives.)
fn header_is_ic_principal(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("x-ic-canister-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map_or(false, |v| Principal::from_text(v).is_ok())
}

/// Whether `resp` is evidence that `expected_origin` itself is IC-served: it carries a
/// valid `x-ic-canister-id` (see [`header_is_ic_principal`]) AND the response came from
/// `expected_origin`, not a redirect target. The origin check matters because the
/// shared SSRF redirect policy permits hops to global IP literals AND same-host
/// different-PORT redirects, so without it a non-IC origin could redirect to a
/// *different* origin that echoes the header and borrow its IC-ness — the gate must
/// attribute evidence to the exact origin (scheme + host + port) it probed. Both sides
/// are canonical `Url::origin().ascii_serialization()` forms, so the compare is exact
/// (host case- and default-port-normalized) rather than a host-only match.
fn ic_evidence_from(resp: &reqwest::Response, expected_origin: &str) -> bool {
    header_is_ic_principal(resp.headers())
        && resp.url().origin().ascii_serialization() == expected_origin
}

/// Resolve an app URL to its Internet Identity derivation context, WITHOUT
/// guessing: the derivation origin is the app's declared one
/// (`/.well-known/ic-app.json` → `derivation_origin`) if present, else a built-in
/// known-app registry entry ([`KNOWN_DERIVATION_ORIGINS`]) if the app is one, else
/// the application origin (a clearly-flagged default). Uses the same SSRF-pinned
/// client and capped reads as `discover`; the app URL is user-controlled.
///
/// Whether an app at `application_origin` is authorized to derive Internet
/// Identity principals against `declared` — the server-side form of the check
/// Internet Identity and the browser enforce via `/.well-known/ii-alternative-origins`
/// (dfinity/internet-identity `validateDerivationOrigin`). A cross-origin claim is
/// honored ONLY when the DECLARED origin itself lists the application origin in
/// `declared_alt_origins` (its own `ii-alternative-origins`); a self-declaration
/// (`declared == application_origin`) needs no cross-origin trust.
///
/// Trusting the `derivation_origin` a site declares about itself — without this
/// gate — let ANY site claim another app's identity and make the user's agent act
/// as their principal there (ICPBB-430). The direction of trust matters: the
/// authority is the origin being impersonated (which publishes who may derive
/// against it), never the requesting site's self-declaration.
fn derivation_origin_authorized(
    application_origin: &str,
    declared: &str,
    declared_alt_origins: &[String],
) -> bool {
    declared == application_origin || declared_alt_origins.iter().any(|o| o == application_origin)
}

/// The `(derivation_origin, source)` a manifest resolves to, given the parsed
/// declared origin (`None` = nothing declared) and — for a cross-origin claim —
/// the declared origin's own alt-origins. Pure; the caller performs the fetches.
///
/// No declaration → the application origin as [`DerivationSource::AppUrlDefault`].
/// An authorized declaration (self, or listed by the declared origin) → the
/// declared origin as [`DerivationSource::Declared`]. A cross-origin declaration the
/// declared origin does NOT authorize is an `Err`, not a silent application-origin
/// fall-back: falling back there would derive the WRONG principal for an app that
/// deliberately pins a custom derivation origin, and would mask a spoof,
/// misconfiguration, or an unreachable `ii-alternative-origins` (ICPBB-430).
fn decide_declared_origin(
    application_origin: &str,
    declared: Option<&str>,
    declared_alt_origins: &[String],
) -> Result<(String, DerivationSource), String> {
    let Some(declared) = declared else {
        return Ok((application_origin.to_string(), DerivationSource::AppUrlDefault));
    };
    if derivation_origin_authorized(application_origin, declared, declared_alt_origins) {
        return Ok((declared.to_string(), DerivationSource::Declared));
    }
    Err(format!(
        "the app at {application_origin} declares derivation origin {declared}, but {declared} \
         does not authorize it — {application_origin} is not listed in {declared}'s \
         /.well-known/ii-alternative-origins (or that list could not be fetched). Refusing to \
         derive an identity here rather than use a wrong one."
    ))
}

/// What the app's `/.well-known/ic-app.json` resolved to: its declared (and
/// authorized) derivation origin or the application-origin default, whether the
/// manifest response carried IC-hosting evidence (`x-ic-canister-id`), and — when
/// an accepted CROSS-origin declaration fetched them — that origin's alt-origins
/// (reused for the display list so it isn't fetched twice).
struct DeclaredResolution {
    derivation_origin: String,
    source: DerivationSource,
    ic_evidence: bool,
    alt_origins: Option<Vec<String>>,
}

impl DeclaredResolution {
    /// The application-origin default (no usable declaration), carrying whatever
    /// IC evidence the manifest response showed.
    fn app_default(application_origin: &str, ic_evidence: bool) -> Self {
        Self {
            derivation_origin: application_origin.to_string(),
            source: DerivationSource::AppUrlDefault,
            ic_evidence,
            alt_origins: None,
        }
    }
}

/// Resolve the app's declared derivation origin from `/.well-known/ic-app.json`,
/// authorizing a cross-origin claim against the declared origin's own
/// `ii-alternative-origins` (the browser/II rule; the decision is
/// [`decide_declared_origin`]). Flat, with early guards. A missing/unsuccessful/
/// undeclared manifest legitimately yields the application-origin default (the app
/// derives against its own origin).
///
/// A cross-origin claim that CANNOT be authorized is an `Err`, not a silent
/// fall-back: falling back to the application origin there would derive the WRONG
/// principal for an app that deliberately pins a custom derivation origin (and
/// would mask a spoof, a misconfiguration, or an unreachable `ii-alternative-origins`).
/// Surfacing it lets the caller refuse rather than act as an unintended identity
/// (ICPBB-430). The manifest response doubles as IC-hosting evidence, captured for
/// the caller's later gate.
async fn resolve_declared_origin(
    client: &reqwest::Client,
    application_origin: &str,
) -> Result<DeclaredResolution, String> {
    let Ok(resp) = client
        .get(format!("{application_origin}/.well-known/ic-app.json"))
        .send()
        .await
    else {
        return Ok(DeclaredResolution::app_default(application_origin, false));
    };
    let ic_evidence = ic_evidence_from(&resp, application_origin);
    if !resp.status().is_success() {
        return Ok(DeclaredResolution::app_default(application_origin, ic_evidence));
    }
    let text = read_capped(resp, MAX_META_BYTES).await;
    let declared = declared_derivation_origin(&text);

    // The declared origin's ii-alternative-origins is the authorization list, and
    // only a CROSS-origin claim needs it — no declaration and a self-declaration
    // authorize without a fetch. Fetched once here, reused for the display list.
    let cross_origin = declared.as_deref().is_some_and(|d| d != application_origin);
    let alts = if cross_origin {
        fetch_alternative_origins(declared.as_deref().unwrap_or_default()).await
    } else {
        Vec::new()
    };

    let (derivation_origin, source) =
        match decide_declared_origin(application_origin, declared.as_deref(), &alts) {
            Ok(decision) => decision,
            Err(e) => {
                // Cross-origin claim we can't authorize (spoof, misconfig, or an
                // unreachable list): refuse rather than derive a wrong identity.
                tracing::warn!(
                    application_origin = %application_origin,
                    declared = declared.as_deref().unwrap_or_default(),
                    "refusing a cross-origin derivation_origin declaration that could not be authorized"
                );
                return Err(e);
            }
        };

    Ok(DeclaredResolution {
        derivation_origin,
        source,
        ic_evidence,
        // Reuse the fetched list for display only when a cross-origin claim was
        // accepted (self / no-declaration fetch nothing here).
        alt_origins: cross_origin.then_some(alts),
    })
}

/// `want_alt_origins` controls whether the resolved derivation origin's
/// `ii-alternative-origins` list is surfaced in the returned [`AppIdentity`]: the
/// `resolve_app` tool passes `true`; identity-bearing tools that resolve an
/// `app_url` only to derive against it pass `false`. Note this list is ALSO the
/// authorization check for a cross-origin declared derivation origin (see
/// [`derivation_origin_authorized`]), so it is fetched regardless of this flag
/// whenever a declaration names a different origin — the flag only governs whether
/// it is additionally returned for display.
pub async fn resolve_app_identity(app_url: &str, want_alt_origins: bool) -> Result<AppIdentity, String> {
    let base = normalize(app_url);
    let (base_url, pinned) = resolve_public_url(&base).await?;
    // Lowercase the host: the known-app registry is keyed by lowercased host, and
    // hosts are case-insensitive anyway. (The url crate already lowercases https
    // hosts, but do it explicitly so the registry lookup can't silently miss.)
    let host = base_url.host_str().unwrap_or_default().to_ascii_lowercase();
    let client = site_client(&host, &pinned)?;
    let application_origin = base_url.origin().ascii_serialization();

    // Declared derivation origin from the app's manifest. The manifest response
    // also doubles as IC-ness evidence: the IC HTTP gateway stamps
    // `x-ic-canister-id` (a canister principal) on every response it serves
    // (including 404s), so capture it here — value-validated AND attributed to this
    // origin (not a redirect target), not just present — before any fallback decision.
    // Resolve (and, for a cross-origin claim, authorize) the app's declared
    // derivation origin from its manifest — see [`resolve_declared_origin`]. The
    // alt-origins of an accepted cross-origin declaration are reused for the
    // display list below so it isn't fetched twice.
    let resolved = resolve_declared_origin(&client, &application_origin).await?;
    let mut derivation_origin = resolved.derivation_origin;
    let mut derivation_origin_source = resolved.source;
    let mut ic_evidence = resolved.ic_evidence;
    let resolved_alt_origins = resolved.alt_origins;

    // If the app didn't declare one, fall back to the built-in registry of
    // well-known custom-derivation-origin apps (the app's own declaration always
    // wins, so this only fills the gap for apps that haven't shipped one yet).
    if derivation_origin_source == DerivationSource::AppUrlDefault {
        if let Some(known) = known_derivation_origin(&host) {
            derivation_origin = known.to_string();
            derivation_origin_source = DerivationSource::Known;
        }
    }

    // When the derivation origin had to be ASSUMED, decide whether that assumption
    // even makes sense: a real IC app's origin carries the gateway's
    // `x-ic-canister-id` header (a valid canister principal) on every response. If
    // the manifest response didn't already show it (e.g. a non-IC CDN 404s that
    // path without the header, or echoes a junk value),
    // confirm against the ORIGIN ROOT — not the caller's full URL, whose arbitrary
    // path could point at a huge resource — reading headers only (the body is
    // dropped unread, aborting the transfer). `Some(false)` is concluded ONLY from
    // a successful exchange with the origin; a fetch error (timeout/TLS/connect)
    // propagates as an error instead, so an unreachable-but-real IC app is
    // reported as unreachable rather than misclassified as a reachable non-IC
    // site. Callers refuse the `Some(false)` case rather than resolving a guessed
    // lookalike domain to a wrong identity.
    let application_is_ic = if derivation_origin_source == DerivationSource::AppUrlDefault {
        if !ic_evidence {
            let resp = client
                .get(format!("{application_origin}/"))
                .send()
                .await
                .map_err(|e| format!("could not reach {application_origin}: {e}"))?;
            ic_evidence = ic_evidence_from(&resp, &application_origin);
        }
        Some(ic_evidence)
    } else {
        None
    };

    // The alternative-origins list surfaced to the caller (resolve_app). It is
    // authoritative at the DERIVATION ORIGIN (which declares the frontends allowed
    // to derive against it), and is the same list the authorization check above
    // already consulted — so reuse it when a cross-origin declaration was accepted,
    // and otherwise fetch the resolved origin's list. The identity hot path
    // (`want_alt_origins == false`) never surfaces it.
    let alternative_origins = if want_alt_origins {
        match resolved_alt_origins {
            Some(alts) => alts,
            None => fetch_alternative_origins(&derivation_origin).await,
        }
    } else {
        Vec::new()
    };

    Ok(AppIdentity {
        application_origin,
        derivation_origin,
        derivation_origin_source,
        alternative_origins,
        application_is_ic,
    })
}

/// The well-known app whose NAME a (typically guessed) app URL's host resembles,
/// when the host is NOT one of that app's real registered hosts — e.g.
/// "multidex.com", "multidex.app", or "multi.dex" all resemble MULTI/DEX, whose
/// real URL is https://multidex.ai. Used to attach a "did you mean …" repair to
/// refusals and warnings, so an agent that fabricated a domain from an app name
/// converges on the real app in one step instead of guessing again. `None` when
/// the host IS a registered known-app host (nothing to repair) or resembles no
/// known app. Offline (registry lookup only).
pub fn similar_known_app(app_url: &str) -> Option<AppMatch> {
    let host = url::Url::parse(&normalize(app_url))
        .ok()?
        .host_str()?
        .to_ascii_lowercase();
    if known_derivation_origin(&host).is_some() {
        return None; // a real known-app host — not a lookalike
    }
    // Token-window alias matching (see find_known_app): "multidex.com" tokenizes
    // to ["multidex","com"] and "multi.dex" to ["multi","dex"] — both match the
    // "multidex" alias on whole-token boundaries, while "noisy.com" matches nothing.
    let app = find_known_app(&host)?;
    Some(AppMatch {
        name: app.name.to_string(),
        app_url: app.app_url.to_string(),
        derivation_origin: known_app_derivation_origin(app).to_string(),
    })
}

/// How a free-form `open_app` query (a NAME or a URL) was interpreted — the
/// one-tool entry point's disambiguation, kept here beside the registry it
/// consults so name-matching and URL-detection stay in one place.
pub enum AppQuery {
    /// The query matched the built-in known-app registry (by name, or by a bare
    /// host whose tokens contain a known alias — so a wrong-TLD guess like
    /// "multidex.com" repairs to the canonical app). Carries the canonical match.
    Known(AppMatch),
    /// The query is (or looks like) a URL/host to resolve AS GIVEN — an explicit
    /// `scheme://…`, or a dotted host that matched no known app. The caller is
    /// asserting a specific origin; the IC-evidence gate still applies downstream.
    Url(String),
    /// A bare word (no scheme, no dot) that matched no known app — there is no way
    /// to turn a NAME into a URL without guessing, so the caller must supply one.
    UnknownName,
}

/// Classify an `open_app` query as a known app, a URL to resolve, or an unknown
/// bare name. Precedence: an explicit `scheme://` is honoured verbatim as a URL
/// (the caller is asserting that exact origin — validated, never registry-
/// overridden); otherwise the registry is tried first (so "multidex", "multi dex",
/// and the wrong-TLD "multidex.com" all repair to the canonical known app); a
/// remaining dotted host is a URL to resolve as given, and a remaining bare word
/// is an unknown NAME. Offline (registry + string inspection only).
pub fn classify_app_query(query: &str) -> AppQuery {
    let q = query.trim();
    // An explicit scheme is an assertion of a specific origin — honour it as a URL
    // rather than letting the registry rewrite it, so a caller who deliberately
    // types `https://multidex.com` gets the gate's refuse+repair on THAT origin.
    if q.contains("://") {
        return AppQuery::Url(q.to_string());
    }
    // Bare name or host: the registry wins first, repairing wrong-TLD guesses to
    // the canonical app (find_known_app tokenizes, so "multidex.com" → MULTI/DEX).
    if let Some(app) = find_known_app(q) {
        return AppQuery::Known(AppMatch {
            name: app.name.to_string(),
            app_url: app.app_url.to_string(),
            derivation_origin: known_app_derivation_origin(app).to_string(),
        });
    }
    // No registry match: a dotted host is a URL to resolve; a bare word is a NAME
    // we refuse to fabricate a domain for.
    if q.contains('.') {
        AppQuery::Url(q.to_string())
    } else {
        AppQuery::UnknownName
    }
}

/// Tidy an app-supplied label for display: control characters (ANSI escapes,
/// CR/LF tricks) become spaces, then trim and cap — manifest roles and
/// descriptions are untrusted server text (CWE-150).
fn clean_label(s: &str) -> String {
    const MAX_LABEL_CHARS: usize = 120;
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

fn normalize(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('/');
    // Case-insensitive scheme check: an already-schemed URL (any case — url parsing
    // lowercases the scheme downstream) is left as-is; a bare host gets https. Matching
    // only lowercase here would turn a validated `HTTPS://host` into `https://HTTPS://host`.
    let lower = d.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        d.to_string()
    } else {
        format!("https://{d}")
    }
}

// ---------------------------------------------------------------------------
// SSRF guard (CWE-918). `discover`'s `domain` is fully user-controlled, so every
// outbound request it drives must be constrained to PUBLIC https destinations:
//   - the scheme is pinned to https (no http:// to metadata IPs / plaintext ports);
//   - the host is resolved and refused if ANY address is loopback / private /
//     link-local / CGNAT / documentation / otherwise-reserved;
//   - the validated addresses are PINNED into the site client, so a later
//     re-resolution can't rebind the connection to an internal address (DNS
//     rebinding); and
//   - each redirect hop is re-validated the same way (a 3xx can't bounce us to an
//     internal host).
// ---------------------------------------------------------------------------

/// Whether `ip` is a publicly-routable ("global") address. Hand-rolled because
/// `IpAddr::is_global` is still unstable; conservative — anything not clearly
/// public is treated as non-global and refused.
fn ip_is_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_global(v4),
        IpAddr::V6(v6) => ipv6_is_global(v6),
    }
}

fn ipv4_is_global(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()                       // 0.0.0.0
        || o[0] == 0                            // 0.0.0.0/8 "this network"
        || ip.is_loopback()                     // 127.0.0.0/8
        || ip.is_private()                      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                   // 169.254.0.0/16
        || ip.is_broadcast()                    // 255.255.255.255
        || ip.is_documentation()                // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_multicast()                    // 224.0.0.0/4
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT (shared)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240)                         // 240.0.0.0/4 reserved
}

fn ipv6_is_global(ip: &Ipv6Addr) -> bool {
    // An IPv4-mapped (`::ffff:0:0/96`) OR IPv4-compatible (`::/96`, e.g.
    // `::127.0.0.1`) address is only as global as the v4 it embeds. `to_ipv4`
    // (unlike `to_ipv4_mapped`) covers BOTH forms — plus `::`/`::1` — so a
    // private/loopback v4 can't slip through via IPv6 embedding.
    if let Some(v4) = ip.to_ipv4() {
        return ipv4_is_global(&v4);
    }
    let seg = ip.segments();
    !(ip.is_unspecified()                    // ::
        || ip.is_loopback()                  // ::1
        || ip.is_multicast()                 // ff00::/8
        || (seg[0] & 0xfe00) == 0xfc00       // fc00::/7 unique-local
        || (seg[0] & 0xffc0) == 0xfe80       // fe80::/10 link-local unicast
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 documentation
        // Transition mechanisms embed an IPv4 address deeper in the v6 space than
        // `to_ipv4` decodes, so a NAT64/6to4/Teredo host would otherwise translate
        // one of these to loopback/link-local/RFC1918/metadata (ICPBB-377). imcp2
        // never needs to reach them, so refuse the prefixes outright.
        || (seg[0] == 0x0064 && seg[1] == 0xff9b)  // 64:ff9b::/32 NAT64 (RFC 6052 WKP + RFC 8215 local-use)
        || seg[0] == 0x2002                        // 2002::/16 6to4
        || (seg[0] == 0x2001 && seg[1] == 0x0000)) // 2001::/32 Teredo
}

/// Validate a user-supplied discovery URL against SSRF and return the parsed URL
/// plus the socket addresses to PIN the client to. https only; every resolved
/// address must be global. Async DNS (no blocking of the executor).
async fn resolve_public_url(raw: &str) -> Result<(url::Url, Vec<SocketAddr>), String> {
    let url = url::Url::parse(raw).map_err(|e| format!("invalid discovery URL {raw}: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!(
            "refusing to fetch {raw}: only https:// discovery targets are allowed (SSRF guard)"
        ));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = match url.host() {
        Some(url::Host::Ipv4(v4)) => vec![SocketAddr::new(IpAddr::V4(v4), port)],
        Some(url::Host::Ipv6(v6)) => vec![SocketAddr::new(IpAddr::V6(v6), port)],
        Some(url::Host::Domain(host)) => tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("could not resolve {host}: {e}"))?
            .collect(),
        None => return Err(format!("refusing to fetch {raw}: no host")),
    };
    if addrs.is_empty() {
        return Err(format!("refusing to fetch {raw}: host did not resolve"));
    }
    if let Some(bad) = addrs.iter().find(|a| !ip_is_global(&a.ip())) {
        return Err(format!(
            "refusing to fetch {raw}: it resolves to a non-public address ({}) — discovery is \
             restricted to public hosts (SSRF guard)",
            bad.ip()
        ));
    }
    Ok((url, addrs))
}

/// Whether a redirect hop is safe to follow — decided WITHOUT a DNS lookup (the
/// reqwest redirect callback is synchronous, so resolving a fresh domain there
/// would both block a worker thread and reopen a rebind TOCTOU on the redirect
/// target). A hop is allowed only when it is https AND either (a) an IP literal
/// that is globally routable, or (b) a SAME-HOST redirect — the host was already
/// validated up front and, for the site client, pinned, so no new unvalidated
/// destination is introduced. A redirect to a *different* domain is refused;
/// discovery targets normally respond directly, so this trades that rare case for
/// safety (a cross-host redirect would need its own validate+pin).
fn redirect_hop_ok(next: &url::Url, prev_host: Option<&str>) -> bool {
    if next.scheme() != "https" {
        return false;
    }
    match next.host() {
        Some(url::Host::Ipv4(v4)) => ip_is_global(&IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => ip_is_global(&IpAddr::V6(v6)),
        Some(url::Host::Domain(h)) => prev_host == Some(h),
        None => false,
    }
}

/// Redirect policy shared by every discovery/dashboard client: follow only safe
/// public https hops (bounded), and stop — rather than follow — an unsafe hop, so
/// no request is ever issued to an internal host.
fn ssrf_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let prev_host = attempt
            .previous()
            .last()
            .and_then(|u| u.host_str())
            .map(str::to_string);
        if attempt.previous().len() >= 10 {
            attempt.error("too many redirects")
        } else if redirect_hop_ok(attempt.url(), prev_host.as_deref()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// A client for fetching a user-supplied site: the SSRF redirect guard plus the
/// host PINNED to the pre-validated public addresses, so no re-resolution can
/// rebind the connection to an internal address between validation and connect.
/// (Pinning only overrides this host; requests to other hosts — e.g. the
/// dashboard — resolve normally, still under the redirect guard.)
fn site_client(host: &str, addrs: &[SocketAddr]) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent("ic-mcp-discover/0.1")
        .timeout(std::time::Duration::from_secs(15))
        .redirect(ssrf_redirect_policy())
        .resolve_to_addrs(host, addrs)
        .build()
        .map_err(|e| format!("http client: {e}"))
}

// Response-size caps (CWE-770): a fully user-controlled discovery target could
// stream an unbounded (or gzip-bomb-inflated) body and exhaust memory. reqwest's
// `.text()`/`.bytes()` buffer the whole body with no ceiling, so we read chunk by
// chunk and stop once the cap is hit. The connection is dropped when the response
// is, so a truncated read cancels the transfer rather than draining it.
// The per-file cap must comfortably exceed real-world app bundles: OISY's main
// chunks are ~3 MiB, with labelled canister ids sitting past the 2 MiB mark —
// a 2 MiB cap silently truncated them away. Memory stays bounded by the
// AGGREGATE cap regardless (each read is sized to the remaining room), so the
// per-file value only decides how deep into one file we can see.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024; // one document (HTML, one JS file)
const MAX_ENV_JSON_BYTES: usize = 256 * 1024; // /env.json is tiny in practice
const MAX_META_BYTES: usize = 256 * 1024; // ai-connect.html head / ic-app.json manifest
const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024; // aggregate bundle text mined for ids

/// Read up to `max` bytes of a response body, then stop — dropping the response
/// (and so the connection) rather than draining the remainder. Best-effort: a
/// mid-stream error just returns what we have (discovery is opportunistic).
async fn read_capped(mut resp: reqwest::Response, max: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if buf.len() >= max {
            break;
        }
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = (max - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // hit the cap mid-chunk; stop (drops the connection)
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Accumulator for discovered canister ids, with a hard ceiling on the number of
/// DISTINCT entries retained. A hostile discovery target can pack the permitted
/// 8 MiB scan buffer with hundreds of thousands of unique, CRC-valid principals;
/// without a ceiling, every one is validated, allocated as a map key + [`Found`],
/// and later ordered — hundreds of MiB of peak memory for a reply that
/// [`bound_findings`] trims to at most 50 (CWE-770). Entries past the cap are
/// counted (folded into [`Discovery::omitted`]), not stored.
#[derive(Default)]
struct Findings {
    map: BTreeMap<String, Found>,
    /// Count of distinct ids seen once the [`Self::MAX`] cap was reached and
    /// dropped without allocating a `Found`; folded into [`Discovery::omitted`].
    /// Exact for the common shape (each overflow id matched once); a hostile
    /// target that repeats an overflow id — or names it in both scan passes —
    /// makes this an UPPER BOUND. That is acceptable: it only inflates `omitted`
    /// for a target already spamming ids, and counting overflow *distinctly*
    /// would need the unbounded memory this cap exists to avoid. Saturating, so
    /// it can never wrap.
    dropped: usize,
}

impl Findings {
    /// Ceiling on distinct retained ids — an order of magnitude above the largest
    /// real bundle seen in the wild (a token wallet embedding every ledger/index
    /// it supports is still only a few hundred), so legitimate discovery is never
    /// trimmed here; the authority-ranked cut in [`bound_findings`] does the
    /// user-facing trimming. The authoritative sources (metadata/header/env) are
    /// recorded before any bundle scan, so they are never the entries dropped.
    const MAX: usize = 1024;

    /// Ceiling on provenance sources kept per finding. A hostile bundle can name
    /// the SAME retained principal under many distinct `bundle:{LABEL}` constants;
    /// without this, each distinct source is stored (unbounded per-entry growth,
    /// and the linear `contains` below turns quadratic) and later rendered into
    /// the reply. A handful of provenances is all the output needs.
    const MAX_SOURCES: usize = 8;

    /// Record `id` under `source` (validated as a real principal first), merging
    /// labels/sources for an id already seen (first label wins). A NEW id is
    /// stored only while under [`Self::MAX`]; beyond that it is counted, not
    /// allocated — so peak memory and the later ordering stay bounded regardless
    /// of how many matches the scanned bytes contain.
    fn add(&mut self, id: &str, label: Option<String>, source: String) {
        // Drop false positives by validating as a real principal.
        if Principal::from_text(id).is_err() {
            return;
        }
        if let Some(entry) = self.map.get_mut(id) {
            // Already known: merge in place, no new key allocation. First label
            // wins; provenance is bounded so one id can't grow without limit.
            if entry.label.is_none() {
                entry.label = label;
            }
            if entry.sources.len() < Self::MAX_SOURCES && !entry.sources.contains(&source) {
                entry.sources.push(source);
            }
        } else if self.map.len() < Self::MAX {
            self.map.insert(
                id.to_string(),
                Found { canister_id: id.to_string(), label, sources: vec![source], name: None, kind: None },
            );
        } else {
            // At capacity and this id is new — count it (saturating), don't allocate.
            self.dropped = self.dropped.saturating_add(1);
        }
    }
}

pub async fn discover(domain: &str) -> Result<Discovery, String> {
    let base = normalize(domain);
    // SSRF guard (CWE-918): validate + resolve the fully user-controlled target
    // to public addresses BEFORE any request, and pin them into the client so the
    // connection can't rebind to an internal host. The pin only affects this site
    // host, so the dashboard-enrichment calls below (different hosts) still work.
    let (base_url, pinned) = resolve_public_url(&base).await?;
    let host = base_url.host_str().unwrap_or_default().to_string();
    let client = site_client(&host, &pinned)?;
    // Well-known paths and root-relative script paths live at the ORIGIN, not
    // under whatever path the caller's URL carried (e.g. https://x.com/app must
    // probe https://x.com/ai-connect.html) — only the initial page fetch below
    // uses the URL as given.
    let origin = base_url.origin().ascii_serialization();

    let mut found = Findings::default();

    // 1. App-declared metadata — the app saying, in bytes it serves itself,
    // which canisters it comprises. Most authoritative of all sources, and
    // probed FIRST so its labels win `add`'s first-label-wins rule (a
    // single-canister app's id would otherwise keep the header's generic
    // "frontend" label instead of the declared one).
    //   a. The App Connect bridge page's ic:canister-id meta: the app's MAIN
    //      backend (spec §4.7/§6.1). Read from raw markup, no JS execution.
    //      An SPA catch-all serving index.html here fails closed: no such
    //      meta, no finding.
    //   b. /.well-known/ic-app.json: the app's own canister manifest with
    //      roles (proposed convention for the spec's deferred §6.3). A
    //      catch-all HTML response fails JSON parsing → no findings.
    if let Ok(resp) = client.get(format!("{origin}/ai-connect.html")).send().await {
        if resp.status().is_success() {
            let page = read_capped(resp, MAX_META_BYTES).await;
            if let Some(id) = parse_meta(&page, "ic:canister-id") {
                found.add(
                    id.trim(),
                    Some("main backend (App Connect)".into()),
                    "ai-connect.html".into(),
                );
            }
        }
    }
    if let Ok(resp) = client.get(format!("{origin}/.well-known/ic-app.json")).send().await {
        if resp.status().is_success() {
            let text = read_capped(resp, MAX_META_BYTES).await;
            for (id, label) in canisters_from_app_manifest(&text) {
                found.add(&id, label, "ic-app.json".into());
            }
        }
    }

    // 2. Frontend via the gateway header (and keep the HTML for bundle mining).
    // This is also the reachability gate: the two probes above are best-effort,
    // but an unreachable base is a hard error.
    let resp = client
        .get(&base)
        .send()
        .await
        .map_err(|e| format!("could not reach {base}: {e}"))?;
    if let Some(id) = resp
        .headers()
        .get("x-ic-canister-id")
        .and_then(|v| v.to_str().ok())
    {
        found.add(id, Some("frontend".into()), "header".into());
    }
    let html = read_capped(resp, MAX_BODY_BYTES).await;

    // 3. Runtime config: /env.json with *canister_id* keys (e.g. Caffeine apps).
    if let Ok(resp) = client.get(format!("{origin}/env.json")).send().await {
        if resp.status().is_success() {
            let text = read_capped(resp, MAX_ENV_JSON_BYTES).await;
            for (id, label) in canisters_from_env_json(&text) {
                found.add(&id, Some(label), "env.json".into());
            }
        }
    }

    // 4. JS bundle: labelled constants first, then any bare canister literals.
    let mut blob = html.clone();
    let script_re = Regex::new(r#"["'](/[^"'<> ]+?\.js)["']"#).unwrap();
    // Only the first 20 (sorted) paths are fetched below, and no real page has
    // anywhere near this many <script> tags — so collect at most MAX_SCRIPT_PATHS
    // DISTINCT paths (CWE-770). Dedup WHILE collecting, not after: a hostile page
    // front-loaded with copies of one path must not fill the cap and crowd out
    // later real scripts, and a page packed with distinct `"/a.js"` must not grow
    // the Vec without bound. The `contains` is O(cap), so it stays cheap.
    const MAX_SCRIPT_PATHS: usize = 128;
    let mut scripts: Vec<String> = Vec::new();
    for c in script_re.captures_iter(&html) {
        let path = &c[1];
        if !scripts.iter().any(|s| s == path) {
            scripts.push(path.to_string());
            if scripts.len() >= MAX_SCRIPT_PATHS {
                break;
            }
        }
    }
    scripts.sort();
    for s in scripts.iter().take(20) {
        if blob.len() >= MAX_SCAN_BYTES {
            break; // aggregate cap: stop mining once we've buffered enough text
        }
        if let Ok(resp) = client.get(format!("{origin}{s}")).send().await {
            // Push the separator first, then size the read against the space that
            // remains — so the '\n' counts toward the cap and `blob` never exceeds
            // MAX_SCAN_BYTES (loop guard guarantees room for the separator).
            blob.push('\n');
            let room = MAX_SCAN_BYTES.saturating_sub(blob.len());
            let t = read_capped(resp, room.min(MAX_BODY_BYTES)).await;
            blob.push_str(&t);
        }
    }

    let label_re = Regex::new(
        r#"([A-Z][A-Z0-9_]*CANISTER_ID)["'\s:=]+([a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-cai)"#,
    )
    .unwrap();
    for c in label_re.captures_iter(&blob) {
        // Clamp the attacker-controlled constant name (clean_label caps length and
        // strips control chars) BEFORE it becomes both a label and a `bundle:{}`
        // source — the regex's `[A-Z0-9_]*` run is otherwise unbounded.
        let label = clean_label(&c[1]);
        found.add(&c[2], Some(label.clone()), format!("bundle:{label}"));
    }
    for m in canister_re().find_iter(&blob) {
        found.add(m.as_str(), None, "bundle".into());
    }

    // Order: app-declared metadata first (App Connect main, then the manifest
    // siblings), then header (frontend), env.json, labelled bundle, bare.
    // Authority tier of a finding (lower = more authoritative). Kept as a helper
    // so the sort can compare it without cloning `canister_id` into a key.
    let rank = |f: &Found| {
        if f.sources.iter().any(|s| s == "ai-connect.html") {
            0
        } else if f.sources.iter().any(|s| s == "ic-app.json") {
            1
        } else if f.sources.iter().any(|s| s == "header") {
            2
        } else if f.sources.iter().any(|s| s == "env.json") {
            3
        } else if f.sources.iter().any(|s| s.starts_with("bundle:")) {
            4
        } else {
            5
        }
    };
    let dropped = found.dropped;
    let mut out: Vec<Found> = found.map.into_values().collect();
    // Tiebreak by canister_id so the subset that survives the cap in
    // bound_findings follows an explicit order, rather than depending on the
    // source BTreeMap order that the stable sort would carry through.
    out.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.canister_id.cmp(&b.canister_id)));

    // Bound the result BEFORE enrichment, so every kept entry gets a dashboard
    // lookup and dropped ones cost nothing. `dropped` (ids the extraction cap
    // refused to allocate) folds into the reported `omitted`.
    let mut bounded = bound_findings(out, dropped);
    // Annotate each id with its IC dashboard identity (name/type) where known,
    // so a bare principal becomes an identified service. Best-effort.
    enrich_with_dashboard(&client, &mut bounded.canisters).await;

    Ok(bounded)
}

/// Bound a sorted findings list so one discovery can't overwhelm an MCP
/// client's context window: a token-wallet's JS bundle can embed the canister
/// ids of every ledger/index it supports, and each lands here as a bare
/// `bundle` literal (a multi-hundred-entry, ~100+ KB tool reply in the wild).
/// Bare literals are the least meaningful tier (unlabelled, not app-declared),
/// so they're capped hardest; a global cap backstops the labelled tiers too.
/// Assumes authority order (bare literals sort last), so the cut always drops
/// the least authoritative tail. The number dropped is REPORTED via
/// [`Discovery::omitted`], never silently.
fn bound_findings(mut out: Vec<Found>, extra_omitted: usize) -> Discovery {
    const MAX_BARE_BUNDLE: usize = 20;
    const MAX_CANISTERS: usize = 50;
    let total = out.len();
    let mut bare_seen = 0usize;
    out.retain(|f| {
        // A bare literal's ONLY source is "bundle"; an id that also appeared in
        // any labelled/declared source is never dropped by this tier cap.
        if f.sources.iter().all(|s| s == "bundle") {
            bare_seen += 1;
            bare_seen <= MAX_BARE_BUNDLE
        } else {
            true
        }
    });
    out.truncate(MAX_CANISTERS);
    // `extra_omitted` = distinct ids the extraction cap refused before they ever
    // reached this Vec; add it so the reported count covers every dropped id.
    Discovery { omitted: extra_omitted + (total - out.len()), canisters: out }
}

/// Annotate found canisters with their dashboard label/type, concurrently and
/// best-effort. Capped so a bundle full of bare literals can't fan out forever;
/// discovery still works (just unannotated) if the dashboard is unreachable.
async fn enrich_with_dashboard(client: &reqwest::Client, found: &mut [Found]) {
    const MAX_ENRICH: usize = 50;
    let mut set = JoinSet::new();
    for (i, f) in found.iter().enumerate().take(MAX_ENRICH) {
        let client = client.clone();
        let id = f.canister_id.clone();
        set.spawn(async move { (i, lookup_canister(&client, &id).await.ok()) });
    }
    while let Some(res) = set.join_next().await {
        if let Ok((i, Some(info))) = res {
            found[i].name = info.name;
            found[i].kind = info.canister_type;
        }
    }
}

// ---------------------------------------------------------------------------
// Dashboard-backed lookup & search.
//
// https://dashboard.internetcomputer.org is backed by public REST APIs that map
// a canister id to a curated identity, and that let us search the IC's named
// "services" (ICRC tokens + SNS projects) by name. There is NO public endpoint
// to search the full ~1.2M canister set by name, so name search runs over these
// two bounded registries — which is where the meaningful services live.
// ---------------------------------------------------------------------------

/// IC dashboard API (canister identity). Override with `IC_DASHBOARD_API`.
fn dashboard_api() -> String {
    api_base("IC_DASHBOARD_API", "https://ic-api.internetcomputer.org")
}

/// ICRC token registry API. Override with `IC_ICRC_API`.
fn icrc_api() -> String {
    api_base("IC_ICRC_API", "https://icrc-api.internetcomputer.org")
}

/// SNS catalog API. Override with `IC_SNS_API`.
fn sns_api() -> String {
    api_base("IC_SNS_API", "https://sns-api.internetcomputer.org")
}

fn api_base(var: &str, default: &str) -> String {
    resolve_base(std::env::var(var).ok(), default)
}

/// Use the configured base when it's non-blank, else the default — so a set but
/// empty/whitespace `IC_*_API` can't produce a scheme-less or "/api/..." URL.
/// Trailing slashes are trimmed so callers can append `/api/...` uniformly.
fn resolve_base(configured: Option<String>, default: &str) -> String {
    let trimmed = configured.as_deref().unwrap_or("").trim().trim_end_matches('/');
    if trimmed.is_empty() {
        default.trim_end_matches('/').to_string()
    } else {
        trimmed.to_string()
    }
}

/// Shared HTTP client for dashboard/registry calls (fixed public hosts) and the
/// `icp_lookup_canister_info_by_id` tool. Carries the SSRF redirect guard so a 3xx can never
/// bounce a request onto an internal host. Short-ish timeout since these back
/// interactive tools. (User-supplied *site* fetches use [`site_client`], which
/// additionally pins the resolved address.)
pub fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent("ic-mcp-discover/0.1")
        .timeout(std::time::Duration::from_secs(15))
        .redirect(ssrf_redirect_policy())
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// What a canister IS, per the IC dashboard's curated metadata.
#[derive(Serialize, Clone, Debug, Default)]
pub struct CanisterInfo {
    pub canister_id: String,
    /// Curated label, e.g. "ICP Ledger". `None` for unlabelled canisters.
    pub name: Option<String>,
    /// e.g. "ledger". `None` when the dashboard hasn't classified it.
    pub canister_type: Option<String>,
    pub controllers: Vec<String>,
    pub subnet_id: Option<String>,
    pub module_hash: Option<String>,
    pub language: Option<String>,
    /// Proposal id of the most recent recorded upgrade, if any.
    pub latest_upgrade_proposal: Option<u64>,
}

/// Arguments for `icp_lookup_canister_info_by_id`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupCanisterArgs {
    /// Canister principal to identify, e.g. "ryjl3-tyaaa-aaaaa-aaaba-cai".
    pub canister_id: String,
}

/// The `icp_lookup_canister_info_by_id` MCP output shape — the IC dashboard's identity for a
/// canister id (a serialization mirror of [`CanisterInfo`]).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CanisterIdentityOutput {
    /// The canister that was identified.
    pub canister_id: String,
    /// Curated label, e.g. "ICP Ledger"; null for unlabelled canisters.
    pub name: Option<String>,
    /// Classification, e.g. "ledger"; null when unclassified.
    pub canister_type: Option<String>,
    /// Controller principals.
    pub controllers: Vec<String>,
    /// Hosting subnet id, if known.
    pub subnet_id: Option<String>,
    /// Module hash (hex), if known.
    pub module_hash: Option<String>,
    /// Implementation language, if known.
    pub language: Option<String>,
    /// Proposal id of the most recent recorded upgrade, if any.
    pub latest_upgrade_proposal: Option<u64>,
}

impl From<CanisterInfo> for CanisterIdentityOutput {
    fn from(info: CanisterInfo) -> Self {
        Self {
            canister_id: info.canister_id,
            name: info.name,
            canister_type: info.canister_type,
            controllers: info.controllers,
            subnet_id: info.subnet_id,
            module_hash: info.module_hash,
            language: info.language,
            latest_upgrade_proposal: info.latest_upgrade_proposal,
        }
    }
}

#[derive(Deserialize)]
struct RawCanister {
    canister_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    canister_type: Option<String>,
    #[serde(default)]
    controllers: Vec<String>,
    #[serde(default)]
    subnet_id: Option<String>,
    #[serde(default)]
    module_hash: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    upgrades: Option<Vec<RawUpgrade>>,
}

#[derive(Deserialize)]
struct RawUpgrade {
    #[serde(default)]
    executed_timestamp_seconds: i64,
    #[serde(default)]
    proposal_id: Option<u64>,
}

/// The dashboard uses "" for "unknown"; treat blanks as absent.
fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.trim().is_empty())
}

impl From<RawCanister> for CanisterInfo {
    fn from(r: RawCanister) -> Self {
        let latest_upgrade_proposal = r
            .upgrades
            .unwrap_or_default()
            .into_iter()
            .max_by_key(|u| u.executed_timestamp_seconds)
            .and_then(|u| u.proposal_id);
        CanisterInfo {
            canister_id: r.canister_id,
            name: non_empty(r.name),
            canister_type: non_empty(r.canister_type),
            controllers: r.controllers,
            subnet_id: non_empty(r.subnet_id),
            module_hash: non_empty(r.module_hash),
            language: non_empty(r.language),
            latest_upgrade_proposal,
        }
    }
}

/// Identify a canister via the dashboard's `GET /api/v3/canisters/{id}`.
pub async fn lookup_canister(client: &reqwest::Client, id: &str) -> Result<CanisterInfo, String> {
    if Principal::from_text(id).is_err() {
        return Err(format!("invalid canister id: {id}"));
    }
    let url = format!("{}/api/v3/canisters/{id}", dashboard_api());
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("dashboard request failed: {e}"))?;
    // "No dashboard record" (404) is expected for many principals — return a
    // bare, unlabelled identity rather than an error so the tool still responds.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(CanisterInfo {
            canister_id: id.to_string(),
            ..Default::default()
        });
    }
    if !resp.status().is_success() {
        return Err(format!(
            "dashboard returned HTTP {} for {id}",
            resp.status().as_u16()
        ));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| format!("could not read dashboard response: {e}"))?;
    let raw: RawCanister = serde_json::from_str(&body)
        .map_err(|e| format!("could not parse dashboard response: {e}"))?;
    Ok(raw.into())
}

/// A named canister found by searching the IC's service registries.
#[derive(Serialize, Clone, Debug)]
pub struct Match {
    pub canister_id: String,
    pub name: String,
    /// "token" (ICRC ledger) or "sns" (SNS project root).
    pub kind: String,
    pub note: Option<String>,
}

/// One canister matched by `icp_find_canister_by_name` — the MCP output shape (a
/// serialization mirror of [`Match`]).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FoundCanister {
    /// The canister's principal id, e.g. "xevnm-gaaaa-aaaar-qafnq-cai".
    pub canister_id: String,
    /// Human-readable name or token symbol, e.g. "ckUSDC".
    pub name: String,
    /// What the id is: "token" (an ICRC ledger) or "sns" (an SNS project root).
    pub kind: String,
    /// An optional extra note about the match, when the registry provides one.
    pub note: Option<String>,
}

impl From<&Match> for FoundCanister {
    fn from(m: &Match) -> Self {
        Self {
            canister_id: m.canister_id.clone(),
            name: m.name.clone(),
            kind: m.kind.clone(),
            note: m.note.clone(),
        }
    }
}

/// Arguments for `icp_find_canister_by_name`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindCanisterArgs {
    /// A name, token symbol, or project to search for, e.g. "ckUSDC", "ICP",
    /// "OpenChat".
    pub query: String,
}

/// Structured output of `icp_find_canister_by_name`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FindCanisterOutput {
    /// The name, token symbol, or project that was searched for.
    pub query: String,
    /// Canisters from the IC's labelled service registries that matched
    /// `query` — empty when nothing matched.
    pub matches: Vec<FoundCanister>,
}

impl From<(String, Vec<Match>)> for FindCanisterOutput {
    /// `(query, matches)` → the structured `icp_find_canister_by_name` reply.
    fn from((query, matches): (String, Vec<Match>)) -> Self {
        Self {
            query,
            matches: matches.iter().map(FoundCanister::from).collect(),
        }
    }
}

/// Arguments for `icp_find_app_by_name`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindAppArgs {
    /// The app name to look up, as the user said it. For a site you already know
    /// (e.g. "opencloud.org"), use open_app / resolve_app directly.
    pub name: String,
}

/// One well-known app matched by `icp_find_app_by_name`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AppMatch {
    /// The app's display name.
    pub name: String,
    /// The app's canonical front-end URL — feed it to `discover_app_canisters` /
    /// `resolve_app`.
    pub app_url: String,
    /// The app's Internet Identity derivation origin (lets you skip `resolve_app`).
    pub derivation_origin: String,
}

/// Structured output of `icp_find_app_by_name`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FindAppOutput {
    /// The name that was looked up.
    pub query: String,
    /// Matching well-known apps (usually zero or one). Empty when the app isn't in
    /// the connector's built-in set.
    pub matches: Vec<AppMatch>,
    /// Next-step guidance: how to proceed on a match, or an instruction to web-search
    /// the app's URL when there's no match.
    pub note: String,
}

/// Arguments for `open_app`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OpenAppArgs {
    /// An app NAME as the user said it OR its URL (e.g.
    /// "https://opencloud.org"). A name — or a bare host — is matched against the
    /// built-in known-app registry first, so a wrong-TLD guess
    /// repairs to the canonical URL; an explicit `https://…` URL is resolved as
    /// given. NEVER pass a domain you fabricated from a name: an unknown bare name
    /// is refused with instructions to find the real URL, and a URL with no
    /// Internet-Computer evidence is refused — both instead of guessing.
    pub app: String,
}

/// Structured output of `open_app` — an app's whole context in one shot: its
/// Internet Identity derivation origin (as `resolve_app`) plus the canisters
/// behind it (as `discover_app_canisters`).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct OpenAppOutput {
    /// The app URL that was used — the canonical registry URL when the query
    /// matched a known app, else the URL you supplied.
    pub app_url: String,
    /// How `app_url` was obtained: "known_app_registry" (a name/bare host matched
    /// the built-in registry) or "as_provided" (the URL you supplied was used).
    pub app_url_source: String,
    /// The normalized application origin of `app_url`.
    pub application_origin: String,
    /// The Internet Identity derivation origin to use — pass this to
    /// get_app_principal / list_app_accounts / canister_query / canister_update_call.
    pub derivation_origin: String,
    /// How `derivation_origin` was determined: "declared", "known", or
    /// "app_url_default" (see resolve_app).
    pub derivation_origin_source: String,
    /// Origins the derivation origin's `ii-alternative-origins` permits to derive
    /// from it. Informational only — the INVERSE relation; never infer the
    /// derivation origin from it.
    pub alternative_origins: Vec<String>,
    /// Whether the origin showed Internet-Computer evidence (gateway
    /// `x-ic-canister-id`); null unless the derivation origin was assumed. See
    /// resolve_app's field of the same name.
    pub application_is_ic: Option<bool>,
    /// The canisters discovered behind the app, most authoritative first (same
    /// shape/provenance as discover_app_canisters). Empty when the app declares
    /// none OR when discovery failed — disambiguated by `discovery_error`.
    pub canisters: Vec<DiscoveredCanister>,
    /// How many additional findings the discovery output caps dropped (same
    /// meaning as discover_app_canisters' field); 0 = nothing cut.
    pub omitted: usize,
    /// If canister discovery FAILED (DNS/TLS/SSRF refusal/timeout) rather than
    /// merely finding nothing, the error string — so an empty `canisters` meaning
    /// "the app declares none" is distinguishable from "discovery didn't run".
    /// null when discovery succeeded (whether or not it found anything). The
    /// derivation context is valid regardless (origin resolution succeeded first).
    pub discovery_error: Option<String>,
    /// A human note — the derivation-origin caveat and any lookalike caution.
    pub note: Option<String>,
}

/// Resolve an app NAME against the built-in set of well-known apps
/// ([`KNOWN_APPS`]). Pure/offline — there is no on-chain directory mapping an app
/// name to its front-end URL, so an unknown name yields no match and a `note`
/// directing the agent to do a web search for the official URL.
pub fn find_app_by_name(query: &str) -> FindAppOutput {
    match find_known_app(query) {
        Some(app) => {
            let derivation_origin = known_app_derivation_origin(app);
            FindAppOutput {
                query: query.to_string(),
                matches: vec![AppMatch {
                    name: app.name.to_string(),
                    app_url: app.app_url.to_string(),
                    derivation_origin: derivation_origin.to_string(),
                }],
                note: format!(
                    "Well-known app. Use discover_app_canisters(\"{}\") to find its canisters; its \
                     derivation origin is already {} (no resolve_app needed).",
                    app.app_url, derivation_origin
                ),
            }
        }
        None => {
            // Build the known-app list from KNOWN_APPS (the source of truth) so this
            // message can't drift when the set changes.
            let known = KNOWN_APPS.iter().map(|a| a.name).collect::<Vec<_>>().join(", ");
            FindAppOutput {
                query: query.to_string(),
                matches: Vec::new(),
                note: format!(
                    "\"{query}\" is not in the connector's small built-in set of well-known apps \
                     ({known}). There is no on-chain directory mapping an app NAME to its URL, so \
                     do a WEB SEARCH for the app's official front-end URL (or ask the user for it), \
                     then call resolve_app / discover_app_canisters with that URL. Do NOT guess or \
                     fabricate a domain from the name — a lookalike domain (e.g. <name>.com/.app) is \
                     typically an unrelated or squatted site, and an identity derived there would be \
                     wrong."
                ),
            }
        }
    }
}

#[derive(Deserialize)]
struct LedgersResp {
    #[serde(default)]
    data: Vec<RawLedger>,
}

#[derive(Deserialize)]
struct RawLedger {
    ledger_canister_id: String,
    #[serde(default)]
    sns_root_canister_id: Option<String>,
    #[serde(default)]
    icrc1_metadata: LedgerMeta,
}

#[derive(Deserialize, Default)]
struct LedgerMeta {
    #[serde(default)]
    icrc1_name: Option<String>,
    #[serde(default)]
    icrc1_symbol: Option<String>,
}

#[derive(Deserialize)]
struct SnsesResp {
    #[serde(default)]
    data: Vec<RawSns>,
}

#[derive(Deserialize)]
struct RawSns {
    root_canister_id: String,
    #[serde(default)]
    name: Option<String>,
}

/// Search the IC's named services by name/symbol. Fetches the (bounded) ICRC
/// ledger registry and SNS catalog, then filters locally — there is no public
/// name-search over all canisters.
pub async fn search_by_name(query: &str) -> Result<Vec<Match>, String> {
    // Nothing to search for — skip the network round-trips entirely.
    if query.trim().is_empty() {
        return Ok(Vec::new());
    }
    let client = http_client()?;
    // Both registries are small (≈60 entries each); limit=100 captures them all
    // in one request. The API rejects very large limits (HTTP 422). Fetch the two
    // independent registries concurrently to keep this interactive tool snappy.
    let ledgers_url = format!("{}/api/v1/ledgers?limit=100", icrc_api());
    let snses_url = format!("{}/api/v1/snses?limit=100&offset=0", sns_api());
    let (ledgers, snses) = tokio::join!(
        fetch_text(&client, &ledgers_url),
        fetch_text(&client, &snses_url),
    );

    // Best-effort: tolerate one registry being down, but not both.
    if ledgers.is_err() && snses.is_err() {
        return Err(ledgers
            .err()
            .or(snses.err())
            .unwrap_or_else(|| "search failed".into()));
    }
    Ok(search_in(
        ledgers.as_deref().unwrap_or("{}"),
        snses.as_deref().unwrap_or("{}"),
        query,
    ))
}

async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("{url} returned HTTP {}", resp.status().as_u16()));
    }
    resp.text().await.map_err(|e| format!("reading {url}: {e}"))
}

/// Pure filter over the two registries (split out so it's unit-testable).
fn search_in(ledgers_json: &str, snses_json: &str, query: &str) -> Vec<Match> {
    let q = query.trim().to_lowercase();
    let mut out = Vec::new();
    if q.is_empty() {
        return out;
    }

    if let Ok(resp) = serde_json::from_str::<LedgersResp>(ledgers_json) {
        for l in resp.data {
            let symbol = l.icrc1_metadata.icrc1_symbol.unwrap_or_default();
            let name = l.icrc1_metadata.icrc1_name.unwrap_or_default();
            if symbol.to_lowercase().contains(&q) || name.to_lowercase().contains(&q) {
                let display = if symbol.is_empty() {
                    name.clone()
                } else if name.is_empty() || name == symbol {
                    symbol.clone()
                } else {
                    format!("{name} ({symbol})")
                };
                let note = match l.sns_root_canister_id {
                    Some(r) => format!("ICRC token ledger; SNS root {r}"),
                    None => "ICRC token ledger".into(),
                };
                out.push(Match {
                    canister_id: l.ledger_canister_id,
                    name: display,
                    kind: "token".into(),
                    note: Some(note),
                });
            }
        }
    }

    if let Ok(resp) = serde_json::from_str::<SnsesResp>(snses_json) {
        for s in resp.data {
            let name = s.name.unwrap_or_default();
            if name.to_lowercase().contains(&q) {
                out.push(Match {
                    canister_id: s.root_canister_id,
                    name,
                    kind: "sns".into(),
                    note: Some(
                        "SNS project root — icp_lookup_canister_info_by_id (or the SNS detail API) expands it \
                         to governance/ledger/swap/index"
                            .into(),
                    ),
                });
            }
        }
    }

    out.truncate(25);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // SSRF guard (CWE-918): global vs. non-global IP classification (offline).
    #[test]
    fn ip_globality_classification() {
        let g = |s: &str| ip_is_global(&s.parse::<IpAddr>().unwrap());
        // Publicly-routable addresses.
        assert!(g("8.8.8.8"));
        assert!(g("1.1.1.1"));
        assert!(g("2606:4700:4700::1111"));
        // Loopback / private / link-local / CGNAT / reserved / doc / bench, plus
        // IPv4 embedded in IPv6 as MAPPED (::ffff:…) and COMPATIBLE (::…) forms.
        for bad in [
            "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "255.255.255.255", "192.0.2.1", "198.18.0.1", "240.0.0.1",
            "::1", "::", "fc00::1", "fd12::1", "fe80::1", "2001:db8::1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4-mapped private/loopback
            "::127.0.0.1", "::192.168.1.1",        // IPv4-compatible private/loopback
            // Transition-mechanism prefixes: a NAT64/6to4/Teredo host translates
            // these to internal/metadata IPv4 (ICPBB-377), so they must not pass.
            "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "64:ff9b::a00:1", // NAT64 WKP → metadata/loopback/RFC1918
            "64:ff9b:1::a9fe:a9fe",                                   // NAT64 RFC 8215 local-use
            "2002:a9fe:a9fe::", "2002:7f00:1::",                      // 6to4 → metadata/loopback
            "2001:0:0:0:0:0:a9fe:a9fe",                               // Teredo
        ] {
            assert!(!g(bad), "{bad} must be classified non-global");
        }
        // A real public v6 that merely starts with 0x2001 (not db8/Teredo) stays global.
        assert!(g("2001:4860:4860::8888"));
    }

    // The exact vectors from the finding, plus https-to-internal, are refused
    // (all offline: scheme check and IP literals need no DNS).
    #[tokio::test]
    async fn resolve_public_url_rejects_ssrf_targets() {
        for bad in [
            "http://169.254.169.254/latest/meta-data/", // http metadata
            "http://127.0.0.1:6379/",                   // http plaintext port
            "https://127.0.0.1:6379/",                  // https loopback
            "https://10.0.0.1/",                        // private
            "https://169.254.169.254/",                 // link-local metadata
            "https://[::1]/",                           // loopback v6
            "ftp://example.com/",                        // non-https scheme
        ] {
            assert!(resolve_public_url(bad).await.is_err(), "{bad} must be refused");
        }
        // A public IP literal is accepted and pinned to itself.
        let (_, addrs) = resolve_public_url("https://8.8.8.8/").await.expect("public ip ok");
        assert_eq!(addrs, vec!["8.8.8.8:443".parse().unwrap()]);
    }

    // Redirect hops: same-host or global-IP-literal https only; no DNS involved.
    #[test]
    fn redirect_hop_policy() {
        let u = |s: &str| url::Url::parse(s).unwrap();
        // Same-host https redirect is allowed (host already validated / pinned).
        assert!(redirect_hop_ok(&u("https://oisy.com/app"), Some("oisy.com")));
        // A redirect to a DIFFERENT domain is refused (can't validate+pin here).
        assert!(!redirect_hop_ok(&u("https://evil.example/x"), Some("oisy.com")));
        // Global IP-literal hop allowed; internal IP-literal hops refused.
        assert!(redirect_hop_ok(&u("https://8.8.8.8/x"), Some("oisy.com")));
        assert!(!redirect_hop_ok(&u("https://127.0.0.1/x"), Some("oisy.com")));
        assert!(!redirect_hop_ok(&u("https://169.254.169.254/x"), Some("oisy.com")));
        assert!(!redirect_hop_ok(&u("https://[::1]/x"), Some("oisy.com")));
        // Non-https refused even on the same host.
        assert!(!redirect_hop_ok(&u("http://oisy.com/x"), Some("oisy.com")));
    }

    // The output caps drop unlabelled bundle literals past their tier cap (and
    // report the count), while every labelled/declared finding survives: the
    // wild case is a wallet bundle embedding hundreds of token-ledger ids,
    // which used to produce a ~140 KB tool reply.
    #[test]
    fn bound_findings_caps_bare_literals_and_reports_omitted() {
        let mk = |id: usize, label: Option<&str>, source: &str| Found {
            canister_id: format!("id-{id:03}"),
            label: label.map(String::from),
            sources: vec![source.to_string()],
            name: None,
            kind: None,
        };
        // Authority-ordered, as discover() produces: labelled tiers first, then
        // a long tail of bare bundle literals.
        let mut found = vec![
            mk(0, Some("main backend (App Connect)"), "ai-connect.html"),
            mk(1, Some("frontend"), "header"),
            mk(2, Some("IC_BACKEND_CANISTER_ID"), "bundle:IC_BACKEND_CANISTER_ID"),
        ];
        found.extend((3..40).map(|i| mk(i, None, "bundle")));

        let d = bound_findings(found, 0);
        // All 3 labelled kept; bare capped at 20; 37 - 20 = 17 omitted.
        assert_eq!(d.canisters.len(), 23, "3 labelled + 20 bare");
        assert_eq!(d.omitted, 17);
        assert!(d.canisters.iter().take(3).all(|f| f.label.is_some()), "labelled entries survive");
        // The kept bare literals are the FIRST 20 (authority order preserved).
        assert_eq!(d.canisters[3].canister_id, "id-003");
        assert_eq!(d.canisters[22].canister_id, "id-022");

        // The global cap backstops labelled tiers too, and still reports.
        let many_labelled: Vec<Found> = (0..60).map(|i| mk(i, Some("x"), "ic-app.json")).collect();
        let d = bound_findings(many_labelled, 0);
        assert_eq!(d.canisters.len(), 50);
        assert_eq!(d.omitted, 10);

        // Nothing to cut: nothing reported.
        let d = bound_findings(vec![mk(0, Some("frontend"), "header")], 0);
        assert_eq!((d.canisters.len(), d.omitted), (1, 0));
    }

    // A distinct, round-tripped principal for `i` — always accepted by from_text.
    fn valid_principal(i: usize) -> String {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        Principal::from_slice(&bytes).to_text()
    }

    // A hostile target can pack the scan buffer with hundreds of thousands of
    // distinct valid principals. `Findings` must cap the DISTINCT entries it
    // allocates (so peak memory / the sort stay bounded), count the overflow, and
    // still report every dropped id via `omitted` (CWE-770, ICPBB-380).
    #[test]
    fn findings_caps_distinct_ids_and_reports_every_omission() {
        let overflow = 500;
        let n = Findings::MAX + overflow;
        let mut found = Findings::default();
        for i in 0..n {
            found.add(&valid_principal(i), None, "bundle".into());
        }
        assert_eq!(found.map.len(), Findings::MAX, "distinct ids are capped at MAX");
        assert_eq!(found.dropped, overflow, "each once-seen overflow id is counted, not allocated");

        // The full pipeline still reports every omitted id: MAX entries reach
        // bound_findings, 20 bare survive, and the extraction drop is folded in.
        let dropped = found.dropped;
        let d = bound_findings(found.map.into_values().collect(), dropped);
        assert_eq!(d.canisters.len(), 20, "bare-bundle tier capped to 20");
        assert_eq!(d.omitted, n - 20, "every one of the {n} ids beyond the 20 kept is reported");
    }

    // Overflow ids that REPEAT (or are matched by both scan passes) must not grow
    // memory — the map stays capped — and `dropped` stays a bounded UPPER BOUND on
    // distinct overflow rather than an unbounded occurrence count that wraps.
    #[test]
    fn findings_overflow_is_bounded_under_repeats() {
        let mut found = Findings::default();
        for i in 0..Findings::MAX {
            found.add(&valid_principal(i), None, "bundle".into());
        }
        // One brand-new overflow id, hammered many times.
        let overflow = valid_principal(Findings::MAX);
        for _ in 0..10_000 {
            found.add(&overflow, None, "bundle".into());
        }
        assert_eq!(found.map.len(), Findings::MAX, "memory stays capped under repeats");
        // Occurrence-counted, so repeats inflate it (the documented upper-bound
        // contract) — but it is finite and never allocates the overflow id.
        assert_eq!(found.dropped, 10_000);
        assert!(!found.map.contains_key(&overflow), "the overflow id is never stored");
    }

    // A single retained id named under many distinct `bundle:{LABEL}` constants
    // must not grow its provenance list without bound (per-entry memory + the
    // linear `contains` would otherwise be quadratic, and every source is rendered).
    #[test]
    fn findings_caps_sources_per_id() {
        let id = valid_principal(0);
        let mut found = Findings::default();
        for i in 0..1000 {
            found.add(&id, None, format!("bundle:LABEL_{i}"));
        }
        assert_eq!(found.map.len(), 1, "still one distinct id");
        assert_eq!(found.map[&id].sources.len(), Findings::MAX_SOURCES, "provenance is capped");
    }

    // Live network test against a stable public IC app (OISY). Bundle mining
    // streams multi-MB chunks from a live CDN, and `read_capped` deliberately
    // treats a mid-stream error as end-of-body (discovery is opportunistic) —
    // so a transient reset can truncate a chunk before the labelled id. Retry
    // the whole discovery a few times before declaring failure, so the test
    // asserts the mining logic rather than one fetch's luck.
    #[tokio::test]
    async fn discovers_oisy_frontend_and_backend() {
        let mut ids: Vec<String> = Vec::new();
        for attempt in 1..=3 {
            let found = discover("oisy.com").await.expect("discover");
            ids = found.canisters.iter().map(|f| f.canister_id.clone()).collect();
            if ids.iter().any(|i| i == "cha4i-riaaa-aaaan-qeccq-cai")
                && ids.iter().any(|i| i == "doked-biaaa-aaaar-qag2a-cai")
            {
                return;
            }
            eprintln!("attempt {attempt}: incomplete discovery, retrying: {ids:?}");
        }
        // Frontend from the gateway header.
        assert!(
            ids.iter().any(|i| i == "cha4i-riaaa-aaaan-qeccq-cai"),
            "frontend not found: {ids:?}"
        );
        // Backend from the labelled bundle constant (IC_BACKEND_CANISTER_ID).
        assert!(
            ids.iter().any(|i| i == "doked-biaaa-aaaar-qag2a-cai"),
            "backend not found: {ids:?}"
        );
    }

    // Live network: "ckUSDC" resolves to the ckUSDC ledger via the dashboard's
    // token registry, and that id identifies as a "ledger".
    #[tokio::test]
    async fn search_finds_ckusdc_and_lookup_identifies_it() {
        let matches = search_by_name("ckUSDC").await.expect("search");
        assert!(
            matches.iter().any(|m| m.canister_id == "xevnm-gaaaa-aaaar-qafnq-cai"),
            "ckUSDC ledger not found: {matches:?}"
        );

        let client = http_client().expect("client");
        let info = lookup_canister(&client, "xevnm-gaaaa-aaaar-qafnq-cai")
            .await
            .expect("lookup");
        assert_eq!(info.canister_type.as_deref(), Some("ledger"));
        assert!(info.name.as_deref().unwrap_or_default().contains("ckUSDC"));
    }

    // A set-but-blank IC_*_API env var must not yield a scheme-less base URL.
    #[test]
    fn resolve_base_falls_back_on_blank_or_unset() {
        let default = "https://d.example";
        assert_eq!(resolve_base(None, default), default);
        assert_eq!(resolve_base(Some("".into()), default), default);
        assert_eq!(resolve_base(Some("   ".into()), default), default);
        assert_eq!(
            resolve_base(Some("https://x.example/".into()), default),
            "https://x.example"
        );
    }

    // A blank query short-circuits before any network call.
    #[tokio::test]
    async fn search_by_name_blank_is_empty_without_network() {
        assert!(search_by_name("   ").await.unwrap().is_empty());
    }

    // Name search filters the bounded token + SNS registries (offline fixtures).
    #[test]
    fn search_in_matches_token_symbol_and_sns_name() {
        let ledgers = r#"{"data":[
            {"ledger_canister_id":"xevnm-gaaaa-aaaar-qafnq-cai","sns_root_canister_id":null,
             "icrc1_metadata":{"icrc1_name":"ckUSDC","icrc1_symbol":"ckUSDC"}},
            {"ledger_canister_id":"ryjl3-tyaaa-aaaaa-aaaba-cai","sns_root_canister_id":null,
             "icrc1_metadata":{"icrc1_name":"Internet Computer","icrc1_symbol":"ICP"}}
        ],"total_ledgers":2}"#;
        let snses = r#"{"data":[
            {"root_canister_id":"3e3x2-xyaaa-aaaaq-aaala-cai","name":"OpenChat"}
        ],"total_snses":1}"#;

        // The headline flow: "ckUSDC" -> the ledger canister id.
        let usdc = search_in(ledgers, snses, "ckusdc");
        assert_eq!(usdc.len(), 1, "{usdc:?}");
        assert_eq!(usdc[0].canister_id, "xevnm-gaaaa-aaaar-qafnq-cai");
        assert_eq!(usdc[0].kind, "token");

        // SNS projects match by name and resolve to the root canister.
        let oc = search_in(ledgers, snses, "openchat");
        assert_eq!(oc.len(), 1, "{oc:?}");
        assert_eq!(oc[0].canister_id, "3e3x2-xyaaa-aaaaq-aaala-cai");
        assert_eq!(oc[0].kind, "sns");

        // Symbol substring still matches the ICP ledger.
        assert!(search_in(ledgers, snses, "icp")
            .iter()
            .any(|m| m.canister_id == "ryjl3-tyaaa-aaaaa-aaaba-cai"));

        // Blank query matches nothing.
        assert!(search_in(ledgers, snses, "   ").is_empty());
    }

    // Dashboard JSON normalisation: blanks -> None, newest upgrade by timestamp.
    #[test]
    fn raw_canister_normalises_and_picks_latest_upgrade() {
        let json = r#"{"canister_id":"ryjl3-tyaaa-aaaaa-aaaba-cai","name":"ICP Ledger",
          "canister_type":"ledger","controllers":["r7inp-6aaaa-aaaaa-aaabq-cai"],
          "subnet_id":"tdb26-jop6k","module_hash":"51f4be","language":"",
          "upgrades":[{"executed_timestamp_seconds":100,"proposal_id":3},
                      {"executed_timestamp_seconds":200,"proposal_id":42}]}"#;
        let raw: RawCanister = serde_json::from_str(json).unwrap();
        let info: CanisterInfo = raw.into();
        assert_eq!(info.name.as_deref(), Some("ICP Ledger"));
        assert_eq!(info.canister_type.as_deref(), Some("ledger"));
        assert_eq!(info.language, None); // "" -> None
        assert_eq!(info.latest_upgrade_proposal, Some(42)); // newest by timestamp
    }

    // The Caffeine env.json pattern (offline so it doesn't flake when drafts expire).
    #[test]
    fn env_json_yields_backend_canister_id() {
        let body = r#"{"backend_canister_id":"dmp3l-2yaaa-aaaae-aamva-cai",
                       "backend_host":"https://icp-api.io",
                       "project_id":"019ed114-d95a-71aa-bb1f-2410200446d2"}"#;
        let got = canisters_from_env_json(body);
        assert_eq!(got.len(), 1, "only the canister key should match: {got:?}");
        assert_eq!(got[0].0, "dmp3l-2yaaa-aaaae-aamva-cai");
        assert_eq!(got[0].1, "backend_canister_id");
    }

    // App Connect discovery metadata (spec §4.7/§6.1): the ic:canister-id meta
    // is read from the RAW markup, tolerating attribute order and quote style;
    // an SPA catch-all page without the meta yields nothing.
    #[test]
    fn parse_meta_reads_app_connect_canister_id() {
        // The shipped ai-connect.html shape (name first, double quotes).
        let page = r#"<!doctype html><html><head><meta charset="utf-8">
            <meta name="ic:canister-id" content="dmp3l-2yaaa-aaaae-aamva-cai">
            <title>Connect</title></head><body></body></html>"#;
        assert_eq!(
            parse_meta(page, "ic:canister-id").as_deref(),
            Some("dmp3l-2yaaa-aaaae-aamva-cai")
        );
        // Attribute order flipped + single quotes.
        let flipped = r#"<meta content='aaaaa-aa' name='ic:canister-id'>"#;
        assert_eq!(parse_meta(flipped, "ic:canister-id").as_deref(), Some("aaaaa-aa"));
        // Other metas don't match; absent meta yields None.
        let other = r#"<meta name="viewport" content="width=device-width">"#;
        assert_eq!(parse_meta(other, "ic:canister-id"), None);
        assert_eq!(parse_meta("<html>no metas</html>", "ic:canister-id"), None);
        // The right meta is found among several.
        let multi = format!("{other}\n<meta name=\"ic:network\" content=\"ic\">\n{flipped}");
        assert_eq!(parse_meta(&multi, "ic:canister-id").as_deref(), Some("aaaaa-aa"));
        assert_eq!(parse_meta(&multi, "ic:network").as_deref(), Some("ic"));
        // Attribute boundaries (per review): `data-name` must NOT match `name`,
        // and whitespace around `=` is legal HTML that must still parse.
        let trap = r#"<meta data-name="ic:canister-id" content="evil-id">"#;
        assert_eq!(parse_meta(trap, "ic:canister-id"), None, "data-name must not match name");
        let spaced = r#"<meta name = "ic:canister-id" content =  "aaaaa-aa">"#;
        assert_eq!(parse_meta(spaced, "ic:canister-id").as_deref(), Some("aaaaa-aa"));
        // Both shapes on one tag: the boundary-checked real `name` wins.
        let both = r#"<meta data-name="decoy" name="ic:canister-id" content="aaaaa-aa">"#;
        assert_eq!(parse_meta(both, "ic:canister-id").as_deref(), Some("aaaaa-aa"));
        // An unquoted value is not accepted (we only read the quoted shape).
        assert_eq!(attr("name=bare content=\"x\"", "name"), None);
        // Tag-name boundary (per review): `<metadata …>` is not a <meta> tag,
        // and must not shadow a real meta that follows it.
        let metadata = r#"<metadata name="ic:canister-id" content="evil-id">"#;
        assert_eq!(parse_meta(metadata, "ic:canister-id"), None, "<metadata> must not match");
        let after = format!("{metadata}\n<meta name=\"ic:canister-id\" content=\"aaaaa-aa\">");
        assert_eq!(parse_meta(&after, "ic:canister-id").as_deref(), Some("aaaaa-aa"));
        // A malformed, never-closed `<meta` can't panic or loop; it just ends
        // the scan (no '>' remains, so no complete tag can follow anyway).
        assert_eq!(parse_meta("<meta name=\"ic:canister-id\" content=\"x\"", "ic:canister-id"), None);
        // A key inside another attribute's quoted VALUE must not match (per
        // review): the tokenizer consumes values whole, so `name=…` embedded in
        // `data="…"` is invisible, and the tag's REAL name attribute is used.
        let embedded = r#"<meta data="junk name='ic:canister-id' content='evil'" name="viewport" content="w">"#;
        assert_eq!(parse_meta(embedded, "ic:canister-id"), None, "key inside a value must not match");
        assert_eq!(attr(r#"data="x name='inner' y" name="real""#, "name").as_deref(), Some("real"));
        // HTML tag and attribute names are ASCII-case-insensitive (per review):
        // <META NAME=… CONTENT=…> parses; a mixed-case <MetaData> still doesn't.
        let upper = r#"<META NAME="ic:canister-id" CONTENT="aaaaa-aa">"#;
        assert_eq!(parse_meta(upper, "ic:canister-id").as_deref(), Some("aaaaa-aa"));
        let mixed_decoy = r#"<MetaData name="ic:canister-id" content="evil">"#;
        assert_eq!(parse_meta(mixed_decoy, "ic:canister-id"), None, "<MetaData> must not match");
    }

    // App-declared labels must win over the header's generic "frontend" for the
    // SAME canister (single-canister apps): `add` keeps the FIRST label, so
    // discover() probes the declared metadata before the header. This pins the
    // first-label-wins semantics that ordering relies on.
    #[test]
    fn add_keeps_first_label_so_declared_probes_run_first() {
        let mut found = Findings::default();
        let id = "dmp3l-2yaaa-aaaae-aamva-cai";
        found.add(id, Some("main backend (App Connect)".into()), "ai-connect.html".into());
        found.add(id, Some("frontend".into()), "header".into());
        let f = &found.map[id];
        assert_eq!(f.label.as_deref(), Some("main backend (App Connect)"));
        assert_eq!(f.sources, vec!["ai-connect.html", "header"], "both provenances kept");
    }

    // The proposed /.well-known/ic-app.json manifest: entries yield (id, label)
    // pairs with "role — description" labels; unknown fields are ignored;
    // hostile shapes (non-JSON / HTML catch-all / huge lists / control chars in
    // labels) fail closed or are bounded.
    #[test]
    fn app_manifest_parses_and_fails_closed() {
        let manifest = r#"{
          "name": "Example DEX",
          "canisters": [
            {"id": "dmp3l-2yaaa-aaaae-aamva-cai", "role": "backend", "description": "orders API"},
            {"id": "ryjl3-tyaaa-aaaaa-aaaba-cai", "role": "ledger"},
            {"id": "qoctq-giaaa-aaaaa-aaaea-cai", "description": "governance"},
            {"id": "aaaaa-aa", "future_field": {"nested": true}},
            {"id": "  "},
            {"role": "orphan-no-id"}
          ]
        }"#;
        let got = canisters_from_app_manifest(manifest);
        assert_eq!(got.len(), 4, "blank/missing ids are skipped: {got:?}");
        assert_eq!(got[0], ("dmp3l-2yaaa-aaaae-aamva-cai".into(), Some("backend — orders API".into())));
        assert_eq!(got[1], ("ryjl3-tyaaa-aaaaa-aaaba-cai".into(), Some("ledger".into())));
        assert_eq!(got[2], ("qoctq-giaaa-aaaaa-aaaea-cai".into(), Some("governance".into())));
        assert_eq!(got[3], ("aaaaa-aa".into(), None), "unknown fields are ignored");

        // Fail closed: not JSON (an SPA catch-all serving HTML) or wrong shape.
        assert!(canisters_from_app_manifest("<!doctype html><html>app</html>").is_empty());
        assert!(canisters_from_app_manifest("[1,2,3]").is_empty());
        assert!(canisters_from_app_manifest("").is_empty());

        // Bounded: a hostile manifest can't produce unbounded findings.
        let huge = format!(
            r#"{{"canisters":[{}]}}"#,
            std::iter::repeat(r#"{"id":"aaaaa-aa"}"#)
                .take(500)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(canisters_from_app_manifest(&huge).len(), MAX_MANIFEST_CANISTERS);

        // Labels are sanitized: control chars (ANSI/CR) become spaces, length capped.
        let sneaky = r#"{"canisters":[{"id":"aaaaa-aa","role":"ok\u001b[31mEVIL\r\nline"}]}"#;
        let got = canisters_from_app_manifest(sneaky);
        let label = got[0].1.as_deref().unwrap();
        assert!(!label.chars().any(char::is_control), "control chars must be gone: {label:?}");
        let long = format!(r#"{{"canisters":[{{"id":"aaaaa-aa","role":"{}"}}]}}"#, "x".repeat(1000));
        assert!(canisters_from_app_manifest(&long)[0].1.as_deref().unwrap().len() <= 120);
    }

    // The manifest's optional declared derivation origin is read and reduced to a
    // bare origin; absent / blank / non-http values yield None (fail-closed).
    #[test]
    fn declared_derivation_origin_parses_and_fails_closed() {
        let declared = r#"{"derivation_origin":"https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io","canisters":[]}"#;
        assert_eq!(
            declared_derivation_origin(declared).as_deref(),
            Some("https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io")
        );
        // Reduced to a bare origin (path/query/trailing slash dropped).
        let with_path = r#"{"derivation_origin":"https://app.example.com/x?y=1"}"#;
        assert_eq!(declared_derivation_origin(with_path).as_deref(), Some("https://app.example.com"));
        // A scheme-less bare host is accepted (https assumed), matching the
        // interactive `derivation_origin` param, so a good-faith bare-host
        // declaration resolves instead of being silently dropped.
        let bare = r#"{"derivation_origin":"app.example.com"}"#;
        assert_eq!(declared_derivation_origin(bare).as_deref(), Some("https://app.example.com"));
        // Absent, blank, non-http, or non-JSON → None.
        assert_eq!(declared_derivation_origin(r#"{"canisters":[]}"#), None);
        assert_eq!(declared_derivation_origin(r#"{"derivation_origin":"  "}"#), None);
        assert_eq!(declared_derivation_origin(r#"{"derivation_origin":"ftp://x/"}"#), None);
        // Non-https is rejected (https-only; else target_origin would silently
        // upgrade an http:// declaration while still reporting source=declared).
        assert_eq!(declared_derivation_origin(r#"{"derivation_origin":"http://example.com"}"#), None);
        // User-info is rejected (url.origin() would silently drop it).
        assert_eq!(declared_derivation_origin(r#"{"derivation_origin":"https://u:p@example.com"}"#), None);
        assert_eq!(declared_derivation_origin("<!doctype html>"), None);
    }

    // ii-alternative-origins parsing is tolerant and bounded, and sanitizes
    // entries; a non-conforming body yields an empty list.
    #[test]
    fn parse_alternative_origins_reads_the_list() {
        let body = r#"{"alternativeOrigins":["https://multidex.ai","https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io"]}"#;
        assert_eq!(
            parse_alternative_origins(body),
            vec!["https://multidex.ai", "https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io"]
        );
        assert!(parse_alternative_origins("<!doctype html>").is_empty());
        assert!(parse_alternative_origins(r#"{"other":1}"#).is_empty());
        // Fail-closed + normalize: a path is reduced to the bare origin, and a
        // non-https / unparseable entry is dropped rather than surfaced.
        assert_eq!(
            parse_alternative_origins(
                r#"{"alternativeOrigins":["https://a.example/some/path","http://insecure.example","ftp://x","not a url"]}"#
            ),
            // Path reduced to bare origin; http:// / non-https / unparseable dropped.
            vec!["https://a.example"]
        );
    }

    // A cross-origin derivation_origin declaration is honored ONLY when the
    // declared origin's ii-alternative-origins lists the requesting app origin —
    // the browser/II rule. A self-declaration is always allowed; an unlisted claim
    // (the ICPBB-430 spoof) is refused, and matching is by exact origin.
    #[test]
    fn derivation_origin_authorized_requires_the_declared_origin_to_list_the_app() {
        use super::derivation_origin_authorized;
        let app = "https://attacker.example";
        // Self-declaration: the app names its own origin — always allowed.
        assert!(derivation_origin_authorized(app, app, &[]));
        // Cross-origin claim, NOT listed by the declared origin → refused (the spoof).
        assert!(!derivation_origin_authorized(
            app,
            "https://oisy.com",
            &["https://oisy.com".into(), "https://nns.ic0.app".into()]
        ));
        // Empty / missing list → refused.
        assert!(!derivation_origin_authorized(app, "https://oisy.com", &[]));
        // Cross-origin claim that IS listed → allowed (a legitimate multi-frontend app).
        assert!(derivation_origin_authorized(
            "https://frontend.example",
            "https://oisy.com",
            &["https://frontend.example".into()]
        ));
        // Matching is by exact origin: a different scheme/port/host must not pass.
        assert!(!derivation_origin_authorized(
            "https://app.example",
            "https://oisy.com",
            &["https://app.example:8443".into(), "http://app.example".into(), "https://app.example.evil".into()]
        ));
    }

    // The full resolver decision (given the parsed declared origin + its
    // alt-origins): no declaration → app-origin default; self/authorized → the
    // declared origin as Declared; an unauthorizable cross-origin claim is an
    // ERROR, not a silent app-origin fall-back that would derive a wrong identity
    // (ICPBB-430; aterga's review of PR #131).
    #[test]
    fn decide_declared_origin_authorizes_or_errors() {
        use super::{decide_declared_origin, DerivationSource};
        let app = "https://app.example";
        // No declaration → the application origin, AppUrlDefault.
        assert_eq!(
            decide_declared_origin(app, None, &[]).unwrap(),
            (app.to_string(), DerivationSource::AppUrlDefault)
        );
        // Self-declaration → the app's own origin, Declared.
        assert_eq!(
            decide_declared_origin(app, Some(app), &[]).unwrap(),
            (app.to_string(), DerivationSource::Declared)
        );
        // Authorized cross-origin (the declared origin lists the app) → declared, Declared.
        assert_eq!(
            decide_declared_origin(app, Some("https://oisy.com"), &[app.into()]).unwrap(),
            ("https://oisy.com".to_string(), DerivationSource::Declared)
        );
        // Unauthorized cross-origin (the spoof) → Err, NOT an app-origin fall-back.
        assert!(decide_declared_origin(app, Some("https://oisy.com"), &["https://oisy.com".into()]).is_err());
        // Unverifiable — empty list (not listed, or the fetch failed) → Err.
        assert!(decide_declared_origin(app, Some("https://oisy.com"), &[]).is_err());
    }

    // `normalize` prepends https to a bare host but leaves an already-schemed URL
    // (ANY scheme case) untouched — matching only lowercase would double-prefix a
    // validated `HTTPS://host` into `https://HTTPS://host` and break URL parsing.
    #[test]
    fn normalize_is_scheme_case_insensitive() {
        assert_eq!(normalize("example.com"), "https://example.com");
        assert_eq!(normalize("https://example.com/"), "https://example.com");
        assert_eq!(normalize("HTTPS://example.com"), "HTTPS://example.com");
        // The uppercase-scheme result parses cleanly (url lowercases the scheme),
        // rather than becoming a double-prefixed `https://HTTPS://example.com`.
        assert_eq!(
            url::Url::parse(&normalize("HTTPS://example.com")).unwrap().scheme(),
            "https"
        );
    }

    // The built-in registry maps each special-cased app host to its custom
    // derivation origin; unknown hosts fall through (to app_url_default), and every
    // registered value is already a canonical bare https origin.
    #[test]
    fn known_derivation_origin_maps_special_cased_apps() {
        assert_eq!(known_derivation_origin("nns.internetcomputer.org"), Some("https://nns.ic0.app"));
        assert_eq!(known_derivation_origin("nns.ic0.app"), Some("https://nns.ic0.app"));
        assert_eq!(known_derivation_origin("oisy.com"), Some("https://oisy.com"));
        assert_eq!(
            known_derivation_origin("multidex.ai"),
            Some("https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io")
        );
        assert_eq!(known_derivation_origin("app.icpswap.com"), Some("https://app.icpswap.com"));
        assert_eq!(known_derivation_origin("example.com"), None);
        // Invariant: each registry origin round-trips through normalize_origin
        // unchanged (i.e. it's already a canonical bare https origin).
        for (host, origin) in KNOWN_DERIVATION_ORIGINS {
            assert_eq!(
                normalize_origin(origin).as_deref(),
                Some(*origin),
                "registry origin for {host} must be a canonical bare https origin"
            );
        }
    }

    // Closure (offline): every derivation-origin VALUE in the registry is itself a
    // key mapping to itself — so resolving a known app's derivation origin returns
    // that same origin (source `known`), i.e. resolve_app is idempotent on it.
    #[test]
    fn registry_is_closed_under_its_derivation_origins() {
        for (host, origin) in KNOWN_DERIVATION_ORIGINS {
            let d_host = url::Url::parse(origin).unwrap().host_str().unwrap().to_ascii_lowercase();
            assert_eq!(
                known_derivation_origin(&d_host),
                Some(*origin),
                "derivation origin {origin} (from entry {host}) must itself be a registry key mapping to itself",
            );
        }
    }

    // icp_find_app_by_name maps a well-known app NAME (in various forms) to its URL +
    // derivation origin; an unknown name yields no match and a web-lookup note. Each
    // known app's derivation origin must agree with KNOWN_DERIVATION_ORIGINS.
    #[test]
    fn find_app_by_name_resolves_known_apps_and_directs_others() {
        // MULTI/DEX matches regardless of punctuation/casing/spacing, including when
        // the name is split across tokens inside a longer phrase.
        for q in ["MULTI/DEX", "multidex", "multi dex", "Use the MULTIDEX app", "Use the MULTI DEX app"] {
            let out = find_app_by_name(q);
            assert_eq!(out.matches.len(), 1, "{q:?} should match one app");
            assert_eq!(out.matches[0].app_url, "https://multidex.ai");
            // Derive the expected origin from the registry (single source of truth),
            // don't re-hard-code it.
            assert_eq!(
                out.matches[0].derivation_origin,
                known_derivation_origin("multidex.ai").unwrap(),
            );
        }
        assert_eq!(find_app_by_name("Oisy").matches[0].app_url, "https://oisy.com");
        assert_eq!(find_app_by_name("nns").matches[0].app_url, "https://nns.internetcomputer.org");
        assert_eq!(find_app_by_name("ICPSwap").matches[0].app_url, "https://app.icpswap.com");

        // The derivation origin is DERIVED from KNOWN_DERIVATION_ORIGINS (single
        // source of truth), so every app_url host must be a registry key — otherwise
        // known_app_derivation_origin would silently fall back to the app URL.
        for app in KNOWN_APPS {
            let host = url::Url::parse(app.app_url).unwrap().host_str().unwrap().to_ascii_lowercase();
            assert!(
                known_derivation_origin(&host).is_some(),
                "{}'s app_url host {host} must be a key in KNOWN_DERIVATION_ORIGINS \
                 (the derivation origin is derived from it, not stored)",
                app.name,
            );
            // And the derived origin is exactly the registry value.
            assert_eq!(known_app_derivation_origin(app), known_derivation_origin(&host).unwrap());
        }

        // An unknown app: no match, and the note points to a web search.
        let unknown = find_app_by_name("Totally Unknown DApp");
        assert!(unknown.matches.is_empty());
        assert!(unknown.note.to_lowercase().contains("web search"), "note: {}", unknown.note);
        // Blank / punctuation-only input doesn't match anything.
        assert!(find_app_by_name("   /  ").matches.is_empty());
        // Token-boundary matching: a word that merely CONTAINS an alias as a
        // substring must NOT match (these all would have under the old contains rule).
        for q in ["noisy", "a noisy afternoon", "annoisyance", "icpswapper", "multidexchange"] {
            assert!(
                find_app_by_name(q).matches.is_empty(),
                "{q:?} must not match a known app (substring false positive)",
            );
        }
    }

    // IC evidence requires a VALID canister-principal value, not just header
    // presence — so an unrelated site echoing an empty/junk `x-ic-canister-id`
    // can't fake IC hosting and slip past the guessed-domain guard. (The
    // same-host attribution in ic_evidence_from — evidence must come from the
    // probed origin, not a redirect target — is exercised by the live tests.)
    #[test]
    fn ic_gateway_header_requires_valid_principal_value() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-ic-canister-id", HeaderValue::from_str(v).unwrap());
            header_is_ic_principal(&h)
        };
        // Real canister ids (gateway form + the management canister) count.
        assert!(with("ryjl3-tyaaa-aaaaa-aaaba-cai"));
        assert!(with("  cha4i-riaaa-aaaan-qeccq-cai  ")); // surrounding space tolerated
        assert!(with("aaaaa-aa"));
        // Presence with an empty/junk value does NOT.
        assert!(!with(""));
        assert!(!with("true"));
        assert!(!with("not-a-principal"));
        // Absent header: no evidence.
        assert!(!header_is_ic_principal(&HeaderMap::new()));
    }

    // "Did you mean" repair: a host FABRICATED from a well-known app's name (the
    // guessed-domain failure mode) maps back to the real app; real registered
    // hosts and unrelated hosts don't trigger it.
    #[test]
    fn similar_known_app_repairs_guessed_domains() {
        // The exact guesses observed in the wild for MULTI/DEX (real URL multidex.ai).
        for guess in ["multidex.com", "https://multidex.app", "multi.dex", "www.multidex.io"] {
            let m = similar_known_app(guess)
                .unwrap_or_else(|| panic!("{guess} should suggest MULTI/DEX"));
            assert_eq!(m.name, "MULTI/DEX");
            assert_eq!(m.app_url, "https://multidex.ai");
            assert_eq!(m.derivation_origin, known_derivation_origin("multidex.ai").unwrap());
        }
        assert_eq!(similar_known_app("icpswap.com").map(|m| m.app_url).as_deref(), Some("https://app.icpswap.com"));
        assert_eq!(similar_known_app("oisy.org").map(|m| m.name).as_deref(), Some("Oisy"));
        // A REAL known-app host is not a lookalike — nothing to repair.
        for real in ["multidex.ai", "https://oisy.com", "app.icpswap.com", "nns.internetcomputer.org"] {
            assert!(similar_known_app(real).is_none(), "{real} is a real host, no suggestion");
        }
        // Token boundaries hold (no substring false positives), and unrelated or
        // unparseable inputs yield nothing.
        for other in ["noisy.com", "multidexchange.org", "example.com", ""] {
            assert!(similar_known_app(other).is_none(), "{other:?} must not match");
        }
    }

    // open_app's query classifier: a bare name / wrong-TLD guess repairs to the
    // canonical known app; an explicit https:// URL is honoured verbatim (so the
    // gate refuses it if it's a guess); a dotted non-known host is a URL to
    // resolve; a bare unknown word is refused rather than turned into a domain.
    #[test]
    fn classify_app_query_routes_names_urls_and_guesses() {
        use AppQuery::*;
        let known = |q: &str, want: &str| match classify_app_query(q) {
            Known(m) => assert_eq!(m.app_url, want, "{q:?}"),
            other => panic!("{q:?} should be a Known match, got {:?}", DebugQ(&other)),
        };
        // Names, spaced/cased/punctuated names, and wrong-TLD guesses all repair to
        // the canonical known-app URL.
        known("MULTI/DEX", "https://multidex.ai");
        known("multi dex", "https://multidex.ai");
        known("multidex.com", "https://multidex.ai"); // wrong-TLD guess, no scheme
        known("Oisy", "https://oisy.com");
        known("nns", "https://nns.internetcomputer.org");
        // An explicit scheme is honoured as a URL (NOT registry-rewritten) — so a
        // deliberately-typed guess reaches the IC-evidence gate on that origin.
        match classify_app_query("https://multidex.com") {
            Url(u) => assert_eq!(u, "https://multidex.com"),
            other => panic!("explicit scheme must be a Url, got {:?}", DebugQ(&other)),
        }
        // A dotted host that matches no known app is a URL to resolve as given.
        match classify_app_query("coolapp.io") {
            Url(u) => assert_eq!(u, "coolapp.io"),
            other => panic!("unknown dotted host must be a Url, got {:?}", DebugQ(&other)),
        }
        // A bare unknown word is an unknown NAME — refused, never fabricated into a host.
        assert!(matches!(classify_app_query("totallyunknownapp"), UnknownName));
        assert!(matches!(classify_app_query("   "), UnknownName));
    }

    // Tiny Debug shim so the assertions above can name the variant they got.
    struct DebugQ<'a>(&'a AppQuery);
    impl std::fmt::Debug for DebugQ<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                AppQuery::Known(m) => write!(f, "Known({})", m.app_url),
                AppQuery::Url(u) => write!(f, "Url({u})"),
                AppQuery::UnknownName => write!(f, "UnknownName"),
            }
        }
    }

    // Live network: a reachable NON-IC origin resolves to app_url_default with
    // application_is_ic = Some(false) — the signature callers refuse on. example.com
    // is IANA-reserved and stable, and will never be served from the IC.
    #[tokio::test]
    async fn resolve_app_identity_flags_non_ic_origin() {
        let r = resolve_app_identity("example.com", false).await.expect("resolve");
        assert_eq!(r.derivation_origin_source, DerivationSource::AppUrlDefault);
        assert_eq!(r.application_is_ic, Some(false), "example.com must show no IC evidence");
    }

    // Live network: a KNOWN app skips the IC probe entirely (the registry answers).
    #[tokio::test]
    async fn resolve_app_identity_skips_probe_for_known_apps() {
        let r = resolve_app_identity("oisy.com", false).await.expect("resolve");
        assert_eq!(r.derivation_origin_source, DerivationSource::Known);
        assert_eq!(r.application_is_ic, None, "known apps are not probed");
    }

    // Consistency (networked): every origin in a known app's LIVE
    // ii-alternative-origins must map, in the registry, to the SAME derivation
    // origin — so resolve_app yields the same result for any of an app's frontends,
    // not just its primary host. A failure flags registry drift (the app added a new
    // alternative origin we should include). Best-effort on fetch: an unreachable /
    // offline endpoint (empty list) is skipped so a network blip doesn't fail CI.
    #[tokio::test]
    async fn known_apps_are_closed_over_their_alt_origins() {
        for d in [
            "https://nns.ic0.app",
            "https://oisy.com",
            "https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io",
        ] {
            let d_host = url::Url::parse(d).unwrap().host_str().unwrap().to_ascii_lowercase();
            let expected = known_derivation_origin(&d_host)
                .unwrap_or_else(|| panic!("{d_host} must be a registry key"));
            let alts = fetch_alternative_origins(d).await;
            if alts.is_empty() {
                continue; // unreachable / offline — don't fail CI on a network blip
            }
            for o in &alts {
                let h = url::Url::parse(o).unwrap().host_str().unwrap().to_ascii_lowercase();
                assert_eq!(
                    known_derivation_origin(&h),
                    Some(expected),
                    "alt-origin {o} of {d} is not mapped to {expected} in the registry (drift?)",
                );
            }
        }
    }

    // #3: the capability probe + data-access handle attach ONLY to the app's own
    // data canisters — never the gateway frontend or a shared system canister
    // (ledger/II/NNS), per the security guardrail.
    #[test]
    fn is_app_data_candidate_scopes_to_app_backends() {
        let dc = |label: Option<&str>, sources: &[&str], kind: Option<&str>| DiscoveredCanister {
            canister_id: "aaaaa-aa".to_string(),
            label: label.map(str::to_string),
            name: None,
            kind: kind.map(str::to_string),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            oql: None,
            api_doc_available: None,
        };
        // App-declared / app-mined backends → candidates.
        assert!(is_app_data_candidate(&dc(None, &["ai-connect.html"], None)));
        assert!(is_app_data_candidate(&dc(Some("backend"), &["ic-app.json"], None)));
        assert!(is_app_data_candidate(&dc(Some("backend_canister_id"), &["env.json"], None)));
        assert!(is_app_data_candidate(&dc(Some("BACKEND"), &["bundle:BACKEND"], None)));
        // The frontend / asset canister → NOT a candidate.
        assert!(!is_app_data_candidate(&dc(Some("frontend"), &["ic-app.json"], None)));
        assert!(!is_app_data_candidate(&dc(None, &["header"], None)));
        // A shared system canister (dashboard-classified) → NOT a candidate, even
        // if it slipped in via a bundle literal.
        assert!(!is_app_data_candidate(&dc(None, &["bundle"], Some("ledger"))));
        assert!(!is_app_data_candidate(&dc(None, &["ic-app.json"], Some("governance"))));
    }
}
