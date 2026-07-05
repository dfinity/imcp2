//! Best-effort discovery of the canisters behind a web domain served from the
//! Internet Computer, folding together the patterns we've seen across apps:
//!
//!   1. `x-ic-canister-id` response header — the frontend/asset canister. This
//!      is the one universal, authoritative signal (the HTTP gateway sets it).
//!   2. a runtime config asset (`/env.json`) carrying `*canister_id*` keys —
//!      e.g. Caffeine apps expose `backend_canister_id` here.
//!   3. canister-id literals in the JS bundle, preferring labelled
//!      `*_CANISTER_ID` constants — e.g. dfx/Vite apps like OISY bake
//!      `IC_BACKEND_CANISTER_ID`, `IC_SIGNER_CANISTER_ID`, etc.
//!
//! There is NO authoritative reverse lookup for "this site's backend" — only
//! the frontend (1) is certain. (2) and (3) are mined from client code, so each
//! result carries its provenance and the caller decides (and should confirm
//! with `get_candid`).

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use candid::Principal;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

#[derive(Serialize, Clone, Debug)]
pub struct Found {
    pub canister_id: String,
    /// A human label if one was attached (env.json key, bundle constant name,
    /// or "frontend"); None for a bare bundle literal.
    pub label: Option<String>,
    /// Where it was found: "header", "env.json", "bundle:<LABEL>", "bundle".
    pub sources: Vec<String>,
    /// IC dashboard label (e.g. "ICP Ledger"), filled in when the id is a known
    /// canister; None otherwise. Set during dashboard enrichment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// IC dashboard classification (e.g. "ledger"), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
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

fn normalize(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('/');
    if d.starts_with("http://") || d.starts_with("https://") {
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
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)) // 2001:db8::/32 documentation
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
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024; // one document (HTML, one JS file)
const MAX_ENV_JSON_BYTES: usize = 256 * 1024; // /env.json is tiny in practice
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

fn add(found: &mut BTreeMap<String, Found>, id: &str, label: Option<String>, source: String) {
    // Drop false positives by validating as a real principal.
    if Principal::from_text(id).is_err() {
        return;
    }
    let entry = found.entry(id.to_string()).or_insert_with(|| Found {
        canister_id: id.to_string(),
        label: None,
        sources: Vec::new(),
        name: None,
        kind: None,
    });
    if entry.label.is_none() {
        entry.label = label;
    }
    if !entry.sources.contains(&source) {
        entry.sources.push(source);
    }
}

pub async fn discover(domain: &str) -> Result<Vec<Found>, String> {
    let base = normalize(domain);
    // SSRF guard (CWE-918): validate + resolve the fully user-controlled target
    // to public addresses BEFORE any request, and pin them into the client so the
    // connection can't rebind to an internal host. The pin only affects this site
    // host, so the dashboard-enrichment calls below (different hosts) still work.
    let (base_url, pinned) = resolve_public_url(&base).await?;
    let host = base_url.host_str().unwrap_or_default().to_string();
    let client = site_client(&host, &pinned)?;

    let mut found: BTreeMap<String, Found> = BTreeMap::new();

    // 1. Frontend via the gateway header (and keep the HTML for bundle mining).
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
        add(&mut found, id, Some("frontend".into()), "header".into());
    }
    let html = read_capped(resp, MAX_BODY_BYTES).await;

    // 2. Runtime config: /env.json with *canister_id* keys (e.g. Caffeine apps).
    if let Ok(resp) = client.get(format!("{base}/env.json")).send().await {
        if resp.status().is_success() {
            let text = read_capped(resp, MAX_ENV_JSON_BYTES).await;
            for (id, label) in canisters_from_env_json(&text) {
                add(&mut found, &id, Some(label), "env.json".into());
            }
        }
    }

    // 3. JS bundle: labelled constants first, then any bare canister literals.
    let mut blob = html.clone();
    let script_re = Regex::new(r#"["'](/[^"'<> ]+?\.js)["']"#).unwrap();
    let mut scripts: Vec<String> = script_re
        .captures_iter(&html)
        .map(|c| c[1].to_string())
        .collect();
    scripts.sort();
    scripts.dedup();
    for s in scripts.iter().take(20) {
        if blob.len() >= MAX_SCAN_BYTES {
            break; // aggregate cap: stop mining once we've buffered enough text
        }
        if let Ok(resp) = client.get(format!("{base}{s}")).send().await {
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
        let label = c[1].to_string();
        add(&mut found, &c[2], Some(label.clone()), format!("bundle:{label}"));
    }
    for m in canister_re().find_iter(&blob) {
        add(&mut found, m.as_str(), None, "bundle".into());
    }

    // Order: header (frontend) first, then env.json, then labelled bundle, then bare.
    let mut out: Vec<Found> = found.into_values().collect();
    out.sort_by_key(|f| {
        if f.sources.iter().any(|s| s == "header") {
            0
        } else if f.sources.iter().any(|s| s == "env.json") {
            1
        } else if f.sources.iter().any(|s| s.starts_with("bundle:")) {
            2
        } else {
            3
        }
    });

    // Annotate each id with its IC dashboard identity (name/type) where known,
    // so a bare principal becomes an identified service. Best-effort.
    enrich_with_dashboard(&client, &mut out).await;

    Ok(out)
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
/// `lookup_canister` tool. Carries the SSRF redirect guard so a 3xx can never
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
                        "SNS project root — lookup_canister (or the SNS detail API) expands it \
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
        ] {
            assert!(!g(bad), "{bad} must be classified non-global");
        }
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

    // Live network test against a stable public IC app (OISY).
    #[tokio::test]
    async fn discovers_oisy_frontend_and_backend() {
        let found = discover("oisy.com").await.expect("discover");
        let ids: Vec<&str> = found.iter().map(|f| f.canister_id.as_str()).collect();
        // Frontend from the gateway header.
        assert!(
            ids.contains(&"cha4i-riaaa-aaaan-qeccq-cai"),
            "frontend not found: {ids:?}"
        );
        // Backend from the labelled bundle constant (IC_BACKEND_CANISTER_ID).
        assert!(
            ids.contains(&"doked-biaaa-aaaar-qag2a-cai"),
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
}
