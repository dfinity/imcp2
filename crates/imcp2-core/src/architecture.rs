//! The **ICP service-discoverability protocol** — the canonical way an
//! Internet Computer application describes itself to an agent, specified at
//! <https://docs.internetcomputer.org/guides/frontends/service-discoverability/>.
//!
//! The protocol has five layers, and this server speaks all of them:
//!
//!   1. **Composition** — `/.well-known/ic-architecture`, served at the
//!      application origin: the app enumerates the canisters it comprises,
//!      each with an `id` and human-readable `name`/`role`. THIS module.
//!   2. **Interface** — the canister's own `candid:service` metadata
//!      (`get_canister_candid`, [`crate::calls`]).
//!   3. **Behaviour** — the `getApiDoc`/`get_api_doc` query method
//!      (`get_canister_api_doc`).
//!   4. **Data** — the OQL `schema`/`execute` query convention
//!      (`get_canister_oql_schema`, `canister_query`'s `oql` argument).
//!   5. **Identity** — `/.well-known/ii-derivation-origin`, the one line
//!      naming the origin Internet Identity derives the user's principal
//!      against. Parsed here, resolved in [`crate::discover`].
//!
//! Layer 1 is load-bearing beyond discovery: it is what an **update call**
//! is authorized against ([`crate::authorization`]). An app's architecture
//! manifest is the app's own signed-by-serving statement of which canisters
//! belong to it, fetched from the exact application origin over HTTPS — so
//! unlike a canister id mined out of a JS bundle, an `/env.json`, or a
//! response header, it cannot be attributed to an app that never claimed it.
//! Everything here therefore **fails closed**: an unreachable origin, a
//! missing file, a body that isn't the declared schema, or an entry whose id
//! isn't a canister principal all yield "not declared", never "assume yes".
//!
//! The manifest is deliberately **not cached**. Each authorization decision
//! re-reads the live file, so an app that removes a canister from its
//! manifest loses write access to it on the next call rather than at the end
//! of a TTL.

use candid::Principal;
use serde::Deserialize;

use crate::discover;

/// Layer 1: where the composition manifest lives. Path-exact, per the spec —
/// no extension, no alternate spelling, no fallback path.
pub const ARCHITECTURE_WELL_KNOWN: &str = "/.well-known/ic-architecture";

/// Layer 5: where an app declares the Internet Identity derivation origin its
/// frontends pin. A single line holding that origin; absent when the app
/// derives against the visible origin itself.
pub const II_DERIVATION_ORIGIN_WELL_KNOWN: &str = "/.well-known/ii-derivation-origin";

/// The schema version this server understands. The spec's `version` field
/// identifies the manifest schema; we accept the `1.x` line (unknown fields
/// are ignored for forward compatibility, which is what a minor bump is for)
/// and refuse anything else rather than guessing at a future shape.
const SUPPORTED_SCHEMA_MAJOR: &str = "1";

/// Cap on manifest entries. Generous — the body itself is capped at
/// [`discover::MAX_META_BYTES`], so this only bounds a hostile manifest that
/// packs the cap full of tiny entries.
///
/// Exceeding it rejects the WHOLE manifest rather than truncating it.
/// Truncation is the wrong failure here: a legitimately declared canister
/// past the cut would be silently refused, and the app developer would see
/// one canister mysteriously not working with nothing to go on. A whole-
/// manifest refusal names the cap, so the signal is actionable.
const MAX_ARCHITECTURE_CANISTERS: usize = 1000;

/// The `/.well-known/ic-architecture` document. Unknown fields are ignored
/// (the spec mandates forward compatibility); `version` is validated rather
/// than defaulted, so a body that merely happens to carry a `canisters` array
/// is not mistaken for a manifest.
#[derive(Debug, Deserialize)]
pub struct Architecture {
    /// The manifest schema version, e.g. `"1.0.0"`.
    pub version: String,
    #[serde(default)]
    pub canisters: Vec<ArchitectureCanister>,
}

/// One canister the app declares itself to comprise.
#[derive(Debug, Deserialize)]
pub struct ArchitectureCanister {
    /// The canister's principal id — the only required field.
    pub id: String,
    /// A short identifier for the canister within the app, e.g. `"backend"`.
    #[serde(default)]
    pub name: Option<String>,
    /// What the canister does in the app, e.g. `"the backend"`.
    #[serde(default)]
    pub role: Option<String>,
    /// Optional longer prose, e.g. `"orders + inventory API"`.
    #[serde(default)]
    pub description: Option<String>,
}

impl ArchitectureCanister {
    /// The entry's id as a principal, or `None` when it isn't one. App-supplied
    /// text, so never assumed valid: a membership test compares parsed
    /// principals, never raw strings, so `" aaaaa-aa "` and `"AAAAA-AA"` cannot
    /// smuggle a different target past the comparison.
    fn principal(&self) -> Option<Principal> {
        Principal::from_text(self.id.trim()).ok()
    }

    /// The human label for this entry — `name`, `role`, and `description`
    /// folded into one display string, each sanitized (app-supplied text,
    /// never markup or unbounded).
    pub fn label(&self) -> Option<String> {
        let clean = |s: &Option<String>| {
            s.as_deref()
                .map(discover::clean_label)
                .filter(|s| !s.is_empty())
        };
        let (name, role, desc) = (
            clean(&self.name),
            clean(&self.role),
            clean(&self.description),
        );
        // `role` is the richer of the two identifiers ("the backend" vs
        // "backend"), so it leads when both are present.
        let head = match (name, role) {
            (Some(n), Some(r)) if r.eq_ignore_ascii_case(&n) => Some(r),
            (Some(n), Some(r)) => Some(format!("{r} ({n})")),
            (Some(n), None) => Some(n),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        };
        match (head, desc) {
            (Some(h), Some(d)) => Some(format!("{h} — {d}")),
            (Some(h), None) => Some(h),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        }
    }
}

impl Architecture {
    /// The declared entry for `canister_id` — the membership test an update
    /// call is authorized against: `Some(label)` when the app lists it (the
    /// label itself may be absent, hence the nested `Option`), `None` when it
    /// doesn't. Compares parsed principals, so only a genuine id match counts.
    pub fn role_of(&self, canister_id: &Principal) -> Option<Option<String>> {
        self.canisters
            .iter()
            .find(|c| c.principal().as_ref() == Some(canister_id))
            .map(|c| c.label())
    }

    /// The declared canisters as `(id, label)` pairs for discovery output.
    /// Entries whose id isn't a canister principal are dropped — the app said
    /// something we can't act on, so we don't surface it as a finding.
    pub fn findings(&self) -> Vec<(String, Option<String>)> {
        self.canisters
            .iter()
            .filter_map(|c| c.principal().map(|p| (p.to_text(), c.label())))
            .collect()
    }
}

/// Parse an `/.well-known/ic-architecture` body. `Err` carries why the body is
/// not a usable manifest, for the refusal message — every failure is a
/// fail-closed "this app declares nothing", never a soft default.
pub fn parse_architecture(text: &str) -> Result<Architecture, String> {
    let arch: Architecture = serde_json::from_str(text).map_err(|e| {
        // A frontend's SPA catch-all serves index.html for unknown paths, which
        // is the overwhelmingly common reason this isn't JSON — say so, since
        // the fix (exempt the path from the rewrite) is in the app's hands.
        format!(
            "the body is not the declared JSON schema ({e}) — an SPA catch-all \
             serving HTML at this path is the usual cause; the spec requires \
             {ARCHITECTURE_WELL_KNOWN} to be exempt from catch-all rewrites and \
             served as application/json"
        )
    })?;
    let major = arch.version.trim().split('.').next().unwrap_or_default();
    if major != SUPPORTED_SCHEMA_MAJOR {
        return Err(format!(
            "manifest schema version {:?} is not supported (this server reads the \
             {SUPPORTED_SCHEMA_MAJOR}.x line)",
            arch.version.trim()
        ));
    }
    if arch.canisters.len() > MAX_ARCHITECTURE_CANISTERS {
        return Err(format!(
            "the manifest declares {} canisters, past the {MAX_ARCHITECTURE_CANISTERS} this \
             server reads — the whole manifest is refused rather than silently truncated",
            arch.canisters.len()
        ));
    }
    Ok(arch)
}

/// The app's declared Internet Identity derivation origin from a
/// `/.well-known/ii-derivation-origin` body: the file's single line, reduced
/// to a canonical bare `https://host[:port]` origin. `None` when the file is
/// blank or the line is not an explicit https origin — so a malformed
/// declaration falls back to the application origin instead of deriving
/// against garbage.
///
/// The `https://` scheme is REQUIRED here, unlike the scheme-tolerant
/// [`discover::normalize_origin`] used for interactively-supplied origins. The
/// spec's file holds a full origin, and accepting a bare host would read any
/// one-word 200 body as a declaration: an SPA catch-all answering this path
/// with a single token would become a bogus CROSS-origin claim, which the
/// alternative-origins check then refuses — turning a missing file into a hard
/// failure to resolve the app at all, instead of the application-origin default
/// the spec prescribes.
pub fn parse_derivation_origin(text: &str) -> Option<String> {
    // "Single line" per the spec; tolerate a trailing newline, a UTF-8 BOM, and
    // stray surrounding whitespace, but not a second line of content — a file
    // with more than one origin in it is not something to guess at.
    let mut lines =
        text.trim_start_matches('\u{feff}').lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    // The `https://` scheme is REQUIRED (`get`, not slicing, so a multi-byte
    // first character can't panic). See the doc above for why a bare host must
    // not be accepted here.
    if !first.get(..8).is_some_and(|p| p.eq_ignore_ascii_case("https://")) {
        return None;
    }
    discover::normalize_origin(first)
}

/// The outcome of reading an origin's architecture manifest. Both failure
/// variants deny authorization; they are distinct only so the refusal can tell
/// the agent whether the app's manifest said no or the app's origin couldn't be
/// read at all — two very different things for the developer to fix.
pub enum ArchitectureFetch {
    /// The exact origin served a well-formed manifest.
    Served(Architecture),
    /// The origin answered, but not with a usable manifest (404, a redirect off
    /// the origin, a catch-all HTML page, an unsupported schema version).
    NotDeclared(String),
    /// The origin could not be read at all (DNS, TLS, timeout, or the SSRF
    /// guard refusing a non-public target).
    Unreachable(String),
}

/// How long the whole manifest read may take before the call is refused as
/// unreadable. Deliberately shorter than the shared site-fetch timeout: this
/// one sits in front of every state-changing call, so a slow origin must cost
/// the caller a prompt "retry" rather than a long stall. The refusal says it is
/// retryable, so a transient slow patch costs a round trip, not a wrong answer.
const FETCH_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Fetch `origin`'s architecture manifest from the **exact** origin, within
/// [`FETCH_BUDGET`].
///
/// `origin` must already be canonical (see [`discover::normalize_origin`]).
/// Reuses the site-fetch guards every caller-supplied fetch in this crate
/// carries: the target is resolved to public addresses and pinned into the
/// client before the request (SSRF, CWE-918), the body is size-capped — and read
/// STRICTLY, so an incomplete or over-cap body is an error rather than a prefix
/// this gate would decide on — and the response must have come from the origin we
/// asked — the shared redirect
/// policy permits same-host different-PORT hops, so a manifest served after a
/// redirect could otherwise come from a neighbouring origin and be read as
/// this one's declaration.
pub async fn fetch_architecture(origin: &str) -> ArchitectureFetch {
    match tokio::time::timeout(FETCH_BUDGET, read_architecture(origin)).await {
        Ok(fetched) => fetched,
        Err(_) => ArchitectureFetch::Unreachable(format!(
            "reading {origin}{ARCHITECTURE_WELL_KNOWN} took longer than {}s",
            FETCH_BUDGET.as_secs()
        )),
    }
}

async fn read_architecture(origin: &str) -> ArchitectureFetch {
    let (url, pinned) = match discover::resolve_public_url(origin).await {
        Ok(v) => v,
        Err(e) => return ArchitectureFetch::Unreachable(e),
    };
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let client = match discover::site_client(&host, &pinned) {
        Ok(c) => c,
        Err(e) => return ArchitectureFetch::Unreachable(e),
    };
    let expected = url.origin().ascii_serialization();
    let resp = match client
        .get(format!("{expected}{ARCHITECTURE_WELL_KNOWN}"))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return ArchitectureFetch::Unreachable(format!(
                "could not read {expected}{ARCHITECTURE_WELL_KNOWN}: {e}"
            ))
        }
    };
    let served_by = resp.url().origin().ascii_serialization();
    if served_by != expected {
        return ArchitectureFetch::NotDeclared(format!(
            "{expected}{ARCHITECTURE_WELL_KNOWN} redirected to {served_by} — the \
             manifest must be served by the application origin itself"
        ));
    }
    if !resp.status().is_success() {
        return ArchitectureFetch::NotDeclared(format!(
            "{expected}{ARCHITECTURE_WELL_KNOWN} answered {} — the application serves \
             no architecture manifest",
            resp.status().as_u16()
        ));
    }
    // STRICTLY read: an incomplete body is an error here, not a prefix. A
    // truncated manifest could only ever deny a canister (a prefix cannot add an
    // entry), but a gate must not decide on a document it did not fully receive.
    let text = match discover::read_strict(resp, discover::MAX_META_BYTES).await {
        Ok(text) => text,
        Err(e) => {
            return ArchitectureFetch::Unreachable(format!(
                "{expected}{ARCHITECTURE_WELL_KNOWN} could not be read in full: {e}"
            ))
        }
    };
    match parse_architecture(&text) {
        Ok(arch) => ArchitectureFetch::Served(arch),
        Err(e) => ArchitectureFetch::NotDeclared(format!(
            "{expected}{ARCHITECTURE_WELL_KNOWN} is not readable as a manifest: {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The spec's own example manifest, verbatim from the guide.
    const SPEC_EXAMPLE: &str = r#"{
      "version": "1.0.0",
      "canisters": [
        { "id": "hcv4s-uaaaa-aaabq-qaaba-cai", "name": "frontend", "role": "the frontend" },
        { "id": "hmxr2-pqaaa-aaabq-qaaaa-cai", "name": "backend", "role": "the backend",
          "description": "orders + inventory API; call getApiDoc() first" }
      ]
    }"#;

    fn p(s: &str) -> Principal {
        Principal::from_text(s).unwrap()
    }

    #[test]
    fn parses_the_spec_example_and_answers_membership() {
        let arch = parse_architecture(SPEC_EXAMPLE).expect("spec example must parse");
        assert_eq!(arch.version, "1.0.0");
        assert!(arch.role_of(&p("hcv4s-uaaaa-aaabq-qaaba-cai")).is_some());
        assert!(arch.role_of(&p("hmxr2-pqaaa-aaabq-qaaaa-cai")).is_some());
        // A canister the app does NOT list is not declared, however real it is.
        assert!(arch.role_of(&p("ryjl3-tyaaa-aaaaa-aaaba-cai")).is_none());
        // Labels fold name/role/description for display.
        assert_eq!(
            arch.role_of(&p("hcv4s-uaaaa-aaabq-qaaba-cai")),
            Some(Some("the frontend (frontend)".to_string()))
        );
        assert_eq!(
            arch.findings()
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>(),
            vec!["hcv4s-uaaaa-aaabq-qaaba-cai", "hmxr2-pqaaa-aaabq-qaaaa-cai"]
        );
    }

    // Every malformed body is an error, not an empty-but-usable manifest: a
    // membership test against a silently-empty manifest would refuse, but a
    // membership test against a body we misread as a manifest could ALLOW.
    #[test]
    fn parse_fails_closed() {
        for (body, why) in [
            ("", "empty"),
            (
                "<!doctype html><html>SPA catch-all</html>",
                "an SPA catch-all page",
            ),
            (r#"{"canisters":[{"id":"aaaaa-aa"}]}"#, "no version field"),
            (
                r#"{"version":"2.0.0","canisters":[{"id":"aaaaa-aa"}]}"#,
                "a future schema",
            ),
            (
                r#"{"version":"1.0.0","canisters":"aaaaa-aa"}"#,
                "canisters not a list",
            ),
        ] {
            assert!(
                parse_architecture(body).is_err(),
                "{why} must not parse: {body}"
            );
        }
    }

    // An entry whose id is not a canister principal is inert: it can neither
    // authorize a call nor appear as a finding. So a manifest cannot smuggle a
    // target past the membership test by spelling it oddly.
    #[test]
    fn junk_ids_authorize_nothing() {
        let arch = parse_architecture(
            r#"{"version":"1.0.0","canisters":[
                 {"id":"not-a-principal"},
                 {"id":""},
                 {"id":"  ryjl3-tyaaa-aaaaa-aaaba-cai  ","role":"padded"}]}"#,
        )
        .expect("parses");
        assert_eq!(arch.findings().len(), 1, "only the real id is a finding");
        // A padded id is trimmed to the same principal — the comparison is on
        // parsed principals, so whitespace cannot fork the identity.
        assert!(arch.role_of(&p("ryjl3-tyaaa-aaaaa-aaaba-cai")).is_some());
    }

    // Forward compatibility: unknown fields (top-level and per entry) and a
    // minor/patch bump are accepted, because the spec says consumers must
    // ignore what they don't know.
    #[test]
    fn unknown_fields_and_minor_bumps_are_accepted() {
        let arch = parse_architecture(
            r#"{"version":"1.4.2","future_key":{"x":1},"canisters":[
                 {"id":"ryjl3-tyaaa-aaaaa-aaaba-cai","role":"ledger","future_entry_key":true}]}"#,
        )
        .expect("a 1.x manifest with unknown fields must parse");
        assert!(arch.role_of(&p("ryjl3-tyaaa-aaaaa-aaaba-cai")).is_some());
    }

    // Past the entry cap the WHOLE manifest is refused, not truncated: a
    // truncated manifest would silently deny a canister the app declared,
    // leaving the developer with one canister that mysteriously doesn't work.
    #[test]
    fn entry_cap_rejects_the_whole_manifest_rather_than_truncating() {
        let entry = r#"{"id":"ryjl3-tyaaa-aaaaa-aaaba-cai"}"#;
        let at_cap = format!(
            r#"{{"version":"1.0.0","canisters":[{}]}}"#,
            vec![entry; MAX_ARCHITECTURE_CANISTERS].join(",")
        );
        assert!(
            parse_architecture(&at_cap).is_ok(),
            "exactly at the cap is fine"
        );
        let over_cap = format!(
            r#"{{"version":"1.0.0","canisters":[{}]}}"#,
            vec![entry; MAX_ARCHITECTURE_CANISTERS + 1].join(",")
        );
        let msg = parse_architecture(&over_cap).expect_err("over the cap must be refused");
        assert!(msg.contains("truncated"), "the refusal must say why: {msg}");
    }

    // Layer 5: the identity file is one origin, canonicalized, or nothing.
    #[test]
    fn derivation_origin_file_parses_one_origin_or_nothing() {
        assert_eq!(
            parse_derivation_origin("https://hcv4s-uaaaa-aaabq-qaaba-cai.icp.net\n").as_deref(),
            Some("https://hcv4s-uaaaa-aaabq-qaaba-cai.icp.net")
        );
        // Canonicalized: case-normalized host, default port dropped.
        assert_eq!(
            parse_derivation_origin("HTTPS://Example.COM:443").as_deref(),
            Some("https://example.com")
        );
        // A BOM-prefixed file still reads (deployment tooling adds them).
        assert_eq!(
            parse_derivation_origin("\u{feff}https://example.com\n").as_deref(),
            Some("https://example.com")
        );
        for bad in [
            "",
            "\n\n",
            "http://example.com",           // not https
            "https://user@example.com",     // user-info
            "not a url",                    // unparseable
            "https://a.com\nhttps://b.com", // two origins: don't guess
            // A bare host is NOT accepted here: an SPA catch-all answering this
            // path with one token would otherwise become a bogus cross-origin
            // claim, and the alternative-origins check would then refuse to
            // resolve the app at all rather than defaulting to its own origin.
            "example.com",
            "maintenance",
            "<!doctype html><html><body>app</body></html>",
        ] {
            assert!(
                parse_derivation_origin(bad).is_none(),
                "{bad:?} must not resolve"
            );
        }
    }
}
