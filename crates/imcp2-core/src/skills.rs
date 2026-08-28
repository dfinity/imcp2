//! ICP skills awareness.
//!
//! Surfaces the official Internet Computer skills published at
//! <https://skills.internetcomputer.org> so an agent knows *how* to author
//! Motoko, build with mops, deploy with the `icp` CLI, manage cycles, etc. —
//! the knowledge that complements the on-chain canister-management tools.
//!
//! Two surfaces live here. The served `skill://` resources come from
//! [`BUNDLED_SKILLS`]: reviewed, versioned copies of the documents compiled
//! into the binary (`static/skills/`, provenance in its README) — the served
//! endpoint retrieves nothing dynamically, so what a client reads is exactly
//! what was reviewed at build time. The live [`SkillsCatalog`] below (registry
//! manifest at `/api/skills.json`, `SKILL.md` fetched on demand) remains
//! library code backing the unserved [`crate::tools::IcProtocolTools`] skills
//! tools, for embedders that choose to serve them.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

// rmcp re-exports schemars 1.x; the `#[tool]` output-schema machinery requires
// THAT version's `JsonSchema`, so derive the MCP output types against it.
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

const SKILLS_BASE_DEFAULT: &str = "https://skills.internetcomputer.org";
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// The reviewed, versioned skill documents served as `skill://<name>`
/// resources: (name, title, SKILL.md). Compiled in from `static/skills/`
/// (see that directory's README for provenance, the bundle date, and the
/// refresh procedure); updates ship like any other code change, through
/// review and a release.
pub const BUNDLED_SKILLS: &[(&str, &str, &str)] = &[
    ("agent-web-identity", "Agent Web Identity Sign-In", include_str!("../static/skills/agent-web-identity.md")),
    ("caffeine-app", "Caffeine App (build from scratch)", include_str!("../static/skills/caffeine-app.md")),
    ("canister-security", "Canister Security", include_str!("../static/skills/canister-security.md")),
    ("certified-variables", "Certified Variables", include_str!("../static/skills/certified-variables.md")),
    ("cloud-engine-canisters", "Cloud Engine Canisters", include_str!("../static/skills/cloud-engine-canisters.md")),
    ("custom-domains", "Custom Domains", include_str!("../static/skills/custom-domains.md")),
    ("cycles-management", "Cycles Management", include_str!("../static/skills/cycles-management.md")),
    ("deploy-to-cloud-engine", "Deploy to Cloud Engine", include_str!("../static/skills/deploy-to-cloud-engine.md")),
    ("encrypted-maps", "Encrypted Maps", include_str!("../static/skills/encrypted-maps.md")),
    ("evm-rpc", "EVM RPC", include_str!("../static/skills/evm-rpc.md")),
    ("https-outcalls", "HTTPS Outcalls", include_str!("../static/skills/https-outcalls.md")),
    ("ic-dashboard", "IC Dashboard APIs", include_str!("../static/skills/ic-dashboard.md")),
    ("icp-cli", "ICP CLI", include_str!("../static/skills/icp-cli.md")),
    ("internet-identity", "Internet Identity", include_str!("../static/skills/internet-identity.md")),
    ("migrating-motoko-actors", "Motoko Actor Migrations", include_str!("../static/skills/migrating-motoko-actors.md")),
    ("mops-cli", "Mops CLI", include_str!("../static/skills/mops-cli.md")),
    ("multi-canister", "Multi-Canister Architecture", include_str!("../static/skills/multi-canister.md")),
    ("service-discoverability", "Service Discoverability", include_str!("../static/skills/service-discoverability.md")),
    ("stable-memory", "Stable Memory & Upgrades", include_str!("../static/skills/stable-memory.md")),
    ("static-site", "Static Site (Certified Assets)", include_str!("../static/skills/static-site.md")),
    ("troubleshooting-motoko-migrations", "Troubleshooting Motoko Migrations", include_str!("../static/skills/troubleshooting-motoko-migrations.md")),
    ("vetkeys", "vetKeys", include_str!("../static/skills/vetkeys.md")),
    ("writing-motoko", "Writing Motoko", include_str!("../static/skills/writing-motoko.md")),
];

/// The companion documents those skills link to, served as
/// `skill://<name>/references/<file>`: (skill, file name, contents). Several
/// skills carry their detail in sibling files rather than inline — the Motoko
/// API reference, the asset-canister migration notes — so the bundle carries
/// them too and the links in the bundled documents point at these URIs. A
/// bundle whose links led back to the registry would put the retrieval it
/// removes back in the agent's path.
pub const BUNDLED_SKILL_REFERENCES: &[(&str, &str, &str)] = &[
    ("caffeine-app", "frontend-template.md", include_str!("../static/skills/references/caffeine-app/frontend-template.md")),
    ("encrypted-maps", "metadata.md", include_str!("../static/skills/references/encrypted-maps/metadata.md")),
    ("icp-cli", "binding-generation.md", include_str!("../static/skills/references/icp-cli/binding-generation.md")),
    ("icp-cli", "canister-env-vars.md", include_str!("../static/skills/references/icp-cli/canister-env-vars.md")),
    ("icp-cli", "dev-server.md", include_str!("../static/skills/references/icp-cli/dev-server.md")),
    ("icp-cli", "dfx-migration.md", include_str!("../static/skills/references/icp-cli/dfx-migration.md")),
    ("migrating-motoko-actors", "examples.md", include_str!("../static/skills/references/migrating-motoko-actors/examples.md")),
    ("static-site", "legacy-asset-canister.md", include_str!("../static/skills/references/static-site/legacy-asset-canister.md")),
    ("static-site", "migrating-from-asset-canister.md", include_str!("../static/skills/references/static-site/migrating-from-asset-canister.md")),
    ("vetkeys", "bls-signing.md", include_str!("../static/skills/references/vetkeys/bls-signing.md")),
    ("vetkeys", "ibe.md", include_str!("../static/skills/references/vetkeys/ibe.md")),
    ("writing-motoko", "api-reference.md", include_str!("../static/skills/references/writing-motoko/api-reference.md")),
    ("writing-motoko", "control-flow.md", include_str!("../static/skills/references/writing-motoko/control-flow.md")),
    ("writing-motoko", "equality.md", include_str!("../static/skills/references/writing-motoko/equality.md")),
    ("writing-motoko", "examples.md", include_str!("../static/skills/references/writing-motoko/examples.md")),
    ("writing-motoko", "project-setup.md", include_str!("../static/skills/references/writing-motoko/project-setup.md")),
    ("writing-motoko", "reserved-keywords.md", include_str!("../static/skills/references/writing-motoko/reserved-keywords.md")),
    ("writing-motoko", "type-conversions.md", include_str!("../static/skills/references/writing-motoko/type-conversions.md")),
];

/// The bundled `SKILL.md` for `name` (trimmed, ASCII case-insensitive), if
/// any — the lookup behind `skill://<name>` reads.
pub fn bundled_skill(name: &str) -> Option<&'static str> {
    let name = name.trim();
    BUNDLED_SKILLS
        .iter()
        .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, _, md)| *md)
}

/// The bundled document a `skill://` URI addresses, given the part after the
/// scheme: `<name>` for a skill, `<name>/references/<file>` for one of its
/// companions. The one place that mapping is decided, so what `read_resource`
/// serves cannot drift from what `list_resources` advertises.
pub fn bundled_skill_document(path: &str) -> Option<&'static str> {
    match path.split_once("/references/") {
        Some((name, file)) => bundled_skill_reference(name, file),
        None => bundled_skill(path),
    }
}

/// The bundled companion document `file` of skill `name`, if any — the lookup
/// behind `skill://<name>/references/<file>` reads. Both parts are trimmed and
/// matched ASCII case-insensitively, like [`bundled_skill`].
pub fn bundled_skill_reference(name: &str, file: &str) -> Option<&'static str> {
    let (name, file) = (name.trim(), file.trim());
    BUNDLED_SKILL_REFERENCES
        .iter()
        .find(|(n, f, _)| n.eq_ignore_ascii_case(name) && f.eq_ignore_ascii_case(file))
        .map(|(_, _, md)| *md)
}

/// Registry origin (no trailing slash). Override with `SKILLS_URL`.
fn skills_base() -> String {
    resolve_skills_base(std::env::var("SKILLS_URL").ok())
}

/// Pure resolver for the registry origin (split out so it's testable without
/// mutating the process-global `SKILLS_URL`). A set-but-blank value falls back
/// to the default; trailing slashes are trimmed.
fn resolve_skills_base(configured: Option<String>) -> String {
    configured
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| SKILLS_BASE_DEFAULT.to_string())
}

/// The URL to fetch a skill's `SKILL.md` from. The manifest's `urls.markdown` is
/// honoured ONLY when it stays on the configured registry (same host, and an
/// https — or base-scheme — URL); otherwise we fall back to the conventional
/// `{base}/.well-known/skills/<name>/SKILL.md`. This keeps a compromised or
/// MITM'd manifest from turning the fetch into an SSRF primitive (e.g. cloud
/// metadata IPs) and preserves the expectation that skills come from the
/// configured origin.
fn markdown_url(name: &str, candidate: &str) -> String {
    markdown_url_for_base(&skills_base(), name, candidate)
}

/// Pure core of [`markdown_url`] (base passed in, so it's testable without env).
fn markdown_url_for_base(base: &str, name: &str, candidate: &str) -> String {
    let fallback = format!("{base}/.well-known/skills/{name}/SKILL.md");
    let Ok(base_url) = url::Url::parse(base) else {
        return fallback;
    };
    match url::Url::parse(candidate) {
        Ok(u)
            if u.host_str().is_some()
                && u.host_str() == base_url.host_str()
                && (u.scheme() == "https" || u.scheme() == base_url.scheme()) =>
        {
            candidate.to_string()
        }
        _ => fallback,
    }
}

/// One entry from the skills manifest. Optional fields default so a manifest
/// that grows new keys can't break parsing.
#[derive(Deserialize, Clone)]
pub struct SkillEntry {
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub urls: SkillUrls,
}

#[derive(Deserialize, Clone, Default)]
pub struct SkillUrls {
    #[serde(default)]
    pub markdown: String,
}

/// Arguments for `icp_get_skill`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSkillArgs {
    /// Skill name, e.g. "writing-motoko", "icp-cli", "cycles-management".
    pub name: String,
}

/// One skill in the `icp_list_skills` MCP output (the catalogue-facing subset of
/// [`SkillEntry`] — the internal fetch `urls` are intentionally omitted).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SkillSummary {
    /// The skill name to pass to icp_get_skill, e.g. "writing-motoko".
    pub name: String,
    /// The skill's human title.
    pub title: String,
    /// The category it's grouped under.
    pub category: String,
    /// A one-line description.
    pub description: String,
}

impl From<&SkillEntry> for SkillSummary {
    fn from(e: &SkillEntry) -> Self {
        Self {
            name: e.name.clone(),
            title: e.title.clone(),
            category: e.category.clone(),
            description: e.description.clone(),
        }
    }
}

/// Structured output of `icp_list_skills`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SkillsOutput {
    /// The available IC skills.
    pub skills: Vec<SkillSummary>,
}

impl From<Vec<SkillEntry>> for SkillsOutput {
    fn from(entries: Vec<SkillEntry>) -> Self {
        Self {
            skills: entries.iter().map(SkillSummary::from).collect(),
        }
    }
}

/// Structured output of `icp_get_skill`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SkillOutput {
    /// The skill name.
    pub name: String,
    /// The full SKILL.md instructions (markdown).
    pub content: String,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    skills: Vec<SkillEntry>,
}

struct Cached {
    skills: Vec<SkillEntry>,
    fetched_at: Instant,
}

/// Cache-backed access to the IC skills registry.
#[derive(Clone, Default)]
pub struct SkillsCatalog {
    cache: Arc<RwLock<Option<Cached>>>,
}

impl SkillsCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// The skill catalogue, served from cache when fresh, else fetched.
    pub async fn list(&self) -> Result<Vec<SkillEntry>, String> {
        if let Some(c) = self.cache.read().await.as_ref() {
            if c.fetched_at.elapsed() < CACHE_TTL {
                return Ok(c.skills.clone());
            }
        }
        let url = format!("{}/api/skills.json", skills_base());
        let client = crate::discover::http_client()?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("could not reach the skills registry: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "skills registry returned HTTP {}",
                resp.status().as_u16()
            ));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| format!("reading skills registry: {e}"))?;
        let manifest: Manifest =
            serde_json::from_str(&text).map_err(|e| format!("could not parse skills manifest: {e}"))?;
        let skills = manifest.skills;
        *self.cache.write().await = Some(Cached {
            skills: skills.clone(),
            fetched_at: Instant::now(),
        });
        Ok(skills)
    }

    /// The full `SKILL.md` text of one skill, by name.
    pub async fn get(&self, name: &str) -> Result<String, String> {
        let name = name.trim();
        let skills = self.list().await?;
        let entry = skills.iter().find(|s| s.name.eq_ignore_ascii_case(name));
        if entry.is_none() {
            return Err(format!(
                "no skill named `{name}` — list the `skill://` resources to see the available skills"
            ));
        }
        // Use the manifest's markdown URL only when it stays on the configured
        // registry; otherwise fall back to the conventional path (see markdown_url).
        let url = markdown_url(name, entry.map(|e| e.urls.markdown.as_str()).unwrap_or(""));
        let client = crate::discover::http_client()?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("could not fetch skill `{name}`: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "fetching skill `{name}` returned HTTP {}",
                resp.status().as_u16()
            ));
        }
        resp.text()
            .await
            .map_err(|e| format!("reading skill `{name}`: {e}"))
    }

    /// Render the catalogue grouped by category for the `icp_list_skills` tool.
    pub fn format_list(skills: &[SkillEntry]) -> String {
        use std::collections::BTreeMap;
        let mut by_cat: BTreeMap<&str, Vec<&SkillEntry>> = BTreeMap::new();
        for s in skills {
            let cat = if s.category.trim().is_empty() {
                "Other"
            } else {
                s.category.as_str()
            };
            by_cat.entry(cat).or_default().push(s);
        }
        let mut out = String::from(
            "Internet Computer skills — authoritative how-to guides. Load one with \
             icp_get_skill(name).\n",
        );
        for (cat, mut items) in by_cat {
            items.sort_by(|a, b| a.name.cmp(&b.name));
            out.push_str(&format!("\n{cat}:\n"));
            for s in items {
                out.push_str(&format!("- {} — {}: {}\n", s.name, s.title, s.description));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The served bundle stays well-formed: names unique and lookup-friendly,
    // every document non-empty, and the two skills the financial refusal
    // message points at (skill://icp-cli, skill://cycles-management) present.
    #[test]
    fn bundled_skills_are_well_formed() {
        let mut names: Vec<&str> = BUNDLED_SKILLS.iter().map(|(n, _, _)| *n).collect();
        for (name, title, md) in BUNDLED_SKILLS {
            assert!(!name.is_empty() && *name == name.trim() && !title.is_empty(), "{name}");
            assert!(!md.trim().is_empty(), "{name} must carry its document");
            assert_eq!(bundled_skill(name), Some(*md), "{name} must be readable");
        }
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "bundled skill names must be unique");
        for referenced in ["icp-cli", "cycles-management"] {
            assert!(bundled_skill(referenced).is_some(), "{referenced} is referenced by the financial refusal");
        }
        assert!(bundled_skill("no-such-skill").is_none());
        assert_eq!(bundled_skill(" ICP-CLI "), bundled_skill("icp-cli"));
    }

    // The bundle is closed under its own links: every `skill://` link inside a
    // bundled document resolves to another bundled document. A link that led
    // back to the registry would put the retrieval this bundle removes right
    // back in the agent's path, and a link to a companion nobody bundled would
    // be a dead end the client can't follow.
    #[test]
    fn bundled_documents_link_only_within_the_bundle() {
        for (skill, file, md) in BUNDLED_SKILL_REFERENCES {
            assert!(!skill.is_empty() && !file.is_empty() && !md.trim().is_empty(), "{skill}/{file}");
            assert_eq!(bundled_skill_reference(skill, file), Some(*md), "{skill}/{file} must be readable");
            assert!(
                bundled_skill(skill).is_some(),
                "{skill}/{file} belongs to a skill that is not bundled"
            );
        }
        // Every URI `list_resources` advertises — built here exactly as it
        // builds them — must resolve through the same lookup `read_resource`
        // uses, so nothing is listed that cannot be read.
        let documents: Vec<(String, &str)> = BUNDLED_SKILLS
            .iter()
            .map(|(n, _, md)| (n.to_string(), *md))
            .chain(
                BUNDLED_SKILL_REFERENCES
                    .iter()
                    .map(|(s, f, md)| (format!("{s}/references/{f}"), *md)),
            )
            .collect();
        for (uri_path, md) in &documents {
            assert_eq!(
                bundled_skill_document(uri_path),
                Some(*md),
                "the listed resource skill://{uri_path} must be readable"
            );
        }
        for (where_, md) in documents {
            // No document may send the reader to the live registry...
            assert!(
                !md.contains("skills.internetcomputer.org"),
                "{where_} points at the live registry"
            );
            // ...and every skill:// link it does carry must be served.
            for link in md.match_indices("skill://").map(|(i, _)| {
                md[i + "skill://".len()..]
                    .split(|c: char| {
                        c.is_whitespace() || matches!(c, ')' | '(' | ']' | '[' | '`' | '>' | ',' | '"')
                    })
                    .next()
                    .unwrap_or_default()
            }) {
                let target = link.trim_end_matches(['.', ';', ':']);
                let found = match target.split_once("/references/") {
                    Some((s, f)) => bundled_skill_reference(s, f).is_some(),
                    None => bundled_skill(target).is_some(),
                };
                assert!(found, "{where_} links to `skill://{target}`, which is not bundled");
            }
            // ...and no document may name a companion by bare relative path,
            // which a client has no way to open. A path preceded by `/` is
            // already inside a URI — this scheme's, or an ordinary docs link —
            // so only the bare mentions are flagged. Markdown-link syntax is
            // not the only form these take, which is how the first pass missed
            // nine of them.
            for (i, _) in md.match_indices("references/") {
                assert!(
                    md[..i].ends_with('/'),
                    "{where_} names a companion by bare path: {:?}",
                    &md[i..md.len().min(i + 60)]
                );
            }
        }
    }

    #[test]
    fn parses_manifest_and_groups_by_category() {
        let json = r#"{
          "count": 2,
          "skills": [
            {"name":"motoko","title":"Motoko Language","category":"Motoko",
             "description":"Motoko syntax and patterns.",
             "urls":{"markdown":"https://x/.well-known/skills/motoko/SKILL.md","html":"https://x/skills/motoko/"}},
            {"name":"icp-cli","title":"ICP CLI","category":"Infrastructure",
             "description":"Build and deploy with the icp CLI.",
             "urls":{"markdown":"https://x/.well-known/skills/icp-cli/SKILL.md"},
             "compatibility":null,"updated":"2026-06-17T20:26:42.000Z","license":"Apache-2.0"}
          ]
        }"#;
        let manifest: Manifest = serde_json::from_str(json).expect("parse");
        assert_eq!(manifest.skills.len(), 2);
        let rendered = SkillsCatalog::format_list(&manifest.skills);
        assert!(rendered.contains("Motoko:"), "{rendered}");
        assert!(rendered.contains("Infrastructure:"), "{rendered}");
        assert!(rendered.contains("- motoko — Motoko Language:"), "{rendered}");
        assert!(rendered.contains("- icp-cli — ICP CLI:"), "{rendered}");
    }

    // Pure resolver — no process-global env mutation, so it can't race other tests.
    #[test]
    fn resolve_skills_base_default_and_override() {
        let default = "https://skills.internetcomputer.org";
        assert_eq!(resolve_skills_base(None), default);
        assert_eq!(resolve_skills_base(Some(String::new())), default);
        assert_eq!(resolve_skills_base(Some("   ".into())), default);
        assert_eq!(
            resolve_skills_base(Some("https://x.example/".into())),
            "https://x.example"
        );
    }

    // markdown_url_for_base honours same-origin https URLs and falls back
    // otherwise, so a tampered manifest can't redirect the fetch off the
    // configured registry. Pure (base passed in) → no env mutation.
    #[test]
    fn markdown_url_only_trusts_same_origin() {
        let base = "https://skills.internetcomputer.org";
        let fallback = "https://skills.internetcomputer.org/.well-known/skills/motoko/SKILL.md";

        // Same host + https → trusted as-is.
        let good = "https://skills.internetcomputer.org/.well-known/skills/motoko/SKILL.md";
        assert_eq!(markdown_url_for_base(base, "motoko", good), good);
        // Different host → fall back to the configured origin (no SSRF).
        assert_eq!(markdown_url_for_base(base, "motoko", "https://evil.example/x"), fallback);
        // Internal/metadata IP → fall back.
        assert_eq!(
            markdown_url_for_base(base, "motoko", "http://169.254.169.254/latest/meta-data"),
            fallback
        );
        // Non-web scheme → fall back.
        assert_eq!(markdown_url_for_base(base, "motoko", "file:///etc/passwd"), fallback);
        // Empty (no manifest URL) → fall back.
        assert_eq!(markdown_url_for_base(base, "motoko", ""), fallback);
        // A local http override accepts same-host http (base scheme) URLs.
        assert_eq!(
            markdown_url_for_base("http://localhost:8080", "motoko", "http://localhost:8080/x.md"),
            "http://localhost:8080/x.md"
        );
    }

    // Live network: the real registry parses into our (subset) structs, is
    // non-empty, and a known skill is fetchable. Mirrors discover.rs's live tests.
    #[tokio::test]
    async fn fetches_real_registry_and_a_skill() {
        let catalog = SkillsCatalog::new();
        let skills = catalog.list().await.expect("list skills");

        // The registry parses and is non-empty. Deliberately do NOT pin a single
        // skill name: the registry reorganizes its catalog over time (e.g.
        // `motoko` was split into `writing-motoko` / `migrating-motoko-actors`),
        // so a hard-coded name is a standing false-failure. Instead require that
        // at least one CORE skill is present — resilient to any single rename.
        assert!(!skills.is_empty(), "the registry returned no skills");
        let core = ["internet-identity", "icp-cli", "cycles-management"];
        let present = skills.iter().find(|s| core.contains(&s.name.as_str())).unwrap_or_else(|| {
            let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
            panic!("none of the core skills {core:?} are in the registry; got {names:?}")
        });

        // Every entry carries a markdown URL we can fetch; the SKILL.md is non-empty.
        let md = catalog.get(&present.name).await.expect("get a core skill's markdown");
        assert!(!md.trim().is_empty(), "{}'s SKILL.md was empty", present.name);
    }
}
