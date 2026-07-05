//! ICP skills awareness.
//!
//! Surfaces the official Internet Computer skills published at
//! <https://skills.internetcomputer.org> so an agent knows *how* to author
//! Motoko, build with mops, deploy with the `icp` CLI, manage cycles, etc. —
//! the knowledge that complements the on-chain canister-management tools.
//!
//! The skill catalogue is fetched live from the registry's JSON manifest
//! (`/api/skills.json`) and cached briefly; individual skills are returned from
//! their `SKILL.md` markdown URL on demand. Nothing is bundled, so the agent
//! always sees the current skills (mirroring the registry's own auto-sync
//! philosophy).

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

/// One skill in the `list_ic_skills` MCP output (the catalogue-facing subset of
/// [`SkillEntry`] — the internal fetch `urls` are intentionally omitted).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SkillSummary {
    /// The skill name to pass to get_ic_skill, e.g. "motoko".
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

/// Structured output of `list_ic_skills`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SkillsOutput {
    /// The available IC skills.
    pub skills: Vec<SkillSummary>,
}

/// Structured output of `get_ic_skill`.
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
                "no skill named `{name}` — call list_ic_skills to see the available skills"
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

    /// Render the catalogue grouped by category for the `list_ic_skills` tool.
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
             get_ic_skill(name).\n",
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

    // Live network: the real registry parses into our (subset) structs and the
    // headline skills are present and fetchable. Mirrors discover.rs's live tests.
    #[tokio::test]
    async fn fetches_real_registry_and_a_skill() {
        let catalog = SkillsCatalog::new();
        let skills = catalog.list().await.expect("list skills");
        assert!(
            skills.iter().any(|s| s.name == "motoko"),
            "motoko skill missing from registry"
        );
        assert!(
            skills.iter().any(|s| s.name == "cycles-management"),
            "cycles-management skill missing"
        );
        // Every entry should carry a markdown URL we can fetch.
        let motoko = catalog.get("motoko").await.expect("get motoko skill");
        assert!(!motoko.trim().is_empty(), "motoko SKILL.md was empty");
    }
}
