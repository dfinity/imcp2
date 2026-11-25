//! ICP skills awareness.
//!
//! Surfaces the official Internet Computer skills published at
//! <https://skills.internetcomputer.org> so an agent knows *how* to author
//! Motoko, build with mops, deploy with the `icp` CLI, manage cycles, etc.
//!
//! The served `skill://` resources come from [`BUNDLED_SKILLS`]: reviewed,
//! versioned copies of the documents compiled into the binary
//! (`static/skills/`, provenance in its README) — the served endpoint
//! retrieves nothing dynamically, so what a client reads is exactly what was
//! reviewed at build time.

/// The reviewed, versioned skill documents served as `skill://<name>`
/// resources: (name, title, SKILL.md). Compiled in from `static/skills/`
/// (see that directory's README for provenance, the bundle date, and the
/// refresh procedure); updates ship like any other code change, through
/// review and a release.
pub const BUNDLED_SKILLS: &[(&str, &str, &str)] = &[
    (
        "agent-web-identity",
        "Agent Web Identity Sign-In",
        include_str!("../static/skills/agent-web-identity.md"),
    ),
    (
        "caffeine-app",
        "Caffeine App (build from scratch)",
        include_str!("../static/skills/caffeine-app.md"),
    ),
    (
        "canister-security",
        "Canister Security",
        include_str!("../static/skills/canister-security.md"),
    ),
    (
        "certified-variables",
        "Certified Variables",
        include_str!("../static/skills/certified-variables.md"),
    ),
    (
        "cloud-engine-canisters",
        "Cloud Engine Canisters",
        include_str!("../static/skills/cloud-engine-canisters.md"),
    ),
    ("custom-domains", "Custom Domains", include_str!("../static/skills/custom-domains.md")),
    (
        "cycles-management",
        "Cycles Management",
        include_str!("../static/skills/cycles-management.md"),
    ),
    (
        "deploy-to-cloud-engine",
        "Deploy to Cloud Engine",
        include_str!("../static/skills/deploy-to-cloud-engine.md"),
    ),
    ("encrypted-maps", "Encrypted Maps", include_str!("../static/skills/encrypted-maps.md")),
    ("evm-rpc", "EVM RPC", include_str!("../static/skills/evm-rpc.md")),
    ("https-outcalls", "HTTPS Outcalls", include_str!("../static/skills/https-outcalls.md")),
    ("ic-dashboard", "IC Dashboard APIs", include_str!("../static/skills/ic-dashboard.md")),
    ("icp-cli", "ICP CLI", include_str!("../static/skills/icp-cli.md")),
    (
        "internet-identity",
        "Internet Identity",
        include_str!("../static/skills/internet-identity.md"),
    ),
    (
        "migrating-motoko-actors",
        "Motoko Actor Migrations",
        include_str!("../static/skills/migrating-motoko-actors.md"),
    ),
    ("mops-cli", "Mops CLI", include_str!("../static/skills/mops-cli.md")),
    (
        "multi-canister",
        "Multi-Canister Architecture",
        include_str!("../static/skills/multi-canister.md"),
    ),
    (
        "service-discoverability",
        "Service Discoverability",
        include_str!("../static/skills/service-discoverability.md"),
    ),
    (
        "stable-memory",
        "Stable Memory & Upgrades",
        include_str!("../static/skills/stable-memory.md"),
    ),
    (
        "static-site",
        "Static Site (Certified Assets)",
        include_str!("../static/skills/static-site.md"),
    ),
    (
        "troubleshooting-motoko-migrations",
        "Troubleshooting Motoko Migrations",
        include_str!("../static/skills/troubleshooting-motoko-migrations.md"),
    ),
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
    (
        "caffeine-app",
        "frontend-template.md",
        include_str!("../static/skills/references/caffeine-app/frontend-template.md"),
    ),
    (
        "encrypted-maps",
        "metadata.md",
        include_str!("../static/skills/references/encrypted-maps/metadata.md"),
    ),
    (
        "icp-cli",
        "binding-generation.md",
        include_str!("../static/skills/references/icp-cli/binding-generation.md"),
    ),
    (
        "icp-cli",
        "canister-env-vars.md",
        include_str!("../static/skills/references/icp-cli/canister-env-vars.md"),
    ),
    ("icp-cli", "dev-server.md", include_str!("../static/skills/references/icp-cli/dev-server.md")),
    (
        "icp-cli",
        "dfx-migration.md",
        include_str!("../static/skills/references/icp-cli/dfx-migration.md"),
    ),
    (
        "migrating-motoko-actors",
        "examples.md",
        include_str!("../static/skills/references/migrating-motoko-actors/examples.md"),
    ),
    (
        "static-site",
        "legacy-asset-canister.md",
        include_str!("../static/skills/references/static-site/legacy-asset-canister.md"),
    ),
    (
        "static-site",
        "migrating-from-asset-canister.md",
        include_str!("../static/skills/references/static-site/migrating-from-asset-canister.md"),
    ),
    (
        "vetkeys",
        "bls-signing.md",
        include_str!("../static/skills/references/vetkeys/bls-signing.md"),
    ),
    ("vetkeys", "ibe.md", include_str!("../static/skills/references/vetkeys/ibe.md")),
    (
        "writing-motoko",
        "api-reference.md",
        include_str!("../static/skills/references/writing-motoko/api-reference.md"),
    ),
    (
        "writing-motoko",
        "control-flow.md",
        include_str!("../static/skills/references/writing-motoko/control-flow.md"),
    ),
    (
        "writing-motoko",
        "equality.md",
        include_str!("../static/skills/references/writing-motoko/equality.md"),
    ),
    (
        "writing-motoko",
        "examples.md",
        include_str!("../static/skills/references/writing-motoko/examples.md"),
    ),
    (
        "writing-motoko",
        "project-setup.md",
        include_str!("../static/skills/references/writing-motoko/project-setup.md"),
    ),
    (
        "writing-motoko",
        "reserved-keywords.md",
        include_str!("../static/skills/references/writing-motoko/reserved-keywords.md"),
    ),
    (
        "writing-motoko",
        "type-conversions.md",
        include_str!("../static/skills/references/writing-motoko/type-conversions.md"),
    ),
];

/// The bundled `SKILL.md` for `name` (trimmed, ASCII case-insensitive), if
/// any — the lookup behind `skill://<name>` reads.
pub fn bundled_skill(name: &str) -> Option<&'static str> {
    let name = name.trim();
    BUNDLED_SKILLS.iter().find(|(n, _, _)| n.eq_ignore_ascii_case(name)).map(|(_, _, md)| *md)
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
            assert!(
                bundled_skill(referenced).is_some(),
                "{referenced} is referenced by the financial refusal"
            );
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
            assert!(
                !skill.is_empty() && !file.is_empty() && !md.trim().is_empty(),
                "{skill}/{file}"
            );
            assert_eq!(
                bundled_skill_reference(skill, file),
                Some(*md),
                "{skill}/{file} must be readable"
            );
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
                        c.is_whitespace()
                            || matches!(c, ')' | '(' | ']' | '[' | '`' | '>' | ',' | '"')
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
            // The same holds for a markdown link straight at a sibling file,
            // which carries no `references/` segment to catch it by: inside a
            // companion, `](migrating-from-asset-canister.md)` addresses a
            // document the client cannot open either. Every markdown target
            // ending in `.md` must be an absolute URI.
            for (i, _) in md.match_indices("](") {
                let target = md[i + 2..].split(')').next().unwrap_or_default();
                if !target.ends_with(".md") {
                    continue;
                }
                assert!(
                    target.contains("://"),
                    "{where_} links to the bare relative target `{target}`"
                );
            }
        }
    }
}
