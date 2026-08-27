//! `imcp2-local setup` — register this binary with the AI tools installed on
//! this machine, so the user never opens a JSON/TOML file (the design's
//! end-user-setup bar). It detects each supported client, says what it will
//! write, and writes that client's own MCP registration format:
//!
//!   * Claude Desktop — `claude_desktop_config.json` → `mcpServers.imcp2`
//!   * Cursor — `~/.cursor/mcp.json` → `mcpServers.imcp2`
//!   * Antigravity — `~/.gemini/config/mcp_config.json` → `mcpServers.imcp2`
//!   * Codex — `~/.codex/config.toml` → `[mcp_servers.imcp2]`, edited in
//!     place rather than via `codex mcp add` (works without `codex` on
//!     `PATH` or a recent CLI — see the Codex section below)
//!   * Claude Code — via its own CLI (`claude mcp add --scope user …`), which
//!     owns that config's format
//!   * Perplexity (macOS) — has no writable config file; its UI-driven steps
//!     are printed instead
//!
//! `setup --remove` deletes those `imcp2` registrations — by name, whatever
//! they hold by then, with the one-time backup keeping the pre-imcp2 state;
//! `setup --print` only
//! shows the per-client instructions (nothing is written). The first time an
//! existing config file is modified, a one-time backup is kept next to it as
//! `<file>.imcp2-bak`.
//!
//! This is a plain CLI subcommand: it runs and exits before the MCP server
//! starts, so printing to stdout here is fine (stdout is only reserved for
//! JSON-RPC while *serving*).

use std::path::{Path, PathBuf};

use anyhow::Context;

/// The server name registered in every client, matching the design's
/// registration snippets.
const SERVER_NAME: &str = "imcp2";

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut mode = Mode::Apply;
    for a in args {
        match a.as_str() {
            "--remove" => mode = Mode::Remove,
            "--print" => mode = Mode::Print,
            other => anyhow::bail!(
                "unknown setup flag {other:?} — usage: imcp2-local setup [--remove | --print]"
            ),
        }
    }
    let env = Env::from_system()?;
    let (report, failed) = run_in(&env, mode);
    println!("{report}");
    if failed > 0 {
        anyhow::bail!("{failed} client registration(s) failed — see the report above");
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Detect clients and write their registrations.
    Apply,
    /// Detect clients and remove the registrations `Apply` wrote.
    Remove,
    /// Only print what would be done, plus manual steps for every client.
    Print,
}

/// Everything `setup` reads from the machine, injected so the tests can point
/// it at a scratch directory instead of the real home.
struct Env {
    /// The user's home directory (`~`).
    home: PathBuf,
    /// The OS config base: `~/Library/Application Support` on macOS,
    /// `%APPDATA%` on Windows, `~/.config` elsewhere — where Claude Desktop
    /// keeps its config.
    config_dir: PathBuf,
    /// The absolute path registered as the server `command`.
    exe: PathBuf,
    /// `claude` (Claude Code's CLI) on `PATH`, if present.
    claude_cli: Option<PathBuf>,
    /// Where macOS applications live, for detecting the Perplexity app.
    applications_dir: PathBuf,
}

impl Env {
    fn from_system() -> anyhow::Result<Self> {
        let exe = std::env::current_exe().context("resolve this binary's path")?;
        // Canonical, so client configs point at the real file even when setup
        // ran through a symlink; fall back to the raw path if e.g. a network
        // mount refuses canonicalization.
        let exe = exe.canonicalize().unwrap_or(exe);
        Ok(Self {
            home: dirs::home_dir().context("no home directory")?,
            config_dir: dirs::config_dir().context("no OS config directory")?,
            exe,
            claude_cli: find_on_path("claude"),
            applications_dir: PathBuf::from("/Applications"),
        })
    }
}

/// A minimal `which`: the first existing file named `name` (with the usual
/// Windows extensions) in `PATH`.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        if cfg!(windows) {
            for ext in ["exe", "cmd", "bat"] {
                let candidate = dir.join(format!("{name}.{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Run one mode over every supported client and render the report the user
/// reads, plus how many clients FAILED (detected and attempted, but not
/// done), so `run` can exit nonzero where a script would otherwise read
/// partial failure as success. Pure with respect to `Env`, so the tests
/// drive it end to end against a scratch home.
fn run_in(env: &Env, mode: Mode) -> (String, usize) {
    let mut lines: Vec<String> = Vec::new();
    let mut failed = 0usize;
    let verb = match mode {
        Mode::Apply => "Registering",
        Mode::Remove => "Removing",
        Mode::Print => "Setup steps for",
    };
    lines.push(format!(
        "{verb} the imcp2 local MCP server (binary: {}).\n",
        env.exe.display()
    ));

    for client in clients(env) {
        let line = match mode {
            Mode::Print => format!(
                "• {}\n  {}",
                client.name,
                client.manual.replace('\n', "\n  ")
            ),
            Mode::Apply | Mode::Remove => match &client.target {
                Target::NotDetected(reason) => {
                    format!("• {}: not detected ({reason}) — skipped.", client.name)
                }
                Target::Json(file) => {
                    let result = if mode == Mode::Apply {
                        upsert_json_server(file, &env.exe)
                    } else {
                        remove_json_server(file)
                    };
                    if result.is_err() {
                        failed += 1;
                    }
                    render(client.name, file, result)
                }
                Target::CodexToml(file) => {
                    let result = if mode == Mode::Apply {
                        upsert_codex_server(file, &env.exe)
                    } else {
                        remove_codex_server(file)
                    };
                    if result.is_err() {
                        failed += 1;
                    }
                    render(client.name, file, result)
                }
                Target::ClaudeCli(cli) => {
                    let args: &[&str] = if mode == Mode::Apply {
                        &[
                            "mcp",
                            "add",
                            "--scope",
                            "user",
                            "--transport",
                            "stdio",
                            SERVER_NAME,
                            "--",
                        ]
                    } else {
                        &["mcp", "remove", "--scope", "user", SERVER_NAME]
                    };
                    let mut cmd = std::process::Command::new(cli);
                    cmd.args(args);
                    if mode == Mode::Apply {
                        cmd.arg(&env.exe);
                    }
                    // The fallback one-liner must match the mode: telling a
                    // removing user to re-add the server would invert the ask.
                    let fallback = match mode {
                        Mode::Remove => format!("claude mcp remove --scope user {SERVER_NAME}"),
                        _ => client.manual.lines().next().unwrap_or_default().to_string(),
                    };
                    match cmd.output() {
                        Ok(out) if out.status.success() => {
                            format!("• {}: done (via `claude mcp`, user scope).", client.name)
                        }
                        Ok(out) => {
                            // On removal, only a recognizably-absent
                            // registration is benign; any other refusal
                            // (permissions, corrupt config) must count.
                            let msg = format!(
                                "{}{}",
                                String::from_utf8_lossy(&out.stdout),
                                String::from_utf8_lossy(&out.stderr)
                            )
                            .to_lowercase();
                            let absent = mode == Mode::Remove
                                && (msg.contains("not found") || msg.contains("no mcp server"));
                            if !absent {
                                failed += 1;
                            }
                            format!(
                                "• {}: `claude mcp` refused ({}). Run it yourself:\n  {fallback}",
                                client.name,
                                String::from_utf8_lossy(&out.stderr).trim(),
                            )
                        }
                        Err(e) => {
                            failed += 1;
                            format!(
                                "• {}: could not run `claude` ({e}). Run it yourself:\n  {fallback}",
                                client.name,
                            )
                        }
                    }
                }
                Target::Manual => match mode {
                    Mode::Remove => format!(
                        "• {}: has no config file this tool can write — remove the \
                         {SERVER_NAME} connector in the app (Settings → Connectors).",
                        client.name
                    ),
                    _ => format!(
                        "• {}: has no config file this tool can write — do it in the app:\n  {}",
                        client.name,
                        client.manual.replace('\n', "\n  ")
                    ),
                },
            },
        };
        lines.push(line);
    }

    lines.push(String::new());
    lines.push(match mode {
        Mode::Apply => "Restart each client to pick the server up. On the first tool call that \
                        needs your identity, approve the `authenticate` tool and finish the \
                        sign-in in your browser."
            .to_string(),
        Mode::Remove => "Restart each client to drop the server.".to_string(),
        Mode::Print => {
            "Run `imcp2-local setup` to apply the writable ones automatically.".to_string()
        }
    });
    (lines.join("\n"), failed)
}

/// Where (and whether) one client's registration lives on this machine.
enum Target {
    /// A `mcpServers` JSON file to edit.
    Json(PathBuf),
    /// Codex's `config.toml` (`[mcp_servers.<name>]`).
    CodexToml(PathBuf),
    /// Claude Code: registered through its own CLI.
    ClaudeCli(PathBuf),
    /// Detected, but only registrable through the app's UI (Perplexity).
    Manual,
    /// Not installed here (the reason names what was looked for).
    NotDetected(String),
}

struct Client {
    name: &'static str,
    target: Target,
    /// The manual steps / one-liner for `--print` and failure fallbacks.
    manual: String,
}

/// The supported clients, in the design's component-9 order, resolved against
/// this machine.
fn clients(env: &Env) -> Vec<Client> {
    // The pasted snippets embed the path as a *literal* of each target
    // format, so it gets that format's own escaping (Windows `\` in
    // JSON/TOML, spaces in the shell one-liner) — a raw `display()` would
    // hand the user an invalid file.
    let exe_str = env.exe.display().to_string();
    let exe_json = serde_json::Value::from(exe_str.as_str()).to_string();
    let exe_toml = toml_edit::Value::from(exe_str.as_str()).to_string();
    // Always single-quote: literal in POSIX shells and PowerShell alike, so
    // `$`, backticks, and spaces in the path never expand or split. (Double
    // quotes would interpolate `$USER` in both.)
    let exe_sh = if cfg!(windows) {
        format!("'{}'", exe_str.replace('\'', "''"))
    } else {
        format!("'{}'", exe_str.replace('\'', r"'\''"))
    };
    let json_snippet =
        format!("{{ \"mcpServers\": {{ \"{SERVER_NAME}\": {{ \"command\": {exe_json} }} }} }}");

    let detect_dir = |dir: PathBuf, target_file: PathBuf, label: &str| {
        if dir.is_dir() {
            Target::Json(target_file)
        } else {
            Target::NotDetected(format!("{label} missing"))
        }
    };

    let claude_dir = env.config_dir.join("Claude");
    let cursor_dir = env.home.join(".cursor");
    let gemini_dir = env.home.join(".gemini");
    let codex_dir = env.home.join(".codex");

    vec![
        Client {
            name: "Claude Desktop",
            target: detect_dir(
                claude_dir.clone(),
                claude_dir.join("claude_desktop_config.json"),
                "its config directory is",
            ),
            manual: format!(
                "Merge into claude_desktop_config.json (Settings → Developer → Edit Config):\n{json_snippet}\n(Or install the imcp2 .mcpb bundle by double-clicking it, once released.)"
            ),
        },
        Client {
            name: "Claude Code",
            target: match &env.claude_cli {
                Some(cli) => Target::ClaudeCli(cli.clone()),
                None => Target::NotDetected("`claude` is not on PATH".into()),
            },
            manual: format!(
                "claude mcp add --scope user --transport stdio {SERVER_NAME} -- {exe_sh}"
            ),
        },
        Client {
            name: "Codex",
            target: if codex_dir.is_dir() {
                Target::CodexToml(codex_dir.join("config.toml"))
            } else {
                Target::NotDetected("~/.codex is missing".into())
            },
            manual: format!(
                "Add to ~/.codex/config.toml:\n[mcp_servers.{SERVER_NAME}]\ncommand = {exe_toml}"
            ),
        },
        Client {
            name: "Cursor",
            target: detect_dir(
                cursor_dir.clone(),
                cursor_dir.join("mcp.json"),
                "~/.cursor is",
            ),
            manual: format!("Merge into ~/.cursor/mcp.json:\n{json_snippet}"),
        },
        Client {
            name: "Antigravity",
            target: detect_dir(
                gemini_dir.clone(),
                gemini_dir.join("config").join("mcp_config.json"),
                "~/.gemini is",
            ),
            manual: format!("Merge into ~/.gemini/config/mcp_config.json:\n{json_snippet}"),
        },
        Client {
            name: "Perplexity (macOS)",
            target: if env.applications_dir.join("Perplexity.app").exists() {
                Target::Manual
            } else {
                Target::NotDetected("Perplexity.app is not in /Applications".into())
            },
            manual: format!(
                "Settings → Connectors → Add Connector → Advanced, then paste:\n{{ \"command\": {exe_json}, \"args\": [], \"env\": {{}} }}\n(Needs Perplexity's local-MCP helper; the app prompts to install it once.)"
            ),
        },
    ]
}

fn render(name: &str, file: &Path, result: anyhow::Result<String>) -> String {
    match result {
        Ok(summary) => format!("• {name}: {summary} ({})", file.display()),
        Err(e) => format!("• {name}: FAILED — {e:#} ({})", file.display()),
    }
}

/// Keep a one-time backup next to a config file about to be modified. Only
/// the FIRST setup run makes one, so the backup always holds the pre-imcp2
/// state rather than being rotated away by a later run.
fn backup_once(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let backup = path.with_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.imcp2-bak"),
        None => "imcp2-bak".to_string(),
    });
    if backup.exists() {
        return Ok(Some(backup));
    }
    std::fs::copy(path, &backup).with_context(|| format!("back up {}", path.display()))?;
    Ok(Some(backup))
}

// ---- mcpServers JSON files (Claude Desktop, Cursor, Antigravity) -----------

fn upsert_json_server(path: &Path, exe: &Path) -> anyhow::Result<String> {
    let mut root: serde_json::Value = if path.exists() {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        if text.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "{} is not valid JSON — fix or remove it, then rerun",
                    path.display()
                )
            })?
        }
    } else {
        serde_json::json!({})
    };
    let obj = root
        .as_object_mut()
        .with_context(|| format!("{} top level is not a JSON object", path.display()))?;
    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .with_context(|| format!("`mcpServers` in {} is not an object", path.display()))?;
    // Merge, don't replace: `command` is the only key setup owns, so a
    // user's additions to the entry (say `env` for a local replica) survive
    // re-runs and upgrades. A non-object under the name is replaced.
    match servers.get_mut(SERVER_NAME) {
        Some(serde_json::Value::Object(entry)) => {
            entry.insert(
                "command".to_string(),
                serde_json::Value::from(exe.to_string_lossy().as_ref()),
            );
        }
        _ => {
            servers.insert(
                SERVER_NAME.to_string(),
                serde_json::json!({ "command": exe.to_string_lossy() }),
            );
        }
    }
    let backup = backup_once(path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, format!("{:#}\n", root))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(match backup {
        Some(b) => format!("registered; backup at {}", b.display()),
        None => "registered".to_string(),
    })
}

fn remove_json_server(path: &Path) -> anyhow::Result<String> {
    if !path.exists() {
        return Ok("nothing to remove".to_string());
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut root: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    let removed = root
        .get_mut("mcpServers")
        .and_then(|s| s.as_object_mut())
        .and_then(|s| s.remove(SERVER_NAME))
        .is_some();
    if !removed {
        return Ok("nothing to remove".to_string());
    }
    // A removal is a modification too: the first one still earns the one-time
    // pre-imcp2 backup (e.g. `--remove` before any apply on this machine).
    let backup = backup_once(path)?;
    std::fs::write(path, format!("{:#}\n", root))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(match backup {
        Some(b) => format!("removed; backup at {}", b.display()),
        None => "removed".to_string(),
    })
}

// ---- Codex config.toml ------------------------------------------------------
//
// A direct edit of Codex's documented config file, rather than shelling out
// to `codex mcp add`: detection keyed on the `~/.codex` directory reaches
// installs whose `codex` binary isn't on `PATH` (e.g. IDE-extension use),
// removal here stays cleanly idempotent, and the file format works on Codex
// versions that predate the `codex mcp` subcommand. (`toml_edit` preserves
// the user's comments and formatting — a nicety, not the differentiator.)
// Claude Code gets the opposite treatment because its user-scope config is
// CLI-owned rather than a documented standalone file.

fn upsert_codex_server(path: &Path, exe: &Path) -> anyhow::Result<String> {
    let mut doc: toml_edit::DocumentMut = if path.exists() {
        std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?
            .parse()
            .with_context(|| format!("{} is not valid TOML", path.display()))?
    } else {
        toml_edit::DocumentMut::new()
    };
    // `[mcp_servers]` as an implicit parent so an absent table doesn't render
    // an empty `[mcp_servers]` header; the entry itself is `[mcp_servers.imcp2]`.
    let servers = doc
        .entry("mcp_servers")
        .or_insert(toml_edit::Item::Table({
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            t
        }))
        .as_table_mut()
        .with_context(|| format!("`mcp_servers` in {} is not a table", path.display()))?;
    // Merge, don't replace — same contract as the JSON path: only `command`
    // is owned here, user-added keys in the table survive.
    match servers.get_mut(SERVER_NAME).and_then(|i| i.as_table_mut()) {
        Some(entry) => {
            entry.insert("command", toml_edit::value(exe.to_string_lossy().as_ref()));
        }
        None => {
            let mut entry = toml_edit::Table::new();
            entry.insert("command", toml_edit::value(exe.to_string_lossy().as_ref()));
            servers.insert(SERVER_NAME, toml_edit::Item::Table(entry));
        }
    }
    let backup = backup_once(path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, doc.to_string()).with_context(|| format!("write {}", path.display()))?;
    Ok(match backup {
        Some(b) => format!("registered; backup at {}", b.display()),
        None => "registered".to_string(),
    })
}

fn remove_codex_server(path: &Path) -> anyhow::Result<String> {
    if !path.exists() {
        return Ok("nothing to remove".to_string());
    }
    let mut doc: toml_edit::DocumentMut = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?
        .parse()
        .with_context(|| format!("{} is not valid TOML", path.display()))?;
    let removed = doc
        .get_mut("mcp_servers")
        .and_then(|s| s.as_table_mut())
        .map(|s| s.remove(SERVER_NAME).is_some())
        .unwrap_or(false);
    if !removed {
        return Ok("nothing to remove".to_string());
    }
    // Drop a now-empty `[mcp_servers]` table rather than leaving a bare header.
    if doc
        .get("mcp_servers")
        .and_then(|s| s.as_table())
        .is_some_and(|t| t.is_empty())
    {
        doc.remove("mcp_servers");
    }
    // Same one-time backup contract as the JSON removal above.
    let backup = backup_once(path)?;
    std::fs::write(path, doc.to_string()).with_context(|| format!("write {}", path.display()))?;
    Ok(match backup {
        Some(b) => format!("removed; backup at {}", b.display()),
        None => "removed".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch machine: a temp home with the given client dirs pre-created,
    /// no `claude` CLI, no /Applications.
    fn scratch(dirs_present: &[&str]) -> (tempdir::Guard, Env) {
        let root = tempdir::fresh();
        for d in dirs_present {
            std::fs::create_dir_all(root.path.join(d)).unwrap();
        }
        let env = Env {
            home: root.path.clone(),
            config_dir: root.path.join("config"),
            exe: PathBuf::from("/opt/imcp2/imcp2-local"),
            claude_cli: None,
            applications_dir: root.path.join("Applications"),
        };
        (root, env)
    }

    /// Tiny self-cleaning temp dir (no external crate): unique per test via
    /// name + pid + a counter, removed on drop even across panics.
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        static N: AtomicU64 = AtomicU64::new(0);

        pub struct Guard {
            pub path: PathBuf,
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        pub fn fresh() -> Guard {
            let path = std::env::temp_dir().join(format!(
                "imcp2-setup-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Guard { path }
        }
    }

    // The full apply → remove cycle over every file-based client: registers
    // exactly the design's per-client formats, then removes exactly that
    // entry — leaving everything else in each file intact.
    #[test]
    fn apply_then_remove_round_trips_every_file_based_client() {
        let (root, env) = scratch(&["config/Claude", ".cursor", ".gemini", ".codex"]);

        // Pre-existing content that must survive: another MCP server in
        // Cursor's JSON, comments + another server in Codex's TOML.
        std::fs::write(
            root.path.join(".cursor/mcp.json"),
            r#"{ "mcpServers": { "other": { "command": "/bin/other" }, "imcp2": { "command": "/old/imcp2-local", "env": { "IMCP2_IC_URL": "http://127.0.0.1:4943" } } }, "theme": "dark" }"#,
        )
        .unwrap();
        std::fs::write(
            root.path.join(".codex/config.toml"),
            "# my codex config\nmodel = \"o5\"\n\n[mcp_servers.other]\ncommand = \"/bin/other\"\n",
        )
        .unwrap();

        let (report, failed) = run_in(&env, Mode::Apply);
        assert_eq!(failed, 0, "{report}");
        assert!(report.contains("Claude Desktop: registered"), "{report}");
        assert!(report.contains("Cursor: registered; backup at"), "{report}");
        assert!(report.contains("Antigravity: registered"), "{report}");
        assert!(report.contains("Codex: registered; backup at"), "{report}");
        assert!(report.contains("Claude Code: not detected"), "{report}");
        assert!(
            report.contains("Perplexity (macOS): not detected"),
            "{report}"
        );

        // Claude Desktop / Antigravity: files created with the exact snippet.
        for file in [
            root.path.join("config/Claude/claude_desktop_config.json"),
            root.path.join(".gemini/config/mcp_config.json"),
        ] {
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(
                v["mcpServers"]["imcp2"]["command"], "/opt/imcp2/imcp2-local",
                "{file:?}"
            );
        }
        // Cursor: our entry added, the other server and unrelated keys intact.
        let cursor: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.path.join(".cursor/mcp.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cursor["mcpServers"]["imcp2"]["command"],
            "/opt/imcp2/imcp2-local"
        );
        assert_eq!(
            cursor["mcpServers"]["imcp2"]["env"]["IMCP2_IC_URL"], "http://127.0.0.1:4943",
            "user-added keys survive re-registration"
        );
        assert_eq!(cursor["mcpServers"]["other"]["command"], "/bin/other");
        assert_eq!(cursor["theme"], "dark");
        assert!(
            root.path.join(".cursor/mcp.json.imcp2-bak").exists(),
            "backup kept"
        );
        // Codex: comments and existing entries survive toml_edit.
        let codex = std::fs::read_to_string(root.path.join(".codex/config.toml")).unwrap();
        assert!(codex.contains("# my codex config"), "{codex}");
        assert!(codex.contains("model = \"o5\""), "{codex}");
        assert!(codex.contains("[mcp_servers.other]"), "{codex}");
        assert!(codex.contains("[mcp_servers.imcp2]"), "{codex}");
        assert!(
            codex.contains("command = \"/opt/imcp2/imcp2-local\""),
            "{codex}"
        );

        // Remove: exactly our entry goes; everything else stays.
        let (report, _) = run_in(&env, Mode::Remove);
        assert!(report.contains("Cursor: removed"), "{report}");
        assert!(report.contains("Codex: removed"), "{report}");
        let cursor: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.path.join(".cursor/mcp.json")).unwrap(),
        )
        .unwrap();
        assert!(cursor["mcpServers"].get("imcp2").is_none());
        assert_eq!(cursor["mcpServers"]["other"]["command"], "/bin/other");
        let codex = std::fs::read_to_string(root.path.join(".codex/config.toml")).unwrap();
        assert!(!codex.contains("imcp2"), "{codex}");
        assert!(codex.contains("[mcp_servers.other]"), "{codex}");
        assert!(codex.contains("# my codex config"), "{codex}");

        // A second remove is a clean no-op.
        let (report, _) = run_in(&env, Mode::Remove);
        assert!(report.contains("Cursor: nothing to remove"), "{report}");
    }

    // Undetected clients are skipped with the reason named — setup never
    // creates a client's config tree the client itself hasn't created.
    #[test]
    fn undetected_clients_are_skipped_not_invented() {
        let (root, env) = scratch(&[]);
        let (report, _) = run_in(&env, Mode::Apply);
        for client in [
            "Claude Desktop",
            "Claude Code",
            "Codex",
            "Cursor",
            "Antigravity",
        ] {
            assert!(
                report.contains(&format!("{client}: not detected")),
                "{client} should be skipped:\n{report}"
            );
        }
        assert!(!root.path.join(".cursor").exists());
        assert!(!root.path.join(".codex").exists());
    }

    // --print writes nothing and shows every client's manual path, including
    // the one-liners for Claude Code / Codex and Perplexity's UI steps.
    #[test]
    fn print_mode_only_prints() {
        let (root, env) = scratch(&[".cursor"]);
        let (report, _) = run_in(&env, Mode::Print);
        assert!(
            report.contains("claude mcp add --scope user --transport stdio imcp2"),
            "{report}"
        );
        assert!(report.contains("[mcp_servers.imcp2]"), "{report}");
        assert!(
            report.contains("Settings → Connectors → Add Connector"),
            "{report}"
        );
        assert!(report.contains("mcpServers"), "{report}");
        assert!(
            !root.path.join(".cursor/mcp.json").exists(),
            "--print must not write"
        );
    }

    // A corrupt config is refused with a clear error naming the file — setup
    // must never destroy what it cannot parse.
    #[test]
    fn corrupt_configs_are_refused_not_overwritten() {
        let (root, env) = scratch(&[".cursor"]);
        let file = root.path.join(".cursor/mcp.json");
        std::fs::write(&file, "{ not json").unwrap();
        let (report, failed) = run_in(&env, Mode::Apply);
        assert_eq!(failed, 1, "the refusal must reach the exit code: {report}");
        assert!(report.contains("Cursor: FAILED"), "{report}");
        assert!(report.contains("not valid JSON"), "{report}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "{ not json",
            "file untouched"
        );
    }

    // The pasted snippets must stay valid in their target formats even for an
    // awkward binary path — Windows backslashes and spaces are the cases a
    // raw `display()` interpolation used to corrupt.
    #[test]
    fn manual_snippets_escape_awkward_paths() {
        let (_root, mut env) = scratch(&[]);
        env.exe = PathBuf::from(r"C:\Program Files\imcp2\imcp2-local.exe");
        let by_name = |name: &str| {
            clients(&env)
                .into_iter()
                .find(|c| c.name == name)
                .unwrap()
                .manual
        };

        let cursor = by_name("Cursor");
        let snippet = cursor.split_once(":\n").unwrap().1;
        let parsed: serde_json::Value = serde_json::from_str(snippet).expect(snippet);
        assert_eq!(
            parsed["mcpServers"]["imcp2"]["command"],
            r"C:\Program Files\imcp2\imcp2-local.exe"
        );

        let codex = by_name("Codex");
        let toml_body = codex.split_once(":\n").unwrap().1;
        let doc: toml_edit::DocumentMut = toml_body.parse().expect(toml_body);
        assert_eq!(
            doc["mcp_servers"]["imcp2"]["command"].as_str(),
            Some(r"C:\Program Files\imcp2\imcp2-local.exe")
        );

        let claude = by_name("Claude Code");
        assert!(
            claude.ends_with(r#"-- 'C:\Program Files\imcp2\imcp2-local.exe'"#),
            "the one-liner must quote a spaced path literally: {claude}"
        );
    }

    // The one-time backup holds the PRE-imcp2 state: a second apply must not
    // rotate it away with an already-registered copy.
    #[test]
    fn the_backup_is_first_run_only() {
        let (root, env) = scratch(&[".cursor"]);
        let file = root.path.join(".cursor/mcp.json");
        std::fs::write(&file, r#"{ "mcpServers": {} }"#).unwrap();
        run_in(&env, Mode::Apply);
        let bak = root.path.join(".cursor/mcp.json.imcp2-bak");
        let first = std::fs::read_to_string(&bak).unwrap();
        assert!(!first.contains("imcp2"), "backup is the pre-imcp2 state");
        run_in(&env, Mode::Apply);
        assert_eq!(
            std::fs::read_to_string(&bak).unwrap(),
            first,
            "backup not rotated"
        );
    }
}
