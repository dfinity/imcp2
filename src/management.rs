//! Canister creation & management as the connection's **management identity** —
//! the user's default account at this server's own origin, a stable per-user
//! controller/funder (derived on demand like any per-app account).
//!
//! Two on-chain surfaces are used:
//!
//!   * The **management canister** (`aaaaa-aa`) for the canister lifecycle:
//!     `install_code` (single-shot or chunked), `canister_status`,
//!     `update_settings`, `start`/`stop`/`uninstall`/`delete`. Every call sets
//!     the ic-agent **effective canister id** to the *target* canister (not
//!     `aaaaa-aa`), as the boundary node requires, and is signed by a
//!     controller (the management identity).
//!
//!   * The **cycles ledger** (`um5iw-rqaaa-aaaaq-qaaba-cai`) for funding: a user
//!     ingress message cannot attach cycles, so `create_canister`/`top_up` draw
//!     from the caller's existing cycles-ledger balance (the ledger, being a
//!     canister, attaches the cycles). Amounts may be given directly in `cycles`
//!     or expressed in `icp` and converted at the CMC's current rate (a
//!     read-only query — no ICP is moved by this server).
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
use serde::Deserialize;

use crate::identities::Identities;

/// Public IC API boundary node (same as elsewhere in the crate).
const IC_URL: &str = "https://icp-api.io";
/// Cycles ledger — creates/funds canisters from a principal's cycles balance.
const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";
/// Cycles Minting Canister — only its read-only ICP↔XDR rate query is used here.
const CMC: &str = "rkp4c-7iaaa-aaaaa-aaaca-cai";
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
    /// Cycles to fund the new canister with (exact). Omit to use `icp` instead.
    #[serde(default)]
    pub cycles: Option<u64>,
    /// ICP worth of cycles to fund the canister with, as a decimal string e.g.
    /// "0.5" or "2". Converted to cycles at the network's current rate. Ignored
    /// when `cycles` is set.
    #[serde(default)]
    pub icp: Option<String>,
    /// Controller principals for the new canister. Defaults to [your principal].
    #[serde(default)]
    pub controllers: Vec<String>,
    /// Optional subnet principal to create the canister on. Omit to let the
    /// system choose.
    #[serde(default)]
    pub subnet: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TopUpArgs {
    /// Canister to top up.
    pub canister_id: String,
    /// Cycles to add (exact). Omit to use `icp` instead.
    #[serde(default)]
    pub cycles: Option<u64>,
    /// ICP worth of cycles to add, as a decimal string. Ignored when `cycles` is set.
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

/// Your cycles-ledger balance (the funds `create_canister`/`top_up_canister` spend).
pub async fn cycles_balance(ids: &Identities, session_id: &str) -> Result<String, String> {
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
    Ok(format!(
        "Your cycles-ledger balance (principal {principal}): {balance} cycles."
    ))
}

/// Create + fund a canister from your cycles-ledger balance.
pub async fn create_canister(
    ids: &Identities,
    session_id: &str,
    args: CreateCanisterArgs,
) -> Result<String, String> {
    let (agent, principal) = management_agent(ids, session_id).await?;
    let cycles = resolve_cycles(&agent, args.icp.as_deref(), args.cycles).await?;

    let controllers = if args.controllers.is_empty() {
        vec![principal]
    } else {
        args.controllers
            .iter()
            .map(|c| parse_principal(c))
            .collect::<Result<Vec<_>, _>>()?
    };
    let subnet_selection = match &args.subnet {
        Some(s) => Some(SubnetSelection::Subnet {
            subnet: parse_principal(s)?,
        }),
        None => None,
    };
    let settings = CanisterSettings {
        controllers: Some(controllers.clone()),
        ..Default::default()
    };
    let create = CyclesCreateArg {
        from_subaccount: None,
        created_at_time: None,
        amount: Nat::from(cycles),
        creation_args: Some(CmcCreateCanisterArgs {
            settings: Some(settings),
            subnet_selection,
        }),
    };

    let ledger = parse_principal(CYCLES_LEDGER)?;
    let arg = Encode!(&create).map_err(|e| format!("encode create_canister: {e}"))?;
    let reply = update_call(&agent, ledger, "create_canister", arg).await?;
    let result =
        Decode!(&reply, CreateResult).map_err(|e| format!("decode create_canister reply: {e}"))?;
    match result {
        Ok(s) => Ok(format!(
            "Created canister {} — funded with {} cycles (cycles-ledger block {}). Controllers: {}.\n\
             Next: build your Wasm and install it with install_code.",
            s.canister_id,
            cycles,
            s.block_id,
            controllers
                .iter()
                .map(Principal::to_text)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Err(e) => Err(format!("cycles ledger refused create_canister: {e:?}")),
    }
}

/// Add cycles to an existing canister, paying from your cycles-ledger balance.
pub async fn top_up_canister(
    ids: &Identities,
    session_id: &str,
    args: TopUpArgs,
) -> Result<String, String> {
    let target = parse_principal(&args.canister_id)?;
    let (agent, _) = management_agent(ids, session_id).await?;
    let cycles = resolve_cycles(&agent, args.icp.as_deref(), args.cycles).await?;

    let ledger = parse_principal(CYCLES_LEDGER)?;
    let withdraw = WithdrawArg {
        amount: Nat::from(cycles),
        from_subaccount: None,
        to: target,
        created_at_time: None,
    };
    let arg = Encode!(&withdraw).map_err(|e| format!("encode withdraw: {e}"))?;
    let reply = update_call(&agent, ledger, "withdraw", arg).await?;
    let result = Decode!(&reply, WithdrawResult).map_err(|e| format!("decode withdraw reply: {e}"))?;
    match result {
        Ok(block) => Ok(format!(
            "Topped up {target} with {cycles} cycles (cycles-ledger block {block})."
        )),
        Err(e) => Err(format!("cycles ledger refused withdraw: {e:?}")),
    }
}

/// Install (or reinstall/upgrade) a Wasm module on a canister you control.
pub async fn install_code(
    ids: &Identities,
    session_id: &str,
    args: InstallCodeArgs,
) -> Result<String, String> {
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
    let agent = Agent::builder()
        .with_url(IC_URL)
        .with_identity(identity)
        .build()
        .map_err(|e| format!("could not build agent: {e}"))?;
    Ok((agent, principal))
}

/// A management-canister (`aaaaa-aa`) update call with the effective canister id
/// set to the TARGET — the boundary node requires this for lifecycle methods.
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

/// A plain update call to a specific canister (cycles ledger, etc.).
async fn update_call(
    agent: &Agent,
    canister: Principal,
    method: &str,
    arg: Vec<u8>,
) -> Result<Vec<u8>, String> {
    agent
        .update(&canister, method)
        .with_arg(arg)
        .call_and_wait()
        .await
        .map_err(|e| format!("{method} failed: {e}"))
}

/// Shared body for the no-payload lifecycle methods.
async fn lifecycle(
    ids: &Identities,
    session_id: &str,
    canister_id: &str,
    method: &str,
) -> Result<(), String> {
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

/// Resolve a cycle amount from `cycles` (exact) or `icp` (converted via the CMC rate).
async fn resolve_cycles(
    agent: &Agent,
    icp: Option<&str>,
    cycles: Option<u64>,
) -> Result<u128, String> {
    if let Some(c) = cycles {
        if c == 0 {
            return Err("cycles amount must be greater than 0".into());
        }
        return Ok(c as u128);
    }
    if let Some(icp) = icp {
        let e8s = parse_icp_to_e8s(icp)?;
        if e8s == 0 {
            return Err("ICP amount must be greater than 0".into());
        }
        let rate = icp_xdr_rate(agent).await?; // xdr_permyriad_per_icp
        // cycles_per_icp = (xdr_permyriad_per_icp / 10_000) XDR * 1e12 cycles/XDR
        //               = xdr_permyriad_per_icp * 1e8, so for `e8s` e8s of ICP:
        // cycles = (e8s / 1e8) * xdr_permyriad_per_icp * 1e8 = e8s * xdr_permyriad_per_icp.
        return Ok(e8s as u128 * rate as u128);
    }
    Err("specify either `cycles` or `icp`".into())
}

/// Read the CMC's current ICP→XDR rate (`xdr_permyriad_per_icp`).
async fn icp_xdr_rate(agent: &Agent) -> Result<u64, String> {
    let cmc = parse_principal(CMC)?;
    let arg = Encode!().map_err(|e| format!("encode: {e}"))?;
    let reply = agent
        .query(&cmc, "get_icp_xdr_conversion_rate")
        .with_arg(arg)
        .call()
        .await
        .map_err(|e| format!("CMC rate query failed: {e}"))?;
    let resp = Decode!(&reply, IcpXdrRateResponse).map_err(|e| format!("decode rate: {e}"))?;
    Ok(resp.data.xdr_permyriad_per_icp)
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
    candid_parser::parse_idl_args(arg)
        .map_err(|e| format!("could not parse init arg `{arg}`: {e}"))?
        .to_bytes()
        .map_err(|e| format!("could not encode init arg: {e}"))
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
        Err(_) => match IDLArgs::from_bytes(bytes) {
            Ok(d) => format!("Canister {target} status (raw Candid):\n{d}"),
            Err(e) => format!("canister_status succeeded but the reply didn't decode: {e}"),
        },
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

#[derive(CandidType)]
struct CyclesCreateArg {
    from_subaccount: Option<Vec<u8>>,
    created_at_time: Option<u64>,
    amount: Nat,
    creation_args: Option<CmcCreateCanisterArgs>,
}

#[derive(CandidType)]
struct CmcCreateCanisterArgs {
    settings: Option<CanisterSettings>,
    subnet_selection: Option<SubnetSelection>,
}

#[derive(CandidType)]
enum SubnetSelection {
    Subnet { subnet: Principal },
}

#[derive(CandidType, Deserialize)]
struct CreateCanisterSuccess {
    block_id: Nat,
    canister_id: Principal,
}

#[derive(CandidType, Deserialize, Debug)]
enum CreateCanisterError {
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    TemporarilyUnavailable,
    Duplicate { duplicate_of: Nat, canister_id: Option<Principal> },
    FailedToCreate { fee_block: Option<Nat>, refund_block: Option<Nat>, error: String },
    GenericError { message: String, error_code: Nat },
}
type CreateResult = std::result::Result<CreateCanisterSuccess, CreateCanisterError>;

#[derive(CandidType)]
struct WithdrawArg {
    amount: Nat,
    from_subaccount: Option<Vec<u8>>,
    to: Principal,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    Unknown,
}

#[derive(CandidType, Deserialize, Debug)]
enum WithdrawError {
    GenericError { message: String, error_code: Nat },
    TemporarilyUnavailable,
    FailedToWithdraw { fee_block: Option<Nat>, rejection_code: RejectionCode, rejection_reason: String },
    Duplicate { duplicate_of: Nat },
    BadFee { expected_fee: Nat },
    InvalidReceiver { receiver: Principal },
    CreatedInFuture { ledger_time: u64 },
    TooOld,
    InsufficientFunds { balance: Nat },
}
type WithdrawResult = std::result::Result<Nat, WithdrawError>;

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

// ---- CMC (read-only rate query) ----

#[derive(CandidType, Deserialize)]
struct IcpXdrRateResponse {
    data: IcpXdrRate,
    hash_tree: Vec<u8>,
    certificate: Vec<u8>,
}
#[derive(CandidType, Deserialize)]
struct IcpXdrRate {
    timestamp_seconds: u64,
    xdr_permyriad_per_icp: u64,
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
    fn icp_to_cycles_math() {
        // xdr_permyriad_per_icp = 50_000 ⇒ 1 ICP = 5 XDR = 5e12 cycles.
        let rate: u64 = 50_000;
        let e8s = parse_icp_to_e8s("1").unwrap();
        assert_eq!(e8s as u128 * rate as u128, 5_000_000_000_000u128);
        let e8s_half = parse_icp_to_e8s("0.5").unwrap();
        assert_eq!(e8s_half as u128 * rate as u128, 2_500_000_000_000u128);
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

    #[test]
    fn create_args_encode() {
        let create = CyclesCreateArg {
            from_subaccount: None,
            created_at_time: None,
            amount: Nat::from(5_000_000_000_000u128),
            creation_args: Some(CmcCreateCanisterArgs {
                settings: Some(CanisterSettings {
                    controllers: Some(vec![Principal::management_canister()]),
                    ..Default::default()
                }),
                subnet_selection: None,
            }),
        };
        assert!(Encode!(&create).is_ok());
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
