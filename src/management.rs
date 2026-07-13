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
//!   * Funding, two ways (both as the management identity):
//!       - **`cycles`** — draw from the caller's existing **cycles-ledger**
//!         (`um5iw-rqaaa-aaaaq-qaaba-cai`) balance (a user ingress message can't
//!         attach cycles, so the ledger, being a canister, attaches them).
//!       - **`icp`** — transfer ICP from the caller's **ICP-ledger** account to
//!         the **CMC** (memo-tagged deposit) and `notify_create_canister` /
//!         `notify_top_up` to mint cycles. Best-effort, single attempt: if the
//!         transfer lands but the notify fails, the ICP is held by the CMC and is
//!         recoverable by re-notifying with the returned block index (we do NOT
//!         retry, and the caller must NOT blindly re-run — that transfers again).
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

/// Public IC API boundary node (same as elsewhere in the crate).
const IC_URL: &str = "https://icp-api.io";
/// Cycles ledger — creates/funds canisters from a principal's cycles balance.
const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";
/// Cycles Minting Canister — mints cycles from ICP for the `icp` funding path
/// (`notify_create_canister` / `notify_top_up`).
const CMC: &str = "rkp4c-7iaaa-aaaaa-aaaca-cai";
/// ICP ledger — the `icp` funding path transfers ICP from the caller's account here.
const ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
/// Standard ICP-ledger transfer fee (0.0001 ICP), charged on top of the amount.
const ICP_TRANSFER_FEE_E8S: u64 = 10_000;
/// CMC deposit memos (ASCII, little-endian u64) that tag an ICP transfer with the
/// operation it funds. Defined by the ICP ledger / cycles-minting canister.
const MEMO_CREATE_CANISTER: u64 = 0x4145_5243; // 'CREA'
const MEMO_TOP_UP_CANISTER: u64 = 0x5055_5054; // 'TPUP'
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
    /// Cycles to fund the new canister with (exact), drawn from your
    /// **cycles-ledger** balance (the principal `icp_cycles_balance` reports). Omit to
    /// use `icp` instead.
    #[serde(default)]
    pub cycles: Option<u64>,
    /// ICP to convert into the new canister's cycles, as a decimal string e.g.
    /// "0.5" or "2". Transferred from your **ICP-ledger** account (same management
    /// principal as `icp_cycles_balance`, default subaccount) and minted to cycles via
    /// the CMC — best-effort, single attempt, no retries. Ignored when `cycles` is
    /// set.
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
    /// Cycles to add (exact), drawn from your **cycles-ledger** balance (the
    /// principal `icp_cycles_balance` reports). Omit to use `icp` instead.
    #[serde(default)]
    pub cycles: Option<u64>,
    /// ICP to convert into cycles for the top-up, as a decimal string. Transferred
    /// from your **ICP-ledger** account (same management principal as
    /// `icp_cycles_balance`, default subaccount) and minted via the CMC — best-effort,
    /// single attempt, no retries. Ignored when `cycles` is set.
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
/// `icp_update_canister_settings`, `icp_top_up_canister`, `icp_start_canister`,
/// `icp_stop_canister`, `icp_uninstall_code`, `icp_delete_canister`).
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CanisterActionOutput {
    /// The canister the action targeted.
    pub canister_id: String,
    /// Human-readable summary of the outcome (same as the text content).
    pub message: String,
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

/// Structured result of `icp_create_canister`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CreatedCanister {
    /// The new canister's principal id — install code on it with icp_install_code.
    pub canister_id: String,
    /// The canister's controller principals.
    pub controllers: Vec<String>,
    /// How the canister was funded, human-readable: for the `cycles` path, the
    /// cycle amount and cycles-ledger block; for the `icp` path, the ICP amount
    /// the CMC converted and the ICP-ledger block index.
    pub funding: String,
}

impl CreatedCanister {
    pub fn human(&self) -> String {
        format!(
            "Created canister {} — {}. Controllers: {}.\n\
             Next: build your Wasm and install it with icp_install_code.",
            self.canister_id,
            self.funding,
            self.controllers.join(", ")
        )
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

/// Your cycles-ledger balance (the funds `icp_create_canister`/`icp_top_up_canister` spend).
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

/// Create + fund a canister — from your cycles-ledger balance (`cycles`) or by
/// converting ICP via the CMC (`icp`). `cycles` takes precedence when both given.
pub async fn create_canister(
    ids: &Identities,
    session_id: &str,
    args: CreateCanisterArgs,
) -> Result<CreatedCanister, String> {
    ids.require_write(session_id).await?;
    let (agent, principal) = management_agent(ids, session_id).await?;

    let controllers = if args.controllers.is_empty() {
        vec![principal]
    } else {
        args.controllers
            .iter()
            .map(|c| parse_principal(c))
            .collect::<Result<Vec<_>, _>>()?
    };
    let controllers_text = || controllers.iter().map(Principal::to_text).collect::<Vec<_>>();
    let subnet_selection = match &args.subnet {
        Some(s) => Some(SubnetSelection::Subnet {
            subnet: parse_principal(s)?,
        }),
        None => None,
    };

    // ICP funding path: transfer ICP from your ICP-ledger account to the CMC
    // (memo = CREATE, deposit sub-account derived from YOU, the payer/caller),
    // then notify the CMC to mint cycles and create the canister. Best-effort.
    if args.cycles.is_none() {
        if let Some(icp) = args.icp.as_deref() {
            let e8s = parse_icp_e8s_positive(icp)?;
            let block = cmc_icp_deposit(&agent, &principal, MEMO_CREATE_CANISTER, e8s).await?;
            let arg = NotifyCreateCanisterArg {
                block_index: block,
                controller: principal,
                subnet_type: None,
                subnet_selection: subnet_selection.clone(),
                settings: Some(CanisterSettings {
                    controllers: Some(controllers.clone()),
                    ..Default::default()
                }),
            };
            let bytes = Encode!(&arg).map_err(|e| format!("encode notify_create_canister: {e}"))?;
            let reply = update_call(&agent, parse_principal(CMC)?, "notify_create_canister", bytes)
                .await
                .map_err(|e| notify_failed_hint("notify_create_canister", block, &e))?;
            let result = Decode!(&reply, NotifyCreateResult)
                .map_err(|e| format!("decode notify_create_canister reply: {e}"))?;
            return match result {
                Ok(canister_id) => Ok(CreatedCanister {
                    canister_id: canister_id.to_text(),
                    controllers: controllers_text(),
                    funding: format!(
                        "funded from {icp} ICP converted by the CMC (ICP-ledger block {block})"
                    ),
                }),
                Err(e) => Err(notify_error_msg("notify_create_canister", block, e)),
            };
        }
    }

    // Cycles funding path: draw from your cycles-ledger balance.
    let cycles = require_cycles(args.cycles)?;
    let create = CyclesCreateArg {
        from_subaccount: None,
        created_at_time: None,
        amount: Nat::from(cycles),
        creation_args: Some(CmcCreateCanisterArgs {
            settings: Some(CanisterSettings {
                controllers: Some(controllers.clone()),
                ..Default::default()
            }),
            subnet_selection,
        }),
    };
    let ledger = parse_principal(CYCLES_LEDGER)?;
    let arg = Encode!(&create).map_err(|e| format!("encode create_canister: {e}"))?;
    let reply = update_call(&agent, ledger, "create_canister", arg).await?;
    let result =
        Decode!(&reply, CreateResult).map_err(|e| format!("decode create_canister reply: {e}"))?;
    match result {
        Ok(s) => Ok(CreatedCanister {
            canister_id: s.canister_id.to_text(),
            controllers: controllers_text(),
            funding: format!(
                "funded with {cycles} cycles (cycles-ledger block {})",
                s.block_id
            ),
        }),
        Err(e) => Err(format!("cycles ledger refused create_canister: {e:?}")),
    }
}

/// Add cycles to an existing canister — from your cycles-ledger balance (`cycles`)
/// or by converting ICP via the CMC (`icp`). `cycles` takes precedence.
pub async fn top_up_canister(
    ids: &Identities,
    session_id: &str,
    args: TopUpArgs,
) -> Result<String, String> {
    ids.require_write(session_id).await?;
    let target = parse_principal(&args.canister_id)?;
    let (agent, _) = management_agent(ids, session_id).await?;

    // ICP funding path: transfer ICP to the CMC (memo = TOP_UP, deposit
    // sub-account derived from the TARGET canister), then notify_top_up to mint
    // cycles straight into it. Best-effort, single attempt.
    if args.cycles.is_none() {
        if let Some(icp) = args.icp.as_deref() {
            let e8s = parse_icp_e8s_positive(icp)?;
            let block = cmc_icp_deposit(&agent, &target, MEMO_TOP_UP_CANISTER, e8s).await?;
            let arg = NotifyTopUpArg {
                block_index: block,
                canister_id: target,
            };
            let bytes = Encode!(&arg).map_err(|e| format!("encode notify_top_up: {e}"))?;
            let reply = update_call(&agent, parse_principal(CMC)?, "notify_top_up", bytes)
                .await
                .map_err(|e| notify_failed_hint("notify_top_up", block, &e))?;
            let result = Decode!(&reply, NotifyTopUpResult)
                .map_err(|e| format!("decode notify_top_up reply: {e}"))?;
            return match result {
                Ok(cycles) => Ok(format!(
                    "Topped up {target} with {cycles} cycles (converted from {icp} ICP; ICP-ledger block {block})."
                )),
                Err(e) => Err(notify_error_msg("notify_top_up", block, e)),
            };
        }
    }

    // Cycles funding path: draw from your cycles-ledger balance.
    let cycles = require_cycles(args.cycles)?;
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

/// Validate the exact `cycles` amount for the cycles-ledger funding path (used
/// when no `icp` was given).
fn require_cycles(cycles: Option<u64>) -> Result<u128, String> {
    match cycles {
        Some(c) if c > 0 => Ok(c as u128),
        Some(_) => Err("cycles amount must be greater than 0".into()),
        None => Err("specify either `cycles` or `icp`".into()),
    }
}

/// Parse a decimal-ICP string and require it to be > 0.
fn parse_icp_e8s_positive(icp: &str) -> Result<u64, String> {
    let e8s = parse_icp_to_e8s(icp)?;
    if e8s == 0 {
        return Err("ICP amount must be greater than 0".into());
    }
    Ok(e8s)
}

/// CMC deposit sub-account for a principal: a 32-byte array `[len][principal
/// bytes][zero-pad]`. Matches `ic_ledger_types::Subaccount::from(principal)`.
fn principal_subaccount(p: &Principal) -> [u8; 32] {
    let mut sub = [0u8; 32];
    let bytes = p.as_slice();
    sub[0] = bytes.len() as u8;
    sub[1..1 + bytes.len()].copy_from_slice(bytes);
    sub
}

/// ICP-ledger AccountIdentifier (32 bytes): the big-endian CRC32 checksum of the
/// SHA-224 of `"\x0Aaccount-id" ‖ owner ‖ subaccount`, prepended to that hash.
fn account_identifier(owner: &Principal, subaccount: &[u8; 32]) -> Vec<u8> {
    use sha2::{Digest, Sha224};
    let mut hasher = Sha224::new();
    hasher.update(b"\x0Aaccount-id");
    hasher.update(owner.as_slice());
    hasher.update(&subaccount[..]);
    let hash = hasher.finalize(); // 28 bytes
    let crc = crc32fast::hash(&hash).to_be_bytes();
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&crc);
    out.extend_from_slice(&hash);
    out
}

/// Transfer ICP from your ICP-ledger account to the CMC's memo-tagged deposit
/// account for `dest` (the payer for CREATE, the target canister for TOP_UP), and
/// return the ICP-ledger block index. A failure here means no funds were moved.
async fn cmc_icp_deposit(
    agent: &Agent,
    dest: &Principal,
    memo: u64,
    amount_e8s: u64,
) -> Result<u64, String> {
    let to = account_identifier(&parse_principal(CMC)?, &principal_subaccount(dest));
    let args = TransferArgs {
        memo,
        amount: Tokens { e8s: amount_e8s },
        fee: Tokens {
            e8s: ICP_TRANSFER_FEE_E8S,
        },
        from_subaccount: None,
        to,
        created_at_time: None,
    };
    let bytes = Encode!(&args).map_err(|e| format!("encode ICP transfer: {e}"))?;
    let reply = update_call(agent, parse_principal(ICP_LEDGER)?, "transfer", bytes).await?;
    let result =
        Decode!(&reply, TransferResult).map_err(|e| format!("decode ICP transfer reply: {e}"))?;
    result.map_err(|e| match e {
        TransferError::InsufficientFunds { balance } => format!(
            "not enough ICP in your ICP-ledger account (balance {} e8s; need {} + {} fee). \
             Send ICP to your management principal's default ICP-ledger account first.",
            balance.e8s, amount_e8s, ICP_TRANSFER_FEE_E8S
        ),
        TransferError::BadFee { expected_fee } => format!(
            "the ICP-ledger transfer fee has changed: the ledger expected {} e8s but we sent {} \
             (the server's ICP_TRANSFER_FEE_E8S constant needs updating). No ICP was moved.",
            expected_fee.e8s, ICP_TRANSFER_FEE_E8S
        ),
        other => format!("ICP-ledger transfer failed: {other:?}"),
    })
}

/// Message for a transport-level failure of the CMC notify AFTER the ICP transfer
/// landed: the ICP is held by the CMC and is recoverable — do NOT blindly re-run.
fn notify_failed_hint(method: &str, block: u64, e: &str) -> String {
    // `e` already reads "<method> failed: …" (from `update_call`), so don't
    // restate the method here.
    format!(
        "ICP transfer succeeded (ICP-ledger block {block}) but the follow-up CMC notify did not \
         complete: {e}. Your ICP is held by the CMC — recover it by re-calling {method} for block \
         {block} with the SAME arguments this call used (block_index alone is not enough). Do NOT \
         re-run this tool; that would transfer ICP again."
    )
}

/// Actionable message for each `NotifyError` the CMC can return.
fn notify_error_msg(method: &str, block: u64, e: NotifyError) -> String {
    match e {
        NotifyError::Refunded {
            reason,
            block_index,
        } => format!(
            "the CMC refunded your ICP ({reason}{}); no cycles were minted, so you can retry.",
            block_index
                .map(|b| format!("; refund block {b}"))
                .unwrap_or_default()
        ),
        NotifyError::Processing => format!(
            "the CMC is still processing the deposit. Finish by re-calling {method} for block \
             {block} shortly, with the SAME arguments this call used (block_index alone is not \
             enough). Do NOT re-run this tool; that would transfer ICP again."
        ),
        NotifyError::TransactionTooOld(_) => format!(
            "the ICP transfer (block {block}) is too old for the CMC to accept — check your \
             ICP-ledger / CMC balance before retrying."
        ),
        NotifyError::InvalidTransaction(m) => {
            format!("the CMC rejected the deposit as invalid: {m}")
        }
        NotifyError::Other {
            error_code,
            error_message,
        } => format!(
            "the CMC returned an error ({error_code}): {error_message}. If your ICP left your \
             account, recover by re-calling {method} for block {block} with the SAME arguments this \
             call used (block_index alone is not enough)."
        ),
    }
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

#[derive(CandidType, Clone)]
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

// ---- ICP ledger (legacy `transfer`, for the ICP funding path) ----

#[derive(CandidType, Deserialize, Debug)]
struct Tokens {
    e8s: u64,
}

#[derive(CandidType)]
struct TimeStamp {
    timestamp_nanos: u64,
}

#[derive(CandidType)]
struct TransferArgs {
    memo: u64,
    amount: Tokens,
    fee: Tokens,
    from_subaccount: Option<Vec<u8>>,
    /// AccountIdentifier — a 32-byte blob (`vec nat8`).
    to: Vec<u8>,
    created_at_time: Option<TimeStamp>,
}

#[derive(CandidType, Deserialize, Debug)]
enum TransferError {
    BadFee { expected_fee: Tokens },
    InsufficientFunds { balance: Tokens },
    TxTooOld { allowed_window_nanos: u64 },
    TxCreatedInFuture,
    TxDuplicate { duplicate_of: u64 },
}
type TransferResult = std::result::Result<u64, TransferError>;

// ---- CMC (ICP → cycles: notify_create_canister / notify_top_up) ----

#[derive(CandidType)]
struct NotifyTopUpArg {
    block_index: u64,
    canister_id: Principal,
}

#[derive(CandidType)]
struct NotifyCreateCanisterArg {
    block_index: u64,
    controller: Principal,
    subnet_type: Option<String>,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettings>,
}

#[derive(CandidType, Deserialize, Debug)]
enum NotifyError {
    Refunded {
        reason: String,
        block_index: Option<u64>,
    },
    Processing,
    TransactionTooOld(u64),
    InvalidTransaction(String),
    Other {
        error_code: u64,
        error_message: String,
    },
}
/// `notify_top_up` → `variant { Ok: nat (cycles); Err: NotifyError }`.
type NotifyTopUpResult = std::result::Result<Nat, NotifyError>;
/// `notify_create_canister` → `variant { Ok: principal; Err: NotifyError }`.
type NotifyCreateResult = std::result::Result<Principal, NotifyError>;

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
    fn require_cycles_validates() {
        assert_eq!(require_cycles(Some(5)).unwrap(), 5u128);
        assert!(require_cycles(Some(0)).is_err()); // zero rejected
        assert!(require_cycles(None).is_err()); // neither cycles nor icp
        assert!(parse_icp_e8s_positive("0").is_err()); // zero ICP rejected
        assert_eq!(parse_icp_e8s_positive("0.5").unwrap(), 50_000_000);
    }

    // CMC deposit sub-account: [len][principal bytes][zero-pad] to 32 bytes.
    #[test]
    fn principal_subaccount_layout() {
        // The management canister principal is the empty slice → all-zero sub-account.
        assert_eq!(principal_subaccount(&Principal::management_canister()), [0u8; 32]);
        // A real principal: byte 0 is the length, then the raw principal bytes.
        let p = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
        let sub = principal_subaccount(&p);
        assert_eq!(sub[0] as usize, p.as_slice().len());
        assert_eq!(&sub[1..1 + p.as_slice().len()], p.as_slice());
        assert!(sub[1 + p.as_slice().len()..].iter().all(|&b| b == 0));
    }

    // AccountIdentifier is 32 bytes whose first 4 are the big-endian CRC32 of the
    // remaining 28 — validate that self-consistency (guards the hashing wiring).
    #[test]
    fn account_identifier_is_crc_prefixed() {
        let owner = Principal::from_text("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
        let id = account_identifier(&owner, &principal_subaccount(&Principal::management_canister()));
        assert_eq!(id.len(), 32);
        let crc = crc32fast::hash(&id[4..]).to_be_bytes();
        assert_eq!(&id[0..4], &crc[..], "first 4 bytes must be the CRC32 of the last 28");
        // Deterministic: same inputs → same account id.
        let id2 = account_identifier(&owner, &principal_subaccount(&Principal::management_canister()));
        assert_eq!(id, id2);
    }

    // The ICP-ledger transfer args and both CMC notify args must encode — a bad
    // field name/order would only surface on mainnet otherwise.
    #[test]
    fn icp_and_cmc_args_encode() {
        let transfer = TransferArgs {
            memo: MEMO_TOP_UP_CANISTER,
            amount: Tokens { e8s: 100_000_000 },
            fee: Tokens { e8s: ICP_TRANSFER_FEE_E8S },
            from_subaccount: None,
            to: account_identifier(
                &parse_principal(CMC).unwrap(),
                &principal_subaccount(&Principal::management_canister()),
            ),
            created_at_time: None,
        };
        assert!(Encode!(&transfer).is_ok());
        assert!(Encode!(&NotifyTopUpArg {
            block_index: 7,
            canister_id: Principal::management_canister(),
        })
        .is_ok());
        assert!(Encode!(&NotifyCreateCanisterArg {
            block_index: 7,
            controller: Principal::management_canister(),
            subnet_type: None,
            subnet_selection: Some(SubnetSelection::Subnet {
                subnet: Principal::management_canister()
            }),
            settings: Some(CanisterSettings {
                controllers: Some(vec![Principal::management_canister()]),
                ..Default::default()
            }),
        })
        .is_ok());
    }

    // Round-trip the reply enums so a variant rename/reshape fails at test time.
    #[test]
    fn notify_and_transfer_errors_round_trip() {
        let bytes = Encode!(&NotifyTopUpResult::Err(NotifyError::Processing)).unwrap();
        assert!(matches!(
            Decode!(&bytes, NotifyTopUpResult).unwrap(),
            Err(NotifyError::Processing)
        ));
        let refunded = NotifyError::Refunded {
            reason: "x".into(),
            block_index: Some(3),
        };
        let bytes = Encode!(&NotifyCreateResult::Err(refunded)).unwrap();
        assert!(matches!(
            Decode!(&bytes, NotifyCreateResult).unwrap(),
            Err(NotifyError::Refunded { .. })
        ));
        let te = TransferResult::Err(TransferError::InsufficientFunds {
            balance: Tokens { e8s: 1 },
        });
        let bytes = Encode!(&te).unwrap();
        assert!(matches!(
            Decode!(&bytes, TransferResult).unwrap(),
            Err(TransferError::InsufficientFunds { .. })
        ));
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
