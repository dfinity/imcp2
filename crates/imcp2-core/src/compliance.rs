//! The financial-transactions guard for the generic update-call tool.
//!
//! This server is not a financial tool: its purpose is reading, building, and
//! operating canisters, and the marketplace directories it is listed in
//! (Anthropic's Connectors Directory, OpenAI's plugins directory) prohibit a
//! connector from initiating or executing money or crypto transfers, or
//! trades, on the user's behalf. `canister_update_call` therefore refuses the
//! ledger methods that move value or grant spending rights, and the refusal
//! tells the user to perform the operation outside this connector, in a
//! trusted interface they control. It deliberately names no venue: metadata
//! that answered a refused financial operation with a specific transactional
//! service would read as a redirect from one such route to another. Canister
//! creation and funding are the one exception — they point at the user's own
//! icp CLI, which is where this connector already says that work happens.
//!
//! The guard has three groups (the method groups are split per review, so an
//! app that happens to name a non-financial method `transfer` or `approve`
//! keeps working):
//!
//!   * **Standardized methods, matched literally on every canister.** Token
//!     ledgers on the Internet Computer follow the ICRC standards —
//!     ICRC-1/ICRC-2 for fungible tokens (ICRC-4 for batch transfers),
//!     ICRC-7/ICRC-37 for NFTs — and the standards fix the exact method
//!     names; likewise the NNS/SNS governance interface fixes
//!     `manage_neuron`, the one method through which staked neurons are
//!     disbursed, split, and spawned. That covers every SNS DAO's governance
//!     (dozens exist and more launch by NNS proposal, so no per-DAO
//!     enumeration could stay current) as well as the NNS's. Candid method
//!     names are case-sensitive, so literal matching is both sufficient (the
//!     real ledgers and governances use exactly these names) and precise (a
//!     differently-spelled name is not the standard method).
//!   * **Abstract names, scoped to the system canister where they are
//!     financial.** `transfer` on the ICP ledger or `withdraw` on the cycles
//!     ledger moves the user's funds; the same names on an arbitrary app
//!     canister are often something else entirely, so they are refused only
//!     on those specific canister ids. The cycles-minting canister's whole
//!     user-callable update surface is here too — `notify_top_up`,
//!     `notify_create_canister`, `notify_mint_cycles`, `create_canister` —
//!     because each one *completes* a funding operation: the ICP debit
//!     happened earlier, but the call is what finishes the flow, which makes
//!     it a concrete financial path rather than a theoretical one. Their
//!     refusal points at the icp CLI, which is also how an interrupted mint
//!     is recovered.
//!   * **Finance-related canisters, refused entirely.** A curated list of
//!     canisters whose purpose is holding, staking, exchanging, or moving
//!     value — token ledgers and chain-key minters, exchanges, wallet
//!     backends, staking/governance canisters, and the frontends that serve
//!     them. On these, EVERY update call is refused: their update surface
//!     acts on the user's assets (or administers the service that does), so
//!     there is no non-financial update call worth allowing. Each entry
//!     carries a label saying what the service is and how it is financial,
//!     used verbatim in the refusal.
//!
//! Why the standardized surface is where real funds live: tokens are only
//! valuable if they can be exchanged or used, and the ICP ecosystem's
//! financial platforms (wallets like Oisy, exchanges like ICP Swap) integrate
//! ledgers through these standards — a token on a bespoke, non-standard
//! ledger can exist, but the ecosystem's platforms cannot hold or trade it,
//! so it carries little exchangeable value.
//!
//! Two scope notes, so nobody over-claims what this guard does:
//!
//!   * It is a guardrail enforcing a stated policy, not a hermetic seal — a
//!     bespoke canister can expose value-moving methods under any name (a
//!     custom swap method, an intermediary that forwards a transfer), which
//!     no name-based list can enumerate. The policy itself ("financial
//!     transactions are not supported") is stated in the server-level
//!     instructions (get_info) and disclosed in `canister_update_call`'s own
//!     description; this guard enforces it for the standardized
//!     ledger surface, where real funds overwhelmingly live (see above).
//!     Likewise the canister list is curated and static, while exchanges
//!     create per-pair pool/farm canisters dynamically and new services
//!     launch: entries cover each service's central canisters (verified
//!     against the IC dashboard's registry and the services' own published
//!     sources), and the standardized-methods group plus the stated policy
//!     cover the rest.
//!   * Legacy pre-ICRC token standards (DIP20/EXT `transfer`/`transferFrom`/
//!     `approve` on arbitrary canisters) are deliberately NOT matched: the
//!     names are too abstract to block everywhere without breaking
//!     non-financial apps (per review), and those standards sit outside the
//!     ecosystem's ICRC-integrated platforms. The stated policy covers them.

use candid::Principal;

/// Standardized value-moving methods, refused on EVERY canister, matched
/// literally (the ICRC token standards and the NNS/SNS governance interface
/// fix these exact names; Candid method names are case-sensitive). Each entry
/// carries the label used in the refusal message.
const DISALLOWED_STANDARD_METHODS: &[(&str, &str)] = &[
    // ICRC-1 / ICRC-2 / ICRC-4: fungible-token transfers, spending
    // approvals, and batch transfers.
    ("icrc1_transfer", "an ICRC-1 token transfer"),
    ("icrc2_approve", "an ICRC-2 spending approval"),
    ("icrc2_transfer_from", "an ICRC-2 delegated token transfer"),
    ("icrc4_transfer_batch", "an ICRC-4 batch token transfer"),
    // ICRC-7 / ICRC-37: NFT transfers and approval management.
    ("icrc7_transfer", "an ICRC-7 NFT transfer"),
    ("icrc37_transfer_from", "an ICRC-37 delegated NFT transfer"),
    ("icrc37_approve_tokens", "an ICRC-37 NFT spending approval"),
    ("icrc37_approve_collection", "an ICRC-37 collection spending approval"),
    ("icrc37_revoke_token_approvals", "an ICRC-37 NFT approval change"),
    ("icrc37_revoke_collection_approvals", "an ICRC-37 collection approval change"),
    // The NNS/SNS governance interface: every neuron operation — including
    // disbursing, splitting, and spawning staked tokens — goes through this
    // one method, on the NNS and on every SNS DAO alike. Its non-financial
    // commands (voting, following, dissolve delay) share that entry point, so
    // the label says the method is refused wholesale rather than calling the
    // caller's particular command a transfer.
    (
        "manage_neuron",
        "the single entry point for every neuron operation on an NNS/SNS governance interface — \
         disbursing, splitting, and spawning staked tokens among them — so it is refused as a \
         whole rather than per command",
    ),
];

/// The ICP ledger — its pre-ICRC methods move the user's ICP.
const ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
/// The cycles ledger — its withdrawal/creation methods move the user's cycles.
const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";
/// The NNS cycles-minting canister — its update methods complete a funding
/// operation (minting cycles against the user's ICP, or creating a canister
/// from it).
const CYCLES_MINTING_CANISTER: &str = "rkp4c-7iaaa-aaaaa-aaaca-cai";

/// Abstract method names refused only on the specific system canister where
/// they are financial: (canister id, method, label). On any other canister
/// these names are allowed — an app's own `transfer` is often not a token
/// transfer at all.
const DISALLOWED_CANISTER_METHODS: &[(&str, &str, &str)] = &[
    // The ICP ledger's pre-ICRC surface.
    (ICP_LEDGER, "transfer", "the ICP ledger's legacy transfer"),
    (ICP_LEDGER, "send_dfx", "a legacy ICP-ledger transfer"),
    (ICP_LEDGER, "notify_dfx", "a legacy ICP-ledger transfer notification"),
    // The cycles ledger's value movement beyond ICRC-1/-2 (which group one
    // already covers): withdrawals and the canister-creation spends. The
    // creation refusal points the user at running the operation themselves
    // with the icp CLI directly (the dedicated instructions-only creation
    // tool is deferred from this version's served surface).
    (CYCLES_LEDGER, "withdraw", "a cycles-ledger withdrawal"),
    (CYCLES_LEDGER, "withdraw_from", "a cycles-ledger delegated withdrawal"),
    (CYCLES_LEDGER, "create_canister", "a cycles-ledger spend (canister creation)"),
    (CYCLES_LEDGER, "create_canister_from", "a cycles-ledger delegated spend (canister creation)"),
    // The cycles-minting canister's user-callable update surface. Each call
    // completes a funding operation against ICP the user already sent; the
    // remaining methods on this canister are queries or NNS-only admin calls.
    (CYCLES_MINTING_CANISTER, "notify_top_up", "a cycles top-up completion (minting cycles for a canister)"),
    (
        CYCLES_MINTING_CANISTER,
        "notify_create_canister",
        "a canister-creation payment completion",
    ),
    (CYCLES_MINTING_CANISTER, "notify_mint_cycles", "a cycles mint to a cycles-ledger account"),
    (CYCLES_MINTING_CANISTER, "create_canister", "a canister creation paid with attached cycles"),
];

/// The refused methods whose "do it yourself" pointer is the icp CLI rather
/// than the neutral wording: creating and funding canisters is work this
/// connector already says the user does in their own terminal, and an
/// interrupted mint is recovered there too.
const CLI_REDIRECT_METHODS: &[&str] = &[
    "create_canister",
    "create_canister_from",
    "notify_create_canister",
    "notify_top_up",
    "notify_mint_cycles",
];

/// Finance-related canisters where EVERY update call is refused: (canister
/// id, what the service is, how it is financial). The service and reason are
/// used verbatim in the refusal message. Every id was verified against the IC
/// dashboard's canister registry (ic-api.internetcomputer.org) and the
/// service's own published sources (canister_ids.json / docs / on-chain SNS
/// records) on 2026-08-28.
const DISALLOWED_FINANCE_CANISTERS: &[(&str, &str, &str)] = &[
    // --- The network's own staking, funds, and token infrastructure ---
    (
        "rrkah-fqaaa-aaaaa-aaaaq-cai",
        "NNS Governance",
        "its manage_neuron call stakes, splits, and disburses neuron-held ICP",
    ),
    (
        "qoctq-giaaa-aaaaa-aaaea-cai",
        "the NNS dapp frontend (the network's staking and transfer UI, classic origin)",
        "its update surface is the content store behind that UI",
    ),
    (
        "mc7vh-sqaaa-aaaai-q33na-cai",
        "the NNS dapp frontend (the network's staking and transfer UI, current origin)",
        "its update surface is the content store behind that UI",
    ),
    (
        "renrk-eyaaa-aaaaa-aaada-cai",
        "the NNS Genesis Token canister",
        "its claim_neurons call hands control of genesis neurons (staked ICP) to a caller-supplied key",
    ),
    (
        ICP_LEDGER,
        "the ICP ledger",
        "its update surface transfers ICP or grants spending approvals",
    ),
    (
        CYCLES_LEDGER,
        "the cycles ledger",
        "its update surface moves cycles (prepaid compute value) or spends them on canister creation",
    ),
    // --- Chain-key token minters: they move REAL assets on other chains ---
    (
        "mqygn-kiaaa-aaaar-qaadq-cai",
        "the ckBTC minter",
        "its retrieve_btc calls burn ckBTC and send real BTC to a Bitcoin address",
    ),
    (
        "sv3dd-oaaaa-aaaar-qacoa-cai",
        "the ckETH and ckERC20 minter",
        "its withdraw_eth / withdraw_erc20 calls burn ck-tokens and submit real Ethereum withdrawals",
    ),
    (
        "eqltq-xqaaa-aaaar-qb3vq-cai",
        "the ckDOGE minter",
        "its retrieve_doge calls burn ckDOGE and send real DOGE out",
    ),
    // --- Chain-key token ledgers (the standardized-methods group already
    // refuses the transfer/approval names on these; listing the canisters
    // closes the rest of their update surface too) ---
    ("mxzaz-hqaaa-aaaar-qaada-cai", "the ckBTC ledger", CK_LEDGER_WHY),
    ("ss2fx-dyaaa-aaaar-qacoq-cai", "the ckETH ledger", CK_LEDGER_WHY),
    ("xevnm-gaaaa-aaaar-qafnq-cai", "the ckUSDC ledger", CK_LEDGER_WHY),
    ("cngnf-vqaaa-aaaar-qag4q-cai", "the ckUSDT ledger", CK_LEDGER_WHY),
    ("pe5t5-diaaa-aaaar-qahwa-cai", "the ckEURC ledger", CK_LEDGER_WHY),
    ("bptq2-faaaa-aaaar-qagxq-cai", "the ckWBTC ledger", CK_LEDGER_WHY),
    ("j2tuh-yqaaa-aaaar-qahcq-cai", "the ckWSTETH ledger", CK_LEDGER_WHY),
    ("g4tto-rqaaa-aaaar-qageq-cai", "the ckLINK ledger", CK_LEDGER_WHY),
    ("ilzky-ayaaa-aaaar-qahha-cai", "the ckUNI ledger", CK_LEDGER_WHY),
    ("fxffn-xiaaa-aaaar-qagoa-cai", "the ckSHIB ledger", CK_LEDGER_WHY),
    ("etik7-oiaaa-aaaar-qagia-cai", "the ckPEPE ledger", CK_LEDGER_WHY),
    ("nza5v-qaaaa-aaaar-qahzq-cai", "the ckXAUT ledger", CK_LEDGER_WHY),
    ("ebo5g-cyaaa-aaaar-qagla-cai", "the ckOCT ledger", CK_LEDGER_WHY),
    ("efmc5-wyaaa-aaaar-qb3wa-cai", "the ckDOGE ledger", CK_LEDGER_WHY),
    // --- Wallets and the signer behind them ---
    (
        "doked-biaaa-aaaar-qag2a-cai",
        "the Oisy wallet backend",
        "it grants the signing allowances and tracks the pending transactions behind the wallet's transfers",
    ),
    (
        "grghe-syaaa-aaaar-qabyq-cai",
        "the Chain Fusion Signer (the signer behind Oisy)",
        "its btc_caller_send call signs and broadcasts Bitcoin transactions, and its eth/ecdsa/schnorr signing calls move funds on other chains",
    ),
    (
        "sy2xe-miaaa-aaaar-qb7sq-cai",
        "Oisy Trade",
        "an in-wallet trading engine — its update surface places and fills orders",
    ),
    (
        "nynz6-haaaa-aaaan-qzqda-cai",
        "the Oisy rewards canister",
        "its update surface drives reward-token payouts",
    ),
    (
        "cha4i-riaaa-aaaan-qeccq-cai",
        "the Oisy wallet frontend",
        "its update surface is the content store behind the wallet UI",
    ),
    // --- Liquid staking: WaterNeuron ---
    (
        "tsbvt-pyaaa-aaaar-qafva-cai",
        "the WaterNeuron liquid-staking protocol",
        "it takes ICP deposits, mints nICP, and processes unstaking withdrawals",
    ),
    (
        "buwm7-7yaaa-aaaar-qagva-cai",
        "the WaterNeuron nICP ledger",
        "its update surface transfers the liquid-staking token or grants spending approvals",
    ),
    (
        "n3i53-gyaaa-aaaam-acfaq-cai",
        "the WaterNeuron frontend",
        "its update surface is the content store behind the staking UI",
    ),
    // --- Exchanges: MULTI/DEX (canisters self-declared by the app's own
    // /.well-known/ic-app.json manifest) ---
    (
        "hmxr2-pqaaa-aaabq-qaaaa-cai",
        "the MULTI/DEX exchange backend",
        "its update surface executes the exchange's trading operations",
    ),
    (
        "hlwxo-ciaaa-aaabq-qaaaq-cai",
        "the MULTI/DEX bridge",
        "it moves tokens in and out of the exchange",
    ),
    (
        "hcv4s-uaaaa-aaabq-qaaba-cai",
        "the MULTI/DEX frontend",
        "its update surface is the content store behind the exchange UI",
    ),
    // --- Exchanges: ICPSwap ---
    (
        "4mmnk-kiaaa-aaaag-qbllq-cai",
        "the ICPSwap SwapFactory",
        "it creates and administers the per-pair swap pools that hold user funds",
    ),
    (
        "7eikv-2iaaa-aaaag-qdgwa-cai",
        "the ICPSwap PasscodeManager",
        "its depositFrom call pulls ICP from the caller as the pool-creation fee",
    ),
    (
        "c5jrt-yaaaa-aaaag-qb5ra-cai",
        "the ICPSwap farm factory",
        "it creates the farms where users stake liquidity positions for rewards",
    ),
    (
        "34ovl-syaaa-aaaag-qkanq-cai",
        "the ICPSwap staking-pool factory",
        "it creates the pools where users stake one token to earn another",
    ),
    (
        "bplw4-cqaaa-aaaag-qcb7q-cai",
        "the ICPSwap frontend",
        "its update surface is the content store behind the exchange UI",
    ),
    // --- Exchanges: Sonic (plus the legacy DIP-20 ledgers its DAO operates,
    // whose transfer names the ICRC group deliberately does not match) ---
    (
        "3xwpq-ziaaa-aaaah-qcn4a-cai",
        "the Sonic exchange swap canister",
        "its deposit, swap, and liquidity calls move tokens between user subaccounts and pools",
    ),
    (
        "lfzsk-7qaaa-aaaah-adk2q-cai",
        "the Sonic LBP registry",
        "it manages liquidity-bootstrapping token launches, taking deposits and purchases",
    ),
    (
        "eo2vl-tyaaa-aaaah-adtfa-cai",
        "the Sonic vesting canister",
        "it holds and releases vested token allocations",
    ),
    (
        "aanaa-xaaaa-aaaah-aaeiq-cai",
        "the XTC cycles-token ledger (DIP-20)",
        "its legacy transfer, burn, and mint calls move cycles-backed value under non-ICRC names",
    ),
    (
        "utozz-siaaa-aaaam-qaaxq-cai",
        "the WICP wrapped-ICP ledger (DIP-20)",
        "its legacy mint, transfer, and unwrap calls move wrapped ICP under non-ICRC names",
    ),
    // --- Exchanges: ICDex / ICLighthouse ---
    (
        "i5jcx-ziaaa-aaaar-qaazq-cai",
        "the ICDex router (ICLighthouse)",
        "it creates and administers the per-pair orderbook canisters that hold user funds",
    ),
    (
        "i2ied-uqaaa-aaaar-qaaza-cai",
        "the ICLighthouse DexAggregator",
        "a cross-exchange listing registry whose update surface includes staking and treasury withdrawals",
    ),
    (
        "3yss5-5qaaa-aaaar-qad7a-cai",
        "the ICLighthouse DAO trader",
        "it holds treasury ICP and places orders on ICDex",
    ),
    (
        "odhfn-cqaaa-aaaar-qaana-cai",
        "the ICDex trading-mining canister",
        "it runs trading and liquidity mining rounds and pays token rewards",
    ),
    (
        "7vkf4-jqaaa-aaaaj-azrua-cai",
        "the ICLighthouse frontend",
        "its update surface is the content store behind the exchange UI",
    ),
    // --- Exchanges: ICPEx ---
    (
        "2ackz-dyaaa-aaaam-ab5eq-cai",
        "the ICPEx router",
        "its update surface creates pools, moves liquidity, and executes swaps",
    ),
    (
        "24gqi-uyaaa-aaaam-ab5gq-cai",
        "the ICPEx token-creation service",
        "it mints new tokens for a fee taken from the caller",
    ),
    (
        "gdz52-oaaaa-aaaam-ab7ea-cai",
        "the ICPEx frontend",
        "its update surface is the content store behind the exchange UI",
    ),
];

/// The shared label for chain-key token ledgers in
/// [`DISALLOWED_FINANCE_CANISTERS`].
const CK_LEDGER_WHY: &str = "its update surface transfers the token or grants spending approvals";

/// The financial-transactions gate: `Some(refusal)` when the call is
/// disallowed, `None` when it may proceed. Three scopes, checked in order:
/// the standardized value-moving method names (refused on every canister),
/// the abstract names scoped to the system ledger where they are financial,
/// and the finance-canister list — on a listed canister EVERY update method
/// is refused, so `None` never depends on the method name alone. Method
/// matching is literal — the IC matches method names by exact bytes, so a
/// differently-spelled name would not reach the real method anyway. The
/// refusal is the complete tool error text — it names the method (and, on a
/// listed canister, the service and how it is financial), states the policy
/// and why it exists, and tells the agent what to recommend to the user
/// instead: performing the operation outside this connector in a trusted
/// interface they control, or, for the creation/funding methods, with their
/// own icp CLI.
pub fn disallowed_update_method(canister_id: &Principal, method: &str) -> Option<String> {
    let canister = canister_id.to_text();
    // Method-level matches run first: their refusals carry the more specific
    // label and redirect (a creation spend points at the icp CLI). The
    // canister-level blanket below then catches every other update call on a
    // listed finance canister.
    let what = DISALLOWED_STANDARD_METHODS
        .iter()
        .find(|(m, _)| *m == method)
        .map(|(_, what)| *what)
        .or_else(|| {
            DISALLOWED_CANISTER_METHODS
                .iter()
                .find(|(c, m, _)| *c == canister && *m == method)
                .map(|(_, _, what)| *what)
        });
    if let Some(what) = what {
        // Every refusal points the user at doing the operation themselves:
        // canister creation and funding at the user-run icp CLI (deliberately
        // NOT at another connector tool, per review), everything else outside
        // this connector without naming a venue (see the module doc).
        let instead = if CLI_REDIRECT_METHODS.contains(&method) {
            "Recommend that the user creates and funds canisters themselves with \
             the icp CLI in their own terminal (install with `npm install -g \
             @icp-sdk/icp-cli`, or see https://github.com/dfinity/icp-cli); the \
             skill://icp-cli and skill://cycles-management resources carry the \
             full guide."
        } else {
            "Recommend that the user performs this operation outside this \
             connector, in a trusted interface they control."
        };
        return Some(format!(
            "`{method}` is {what}. Financial transactions \
             (token transfers, spending approvals, payments, or trades) are not \
             supported by this server, to protect the user: asset-moving requests \
             are denied. {instead}"
        ));
    }
    let (_, service, why) = DISALLOWED_FINANCE_CANISTERS
        .iter()
        .find(|(c, _, _)| *c == canister)?;
    Some(format!(
        "`{method}` is an update call to {service} — {why}. State-changing calls \
         to financial services are not supported by this server, to protect the \
         user: asset-moving requests are denied. Recommend that the user performs \
         this operation outside this connector, in a trusted interface they \
         control."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_canister() -> Principal {
        Principal::management_canister()
    }
    fn icp_ledger() -> Principal {
        Principal::from_text(ICP_LEDGER).unwrap()
    }
    fn cycles_ledger() -> Principal {
        Principal::from_text(CYCLES_LEDGER).unwrap()
    }
    fn cmc() -> Principal {
        Principal::from_text(CYCLES_MINTING_CANISTER).unwrap()
    }

    // Every standardized value-moving method is refused on ANY canister, in
    // its exact standard spelling — the ICRC token surface and the NNS/SNS
    // governance interface's manage_neuron alike.
    #[test]
    fn refuses_standard_methods_on_every_canister() {
        for method in [
            "manage_neuron",
            "icrc1_transfer",
            "icrc2_approve",
            "icrc2_transfer_from",
            "icrc4_transfer_batch",
            "icrc7_transfer",
            "icrc37_transfer_from",
            "icrc37_approve_tokens",
            "icrc37_approve_collection",
            "icrc37_revoke_token_approvals",
            "icrc37_revoke_collection_approvals",
        ] {
            assert!(
                disallowed_update_method(&any_canister(), method).is_some(),
                "{method} must be refused on any canister"
            );
        }
    }

    // Matching is literal: a differently-spelled name is NOT the standard
    // method (Candid method names are case-sensitive), so it is allowed on an
    // unlisted canister — it could never reach the ledger method on chain
    // anyway. (On a finance-listed canister every update call is refused
    // regardless of spelling, so the property is observable only off the list.)
    #[test]
    fn matching_is_literal_not_normalized() {
        for method in ["ICRC1_Transfer", "icrc1-transfer", " icrc1_transfer ", "Transfer"] {
            assert!(
                disallowed_update_method(&any_canister(), method).is_none(),
                "{method} is not the standard spelling and must not match"
            );
        }
    }

    // Abstract names are refused only on the system canister where they are
    // financial — and allowed on any other canister, so an app whose own
    // `transfer`/`withdraw` is non-financial keeps working.
    #[test]
    fn abstract_names_are_scoped_to_their_ledger() {
        for (canister, method) in [
            (icp_ledger(), "transfer"),
            (icp_ledger(), "send_dfx"),
            (icp_ledger(), "notify_dfx"),
            (cycles_ledger(), "withdraw"),
            (cycles_ledger(), "withdraw_from"),
            (cycles_ledger(), "create_canister"),
            (cycles_ledger(), "create_canister_from"),
            (cmc(), "notify_top_up"),
            (cmc(), "notify_create_canister"),
            (cmc(), "notify_mint_cycles"),
            (cmc(), "create_canister"),
        ] {
            assert!(
                disallowed_update_method(&canister, method).is_some(),
                "{method} must be refused on its ledger"
            );
            assert!(
                disallowed_update_method(&any_canister(), method).is_none(),
                "{method} must be allowed on an unrelated canister"
            );
        }
    }

    // The creation and funding-completion calls — the cycles ledger's creation
    // spends and the cycles-minting canister's whole update surface — are
    // refused on the generic route, and their refusal points the user at
    // doing it themselves with the icp CLI (install pointer included), which
    // is also the recovery path for an interrupted mint. Never at a connector
    // tool (the dedicated instructions-only creation tool is deferred from
    // this version).
    #[test]
    fn refuses_creation_and_funding_completions_with_cli_redirect() {
        for (canister, method) in [
            (cycles_ledger(), "create_canister"),
            (cycles_ledger(), "create_canister_from"),
            (cmc(), "notify_top_up"),
            (cmc(), "notify_create_canister"),
            (cmc(), "notify_mint_cycles"),
            (cmc(), "create_canister"),
        ] {
            let msg = disallowed_update_method(&canister, method)
                .unwrap_or_else(|| panic!("{method} must be refused"));
            assert!(msg.contains("icp CLI"), "{msg}");
            assert!(msg.contains("npm install -g @icp-sdk/icp-cli"), "{msg}");
            assert!(!msg.contains("icp_create_canister"), "no connector-tool redirect: {msg}");
        }
    }

    // Reads, fees, metadata, and legacy DIP20-style names on arbitrary
    // canisters stay callable. The cycles-minting canister's method names are
    // in the list too: they are refused on the CMC itself (above), and an
    // unrelated canister's method that happens to share the name is not a
    // funding completion.
    #[test]
    fn allows_non_financial_methods() {
        for method in [
            "icrc1_balance_of",
            "icrc1_metadata",
            "icrc1_fee",
            "transfer_fee",
            "get_transactions",
            "notify_create_canister",
            "notify_top_up",
            "greet",
            "set_name",
            "register_user",
            "http_request_update",
            // Abstract names on a non-ledger canister (per review: an app's
            // own transfer/approve is often not financial at all).
            "transfer",
            "transferFrom",
            "approve",
            "withdraw",
        ] {
            assert!(
                disallowed_update_method(&any_canister(), method).is_none(),
                "{method} must be allowed on a non-ledger canister"
            );
        }
    }

    // Every listed finance canister refuses EVERY update call — arbitrary
    // names included — and the refusal names the service, its finance
    // relation, and the policy, in the same plain protective register as the
    // method refusals (no marketplace/compliance jargon), recommending the
    // operation happen outside this connector without naming a venue.
    #[test]
    fn refuses_every_update_on_finance_canisters() {
        for (id, service, why) in DISALLOWED_FINANCE_CANISTERS {
            let canister = Principal::from_text(id).unwrap_or_else(|e| panic!("{id}: {e}"));
            for method in ["greet", "swap", "set_name", "store", "http_request_update"] {
                let msg = disallowed_update_method(&canister, method)
                    .unwrap_or_else(|| panic!("{method} on {service} ({id}) must be refused"));
                assert!(msg.contains(service), "{msg}");
                assert!(msg.contains(why), "{msg}");
                assert!(msg.contains("not supported"), "{msg}");
                assert!(msg.contains("to protect the user"), "{msg}");
                assert!(msg.contains("outside this connector"), "{msg}");
                assert!(!msg.contains("marketplace"), "{msg}");
                assert!(!msg.contains("compliance"), "{msg}");
            }
        }
    }

    // The list itself stays well-formed: every id parses as a principal, ids
    // are unique, and every entry carries both labels (what the service is,
    // how it is financial) — the shape the refusal message interpolates.
    #[test]
    fn finance_canister_list_is_well_formed() {
        let mut ids: Vec<&str> =
            DISALLOWED_FINANCE_CANISTERS.iter().map(|(id, _, _)| *id).collect();
        for (id, service, why) in DISALLOWED_FINANCE_CANISTERS {
            Principal::from_text(id).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert!(!service.is_empty() && !why.is_empty(), "{id} needs both labels");
        }
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate canister ids in the finance list");
    }

    // Method-level refusals keep precedence on listed canisters, so the
    // tailored messages (and their redirects) survive the canister blanket:
    // a creation spend still points at the icp CLI, an ICRC hit still names
    // the standard method.
    #[test]
    fn method_refusals_take_precedence_on_listed_canisters() {
        let msg = disallowed_update_method(&cycles_ledger(), "create_canister").unwrap();
        assert!(msg.contains("icp CLI"), "{msg}");
        let msg = disallowed_update_method(&icp_ledger(), "icrc1_transfer").unwrap();
        assert!(msg.contains("ICRC-1"), "{msg}");
        // ...and anything else on those ledgers now falls to the blanket.
        let msg = disallowed_update_method(&icp_ledger(), "greet").unwrap();
        assert!(msg.contains("the ICP ledger"), "{msg}");
    }

    // The refusal is the whole story: it names the method, states the policy
    // in plain terms an agent can relay (not supported, to protect the user —
    // no marketplace/compliance jargon, and no hint that another route might
    // work; per review), and sends the user outside this connector WITHOUT
    // naming a venue — metadata answering a refused financial operation with
    // a specific transactional service would read as a redirect from one such
    // route to another. Pin those pieces so the message can't degrade.
    #[test]
    fn refusal_names_method_and_policy_without_naming_a_venue() {
        let msg = disallowed_update_method(&any_canister(), "icrc1_transfer")
            .expect("must be refused");
        assert!(msg.contains("`icrc1_transfer`"), "{msg}");
        assert!(msg.contains("an ICRC-1 token transfer"), "{msg}");
        assert!(msg.contains("Financial transactions"), "{msg}");
        assert!(msg.contains("not supported"), "{msg}");
        assert!(msg.contains("to protect the user"), "{msg}");
        assert!(msg.contains("outside this connector"), "{msg}");
        assert!(msg.contains("trusted interface they control"), "{msg}");
        assert!(!msg.to_lowercase().contains("wallet"), "no venue may be named: {msg}");
        assert!(!msg.contains(".com"), "no venue may be named: {msg}");
        assert!(!msg.contains("marketplace"), "{msg}");
        assert!(!msg.contains("compliance"), "{msg}");
    }

    // manage_neuron is refused for its whole surface, not because the caller's
    // particular command moves value: the same method votes, follows, and sets
    // dissolve delays as well as disbursing. The refusal says that, instead of
    // classifying every invocation as a transfer (per review) — the policy
    // sentence that follows states what is not supported, and the label states
    // why the method as a whole is out.
    #[test]
    fn manage_neuron_refusal_explains_the_whole_surface() {
        let msg = disallowed_update_method(&any_canister(), "manage_neuron")
            .expect("must be refused");
        assert!(msg.contains("refused as a whole rather than per command"), "{msg}");
        assert!(msg.contains("disbursing, splitting, and spawning staked tokens"), "{msg}");
        assert!(
            !msg.contains("is a financial transaction") && !msg.contains("— a financial transaction"),
            "the caller's command is not classified as a transfer: {msg}"
        );
    }
}
