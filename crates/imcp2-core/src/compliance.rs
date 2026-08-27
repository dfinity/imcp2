//! The financial-transactions guard for the generic update-call tool.
//!
//! This server is not a financial tool: its purpose is reading, building, and
//! operating canisters, and the marketplace directories it is listed in
//! (Anthropic's Connectors Directory, OpenAI's plugins directory) prohibit a
//! connector from initiating or executing money or crypto transfers, or
//! trades, on the user's behalf. `canister_update_call` therefore refuses the
//! ledger methods that move value or grant spending rights, and the refusal
//! redirects the user to perform the operation themselves — in a wallet or
//! frontend they control (e.g. <https://oisy.com>) in their own browser, or,
//! for canister creation, with the icp CLI in their own terminal.
//!
//! The guard has two groups (split per review, so an app that happens to name
//! a non-financial method `transfer` or `approve` keeps working):
//!
//!   * **ICRC-standard methods, matched literally on every canister.** Token
//!     ledgers on the Internet Computer follow the ICRC standards —
//!     ICRC-1/ICRC-2 for fungible tokens (ICRC-4 for batch transfers),
//!     ICRC-7/ICRC-37 for NFTs — and the standards fix the exact method
//!     names. Candid method names are case-sensitive, so literal matching is
//!     both sufficient (the real ledgers use exactly these names) and precise
//!     (a differently-spelled name is not the standard method).
//!   * **Abstract names, scoped to the system canister where they are
//!     financial.** `transfer` on the ICP ledger or `withdraw` on the cycles
//!     ledger moves the user's funds; the same names on an arbitrary app
//!     canister are often something else entirely, so they are refused only
//!     on those specific canister ids.
//!
//! Why the standardized surface is where real funds live: tokens are only
//! valuable if they can be exchanged or used, and the ICP ecosystem's
//! financial platforms (wallets like Oisy, exchanges like ICP Swap) integrate
//! ledgers through these standards — a token on a bespoke, non-standard
//! ledger can exist, but the ecosystem's platforms cannot hold or trade it,
//! so it carries little exchangeable value.
//!
//! Three scope notes, so nobody over-claims what this guard does:
//!
//!   * It is a guardrail enforcing a stated policy, not a hermetic seal — a
//!     bespoke canister can expose value-moving methods under any name (a
//!     custom swap method, an intermediary that forwards a transfer), which
//!     no name-based list can enumerate. The policy itself ("financial
//!     transactions are not supported") is stated in the server-level
//!     instructions (get_info); this guard enforces it for the standardized
//!     ledger surface, where real funds overwhelmingly live (see above).
//!   * Legacy pre-ICRC token standards (DIP20/EXT `transfer`/`transferFrom`/
//!     `approve` on arbitrary canisters) are deliberately NOT matched: the
//!     names are too abstract to block everywhere without breaking
//!     non-financial apps (per review), and those standards sit outside the
//!     ecosystem's ICRC-integrated platforms. The stated policy covers them.
//!   * The CMC's `notify_create_canister` / `notify_top_up` are deliberately
//!     NOT listed: they move no funds out of any account (they finalize a
//!     mint from ICP the ledger already holds for the CMC), and they are the
//!     recovery path when a user's own icp-CLI funding flow is interrupted
//!     mid-mint.

use candid::Principal;

/// ICRC-standard value-moving methods, refused on EVERY canister, matched
/// literally (the standards fix these exact names; Candid method names are
/// case-sensitive). Each entry carries the label used in the refusal message.
const DISALLOWED_ICRC_METHODS: &[(&str, &str)] = &[
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
];

/// The ICP ledger — its pre-ICRC methods move the user's ICP.
const ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
/// The cycles ledger — its withdrawal/creation methods move the user's cycles.
const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";

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
];

/// The financial-transactions gate: `Some(refusal)` when `method` on
/// `canister_id` is a disallowed ledger call, `None` when the call may
/// proceed. Matching is literal in both groups — the IC matches method names
/// by exact bytes, so a differently-spelled name would not reach the ledger
/// method anyway. The refusal is the complete tool error text — it names the
/// method, states the policy and why it exists, and tells the agent what to
/// recommend to the user instead.
pub fn disallowed_update_method(canister_id: &Principal, method: &str) -> Option<String> {
    let what = DISALLOWED_ICRC_METHODS
        .iter()
        .find(|(m, _)| *m == method)
        .map(|(_, what)| *what)
        .or_else(|| {
            let canister = canister_id.to_text();
            DISALLOWED_CANISTER_METHODS
                .iter()
                .find(|(c, m, _)| *c == canister && *m == method)
                .map(|(_, _, what)| *what)
        })?;
    // Every refusal points the user at doing the operation themselves:
    // canister creation at the user-run icp CLI (deliberately NOT at another
    // connector tool, per review), everything else at a user-controlled
    // wallet or frontend in the user's own browser.
    let instead = if method.starts_with("create_canister") {
        "Recommend that the user creates and funds canisters themselves with \
         the icp CLI in their own terminal (install with `npm install -g \
         @icp-sdk/icp-cli`, or see https://github.com/dfinity/icp-cli); the \
         skill://icp-cli and skill://cycles-management resources carry the \
         full guide."
    } else {
        "Recommend that the user performs this operation themselves, in a wallet \
         or app frontend they control, in their own web browser — e.g. their \
         wallet at https://oisy.com."
    };
    Some(format!(
        "`{method}` is {what} — a financial transaction. Financial transactions \
         (token transfers, spending approvals, payments, or trades) are not \
         supported by this server, to protect the user: asset-moving requests \
         are denied. {instead}"
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

    // Every ICRC-standard value-moving method is refused on ANY canister, in
    // its exact standard spelling.
    #[test]
    fn refuses_icrc_methods_on_every_canister() {
        for method in [
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
    // method (Candid method names are case-sensitive), so it is allowed here —
    // it could never reach the ledger method on chain anyway.
    #[test]
    fn matching_is_literal_not_normalized() {
        for method in ["ICRC1_Transfer", "icrc1-transfer", " icrc1_transfer ", "Transfer"] {
            assert!(
                disallowed_update_method(&icp_ledger(), method).is_none(),
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

    // The cycles ledger's canister-creation spends are refused on the generic
    // route, and their refusal points the user at running creation themselves
    // with the icp CLI (install pointer included) — never at a wallet (the
    // wrong venue for creation) and never at a connector tool (the dedicated
    // instructions-only creation tool is deferred from this version).
    #[test]
    fn refuses_cycles_ledger_creation_spends_with_cli_redirect() {
        for method in ["create_canister", "create_canister_from"] {
            let msg = disallowed_update_method(&cycles_ledger(), method)
                .unwrap_or_else(|| panic!("{method} must be refused"));
            assert!(msg.contains("icp CLI"), "{msg}");
            assert!(msg.contains("npm install -g @icp-sdk/icp-cli"), "{msg}");
            assert!(!msg.contains("icp_create_canister"), "no connector-tool redirect: {msg}");
            assert!(!msg.contains("oisy.com"), "a wallet is the wrong venue for creation: {msg}");
        }
    }

    // Reads, fees, metadata, the CMC recovery methods, and legacy DIP20-style
    // names on arbitrary canisters stay callable.
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

    // The refusal is the whole story: it names the method, states the policy
    // in plain terms an agent can relay (not supported, to protect the user —
    // no marketplace/compliance jargon, and no hint that another route might
    // work; per review), and redirects to a user-controlled wallet in the
    // browser (oisy.com). Pin those pieces so the message can't degrade.
    #[test]
    fn refusal_names_method_policy_and_wallet() {
        let msg = disallowed_update_method(&any_canister(), "icrc1_transfer")
            .expect("must be refused");
        assert!(msg.contains("`icrc1_transfer`"), "{msg}");
        assert!(msg.contains("financial transaction"), "{msg}");
        assert!(msg.contains("not supported"), "{msg}");
        assert!(msg.contains("to protect the user"), "{msg}");
        assert!(msg.contains("https://oisy.com"), "{msg}");
        assert!(!msg.contains("marketplace"), "{msg}");
        assert!(!msg.contains("compliance"), "{msg}");
    }
}
