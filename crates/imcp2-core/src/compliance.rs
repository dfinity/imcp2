//! The financial-transactions guard for the generic update-call tool.
//!
//! This server is not a financial tool: its purpose is reading, building, and
//! operating canisters, and the marketplace directories it is listed in
//! (Anthropic's Connectors Directory, OpenAI's plugins directory) prohibit a
//! connector from initiating or executing money or crypto transfers, or
//! trades, on the user's behalf. `canister_update_call` therefore refuses the
//! ledger methods that move value or grant spending rights, and the refusal
//! redirects the user to perform the operation themselves in a wallet or
//! frontend they control (e.g. <https://oisy.com>) in their own browser.
//!
//! The list leans on the fact that token ledgers on the Internet Computer
//! follow the ICRC standards — ICRC-1/ICRC-2 for fungible tokens (ICRC-4 for
//! batch transfers), ICRC-7/ICRC-37 for NFTs — whose method names are fixed
//! by the standard; plus the ICP ledger's pre-ICRC methods, the cycles
//! ledger's withdrawal methods, and the ERC-20-style names older IC token
//! standards (DIP20, EXT) use. Matching is by NORMALIZED name (lowercased,
//! separators stripped — see [`normalize`]), so `Transfer`, `transfer_from`,
//! and `transferFrom` all match, and it applies on ANY target canister:
//! whether a given canister really is a ledger cannot be established
//! reliably, and the cost of a false positive is only that the user is
//! pointed at their own wallet, the app's own frontend, or (for the
//! canister-creation spends) the dedicated icp_create_canister tool.
//!
//! Two scope notes, so nobody over-claims what this guard does:
//!
//!   * It is a guardrail enforcing a stated policy, not a hermetic seal — a
//!     bespoke canister can expose value-moving methods under any name (a
//!     custom swap method, an intermediary that forwards a transfer), which
//!     no name-based list can enumerate. The policy itself ("this server
//!     does not support financial transactions") is stated in the tool
//!     description; this guard enforces it for the standardized ledger
//!     surface, where real funds overwhelmingly live.
//!   * The CMC's `notify_create_canister` / `notify_top_up` are deliberately
//!     NOT listed: they move no funds out of any account (they finalize a
//!     mint from ICP the ledger already holds for the CMC), and blocking
//!     them would strand the documented recovery path for an interrupted
//!     `icp_create_canister` ICP funding flow.

/// Disallowed update methods in [`normalize`]d form, each with a short label
/// used in the refusal message. Grouped by the standard that fixes the name.
const DISALLOWED_METHODS: &[(&str, &str)] = &[
    // ICRC-1 / ICRC-2 / ICRC-4: fungible-token transfers, spending
    // approvals, and batch transfers (icrc1_transfer, icrc2_approve,
    // icrc2_transfer_from, icrc4_transfer_batch).
    ("icrc1transfer", "an ICRC-1 token transfer"),
    ("icrc2approve", "an ICRC-2 spending approval"),
    ("icrc2transferfrom", "an ICRC-2 delegated token transfer"),
    ("icrc4transferbatch", "an ICRC-4 batch token transfer"),
    // ICRC-7 / ICRC-37: NFT transfers and approval management
    // (icrc7_transfer, icrc37_transfer_from, icrc37_approve_tokens,
    // icrc37_approve_collection, icrc37_revoke_*_approvals).
    ("icrc7transfer", "an ICRC-7 NFT transfer"),
    ("icrc37transferfrom", "an ICRC-37 delegated NFT transfer"),
    ("icrc37approvetokens", "an ICRC-37 NFT spending approval"),
    ("icrc37approvecollection", "an ICRC-37 collection spending approval"),
    ("icrc37revoketokenapprovals", "an ICRC-37 NFT approval change"),
    ("icrc37revokecollectionapprovals", "an ICRC-37 collection approval change"),
    // The ICP ledger's pre-ICRC surface (transfer, send_dfx, notify_dfx).
    // `transfer` doubles as the DIP20/EXT transfer method.
    ("transfer", "a ledger token transfer"),
    ("senddfx", "a legacy ICP-ledger transfer"),
    ("notifydfx", "a legacy ICP-ledger transfer notification"),
    // The cycles ledger's value movement (withdraw, withdraw_from, and the
    // canister-creation spends create_canister / create_canister_from) — the
    // cycles ledger is ICRC-1/-2 plus these, and they all move the user's
    // cycles. Creation stays available through the dedicated
    // icp_create_canister tool; this closes the uncontrolled generic route.
    ("withdraw", "a cycles-ledger withdrawal"),
    ("withdrawfrom", "a cycles-ledger delegated withdrawal"),
    ("createcanister", "a cycles-ledger spend (canister creation)"),
    ("createcanisterfrom", "a cycles-ledger delegated spend (canister creation)"),
    // ERC-20-style names fixed by the older IC token standards (DIP20's
    // transferFrom/approve; `transfer` is already listed above).
    ("transferfrom", "a delegated token transfer"),
    ("approve", "a token spending approval"),
];

/// The financial-transactions gate: `Some(refusal)` when `method` is a
/// disallowed ledger method, `None` when the call may proceed. The refusal is
/// the complete tool error text — it names the method, states the policy and
/// why it exists, and tells the agent what to recommend to the user instead.
pub fn disallowed_update_method(method: &str) -> Option<String> {
    let normalized = normalize(method);
    let (_, what) = DISALLOWED_METHODS.iter().find(|(m, _)| *m == normalized)?;
    let method = method.trim();
    // Canister creation has a supported, purpose-built route, so its refusal
    // redirects there; everything else redirects to a user-controlled wallet
    // or frontend in the user's own browser.
    let instead = if normalized.starts_with("createcanister") {
        "For creating and funding the user's own canisters, use the dedicated \
         icp_create_canister tool (or the icp CLI) instead of calling the cycles \
         ledger through this generic tool."
    } else {
        "Recommend that the user performs this operation themselves, in a wallet \
         or app frontend they control, in their own web browser — e.g. their \
         wallet at https://oisy.com, or for governance the NNS dapp at \
         https://nns.ic0.app."
    };
    Some(format!(
        "`{method}` is {what} — a financial transaction — and this tool does not \
         initiate or execute financial transactions (token transfers, spending \
         approvals, payments, or trades) on the user's behalf. Methods defined by the \
         ICRC-1/ICRC-2 and related ledger standards are refused on every canister, \
         for marketplace compliance and user safety. {instead} Do not look for another \
         route to the same operation through this tool."
    ))
}

/// Normalize a method name for matching: keep ASCII alphanumerics only,
/// lowercased. Collapses the spelling variants one method name travels under
/// (`Transfer`, ` transfer `, `transfer_from`, `transferFrom`) without ever
/// matching a *different* name — matching is exact on the normalized form,
/// never a substring test.
fn normalize(method: &str) -> String {
    method
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every standardized value-moving method is refused, in its canonical
    // spelling and in the case/separator variants the normalizer collapses.
    #[test]
    fn refuses_ledger_transfer_and_approval_methods() {
        for method in [
            // ICRC fungible + batch
            "icrc1_transfer",
            "icrc2_approve",
            "icrc2_transfer_from",
            "icrc4_transfer_batch",
            // ICRC NFT
            "icrc7_transfer",
            "icrc37_transfer_from",
            "icrc37_approve_tokens",
            "icrc37_approve_collection",
            "icrc37_revoke_token_approvals",
            "icrc37_revoke_collection_approvals",
            // ICP ledger legacy + cycles ledger
            "transfer",
            "send_dfx",
            "notify_dfx",
            "withdraw",
            "withdraw_from",
            // ERC-20-style (DIP20/EXT)
            "transferFrom",
            "approve",
            // Variants that must not slip through the normalizer
            "Transfer",
            "ICRC1_Transfer",
            "  icrc2_approve  ",
            "icrc2-transfer-from",
        ] {
            assert!(
                disallowed_update_method(method).is_some(),
                "{method} must be refused"
            );
        }
    }

    // The cycles ledger's canister-creation spends are refused on the generic
    // route, and their refusal redirects to the purpose-built tool rather
    // than to a wallet.
    #[test]
    fn refuses_cycles_ledger_creation_spends_with_tool_redirect() {
        for method in ["create_canister", "create_canister_from", "CreateCanister"] {
            let msg = disallowed_update_method(method)
                .unwrap_or_else(|| panic!("{method} must be refused"));
            assert!(msg.contains("icp_create_canister"), "{msg}");
            assert!(!msg.contains("oisy.com"), "creation redirects to the tool, not a wallet: {msg}");
        }
    }

    // Reads, fees, metadata, and the CMC recovery methods stay callable: the
    // guard matches exactly (normalized), never by substring, so a name that
    // merely CONTAINS a blocked one is not a false positive.
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
        ] {
            assert!(
                disallowed_update_method(method).is_none(),
                "{method} must be allowed"
            );
        }
    }

    // The refusal is the whole story: it names the method, states the policy
    // (financial transactions, compliance + user safety), and redirects to a
    // user-controlled wallet in the browser (oisy.com), per the listing
    // requirements. Pin those pieces so the message can't degrade silently.
    #[test]
    fn refusal_names_method_policy_and_wallet() {
        let msg = disallowed_update_method("icrc1_transfer").expect("must be refused");
        assert!(msg.contains("`icrc1_transfer`"), "{msg}");
        assert!(msg.contains("financial transaction"), "{msg}");
        assert!(msg.contains("marketplace compliance and user safety"), "{msg}");
        assert!(msg.contains("https://oisy.com"), "{msg}");
        // The method is echoed trimmed, so a padded spelling can't inject
        // leading/trailing whitespace into the backticked name.
        let padded = disallowed_update_method("  transfer ").expect("must be refused");
        assert!(padded.contains("`transfer` is"), "{padded}");
    }
}
