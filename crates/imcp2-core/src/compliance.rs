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
//! The guard has seven scopes — six decided from the request alone, before any
//! network work, and one decided from the canister's own declared interface
//! once `canister_update_call` has read it (the scopes are split per review so
//! that each refusal says only what its scope knows about the call):
//!
//!   * **Standardized value-moving methods, matched literally on every
//!     canister.** Token ledgers on the Internet Computer follow the ICRC
//!     standards — ICRC-1/ICRC-2 for fungible tokens (ICRC-4 for batch
//!     transfers), ICRC-7/ICRC-37 for NFTs — and the standards fix the exact
//!     method names. Candid method names are case-sensitive, so literal
//!     matching is both sufficient (the real ledgers use exactly these names)
//!     and precise (a differently-spelled name is not the standard method).
//!   * **Mixed-purpose entry points, matched literally on every canister.**
//!     The NNS/SNS governance interface fixes `manage_neuron`, the one method
//!     through which staked neurons are disbursed, split, and spawned — but
//!     also voted with, followed, and re-delayed. That covers every SNS DAO's
//!     governance (dozens exist and more launch by NNS proposal, so no
//!     per-DAO enumeration could stay current) as well as the NNS's. The
//!     method is refused as a whole rather than per command, so its refusal
//!     says exactly that instead of calling the caller's command a transfer.
//!   * **Abstract names, scoped to the system canister where they are
//!     financial.** `transfer` on the ICP ledger or `withdraw` on the cycles
//!     ledger moves the user's funds, so on those specific canister ids they
//!     get the precise register and label; on any other canister the same
//!     names fall to the keyword scope below, which refuses them by name with
//!     a register that claims less. The cycles-minting canister's whole
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
//!     used verbatim in the refusal. Because the rule is about the
//!     destination, the refusal says so and claims nothing about the call
//!     itself: `store` on a wallet backend is refused for where it goes, not
//!     for what it does (per review).
//!   * **ICRC ledger methods by name, refused on every canister.** A call
//!     addressed to any other `icrc1_*` / `icrc2_*` method — a balance read,
//!     the metadata, an allowance query invoked as an update — is refused
//!     before any network work: the caller is addressing the canister as an
//!     ICRC ledger, and a canister that provides those methods is a financial
//!     canister (next scope). The register disclaims the call: a balance read
//!     is not a transfer, and the guard says only that the name is a ledger
//!     method's.
//!   * **Financial keywords in the method name, refused on every canister.**
//!     A call whose method name contains a financial / crypto keyword
//!     (`transfer`, `withdraw`, `swap`, `trade`, `exchange`, `pay`, `buy`,
//!     `deposit`, … — [`FINANCIAL_KEYWORDS`]) is refused before any network
//!     work, modulo a literal list of exempt control-handover names
//!     ([`EXEMPT_METHODS`], `transfer_ownership` and its spellings). Matching
//!     is by WHOLE WORD: the name is split on `_`, `-`, digits and camelCase
//!     humps and lowercased, so `swapTokens`, `withdraw_all` and `Transfer`
//!     match while `payload`, `buyer` and `swapped` do not — a substring test
//!     would refuse every `set_payload`. The guard cannot know what an
//!     arbitrary app's `transfer` does, so the register says exactly that:
//!     the name is refused everywhere rather than judged app by app, and the
//!     call is not classified. Checked last of the request-only scopes, so a
//!     ledger-scoped name keeps its precise register and a listed canister
//!     keeps its destination register.
//!   * **Financial canisters detected from the canister itself, refused
//!     entirely.** Once the interface is in hand — the canister's own
//!     `candid:service`, else the caller-supplied `candid`, which
//!     `resolve_did` consults only when the canister publishes none, so it can
//!     only ADD a refusal — a canister whose declared interface provides ANY
//!     `icrc1_*` / `icrc2_*` method (a query such as `icrc1_balance_of`
//!     included) is a financial canister, and every update call to it gets the
//!     destination register, naming the standard(s) and the methods that
//!     established them. That covers every ICRC-1/ICRC-2 ledger — the ICP
//!     ledger, the cycles ledger, every SNS and chain-key ledger, every token
//!     built on the ic-icrc1 ledger — with no list to keep current. An update
//!     call NEEDS that published interface, so this scope always has it (per
//!     review and the maintainer's direction): a canister that publishes none
//!     — a CERTIFIED absence, the certificate proving the path is not in the
//!     state tree — one whose published text the parser cannot read, and one
//!     whose read FAILED (a transport, HTTP or certificate error) are each
//!     refused with [`unchecked_update_refusal`], which says which it was and
//!     what follows (publish the interface; retry). No update this server
//!     sends went unchecked, and no caller-supplied text is consulted for an
//!     update call (`canister_query` keeps its `candid` fallback: a query
//!     cannot commit state). Other ICRC token namespaces (`icrc4_`, `icrc7_`,
//!     `icrc37_`, `icrc152_`) are not detected this way; their value-moving
//!     names are refused literally above.
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
//!     instructions (get_info), and deliberately in no tool description —
//!     a policy paragraph inside `canister_update_call`'s description would
//!     read as a hint that the tool is usable for financial transactions.
//!     This guard enforces the policy for the standardized ledger surface,
//!     where real funds overwhelmingly live (see above), and — from the
//!     canister's own interface, which every update call must have published
//!     — for every canister that provides ICRC methods; a canister whose
//!     interface is missing, unreadable or failed to read gets no update call
//!     at all. What is not detected is a bespoke value-moving method under an
//!     unrelated name on a canister whose published interface is not a
//!     ledger's, and that limit is stated wherever the guard is described,
//!     never implied away.
//!     Likewise the canister list is curated and static, while exchanges
//!     create per-pair pool/farm canisters dynamically and new services
//!     launch: entries cover each service's central canisters (verified
//!     against the IC dashboard's registry and the services' own published
//!     sources), and the standardized-methods group plus the stated policy
//!     cover the rest.
//!   * Generic value-moving names (`transfer`, `withdraw`, `swap`, … on
//!     arbitrary canisters) were deliberately unmatched between #154 and the
//!     keyword scope: review on #154 found them too abstract to refuse
//!     everywhere without breaking non-financial apps, and this note recorded
//!     that the stated policy covered them. The maintainer reversed that:
//!     refusing a real ledger's, pool's or DIP20 token's method is worth more
//!     than allowing an app's non-financial one, so such names are now
//!     refused on every canister by whole-word keyword, with a register that
//!     says so rather than classifying the call, and a literal exemption list
//!     for the control-handover names. Still unlisted, on purpose: `approve`,
//!     `send`, `claim`, `reward`, `balance`, `token`, `wallet`, `ledger`,
//!     `order`, `fee`, `cycles` (ordinary app verbs and nouns far more often
//!     than value operations), and derived forms such as `payment` or
//!     `withdrawal` (one line each to add).

use candid::Principal;
use std::collections::BTreeSet;

/// Standardized value-moving methods, refused on EVERY canister, matched
/// literally (the ICRC token standards fix these exact names; Candid method
/// names are case-sensitive). Each entry carries the label used in the refusal
/// message, which says the call itself carries out that operation — so only
/// methods that do belong here (a mixed-purpose entry point goes in
/// [`MIXED_PURPOSE_METHODS`] instead).
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
];

/// Methods that are one entry point for both financial and non-financial
/// operations, refused on EVERY canister like the standardized names above but
/// with their own refusal register: the label says what the method covers, and
/// the message adds that the method is disabled as a whole rather than per
/// command, so the refusal is not a claim about the caller's particular call
/// (per review).
const MIXED_PURPOSE_METHODS: &[(&str, &str)] = &[(
    "manage_neuron",
    "the single entry point for every neuron operation on an NNS/SNS governance interface — \
     voting, following, and dissolve delay as well as disbursing, splitting, and spawning \
     staked tokens",
)];

/// The ICP ledger — its pre-ICRC methods move the user's ICP.
const ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
/// The cycles ledger — its withdrawal/creation methods move the user's cycles.
const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";
/// The NNS cycles-minting canister — its update methods complete a funding
/// operation (minting cycles against the user's ICP, or creating a canister
/// from it).
const CYCLES_MINTING_CANISTER: &str = "rkp4c-7iaaa-aaaaa-aaaca-cai";

/// Abstract method names refused on the specific system canister where they
/// are financial, with the precise label and register: (canister id, method,
/// label). On any other canister the ones that carry a financial keyword
/// (`transfer`, `withdraw`, `withdraw_from`, `notify_mint_cycles`) fall to
/// the keyword scope, whose refusal claims less; the rest are allowed there.
const DISALLOWED_CANISTER_METHODS: &[(&str, &str, &str)] = &[
    // The ICP ledger's pre-ICRC surface.
    (ICP_LEDGER, "transfer", "the ICP ledger's legacy transfer"),
    (ICP_LEDGER, "send_dfx", "a legacy ICP-ledger transfer"),
    (ICP_LEDGER, "notify_dfx", "a legacy ICP-ledger transfer notification"),
    // The cycles ledger's value movement beyond ICRC-1/-2 (which group one
    // already covers): withdrawals and the canister-creation spends. The
    // creation refusal points the user at running the operation themselves
    // with the icp CLI, which is where creating and funding canisters
    // happens — this server serves no tool for either.
    (CYCLES_LEDGER, "withdraw", "a cycles-ledger withdrawal"),
    (CYCLES_LEDGER, "withdraw_from", "a cycles-ledger delegated withdrawal"),
    (CYCLES_LEDGER, "create_canister", "a cycles-ledger spend (canister creation)"),
    (CYCLES_LEDGER, "create_canister_from", "a cycles-ledger delegated spend (canister creation)"),
    // The cycles-minting canister's user-callable update surface. Each call
    // completes a funding operation against ICP the user already sent; the
    // remaining methods on this canister are queries or NNS-only admin calls.
    (
        CYCLES_MINTING_CANISTER,
        "notify_top_up",
        "a cycles top-up completion (minting cycles for a canister)",
    ),
    (CYCLES_MINTING_CANISTER, "notify_create_canister", "a canister-creation payment completion"),
    (CYCLES_MINTING_CANISTER, "notify_mint_cycles", "a cycles mint to a cycles-ledger account"),
    (CYCLES_MINTING_CANISTER, "create_canister", "a canister creation paid with attached cycles"),
];

/// Where a refusal sends the user when the operation is not creation or
/// funding: outside this connector, deliberately without naming a venue (see
/// the module doc).
const NEUTRAL_REDIRECT: &str = "Recommend that the user performs this operation outside this \
     connector, in a trusted interface they control.";

/// Where a creation, funding, or cycles-minting refusal sends the user: their
/// own icp CLI, never a connector tool (this server serves none for any of
/// them). Worded for all three, since `notify_mint_cycles` mints cycles into a
/// cycles-ledger account rather than creating or funding a canister, and a
/// redirect naming only canisters would give that caller the wrong next step.
const CLI_REDIRECT: &str = "Recommend that the user performs this operation themselves with the \
     icp CLI in their own terminal — creating and funding canisters, and minting or topping up \
     cycles, is work they do there (install with `npm install -g @icp-sdk/icp-cli`, or see \
     https://github.com/dfinity/icp-cli); the skill://icp-cli and skill://cycles-management \
     resources carry the full guide.";

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
    // whose legacy `transfer` the keyword scope refuses everywhere; the list
    // still closes the rest of their surface) ---
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

/// The ICRC token-ledger namespaces, with the standard each names: a method
/// whose name starts with one of these prefixes is an ICRC-1 / ICRC-2 ledger
/// method, and a canister that provides one is a financial canister (see the
/// module doc). Literal prefixes WITH the underscore, so
/// `icrc10_supported_standards` (ICRC-10, a generic capability listing) and
/// `icrc21_canister_call_consent_message` (ICRC-21, consent messages) do not
/// match.
const ICRC_LEDGER_PREFIXES: &[(&str, &str)] = &[("icrc1_", "ICRC-1"), ("icrc2_", "ICRC-2")];

/// The ICRC-1 / ICRC-2 standard `method` is named for, if any.
fn icrc_ledger_standard(method: &str) -> Option<&'static str> {
    ICRC_LEDGER_PREFIXES.iter().find(|(prefix, _)| method.starts_with(prefix)).map(|(_, s)| *s)
}

/// How many of a financial canister's ICRC method names a refusal lists before
/// summarizing the rest — enough to make the evidence checkable against
/// `get_canister_candid`, not the whole ledger interface.
const MAX_LISTED_METHODS: usize = 5;

/// Financial / crypto keywords: a method whose name contains one of these as a
/// WHOLE WORD (see [`name_words`]) is refused on every canister. Admission
/// rule: a word that names a value operation and is rare as an ordinary app
/// verb. The first row is the maintainer's list; the second adds the value
/// verbs. Deliberately absent — ordinary app verbs and nouns far more often
/// than value operations: `approve`, `send`, `claim`, `reward`, `balance`,
/// `token`, `wallet`, `ledger`, `order`, `fee`, `cycles`; and derived forms
/// (`payment`, `payout`, `withdrawal`, `trading`, `staking`, plurals), which
/// whole-word matching does not reach — add a form here to match it.
const FINANCIAL_KEYWORDS: &[&str] = &[
    "trade",
    "swap",
    "transfer",
    "withdraw",
    "exchange",
    "pay",
    "buy",
    "deposit",
    "purchase",
    "sell",
    "mint",
    "burn",
    "stake",
    "unstake",
    "redeem",
    "refund",
    "liquidity",
    "allowance",
    "escrow",
    "loan",
    "lend",
    "borrow",
    "bridge",
];

/// Method names exempt from the keyword scope although they contain a keyword
/// — a control handover (of a canister, a record, an app), not a value
/// movement — matched LITERALLY, by exact bytes: `Transfer_Ownership` or
/// `transfer_ownership_v2` are not exempt. Every entry records where the name
/// comes from, so the list can be audited (per review): a name with no source
/// does not get in, and an entry whose source goes away goes with it.
const EXEMPT_METHODS: &[&str] = &[
    // The `Ownable` access-control convention — OpenZeppelin's Solidity
    // `transferOwnership(address)` — which app code ported from the EVM keeps
    // when it hands a canister's or a record's admin role to a new principal;
    // the snake_case form is the Rust (ic-cdk) spelling of the same method.
    // Kept at the maintainer's direction as the one control-handover name
    // worth exempting. No mainnet interface declaring either spelling has
    // been verified yet (the IC token standards use `setOwner` — DIP20,
    // Sonic — or `set_custodians` — DIP721 — which carry no keyword); should
    // a canister whose `transfer_ownership` moves VALUE turn up (an NFT
    // handover is one), the exemption goes. Controller handover has no entry:
    // on the Internet Computer a canister's controllers change through the
    // management canister's `update_settings`, never through an app method.
    "transfer_ownership",
    "transferOwnership",
];

/// The words of a method name, for whole-word keyword matching: maximal runs
/// of ASCII letters, split additionally at a lower→upper boundary and before
/// the last upper of an upper run that a lower follows (`HTTPRequest` →
/// `http`, `request`); digits and every other byte separate; each word
/// lowercased. So `swapTokens` → `swap`, `tokens`; `icrc1_transfer` → `icrc`,
/// `transfer`; `withdraw2` → `withdraw`; `payload` stays one word. The one
/// corner: an all-caps keyword with a lowercase plural (`SWAPs`) splits as
/// `swa`, `ps` and misses — no Internet Computer interface spells names that
/// way.
fn name_words(method: &str) -> Vec<String> {
    let chars: Vec<char> = method.chars().collect();
    let mut words = Vec::new();
    let mut current = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphabetic() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        if c.is_ascii_uppercase() && !current.is_empty() {
            let prev = chars[i - 1];
            let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
            if prev.is_ascii_lowercase() || (prev.is_ascii_uppercase() && next_is_lower) {
                words.push(std::mem::take(&mut current));
            }
        }
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// The first financial keyword `method` carries as a whole word, unless the
/// name is one of the literal [`EXEMPT_METHODS`].
pub(crate) fn financial_keyword(method: &str) -> Option<&'static str> {
    if EXEMPT_METHODS.contains(&method) {
        return None;
    }
    name_words(method)
        .into_iter()
        .find_map(|word| FINANCIAL_KEYWORDS.iter().copied().find(|keyword| *keyword == word))
}

/// The destination register: what is disallowed is the service the call goes
/// to, not this call, so the message says that and claims nothing about the
/// method (per review — `store` on a wallet backend is not a transfer). Shared
/// by the listed-canister blanket and the interface scope, so both carry the
/// same pinned phrases by construction.
fn destination_refusal(method: &str, service: &str, why: &str) -> String {
    format!(
        "`{method}` is an update call to {service} — {why}. Every state-changing \
         call to that service is refused, so this refusal does not mean this \
         particular call moves assets. State-changing calls to financial services \
         are not supported by this server, to protect the user. {NEUTRAL_REDIRECT}"
    )
}

/// The financial-transactions gate, the scopes decided from the request alone:
/// `Some(refusal)` when the call is disallowed, `None` when it may proceed.
/// Six scopes, checked in order: the mixed-purpose entry points and the
/// standardized value-moving method names (both refused on every canister),
/// the abstract names scoped to the system ledger where they are financial,
/// the finance-canister list — on a listed canister EVERY update method is
/// refused, so `None` never depends on the method name alone — a call
/// addressed to any other ICRC-1 / ICRC-2 ledger method by name, and, last, a
/// method name that carries a financial keyword as a whole word. The seventh
/// scope, decided from the canister's own declared interface, is
/// [`disallowed_update_on_ledger_interface`], which the tool runs once it has
/// read that interface. Method matching is literal — the IC matches method
/// names by exact bytes, so a differently-spelled name would not reach the
/// real method anyway.
///
/// The refusal is the complete tool error text, and each scope gets the
/// register that is true of it (per review — a refusal must not say more about
/// the caller's call than the guard actually knows):
///
///   * a value-moving method: the call itself carries out that operation;
///   * a mixed-purpose entry point: some of its commands move assets and the
///     method is disabled as a whole, so this call is not classified;
///   * a listed canister: every state-changing call to that service is
///     refused, which again says nothing about this particular call;
///   * a call addressed to an ICRC ledger method by name: the caller is
///     treating the canister as a ledger, so the call is refused and, again,
///     not classified;
///   * a keyword-named method: the name is refused on every canister rather
///     than judged app by app, so the call is not classified.
///
/// All five name the method, state the policy and why it exists, and tell the
/// agent what to recommend to the user instead: performing the operation
/// outside this connector in a trusted interface they control, or, for the
/// creation/funding methods, with their own icp CLI.
pub fn disallowed_update_method(canister_id: &Principal, method: &str) -> Option<String> {
    let canister = canister_id.to_text();
    // Method-level matches run first: their refusals carry the more specific
    // label and redirect (a creation spend points at the icp CLI). The
    // canister-level blanket below then catches every other update call on a
    // listed finance canister.
    //
    // The mixed-purpose entry points come first of all, so a governance call
    // gets the "disabled as a whole" wording even on a listed canister rather
    // than either message that would read as a finding about this call.
    if let Some((_, what)) = MIXED_PURPOSE_METHODS.iter().find(|(m, _)| *m == method) {
        return Some(format!(
            "`{method}` is {what}. Some of those commands move staked assets, so the \
             method is disabled as a whole rather than per command — this refusal does \
             not mean this particular call moves assets. Financial transactions (token \
             transfers, spending approvals, payments, or trades) are not supported by \
             this server, to protect the user. {NEUTRAL_REDIRECT}"
        ));
    }
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
        let instead =
            if CLI_REDIRECT_METHODS.contains(&method) { CLI_REDIRECT } else { NEUTRAL_REDIRECT };
        // These are the methods that ARE the operation, so the message says so
        // — the one register that may state what the call does.
        return Some(format!(
            "`{method}` is {what} — the call itself carries out that operation. \
             Financial transactions (token transfers, spending approvals, payments, \
             or trades) are not supported by this server, to protect the user. \
             {instead}"
        ));
    }
    // The blanket: what is disallowed here is the destination, not this call,
    // so the message says that and claims nothing about the method (per
    // review — `store` on a wallet backend is not a transfer).
    if let Some((_, service, why)) =
        DISALLOWED_FINANCE_CANISTERS.iter().find(|(c, _, _)| *c == canister)
    {
        return Some(destination_refusal(method, service, why));
    }
    // Last, a call addressed to an ICRC ledger method by name — any `icrc1_*` /
    // `icrc2_*` beyond the exact value-moving names above. The caller is
    // treating the canister as a ledger, which makes it a financial canister
    // (see `disallowed_update_on_ledger_interface`); the register disclaims the
    // call, since a balance read invoked as an update is not a transfer.
    if let Some(standard) = icrc_ledger_standard(method) {
        return Some(format!(
            "`{method}` is named as an {standard} ledger method. A canister that provides \
             ICRC-1 or ICRC-2 methods is treated as a financial service and update calls \
             to it are refused, so this refusal does not mean this particular call moves \
             assets. Financial transactions (token transfers, spending approvals, payments, \
             or trades) are not supported by this server, to protect the user. \
             {NEUTRAL_REDIRECT}"
        ));
    }
    // Last, a method name that carries a financial keyword — the weakest
    // evidence the guard acts on, so the weakest claim: the name is refused
    // everywhere rather than judged app by app, and nothing is said about what
    // this call does.
    let keyword = financial_keyword(method)?;
    Some(format!(
        "`{method}` has the financial keyword `{keyword}` in its name. Method names that \
         contain a financial keyword are refused on every canister rather than judged app \
         by app, so this refusal does not mean this particular call moves assets. \
         Financial transactions (token transfers, spending approvals, payments, or \
         trades) are not supported by this server, to protect the user. {NEUTRAL_REDIRECT}"
    ))
}

/// The interface scope of the gate, decided from the canister itself:
/// `Some(refusal)` when `declared` — the method names the canister's Candid
/// interface declares, as `calls::declared_methods` read them — includes an
/// ICRC-1 / ICRC-2 ledger method, `None` otherwise. A canister that provides
/// those methods is a financial canister, and EVERY update call to it is refused
/// with the destination register: the rule is about where the call goes, so the
/// message names the standard(s) and the methods that established them and
/// claims nothing about this call.
///
/// Runs only where the interface is legitimately in hand — after the
/// discoverability gate admitted the canister and `canister_update_call` read
/// the interface it encodes against — and AFTER [`disallowed_update_method`],
/// whose scopes are cheaper and more specific. A canister that publishes no
/// interface, one the parser cannot read, and a read that FAILED never reach
/// here: the caller refuses each with [`unchecked_update_refusal`], since an
/// update call needs the published interface.
pub fn disallowed_update_on_ledger_interface(
    method: &str,
    declared: &BTreeSet<String>,
) -> Option<String> {
    let ledger_methods: Vec<(&String, &'static str)> = declared
        .iter()
        .filter_map(|name| icrc_ledger_standard(name).map(|standard| (name, standard)))
        .collect();
    if ledger_methods.is_empty() {
        return None;
    }
    // The standards present, in the table's order ("ICRC-1 and ICRC-2").
    let standards = ICRC_LEDGER_PREFIXES
        .iter()
        .map(|(_, standard)| *standard)
        .filter(|standard| ledger_methods.iter().any(|(_, s)| s == standard))
        .collect::<Vec<_>>()
        .join(" and ");
    let mut listed = ledger_methods
        .iter()
        .take(MAX_LISTED_METHODS)
        .map(|(name, _)| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ");
    if ledger_methods.len() > MAX_LISTED_METHODS {
        listed.push_str(&format!(", and {} more", ledger_methods.len() - MAX_LISTED_METHODS));
    }
    let service =
        format!("a canister whose Candid interface declares {standards} ledger methods ({listed})");
    Some(destination_refusal(
        method,
        &service,
        "a canister that provides the ICRC token-ledger interface is treated as a financial \
         service as a whole",
    ))
}

/// Why `canister_update_call` has no interface to check a call against — each
/// a refusal, since an update call needs the canister's published interface,
/// and each with its own next step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MissingInterface {
    /// The canister publishes no `candid:service` (a certified absence), or
    /// publishes bytes that are not text.
    NotPublished,
    /// The canister publishes text this server's parser cannot read: not valid
    /// Candid, no service declared, or over the size / depth limits (CWE-674).
    Unreadable,
    /// The read failed — a transport, HTTP or certificate error — with its text.
    ReadFailed(String),
}

/// The refusal for an update whose target could not be checked: the interface
/// scope needs the canister's own published interface, and there is none in
/// hand — `missing` says why. Refused rather than sent unchecked (per review and
/// the maintainer's direction: a canister must publish its interface to receive
/// update calls, and a failed read must not be the way past the scope). The
/// register claims nothing about the call: the guard learned nothing about it.
pub fn unchecked_update_refusal(method: &str, missing: &MissingInterface) -> String {
    let (what, next) = match missing {
        MissingInterface::NotPublished => (
            "the canister publishes no Candid interface (no `candid:service` metadata)".to_string(),
            "A canister receives update calls through this server only once it publishes its \
             interface; this one does not.",
        ),
        MissingInterface::Unreadable => (
            "the canister's published Candid interface could not be read by this server (not \
             valid Candid, no service declared, or over its size or depth limits)"
                .to_string(),
            "Until the canister publishes a readable interface, no update call to it is sent.",
        ),
        MissingInterface::ReadFailed(error) => (
            format!("the canister's Candid interface could not be read ({error})"),
            "Retry: an error that persists means this server cannot reach the interface it \
             needs, or the canister id is not one the network routes.",
        ),
    };
    format!(
        "`{method}` was not sent: {what}. An update call is checked against the canister's \
         published interface before it is sent — a canister that provides the ICRC token-ledger \
         interface is treated as a financial service as a whole — and a call that cannot be \
         checked is refused rather than sent unchecked, to protect the user. This refusal is \
         about the missing interface, so it does not mean this particular call moves assets. \
         {next} {NEUTRAL_REDIRECT}"
    )
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

    /// The clause a listed-canister refusal must carry: the rule is about the
    /// destination, so the message states that rather than the call.
    const DESTINATION_RULE: &str = "Every state-changing call to that service is refused";
    /// The one claim only a value-moving method's refusal may make.
    const ITSELF: &str = "the call itself carries out that operation";
    /// The disclaimer every other register must carry.
    const NOT_THIS_CALL: &str = "does not mean this particular call moves assets";
    /// The clause the interface scope's refusal must carry: the evidence is what
    /// the canister itself declares.
    const INTERFACE_RULE: &str = "whose Candid interface declares";
    /// The clause the keyword scope's refusal must carry: the name is refused
    /// everywhere, which is all the guard knows.
    const NAME_RULE: &str = "refused on every canister rather than judged app by app";
    /// The clause the missing-interface refusal must carry: an update call needs
    /// the published interface, and the check could not run without it.
    const UNCHECKED_RULE: &str =
        "checked against the canister's published interface before it is sent";
    /// Every way an update call can lack the interface it needs.
    fn every_missing_interface() -> [MissingInterface; 3] {
        [
            MissingInterface::NotPublished,
            MissingInterface::Unreadable,
            MissingInterface::ReadFailed("The request timed out.".to_string()),
        ]
    }

    /// A declared method set, as `calls::declared_methods` would read it.
    fn declared(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
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

    // The standard names are matched literally: a differently-spelled name is
    // NOT the standard method (Candid method names are case-sensitive), so it
    // never gets the standard's label or the "the call itself" register. It is
    // still refused — by the keyword scope, which sees the word `transfer` in
    // every one of these spellings — but with the weaker, disclaiming register.
    #[test]
    fn standard_names_stay_literal_while_keywords_catch_variants() {
        for method in ["ICRC1_Transfer", "icrc1-transfer", " icrc1_transfer ", "Transfer"] {
            let msg = disallowed_update_method(&any_canister(), method).unwrap_or_else(|| {
                panic!("{method} carries the keyword transfer: must be refused")
            });
            assert!(msg.contains(NAME_RULE), "{msg}");
            assert!(!msg.contains(ITSELF), "{method} is not the standard spelling: {msg}");
            assert!(!msg.contains("an ICRC-1 token transfer"), "{msg}");
        }
    }

    // The system canisters' own names are refused there with the precise
    // register and label. Elsewhere, the ones that carry no financial keyword
    // stay allowed; the ones that do (`transfer`, `withdraw`, `withdraw_from`,
    // and `notify_mint_cycles` with its `mint`) fall to the keyword scope,
    // which refuses them by name with the weaker, disclaiming register — never
    // the system canister's label.
    #[test]
    fn system_canister_names_keep_their_register_and_scope() {
        for (canister, method) in [
            (icp_ledger(), "send_dfx"),
            (icp_ledger(), "notify_dfx"),
            (cycles_ledger(), "create_canister"),
            (cycles_ledger(), "create_canister_from"),
            (cmc(), "notify_top_up"),
            (cmc(), "notify_create_canister"),
            (cmc(), "create_canister"),
        ] {
            assert!(
                disallowed_update_method(&canister, method).is_some(),
                "{method} must be refused on its canister"
            );
            assert!(
                disallowed_update_method(&any_canister(), method).is_none(),
                "{method} must be allowed on an unrelated canister"
            );
        }
        for (canister, method, label) in [
            (icp_ledger(), "transfer", "the ICP ledger's legacy transfer"),
            (cycles_ledger(), "withdraw", "a cycles-ledger withdrawal"),
            (cycles_ledger(), "withdraw_from", "a cycles-ledger delegated withdrawal"),
            (cmc(), "notify_mint_cycles", "a cycles mint to a cycles-ledger account"),
        ] {
            let msg =
                disallowed_update_method(&canister, method).expect("refused on its own canister");
            assert!(msg.contains(label) && msg.contains(ITSELF), "{msg}");
            let msg = disallowed_update_method(&any_canister(), method).unwrap_or_else(|| {
                panic!("{method} carries a financial keyword: refused anywhere")
            });
            assert!(msg.contains(NAME_RULE), "{msg}");
            assert!(!msg.contains(label) && !msg.contains(ITSELF), "{msg}");
        }
    }

    // The creation and funding-completion calls — the cycles ledger's creation
    // spends and the cycles-minting canister's whole update surface — are
    // refused on the generic route, and their refusal points the user at
    // doing it themselves with the icp CLI (install pointer included), which
    // is also the recovery path for an interrupted mint. Never at a connector
    // tool: this server serves none for creating or funding a canister.
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

    // Reads and generic names on arbitrary canisters stay callable: a word
    // that merely contains a keyword (`payload`, `buyer`, `swapped`, `trader`)
    // is not that keyword, `approve`/`send`/`claim` are deliberately not
    // keywords, and the literal exemptions are control handovers. (An
    // ICRC-named read is refused — it addresses the canister as a ledger — and
    // `transfer_fee` is the keyword scope's accepted false positive.) The
    // cycles-minting canister's non-keyword names are here too: refused on the
    // CMC itself (above), an unrelated canister's method that shares the name
    // is not a funding completion.
    #[test]
    fn allows_non_financial_methods() {
        for method in [
            "get_transactions",
            "notify_create_canister",
            "notify_top_up",
            "greet",
            "set_name",
            "register_user",
            "http_request_update",
            "approve",
            "send",
            "claim",
            "set_payload",
            "upload_payload",
            "get_buyer",
            "swapped",
            "trader",
            "transfer_ownership",
            "transferOwnership",
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
    // operation happen outside this connector without naming a venue. What it
    // must NOT do is classify the call: `store` on a wallet backend is refused
    // because of where it goes, not because it moves anything (per review), so
    // the message says the destination rule out loud and says so explicitly.
    // (`swap` is a keyword too, so this loop also pins that a listed service's
    // destination register wins over the keyword scope's name register.)
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
                assert!(msg.contains(DESTINATION_RULE), "{msg}");
                assert!(
                    msg.contains("does not mean this particular call moves assets"),
                    "the destination rule must not be stated as a finding about \
                     this call: {msg}"
                );
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
        let msg =
            disallowed_update_method(&any_canister(), "icrc1_transfer").expect("must be refused");
        assert!(msg.contains("`icrc1_transfer`"), "{msg}");
        assert!(msg.contains("an ICRC-1 token transfer"), "{msg}");
        assert!(msg.contains("the call itself carries out that operation"), "{msg}");
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
    // dissolve delays as well as disbursing. The refusal says both halves —
    // what the entry point covers, and that it is disabled wholesale — and then
    // says in as many words that this call is not being classified (per
    // review), instead of calling every invocation a transfer.
    #[test]
    fn manage_neuron_refusal_explains_the_whole_surface() {
        let msg =
            disallowed_update_method(&any_canister(), "manage_neuron").expect("must be refused");
        assert!(msg.contains("voting, following, and dissolve delay"), "{msg}");
        assert!(msg.contains("disbursing, splitting, and spawning staked tokens"), "{msg}");
        assert!(msg.contains("disabled as a whole rather than per command"), "{msg}");
        assert!(msg.contains("does not mean this particular call moves assets"), "{msg}");
        assert!(
            !msg.contains("is a financial transaction")
                && !msg.contains("— a financial transaction"),
            "the caller's command is not classified as a transfer: {msg}"
        );
    }

    // One register per scope, and no scope borrows another's claim (per
    // review): only a value-moving method's refusal says the call carries out
    // the operation, while the mixed-purpose entry point and the listed
    // destination both disclaim it. Read the three side by side so a future
    // edit that collapses them back into one message fails here.
    #[test]
    fn each_scope_gets_the_refusal_register_that_is_true_of_it() {
        // A method that IS the operation: transfers, approvals, and the
        // funding completions that finish a payment.
        for (canister, method) in [
            (any_canister(), "icrc1_transfer"),
            (icp_ledger(), "transfer"),
            (cmc(), "notify_top_up"),
        ] {
            let msg = disallowed_update_method(&canister, method).expect("must be refused");
            assert!(msg.contains(ITSELF), "{msg}");
            assert!(!msg.contains(NOT_THIS_CALL), "{msg}");
        }

        // A mixed-purpose entry point: disabled as a whole, so the call is not
        // classified — and that holds even on a listed canister, where the
        // method-level register must win over the blanket.
        let listed = Principal::from_text(DISALLOWED_FINANCE_CANISTERS[0].0).unwrap();
        for canister in [any_canister(), listed] {
            let msg =
                disallowed_update_method(&canister, "manage_neuron").expect("must be refused");
            assert!(msg.contains("disabled as a whole rather than per command"), "{msg}");
            assert!(msg.contains(NOT_THIS_CALL), "{msg}");
            assert!(!msg.contains(ITSELF), "{msg}");
        }

        // A listed destination reached by an arbitrary method: the rule is
        // about the service, and the message says only that.
        let msg = disallowed_update_method(&listed, "store").expect("must be refused");
        assert!(msg.contains(DESTINATION_RULE), "{msg}");
        assert!(msg.contains(NOT_THIS_CALL), "{msg}");
        assert!(!msg.contains(ITSELF), "{msg}");

        // A financial canister detected from its own interface: the destination
        // register again, with the interface as the evidence.
        let ledger = declared(&["icrc1_transfer", "icrc1_balance_of", "set_message"]);
        let msg =
            disallowed_update_on_ledger_interface("set_message", &ledger).expect("must be refused");
        assert!(msg.contains(DESTINATION_RULE), "{msg}");
        assert!(msg.contains(NOT_THIS_CALL), "{msg}");
        assert!(msg.contains(INTERFACE_RULE), "{msg}");
        assert!(!msg.contains(ITSELF), "{msg}");

        // A call addressed to an ICRC ledger method by name, with no interface in
        // hand: disclaimed, and neither of the other two registers.
        let msg =
            disallowed_update_method(&any_canister(), "icrc1_balance_of").expect("must be refused");
        assert!(msg.contains(NOT_THIS_CALL), "{msg}");
        assert!(!msg.contains(ITSELF), "{msg}");
        assert!(!msg.contains(DESTINATION_RULE), "{msg}");

        // A keyword in the method name: refused everywhere rather than judged,
        // so disclaimed — and neither the operation nor the destination claim.
        let msg = disallowed_update_method(&any_canister(), "swapTokens").expect("must be refused");
        assert!(msg.contains(NAME_RULE), "{msg}");
        assert!(msg.contains(NOT_THIS_CALL), "{msg}");
        assert!(!msg.contains(ITSELF), "{msg}");
        assert!(!msg.contains(DESTINATION_RULE), "{msg}");
        // ...while the sharper scopes keep precedence over it: the ICP ledger's
        // own `transfer` is the operation, and `swap` on a listed exchange is
        // refused for its destination.
        let msg = disallowed_update_method(&icp_ledger(), "transfer").expect("must be refused");
        assert!(msg.contains(ITSELF) && !msg.contains(NAME_RULE), "{msg}");
        let msg = disallowed_update_method(&listed, "swap").expect("must be refused");
        assert!(msg.contains(DESTINATION_RULE) && !msg.contains(NAME_RULE), "{msg}");

        // No interface to check against — not published, unreadable, or a read
        // that failed: nothing was learned about the call or the canister, so
        // the message says only that the check could not run — disclaimed, and
        // none of the other registers.
        for missing in every_missing_interface() {
            let msg = unchecked_update_refusal("set_message", &missing);
            assert!(msg.contains(UNCHECKED_RULE), "{msg}");
            assert!(msg.contains(NOT_THIS_CALL), "{msg}");
            assert!(!msg.contains(ITSELF), "{msg}");
            assert!(!msg.contains(DESTINATION_RULE), "{msg}");
            assert!(!msg.contains(INTERFACE_RULE), "{msg}");
        }
    }

    // Whole-word splitting: snake_case, kebab-case, camelCase humps (an acronym
    // run keeps its last capital with the word that follows), digits and other
    // bytes as separators, everything lowercased.
    #[test]
    fn name_words_splits_snake_camel_and_digits() {
        let words = |m: &str| name_words(m);
        assert_eq!(words("swapTokens"), ["swap", "tokens"]);
        assert_eq!(words("withdraw_all"), ["withdraw", "all"]);
        assert_eq!(words("icrc1_transfer"), ["icrc", "transfer"]);
        assert_eq!(words("ICRC1Transfer"), ["icrc", "transfer"]);
        assert_eq!(words("Transfer"), ["transfer"]);
        assert_eq!(words("withdraw2"), ["withdraw"]);
        assert_eq!(words("payload"), ["payload"]);
        assert_eq!(words("transferOwnership"), ["transfer", "ownership"]);
        assert_eq!(words("HTTPRequest"), ["http", "request"]);
        assert_eq!(words("getHTTPResponse"), ["get", "http", "response"]);
        assert_eq!(words("icrc1-transfer"), ["icrc", "transfer"]);
        assert_eq!(words(" icrc1_transfer "), ["icrc", "transfer"]);
        assert!(words("").is_empty());
        assert!(words("42").is_empty());
    }

    // A keyword matches a whole word only — in any spelling convention — and
    // the literal exemptions are the one way around it.
    #[test]
    fn financial_keyword_matches_whole_words_only() {
        for (method, keyword) in [
            ("swapTokens", "swap"),
            ("withdraw_all", "withdraw"),
            ("icrc1_transfer", "transfer"),
            ("Transfer", "transfer"),
            ("TRANSFER", "transfer"),
            ("withdraw2", "withdraw"),
            ("pay_invoice", "pay"),
            ("buy_ticket", "buy"),
            ("exchange_rate", "exchange"),
            ("key_exchange", "exchange"),
            ("deposit_count", "deposit"),
            ("notify_mint_cycles", "mint"),
            ("icrc2_allowance", "allowance"),
            ("add_liquidity", "liquidity"),
            ("transfer_tokens_to_controller", "transfer"),
            ("transfer_controller", "transfer"),
            ("transferControllers", "transfer"),
            ("trade", "trade"),
        ] {
            assert_eq!(financial_keyword(method), Some(keyword), "{method}");
        }
        for method in [
            "payload",
            "set_payload",
            "buyer",
            "swapped",
            "trader",
            "get_transactions",
            "approve",
            "send",
            "claim",
            "process_payment",
            "transfer_ownership",
            "transferOwnership",
            "",
        ] {
            assert_eq!(financial_keyword(method), None, "{method}");
        }
    }

    // Every keyword refuses a method named for it on any canister, with the
    // name register: the method and the keyword named, the disclaimer, the
    // policy, the redirect, and no venue.
    #[test]
    fn refuses_keyword_names_on_every_canister() {
        for keyword in FINANCIAL_KEYWORDS {
            let method = format!("do_{keyword}_now");
            let msg = disallowed_update_method(&any_canister(), &method)
                .unwrap_or_else(|| panic!("{method} must be refused on any canister"));
            assert!(msg.contains(&format!("`{method}`")), "{msg}");
            assert!(msg.contains(&format!("keyword `{keyword}`")), "{msg}");
            assert!(msg.contains(NAME_RULE), "{msg}");
            assert!(msg.contains(NOT_THIS_CALL), "{msg}");
            assert!(!msg.contains(ITSELF), "{msg}");
            assert!(msg.contains("not supported by this server, to protect the user"), "{msg}");
            assert!(msg.contains("outside this connector"), "{msg}");
            assert!(msg.contains("trusted interface they control"), "{msg}");
            assert!(!msg.to_lowercase().contains("wallet"), "no venue may be named: {msg}");
            assert!(!msg.contains(".com"), "no venue may be named: {msg}");
            assert!(!msg.contains("marketplace"), "{msg}");
            assert!(!msg.contains("compliance"), "{msg}");
        }
    }

    // Exemptions are literal: the exact spellings pass, anything else that
    // contains the keyword does not.
    #[test]
    fn exemptions_are_literal() {
        for method in EXEMPT_METHODS {
            assert!(
                disallowed_update_method(&any_canister(), method).is_none(),
                "{method} is a literal exemption"
            );
        }
        for method in ["Transfer_Ownership", "transfer_ownership_v2", "transfer_owner"] {
            let msg = disallowed_update_method(&any_canister(), method)
                .unwrap_or_else(|| panic!("{method} is not literally exempt"));
            assert!(msg.contains(NAME_RULE), "{msg}");
        }
    }

    // The lists stay well-formed: keywords unique, lowercase, alphabetic, and
    // none of them a word of the mixed-purpose entry point (one register per
    // name); every exemption unique and actually carrying a keyword, so no
    // entry is dead.
    #[test]
    fn keyword_and_exemption_lists_are_well_formed() {
        let mut keywords: Vec<&str> = FINANCIAL_KEYWORDS.to_vec();
        for keyword in &keywords {
            assert!(
                !keyword.is_empty() && keyword.chars().all(|c| c.is_ascii_lowercase()),
                "{keyword}"
            );
        }
        let total = keywords.len();
        keywords.sort_unstable();
        keywords.dedup();
        assert_eq!(keywords.len(), total, "duplicate keywords");
        for (method, _) in MIXED_PURPOSE_METHODS {
            assert_eq!(financial_keyword(method), None, "{method} has its own register");
        }
        let mut exempt: Vec<&str> = EXEMPT_METHODS.to_vec();
        for method in &exempt {
            let words = name_words(method);
            assert!(
                words.iter().any(|w| FINANCIAL_KEYWORDS.contains(&w.as_str())),
                "{method} carries no keyword, so the exemption is dead"
            );
        }
        let total = exempt.len();
        exempt.sort_unstable();
        exempt.dedup();
        assert_eq!(exempt.len(), total, "duplicate exemptions");
    }

    // A canister that provides an ICRC-1 / ICRC-2 method is a financial canister:
    // every update call to it is refused, whatever the method is called, and the
    // refusal names the standard(s) and the methods that established them —
    // enough to check against get_canister_candid, summarizing the rest.
    #[test]
    fn an_icrc_interface_makes_every_update_refused() {
        let ledger = declared(&["greet", "set_message", "icrc1_transfer", "icrc1_balance_of"]);
        for method in ["set_message", "greet", "http_request_update"] {
            let msg = disallowed_update_on_ledger_interface(method, &ledger)
                .unwrap_or_else(|| panic!("{method} on an ICRC-1 canister must be refused"));
            assert!(msg.contains(&format!("`{method}`")), "{msg}");
            assert!(msg.contains("ICRC-1 ledger methods"), "{msg}");
            assert!(
                msg.contains("`icrc1_balance_of`") && msg.contains("`icrc1_transfer`"),
                "{msg}"
            );
        }
        let approvals = declared(&["icrc2_allowance", "set_message"]);
        let msg = disallowed_update_on_ledger_interface("set_message", &approvals).unwrap();
        assert!(msg.contains("ICRC-2 ledger methods (`icrc2_allowance`)"), "{msg}");
        let both = declared(&["icrc1_transfer", "icrc2_approve", "x"]);
        let msg = disallowed_update_on_ledger_interface("x", &both).unwrap();
        assert!(msg.contains("ICRC-1 and ICRC-2 ledger methods"), "{msg}");
        // Seven ICRC names: five are listed, the rest counted.
        let many = declared(&[
            "icrc1_name",
            "icrc1_symbol",
            "icrc1_decimals",
            "icrc1_fee",
            "icrc1_metadata",
            "icrc1_total_supply",
            "icrc1_transfer",
            "store",
        ]);
        let msg = disallowed_update_on_ledger_interface("store", &many).unwrap();
        assert!(msg.contains(", and 2 more)"), "{msg}");
        assert_eq!(msg.matches("`icrc1_").count(), 5, "{msg}");
        // The real ICP ledger's surface (the methods of its service constructor).
        let icp = declared(&[
            "transfer",
            "account_balance",
            "transfer_fee",
            "send_dfx",
            "account_balance_dfx",
            "query_blocks",
            "icrc1_balance_of",
            "icrc1_transfer",
            "icrc2_approve",
            "icrc2_transfer_from",
            "icrc21_canister_call_consent_message",
            "icrc10_supported_standards",
        ]);
        let msg = disallowed_update_on_ledger_interface("remove_approval", &icp).unwrap();
        assert!(msg.contains("ICRC-1 and ICRC-2 ledger methods"), "{msg}");
    }

    // The rule is "provides an ICRC-1 / ICRC-2 function", not "implements the
    // standard": a lone query such as icrc1_balance_of is enough.
    #[test]
    fn a_query_only_icrc_method_still_counts() {
        let index = declared(&["icrc1_balance_of", "get_message", "set_message"]);
        assert!(disallowed_update_on_ledger_interface("set_message", &index).is_some());
    }

    // The prefixes are literal, underscore included: the generic ICRC-10 listing
    // and the ICRC-21 consent message are not ledger methods, nor are other
    // token namespaces, re-spellings, or a name that merely contains the prefix.
    // The e2e `app` fixture (greet/whoami/get_message/set_message/get_api_doc)
    // is the plain shape that must stay callable.
    #[test]
    fn icrc_prefixes_are_literal() {
        for names in [
            vec!["icrc10_supported_standards", "set_message"],
            vec!["icrc21_canister_call_consent_message", "set_message"],
            vec!["icrc7_transfer", "set_message"],
            vec!["ICRC1_transfer", "set_message"],
            vec!["my_icrc1_transfer", "set_message"],
            vec!["greet", "whoami", "get_message", "set_message", "get_api_doc"],
            vec![],
        ] {
            let set = declared(&names);
            assert_eq!(
                disallowed_update_on_ledger_interface("set_message", &set),
                None,
                "{names:?} must not be a financial canister"
            );
        }
    }

    // The interface refusal is the destination register, in the same plain
    // protective terms as the listed-canister one: it names the method, the
    // standard, the policy, and the redirect, claims nothing about this call,
    // and names no venue.
    #[test]
    fn ledger_interface_refusal_uses_the_destination_register() {
        let ledger = declared(&["icrc1_transfer", "icrc1_balance_of", "set_message"]);
        let msg =
            disallowed_update_on_ledger_interface("set_message", &ledger).expect("must be refused");
        assert!(msg.contains("`set_message`"), "{msg}");
        assert!(msg.contains(INTERFACE_RULE), "{msg}");
        assert!(msg.contains("ICRC-1 ledger methods"), "{msg}");
        assert!(msg.contains(DESTINATION_RULE), "{msg}");
        assert!(msg.contains(NOT_THIS_CALL), "{msg}");
        assert!(!msg.contains(ITSELF), "{msg}");
        assert!(msg.contains("not supported by this server, to protect the user"), "{msg}");
        assert!(msg.contains("outside this connector"), "{msg}");
        assert!(msg.contains("trusted interface they control"), "{msg}");
        assert!(!msg.to_lowercase().contains("wallet"), "no venue may be named: {msg}");
        assert!(!msg.contains(".com"), "no venue may be named: {msg}");
        assert!(!msg.contains("marketplace"), "{msg}");
        assert!(!msg.contains("compliance"), "{msg}");
    }

    // An update call needs the canister's published interface. Without one —
    // not published, published but unreadable, or a read that FAILED — the call
    // is refused with a message that names the method, says which it was and
    // what follows (publish it; retry only for the failed read), claims nothing
    // about the call — the guard learned nothing about it — and names no venue.
    #[test]
    fn an_update_without_a_readable_interface_is_refused() {
        for missing in every_missing_interface() {
            let msg = unchecked_update_refusal("set_message", &missing);
            assert!(msg.contains("`set_message`"), "{msg}");
            assert!(msg.contains("was not sent"), "{msg}");
            assert!(msg.contains(UNCHECKED_RULE), "{msg}");
            assert!(msg.contains(NOT_THIS_CALL), "{msg}");
            assert!(!msg.contains(ITSELF), "{msg}");
            assert!(!msg.contains(DESTINATION_RULE), "{msg}");
            assert!(!msg.contains(INTERFACE_RULE), "{msg}");
            assert!(msg.contains("to protect the user"), "{msg}");
            assert!(msg.contains("outside this connector"), "{msg}");
            assert!(msg.contains("trusted interface they control"), "{msg}");
            assert!(!msg.to_lowercase().contains("wallet"), "no venue may be named: {msg}");
            assert!(!msg.contains(".com"), "no venue may be named: {msg}");
            assert!(!msg.contains("marketplace"), "{msg}");
            assert!(!msg.contains("compliance"), "{msg}");
            match missing {
                MissingInterface::NotPublished => {
                    assert!(msg.contains("publishes no Candid interface"), "{msg}");
                    assert!(msg.contains("only once it publishes its interface"), "{msg}");
                    assert!(!msg.contains("Retry"), "nothing to retry: {msg}");
                }
                MissingInterface::Unreadable => {
                    assert!(msg.contains("could not be read by this server"), "{msg}");
                    assert!(msg.contains("publishes a readable interface"), "{msg}");
                    assert!(!msg.contains("Retry"), "nothing to retry: {msg}");
                }
                MissingInterface::ReadFailed(error) => {
                    assert!(msg.contains(&error), "the error is named: {msg}");
                    assert!(msg.contains("Retry"), "{msg}");
                    assert!(msg.contains("canister id is not one the network routes"), "{msg}");
                }
            }
        }
    }

    // Addressing a canister by an ICRC-1 / ICRC-2 method name is refused before
    // any network work, even when no interface says the canister provides it:
    // the caller is treating it as a ledger. The exact transfer/approval names
    // keep their sharper register (they ARE the operation); the rest get the
    // disclaiming one; ICRC-10 / ICRC-21 names and other token namespaces are
    // not ledger methods here.
    #[test]
    fn icrc_named_calls_are_refused_pre_network() {
        for method in ["icrc1_balance_of", "icrc1_metadata", "icrc1_fee", "icrc2_allowance"] {
            let msg = disallowed_update_method(&any_canister(), method)
                .unwrap_or_else(|| panic!("{method} must be refused on any canister"));
            assert!(msg.contains(&format!("`{method}`")), "{msg}");
            assert!(msg.contains("ledger method"), "{msg}");
            assert!(msg.contains(NOT_THIS_CALL), "{msg}");
            assert!(!msg.contains(ITSELF), "{msg}");
            assert!(msg.contains("to protect the user"), "{msg}");
            assert!(msg.contains("outside this connector"), "{msg}");
        }
        let msg = disallowed_update_method(&any_canister(), "icrc1_transfer").unwrap();
        assert!(msg.contains(ITSELF), "{msg}");
        for method in [
            "icrc10_supported_standards",
            "icrc21_canister_call_consent_message",
            "icrc7_balance_of",
            "ICRC1_balance_of",
        ] {
            assert!(
                disallowed_update_method(&any_canister(), method).is_none(),
                "{method} is not an ICRC-1 / ICRC-2 ledger method"
            );
        }
    }
}
