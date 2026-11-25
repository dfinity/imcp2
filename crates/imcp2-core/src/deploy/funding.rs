//! Where the cycles a deploy spends come from: what `icp_funding_options`
//! reports.
//!
//! `icp_deploy` creates canisters from the cycles-ledger balance of the
//! principal it signs as ([`super::CLI_ORIGIN`]). When that balance is short
//! the user has to buy cycles, and this server neither sells them nor takes a
//! payment: its financial-operations policy (see [`crate::compliance`]) keeps
//! every payment in an interface the user controls. What it can say is how
//! much is there, to whom bought cycles must be delivered, and where they are
//! sold.
//!
//! It says so without knowing any one payment provider:
//!
//!   * **A provider is an app, named by its URL** ([`FundingProvider`]). The
//!     list ([`FUNDING_PROVIDERS`]) holds nothing of how a provider takes an
//!     order: no canister id, no method name, no price.
//!   * **How to order is the provider's to say**, through the
//!     service-discoverability layers the tools here already read. Its
//!     manifest at `/.well-known/ic-architecture` names its canisters, and is
//!     its operators' word that an agent may drive them; the canister's
//!     Candid interface gives the methods, and its API doc the flow. The
//!     agent reads them with `open_app` and `get_canister_api_doc` and calls
//!     with `canister_query` and `canister_update_call`, as for any app.
//!   * **Every provider's flow ends the same way** ([`STEPS`]): an order call
//!     that moves nothing and answers one payment URL, which the user opens
//!     to confirm a single payment on the provider's own page; the cycles
//!     are delivered to the account of [`FundingOptions::principal`], and
//!     `icp_deploy` creates canisters from it.
//!
//! So another provider is another entry in the list, and one that takes its
//! manifest down can no longer be ordered from, with no change here: the
//! manifest gates every call to its canisters (see
//! [`crate::discoverability`]).
//!
//! The order call is an ordinary `canister_update_call`, held to that tool's
//! guard like any other. That is a condition on what can be listed rather
//! than something to work around: a method that itself moved assets would be
//! refused by its name or by its canister's interface, and an order that
//! only records what the user is about to pay for, on a page of the
//! provider's, is neither.

use rmcp::schemars;
use serde::{Deserialize, Serialize};

use super::DEFAULT_CYCLES;

/// A service that sells cycles to the user: an Internet Computer app whose
/// canisters an agent can find and read from its URL alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundingProvider {
    /// What the user knows it as.
    pub name: &'static str,
    /// The app's URL: what `open_app` takes, and the origin whose
    /// `/.well-known/ic-architecture` declares the canister orders are made
    /// on.
    pub app_url: &'static str,
    /// How the user pays there, in a few words they can choose by.
    pub pays_with: &'static str,
}

/// The providers `icp_funding_options` lists, in the order it lists them.
///
/// What an entry takes, since listing one tells users of this server where
/// to spend money:
///
///   1. Its `app_url` serves a service-discoverability manifest that
///      declares the canister orders are made on, and that canister
///      publishes its Candid interface and an API doc
///      (`get_api_doc`/`getApiDoc`). Without them no tool here reaches it.
///   2. The API doc describes an order that names the amount and the
///      principal whose Cycles Ledger account is credited, that answers a
///      URL where the user confirms one payment, and whose status can be
///      read until the cycles are delivered.
///   3. The order call moves no assets itself, so `canister_update_call`'s
///      guard lets it through: no financial keyword in the method's name, no
///      ICRC-1 or ICRC-2 method on the canister.
///
/// Nothing provider-specific beyond these three fields belongs here. A fee,
/// a limit or a method name written into this list would go stale the day
/// the provider changed it; its API doc is read at the time of the order.
pub const FUNDING_PROVIDERS: &[FundingProvider] = &[FundingProvider {
    name: "CyclePay",
    // `www`: the bare domain redirects there and serves no manifest itself.
    app_url: "https://www.cyclepay.org",
    pays_with: "card, on Stripe's checkout page",
}];

/// What the cycles ledger takes from the balance for creating a canister,
/// over the cycles the canister is created with.
pub const CREATE_FEE: u128 = 100_000_000;

/// What an agent does with a provider, whichever it is: the steps
/// `icp_funding_options` returns with every answer. They name tools of this
/// server and nothing of any provider.
pub const STEPS: &[&str] = &[
    "Tell the user the balance and what is missing, show them the providers, and let them pick \
     one and how much to buy. Which provider and how much are theirs to decide.",
    "Call open_app with that provider's `app_url`, then get_canister_api_doc on the canister it \
     marks [declared] for orders. That guide is the provider's own: it says how to quote a \
     price and how to make an order.",
    "Following the guide, make an order whose cycles go to the Cycles Ledger account of \
     `principal`. Name that principal as the account to credit: the order is made as the \
     user's account at the provider, which is another principal. The order call takes no \
     payment and answers a payment URL.",
    "Give the user that URL as it is. They confirm one payment there, on the provider's page; \
     never ask for card details, which go to that page alone.",
    "Read the order's status as the guide says until the cycles are delivered, or call this \
     tool again for the balance. Then call icp_deploy.",
];

/// What to do when the steps cannot be followed.
const OTHERWISE: &str = "If open_app marks none of a provider's canisters [declared], or the \
    session cannot make update calls, the user can still buy on the provider's site, entering \
    `principal` as the Cycles Ledger account to credit.";

/// The icp library's words for a cycles-ledger balance that does not cover
/// the canister a deploy is creating (matched in lowercase).
const SHORT_OF_CYCLES: &str = "insufficient cycles";

/// What a deploy that ran short of cycles is told next, after its error.
const SHORT_OF_CYCLES_HINT: &str = "To add cycles: icp_funding_options reports the balance and \
    where the user can buy more. Write `canister_ids` back first, so that the next deploy \
    creates only what is still missing.";

/// Arguments of `icp_funding_options`.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct FundingOptionsArgs {
    /// How many canisters the deploy will create: those the project's
    /// environment declares that its canister-id mapping does not name yet.
    /// With it the answer says what the deploy needs and how much is
    /// missing. Omit it for the balance and the providers alone.
    #[serde(default)]
    pub canisters: Option<u32>,
    /// Cycles each new canister is created with: the `cycles` icp_deploy
    /// will be called with. Default 2 trillion, as there.
    #[serde(default)]
    pub cycles: Option<u64>,
}

/// A funding provider, as `icp_funding_options` returns it.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FundingProviderOutput {
    /// The provider's name.
    pub name: String,
    /// The provider's app URL: pass it to open_app.
    pub app_url: String,
    /// How the user pays there.
    pub pays_with: String,
}

/// Structured result of `icp_funding_options`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FundingOptions {
    /// The principal icp_deploy creates canisters as. Its Cycles Ledger
    /// account holds the balance, and is the account an order must credit.
    pub principal: String,
    /// That account's balance, in cycles (decimal digits).
    pub balance: String,
    /// What a deploy creating `canisters` canisters takes from the balance,
    /// in cycles: each canister's cycles and the ledger's fee for creating
    /// it. Absent when `canisters` was not given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needed: Option<String>,
    /// How many cycles of `needed` the balance does not cover; "0" when it
    /// covers them. Absent when `canisters` was not given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shortfall: Option<String>,
    /// Where the user can buy cycles.
    pub providers: Vec<FundingProviderOutput>,
    /// How to buy from one, whichever it is, in order.
    pub steps: Vec<String>,
}

impl FundingOptions {
    /// The answer for `principal`, whose account holds `balance` cycles,
    /// asked about a deploy that creates what `args` says.
    pub fn new(principal: String, balance: u128, args: &FundingOptionsArgs) -> Self {
        let needed = args.canisters.map(|canisters| {
            let each = u128::from(args.cycles.unwrap_or(DEFAULT_CYCLES));
            u128::from(canisters).saturating_mul(each.saturating_add(CREATE_FEE))
        });
        Self {
            principal,
            balance: balance.to_string(),
            needed: needed.map(|n| n.to_string()),
            shortfall: needed.map(|n| n.saturating_sub(balance).to_string()),
            providers: FUNDING_PROVIDERS
                .iter()
                .map(|p| FundingProviderOutput {
                    name: p.name.into(),
                    app_url: p.app_url.into(),
                    pays_with: p.pays_with.into(),
                })
                .collect(),
            steps: STEPS.iter().map(|s| (*s).into()).collect(),
        }
    }

    /// The human-readable rendering: the balance and whose it is, what is
    /// missing, the providers, the steps.
    pub fn human(&self) -> String {
        let mut text = format!(
            "Cycles for deploys: {}, on the Cycles Ledger account of {}, the principal \
             icp_deploy creates canisters as.",
            amount(&self.balance),
            self.principal
        );
        if let (Some(needed), Some(shortfall)) = (&self.needed, &self.shortfall) {
            text.push_str(&format!("\nThe deploy asked about needs {}: ", amount(needed)));
            text.push_str(&match shortfall.as_str() {
                "0" => "the balance covers it.".to_string(),
                short => format!("{} short.", amount(short)),
            });
        }
        text.push_str("\n\nWhere the user can buy cycles:");
        for provider in &self.providers {
            text.push_str(&format!(
                "\n- {} ({}): {}",
                provider.name, provider.app_url, provider.pays_with
            ));
        }
        text.push_str("\n\nHow, whichever the user picks:");
        for (n, step) in self.steps.iter().enumerate() {
            text.push_str(&format!("\n{}. {step}", n + 1));
        }
        text.push_str(&format!("\n\n{OTHERWISE}"));
        text
    }
}

/// A cycles ledger balance as [`crate::CyclesBalance`] carries it, which is
/// Candid's rendering of a `nat`: digits grouped by underscores.
pub(super) fn parse_cycles(balance: &str) -> Option<u128> {
    balance.replace('_', "").parse().ok()
}

/// `cycles`, a count in decimal digits, as a reader takes it in: in
/// trillions, the unit cycles are priced and talked about in, with the
/// exact count beside it.
fn amount(cycles: &str) -> String {
    match cycles.parse::<u128>() {
        Ok(n) => format!("{} ({cycles} cycles)", trillions(n)),
        Err(_) => format!("{cycles} cycles"),
    }
}

/// `cycles` in trillions, to four decimal places — the cycles ledger's fee
/// is one ten-thousandth of a trillion — rounded down, so that a balance is
/// never shown as more than it is, and without trailing zeros.
fn trillions(cycles: u128) -> String {
    const T: u128 = 1_000_000_000_000;
    let (whole, fraction) = (cycles / T, cycles % T / (T / 10_000));
    match format!("{fraction:04}").trim_end_matches('0') {
        "" => format!("{whole}T"),
        fraction => format!("{whole}.{fraction}T"),
    }
}

/// `error`, the reason a deploy gave for failing, followed by where cycles
/// are to be had when what it failed for is the balance: said in the error
/// itself or in a line of the deploy's `log`. Any other error is returned as
/// it is.
pub(super) fn with_funding_hint(error: &str, log: &[String]) -> String {
    let short = std::iter::once(error)
        .chain(log.iter().map(String::as_str))
        .any(|line| line.to_ascii_lowercase().contains(SHORT_OF_CYCLES));
    match short {
        true => format!("{error}\n{SHORT_OF_CYCLES_HINT}"),
        false => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked(canisters: Option<u32>, cycles: Option<u64>) -> FundingOptionsArgs {
        FundingOptionsArgs { canisters, cycles }
    }

    // An entry is an app URL and two phrases for the user: an https origin
    // as `open_app` takes one, with nothing after the host, and no two
    // entries alike. CyclePay is among them.
    #[test]
    fn the_providers_are_apps_named_by_their_origin() {
        assert!(FUNDING_PROVIDERS.iter().any(|p| p.name == "CyclePay"));
        for provider in FUNDING_PROVIDERS {
            let url = url::Url::parse(provider.app_url).expect("a URL");
            assert_eq!(url.scheme(), "https", "{provider:?}");
            assert_eq!(url.origin().ascii_serialization(), provider.app_url, "{provider:?}");
            assert!(!provider.name.is_empty() && !provider.pays_with.is_empty(), "{provider:?}");
        }
        for (n, provider) in FUNDING_PROVIDERS.iter().enumerate() {
            for other in &FUNDING_PROVIDERS[n + 1..] {
                assert_ne!(provider.name, other.name);
                assert_ne!(provider.app_url, other.app_url);
            }
        }
    }

    // What a deploy needs is each canister's cycles and the ledger's fee for
    // creating it; what is missing is that less the balance, and never less
    // than nothing. Not asked about a deploy, the answer says neither.
    #[test]
    fn the_shortfall_is_what_the_balance_does_not_cover() {
        let none = FundingOptions::new("aaaaa-aa".into(), 5, &asked(None, None));
        assert_eq!((none.balance.as_str(), &none.needed, &none.shortfall), ("5", &None, &None));

        let short = FundingOptions::new("aaaaa-aa".into(), 350_000_000_000, &asked(Some(2), None));
        assert_eq!(short.needed.as_deref(), Some("4000200000000"));
        assert_eq!(short.shortfall.as_deref(), Some("3650200000000"));

        let covered = FundingOptions::new(
            "aaaaa-aa".into(),
            3_000_000_000_000,
            &asked(Some(1), Some(1_000_000_000_000)),
        );
        assert_eq!(covered.needed.as_deref(), Some("1000100000000"));
        assert_eq!(covered.shortfall.as_deref(), Some("0"));

        // Nothing to create needs nothing, and numbers no deploy has do not
        // wrap.
        let nothing = FundingOptions::new("aaaaa-aa".into(), 0, &asked(Some(0), None));
        assert_eq!(nothing.shortfall.as_deref(), Some("0"));
        let huge =
            FundingOptions::new("aaaaa-aa".into(), 0, &asked(Some(u32::MAX), Some(u64::MAX)));
        assert!(huge.needed.is_some_and(|n| n.parse::<u128>().is_ok()));
    }

    // The text an agent without structured content reads carries the whole
    // answer: whose account, how much, what is missing, each provider with
    // its URL, and the steps in order.
    #[test]
    fn the_text_says_what_the_structure_does() {
        let options =
            FundingOptions::new("abcde-cai".into(), 350_000_000_000, &asked(Some(2), None));
        let text = options.human();
        assert!(text.contains("0.35T (350000000000 cycles)"), "{text}");
        assert!(text.contains("account of abcde-cai"), "{text}");
        assert!(text.contains("needs 4.0002T (4000200000000 cycles): 3.6502T"), "{text}");
        for provider in FUNDING_PROVIDERS {
            assert!(text.contains(&format!("- {} ({})", provider.name, provider.app_url)));
        }
        let at = |needle: &str| text.find(needle).unwrap_or_else(|| panic!("no `{needle}`"));
        assert!(at("1. Tell the user") < at("2. Call open_app"), "{text}");
        assert!(at("get_canister_api_doc") < at("payment URL"), "{text}");
        assert!(at("payment URL") < at("Then call icp_deploy"), "{text}");
        assert!(text.contains("on the provider's site"), "{text}");

        let covered =
            FundingOptions::new("abcde-cai".into(), 9_000_000_000_000, &asked(Some(1), None));
        assert!(covered.human().contains("the balance covers it"));
        let unasked = FundingOptions::new("abcde-cai".into(), 0, &asked(None, None));
        assert!(!unasked.human().contains("needs"), "{}", unasked.human());
    }

    // The steps are the same for every provider: they name this server's
    // tools and the principal to credit, and nothing a provider calls its
    // own.
    #[test]
    fn the_steps_name_no_provider() {
        let steps = STEPS.join(" ");
        for tool in ["open_app", "get_canister_api_doc", "icp_deploy"] {
            assert!(steps.contains(tool), "{tool}");
        }
        assert!(steps.contains("`principal`") && steps.contains("payment URL"));
        for provider in FUNDING_PROVIDERS {
            assert!(!steps.contains(provider.name), "{}", provider.name);
        }
        for theirs in ["create_order", "Stripe", "cyclepay"] {
            assert!(!steps.to_ascii_lowercase().contains(&theirs.to_ascii_lowercase()));
        }
    }

    #[test]
    fn cycles_read_in_trillions() {
        for (cycles, said) in [
            (0, "0T"),
            (2_000_000_000_000, "2T"),
            (350_000_000_000, "0.35T"),
            (4_000_200_000_000, "4.0002T"),
            (1_999_999_999_999, "1.9999T"),
            (99_999_999, "0T"),
            (13_700_000_000_000, "13.7T"),
        ] {
            assert_eq!(trillions(cycles), said);
        }
        assert_eq!(parse_cycles("2_000_000_000_000"), Some(2_000_000_000_000));
        assert_eq!(parse_cycles("0"), Some(0));
        assert_eq!(parse_cycles("two"), None);
    }

    // A deploy that failed for lack of cycles is told where to get them,
    // wherever the library said so: in the error, or in the log's line for
    // the canister it could not create. Any other failure reads as it did.
    #[test]
    fn a_deploy_short_of_cycles_is_told_of_the_funding_options() {
        let ledger = "Insufficient cycles. Requested: 2000000000000 cycles, available balance: \
                      5 cycles.";
        let in_error = with_funding_hint(&format!("create failed: {ledger}"), &[]);
        assert!(in_error.starts_with("create failed: Insufficient cycles"), "{in_error}");
        assert!(in_error.contains("icp_funding_options"), "{in_error}");

        let log = vec![format!("  create backend: failed: {ledger}")];
        let in_log = with_funding_hint("one canister failed", &log);
        assert!(in_log.contains("icp_funding_options"), "{in_log}");

        let other = with_funding_hint("install_code rejected", &["  create backend: ok".into()]);
        assert_eq!(other, "install_code rejected");
    }
}
