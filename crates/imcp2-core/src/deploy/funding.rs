//! Where the cycles a deploy spends come from: what `icp_deploy` says of
//! funding, in its description and in the answer of a deploy that ran short.
//!
//! `icp_deploy` creates canisters from the cycles-ledger balance of the
//! principal it signs as ([`super::CLI_ORIGIN`]). When that balance is short
//! the user has to buy cycles, and this server neither sells them nor takes a
//! payment: its financial-operations policy (see [`crate::compliance`]) keeps
//! every payment in an interface the user controls. What it can say is to
//! whom bought cycles must be delivered, how many are missing, and where they
//! are sold.
//!
//! It says so in the deploy tool itself, with no tool of its own:
//!
//!   * **The tool's description names the providers** ([`advertised`]), so
//!     an agent can tell the user where cycles are sold before it deploys.
//!   * **A deploy the balance did not cover answers with [`Funding`]**: the
//!     principal to credit, what the canisters still to create need, the
//!     providers, and the steps. It is attached when the cycles ledger
//!     itself refused a creation ([`ran_short`]) and never on a guess made
//!     beforehand: a canister on a cloud engine is not paid for from the
//!     ledger at all, so a balance checked ahead of the deploy would refuse
//!     deploys that were going to succeed.
//!
//! And without knowing any one payment provider:
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
//!     are delivered to the account of [`Funding::principal`], and the next
//!     `icp_deploy` creates canisters from it.
//!
//! So another provider is another entry in the list, and one that takes its
//! manifest down can no longer be ordered from, with no change here: the
//! manifest gates every call to its canisters (see
//! [`crate::discoverability`]).
//!
//! The order call is an ordinary `canister_update_call`, held to that tool's
//! guard like any other, with no exemption. Passing the guard is what lets
//! an order be made here at all; it is not what makes a provider fit to
//! list. The guard refuses the standard ledger methods and the financial
//! names, and says of itself that it cannot tell a bespoke value-moving
//! method under another name (see [`crate::compliance`]). That an order
//! takes no payment and moves no assets is therefore established for each
//! provider when its entry is reviewed, from what its method does, and never
//! inferred from the guard having let the call through.

use std::{sync::Arc, time::Duration};

use candid::Principal;
use ic_agent::identity::AnonymousIdentity;
use rmcp::schemars;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use super::{run::mainnet_agent, DeployOutcome, Status};
use crate::cycles_balance_of;

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

/// The providers `icp_deploy` names, in the order it names them.
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
///   3. The order call itself takes no payment and moves no assets: it
///      records what the user is about to pay for, on a page of the
///      provider's. Whoever reviews the entry checks this independently of
///      the guard, from what the method does: the canister's source where
///      it is published, its interface and API doc, and an order made and
///      watched. The guard passing the call shows nothing of the kind: it
///      cannot tell a bespoke value-moving method under an ordinary name,
///      such as one that spends an allowance the user gave elsewhere.
///   4. `canister_update_call`'s guard does let the order through, or it
///      could not be made here: no financial keyword in the method's name,
///      no ICRC-1 or ICRC-2 method on the canister.
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

/// What an agent does with a provider, whichever it is: the steps a deploy
/// that ran short answers with. They name tools of this server and nothing
/// of any provider.
pub const STEPS: &[&str] = &[
    "Write `canister_ids` back to the project first: it holds what this deploy did create, \
     and the next deploy creates only what is missing.",
    "Tell the user what is missing, show them the providers, and let them pick one and how \
     much to buy. Which provider and how much are theirs to decide.",
    "Call open_app with that provider's `app_url`, then get_canister_api_doc on the canister it \
     marks [declared] for orders. That guide is the provider's own: it says how to quote a \
     price and how to make an order.",
    "Following the guide, make an order whose cycles go to the Cycles Ledger account of \
     `principal`. Name that principal as the account to credit: the order is made as the \
     user's account at the provider, which is another principal. The order call takes no \
     payment and answers a payment URL.",
    "Give the user that URL as it is. They confirm one payment there, on the provider's page; \
     never ask for card details, which go to that page alone.",
    "Read the order's status as the guide says until the cycles are delivered. Then call \
     icp_deploy again with the same environment and settings as this deploy, and the mapping \
     from the first step. If this server takes the bundle by upload, upload it again first \
     and pass the new upload id: the upload this deploy was given is spent.",
];

/// What to do when the steps cannot be followed.
const OTHERWISE: &str = "If open_app marks none of a provider's canisters [declared], or the \
    session cannot make update calls, the user can still buy on the provider's site, entering \
    `principal` as the Cycles Ledger account to credit.";

/// The icp library's words for the cycles ledger refusing to create a
/// canister because the balance does not cover it: both are in the one
/// message, and in no other the library has. (Its refusal of a withdrawal
/// starts alike and says `balance`, not `available balance`; a canister that
/// has run out says `out of cycles`.) The library turns the ledger's typed
/// error into this text before a deploy sees it, so the text is the signal.
const SHORT_OF_CYCLES: [&str; 2] = ["Insufficient cycles. Requested:", "available balance:"];

/// How long a deploy that ran short waits to learn the balance as it now
/// is. The answer says where cycles are sold with or without it.
const BALANCE_WAIT: Duration = Duration::from_secs(10);

/// The sentence `icp_deploy`'s description ends with: where cycles are sold,
/// from the list, so that the two cannot differ.
pub fn advertised() -> String {
    let providers: Vec<String> =
        FUNDING_PROVIDERS.iter().map(|p| format!("{} ({})", p.name, p.app_url)).collect();
    format!(" Cycles are sold at: {}.", providers.join(", "))
}

/// Whether `outcome` is that of a deploy the balance did not cover: one that
/// failed with a canister still to create, and with the cycles ledger's
/// refusal of a creation in its error or in the log's line for that
/// canister. Cycles mentioned by any other failure (an install, a sync) are
/// not it, and neither is a deploy with nothing left to create, which no
/// purchase would help. A deploy that was interrupted is not one either,
/// whatever its log says.
pub(super) fn ran_short(outcome: &DeployOutcome) -> bool {
    outcome.status == Status::Failed
        && still_to_create(outcome) > 0
        && outcome
            .error
            .iter()
            .chain(&outcome.log)
            .any(|line| SHORT_OF_CYCLES.iter().all(|words| line.contains(words)))
}

/// A funding provider, as a deploy's answer returns it.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FundingProviderOutput {
    /// The provider's name.
    pub name: String,
    /// The provider's app URL: pass it to open_app.
    pub app_url: String,
    /// How the user pays there.
    pub pays_with: String,
}

/// How to fund a deploy the cycles balance did not cover: part of
/// `icp_deploy`'s answer when it failed for that.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Funding {
    /// The principal icp_deploy creates canisters as. Its Cycles Ledger
    /// account holds the balance, and is the account an order must credit.
    pub principal: String,
    /// What creating the canisters this deploy did not create takes from
    /// the balance, in cycles (decimal digits): each canister's cycles and
    /// the ledger's fee for creating it.
    pub needed: String,
    /// The account's balance after the deploy, in cycles. Absent when it
    /// could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<String>,
    /// How many cycles of `needed` the balance does not cover: what the
    /// user has to buy, at the least. Absent when the balance is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shortfall: Option<String>,
    /// Where the user can buy cycles.
    pub providers: Vec<FundingProviderOutput>,
    /// How to buy from one, whichever it is, in order.
    pub steps: Vec<String>,
}

impl Funding {
    /// What funding takes for `principal`, whose deploy left `to_create`
    /// canisters uncreated at `cycles` each, and whose account holds
    /// `balance` now, if that is known.
    pub fn new(
        principal: Principal,
        to_create: usize,
        cycles: u128,
        balance: Option<u128>,
    ) -> Self {
        let needed = (to_create as u128).saturating_mul(cycles.saturating_add(CREATE_FEE));
        Self {
            principal: principal.to_text(),
            needed: needed.to_string(),
            balance: balance.map(|b| b.to_string()),
            shortfall: balance.map(|b| needed.saturating_sub(b).to_string()),
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

    /// What funding takes after `outcome`, a deploy as `principal` that
    /// created canisters with `cycles` each and ran short. The balance is
    /// read as it now is, and left out if the ledger does not answer in
    /// time or `stop` is cancelled first: the deploy still holds its slot,
    /// and a server told to stop does not wait on a number the answer can
    /// do without.
    pub(super) async fn after(
        outcome: &DeployOutcome,
        principal: Principal,
        cycles: u128,
        stop: &CancellationToken,
    ) -> Self {
        let balance = balance_within(BALANCE_WAIT, stop, balance_of(principal)).await;
        Self::new(principal, still_to_create(outcome), cycles, balance)
    }

    /// The human-readable rendering: what is missing, whose account, the
    /// providers, the steps.
    pub fn human(&self) -> String {
        let mut text = format!(
            "The cycles balance did not cover this deploy. Creating the canisters still \
             missing takes {}",
            amount(&self.needed)
        );
        match (&self.balance, &self.shortfall) {
            (Some(balance), Some(shortfall)) => text.push_str(&format!(
                "; the balance is {}, so at least {} more are needed.",
                amount(balance),
                amount(shortfall)
            )),
            _ => text.push('.'),
        }
        text.push_str(&format!(
            "\nThe balance is that of the Cycles Ledger account of {}, the principal \
             icp_deploy creates canisters as: bought cycles must be delivered there.",
            self.principal
        ));
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

/// `read`'s balance, if it comes within `wait` and before `stop` is
/// cancelled. A stop already asked for comes first.
async fn balance_within(
    wait: Duration,
    stop: &CancellationToken,
    read: impl std::future::Future<Output = Result<u128, String>>,
) -> Option<u128> {
    tokio::select! {
        biased;
        _ = stop.cancelled() => {
            tracing::info!("stopped before the cycles balance was read");
            None
        }
        read = tokio::time::timeout(wait, read) => match read {
            Ok(Ok(balance)) => Some(balance),
            Ok(Err(e)) => {
                tracing::warn!("the cycles balance could not be read: {e}");
                None
            }
            Err(_) => {
                tracing::warn!("the cycles balance was not read in time");
                None
            }
        },
    }
}

/// How many canisters `outcome`'s deploy has yet to create: those it
/// targeted and has no id for.
fn still_to_create(outcome: &DeployOutcome) -> usize {
    outcome.canisters.iter().filter(|c| !outcome.canister_ids.contains_key(*c)).count()
}

/// The cycles-ledger balance of `principal` on the Internet Computer, which
/// anyone may read: asked anonymously, so that it is answered whatever
/// became of the session's delegation while the deploy ran.
async fn balance_of(principal: Principal) -> Result<u128, String> {
    let agent = mainnet_agent(Arc::new(AnonymousIdentity))?;
    let balance = cycles_balance_of(&agent, principal).await?.balance;
    parse_cycles(&balance).ok_or_else(|| format!("the cycles ledger answered '{balance}'"))
}

/// A cycles ledger balance as [`crate::CyclesBalance`] carries it, which is
/// Candid's rendering of a `nat`: digits grouped by underscores.
fn parse_cycles(balance: &str) -> Option<u128> {
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
/// is one ten-thousandth of a trillion — rounded down, and without trailing
/// zeros.
fn trillions(cycles: u128) -> String {
    const T: u128 = 1_000_000_000_000;
    let (whole, fraction) = (cycles / T, cycles % T / (T / 10_000));
    match format!("{fraction:04}").trim_end_matches('0') {
        "" => format!("{whole}T"),
        fraction => format!("{whole}.{fraction}T"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(status: Status, error: &str, log: &[&str]) -> DeployOutcome {
        DeployOutcome {
            status,
            environment: "ic".into(),
            network: "ic".into(),
            canisters: vec!["backend".into(), "frontend".into(), "worker".into()],
            created: vec![("backend".into(), Principal::management_canister())],
            canister_ids: [("backend".to_string(), Principal::management_canister())].into(),
            error: Some(error.into()),
            log: log.iter().map(|l| (*l).to_string()).collect(),
        }
    }

    /// The cycles ledger's refusal of a creation, as the icp library words it.
    const LEDGER: &str = "failed to create canister: Insufficient cycles. Requested: \
                          2000000000000 cycles, available balance: 5 cycles.";

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

    // The deploy tool's description names every provider with its URL, from
    // the list.
    #[test]
    fn the_description_names_every_provider() {
        let said = advertised();
        assert!(said.starts_with(" Cycles are sold at: ") && said.ends_with('.'), "{said}");
        for provider in FUNDING_PROVIDERS {
            assert!(said.contains(&format!("{} ({})", provider.name, provider.app_url)));
        }
    }

    // A deploy ran short when the ledger refused a creation, wherever the
    // library put its words: in the error, or in the log's line for the
    // canister it could not create. Any other failure did not, and neither
    // did a deploy that was stopped.
    #[test]
    fn a_deploy_ran_short_when_the_ledger_refused_a_creation() {
        let create = format!("  create frontend: failed: {LEDGER}");
        assert!(ran_short(&outcome(Status::Failed, &format!("deploy failed: {LEDGER}"), &[])));
        assert!(ran_short(&outcome(Status::Failed, "one canister failed", &[&create])));
        assert!(!ran_short(&outcome(Status::Failed, "install_code rejected", &["create: ok"])));
        assert!(!ran_short(&outcome(Status::Interrupted, "stopped", &[&create])));
        let mut deployed = outcome(Status::Deployed, "", &[&create]);
        deployed.error = None;
        assert!(!ran_short(&deployed));
    }

    // Cycles named by a failure that is not the ledger refusing a creation
    // are not a balance to fund: a canister that ran out while its code was
    // installed, a sync that could not pay, the ledger refusing a
    // withdrawal. Nor is anything a purchase would not help: a deploy that
    // has every canister it targeted.
    #[test]
    fn other_failures_that_mention_cycles_are_not_a_short_balance() {
        for other in [
            "install frontend: failed: Canister abc is out of cycles",
            "sync frontend: failed: insufficient cycles to store the assets",
            "Insufficient cycles for the call",
            "Insufficient cycles. Requested: 5 cycles, balance: 1 cycles.",
        ] {
            assert!(!ran_short(&outcome(Status::Failed, other, &[])), "{other}");
            assert!(!ran_short(&outcome(Status::Failed, "failed", &[other])), "{other}");
        }
        let mut all_created = outcome(Status::Failed, LEDGER, &[]);
        for name in ["frontend", "worker"] {
            all_created.canister_ids.insert(name.into(), Principal::management_canister());
        }
        assert_eq!(still_to_create(&all_created), 0);
        assert!(!ran_short(&all_created), "nothing is left to create");
    }

    // The balance is waited for no longer than it is given, and not at all
    // once the deploy has been told to stop: the answer goes without it.
    #[tokio::test(start_paused = true)]
    async fn the_balance_read_gives_way_to_a_stop_and_to_time() {
        let wait = Duration::from_secs(10);
        let stop = CancellationToken::new();
        assert_eq!(balance_within(wait, &stop, async { Ok(7) }).await, Some(7));
        assert_eq!(balance_within(wait, &stop, async { Err("down".into()) }).await, None);
        let never = std::future::pending::<Result<u128, String>>;
        assert_eq!(balance_within(wait, &stop, never()).await, None, "not past its time");

        let (stopper, waiting) = (stop.clone(), balance_within(wait, &stop, never()));
        let started = tokio::time::Instant::now();
        let (read, ()) = tokio::join!(waiting, async move { stopper.cancel() });
        assert_eq!(read, None);
        assert!(started.elapsed() < wait, "a stop does not wait out the read");
        assert_eq!(balance_within(wait, &stop, async { Ok(7) }).await, None, "stopped already");
    }

    // What is needed is each uncreated canister's cycles and the ledger's
    // fee for creating it; what is missing is that less the balance, and
    // never less than nothing. A balance that could not be read leaves both
    // out and the rest stands.
    #[test]
    fn what_is_missing_is_what_the_balance_does_not_cover() {
        let who = Principal::management_canister();
        let short = Funding::new(who, 2, 2_000_000_000_000, Some(350_000_000_000));
        assert_eq!(short.principal, "aaaaa-aa");
        assert_eq!(short.needed, "4000200000000");
        assert_eq!(short.balance.as_deref(), Some("350000000000"));
        assert_eq!(short.shortfall.as_deref(), Some("3650200000000"));

        // Topped up meanwhile: nothing is missing any more.
        let covered = Funding::new(who, 1, 1_000_000_000_000, Some(3_000_000_000_000));
        assert_eq!(covered.needed, "1000100000000");
        assert_eq!(covered.shortfall.as_deref(), Some("0"));

        let unread = Funding::new(who, 2, 2_000_000_000_000, None);
        assert_eq!(unread.needed, "4000200000000");
        assert_eq!((&unread.balance, &unread.shortfall), (&None, &None));
        assert_eq!(unread.providers.len(), FUNDING_PROVIDERS.len());

        // Numbers no deploy has do not wrap.
        let huge = Funding::new(who, usize::MAX, u128::MAX, Some(0));
        assert_eq!(huge.needed, u128::MAX.to_string());
    }

    // The canisters still to create are those the deploy targeted and has
    // no id for: here two of three, the first having been created before
    // the balance ran out.
    #[test]
    fn the_canisters_still_to_create_are_those_without_an_id() {
        assert_eq!(still_to_create(&outcome(Status::Failed, LEDGER, &[])), 2);
    }

    // The text an agent without structured content reads carries the whole
    // answer: what is missing, whose account, each provider with its URL,
    // and the steps in order.
    #[test]
    fn the_text_says_what_the_structure_does() {
        let who = Principal::management_canister();
        let text = Funding::new(who, 2, 2_000_000_000_000, Some(350_000_000_000)).human();
        assert!(text.contains("takes 4.0002T (4000200000000 cycles)"), "{text}");
        assert!(text.contains("; the balance is 0.35T (350000000000 cycles)"), "{text}");
        assert!(text.contains("at least 3.6502T (3650200000000 cycles) more"), "{text}");
        assert!(text.contains("account of aaaaa-aa"), "{text}");
        for provider in FUNDING_PROVIDERS {
            assert!(text.contains(&format!("- {} ({})", provider.name, provider.app_url)));
        }
        let at = |needle: &str| text.find(needle).unwrap_or_else(|| panic!("no `{needle}`"));
        assert!(at("1. Write `canister_ids` back") < at("2. Tell the user"), "{text}");
        assert!(at("3. Call open_app") < at("payment URL"), "{text}");
        assert!(at("payment URL") < at("Then call icp_deploy again"), "{text}");
        assert!(at("Then call icp_deploy again") < at("upload it again first"), "{text}");
        assert!(text.contains("on the provider's site"), "{text}");

        let unread = Funding::new(who, 1, 2_000_000_000_000, None).human();
        assert!(unread.contains("takes 2.0001T (2000100000000 cycles)."), "{unread}");
        assert!(!unread.contains("; the balance is"), "no balance was read: {unread}");
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
        // The retry is the deploy over again: what it was given, the mapping
        // it returned, and a new upload where the bundle came by one.
        let retry = STEPS.last().expect("steps");
        for needle in ["same environment and settings", "mapping", "new upload id"] {
            assert!(retry.contains(needle), "`{needle}` in: {retry}");
        }
        assert!(steps.contains("`principal`") && steps.contains("payment URL"));
        for provider in FUNDING_PROVIDERS {
            assert!(!steps.contains(provider.name), "{}", provider.name);
        }
        for theirs in ["create_order", "stripe", "cyclepay"] {
            assert!(!steps.to_ascii_lowercase().contains(theirs), "{theirs}");
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
}
