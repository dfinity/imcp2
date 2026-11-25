//! Where the cycles a deploy uses come from: what `icp_deploy` says of
//! funding, in its description and in the answer of a deploy that ran short.
//!
//! `icp_deploy` creates canisters from the cycles-ledger balance of the
//! principal it signs as ([`super::CLI_ORIGIN`]). When that balance is short
//! the user has to add cycles to it, and this server neither provides them
//! nor handles a checkout: its policy (see [`crate::compliance`]) keeps every
//! such step in an interface the user controls. What it can say is to whom
//! added cycles must be delivered, how many are missing, and which funding
//! providers there are.
//!
//! It says so in the deploy tool itself, with no tool of its own:
//!
//!   * **The tool's description names the providers** ([`advertised`]), so
//!     an agent can tell the user which there are before it deploys.
//!   * **A deploy the balance did not cover answers with [`Funding`]**: the
//!     principal that must receive the cycles, what the canisters still to
//!     create need, the providers, and the steps. It is attached when the
//!     cycles ledger itself refused a creation ([`after`]) and never on a
//!     guess made beforehand: a canister on a cloud engine does not draw on
//!     the ledger at all, so a balance checked ahead of the deploy would
//!     refuse deploys that were going to succeed. Nor is it read off the
//!     wording of the deploy's error, which is the same when a cloud
//!     engine's operator refuses: the deploy's calls note the ledger's own
//!     typed answer ([`super::calls::Creations`]).
//!
//! And without knowing any one provider:
//!
//!   * **A provider is an app, named by its URL** ([`FundingProvider`]). The
//!     list ([`FUNDING_PROVIDERS`]) holds nothing of how a provider takes a
//!     funding request: no canister id, no method name, no rate.
//!   * **How to make a request is the provider's to say**, through the
//!     service-discoverability layers the tools here already read. Its
//!     manifest at `/.well-known/ic-architecture` names its canisters, and is
//!     its operators' word that an agent may drive them; the canister's
//!     Candid interface gives the methods, and its API doc the flow. The
//!     agent reads them with `open_app` and `get_canister_api_doc` and calls
//!     with `canister_query` and `canister_update_call`, as for any app.
//!   * **Every provider's flow ends the same way** ([`STEPS`]): a request
//!     that moves nothing and answers one checkout URL, which the user opens
//!     and completes on the provider's own page; the cycles are delivered to
//!     the account of [`Funding::principal`], and the next `icp_deploy`
//!     creates canisters from it.
//!
//! So another provider is another entry in the list, and one that takes its
//! manifest down can no longer be reached, with no change here: the manifest
//! gates every call to its canisters (see [`crate::discoverability`]).
//!
//! The request is an ordinary `canister_update_call`, held to that tool's
//! guard like any other, with no exemption. Passing the guard is what lets a
//! request be made here at all; it is not what makes a provider fit to list.
//! The guard refuses the standard ledger methods and a list of method names,
//! and says of itself that it cannot tell a bespoke value-moving method
//! under another name (see [`crate::compliance`]). That a request charges
//! nothing and moves no assets is therefore established for each provider
//! when its entry is reviewed, from what its method does, and never inferred
//! from the guard having let the call through.

use candid::Principal;
use rmcp::schemars;
use serde::Serialize;

use super::{run::went_unanswered, DeployOutcome, Status};

/// A service the user can get cycles from: an Internet Computer app whose
/// canisters an agent can find and read from its URL alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundingProvider {
    /// What the user knows it as.
    pub name: &'static str,
    /// The app's URL: what `open_app` takes, and the origin whose
    /// `/.well-known/ic-architecture` declares the canister funding requests
    /// are made on.
    pub app_url: &'static str,
    /// How the user completes the checkout there, in a few words they can
    /// choose by.
    pub checkout: &'static str,
}

/// The providers `icp_deploy` names, in the sequence it names them.
///
/// What an entry takes, since listing one tells users of this server where
/// to go for cycles:
///
///   1. Its `app_url` serves a service-discoverability manifest that
///      declares the canister requests are made on, and that canister
///      publishes its Candid interface and an API doc
///      (`get_api_doc`/`getApiDoc`). Without them no tool here reaches it.
///   2. The API doc describes a funding request that names the amount and
///      the principal whose Cycles Ledger account receives the cycles, that
///      answers a URL where the user completes one checkout, and whose
///      status can be read until the cycles are delivered.
///   3. The request itself charges nothing and moves no assets: it records
///      what the user is about to confirm, on a page of the provider's.
///      Whoever reviews the entry checks this independently of the guard,
///      from what the method does: the canister's source where it is
///      published, its interface and API doc, and a request made and
///      watched. The guard passing the call shows nothing of the kind: it
///      cannot tell a bespoke value-moving method under an ordinary name,
///      such as one that acts on an approval the user gave elsewhere.
///   4. `canister_update_call`'s guard does let the request through, or it
///      could not be made here: a method name the guard does not refuse, on
///      a canister with no ICRC-1 or ICRC-2 method.
///
/// Nothing provider-specific beyond these three fields belongs here. A
/// rate, a limit or a method name written into this list would go stale the
/// day the provider changed it; its API doc is read at the time of the
/// request.
pub const FUNDING_PROVIDERS: &[FundingProvider] = &[FundingProvider {
    name: "CyclePay",
    // `www`: the bare domain redirects there and serves no manifest itself.
    app_url: "https://www.cyclepay.org",
    checkout: "by card, on Stripe's checkout page",
}];

/// What the cycles ledger takes from the balance for creating a canister,
/// over the cycles the canister is created with.
pub const CREATE_FEE: u128 = 100_000_000;

/// The first thing to do after a deploy that ran short, whatever follows.
const WRITE_BACK: &str = "Write `canister_ids` back to the project first: it holds what this \
    deploy did create, and the next deploy creates only what is missing.";

/// What an agent does with a provider, whichever it is: the steps a deploy
/// that ran short answers with, between writing the mapping back and
/// deploying again. They name tools of this server and nothing of any
/// provider.
pub const STEPS: &[&str] = &[
    "Tell the user what is missing, show them the funding providers, and let them pick one \
     and how many cycles to add. The shortfall is the guide, not an exact minimum: it goes by \
     the balance the ledger reported as it refused, which the rest of the deploy may have \
     changed since, and a provider may have a minimum. Which provider and how much are theirs \
     to decide.",
    "Call open_app with that provider's `app_url`, then get_canister_api_doc on the canister it \
     marks [declared]. That guide is the provider's own: it says what an amount covers and \
     how to make a funding request.",
    "Following the guide, make a funding request whose cycles go to the Cycles Ledger account \
     of `principal`. Name that principal as the recipient: the request is made as the user's \
     account at the provider, which is another principal. The request itself charges nothing \
     and answers a checkout URL.",
    "Give the user that URL as it is. They complete the checkout there, on the provider's \
     page; never ask for card details, which go to that page alone.",
];

/// The last: the deploy over again.
const RETRY: &str = "Read the request's status as the guide says until the cycles are \
    delivered. Then call icp_deploy again with the same environment and settings as this \
    deploy, and the mapping from the first step. If this server takes the bundle by upload, \
    upload it again first and pass the new upload id: the upload this deploy was given is \
    used up.";

/// What to do when the steps cannot be followed.
const OTHERWISE: &str = "If open_app marks none of a provider's canisters [declared], or the \
    session cannot make update calls, the user can still add cycles on the provider's site, \
    entering `principal` as the Cycles Ledger account to receive them.";

/// The sentence `icp_deploy`'s description ends with: the funding
/// providers, from the list, so that the two cannot differ.
pub fn advertised() -> String {
    let providers: Vec<String> =
        FUNDING_PROVIDERS.iter().map(|p| format!("{} ({})", p.name, p.app_url)).collect();
    format!(" Funding providers: {}.", providers.join(", "))
}

/// How to fund the deploy `outcome` is of, a deploy as `principal` that
/// created canisters with `cycles` each, when the user's balance did not
/// cover it: when the cycles ledger itself refused a creation for lack of
/// cycles ([`DeployOutcome::short_of_cycles`]), the deploy failed for it,
/// and a canister is still to create.
///
/// Nothing is said of funding otherwise, and three cases are worth naming.
/// A refusal worded alike by anything but the ledger, such as a cloud
/// engine's operator, is not the user's balance falling short, and the
/// outcome does not record it as one. A deploy with every canister it
/// targeted has nothing more cycles would help. And a deploy in which a
/// creation ended without a verdict is not one to send back for another
/// run: such a call, unanswered or failed after it was sent
/// ([`DeployOutcome::uncertain_creation`], known from the calls themselves,
/// since the log does not say it of any failure but the first), may have
/// created a canister nothing lists, and a second run would create it
/// again. Its error says to check first, and the steps here, which end in
/// deploying again, are withheld. So are they when the error or the log
/// says of any other call that it went unanswered.
pub(super) fn after(
    outcome: &DeployOutcome,
    principal: Principal,
    cycles: u128,
) -> Option<Funding> {
    let balance = outcome.short_of_cycles?;
    let to_create = still_to_create(outcome);
    let uncertain = outcome.uncertain_creation
        || outcome.error.iter().chain(&outcome.log).any(|line| went_unanswered(line));
    if outcome.status != Status::Failed || to_create == 0 || uncertain {
        return None;
    }
    Some(Funding::new(principal, to_create, cycles, balance))
}

/// A funding provider, as a deploy's answer returns it.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FundingProviderOutput {
    /// The provider's name.
    pub name: String,
    /// The provider's app URL: pass it to open_app.
    pub app_url: String,
    /// How the user completes the checkout there.
    pub checkout: String,
}

/// How to fund a deploy the cycles balance did not cover: part of
/// `icp_deploy`'s answer when it failed for that.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct Funding {
    /// The principal icp_deploy creates canisters as. Its Cycles Ledger
    /// account holds the balance, and is the account added cycles must be
    /// delivered to.
    pub principal: String,
    /// What creating the canisters this deploy did not create takes from
    /// the balance, in cycles (decimal digits): each canister's cycles and
    /// what the ledger takes for creating it.
    pub needed: String,
    /// The account's balance, in cycles, as the cycles ledger reported it
    /// when it refused the creation. Canisters are created at once, so a
    /// creation still under way then may have changed it since.
    pub balance: String,
    /// How many cycles of `needed` that balance does not cover: about what
    /// has to be added. An estimate, as `balance` is of that moment.
    pub shortfall: String,
    /// The funding providers: where the user can get cycles.
    pub providers: Vec<FundingProviderOutput>,
    /// What to do next, one step after another: the same whichever provider
    /// the user picks.
    pub steps: Vec<String>,
}

impl Funding {
    /// What funding takes for `principal`, whose deploy left `to_create`
    /// canisters uncreated at `cycles` each, and whose account held
    /// `balance` when the cycles ledger refused the creation.
    pub fn new(principal: Principal, to_create: usize, cycles: u128, balance: u128) -> Self {
        let needed = (to_create as u128).saturating_mul(cycles.saturating_add(CREATE_FEE));
        // The ledger refused, so something is missing, whatever this sum
        // makes of what the ledger takes for a creation.
        let shortfall = needed.saturating_sub(balance).max(1);
        Self {
            principal: principal.to_text(),
            needed: needed.to_string(),
            balance: balance.to_string(),
            shortfall: shortfall.to_string(),
            providers: FUNDING_PROVIDERS
                .iter()
                .map(|p| FundingProviderOutput {
                    name: p.name.into(),
                    app_url: p.app_url.into(),
                    checkout: p.checkout.into(),
                })
                .collect(),
            steps: std::iter::once(WRITE_BACK)
                .chain(STEPS.iter().copied())
                .chain(std::iter::once(RETRY))
                .map(String::from)
                .collect(),
        }
    }

    /// The human-readable rendering: what is missing, whose account, the
    /// providers, the steps.
    pub fn human(&self) -> String {
        let mut text = format!(
            "The cycles balance did not cover this deploy. Creating the canisters still \
             missing takes {}; the balance was {} when the cycles ledger refused, so about \
             {} more are needed (the balance may have changed since).\nThe balance is that \
             of the Cycles Ledger account of {}, the principal icp_deploy creates canisters \
             as: added cycles must be delivered there.",
            amount(&self.needed),
            amount(&self.balance),
            amount(&self.shortfall),
            self.principal
        );
        text.push_str("\n\nFunding providers:");
        for provider in &self.providers {
            text.push_str(&format!(
                "\n- {} ({}): {}",
                provider.name, provider.app_url, provider.checkout
            ));
        }
        text.push_str("\n\nWhat to do, whichever provider the user picks:");
        for (n, step) in self.steps.iter().enumerate() {
            text.push_str(&format!("\n{}. {step}", n + 1));
        }
        text.push_str(&format!("\n\n{OTHERWISE}"));
        text
    }
}

/// How many canisters `outcome`'s deploy has yet to create: those it
/// targeted and has no id for.
fn still_to_create(outcome: &DeployOutcome) -> usize {
    outcome.canisters.iter().filter(|c| !outcome.canister_ids.contains_key(*c)).count()
}

/// `cycles`, a count in decimal digits, as a reader takes it in: in
/// trillions, the unit cycles are talked about in, with the exact count
/// beside it.
fn amount(cycles: &str) -> String {
    match cycles.parse::<u128>() {
        Ok(n) => format!("{} ({cycles} cycles)", trillions(n)),
        Err(_) => format!("{cycles} cycles"),
    }
}

/// `cycles` in trillions, exactly: every digit a count has below a
/// trillion, without trailing zeros. An amount that has to be added is
/// never shown as less than it is.
fn trillions(cycles: u128) -> String {
    const T: u128 = 1_000_000_000_000;
    let (whole, fraction) = (cycles / T, cycles % T);
    match format!("{fraction:012}").trim_end_matches('0') {
        "" => format!("{whole}T"),
        fraction => format!("{whole}.{fraction}T"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deploy of three canisters that created the first and then failed
    /// with `error`, the cycles ledger having refused a creation with
    /// `short_of_cycles` on the account, if it did.
    fn outcome(status: Status, error: &str, short_of_cycles: Option<u128>) -> DeployOutcome {
        DeployOutcome {
            status,
            environment: "ic".into(),
            network: "ic".into(),
            canisters: vec!["backend".into(), "frontend".into(), "worker".into()],
            created: vec![("backend".into(), Principal::management_canister())],
            canister_ids: [("backend".to_string(), Principal::management_canister())].into(),
            error: Some(error.into()),
            log: Vec::new(),
            short_of_cycles,
            uncertain_creation: false,
        }
    }

    /// The refusal of a creation for lack of cycles as the icp library words
    /// it in a deploy's error: made from the library's own types, as the
    /// library makes it for the cycles ledger and for a cloud engine's
    /// operator alike.
    fn refusal_as_worded() -> String {
        use icp_canister_interfaces::cycles_ledger::CreateCanisterError;
        use icp_project::operations::create::CreateOperationError;
        let refused = CreateCanisterError::InsufficientFunds { balance: candid::Nat::from(5u8) };
        let failed = CreateOperationError::CreateCanister {
            message: refused.format_error(2_000_000_000_000),
        };
        super::super::run::error_chain(&failed)
    }

    const CYCLES: u128 = 2_000_000_000_000;

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
            assert!(!provider.name.is_empty() && !provider.checkout.is_empty(), "{provider:?}");
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
        assert!(said.starts_with(" Funding providers: ") && said.ends_with('.'), "{said}");
        for provider in FUNDING_PROVIDERS {
            assert!(said.contains(&format!("{} ({})", provider.name, provider.app_url)));
        }
    }

    // A deploy the cycles ledger refused for lack of cycles is answered
    // with its funding: the canisters still to create counted off the
    // outcome, and the balance the ledger reported.
    #[test]
    fn a_deploy_the_ledger_refused_is_answered_with_its_funding() {
        let who = Principal::management_canister();
        let short = outcome(Status::Failed, &refusal_as_worded(), Some(7));
        let funding = after(&short, who, CYCLES).expect("a deploy the ledger refused");
        assert_eq!(funding.principal, "aaaaa-aa");
        assert_eq!(funding.needed, "4000200000000", "frontend and worker; backend exists");
        assert_eq!(funding.balance, "7");
        assert_eq!(funding.shortfall, "4000199999993");
    }

    // The wording of an error is not what says the user's balance fell
    // short. A cloud engine's operator creates canisters through the same
    // method and answers in the same shape, and the icp library words its
    // refusal exactly as it words the ledger's: with nothing noted from the
    // ledger itself, that deploy is told nothing of funding an account the
    // operator does not draw on. Nor is any other failure that mentions
    // cycles.
    #[test]
    fn a_refusal_that_is_not_the_ledgers_is_not_a_short_balance() {
        let who = Principal::management_canister();
        let worded = refusal_as_worded();
        assert!(worded.contains("Insufficient cycles"), "{worded}");
        for error in [worded.as_str(), "install frontend: Canister abc is out of cycles"] {
            assert!(after(&outcome(Status::Failed, error, None), who, CYCLES).is_none(), "{error}");
        }
    }

    // A deploy in which a call went unanswered is not sent back for another
    // run, even when the ledger also refused a creation: the unanswered
    // call may have created a canister nothing lists, which a second run
    // would create again. Its error says to check first, and no steps that
    // end in deploying again are put beside that. The same when it is a
    // line of the log that says so.
    #[test]
    fn an_unanswered_call_withholds_the_steps_to_deploy_again() {
        let who = Principal::management_canister();
        let unanswered = "call to 'create_canister' on um5iw-rqaaa-aaaaq-qaaba-cai went \
                          unanswered: timed out";
        let mixed = format!("{unanswered}; then: {}", refusal_as_worded());
        assert!(after(&outcome(Status::Failed, &mixed, Some(7)), who, CYCLES).is_none());

        let mut in_log = outcome(Status::Failed, &refusal_as_worded(), Some(7));
        in_log.log.push(format!("  create worker: failed: {unanswered}"));
        assert!(after(&in_log, who, CYCLES).is_none());
        in_log.log.clear();
        assert!(after(&in_log, who, CYCLES).is_some(), "the refusal alone is answered");
    }

    // Canisters are created at once, and the deploy's error is its first
    // failure alone. With the ledger's refusal first and another creation
    // ending without a verdict, timed out or failed after it was sent, the
    // error is the refusal and the log has, for the other, one line that
    // does not say so. The calls themselves do, and that is enough to
    // withhold the steps.
    #[test]
    fn a_second_creation_without_a_verdict_withholds_the_steps_too() {
        let who = Principal::management_canister();
        let mut second = outcome(Status::Failed, &refusal_as_worded(), Some(7));
        second.log.push("  create frontend: failed: failed to create canister".into());
        second.log.push("  create worker: failed: a canister call failed".into());
        assert!(after(&second, who, CYCLES).is_some(), "nothing in the text says it");
        second.uncertain_creation = true;
        assert!(after(&second, who, CYCLES).is_none());
    }

    // Only a deploy that failed with a canister still to create: one that
    // was interrupted says so and nothing of funding, and one that has
    // every canister it targeted has nothing more cycles would help.
    #[test]
    fn only_a_failed_deploy_with_a_canister_to_create_is_answered() {
        let who = Principal::management_canister();
        for status in [Status::Interrupted, Status::Deployed, Status::NothingToDeploy] {
            let other = outcome(status, &refusal_as_worded(), Some(7));
            assert!(after(&other, who, CYCLES).is_none(), "{status:?}");
        }
        let mut all_created = outcome(Status::Failed, &refusal_as_worded(), Some(7));
        for name in ["frontend", "worker"] {
            all_created.canister_ids.insert(name.into(), Principal::management_canister());
        }
        assert_eq!(still_to_create(&all_created), 0);
        assert!(after(&all_created, who, CYCLES).is_none(), "nothing is left to create");
    }

    // What is needed is each uncreated canister's cycles and what the
    // ledger takes for creating it; what is missing is that less the
    // balance. The ledger having refused, it is never nothing, even should
    // the ledger take more for a creation than is reckoned here.
    #[test]
    fn what_is_missing_is_what_the_balance_does_not_cover() {
        let who = Principal::management_canister();
        let short = Funding::new(who, 2, CYCLES, 350_000_000_000);
        assert_eq!(short.principal, "aaaaa-aa");
        assert_eq!(short.needed, "4000200000000");
        assert_eq!(short.balance, "350000000000");
        assert_eq!(short.shortfall, "3650200000000");
        assert_eq!(short.providers.len(), FUNDING_PROVIDERS.len());
        assert_eq!(short.steps.len(), STEPS.len() + 2);

        let refused_all_the_same = Funding::new(who, 1, CYCLES, CYCLES + CREATE_FEE);
        assert_eq!(refused_all_the_same.shortfall, "1");

        // Numbers no deploy has do not wrap.
        let huge = Funding::new(who, usize::MAX, u128::MAX, 0);
        assert_eq!(huge.needed, u128::MAX.to_string());
    }

    // The text an agent without structured content reads carries the whole
    // answer: what is missing, whose account, each provider with its URL,
    // and the steps one after another.
    #[test]
    fn the_text_says_what_the_structure_does() {
        let who = Principal::management_canister();
        let text = Funding::new(who, 2, CYCLES, 350_000_000_000).human();
        assert!(text.contains("takes 4.0002T (4000200000000 cycles)"), "{text}");
        assert!(text.contains("the balance was 0.35T (350000000000 cycles)"), "{text}");
        assert!(text.contains("about 3.6502T (3650200000000 cycles) more"), "{text}");
        assert!(text.contains("may have changed since"), "{text}");
        assert!(text.contains("account of aaaaa-aa"), "{text}");
        for provider in FUNDING_PROVIDERS {
            assert!(text.contains(&format!("- {} ({})", provider.name, provider.app_url)));
        }
        let at = |needle: &str| text.find(needle).unwrap_or_else(|| panic!("no `{needle}`"));
        assert!(at("1. Write `canister_ids` back") < at("2. Tell the user"), "{text}");
        assert!(at("3. Call open_app") < at("checkout URL"), "{text}");
        assert!(at("checkout URL") < at("Then call icp_deploy again"), "{text}");
        assert!(at("Then call icp_deploy again") < at("upload it again first"), "{text}");
        assert!(text.contains("on the provider's site"), "{text}");
    }

    // The steps are the same for every provider: they name this server's
    // tools and the principal that receives the cycles, and nothing a
    // provider calls its own.
    #[test]
    fn the_steps_name_no_provider() {
        let steps = Funding::new(Principal::management_canister(), 1, CYCLES, 0).steps.join(" ");
        for tool in ["open_app", "get_canister_api_doc", "icp_deploy"] {
            assert!(steps.contains(tool), "{tool}");
        }
        assert!(steps.contains("`principal`") && steps.contains("checkout URL"));
        // How much to add is the user's: the shortfall guides it without
        // being exact, and a provider's minimum may make it more.
        assert!(steps.contains("The shortfall is the guide, not an exact minimum"), "{steps}");
        assert!(steps.contains("a provider may have a minimum"), "{steps}");
        for provider in FUNDING_PROVIDERS {
            assert!(!steps.contains(provider.name), "{}", provider.name);
        }
        for theirs in ["stripe", "cyclepay"] {
            assert!(!steps.to_ascii_lowercase().contains(theirs), "{theirs}");
        }
        // The retry is the deploy over again: what it was given, the mapping
        // it returned, and a new upload where the bundle came by one.
        for needle in ["same environment and settings", "mapping", "new upload id"] {
            assert!(RETRY.contains(needle), "`{needle}` in: {RETRY}");
        }
    }

    // An amount in trillions is the amount: no digit is dropped, so that
    // what has to be added is never shown as less than it is.
    #[test]
    fn cycles_read_in_trillions_exactly() {
        for (cycles, said) in [
            (0, "0T"),
            (2_000_000_000_000, "2T"),
            (350_000_000_000, "0.35T"),
            (4_000_200_000_000, "4.0002T"),
            (1_999_999_999_999, "1.999999999999T"),
            (99_999_999, "0.000099999999T"),
            (1, "0.000000000001T"),
            (13_700_000_000_000, "13.7T"),
        ] {
            assert_eq!(trillions(cycles), said);
        }
    }
}
