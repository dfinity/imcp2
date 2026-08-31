//! The service-discoverability gate for the generic update-call tool.
//!
//! Reading the Internet Computer is open to everyone: any canister's Candid
//! interface, metadata, and query methods are public, and this server treats
//! them that way. WRITING is different. A state-changing call runs against
//! someone's live application — it can create, mutate, or destroy records that
//! app's operators are answerable for — and nothing about a canister being
//! publicly callable means its operators want an AI agent driving it.
//!
//! So `canister_update_call` is restricted to canisters an app DECLARES in its
//! **service-discoverability manifest**: the JSON document at
//! [`ARCHITECTURE_PATH`] listing every canister the app comprises and each one's
//! role (Layer 1 of the protocol, [`SERVICE_DISCOVERABILITY_GUIDE`]). Publishing
//! that file is a deliberate act by the app's operators, and per the guide it is
//! how they opt their app in: it says "these are my canisters, an agent handed my
//! URL may work them out and use them". An app that has not published one has
//! made no such statement, so this server does not write to it — it reads it,
//! discovers it, and tells the agent what the app would have to publish.
//!
//! The gate needs to know WHICH app owns the target, because the manifest lives
//! at the app's origin, not on chain. That is the `app_url` argument on
//! `canister_update_call` (falling back to `derivation_origin` when the app
//! serves its manifest there); `open_app` hands back exactly that URL alongside
//! the canisters it discovered, so the normal flow already carries it.
//!
//! Three scope notes, so nobody over-claims what this gate does:
//!
//!   * It is a **consent and provenance** gate, not a proof of ownership.
//!     Whoever controls a domain controls what its manifest says, so a manifest
//!     can name a canister its publisher does not own. What the gate guarantees
//!     is that SOMEONE published a document, at an origin the caller named,
//!     claiming that canister as part of their app — and that a write the user
//!     later questions can be traced back to that claim (the reply echoes the
//!     origin and path that authorized it). It does not, and cannot, establish
//!     that the claim was theirs to make.
//!   * It bounds the BLAST RADIUS of a confused or misled agent far more than it
//!     stops a determined attacker: an agent that has been talked into writing
//!     somewhere now has to be talked into naming an origin that declares the
//!     target as well, and the vast majority of the ~1.2M canisters on the IC are
//!     declared by no manifest at all. Two limits of that, spelled out because
//!     they are the ones a reader is most likely to assume away (per review):
//!     an ANONYMOUS write skips [`bind_identity`] entirely — there is no app
//!     identity to protect — so an attacker who declares a victim canister in
//!     their own manifest can have this connector make an anonymous call to it;
//!     and an AUTHENTICATED write binds to the attacker's own app identity while
//!     still reaching any victim method that accepts an arbitrary principal.
//!     Neither grants a capability the attacker did not already have — anyone can
//!     send either call to a public canister with an ordinary agent, since the IC
//!     accepts ingress from anywhere — so what the gate withholds is this
//!     connector's willingness to make such a call ON A USER'S BEHALF, and the
//!     binding is what keeps the user's OWN app principals out of it. Closing the
//!     rest would take an association the TARGET attests to, which the protocol
//!     does not define today (nothing a canister publishes names its app's
//!     origin); it is raised on the pull request rather than invented here.
//!   * It gates **writes only**. Reads (`canister_query`, `get_canister_candid`,
//!     the OQL surface) and discovery are unchanged on every canister: the
//!     protocol exists to make apps *more* legible to agents, and it would be a
//!     strange reading of it to make this server see less.
//!
//! Only [`ARCHITECTURE_PATH`] authorizes. This server proposed the same document
//! at [`discover::LEGACY_MANIFEST_PATH`] before the protocol was published, and
//! discovery still READS it — but it cannot authorize a write, because the
//! operators who adopted that proposal published it against different terms and
//! never agreed to the ones publishing the protocol manifest now signifies
//! (<https://internetcomputer.org/icp-mcp/terms/>). Consent that was never given
//! cannot be inherited from a path this server invented, so an early adopter is
//! refused — and told, precisely, that serving the same JSON at the standard
//! path is all that is required.

use candid::Principal;

use crate::discover::{self, ARCHITECTURE_PATH, SERVICE_DISCOVERABILITY_GUIDE};

/// Which argument the checked origin came from, so a refusal can name the
/// argument the agent should actually fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginSource {
    /// The caller's `app_url` — the intended input.
    AppUrl,
    /// The caller's `derivation_origin`, used because no `app_url` was given.
    /// Usually the same origin, but NOT always: an app that pins a custom
    /// derivation origin serves its manifest at its application origin, so a
    /// refusal here has to suggest passing `app_url` explicitly.
    DerivationOrigin,
}

impl OriginSource {
    fn arg(self) -> &'static str {
        match self {
            OriginSource::AppUrl => "`app_url`",
            OriginSource::DerivationOrigin => "`derivation_origin` (no `app_url` was given)",
        }
    }
}

/// What authorized an update call: the app origin whose manifest declares the
/// target canister, and the well-known path that manifest was read from. Echoed
/// in the tool's reply so the write's provenance is visible to the user, not just
/// to the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    pub origin: String,
    pub path: &'static str,
}

/// How many declared ids a refusal lists back. Enough to pick the right canister
/// from a real app's manifest, bounded so an app with a hundred entries can't
/// turn one refusal into a wall of principals.
const MAX_LISTED_DECLARED: usize = 12;

/// The gate: `Ok(declaration)` when the app at `app_origin` declares
/// `canister_id` in its service-discoverability manifest, `Err(refusal)` — the
/// complete tool error text — in every other case. Fails CLOSED: an unreachable
/// origin, an unparseable document, and an absent manifest all refuse.
pub async fn authorize_update_call(
    app_origin: &str,
    source: OriginSource,
    canister_id: &Principal,
) -> Result<Declaration, String> {
    match discover::fetch_declared_manifest(app_origin).await {
        Ok(probe) => decide(probe, app_origin, source, canister_id),
        Err(e) => Err(unreachable_refusal(app_origin, source, &e)),
    }
}

/// The gate's decision, separated from the fetch that feeds it (per review): with
/// no app publishing the standard path yet, every live test of the YES branch can
/// only skip, so the branch that MATTERS — a declared canister authorizes, and
/// each way of not being declared refuses differently — needs to be provable
/// without a network. It cannot be tested by pointing the fetch at a local server
/// either: the SSRF guard resolves and pins public addresses before any request,
/// so a loopback origin is refused before a fixture could answer. Splitting the
/// decision out is what makes it testable at all, and every case below is pinned
/// on constructed input.
fn decide(
    probe: discover::ManifestProbe,
    app_origin: &str,
    source: OriginSource,
    canister_id: &Principal,
) -> Result<Declaration, String> {
    let manifest = match probe {
        discover::ManifestProbe::Declared(m) => m,
        // An origin still on the pre-protocol path gets its own refusal: it HAS
        // published something, so reporting it as publishing nothing would send
        // its operators looking for a file that is already there, when what they
        // actually have to do is serve it at the standard path.
        discover::ManifestProbe::Absent { legacy: Some(legacy), .. } => {
            return Err(legacy_only_refusal(&legacy, canister_id, source))
        }
        discover::ManifestProbe::Absent { served_non_manifest, legacy: None } => {
            return Err(no_manifest_refusal(app_origin, source, served_non_manifest.as_deref()))
        }
    };
    if manifest.canisters.contains(canister_id) {
        return Ok(Declaration { origin: manifest.origin, path: manifest.path });
    }
    Err(not_declared_refusal(&manifest, canister_id, source))
}

/// The identity half of the gate: the app whose manifest authorizes the write
/// must be the app the write is SIGNED as.
///
/// The manifest gate alone establishes that someone published a document at the
/// origin the caller named. It says nothing about whose identity the call goes
/// out under, and those are separable inputs: `app_url` picks the manifest,
/// `derivation_origin` picks the principal. Left unbound, an origin the attacker
/// controls could declare any canister — declaring one is free, and the gate
/// deliberately does not prove ownership — while the call was signed with the
/// principal the user holds at a DIFFERENT app they actually trusted. Requiring
/// the app to resolve to the identity being used removes that pairing: an
/// attacker's manifest can only ever authorize writes made as the attacker's own
/// app identity, which is worth nothing to them.
///
/// The comparison is against what the app ITSELF resolves to — its declared Layer
/// 5 origin, else a known-app value, else its own origin — not against the app URL
/// literally, so the many apps whose derivation origin differs from their website
/// (13 of 17 in the built-in registry) still pass. `resolve_app_identity` also
/// enforces Internet Identity's own rule on the way: a cross-origin declaration
/// counts only if the declared origin authorizes this app in its
/// `ii-alternative-origins`, so an app cannot simply claim another's identity to
/// satisfy this check.
///
/// Fails CLOSED: an origin that cannot be resolved refuses, rather than being
/// treated as a match.
pub async fn bind_identity(
    app_origin: &str,
    requested_identity: &str,
    canister_id: &Principal,
) -> Result<(), String> {
    let identity = discover::resolve_app_identity(app_origin, false)
        .await
        .map_err(|e| identity_unresolvable_refusal(app_origin, &e))?;
    // Compare canonical forms: `requested_identity` has been through the identity
    // path's canonicalization (which remaps the *.icp0.io / *.icp.net gateway
    // hosts to *.ic0.app), so put the resolved value through the same one or the
    // same app spelled two ways would read as two apps.
    let app_identity = crate::identities::target_origin(&identity.derivation_origin);
    if app_identity.eq_ignore_ascii_case(requested_identity) {
        return Ok(());
    }
    Err(identity_mismatch_refusal(app_origin, &app_identity, requested_identity, canister_id))
}

/// Cap on any externally-influenced string a refusal echoes back. A transport
/// error can carry a hostile origin's TLS certificate subject or redirect URL,
/// and a refusal is text the model reads: pass it through the same control-char
/// scrub the manifest labels use, and keep it short enough that it cannot become
/// the bulk of the message.
const MAX_ECHOED_CAUSE: usize = 200;

/// Scrub and cap an ORIGIN before it reaches the model. `app_url` is
/// caller-supplied and only its origin is ever fetched, so the origin is what a
/// refusal should name — but the value reaching a refusal has been through
/// validation, not necessarily through origin reduction, and this module claims a
/// bound on every externally-influenced string it echoes. Applying the same cap
/// here makes that claim hold whatever the caller passed (per review).
fn safe_origin(origin: &str) -> String {
    safe_cause(origin)
}

/// Scrub and cap an error string before it reaches the model (CWE-150).
fn safe_cause(cause: &str) -> String {
    let scrubbed: String = cause
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_ECHOED_CAUSE)
        .collect();
    scrubbed.trim().to_string()
}

/// One sentence, in every refusal, stating the rule the caller just hit. Kept in
/// one place so the policy can never be described two different ways.
fn the_rule() -> String {
    format!(
        "This server makes state-changing calls ONLY to canisters an app declares in its \
         service-discoverability manifest at {ARCHITECTURE_PATH} — publishing it is how an app's \
         operators opt in to being discovered and operated by agents ({SERVICE_DISCOVERABILITY_GUIDE})."
    )
}

/// One sentence, in every refusal, making clear that only WRITES are gated — so
/// an agent doesn't conclude the whole app is off limits and give up on a
/// question it could still answer by reading.
const READS_ARE_FINE: &str = "Reading is unaffected: canister_query, get_canister_candid, \
     get_canister_api_doc, the OQL tools and the discovery tools work on this canister as before, \
     so answer what you can by reading.";

/// No `app_url` and no `derivation_origin`: the gate has no origin to check, so
/// it cannot even start. Names the missing argument and where to get it.
pub fn missing_origin_refusal(canister_id: &Principal) -> String {
    format!(
        "`canister_update_call` needs to know which APP owns {canister_id} before it will write to \
         it: pass `app_url` (the app's website URL, e.g. https://app.example.com). {} Get the URL \
         from open_app — it returns `app_url` alongside the canisters it discovered — or from the \
         user. {READS_ARE_FINE}",
        the_rule()
    )
}

/// The origin could not be reached at all. Distinct from "publishes no manifest":
/// we do not know, so the refusal is retryable rather than a verdict on the app.
fn unreachable_refusal(app_origin: &str, source: OriginSource, error: &str) -> String {
    let app_origin = safe_origin(app_origin);
    // Not every check failure clears on its own: an origin answering 401/403 on
    // the path is denying it deliberately, and a blocked redirect is a
    // configuration this server will not follow. Telling those callers to retry
    // is advice that cannot work, so they get the fix instead (per review).
    let persistent = ["HTTP 401", "HTTP 403", "redirect"]
        .iter()
        .any(|marker| error.contains(marker));
    let next = if persistent {
        "Retrying will not clear this one: the origin is refusing to serve that path, or serving \
         it from somewhere this server will not follow. Its operators fix it by making the \
         manifest publicly readable at that exact path on this origin."
    } else {
        "This is likely transient — retry; if it persists, confirm that the origin is right."
    };
    format!(
        "Could not check whether {app_origin} declares this canister: {}. {} The call is \
         refused rather than made blind. {next} Confirm that {} names the app's real origin \
         (open_app returns it). {READS_ARE_FINE}",
        safe_cause(error),
        the_rule(),
        source.arg()
    )
}

/// The origin answered, but serves no manifest at either well-known path. The
/// common causes are a wrong origin and an app that simply has not adopted the
/// protocol, so the refusal addresses both and tells the agent what to say.
fn no_manifest_refusal(
    app_origin: &str,
    source: OriginSource,
    served_non_manifest: Option<&str>,
) -> String {
    let app_origin = safe_origin(app_origin);
    let mut msg = format!(
        "{app_origin} publishes no service-discoverability manifest at {ARCHITECTURE_PATH}, so \
         this connector will not make a state-changing call to its canisters. {} ",
        the_rule()
    );
    // The origin DID answer that path, just not with a manifest. Naming what it
    // answered with turns "your app publishes nothing" into something its
    // operator can act on from a relayed transcript — and `text/html` is the
    // exact signature of the SPA catch-all the guide calls the most common
    // failure, which an operator would otherwise chase as a missing file.
    if let Some(kind) = served_non_manifest {
        let kind = safe_cause(kind);
        msg.push_str(&format!(
            "It DOES answer that path, but with {} rather than the manifest JSON — the usual cause \
             is a single-page-app catch-all returning index.html for unknown paths, which the app \
             fixes by exempting /.well-known/* from the SPA rewrite. ",
            if kind.is_empty() { "a non-manifest document".to_string() } else { format!("`{kind}`") }
        ));
    }
    if source == OriginSource::DerivationOrigin {
        msg.push_str(
            "This origin came from `derivation_origin`, which is not always where the app serves \
             its manifest — pass the app's website URL as `app_url` and try again. ",
        );
    }
    msg.push_str(&format!(
        "Otherwise: if this is NOT the app's origin (a marketing site, a docs host, a guessed \
         domain), pass the right `app_url` — open_app resolves one from the app's name or URL. If \
         it IS the app's origin, the app has not adopted the protocol, and re-running open_app \
         will not change that: STOP retrying, tell the user this write cannot be made for them \
         here, and that the app's operators enable it by publishing the manifest \
         ({SERVICE_DISCOVERABILITY_GUIDE}); the skill://service-discoverability resource carries \
         the deploy-time recipe for generating it, if the user is the one who can ship it. They \
         can also perform the action themselves in the app's own frontend. {READS_ARE_FINE}"
    ));
    msg
}

/// The origin still serves this server's PRE-PROTOCOL document and nothing at
/// the standard path. It has published something, so the "publishes no manifest"
/// verdict would be wrong and would send its operators hunting for a file that is
/// already there. What it has not done is opt in under the terms the protocol
/// manifest now carries, and that consent cannot be back-filled from a path this
/// server invented — so the refusal names the document it found, says plainly
/// that serving the same JSON at the standard path is the whole fix, and (when
/// the older document does list the target) makes clear the refusal is about
/// WHERE the declaration lives, not about the canister being unknown.
fn legacy_only_refusal(
    legacy: &discover::DeclaredManifest,
    canister_id: &Principal,
    source: OriginSource,
) -> String {
    let mut msg = format!(
        "{} serves this connector's older, pre-protocol document at {} but publishes no \
         service-discoverability manifest at {ARCHITECTURE_PATH}, so this connector will not make \
         a state-changing call to its canisters. {} ",
        legacy.origin,
        legacy.path,
        the_rule()
    );
    msg.push_str(if legacy.canisters.contains(canister_id) {
        "That older document DOES list this canister, but it cannot authorize the write: it \
         predates the protocol, and its publishers never accepted the terms that publishing the \
         standard manifest now signifies (https://internetcomputer.org/icp-mcp/terms/). "
    } else {
        "That older document does not list this canister either. "
    });
    if source == OriginSource::DerivationOrigin {
        msg.push_str(
            "This origin came from `derivation_origin`, which is not always where the app serves \
             its manifest — if the app publishes one elsewhere, pass that website URL as `app_url` \
             and try again. ",
        );
    }
    msg.push_str(&format!(
        "For the app's operators the fix is small and entirely theirs to make: serve the same JSON \
         at {ARCHITECTURE_PATH}, which is how they opt the app in \
         ({SERVICE_DISCOVERABILITY_GUIDE}); the skill://service-discoverability resource carries \
         the deploy-time recipe. Until they do, STOP retrying: tell the user this write cannot be \
         made for them here, and that they can perform the action themselves in the app's own \
         frontend. {READS_ARE_FINE}"
    ));
    msg
}

/// The caller named an app whose manifest authorizes the write, but asked to sign
/// as a DIFFERENT app's identity. Without this check the manifest gate could be
/// satisfied by an origin the attacker controls while the call went out under the
/// principal the user holds somewhere else: any site can publish a manifest naming
/// any canister, so a declaration only means something when it comes from the app
/// whose identity is signing. The refusal names both origins, because which one is
/// wrong depends on what the caller meant to do.
fn identity_mismatch_refusal(
    app_origin: &str,
    app_identity: &str,
    requested_identity: &str,
    canister_id: &Principal,
) -> String {
    let (app_origin, app_identity, requested_identity) =
        (safe_origin(app_origin), safe_origin(app_identity), safe_origin(requested_identity));
    format!(
        "The app at {app_origin} is not the app this call would be signed as. Internet \
         Identity derives that app's users from {app_identity}, while this call asks to act as \
         {requested_identity}. Writing to {canister_id} on that combination is refused: a \
         manifest published at one origin does not authorize a write made under another app's \
         identity, or any site could declare a canister and have this connector write to it as \
         you, at an app you trusted for something else. If {canister_id} belongs to the app you \
         are acting at, pass THAT app's URL as `app_url` — open_app returns the `app_url` and \
         the `derivation_origin` of one app together, so a pair from a single open_app call \
         always matches. If you meant to act at {app_origin} instead, pass its own derivation \
         origin. {READS_ARE_FINE}"
    )
}

/// The binding above could not be established at all — the app origin would not
/// resolve to a derivation origin (unreachable, or a cross-origin declaration its
/// declared origin does not authorize). Distinct from a mismatch: we do not know
/// that the two disagree, only that we cannot show they agree, and the call is
/// refused rather than made blind.
fn identity_unresolvable_refusal(app_origin: &str, cause: &str) -> String {
    // Not every failure here is a blip: `resolve_app_identity` also refuses a
    // cross-origin derivation-origin declaration that the declared origin does
    // not authorize in its ii-alternative-origins, and no amount of retrying
    // repairs that — it is a misconfiguration (or a spoof) at the app. Telling a
    // caller to retry it would be advice that cannot work, so the two cases get
    // different next steps (per review).
    let next = if cause.contains("ii-alternative-origins") {
        "This one does not resolve itself: the app claims a derivation origin that does not \
         authorize it back, which its operators fix by listing this origin in that file. \
         Retrying will not change it."
    } else {
        "This is likely transient — retry; if it persists, confirm that `app_url` names the app \
         you are acting at (open_app returns its `app_url` and `derivation_origin` together)."
    };
    format!(
        "Could not establish that {} is the app this call would be signed as: {}. The call is \
         refused rather than made blind, because a manifest only authorizes a write when it \
         comes from the app whose identity is signing. {next} {READS_ARE_FINE}",
        safe_origin(app_origin),
        safe_cause(cause)
    )
}

/// The app publishes a manifest, but this canister is not in it. The most useful
/// thing a refusal can do here is show what the app DOES declare, so an agent
/// that picked the wrong id out of a discovery listing can correct itself in one
/// step instead of guessing again.
fn not_declared_refusal(
    manifest: &discover::DeclaredManifest,
    canister_id: &Principal,
    source: OriginSource,
) -> String {
    let listed: Vec<String> = manifest
        .canisters
        .iter()
        .take(MAX_LISTED_DECLARED)
        .map(Principal::to_text)
        .collect();
    let declares = if listed.is_empty() {
        "declares no canisters at all".to_string()
    } else {
        let more = manifest.canisters.len().saturating_sub(listed.len());
        let suffix = if more > 0 { format!(" (+{more} more)") } else { String::new() };
        format!("declares: {}{suffix}", listed.join(", "))
    };
    // An over-long manifest is the one case where "not declared" would be a FALSE
    // statement about the app: entries past the read cap ARE declared, we just did
    // not read them. So the VERDICT changes rather than being qualified after the
    // fact — leading with "does not declare" and admitting two sentences later
    // that we never looked is the same false assertion this handling exists to
    // avoid (per review).
    if manifest.omitted > 0 {
        return format!(
            "Could not determine whether {} declares {canister_id}: its manifest ({}) carries {} \
             entries beyond the {} this server reads, which were NOT checked, so this connector \
             will not make a state-changing call to it. {} Of what WAS read, it {declares}. If \
             {canister_id} is one of the unread entries, the manifest is too long and its \
             operators should shorten it ({SERVICE_DISCOVERABILITY_GUIDE}); if it belongs to a \
             DIFFERENT app, pass that app's URL as `app_url` instead of {}. {READS_ARE_FINE}",
            manifest.origin,
            manifest.path,
            manifest.omitted,
            manifest.canisters.len(),
            the_rule(),
            source.arg()
        );
    }
    format!(
        "{} does not declare {canister_id} in its manifest ({}), so this connector will not make a \
         state-changing call to it. It {declares}. {} Use one of the declared canisters for this \
         operation. If {canister_id} really is part of this app, its operators must add it to the \
         manifest ({SERVICE_DISCOVERABILITY_GUIDE}); if it belongs to a DIFFERENT app, pass that \
         app's URL as `app_url` instead of {}. {READS_ARE_FINE}",
        manifest.origin,
        manifest.path,
        the_rule(),
        source.arg()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::LEGACY_MANIFEST_PATH;

    fn canister(text: &str) -> Principal {
        Principal::from_text(text).unwrap()
    }
    fn backend() -> Principal {
        canister("hmxr2-pqaaa-aaabq-qaaaa-cai")
    }
    fn frontend() -> Principal {
        canister("hcv4s-uaaaa-aaabq-qaaba-cai")
    }
    fn manifest(origin: &str, path: &'static str, ids: &[Principal]) -> discover::DeclaredManifest {
        with_omitted(origin, path, ids, 0)
    }
    fn with_omitted(
        origin: &str,
        path: &'static str,
        ids: &[Principal],
        omitted: usize,
    ) -> discover::DeclaredManifest {
        discover::DeclaredManifest {
            origin: origin.to_string(),
            path,
            canisters: ids.to_vec(),
            omitted,
        }
    }

    // Every MANIFEST refusal states the same rule, names the standard path, and
    // links the guide — an app owner reading a relayed refusal must be able to act
    // on it without anyone explaining the protocol to them first.
    //
    // The two identity refusals are deliberately not in this list: their repair
    // belongs to the CALLER (pass an `app_url` and `derivation_origin` from one
    // open_app call), not to the app's operators, and quoting the adoption rule at
    // someone whose app already publishes a manifest would send them to fix
    // something that is not broken. What they must say instead is pinned by
    // `the_identity_mismatch_refusal_names_both_apps`.
    #[test]
    fn every_manifest_refusal_states_the_rule_and_links_the_guide() {
        let refusals = [
            missing_origin_refusal(&backend()),
            unreachable_refusal("https://app.example.com", OriginSource::AppUrl, "timed out"),
            no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, None),
            not_declared_refusal(
                &manifest("https://app.example.com", ARCHITECTURE_PATH, &[frontend()]),
                &backend(),
                OriginSource::AppUrl,
            ),
            legacy_only_refusal(
                &manifest("https://app.example.com", LEGACY_MANIFEST_PATH, &[backend()]),
                &backend(),
                OriginSource::AppUrl,
            ),
        ];
        for msg in refusals {
            assert!(msg.contains(ARCHITECTURE_PATH), "must name the standard path: {msg}");
            assert!(
                msg.contains(SERVICE_DISCOVERABILITY_GUIDE),
                "must link the guide so the app can adopt it: {msg}"
            );
        }
    }

    // A refusal must not read as "this app is off limits": writes are gated,
    // reads are not, and an agent that stops reading has been over-refused.
    #[test]
    fn refusals_keep_the_reading_path_open() {
        for msg in [
            missing_origin_refusal(&backend()),
            no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, None),
            not_declared_refusal(
                &manifest("https://app.example.com", ARCHITECTURE_PATH, &[frontend()]),
                &backend(),
                OriginSource::AppUrl,
            ),
            legacy_only_refusal(
                &manifest("https://app.example.com", LEGACY_MANIFEST_PATH, &[backend()]),
                &backend(),
                OriginSource::AppUrl,
            ),
            identity_mismatch_refusal(
                "https://evil.example",
                "https://evil.example",
                "https://gooddapp.com",
                &backend(),
            ),
            identity_unresolvable_refusal("https://app.example.com", "timed out"),
        ] {
            assert!(msg.contains("canister_query"), "must point at the read path: {msg}");
        }
    }

    // "Could not ask" is not "the app has not adopted the protocol". The
    // unreachable refusal must read as retryable and must NOT accuse the app of
    // publishing nothing — that verdict needs an answer from the origin.
    #[test]
    fn unreachable_is_retryable_not_a_verdict() {
        let msg = unreachable_refusal("https://app.example.com", OriginSource::AppUrl, "timed out");
        assert!(msg.contains("timed out"), "surfaces the cause: {msg}");
        assert!(msg.contains("retry"), "must invite a retry: {msg}");
        assert!(!msg.contains("publishes no"), "must not conclude absence: {msg}");
    }

    // The "no manifest" refusal separates the two real causes — wrong origin vs
    // an app that hasn't adopted the protocol — and, when the origin came from
    // `derivation_origin` rather than `app_url`, says so first: that is the one
    // case where the SAME app might still pass with the right argument.
    #[test]
    fn no_manifest_refusal_distinguishes_wrong_origin_from_no_adoption() {
        let from_url = no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, None);
        assert!(from_url.contains("`app_url`"), "{from_url}");
        assert!(!from_url.contains("came from `derivation_origin`"), "{from_url}");

        let from_origin =
            no_manifest_refusal("https://app.example.com", OriginSource::DerivationOrigin, None);
        assert!(
            from_origin.contains("came from `derivation_origin`"),
            "must suggest the app_url retry first: {from_origin}"
        );
    }

    // A wrong pick out of a discovery listing is the common case, so the refusal
    // shows what the app DOES declare — bounded, so a hundred-entry manifest
    // can't turn one refusal into a wall of principals.
    #[test]
    fn not_declared_refusal_lists_what_the_app_declares() {
        let msg = not_declared_refusal(
            &manifest("https://app.example.com", ARCHITECTURE_PATH, &[frontend()]),
            &backend(),
            OriginSource::AppUrl,
        );
        assert!(msg.contains(&frontend().to_text()), "shows the declared id: {msg}");
        assert!(msg.contains(&backend().to_text()), "names the refused id: {msg}");

        let many: Vec<Principal> = (0..30).map(|_| frontend()).collect();
        let msg = not_declared_refusal(
            &manifest("https://app.example.com", ARCHITECTURE_PATH, &many),
            &backend(),
            OriginSource::AppUrl,
        );
        assert_eq!(
            msg.matches(&frontend().to_text()).count(),
            MAX_LISTED_DECLARED,
            "the listing is capped: {msg}"
        );
        assert!(msg.contains("+18 more"), "and the remainder is reported: {msg}");
    }

    // An app that publishes an EMPTY manifest has adopted the protocol and
    // declared nothing — say that, rather than printing "declares: ".
    #[test]
    fn empty_manifest_is_reported_as_declaring_nothing() {
        let msg = not_declared_refusal(
            &manifest("https://app.example.com", ARCHITECTURE_PATH, &[]),
            &backend(),
            OriginSource::AppUrl,
        );
        assert!(msg.contains("declares no canisters at all"), "{msg}");
        assert!(msg.contains(ARCHITECTURE_PATH), "names the path that answered: {msg}");
    }

    // A gate refusal must never borrow the vocabulary of a DIFFERENT failure.
    // Two neighbours are dangerous here: the read-only-session rejection, whose
    // repair is reconnecting with "Actions & questions" (an agent sent down that
    // path would ask the user to re-authenticate for a problem authentication
    // cannot fix), and the financial-methods refusal, whose repair is a wallet.
    // Neither has anything to do with an app that has not published a manifest.
    #[test]
    fn refusals_never_borrow_another_failures_repair() {
        for msg in [
            missing_origin_refusal(&backend()),
            unreachable_refusal("https://app.example.com", OriginSource::AppUrl, "timed out"),
            no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, None),
            no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, Some("text/html")),
            not_declared_refusal(
                &manifest("https://app.example.com", ARCHITECTURE_PATH, &[frontend()]),
                &backend(),
                OriginSource::AppUrl,
            ),
            legacy_only_refusal(
                &manifest("https://app.example.com", LEGACY_MANIFEST_PATH, &[backend()]),
                &backend(),
                OriginSource::AppUrl,
            ),
            identity_mismatch_refusal(
                "https://evil.example",
                "https://evil.example",
                "https://gooddapp.com",
                &backend(),
            ),
            identity_unresolvable_refusal("https://app.example.com", "timed out"),
        ] {
            for wrong in [
                "reconnect",
                "Actions & questions",
                "Questions only",
                "financial",
                "oisy.com",
            ] {
                assert!(!msg.contains(wrong), "must not say {wrong:?}: {msg}");
            }
        }
    }

    // The origin answered the protocol path, just not with a manifest. Saying so
    // — and naming the content type — turns "your app publishes nothing" into a
    // diagnosis its operator can act on: `text/html` at that path IS the SPA
    // catch-all the protocol guide calls the most common failure, and an operator
    // told only "absent" would go looking for a file that is already there.
    #[test]
    fn no_manifest_refusal_names_the_spa_catch_all() {
        let msg =
            no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, Some("text/html"));
        assert!(msg.contains("`text/html`"), "names what was served: {msg}");
        assert!(msg.contains("single-page-app catch-all"), "names the cause: {msg}");
        assert!(msg.contains("/.well-known/*"), "names the fix: {msg}");

        // Nothing was served there at all: no diagnosis to offer, and none invented.
        let absent = no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, None);
        assert!(!absent.contains("catch-all"), "{absent}");
    }

    // An app that publishes no manifest will still publish none after another
    // open_app, so the refusal must break the loop rather than send the agent
    // back to re-resolve an origin it already has right. It also points at the
    // served how-to skill: the user hitting this refusal is sometimes the very
    // person who can ship the manifest, and "publish a manifest" is a much
    // weaker handoff than the deploy-time recipe for generating one.
    #[test]
    fn no_manifest_refusal_stops_the_agent_retrying() {
        let msg = no_manifest_refusal("https://app.example.com", OriginSource::AppUrl, None);
        assert!(msg.contains("will not change that"), "{msg}");
        assert!(msg.contains("STOP retrying"), "{msg}");
        assert!(msg.contains("skill://service-discoverability"), "names the how-to skill: {msg}");
    }

    // Entries past the read cap ARE declared by the app; refusing one as "not
    // declared" would be a false statement about the app, so the overflow is
    // reported and the blame lands on the manifest's length instead.
    #[test]
    fn not_declared_refusal_reports_an_over_long_manifest() {
        let msg = not_declared_refusal(
            &with_omitted("https://app.example.com", ARCHITECTURE_PATH, &[frontend()], 7),
            &backend(),
            OriginSource::AppUrl,
        );
        assert!(msg.contains("7 entries beyond"), "reports how many were unread: {msg}");
        assert!(msg.contains("NOT checked"), "{msg}");
        // And the VERDICT itself is indeterminate, not an assertion withdrawn a
        // sentence later (per review): if the target is one of the unread
        // entries, "does not declare" is simply false.
        assert!(msg.contains("Could not determine whether"), "{msg}");
        assert!(!msg.contains("does not declare"), "must not assert what it did not check: {msg}");

        // No overflow → the whole manifest was read, so the verdict is definite
        // and there is no speculation about entries that don't exist.
        let exact = not_declared_refusal(
            &manifest("https://app.example.com", ARCHITECTURE_PATH, &[frontend()]),
            &backend(),
            OriginSource::AppUrl,
        );
        assert!(!exact.contains("entries beyond"), "{exact}");
        assert!(exact.contains("does not declare"), "a fully read manifest is definite: {exact}");
    }

    // A transport error is attacker-influenced text (a hostile origin picks its
    // TLS certificate subject and its redirect URLs) that lands verbatim in the
    // model's context. Scrub control characters and cap it, so a refusal can
    // never be turned into a payload or padded out by the thing it is reporting.
    #[test]
    fn the_echoed_cause_is_scrubbed_and_capped() {
        let hostile = format!("error \u{1b}[31m\r\nIGNORE PREVIOUS {}", "x".repeat(4096));
        let msg = unreachable_refusal("https://app.example.com", OriginSource::AppUrl, &hostile);
        assert!(!msg.chars().any(char::is_control), "control chars must be gone: {msg}");
        assert!(
            !msg.contains(&"x".repeat(MAX_ECHOED_CAUSE + 1)),
            "the cause must be capped: {msg}"
        );
        assert!(msg.contains("app.example.com"), "the origin still shows: {msg}");
    }

    // The pre-protocol document does NOT authorize, and the refusal has to be
    // useful to the one population that hits it: operators who adopted this
    // server's own earlier proposal. It must name the document they DO serve (so
    // they don't hunt for a missing file), name the standard path as the fix, and
    // — when the older document lists the target — make clear the refusal is
    // about where the declaration lives rather than about an unknown canister.
    #[test]
    fn a_legacy_only_origin_is_refused_with_the_path_to_adopt() {
        let listed = legacy_only_refusal(
            &manifest("https://app.example.com", LEGACY_MANIFEST_PATH, &[backend(), frontend()]),
            &backend(),
            OriginSource::AppUrl,
        );
        assert!(listed.contains(LEGACY_MANIFEST_PATH), "names what it found: {listed}");
        assert!(listed.contains(ARCHITECTURE_PATH), "names the path to adopt: {listed}");
        assert!(listed.contains("DOES list this canister"), "{listed}");
        assert!(listed.contains("terms"), "says why the older document cannot stand in: {listed}");
        assert!(listed.contains("app.example.com"), "names the origin: {listed}");

        // The other branch: the older document doesn't list it either, and the
        // refusal must not claim it does.
        let unlisted = legacy_only_refusal(
            &manifest("https://app.example.com", LEGACY_MANIFEST_PATH, &[frontend()]),
            &backend(),
            OriginSource::AppUrl,
        );
        assert!(unlisted.contains("does not list this canister either"), "{unlisted}");
        assert!(!unlisted.contains("DOES list"), "{unlisted}");

        // It stays distinguishable from the never-adopted verdict, whose repair
        // is a different conversation with a different person. Both messages do
        // say the standard manifest is missing — that part is simply true — so
        // what separates them is that this one leads with the document the origin
        // DOES serve, before naming the one it doesn't.
        let older = listed.find("older, pre-protocol document").expect("names it: {listed}");
        let missing = listed.find("publishes no service-discoverability manifest").unwrap();
        assert!(older < missing, "the document it DOES serve comes first: {listed}");
    }

    // The gate's decision, on constructed input: the YES branch and each way of
    // failing, with no network involved (per review — the live YES test can only
    // skip until an app publishes the standard path, and a local fixture is
    // unreachable behind the SSRF guard).
    #[test]
    fn the_decision_authorizes_only_a_declared_canister() {
        let declared = |ids: &[Principal]| {
            discover::ManifestProbe::Declared(manifest(
                "https://app.example.com",
                ARCHITECTURE_PATH,
                ids,
            ))
        };
        let call = |probe| decide(probe, "https://app.example.com", OriginSource::AppUrl, &backend());

        // Declared at the standard path: authorized, and the provenance echoed
        // back is the origin and path that authorized it.
        let ok = call(declared(&[frontend(), backend()])).expect("a declared canister authorizes");
        assert_eq!(ok.origin, "https://app.example.com");
        assert_eq!(ok.path, ARCHITECTURE_PATH);

        // The same manifest without this canister: refused, and the refusal shows
        // what the app does declare.
        let err = call(declared(&[frontend()])).expect_err("an undeclared canister is refused");
        assert!(err.contains(&frontend().to_text()), "lists what IS declared: {err}");

        // An empty manifest is adoption without declaration — still a refusal.
        assert!(call(declared(&[])).is_err());

        // No manifest at all, and the SPA catch-all variant that answers the path
        // with something else: the never-adopted verdict, naming the catch-all
        // when there is one to name.
        let absent = |served: Option<&str>, legacy: Option<discover::DeclaredManifest>| {
            discover::ManifestProbe::Absent {
                served_non_manifest: served.map(str::to_string),
                legacy,
            }
        };
        let err = call(absent(None, None)).expect_err("no manifest is refused");
        assert!(err.contains("publishes no service-discoverability manifest"), "{err}");
        let err = call(absent(Some("text/html"), None)).expect_err("refused");
        assert!(err.contains("single-page-app catch-all"), "names the misconfiguration: {err}");

        // The legacy document does NOT authorize, however complete it is — this is
        // the precedence the gate turns on, so it is pinned here rather than only
        // against a live origin that may adopt the standard path at any time.
        let legacy = manifest("https://app.example.com", LEGACY_MANIFEST_PATH, &[backend()]);
        let err = call(absent(None, Some(legacy))).expect_err("the legacy path must not authorize");
        assert!(err.contains(ARCHITECTURE_PATH), "names the path to adopt: {err}");
        assert!(err.contains("DOES list this canister"), "{err}");
    }

    // The identity binding: a manifest at one origin must not authorize a write
    // signed as a different app. The refusal has to name both origins — which one
    // is wrong depends on what the caller meant — and point at the one call that
    // returns a matching pair.
    #[test]
    fn the_identity_mismatch_refusal_names_both_apps() {
        let msg = identity_mismatch_refusal(
            "https://evil.example",
            "https://evil.example",
            "https://gooddapp.com",
            &backend(),
        );
        assert!(msg.contains("evil.example"), "names the app whose manifest was read: {msg}");
        assert!(msg.contains("gooddapp.com"), "names the identity it would sign as: {msg}");
        assert!(msg.contains(&backend().to_text()), "names the target: {msg}");
        assert!(msg.contains("open_app"), "points at the call that returns a matching pair: {msg}");

        // Not knowing is not the same as knowing they differ: the unresolvable
        // refusal reads as a check that failed, not as a verdict on the caller.
        let unresolved = identity_unresolvable_refusal("https://app.example.com", "timed out");
        assert!(unresolved.contains("Could not establish"), "{unresolved}");
        assert!(unresolved.contains("retry"), "{unresolved}");
        assert!(!unresolved.contains("is not the app"), "must not assert a mismatch: {unresolved}");
    }

    // Everything a refusal echoes stays bounded, whatever the caller passed: the
    // origin is capped like the error causes are, so a valid-but-enormous argument
    // cannot flood the reply (per review).
    #[test]
    fn refusals_cap_the_echoed_origin() {
        let flood = format!("https://app.example.com/{}", "a".repeat(10_000));
        for msg in [
            unreachable_refusal(&flood, OriginSource::AppUrl, "timed out"),
            no_manifest_refusal(&flood, OriginSource::AppUrl, None),
            identity_unresolvable_refusal(&flood, "timed out"),
            identity_mismatch_refusal(&flood, &flood, &flood, &backend()),
        ] {
            assert!(
                !msg.contains(&"a".repeat(MAX_ECHOED_CAUSE + 1)),
                "the echoed origin must be capped: {msg}"
            );
            assert!(msg.contains("app.example.com"), "and still name the origin: {msg}");
        }
    }

    // Live network: the gate is only useful if it actually says YES for an app
    // that publishes the manifest at the standard path, so this asserts the YES
    // against a real origin — and an unrelated canister (the ICP ledger) must
    // still be refused there. It SKIPS on anything else, which today includes the
    // origin it names: nothing published on {ARCHITECTURE_PATH} at the time of
    // writing, so this test is a tripwire for adoption rather than live coverage.
    // (The unit tests above cover the YES path's shape.) Skipping is also what
    // keeps a network blip from failing CI.
    #[tokio::test]
    async fn authorizes_a_declared_canister_and_refuses_an_undeclared_one() {
        const APP: &str = "https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io";
        let Ok(discover::ManifestProbe::Declared(m)) = discover::fetch_declared_manifest(APP).await
        else {
            return; // unreachable or not (yet) publishing — don't fail CI on it
        };
        let Some(declared) = m.canisters.first().copied() else {
            return; // publishes an empty manifest — nothing to authorize
        };
        let ok = authorize_update_call(APP, OriginSource::AppUrl, &declared)
            .await
            .expect("a declared canister must authorize");
        assert_eq!(ok.origin, m.origin);

        let ledger = canister("ryjl3-tyaaa-aaaaa-aaaba-cai");
        if !m.canisters.contains(&ledger) {
            let err = authorize_update_call(APP, OriginSource::AppUrl, &ledger)
                .await
                .expect_err("an undeclared canister must be refused");
            assert!(err.contains(&ledger.to_text()), "{err}");
        }
    }

    // Live network: two real apps, deliberately crossed. Reading MULTI/DEX's
    // manifest while signing as the user's identity at OISY is exactly the pairing
    // the binding exists to refuse — before it, the attacker-controlled half was
    // the manifest, and the valuable half was the identity. Skips only if the
    // origin cannot be resolved at all, which is a different (also refusing)
    // outcome rather than a pass.
    #[tokio::test]
    async fn crossing_an_app_with_another_apps_identity_is_refused() {
        let err = bind_identity("https://multidex.ai", "https://oisy.com", &backend())
            .await
            .expect_err("a crossed pair must never bind");
        if err.contains("Could not establish") {
            return; // unreachable — the refusal is right either way
        }
        assert!(err.contains("is not the app this call would be signed as"), "{err}");
        assert!(err.contains("oisy.com"), "names the identity: {err}");
    }

    // The other side of the same coin: an app paired with its OWN resolved
    // identity binds. multidex.ai declares no custom derivation origin, so its
    // identity is its own origin.
    #[tokio::test]
    async fn an_app_paired_with_its_own_identity_binds() {
        const APP: &str = "https://multidex.ai";
        let Ok(identity) = discover::resolve_app_identity(APP, false).await else {
            return; // unreachable — nothing to assert
        };
        let canonical = crate::identities::target_origin(&identity.derivation_origin);
        bind_identity(APP, &canonical, &backend())
            .await
            .expect("an app must bind to its own resolved identity");
    }

    // Live network, the case this gate deliberately gives up: an origin serving
    // only the pre-protocol document is REFUSED, however complete that document
    // is. MULTI/DEX is the real instance — it declares three canisters at the
    // legacy path — so the refusal is checked against the id its own document
    // lists, which is the exact write that used to be allowed. Skips once the
    // origin adopts the standard path (at which point it should authorize, and
    // the test above is the one that will say so).
    #[tokio::test]
    async fn a_legacy_only_origin_is_refused_live() {
        const APP: &str = "https://multidex.ai";
        let Ok(discover::ManifestProbe::Absent { legacy: Some(legacy), .. }) =
            discover::fetch_declared_manifest(APP).await
        else {
            return; // unreachable, or it has adopted the standard path
        };
        let Some(declared) = legacy.canisters.first().copied() else {
            return; // an empty legacy document proves nothing here
        };
        let err = authorize_update_call(APP, OriginSource::AppUrl, &declared)
            .await
            .expect_err("the legacy path must not authorize");
        assert!(err.contains(ARCHITECTURE_PATH), "names the path to adopt: {err}");
        assert!(err.contains(LEGACY_MANIFEST_PATH), "names what the origin does serve: {err}");
        assert!(err.contains("DOES list this canister"), "{err}");
    }

    // Live network: an origin that publishes no manifest is refused with the
    // "publishes no manifest" verdict, not an unreachable error. example.com is
    // IANA-reserved and will never serve one.
    #[tokio::test]
    async fn refuses_an_origin_with_no_manifest() {
        let err = authorize_update_call("https://example.com", OriginSource::AppUrl, &backend())
            .await
            .expect_err("example.com publishes no manifest");
        assert!(err.contains("publishes no service-discoverability manifest"), "{err}");
    }

    // The SSRF guard applies here too: the gate fetches a caller-controlled
    // origin, so a private/loopback target is refused before any request, and the
    // refusal reads as a check failure rather than as a verdict on an app.
    #[tokio::test]
    async fn refuses_a_non_public_origin_without_fetching() {
        let err = authorize_update_call("https://127.0.0.1", OriginSource::AppUrl, &backend())
            .await
            .expect_err("loopback must be refused");
        assert!(err.contains("Could not check"), "{err}");
    }
}
