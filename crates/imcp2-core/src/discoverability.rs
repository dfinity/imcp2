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
//!     declared by no manifest at all.
//!   * It gates **writes only**. Reads (`canister_query`, `get_canister_candid`,
//!     the OQL surface) and discovery are unchanged on every canister: the
//!     protocol exists to make apps *more* legible to agents, and it would be a
//!     strange reading of it to make this server see less.
//!
//! The legacy `/.well-known/ic-app.json` path counts too (see
//! [`discover::LEGACY_MANIFEST_PATH`]): it is the same document at the path this server
//! proposed before the protocol was published, so the handful of apps that
//! adopted the proposal are not cut off the day the standard path lands. New
//! apps should publish [`ARCHITECTURE_PATH`].

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
    let manifest = match discover::fetch_declared_manifest(app_origin).await {
        Ok(m) => m,
        Err(e) => return Err(unreachable_refusal(app_origin, source, &e)),
    };
    let Some(manifest) = manifest else {
        return Err(no_manifest_refusal(app_origin, source));
    };
    if manifest.canisters.contains(canister_id) {
        return Ok(Declaration { origin: manifest.origin, path: manifest.path });
    }
    Err(not_declared_refusal(&manifest, canister_id, source))
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
    format!(
        "Could not check whether {app_origin} declares this canister: {error}. {} The call is \
         refused rather than made blind. This is likely transient — retry; if it persists, confirm \
         that {} names the app's real origin (open_app returns it).",
        the_rule(),
        source.arg()
    )
}

/// The origin answered, but serves no manifest at either well-known path. The
/// common causes are a wrong origin and an app that simply has not adopted the
/// protocol, so the refusal addresses both and tells the agent what to say.
fn no_manifest_refusal(app_origin: &str, source: OriginSource) -> String {
    let mut msg = format!(
        "{app_origin} publishes no service-discoverability manifest at {ARCHITECTURE_PATH}, so \
         this connector will not make a state-changing call to its canisters. {} ",
        the_rule()
    );
    if source == OriginSource::DerivationOrigin {
        msg.push_str(
            "This origin came from `derivation_origin`, which is not always where the app serves \
             its manifest — pass the app's website URL as `app_url` and try again. ",
        );
    }
    msg.push_str(&format!(
        "Otherwise: if this is NOT the app's origin (a marketing site, a docs host, a guessed \
         domain), pass the right `app_url` — open_app resolves one from the app's name or URL. If \
         it IS the app's origin, the app has not adopted the protocol: tell the user that this \
         write cannot be made for them here, and that the app's operators can enable it by \
         publishing the manifest ({SERVICE_DISCOVERABILITY_GUIDE}); they can also perform the \
         action themselves in the app's own frontend. {READS_ARE_FINE}"
    ));
    msg
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
        discover::DeclaredManifest {
            origin: origin.to_string(),
            path,
            canisters: ids.to_vec(),
        }
    }

    // Every refusal states the SAME rule, names the standard path, and links the
    // guide — an app owner reading a relayed refusal must be able to act on it
    // without anyone explaining the protocol to them first.
    #[test]
    fn every_refusal_states_the_rule_and_links_the_guide() {
        let refusals = [
            missing_origin_refusal(&backend()),
            unreachable_refusal("https://app.example.com", OriginSource::AppUrl, "timed out"),
            no_manifest_refusal("https://app.example.com", OriginSource::AppUrl),
            not_declared_refusal(
                &manifest("https://app.example.com", ARCHITECTURE_PATH, &[frontend()]),
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
            no_manifest_refusal("https://app.example.com", OriginSource::AppUrl),
            not_declared_refusal(
                &manifest("https://app.example.com", ARCHITECTURE_PATH, &[frontend()]),
                &backend(),
                OriginSource::AppUrl,
            ),
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
        let from_url = no_manifest_refusal("https://app.example.com", OriginSource::AppUrl);
        assert!(from_url.contains("`app_url`"), "{from_url}");
        assert!(!from_url.contains("came from `derivation_origin`"), "{from_url}");

        let from_origin =
            no_manifest_refusal("https://app.example.com", OriginSource::DerivationOrigin);
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
            &manifest("https://app.example.com", LEGACY_MANIFEST_PATH, &[]),
            &backend(),
            OriginSource::AppUrl,
        );
        assert!(msg.contains("declares no canisters at all"), "{msg}");
        assert!(msg.contains(LEGACY_MANIFEST_PATH), "names the path that answered: {msg}");
    }

    // Live network: the gate is only useful if it actually says YES for an app
    // that publishes the manifest. The reference app from the protocol guide
    // declares its frontend and backend, so both must authorize against it and an
    // unrelated canister (the ICP ledger) must not. Best-effort on reachability:
    // a network blip must not fail CI, so an unreachable origin is skipped rather
    // than asserted on.
    #[tokio::test]
    async fn authorizes_a_declared_canister_and_refuses_an_undeclared_one() {
        const APP: &str = "https://hcv4s-uaaaa-aaabq-qaaba-cai.icp0.io";
        let Ok(Some(m)) = discover::fetch_declared_manifest(APP).await else {
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
