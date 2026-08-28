//! **Who may write.** The authorization boundary for state-changing canister
//! calls (`canister_update_call`), in two layers.
//!
//! ## Layer 1 — the registration gate (this module)
//!
//! An update call is authorized only when ALL of the following hold. Any one
//! of them failing refuses the call; there is no default-allow path:
//!
//!   1. Layer 2 (below) does not refuse the method.
//!   2. The caller supplies an **`application_origin`** — the https origin of
//!      the application the call belongs to.
//!   3. That origin appears in [`REGISTERED_APPLICATIONS`] with an acceptance
//!      of the **current** ICP MCP Developer Terms
//!      ([`DEVELOPER_TERMS_VERSION`]).
//!   4. That exact origin serves a well-formed
//!      `/.well-known/ic-architecture` manifest — the composition layer of
//!      the [ICP service-discoverability protocol].
//!   5. The **target canister is declared in that manifest**.
//!   6. Only then does the call execute.
//!
//! All six must pass, so the ORDER only decides which refusal the caller
//! reads. Layer 2 is evaluated first because it is offline and its refusal is
//! the more specific and more useful one: "transfer 1 ICP" should be answered
//! with "do it in a wallet you control", not with "that application isn't
//! registered" — the latter reads as though a registration would make the
//! transfer possible. It also means a value-moving request never triggers an
//! outbound fetch, and never reveals whether the named origin is registered.
//!
//! ### Why this and not the older discovery signals
//!
//! This server can also *find* canisters behind a domain from a response
//! header, an `/env.json`, or literals mined out of a JS bundle (see
//! [`crate::discover`]). Those are useful for reading, and they remain — but
//! they are **evidence about bytes a frontend happened to ship**, not a
//! statement by the application about what it comprises. A canister id in a
//! bundle says nothing about who operates it, and anything that can serve a
//! header can claim any id. None of them can authorize a write. The
//! architecture manifest can: the application publishes it at its own origin,
//! over HTTPS, as its own declaration.
//!
//! ### Why `derivation_origin` cannot stand in for `application_origin`
//!
//! They are different things and the difference is load-bearing:
//!
//!   * A derivation origin is **shared** by design. This crate's own registry
//!     maps five NNS frontends onto one derivation origin and eight Oisy hosts
//!     onto another, and [`crate::identities::target_origin`] additionally
//!     collapses `<c>.icp0.io` and `<c>.icp.net` onto `<c>.ic0.app`. Keying
//!     authorization on it would let any frontend in such a set write against
//!     a sibling's manifest.
//!   * The manifest is served at the **application** origin, so the
//!     derivation origin is not even where it would be fetched from.
//!
//! So the two are separate arguments with separate jobs:
//! `application_origin` says *which application this call belongs to* (and is
//! what authorizes it); `derivation_origin` says *whose identity to act as*.
//!
//! ### What the protocol does NOT establish
//!
//! Serving a manifest is a technical statement, not a promise. It does not
//! establish that the publisher accepted any terms, that it is entitled to
//! expose every canister it lists, which of its update methods are safe to
//! call, or that its behaviour stays inside this server's policies. Those
//! come from the **ICP MCP Developer Terms** (`/developer-terms`), which the
//! publisher accepts out of band; [`REGISTERED_APPLICATIONS`] is this
//! server's record of who has. Hence step 2: the protocol proves composition,
//! the Terms carry the obligations, and an update call needs both.
//!
//! ## Layer 2 — the financial guard ([`crate::compliance`])
//!
//! Inside the authorized surface, standardized value-moving methods and calls
//! to known finance-related canisters are refused anyway. Layer 2 is
//! deliberately origin-blind — `disallowed_update_method` takes no origin — so
//! no amount of registration can launder a financial call through it.
//!
//! [ICP service-discoverability protocol]: https://docs.internetcomputer.org/guides/frontends/service-discoverability/

use candid::Principal;

use crate::{
    architecture::{self, Architecture, ArchitectureFetch, ARCHITECTURE_WELL_KNOWN},
    compliance, discover,
};

/// The revision of the ICP MCP Developer Terms an acceptance must be against
/// for update calls to be authorized. Bumping this **invalidates every
/// acceptance stamped with an older revision** — each publisher's row has to
/// be re-stamped after they accept the new revision, which is the intended
/// behaviour: a materially changed obligation nobody has agreed to yet must
/// not keep authorizing writes. Kept in step with the effective date on the
/// served `/developer-terms` page (pinned by a test in the serving binary).
pub const DEVELOPER_TERMS_VERSION: &str = "2026-08-28";

/// Where a publisher reads the obligations it is accepting. Named in every
/// refusal this module produces, so an agent can tell the user what the
/// application's developer would have to do.
pub const DEVELOPER_TERMS_URL: &str = "https://mcp.internetcomputer.org/developer-terms";

/// One application whose publisher has accepted the ICP MCP Developer Terms.
pub struct RegisteredApplication {
    /// The application origin, in canonical form — exactly what
    /// [`discover::normalize_origin`] produces (https, lowercased host,
    /// default port dropped, no path, no user-info). Pinned by a test.
    ///
    /// Keyed by **origin**, not by host — deliberately unlike
    /// [`crate::discover`]'s host-keyed derivation-origin registry: an
    /// acceptance is for the exact origin whose manifest was reviewed, and a
    /// different port is a different deployment that must not inherit it.
    pub origin: &'static str,
    /// Who accepted, for the audit trail.
    pub publisher: &'static str,
    /// The Developer Terms revision they accepted. Authorizes writes only
    /// while it equals [`DEVELOPER_TERMS_VERSION`].
    pub accepted_terms_version: &'static str,
    /// When the acceptance was recorded (ISO date).
    pub accepted_on: &'static str,
}

/// Applications whose publishers have accepted the ICP MCP Developer Terms,
/// and whose update surface is therefore reachable through this server.
///
/// **This table is empty, and that is the shipped default.** An empty registry
/// means no application can receive an update call through this server — the
/// gate fails closed for everyone until a publisher actually accepts the
/// Developer Terms and is added here. Adding a row is a reviewed change to
/// this file, which is also the audit record: who accepted, which revision,
/// and when.
///
/// Before adding a row, confirm — and record in the review — that:
///
///   * the publisher accepted revision [`DEVELOPER_TERMS_VERSION`], including
///     the clauses that it is entitled to expose every canister its manifest
///     lists and that its MCP-reachable operations stay inside this server's
///     financial and data policies;
///   * the origin is exactly the one whose `/.well-known/ic-architecture` was
///     reviewed, in canonical form;
///   * the manifest's canisters are the application's own.
///
/// One row is one ORIGIN. An application served at several origins (its own
/// domain and its `<canister>.icp0.io` gateway origin, say) needs a row per
/// origin it will be called with, each with a manifest at that origin — an
/// acceptance is not inherited across origins, and neither is a manifest.
///
/// **Revocation is removal**: deleting a row (or bumping
/// [`DEVELOPER_TERMS_VERSION`] past what a row carries) closes the gate for
/// that application from the first call after the change is deployed. This
/// table is compiled in, so revocation is a release, not a runtime switch;
/// what "no cache" buys is that nothing survives the release — there is no
/// TTL to wait out and no state to reconcile.
///
/// **What review cannot pin down**: a row is reviewed once, against the
/// manifest as it stood then, and the application can rewrite that manifest
/// afterwards — adding a canister widens its own write scope without asking.
/// That is deliberately not enforced here (the manifest must stay live, or a
/// legitimate deploy would break writes) and is instead an obligation under the
/// Developer Terms: the publisher warrants it is entitled to expose every
/// canister the manifest lists. Layer 2 still applies to whatever it adds, and
/// removing the row remains the remedy.
pub const REGISTERED_APPLICATIONS: &[RegisteredApplication] = &[];

/// What authorized a call, echoed back to the caller so an agent can see
/// exactly which application and which declared canister it acted on — and
/// catch an `application_origin` that resolved to the wrong app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The canonical application origin the call was authorized against.
    pub application_origin: String,
    /// How the application's own manifest describes the target canister
    /// (`name`/`role`/`description`, folded); `None` when it declares the id
    /// with no labels.
    pub canister_role: Option<String>,
}

/// The registered application at `origin`, looked up in `registry`. Both sides
/// are canonical origins, so the comparison is exact — no host-only match, no
/// case or port slack. Split from [`registration`] so tests can exercise the
/// lookup against their own table instead of the shipped one.
fn registration_in<'a>(
    registry: &'a [RegisteredApplication],
    origin: &str,
) -> Option<&'a RegisteredApplication> {
    registry.iter().find(|a| a.origin == origin)
}

/// The refusal for a call that arrived with no `application_origin`. Says what
/// to pass, where to get it, and — because an agent holding a
/// `derivation_origin` will otherwise try it here — why that is not the same
/// value.
fn missing_application_origin() -> String {
    format!(
        "`application_origin` is required for an update call and was not supplied. An update \
         call is authorized against the application it belongs to: pass the application's https \
         origin (e.g. `https://example.com` — scheme and host, no path), as returned by \
         open_app / resolve_app in `application_origin`. This is NOT the same value as \
         `derivation_origin`: several frontends can share one derivation origin, and the \
         `{ARCHITECTURE_WELL_KNOWN}` manifest that authorizes the call is served at the \
         application origin. Reads (canister_query) need no application origin — only \
         state-changing calls do."
    )
}

/// The refusal for an origin with no current acceptance on file. Deliberately
/// says the same thing whether the origin is absent or carries a stale
/// revision — both mean "no current acceptance", and the recovery is identical.
fn not_registered(registry: &[RegisteredApplication], origin: &str) -> String {
    // When NOTHING is registered, say so: otherwise an agent reads a
    // single-origin refusal as "try another origin" and burns a loop
    // rediscovering the same answer.
    let scope = if registry.is_empty() {
        " No applications are registered with this server at present, so this is the answer for          every application — do not retry with a different origin or canister id."
    } else {
        ""
    };
    format!(
        "Update calls to {origin} are not available: its developer has not accepted the current \
         ICP MCP Developer Terms (revision {DEVELOPER_TERMS_VERSION}). State-changing calls \
         through this server are limited to applications that publish a \
         `{ARCHITECTURE_WELL_KNOWN}` manifest under the ICP service-discoverability protocol AND \
         whose developer has accepted those Terms — everything else is refused, including \
         canisters this server can otherwise discover behind the domain.{scope} Reading the \
         application is unaffected: use canister_query (and the OQL tools) instead. If you are \
         the application's developer, the Terms and how to register are at {DEVELOPER_TERMS_URL}."
    )
}

/// Steps 2–3, offline: turn a caller-supplied `application_origin` into a
/// registered application with a current acceptance, or a refusal.
///
/// Note the order: the registry is consulted BEFORE anything is fetched, so a
/// caller can never steer this server's HTTP client at an origin of its
/// choosing — the only origins ever fetched are ones already curated into
/// [`REGISTERED_APPLICATIONS`].
fn authorized_origin_in<'a>(
    registry: &'a [RegisteredApplication],
    application_origin: Option<&str>,
) -> Result<(String, &'a RegisteredApplication), String> {
    // 2. The argument is required. An empty or whitespace-only string counts
    //    as absent, so a client that "passes" the field blank gets the
    //    instructive refusal rather than an origin-not-registered one.
    let raw = application_origin.map(str::trim).filter(|s| !s.is_empty());
    let Some(raw) = raw else {
        return Err(missing_application_origin());
    };
    // Canonicalize with the same function every site fetch in this crate uses:
    // https only, real host, no user-info, default port dropped. NOT
    // `identities::target_origin` — that one remaps gateway domains for
    // IDENTITY derivation, which would fetch the manifest from a different
    // host than the caller named.
    let Some(origin) = discover::normalize_origin(raw) else {
        return Err(format!(
            "`application_origin` must be an https origin (scheme + host, e.g. \
             `https://example.com`); {raw:?} is not one. Pass the application origin from \
             open_app / resolve_app."
        ));
    };
    // 3. A current acceptance of the Developer Terms, on the exact origin.
    let app = registration_in(registry, &origin)
        .ok_or_else(|| not_registered(registry, &origin))?;
    if app.accepted_terms_version != DEVELOPER_TERMS_VERSION {
        return Err(not_registered(registry, &origin));
    }
    Ok((origin, app))
}

/// Steps 4–5, pure: decide against a manifest that has already been fetched
/// (or failed to be). Separated from the fetch so the whole decision is
/// testable offline — the fetch itself adds no policy.
fn decide(
    application_origin: &str,
    fetched: &ArchitectureFetch,
    canister_id: &Principal,
) -> Result<Authorization, String> {
    // 4. The exact origin's manifest. Both failure modes deny; they differ
    //    only in what the developer would have to fix, so say which it is
    //    (a fetch failure is worth retrying, a denial is not).
    let arch: &Architecture = match fetched {
        ArchitectureFetch::Served(arch) => arch,
        ArchitectureFetch::Unreachable(why) => {
            return Err(format!(
                "Update calls to {application_origin} could not be authorized: its \
                 `{ARCHITECTURE_WELL_KNOWN}` manifest could not be read ({why}). The manifest \
                 is re-read on every state-changing call and no call proceeds without it, so \
                 this is worth retrying; if it keeps failing, the application's origin is not \
                 serving the manifest reachably. Reads are unaffected — use canister_query."
            ))
        }
        ArchitectureFetch::NotDeclared(why) => {
            return Err(format!(
                "Update calls to {application_origin} are not available: {why}. Under the ICP \
                 service-discoverability protocol an application declares the canisters it \
                 comprises in `{ARCHITECTURE_WELL_KNOWN}`, and this server authorizes a \
                 state-changing call only against that declaration. Reads are unaffected — use \
                 canister_query."
            ))
        }
    };
    // 5. The target must be one of the canisters the application declares.
    //    This is the step that makes discovery non-authorizing: an id mined
    //    from a bundle, an `/env.json`, or a response header reaches this
    //    check with no standing whatsoever.
    let Some(canister_role) = arch.role_of(canister_id) else {
        let declared = declared_ids(arch);
        return Err(format!(
            "{canister_id} is not declared by {application_origin}: its \
             `{ARCHITECTURE_WELL_KNOWN}` manifest lists {declared}. A state-changing call is \
             authorized only against the application's own declaration — finding a canister id \
             behind a domain some other way (a response header, an `/env.json`, a JS bundle) \
             does not authorize writing to it. Check the canister id, or call the application \
             origin that does declare it. Reading this canister is unaffected — use \
             canister_query."
        ));
    };
    Ok(Authorization {
        application_origin: application_origin.to_string(),
        canister_role,
    })
}

/// The declared ids, for the "not declared" refusal — bounded so a large
/// manifest can't turn one refusal into a wall of principals.
fn declared_ids(arch: &Architecture) -> String {
    const MAX_LISTED: usize = 12;
    let ids: Vec<String> = arch.findings().into_iter().map(|(id, _)| id).collect();
    if ids.is_empty() {
        return "no canisters".to_string();
    }
    if ids.len() > MAX_LISTED {
        format!(
            "{} (and {} more)",
            ids[..MAX_LISTED].join(", "),
            ids.len() - MAX_LISTED
        )
    } else {
        ids.join(", ")
    }
}

/// The whole gate: steps 1–6 for one update call. `Ok` means the call is
/// authorized and may execute; `Err` is the complete refusal text for the
/// caller. Fails closed at every step.
///
/// A thin binding of [`authorize_with`] to the shipped registry and the real
/// manifest fetch. The policy itself lives there, and the tests drive THAT
/// function — with their own registry and their own fetch — so no test
/// re-implements the chain this function walks.
pub async fn authorize_update_call(
    application_origin: Option<&str>,
    canister_id: &Principal,
    method: &str,
) -> Result<Authorization, String> {
    authorize_with(
        REGISTERED_APPLICATIONS,
        application_origin,
        canister_id,
        method,
        |origin| async move { architecture::fetch_architecture(&origin).await },
    )
    .await
}

/// The gate's six steps, with the registry and the manifest fetch injected.
///
/// `fetch` is called with the canonical application origin, and — this is a
/// property, not an implementation detail — is called at most once, and ONLY
/// after steps 1–3 have passed. That is what keeps the set of origins this
/// server will ever fetch from equal to the curated registry: a caller cannot
/// make it request an origin of their choosing, whatever they pass.
async fn authorize_with<F, Fut>(
    registry: &[RegisteredApplication],
    application_origin: Option<&str>,
    canister_id: &Principal,
    method: &str,
    fetch: F,
) -> Result<Authorization, String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = ArchitectureFetch>,
{
    // 1. Layer 2 first: offline, and the more specific refusal for the request
    //    the caller actually made (see the module docs). A value-moving call is
    //    therefore answered without reaching the network or the registry at all.
    if let Some(refusal) = compliance::disallowed_update_method(canister_id, method) {
        return Err(refusal);
    }
    // 2–3. The argument, and a current acceptance on that exact origin.
    let (origin, app) = authorized_origin_in(registry, application_origin)?;
    // 4–5. The manifest, fetched fresh with no cache — so a manifest change or
    //      a revocation takes effect on the next call, not at the end of a TTL.
    let fetched = fetch(origin.clone()).await;
    let authorization = match decide(&origin, &fetched, canister_id) {
        Ok(a) => a,
        Err(refusal) => {
            // Refused after the caller cleared registration: the operator's
            // signal that a REGISTERED application's manifest is unreadable or
            // has stopped declaring a canister its users are calling. The
            // refusal text goes to the caller; this is the operational half.
            tracing::info!(
                application_origin = %origin,
                publisher = %app.publisher,
                canister_id = %canister_id,
                method = %method,
                "refused an update call at a registered application's manifest"
            );
            return Err(refusal);
        }
    };
    // 6. One line per authorized write, naming what authorized it: the
    //    operator's record of which registration admitted a state-changing call.
    tracing::info!(
        application_origin = %origin,
        publisher = %app.publisher,
        terms_version = %app.accepted_terms_version,
        accepted_on = %app.accepted_on,
        canister_id = %canister_id,
        method = %method,
        "authorized an update call against a registered application"
    );
    Ok(authorization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::architecture::parse_architecture;

    // A registry standing in for the shipped one. Tests must not depend on
    // curation: the shipped table is empty by design, and a real acceptance is
    // a legal fact, not a fixture.
    const TEST_REGISTRY: &[RegisteredApplication] = &[
        RegisteredApplication {
            origin: "https://example-app.test",
            publisher: "Example App GmbH",
            accepted_terms_version: DEVELOPER_TERMS_VERSION,
            accepted_on: "2026-08-28",
        },
        RegisteredApplication {
            origin: "https://stale-app.test",
            publisher: "Stale App GmbH",
            accepted_terms_version: "2026-01-01",
            accepted_on: "2026-01-01",
        },
    ];

    const REGISTERED: &str = "https://example-app.test";

    // Deliberately NOT the ids from the spec's example manifest: those belong
    // to a real exchange and are on the finance list, so Layer 2 would refuse
    // them and mask what these tests are checking. These are ordinary app
    // canisters on no list.
    const APP_BACKEND: &str = "dmp3l-2yaaa-aaaae-aamva-cai";
    const APP_FRONTEND: &str = "bkyz2-fmaaa-aaaaa-qaaaq-cai";
    const ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";

    fn p(s: &str) -> Principal {
        Principal::from_text(s).unwrap()
    }

    /// A served manifest declaring exactly `ids`.
    fn manifest(ids: &[&str]) -> ArchitectureFetch {
        let entries: Vec<String> = ids
            .iter()
            .map(|id| format!(r#"{{"id":"{id}","name":"backend","role":"the backend"}}"#))
            .collect();
        let body = format!(r#"{{"version":"1.0.0","canisters":[{}]}}"#, entries.join(","));
        ArchitectureFetch::Served(parse_architecture(&body).expect("fixture manifest parses"))
    }

    /// A served manifest from a literal body.
    fn served(body: &str) -> ArchitectureFetch {
        ArchitectureFetch::Served(parse_architecture(body).expect("fixture parses"))
    }

    /// Drive the PRODUCTION gate — [`authorize_with`], the very function
    /// [`authorize_update_call`] binds — against a chosen registry and a canned
    /// manifest, reporting how many times the fetch was reached. No test
    /// re-implements the chain, so a step added to or reordered in the gate
    /// cannot slip past these.
    async fn gate(
        registry: &[RegisteredApplication],
        application_origin: Option<&str>,
        fetched: ArchitectureFetch,
        canister_id: &Principal,
        method: &str,
    ) -> (Result<Authorization, String>, usize) {
        let fetches = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let counter = std::rc::Rc::clone(&fetches);
        let result = authorize_with(
            registry,
            application_origin,
            canister_id,
            method,
            |origin| async move {
                counter.set(counter.get() + 1);
                assert_eq!(
                    discover::normalize_origin(&origin).as_deref(),
                    Some(origin.as_str()),
                    "the gate must hand the fetch a canonical origin"
                );
                fetched
            },
        )
        .await;
        (result, fetches.get())
    }

    /// The common case: the gate over [`TEST_REGISTRY`], result only.
    async fn authorize(
        application_origin: Option<&str>,
        fetched: ArchitectureFetch,
        canister_id: &Principal,
        method: &str,
    ) -> Result<Authorization, String> {
        gate(TEST_REGISTRY, application_origin, fetched, canister_id, method).await.0
    }

    // (c) The happy path: a registered application, a canister its own manifest
    // declares, an ordinary method — authorized, the echo names what authorized
    // it, and the manifest was actually read.
    #[tokio::test]
    async fn registered_app_can_update_a_declared_canister() {
        let (result, fetches) = gate(
            TEST_REGISTRY,
            Some(REGISTERED),
            manifest(&[APP_FRONTEND, APP_BACKEND]),
            &p(APP_BACKEND),
            "place_order",
        )
        .await;
        let auth = result.expect("a registered app's declared canister must be authorized");
        assert_eq!(auth.application_origin, REGISTERED);
        assert_eq!(auth.canister_role.as_deref(), Some("the backend (backend)"));
        assert_eq!(fetches, 1, "the manifest is read once per call, not zero or twice");
    }

    // The origin argument is canonicalized before the lookup, so the same
    // application reached with a differently-spelled origin still authorizes —
    // and a non-https or malformed value is refused outright rather than
    // silently upgraded.
    #[tokio::test]
    async fn application_origin_is_canonicalized_then_matched_exactly() {
        for spelling in [
            REGISTERED,
            "HTTPS://Example-App.TEST",
            "https://example-app.test:443",
            "  https://example-app.test/  ",
            "example-app.test", // bare host: https is prepended
        ] {
            let r = authorize(Some(spelling), manifest(&[APP_BACKEND]), &p(APP_BACKEND), "ping")
                .await;
            assert!(r.is_ok(), "{spelling} must resolve to the registered origin");
        }
        for bad in [
            "http://example-app.test",       // not https
            "https://user@example-app.test", // user-info
            "https://example-app.test:8443", // a different origin, not registered
            "not a url",
        ] {
            let (r, fetches) = gate(
                TEST_REGISTRY,
                Some(bad),
                manifest(&[APP_BACKEND]),
                &p(APP_BACKEND),
                "ping",
            )
            .await;
            assert!(r.is_err(), "{bad} must not authorize");
            assert_eq!(fetches, 0, "{bad} must not become a fetch target");
        }
    }

    // (a) Provenance cannot authorize. A canister the application does not
    // declare is refused however this server found it — the gate never sees a
    // `sources` list (its signature has no way to receive one), so a bundle
    // literal, an `/env.json` key, a response header, or any other heuristic
    // has no path to an authorization.
    #[tokio::test]
    async fn only_the_manifest_authorizes_never_discovery() {
        // Stand in for the OISY backend as this server really discovers it: from
        // a labelled JS-bundle constant and the gateway header, never from a
        // manifest. It is a real canister, reachable, and the app it belongs to
        // is not the one being called.
        let mined = p("be2us-64aaa-aaaaa-qaabq-cai");
        let msg = authorize(
            Some(REGISTERED),
            manifest(&[APP_FRONTEND, APP_BACKEND]),
            &mined,
            "set_name",
        )
        .await
        .expect_err("an undeclared canister must be refused");
        assert!(msg.contains(&mined.to_text()), "the refusal names the id: {msg}");
        assert!(msg.contains(ARCHITECTURE_WELL_KNOWN), "and the manifest path: {msg}");
        assert!(msg.contains("does not authorize writing"), "and why: {msg}");
        // The same canister IS writable from the application that declares it —
        // so what the previous assertion caught is the missing declaration, not
        // something incidental about the id.
        assert!(
            authorize(Some(REGISTERED), manifest(&[mined.to_text().as_str()]), &mined, "set_name")
                .await
                .is_ok(),
            "declared by the application, the same id authorizes"
        );
        // An application declaring NOTHING authorizes nothing.
        assert!(authorize(Some(REGISTERED), manifest(&[]), &p(APP_BACKEND), "set_name")
            .await
            .is_err());
    }

    // Membership is decided on parsed principals, so no spelling of a declared
    // id can be mistaken for a different canister — and a padded entry still
    // matches the canister it names.
    #[tokio::test]
    async fn membership_compares_parsed_principals() {
        let padded = served(&format!(
            r#"{{"version":"1.0.0","canisters":[{{"id":"  {APP_BACKEND}  "}}]}}"#
        ));
        assert!(
            authorize(Some(REGISTERED), padded, &p(APP_BACKEND), "ping").await.is_ok(),
            "a padded declaration still names its canister"
        );
        // An entry that is not a principal at all authorizes nothing, even
        // though its text is a prefix of a real id.
        let junk = served(r#"{"version":"1.0.0","canisters":[{"id":"dmp3l-2yaaa"}]}"#);
        assert!(
            authorize(Some(REGISTERED), junk, &p(APP_BACKEND), "ping").await.is_err(),
            "a non-principal entry must not authorize a lookalike"
        );
    }

    // (b) A canister that IS declared still gets no write access when the
    // application's developer has no current Terms acceptance — and the registry
    // is consulted BEFORE any fetch, which is what keeps the set of origins this
    // server will fetch from equal to the curated registry.
    #[tokio::test]
    async fn declared_but_unaccepted_terms_does_not_authorize() {
        let (result, fetches) = gate(
            TEST_REGISTRY,
            Some("https://unregistered.test"),
            manifest(&[APP_BACKEND]),
            &p(APP_BACKEND),
            "place_order",
        )
        .await;
        let msg = result.expect_err("an unregistered origin must be refused");
        assert!(msg.contains("Developer Terms"), "{msg}");
        assert!(msg.contains(DEVELOPER_TERMS_VERSION), "{msg}");
        assert!(msg.contains("canister_query"), "reads stay available: {msg}");
        assert_eq!(
            fetches, 0,
            "an unregistered origin must never be fetched — that is what keeps the fetch \
             target curated rather than caller-chosen"
        );
    }

    // (e) A Terms bump closes the gate for a stale acceptance: the check is
    // equality against the current revision, not "has ever accepted".
    #[tokio::test]
    async fn a_stale_terms_acceptance_does_not_authorize() {
        assert_ne!(
            registration_in(TEST_REGISTRY, "https://stale-app.test")
                .expect("the row exists")
                .accepted_terms_version,
            DEVELOPER_TERMS_VERSION,
            "fixture must carry an old revision"
        );
        let (result, fetches) = gate(
            TEST_REGISTRY,
            Some("https://stale-app.test"),
            manifest(&[APP_BACKEND]),
            &p(APP_BACKEND),
            "place_order",
        )
        .await;
        let msg = result.expect_err("a stale acceptance must be refused");
        assert!(msg.contains(DEVELOPER_TERMS_VERSION), "{msg}");
        assert_eq!(fetches, 0, "a stale row is not a fetch target either");
    }

    // (e) Revocation is removal, and it takes effect on the next call: the same
    // origin and canister, authorized against a registry that still holds the
    // row, refused against one that no longer does.
    #[tokio::test]
    async fn revocation_closes_the_gate_on_the_next_call() {
        let call = |registry: &'static [RegisteredApplication]| async move {
            gate(registry, Some(REGISTERED), manifest(&[APP_BACKEND]), &p(APP_BACKEND), "ping")
                .await
                .0
        };
        assert!(call(TEST_REGISTRY).await.is_ok(), "registered while the row is present");
        let msg = call(&[]).await.expect_err("removing the row refuses the very next call");
        assert!(msg.contains("Developer Terms"), "{msg}");
    }

    // (e) A manifest change takes effect on the next call: the decision is a
    // function of the manifest read during THAT call, with nothing memoized
    // between calls. If a cache is ever added, this test becomes its TTL
    // contract and must advance a clock.
    #[tokio::test]
    async fn a_manifest_that_drops_the_canister_stops_authorizing() {
        assert!(
            authorize(Some(REGISTERED), manifest(&[APP_BACKEND]), &p(APP_BACKEND), "place_order")
                .await
                .is_ok(),
            "declared: authorized"
        );
        let msg =
            authorize(Some(REGISTERED), manifest(&[APP_FRONTEND]), &p(APP_BACKEND), "place_order")
                .await
                .expect_err("dropped from the manifest: refused");
        assert!(msg.contains("is not declared by"), "{msg}");
        // And back again, so the second result is the new manifest talking
        // rather than a one-way latch.
        assert!(
            authorize(Some(REGISTERED), manifest(&[APP_BACKEND]), &p(APP_BACKEND), "place_order")
                .await
                .is_ok(),
            "re-declared: authorized again"
        );
    }

    // (e) Fail closed when the manifest cannot be read at all — and say so
    // distinguishably, since a fetch failure is worth retrying while a denial
    // is not.
    #[tokio::test]
    async fn an_unreadable_manifest_fails_closed_and_says_it_is_retryable() {
        let msg = authorize(
            Some(REGISTERED),
            ArchitectureFetch::Unreachable("dns failure".into()),
            &p(APP_BACKEND),
            "place_order",
        )
        .await
        .expect_err("an unreachable manifest must refuse");
        assert!(msg.contains("could not be read"), "{msg}");
        assert!(msg.contains("worth retrying"), "{msg}");

        let msg = authorize(
            Some(REGISTERED),
            ArchitectureFetch::NotDeclared("answered 404".into()),
            &p(APP_BACKEND),
            "place_order",
        )
        .await
        .expect_err("a missing manifest must refuse");
        assert!(msg.contains("answered 404"), "{msg}");
        assert!(!msg.contains("worth retrying"), "a denial is not a retry: {msg}");
    }

    // (d) Layer 2 still refuses inside the authorized surface. Registration buys
    // an application access to its OWN declared canisters; it does not make a
    // value-moving call acceptable — even when the application declares the
    // ledger in its own manifest. Layer 2 is also evaluated FIRST, so the caller
    // gets the wallet redirect rather than a registration message, and the call
    // costs no fetch.
    #[tokio::test]
    async fn the_financial_guard_still_refuses_inside_an_authorized_surface() {
        // A standardized transfer is refused on any canister…
        let (result, fetches) = gate(
            TEST_REGISTRY,
            Some(REGISTERED),
            manifest(&[APP_BACKEND, ICP_LEDGER]),
            &p(APP_BACKEND),
            "icrc1_transfer",
        )
        .await;
        let msg = result.expect_err("a standardized transfer must stay refused");
        assert!(msg.contains("icrc1_transfer"), "{msg}");
        assert!(msg.contains("oisy.com"), "the redirect is to a wallet the user controls: {msg}");
        assert_eq!(fetches, 0, "a value-moving call is refused without reaching the network");
        // …and every update on a known finance canister is refused, whatever the
        // application says about it.
        let msg = authorize(
            Some(REGISTERED),
            manifest(&[APP_BACKEND, ICP_LEDGER]),
            &p(ICP_LEDGER),
            "transfer",
        )
        .await
        .expect_err("the ledger must stay refused");
        assert!(msg.contains("the ICP ledger"), "{msg}");
        // The same non-financial method on the app's own canister is fine, so
        // the refusals above are Layer 2 talking, not Layer 1.
        assert!(authorize(
            Some(REGISTERED),
            manifest(&[APP_BACKEND, ICP_LEDGER]),
            &p(APP_BACKEND),
            "place_order"
        )
        .await
        .is_ok());
    }

    // Layer 2 runs before the registration checks, so a value-moving request is
    // answered the same way whether or not the named application is registered:
    // the caller learns to use their own wallet, and learns nothing about the
    // registry by probing with one.
    #[tokio::test]
    async fn the_financial_refusal_does_not_depend_on_registration() {
        for origin in [Some(REGISTERED), Some("https://unregistered.test"), None] {
            let msg = authorize(origin, manifest(&[ICP_LEDGER]), &p(ICP_LEDGER), "icrc1_transfer")
                .await
                .expect_err("a transfer must be refused whatever the origin");
            assert!(
                msg.contains("icrc1_transfer") && !msg.contains("Developer Terms"),
                "{origin:?} must get the financial refusal, not a registration one: {msg}"
            );
        }
    }

    // (1) The argument is mandatory, and the refusal teaches the recovery —
    // including that the derivation origin is a different value, which is the
    // mistake an agent holding one will otherwise make.
    #[tokio::test]
    async fn a_missing_application_origin_is_refused_with_the_recovery() {
        for missing in [None, Some(""), Some("   ")] {
            let msg = authorize(missing, manifest(&[APP_BACKEND]), &p(APP_BACKEND), "ping")
                .await
                .expect_err("an absent application_origin must be refused");
            assert!(msg.contains("`application_origin` is required"), "{msg}");
            assert!(msg.contains("derivation_origin"), "names the confusable value: {msg}");
            assert!(msg.contains("open_app"), "says where to get it: {msg}");
        }
    }

    // The shipped registry is well-formed: canonical origins, no duplicates, no
    // blank fields, and no row carrying a revision other than the current one (a
    // stale row is dead weight that reads as authorization). Vacuously true while
    // the table is empty — which is the shipped default, so this test is the
    // guard for the day rows are added.
    #[test]
    fn the_shipped_registry_is_well_formed() {
        let mut seen: Vec<&str> = Vec::new();
        for app in REGISTERED_APPLICATIONS {
            assert_eq!(
                discover::normalize_origin(app.origin).as_deref(),
                Some(app.origin),
                "{}: origins must be stored in canonical form",
                app.origin
            );
            assert!(!seen.contains(&app.origin), "{}: duplicate row", app.origin);
            seen.push(app.origin);
            assert!(!app.publisher.trim().is_empty(), "{}: publisher required", app.origin);
            assert!(!app.accepted_on.trim().is_empty(), "{}: acceptance date required", app.origin);
            assert_eq!(
                app.accepted_terms_version, DEVELOPER_TERMS_VERSION,
                "{}: a row that does not carry the current Terms revision authorizes nothing — \
                 re-stamp it after the publisher accepts, or remove it",
                app.origin
            );
        }
    }

    // An EMPTY shipped registry authorizes nothing at all — the state this
    // server ships in. Pinned so "the gate fails closed for everyone until a
    // publisher is added" is a tested property rather than a claim in a doc
    // comment, and so a future default-allow path cannot creep in unnoticed.
    // The refusal also SAYS the registry is empty, so an agent stops instead of
    // looping over other origins and canister ids to reach the same answer.
    #[tokio::test]
    async fn an_empty_registry_authorizes_nothing_and_says_so() {
        for origin in [Some(REGISTERED), Some("https://anything.test")] {
            let (result, fetches) =
                gate(&[], origin, manifest(&[APP_BACKEND]), &p(APP_BACKEND), "place_order").await;
            let msg = result.expect_err("must be refused against an empty registry");
            assert!(
                msg.contains("No applications are registered"),
                "{origin:?}: the refusal must say the registry is empty: {msg}"
            );
            assert!(msg.contains("do not retry"), "{origin:?}: and say not to loop: {msg}");
            assert_eq!(fetches, 0, "{origin:?} must not be fetched");
        }
        // A missing argument still gets the argument's own refusal, not the
        // empty-registry one — the caller's first problem is the one to fix.
        let msg = gate(&[], None, manifest(&[APP_BACKEND]), &p(APP_BACKEND), "place_order")
            .await
            .0
            .expect_err("no origin at all must be refused");
        assert!(msg.contains("`application_origin` is required"), "{msg}");
        // …and a non-empty registry does not carry the empty-registry wording.
        let msg = authorize(
            Some("https://unregistered.test"),
            manifest(&[APP_BACKEND]),
            &p(APP_BACKEND),
            "place_order",
        )
        .await
        .expect_err("refused");
        assert!(!msg.contains("No applications are registered"), "{msg}");
    }

    // The fixture registry is held to the same shape as the shipped one, so it
    // can't drift into testing something the real table could never be. (The
    // deliberately-stale row is exempt from the revision rule — it exists to
    // prove the revision rule.)
    #[test]
    fn the_test_registry_mirrors_the_shipped_shape() {
        for app in TEST_REGISTRY {
            assert_eq!(
                discover::normalize_origin(app.origin).as_deref(),
                Some(app.origin),
                "{}: fixture origins must be canonical too",
                app.origin
            );
        }
    }
}
