//! The Rust types and method names against the hand-written `.did`.
//!
//! Structural equality (`candid::types::subtype::equal`) is stricter than
//! subtyping both ways: field and variant names, their types, `opt`-ness and
//! the arity of every method must all match exactly.

use std::collections::{BTreeSet, HashSet};

use candid::types::internal::TypeContainer;
use candid::types::subtype::equal;
use candid::types::{Type, TypeInner};
use candid::{CandidType, TypeEnv};
use candid_parser::utils::CandidSource;

use crate::*;

fn did() -> (TypeEnv, Type) {
    let (env, actor) =
        CandidSource::Text(CANDID).load().expect("imcp2_session.did parses and type-checks");
    (env, actor.expect("imcp2_session.did declares a service"))
}

/// Asserts that the Candid type of `T` equals `expected`, a type of `env`.
fn assert_equal<T: CandidType>(env: &TypeEnv, expected: &Type, what: &str) {
    // A fresh copy per check: merging renames the Rust side's names that clash
    // with the .did's (`SessionRecord` -> `SessionRecord/1`), and those must not
    // leak into the next comparison.
    let mut env = env.clone();
    let mut rust = TypeContainer::new();
    let actual = rust.add::<T>();
    let actual = env.merge_type(rust.env, actual);
    if let Err(e) = equal(&mut HashSet::new(), &env, expected, &actual) {
        panic!("{what}: the Rust type differs from imcp2_session.did: {e:#}");
    }
}

type Check = fn(&TypeEnv, &Type, &str);

/// The Rust counterpart of every named type of the `.did`.
fn named_types() -> Vec<(&'static str, Check)> {
    vec![
        ("Key", assert_equal::<Key>),
        ("Namespace", assert_equal::<Namespace>),
        ("OpId", assert_equal::<OpId>),
        ("Seconds", assert_equal::<Seconds>),
        ("Seq", assert_equal::<Seq>),
        ("Config", assert_equal::<Config>),
        ("ConfigPatch", assert_equal::<ConfigPatch>),
        ("InstallArg", assert_equal::<InstallArg>),
        ("CommonErrorCase", assert_equal::<CommonErrorCase>),
        ("CommonError", assert_equal::<CommonError>),
        ("SessionRecord", assert_equal::<SessionRecord>),
        ("Tombstone", assert_equal::<Tombstone>),
        ("Change", assert_equal::<Change>),
        ("Lookup", assert_equal::<Lookup>),
        ("PutSessionArg", assert_equal::<PutSessionArg>),
        ("PutSessionErrorCase", assert_equal::<PutSessionErrorCase>),
        ("PutSessionError", assert_equal::<PutSessionError>),
        ("PutSessionResult", assert_equal::<PutSessionResult>),
        ("ConsumeCodeArg", assert_equal::<ConsumeCodeArg>),
        ("ConsumeCodeErrorCase", assert_equal::<ConsumeCodeErrorCase>),
        ("ConsumeCodeError", assert_equal::<ConsumeCodeError>),
        ("ConsumeCodeResult", assert_equal::<ConsumeCodeResult>),
        ("Touch", assert_equal::<Touch>),
        ("TouchSessionsArg", assert_equal::<TouchSessionsArg>),
        ("TouchResult", assert_equal::<TouchResult>),
        ("GetSessionsArg", assert_equal::<GetSessionsArg>),
        ("GetSessionsResult", assert_equal::<GetSessionsResult>),
        ("ListChangesArg", assert_equal::<ListChangesArg>),
        ("ChangesPage", assert_equal::<ChangesPage>),
        ("ListChangesResult", assert_equal::<ListChangesResult>),
        ("KeyCheck", assert_equal::<KeyCheck>),
        ("KeyChecks", assert_equal::<KeyChecks>),
        ("KeyChecksResult", assert_equal::<KeyChecksResult>),
        ("GetKeyChecksArg", assert_equal::<GetKeyChecksArg>),
        ("SetKeyCheckArg", assert_equal::<SetKeyCheckArg>),
        ("RetireKidArg", assert_equal::<RetireKidArg>),
        ("PurgeFilter", assert_equal::<PurgeFilter>),
        ("PurgeJob", assert_equal::<PurgeJob>),
        ("PurgeJobResult", assert_equal::<PurgeJobResult>),
        ("NamespaceCount", assert_equal::<NamespaceCount>),
        ("CallerStats", assert_equal::<CallerStats>),
        ("Counters", assert_equal::<Counters>),
        ("Status", assert_equal::<Status>),
        ("GetStatusArg", assert_equal::<GetStatusArg>),
        ("StatusResult", assert_equal::<StatusResult>),
        ("ConfigResult", assert_equal::<ConfigResult>),
    ]
}

#[test]
fn every_did_type_has_an_equal_rust_type() {
    let (env, _) = did();
    let table = named_types();
    let in_did: BTreeSet<&str> = env.0.keys().map(String::as_str).collect();
    let in_rust: BTreeSet<&str> = table.iter().map(|(name, _)| *name).collect();
    assert_eq!(in_rust.len(), table.len(), "a type is listed twice");
    assert_eq!(in_did, in_rust, "the .did and the Rust types name different types");
    for (name, check) in table {
        let expected = env.find_type(name).expect("listed above").clone();
        check(&env, &expected, name);
    }
}

/// The install argument. The methods themselves are checked where they are
/// implemented: the canister compares the interface it exports
/// (`candid::export_service!`) with this `.did`.
#[test]
fn the_install_argument_matches_the_rust_type() {
    let (env, actor) = did();
    let TypeInner::Class(init, _) = actor.as_ref() else {
        panic!("the service takes an install argument: {actor}");
    };
    assert_eq!(init.len(), 1, "one install argument");
    assert_equal::<InstallArg>(&env, &init[0], "install argument");
}

/// The checks above must be able to fail: a Rust type with one field renamed is
/// told apart from the .did.
#[test]
#[should_panic(expected = "differs from imcp2_session.did")]
fn a_renamed_field_is_caught() {
    #[derive(CandidType)]
    struct Renamed {
        after: Seq,
        page_size: Option<u32>,
    }
    let (env, _) = did();
    let expected = env.find_type("ListChangesArg").expect("in the .did").clone();
    assert_equal::<Renamed>(&env, &expected, "ListChangesArg");
}

/// What dfx sends for a textual argument: parsed, annotated with the method's
/// argument types from the canister's published interface (which drops record
/// fields the type does not declare, and fills a missing `opt` field with
/// `null`), then encoded.
fn as_dfx_sends(method: &str, text: &str) -> Result<Vec<u8>, String> {
    let (env, actor) = did();
    let func = env.get_method(&actor, method).map_err(|e| e.to_string())?;
    let args = candid_parser::parse_idl_args(text).map_err(|e| e.to_string())?;
    let args = args.annotate_types(true, &env, &func.args).map_err(|e| e.to_string())?;
    args.to_bytes_with_types(&env, &func.args).map_err(|e| e.to_string())
}

// A purge filter cannot be widened by a typo: every field is a required
// variant, so a misspelled or missing field, a misspelled tag, or the old
// `opt` form fails before anything is sent. Only a filter written out in full
// goes through, and purging everything means writing every field as `Any`.
#[test]
fn a_misspelled_or_missing_purge_field_is_refused() {
    use candid::Decode;

    let any = "variant { Any }";
    let ns = format!("variant {{ Is = blob \"{}\" }}", "\\a0".repeat(NAMESPACE_LEN));
    let full = |namespace: &str, kid: &str| {
        format!(
            "(record {{ namespace = {namespace}; kid = {kid}; opened_by = {any}; \
             created_from = {any}; created_to = {any} }})"
        )
    };
    let refused = [
        // The typo Copilot described: alone, it used to purge everything.
        "(record { namspace = opt blob \"\\a0\" })".to_string(),
        // A misspelled field among correct ones used to drop that condition.
        full(&ns, any).replace("kid =", "kidd ="),
        // A missing field.
        full(&ns, any).replace(&format!("kid = {any}; "), ""),
        // A misspelled tag.
        full(&ns, "variant { Iz = 3 }"),
        // The old optional form.
        full(&ns, "opt 3"),
        // Nothing at all.
        "(record {})".to_string(),
    ];
    for text in &refused {
        assert!(as_dfx_sends("admin_purge_sessions", text).is_err(), "sent: {text}");
    }

    let sent = as_dfx_sends("admin_purge_sessions", &full(&ns, "variant { Is = 3 }"))
        .expect("a full filter type-checks");
    let filter = Decode!(&sent, PurgeFilter).expect("decodes");
    assert_eq!(
        filter,
        PurgeFilter {
            namespace: Match::Is(vec![0xA0; NAMESPACE_LEN]),
            kid: Match::Is(3),
            ..PurgeFilter::default()
        }
    );
    let everything =
        as_dfx_sends("admin_purge_sessions", &full(any, any)).expect("all Any type-checks");
    assert_eq!(Decode!(&everything, PurgeFilter).unwrap(), PurgeFilter::default());
}
