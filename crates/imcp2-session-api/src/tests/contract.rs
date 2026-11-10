//! The Rust types and method names against the hand-written `.did`.
//!
//! Structural equality (`candid::types::subtype::equal`) is stricter than
//! subtyping both ways: field and variant names, their types, `opt`-ness and
//! the arity of every method must all match exactly.

use std::collections::{BTreeSet, HashSet};

use candid::types::internal::TypeContainer;
use candid::types::subtype::equal;
use candid::types::{FuncMode, Type, TypeInner};
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
        ("ErrorInfo", assert_equal::<ErrorInfo>),
        ("CommonError", assert_equal::<CommonError>),
        ("SessionRecord", assert_equal::<SessionRecord>),
        ("Tombstone", assert_equal::<Tombstone>),
        ("Change", assert_equal::<Change>),
        ("Lookup", assert_equal::<Lookup>),
        ("PutSessionArg", assert_equal::<PutSessionArg>),
        ("PutSessionError", assert_equal::<PutSessionError>),
        ("PutSessionResult", assert_equal::<PutSessionResult>),
        ("ConsumeCodeArg", assert_equal::<ConsumeCodeArg>),
        ("ConsumeCodeError", assert_equal::<ConsumeCodeError>),
        ("ConsumeCodeResult", assert_equal::<ConsumeCodeResult>),
        ("Touch", assert_equal::<Touch>),
        ("TouchResult", assert_equal::<TouchResult>),
        ("GetSessionsResult", assert_equal::<GetSessionsResult>),
        ("ListChangesArg", assert_equal::<ListChangesArg>),
        ("ChangesPage", assert_equal::<ChangesPage>),
        ("ListChangesResult", assert_equal::<ListChangesResult>),
        ("KeyCheck", assert_equal::<KeyCheck>),
        ("KeyChecks", assert_equal::<KeyChecks>),
        ("KeyChecksResult", assert_equal::<KeyChecksResult>),
        ("PurgeFilter", assert_equal::<PurgeFilter>),
        ("PurgeJob", assert_equal::<PurgeJob>),
        ("PurgeJobResult", assert_equal::<PurgeJobResult>),
        ("NamespaceCount", assert_equal::<NamespaceCount>),
        ("CallerStats", assert_equal::<CallerStats>),
        ("Counters", assert_equal::<Counters>),
        ("Status", assert_equal::<Status>),
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

/// One method of the service: its Rust argument and reply types, and whether it
/// is a query.
struct Method {
    name: &'static str,
    args: Vec<Check>,
    rets: Vec<Check>,
    query: bool,
}

fn methods() -> Vec<Method> {
    fn update(name: &'static str, args: Vec<Check>, ret: Check) -> Method {
        Method { name, args, rets: vec![ret], query: false }
    }
    fn query(name: &'static str, args: Vec<Check>, ret: Check) -> Method {
        Method { name, args, rets: vec![ret], query: true }
    }
    vec![
        update(
            method::PUT_SESSION,
            vec![assert_equal::<PutSessionArg>],
            assert_equal::<PutSessionResult>,
        ),
        update(
            method::CONSUME_CODE,
            vec![assert_equal::<ConsumeCodeArg>],
            assert_equal::<ConsumeCodeResult>,
        ),
        update(
            method::TOUCH_SESSIONS,
            vec![assert_equal::<Vec<Touch>>],
            assert_equal::<TouchResult>,
        ),
        query(
            method::GET_SESSIONS,
            vec![assert_equal::<Vec<Key>>],
            assert_equal::<GetSessionsResult>,
        ),
        query(
            method::LIST_CHANGES,
            vec![assert_equal::<ListChangesArg>],
            assert_equal::<ListChangesResult>,
        ),
        query(method::GET_KEY_CHECKS, vec![], assert_equal::<KeyChecksResult>),
        query(method::GET_STATUS, vec![], assert_equal::<StatusResult>),
        update(
            method::ADMIN_UPDATE_CONFIG,
            vec![assert_equal::<ConfigPatch>],
            assert_equal::<ConfigResult>,
        ),
        update(
            method::ADMIN_SET_KEY_CHECK,
            vec![assert_equal::<KeyCheck>, assert_equal::<bool>],
            assert_equal::<KeyChecksResult>,
        ),
        update(method::ADMIN_RETIRE_KID, vec![assert_equal::<u8>], assert_equal::<KeyChecksResult>),
        update(
            method::ADMIN_PURGE_SESSIONS,
            vec![assert_equal::<PurgeFilter>],
            assert_equal::<PurgeJobResult>,
        ),
    ]
}

#[test]
fn method_constants_name_exactly_the_service_methods() {
    let (env, actor) = did();
    let in_did: Vec<&str> =
        env.as_service(&actor).expect("a service").iter().map(|(name, _)| name.as_str()).collect();
    let in_did_set: BTreeSet<&str> = in_did.iter().copied().collect();
    let in_rust: BTreeSet<&str> = method::ALL.iter().copied().collect();
    assert_eq!(in_rust.len(), method::ALL.len(), "method::ALL lists a method twice");
    assert_eq!(in_did_set, in_rust);
    let described: Vec<&str> = methods().iter().map(|m| m.name).collect();
    assert_eq!(described, method::ALL, "the signature table below covers every method");
}

#[test]
fn every_method_signature_matches_the_rust_types() {
    let (env, actor) = did();
    let TypeInner::Class(init, service) = actor.as_ref() else {
        panic!("the service takes an install argument: {actor}");
    };
    assert_eq!(init.len(), 1, "one install argument");
    assert_equal::<InstallArg>(&env, &init[0], "install argument");

    for m in methods() {
        let func = env.get_method(service, m.name).expect("listed in the .did");
        assert_eq!(func.args.len(), m.args.len(), "{}: argument count", m.name);
        for (i, (ty, check)) in func.args.iter().zip(&m.args).enumerate() {
            check(&env, ty, &format!("{} argument {i}", m.name));
        }
        assert_eq!(func.rets.len(), m.rets.len(), "{}: reply count", m.name);
        for (i, (ty, check)) in func.rets.iter().zip(&m.rets).enumerate() {
            check(&env, ty, &format!("{} reply {i}", m.name));
        }
        let modes: &[FuncMode] = if m.query { &[FuncMode::Query] } else { &[] };
        assert_eq!(func.modes, modes, "{}: query or update", m.name);
    }
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
