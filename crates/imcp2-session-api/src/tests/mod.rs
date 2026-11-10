//! Contract and wire tests: the Rust types against `imcp2_session.did`, golden
//! encodings, the evolution rules, and reply-size limits.

mod contract;
mod wire;

use candid::{Nat, Principal};

use crate::*;

/// A key in a fixed test namespace (`0xA0` × 16), distinguished by `n`.
fn key(n: u8) -> Key {
    let mut key = vec![0xA0; NAMESPACE_LEN];
    key.extend([n; KEY_LEN - NAMESPACE_LEN]);
    key
}

fn id(n: u8) -> OpId {
    vec![n; ID_LEN]
}

fn node(n: u8) -> Principal {
    Principal::from_slice(&[n; 29])
}

fn record() -> SessionRecord {
    SessionRecord {
        key: key(1),
        seq: 1_700_000_005_000_000_000,
        op_id: id(0x11),
        created_at: 1_700_000_000,
        grant_expires_at: 1_702_592_000,
        last_active_at: 1_700_000_300,
        consumed_at: Some(1_700_000_005),
        sealed: vec![0x01, 0x00, 0x02, 0xC0, 0xFF, 0xEE],
    }
}

fn tombstone() -> Tombstone {
    Tombstone {
        key: key(2),
        seq: 1_700_000_900_000_000_000,
        deleted_at: 1_700_000_900,
        grant_expires_at: 1_702_592_000,
        reason: REASON_IDLE.to_string(),
    }
}

fn config_patch() -> ConfigPatch {
    ConfigPatch {
        authorized: Some(vec![node(1), node(2)]),
        idle_timeout_secs: Some(604_800),
        max_sessions: Some(500_000),
        max_sessions_per_namespace: Some(250_000),
        purge_interval_secs: Some(30),
        purge_batch: Some(1_000),
    }
}

fn config() -> Config {
    let mut config = Config::default();
    config.apply(&config_patch()).expect("the fixture patch is valid");
    config
}

fn key_checks() -> KeyChecks {
    KeyChecks {
        version: 3,
        checks: vec![
            KeyCheck { kid: 1, check: vec![0x31; KEY_CHECK_LEN] },
            KeyCheck { kid: 2, check: vec![0x32; KEY_CHECK_LEN] },
        ],
        retired: vec![1],
        now_ns: 1_700_000_000_000_000_000,
    }
}

fn purge_filter() -> PurgeFilter {
    PurgeFilter {
        namespace: Some(vec![0xA0; NAMESPACE_LEN]),
        kid: Some(1),
        opened_by: Some(node(3)),
        created_from: Some(1_690_000_000),
        created_to: Some(1_700_000_000),
    }
}

fn purge_job() -> PurgeJob {
    PurgeJob {
        filter: purge_filter(),
        started_at: 1_700_000_000,
        scanned: 4_000,
        purged: 12,
        done: false,
    }
}

fn status() -> Status {
    Status {
        version: "0.7.0".to_string(),
        git_commit: "f0f098c".to_string(),
        config: config(),
        sessions: 1_234,
        tombstones: 56,
        per_namespace: vec![NamespaceCount {
            namespace: vec![0xA0; NAMESPACE_LEN],
            sessions: 1_234,
            tombstones: 56,
        }],
        head: 1_700_000_900_000_000_000,
        epoch: 2,
        idle_floor_at: 1_699_000_000,
        key_checks: key_checks(),
        callers: vec![CallerStats {
            caller: node(1),
            authorized: true,
            opened: 800,
            consumed: 790,
            last_seen_at: 1_700_000_850,
        }],
        purge_job: Some(purge_job()),
        counters: Counters {
            opened: 1,
            consumed: 2,
            abandoned: 3,
            expired: 4,
            idle_purged: 5,
            evicted: 6,
            admin_purged: 7,
            tombstones_collected: 8,
            restores_detected: 9,
        },
        last_purge_at: 1_700_000_880,
        purge_backlog_secs: 15,
        cycle_balance: Nat::from(12_345_678_901_234_u64),
        stable_memory_bytes: 536_870_912,
        now_ns: 1_700_000_900_000_000_000,
    }
}

/// `Debug` must never print a code proof or a sealed session: the bytes below
/// (0xEE = 238) appear only in those fields.
#[test]
fn debug_redacts_secrets() {
    let secret = vec![0xEE; 48];
    let rendered = [
        format!(
            "{:?}",
            ConsumeCodeArg { key: key(1), exchange_id: id(2), code_proof: secret.clone() }
        ),
        format!("{:?}", SessionRecord { sealed: secret.clone(), ..record() }),
        format!(
            "{:?}",
            PutSessionArg {
                key: key(1),
                op_id: id(2),
                grant_expires_at: 1,
                sealed: secret.clone(),
                code_lock: id(3),
            }
        ),
        format!("{:?}", Change::Live(SessionRecord { sealed: secret, ..record() })),
    ];
    for r in rendered {
        assert!(!r.contains("238"), "secret bytes in Debug output: {r}");
        assert!(r.contains("<48 bytes redacted>"), "{r}");
    }
}
