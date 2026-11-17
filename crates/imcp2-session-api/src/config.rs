//! The canister configuration, its patches, and its one validation.

use std::collections::BTreeSet;

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

use crate::constants::{
    DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_SESSIONS, DEFAULT_MAX_SESSIONS_PER_NAMESPACE,
    DEFAULT_PURGE_BATCH, DEFAULT_PURGE_INTERVAL_SECS, MAX_AUTHORIZED, MAX_IDLE_TIMEOUT,
    MAX_PURGE_BATCH, MAX_PURGE_INTERVAL_SECS, MIN_IDLE_TIMEOUT, MIN_PURGE_BATCH,
    MIN_PURGE_INTERVAL_SECS,
};

/// The canister configuration (`Config`), changed only by its controllers.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The backend node identities allowed to call the data methods, at most
    /// [`MAX_AUTHORIZED`], never anonymous. Empty means nobody.
    pub authorized: Vec<Principal>,
    /// Sessions unused this long are purged (see
    /// [`idle_deadline`](crate::idle_deadline)); in
    /// [`MIN_IDLE_TIMEOUT`]`..=`[`MAX_IDLE_TIMEOUT`].
    pub idle_timeout_secs: u64,
    /// Cap on live records across all namespaces, at least 1.
    pub max_sessions: u64,
    /// Cap on live records in one namespace, in `1..=max_sessions`.
    pub max_sessions_per_namespace: u64,
    /// Seconds between purge timer firings, in
    /// [`MIN_PURGE_INTERVAL_SECS`]`..=`[`MAX_PURGE_INTERVAL_SECS`].
    pub purge_interval_secs: u32,
    /// Removals per purge firing, in
    /// [`MIN_PURGE_BATCH`]`..=`[`MAX_PURGE_BATCH`].
    pub purge_batch: u32,
}

impl Default for Config {
    /// The configuration of a fresh install: the documented defaults, and nobody
    /// authorized until a controller says otherwise.
    fn default() -> Self {
        Config {
            authorized: Vec::new(),
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_sessions_per_namespace: DEFAULT_MAX_SESSIONS_PER_NAMESPACE,
            purge_interval_secs: DEFAULT_PURGE_INTERVAL_SECS,
            purge_batch: DEFAULT_PURGE_BATCH,
        }
    }
}

impl Config {
    /// Applies `patch` (each `Some` field replaces the current value), but only if
    /// the **resulting** configuration passes [`Config::validate`]. On error
    /// `self` is left unchanged.
    ///
    /// The whole result is validated rather than the patch alone because the
    /// rules relate fields: lowering `max_sessions` below the current
    /// `max_sessions_per_namespace` is invalid even though the patch on its own
    /// looks fine.
    pub fn apply(&mut self, patch: &ConfigPatch) -> Result<(), String> {
        let mut next = self.clone();
        if let Some(authorized) = &patch.authorized {
            next.authorized.clone_from(authorized);
        }
        if let Some(v) = patch.idle_timeout_secs {
            next.idle_timeout_secs = v;
        }
        if let Some(v) = patch.max_sessions {
            next.max_sessions = v;
        }
        if let Some(v) = patch.max_sessions_per_namespace {
            next.max_sessions_per_namespace = v;
        }
        if let Some(v) = patch.purge_interval_secs {
            next.purge_interval_secs = v;
        }
        if let Some(v) = patch.purge_batch {
            next.purge_batch = v;
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Checks every rule of a configuration, returning the first violation as a
    /// message fit for the `InvalidArgument` a controller gets back.
    pub fn validate(&self) -> Result<(), String> {
        if self.authorized.len() > MAX_AUTHORIZED {
            return Err(format!(
                "authorized: at most {MAX_AUTHORIZED} principals, got {}",
                self.authorized.len()
            ));
        }
        // The anonymous principal is anyone at all: authorizing it would open the
        // data methods to the internet.
        if self.authorized.contains(&Principal::anonymous()) {
            return Err("authorized: the anonymous principal cannot be authorized".to_string());
        }
        let mut seen = BTreeSet::new();
        if let Some(dup) = self.authorized.iter().find(|p| !seen.insert(*p)) {
            return Err(format!("authorized: {dup} is listed more than once"));
        }
        if !(MIN_IDLE_TIMEOUT..=MAX_IDLE_TIMEOUT).contains(&self.idle_timeout_secs) {
            return Err(format!(
                "idle_timeout_secs: must be in {MIN_IDLE_TIMEOUT}..={MAX_IDLE_TIMEOUT}, got {}",
                self.idle_timeout_secs
            ));
        }
        if self.max_sessions == 0 {
            return Err("max_sessions: must be at least 1".to_string());
        }
        if !(1..=self.max_sessions).contains(&self.max_sessions_per_namespace) {
            return Err(format!(
                "max_sessions_per_namespace: must be in 1..=max_sessions ({}), got {}",
                self.max_sessions, self.max_sessions_per_namespace
            ));
        }
        if !(MIN_PURGE_INTERVAL_SECS..=MAX_PURGE_INTERVAL_SECS).contains(&self.purge_interval_secs)
        {
            return Err(format!(
                "purge_interval_secs: must be in \
                 {MIN_PURGE_INTERVAL_SECS}..={MAX_PURGE_INTERVAL_SECS}, got {}",
                self.purge_interval_secs
            ));
        }
        if !(MIN_PURGE_BATCH..=MAX_PURGE_BATCH).contains(&self.purge_batch) {
            return Err(format!(
                "purge_batch: must be in {MIN_PURGE_BATCH}..={MAX_PURGE_BATCH}, got {}",
                self.purge_batch
            ));
        }
        Ok(())
    }
}

/// A partial [`Config`] (`ConfigPatch`): each `Some` field replaces the current
/// value, see [`Config::apply`]. The default patch changes nothing.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigPatch {
    /// Replaces the whole allow-list (it is not merged).
    pub authorized: Option<Vec<Principal>>,
    pub idle_timeout_secs: Option<u64>,
    pub max_sessions: Option<u64>,
    pub max_sessions_per_namespace: Option<u64>,
    pub purge_interval_secs: Option<u32>,
    pub purge_batch: Option<u32>,
}

impl ConfigPatch {
    /// Whether the patch changes nothing. An empty `admin_update_config` is still
    /// useful: it re-arms the purge timer, whose immediate run checks the
    /// canister history for a snapshot load.
    pub fn is_empty(&self) -> bool {
        let ConfigPatch {
            authorized,
            idle_timeout_secs,
            max_sessions,
            max_sessions_per_namespace,
            purge_interval_secs,
            purge_batch,
        } = self;
        // Destructured so that a new field cannot be forgotten here.
        authorized.is_none()
            && idle_timeout_secs.is_none()
            && max_sessions.is_none()
            && max_sessions_per_namespace.is_none()
            && purge_interval_secs.is_none()
            && purge_batch.is_none()
    }
}

/// The canister's install argument (`InstallArg`).
#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub enum InstallArg {
    /// A fresh install: [`Config::default`] with this patch applied. Refused on
    /// an upgrade, where it would silently discard the running configuration.
    Init(ConfigPatch),
    /// An upgrade: the stored configuration is kept, with the patch (if any)
    /// applied to it.
    Upgrade(Option<ConfigPatch>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }

    /// Applies `patch` to the default config, asserting it is rejected with a
    /// message mentioning `field` and that the config is unchanged.
    fn assert_rejected(patch: ConfigPatch, field: &str) {
        let mut config = Config { authorized: vec![node(1)], ..Config::default() };
        let before = config.clone();
        let err = config.apply(&patch).expect_err("patch should be rejected");
        assert!(err.starts_with(&format!("{field}:")), "{err:?} does not name {field}");
        assert_eq!(config, before, "a rejected patch changed the config");
    }

    fn assert_accepted(patch: ConfigPatch) -> Config {
        let mut config = Config::default();
        config.apply(&patch).unwrap_or_else(|e| panic!("{patch:?} rejected: {e}"));
        config
    }

    #[test]
    fn default_config_is_valid() {
        let mut config = Config::default();
        assert!(ConfigPatch::default().is_empty());
        config.apply(&ConfigPatch::default()).unwrap();
        assert_eq!(config, Config::default());
        assert!(config.authorized.is_empty());
    }

    #[test]
    fn patch_replaces_only_the_fields_it_sets() {
        let config = assert_accepted(ConfigPatch {
            authorized: Some(vec![node(1), node(2)]),
            purge_batch: Some(5_000),
            ..ConfigPatch::default()
        });
        assert_eq!(
            config,
            Config { authorized: vec![node(1), node(2)], purge_batch: 5_000, ..Config::default() }
        );
        // The allow-list is replaced, not merged.
        let mut config = config;
        config
            .apply(&ConfigPatch { authorized: Some(vec![node(3)]), ..ConfigPatch::default() })
            .unwrap();
        assert_eq!(config.authorized, vec![node(3)]);
    }

    #[test]
    fn is_empty_sees_every_field() {
        let set = [
            ConfigPatch { authorized: Some(vec![]), ..ConfigPatch::default() },
            ConfigPatch { idle_timeout_secs: Some(3_600), ..ConfigPatch::default() },
            ConfigPatch { max_sessions: Some(1), ..ConfigPatch::default() },
            ConfigPatch { max_sessions_per_namespace: Some(1), ..ConfigPatch::default() },
            ConfigPatch { purge_interval_secs: Some(60), ..ConfigPatch::default() },
            ConfigPatch { purge_batch: Some(100), ..ConfigPatch::default() },
        ];
        for patch in set {
            assert!(!patch.is_empty(), "{patch:?}");
        }
    }

    #[test]
    fn authorized_rules() {
        let full: Vec<Principal> = (1..=MAX_AUTHORIZED as u8).map(node).collect();
        assert_accepted(ConfigPatch { authorized: Some(full.clone()), ..ConfigPatch::default() });
        let mut over = full;
        over.push(node(200));
        assert_rejected(
            ConfigPatch { authorized: Some(over), ..ConfigPatch::default() },
            "authorized",
        );
        assert_rejected(
            ConfigPatch {
                authorized: Some(vec![node(1), Principal::anonymous()]),
                ..ConfigPatch::default()
            },
            "authorized",
        );
        assert_rejected(
            ConfigPatch {
                authorized: Some(vec![node(1), node(2), node(1)]),
                ..ConfigPatch::default()
            },
            "authorized",
        );
        // Emptying the list is allowed: it locks every backend out.
        assert_accepted(ConfigPatch { authorized: Some(vec![]), ..ConfigPatch::default() });
    }

    #[test]
    fn idle_timeout_bounds() {
        for ok in [MIN_IDLE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, MAX_IDLE_TIMEOUT] {
            assert_accepted(ConfigPatch { idle_timeout_secs: Some(ok), ..ConfigPatch::default() });
        }
        for bad in [0, MIN_IDLE_TIMEOUT - 1, MAX_IDLE_TIMEOUT + 1, u64::MAX] {
            assert_rejected(
                ConfigPatch { idle_timeout_secs: Some(bad), ..ConfigPatch::default() },
                "idle_timeout_secs",
            );
        }
    }

    #[test]
    fn capacity_rules() {
        assert_rejected(
            ConfigPatch { max_sessions: Some(0), ..ConfigPatch::default() },
            "max_sessions",
        );
        assert_rejected(
            ConfigPatch { max_sessions_per_namespace: Some(0), ..ConfigPatch::default() },
            "max_sessions_per_namespace",
        );
        assert_rejected(
            ConfigPatch {
                max_sessions_per_namespace: Some(DEFAULT_MAX_SESSIONS + 1),
                ..ConfigPatch::default()
            },
            "max_sessions_per_namespace",
        );
        // Validated as a whole: lowering the total below the current
        // per-namespace cap is refused although the patch alone looks fine.
        assert_rejected(
            ConfigPatch {
                max_sessions: Some(DEFAULT_MAX_SESSIONS_PER_NAMESPACE - 1),
                ..ConfigPatch::default()
            },
            "max_sessions_per_namespace",
        );
        let config = assert_accepted(ConfigPatch {
            max_sessions: Some(1),
            max_sessions_per_namespace: Some(1),
            ..ConfigPatch::default()
        });
        assert_eq!((config.max_sessions, config.max_sessions_per_namespace), (1, 1));
    }

    #[test]
    fn purge_bounds() {
        for ok in [MIN_PURGE_INTERVAL_SECS, MAX_PURGE_INTERVAL_SECS] {
            assert_accepted(ConfigPatch {
                purge_interval_secs: Some(ok),
                ..ConfigPatch::default()
            });
        }
        for bad in [0, MIN_PURGE_INTERVAL_SECS - 1, MAX_PURGE_INTERVAL_SECS + 1] {
            assert_rejected(
                ConfigPatch { purge_interval_secs: Some(bad), ..ConfigPatch::default() },
                "purge_interval_secs",
            );
        }
        for ok in [MIN_PURGE_BATCH, MAX_PURGE_BATCH] {
            assert_accepted(ConfigPatch { purge_batch: Some(ok), ..ConfigPatch::default() });
        }
        for bad in [0, MIN_PURGE_BATCH - 1, MAX_PURGE_BATCH + 1] {
            assert_rejected(
                ConfigPatch { purge_batch: Some(bad), ..ConfigPatch::default() },
                "purge_batch",
            );
        }
    }

    #[test]
    fn one_bad_field_rejects_the_whole_patch() {
        assert_rejected(
            ConfigPatch {
                authorized: Some(vec![node(7)]),
                idle_timeout_secs: Some(7 * 86_400),
                purge_batch: Some(0),
                ..ConfigPatch::default()
            },
            "purge_batch",
        );
    }
}
