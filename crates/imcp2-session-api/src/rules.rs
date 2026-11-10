//! The rules the canister and the backends both evaluate.
//!
//! They live here, as pure functions of plain numbers, so the two sides cannot
//! drift: the canister purges and evicts by them, and the backends decide by the
//! same arithmetic whether a touch could ever matter. All arithmetic saturates,
//! and every saturation in a deadline or an eviction decision errs on the side
//! of keeping a session (a later deadline, no eviction). The one exception,
//! [`idle_purge_cutoff`], is only meaningful once [`idle_purge_enabled`] holds,
//! which rules its saturation out.

use crate::constants::{
    CLOCK_SKEW, IDLE_SLACK, KEY_LEN, MAX_GRANT, MAX_TOUCH_GRANULARITY, MIN_EVICT_IDLE,
    MIN_TOUCH_GRANULARITY, NAMESPACE_LEN, TOUCH_FLUSH_INTERVAL,
};

const fn max(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

/// How coarsely a session's activity is reported under idle timeout
/// `idle_timeout_secs`: `clamp(idle / 48, 5 min, 6 h)`.
///
/// A backend reports a session's activity (`touch_sessions`) only once it has
/// advanced by at least this much since the last report, so `last_active_at` in
/// the canister may lag real activity by up to this (plus a flush). The idle
/// deadline adds it back, so lagging reports never purge an active session;
/// 1/48 of the timeout keeps that margin around 2% of it.
pub const fn touch_granularity(idle_timeout_secs: u64) -> u64 {
    let g = idle_timeout_secs / 48;
    if g < MIN_TOUCH_GRANULARITY {
        MIN_TOUCH_GRANULARITY
    } else if g > MAX_TOUCH_GRANULARITY {
        MAX_TOUCH_GRANULARITY
    } else {
        g
    }
}

/// `idle + touch_granularity(idle) + IDLE_SLACK`: how long after its last
/// trustworthy activity a session is idle.
const fn idle_span(idle_timeout_secs: u64) -> u64 {
    idle_timeout_secs
        .saturating_add(touch_granularity(idle_timeout_secs))
        .saturating_add(IDLE_SLACK)
}

/// When a session becomes idle:
/// `max(last_active_at, idle_floor_at) + idle + touch_granularity(idle) + IDLE_SLACK`.
///
/// `idle_floor_at` is the canister's floor under every `last_active_at`. It is
/// raised to `now` when the idle timeout is lowered (sessions were not being
/// touched under the longer timeout, so their `last_active_at` is stale) and when
/// a snapshot load is detected (activity after the snapshot was lost). Measuring
/// from the floor gives every session a full timeout from that moment on, so
/// neither event can log out an active user.
pub const fn idle_deadline(last_active_at: u64, idle_floor_at: u64, idle_timeout_secs: u64) -> u64 {
    max(last_active_at, idle_floor_at).saturating_add(idle_span(idle_timeout_secs))
}

/// Whether the idle purge may run at all: `now >= idle_floor_at + idle +
/// touch_granularity(idle) + IDLE_SLACK`, i.e. a full idle span has passed since
/// the floor was last raised.
///
/// Until then every session's [`idle_deadline`], being at least the floor's,
/// lies in the future, so there is nothing to purge — and gating on this lets
/// the purge compare `last_active_at` against [`idle_purge_cutoff`] alone,
/// without looking up the floor per record.
pub const fn idle_purge_enabled(now: u64, idle_floor_at: u64, idle_timeout_secs: u64) -> bool {
    now >= idle_deadline(0, idle_floor_at, idle_timeout_secs)
}

/// The idle purge's cutoff, `now - idle - touch_granularity(idle) - IDLE_SLACK`:
/// a record with `last_active_at <= cutoff` is idle.
///
/// Only meaningful while [`idle_purge_enabled`] holds. Then the floor is at most
/// the cutoff, so `last_active_at <= cutoff` is exactly `now >=`
/// [`idle_deadline`], and `now` is at least one idle span, so the subtraction
/// never saturates (a saturated cutoff of 0 would call `last_active_at == 0`
/// idle early).
pub const fn idle_purge_cutoff(now: u64, idle_timeout_secs: u64) -> u64 {
    now.saturating_sub(idle_span(idle_timeout_secs))
}

/// Whether reporting activity can ever make a difference under idle timeout
/// `idle_timeout_secs`: `idle + touch_granularity(idle) + IDLE_SLACK + CLOCK_SKEW
/// < MAX_GRANT`.
///
/// No grant II issues outlives [`MAX_GRANT`] from its creation, and no session
/// is idle before one idle span after its creation. When the span (plus skew)
/// reaches `MAX_GRANT`, grant expiry always removes a session before it could go
/// idle, so touches would buy nothing but update calls. This is the case at the
/// 30 d default ([`DEFAULT_IDLE_TIMEOUT`](crate::DEFAULT_IDLE_TIMEOUT)): backends
/// then make no touch calls at all.
///
/// This relies on II's cap, not on what `put_session` accepts: a record with a
/// grant longer than `MAX_GRANT` plus the granularity and slack (possible up to
/// [`MAX_GRANT_ACCEPTED`](crate::MAX_GRANT_ACCEPTED)) would reach its idle
/// deadline before its grant expiry without ever being touched. [`evictable`]
/// guards against such a record explicitly.
pub const fn touches_effective(idle_timeout_secs: u64) -> bool {
    idle_span(idle_timeout_secs).saturating_add(CLOCK_SKEW) < MAX_GRANT
}

/// Whether a record may be evicted to make room for a new session: only when its
/// `last_active_at` can be trusted to say the session is unused. All of:
///
///   * it is `consumed` — an unconsumed record belongs to a sign-in that may be
///     in progress, and is removed by the abandon timer anyway;
///   * [`touches_effective(idle)`](touches_effective) — otherwise backends send
///     no touches at all, and no `last_active_at` means anything;
///   * `now + idle + touch_granularity(idle) + IDLE_SLACK + CLOCK_SKEW <
///     grant_expires_at` — backends report a session's activity only while it
///     could move the idle deadline before grant expiry, so past this point a
///     busy session may look idle;
///   * `now - max(last_active_at, idle_floor_at) >= touch_granularity(idle) +
///     2 * TOUCH_FLUSH_INTERVAL + MIN_EVICT_IDLE` — activity up to one
///     granularity plus two flushes old may not have been reported yet; beyond
///     that the session must have been idle for [`MIN_EVICT_IDLE`]. Below the
///     floor, `last_active_at` is not trustworthy, so the floor counts instead.
///
/// For a grant II issued (at most [`MAX_GRANT`] ahead) the expiry condition
/// already implies the touch condition. It is checked on its own because
/// `put_session` accepts grants up to
/// [`MAX_GRANT_ACCEPTED`](crate::MAX_GRANT_ACCEPTED): at the 30 d default such
/// a record would pass every other condition from about 7 to 18 hours after its
/// creation, judged by a `last_active_at` no backend ever updates.
///
/// So at the 30 d default nothing is evicted, and a full store refuses new
/// sign-ins rather than logging out active users.
pub const fn evictable(
    now: u64,
    last_active_at: u64,
    grant_expires_at: u64,
    consumed: bool,
    idle_floor_at: u64,
    idle_timeout_secs: u64,
) -> bool {
    let reported_until_expiry =
        now.saturating_add(idle_span(idle_timeout_secs)).saturating_add(CLOCK_SKEW)
            < grant_expires_at;
    let idle_for = now.saturating_sub(max(last_active_at, idle_floor_at));
    let unreported =
        touch_granularity(idle_timeout_secs) + 2 * TOUCH_FLUSH_INTERVAL + MIN_EVICT_IDLE;
    consumed
        && touches_effective(idle_timeout_secs)
        && reported_until_expiry
        && idle_for >= unreported
}

/// The namespace of a record key: its first [`NAMESPACE_LEN`] bytes, or `None`
/// unless the key is exactly [`KEY_LEN`] bytes long.
pub fn namespace_of(key: &[u8]) -> Option<[u8; NAMESPACE_LEN]> {
    if key.len() != KEY_LEN {
        return None;
    }
    key[..NAMESPACE_LEN].try_into().ok()
}

// The relations the timings must keep, checked when the crate compiles so that
// an edit breaking one fails every build that uses it, canister included.
const _: () = {
    use crate::constants::{
        ABANDON_AFTER, CODE_TTL, CONSUME_WINDOW, DEFAULT_IDLE_TIMEOUT, MAX_GRANT_ACCEPTED,
        MAX_IDLE_TIMEOUT, MIN_IDLE_TIMEOUT, TOMBSTONE_GRACE,
    };
    // A code a backend still accepts (issued up to 15 s after the put, alive for
    // CODE_TTL by a clock up to CLOCK_SKEW behind IC time) is still consumable;
    // its record outlives the consume window; and every sign-in is over long
    // before the shortest idle timeout could call its record idle.
    assert!(CODE_TTL + CLOCK_SKEW + 15 < CONSUME_WINDOW);
    assert!(CONSUME_WINDOW < ABANDON_AFTER);
    assert!(ABANDON_AFTER < MIN_IDLE_TIMEOUT);
    // The bookkeeping margins stay below the shortest timeout they pad.
    assert!(touch_granularity(MIN_IDLE_TIMEOUT) + IDLE_SLACK < MIN_IDLE_TIMEOUT);
    // The default idle timeout costs nothing (no touches, no eviction), while a
    // lowered one (here 7 days) does make touches worthwhile.
    assert!(!touches_effective(DEFAULT_IDLE_TIMEOUT));
    assert!(touches_effective(7 * 86_400));
    assert!(MIN_IDLE_TIMEOUT <= DEFAULT_IDLE_TIMEOUT && DEFAULT_IDLE_TIMEOUT <= MAX_IDLE_TIMEOUT);
    // put_session accepts every grant II can issue.
    assert!(MAX_GRANT + CLOCK_SKEW <= MAX_GRANT_ACCEPTED);
    // A tombstone outlives every token of its session, on every backend clock.
    assert!(CLOCK_SKEW < TOMBSTONE_GRACE);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_IDLE_TIMEOUT, MAX_IDLE_TIMEOUT, MIN_IDLE_TIMEOUT};

    const DAY: u64 = 86_400;

    #[test]
    fn touch_granularity_clamps_at_both_ends() {
        assert_eq!(touch_granularity(0), MIN_TOUCH_GRANULARITY);
        // 48 * 300 = 14_400 is where the floor stops binding.
        assert_eq!(touch_granularity(14_399), 300);
        assert_eq!(touch_granularity(14_400), 300);
        assert_eq!(touch_granularity(14_448), 301);
        // 48 * 21_600 = 1_036_800 is where the ceiling starts binding.
        assert_eq!(touch_granularity(1_036_799), 21_599);
        assert_eq!(touch_granularity(1_036_800), 21_600);
        assert_eq!(touch_granularity(1_036_848), 21_600);
        assert_eq!(touch_granularity(u64::MAX), MAX_TOUCH_GRANULARITY);
        assert_eq!(touch_granularity(MIN_IDLE_TIMEOUT), 300);
        assert_eq!(touch_granularity(7 * DAY), 12_600);
        assert_eq!(touch_granularity(DEFAULT_IDLE_TIMEOUT), 21_600);
        assert_eq!(touch_granularity(MAX_IDLE_TIMEOUT), 21_600);
    }

    #[test]
    fn idle_deadline_counts_from_the_later_of_activity_and_floor() {
        let idle = 7 * DAY;
        let span = idle + 12_600 + IDLE_SLACK;
        assert_eq!(idle_deadline(1_000, 0, idle), 1_000 + span);
        // The floor dominates stale activity ...
        assert_eq!(idle_deadline(1_000, 5_000, idle), 5_000 + span);
        // ... and activity after the floor dominates the floor.
        assert_eq!(idle_deadline(9_000, 5_000, idle), 9_000 + span);
        assert_eq!(idle_deadline(5_000, 5_000, idle), 5_000 + span);
        assert_eq!(idle_deadline(0, 0, MIN_IDLE_TIMEOUT), 3_600 + 300 + 300);
    }

    #[test]
    fn idle_deadline_saturates_instead_of_wrapping() {
        assert_eq!(idle_deadline(u64::MAX, 0, MIN_IDLE_TIMEOUT), u64::MAX);
        assert_eq!(idle_deadline(0, u64::MAX - 1, MIN_IDLE_TIMEOUT), u64::MAX);
        assert_eq!(idle_deadline(0, 0, u64::MAX), u64::MAX);
    }

    #[test]
    fn idle_purge_is_enabled_one_full_span_after_the_floor() {
        let idle = MIN_IDLE_TIMEOUT;
        let floor = 1_700_000_000;
        let enabled_at = floor + 3_600 + 300 + 300;
        assert!(!idle_purge_enabled(enabled_at - 1, floor, idle));
        assert!(idle_purge_enabled(enabled_at, floor, idle));
        assert!(idle_purge_enabled(enabled_at + 1, floor, idle));
        // A floor at the end of time never enables it.
        assert!(!idle_purge_enabled(u64::MAX - 1, u64::MAX, idle));
    }

    #[test]
    fn idle_purge_cutoff_is_one_span_back_and_saturates() {
        let idle = MIN_IDLE_TIMEOUT;
        let span = 3_600 + 300 + 300;
        assert_eq!(idle_purge_cutoff(1_000_000, idle), 1_000_000 - span);
        assert_eq!(idle_purge_cutoff(span, idle), 0);
        assert_eq!(idle_purge_cutoff(span - 1, idle), 0);
        assert_eq!(idle_purge_cutoff(0, idle), 0);
    }

    /// While the purge is enabled, comparing against the cutoff is exactly
    /// comparing against the per-record deadline, floor included.
    #[test]
    fn cutoff_agrees_with_deadline_whenever_purge_is_enabled() {
        for idle in [MIN_IDLE_TIMEOUT, 7 * DAY, DEFAULT_IDLE_TIMEOUT, MAX_IDLE_TIMEOUT] {
            let span = idle_deadline(0, 0, idle);
            for floor in [0, 1, 1_000, 1_700_000_000] {
                for now in [floor + span - 1, floor + span, floor + span + 1, floor + 3 * span] {
                    if !idle_purge_enabled(now, floor, idle) {
                        assert_eq!(now, floor + span - 1);
                        continue;
                    }
                    let cutoff = idle_purge_cutoff(now, idle);
                    for la in [0, 1, floor, cutoff.saturating_sub(1), cutoff, cutoff + 1, now] {
                        assert_eq!(
                            la <= cutoff,
                            now >= idle_deadline(la, floor, idle),
                            "idle={idle} floor={floor} now={now} la={la}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn touches_are_effective_only_below_the_grant_cap() {
        // idle + 21_600 + 300 + 60 < 2_592_000  <=>  idle < 2_570_040
        assert!(touches_effective(2_570_039));
        assert!(!touches_effective(2_570_040));
        assert!(!touches_effective(DEFAULT_IDLE_TIMEOUT));
        assert!(!touches_effective(MAX_IDLE_TIMEOUT));
        assert!(!touches_effective(u64::MAX));
        assert!(touches_effective(MIN_IDLE_TIMEOUT));
        assert!(touches_effective(7 * DAY));
    }

    /// A session that meets every eviction condition by exactly one second's
    /// margin at the boundaries, under a 7-day timeout.
    struct Evict {
        now: u64,
        last_active_at: u64,
        grant_expires_at: u64,
        consumed: bool,
        idle_floor_at: u64,
        idle: u64,
    }

    impl Evict {
        const IDLE: u64 = 7 * DAY;
        const SPAN: u64 = Self::IDLE + 12_600 + IDLE_SLACK;
        const UNREPORTED: u64 = 12_600 + 2 * TOUCH_FLUSH_INTERVAL + MIN_EVICT_IDLE;
        const NOW: u64 = 1_700_000_000;

        fn edge() -> Self {
            Evict {
                now: Self::NOW,
                last_active_at: Self::NOW - Self::UNREPORTED,
                grant_expires_at: Self::NOW + Self::SPAN + CLOCK_SKEW + 1,
                consumed: true,
                idle_floor_at: 0,
                idle: Self::IDLE,
            }
        }

        fn check(&self) -> bool {
            evictable(
                self.now,
                self.last_active_at,
                self.grant_expires_at,
                self.consumed,
                self.idle_floor_at,
                self.idle,
            )
        }
    }

    #[test]
    fn evictable_at_the_exact_edge() {
        assert!(Evict::edge().check());
    }

    #[test]
    fn unconsumed_records_are_never_evicted() {
        assert!(!Evict { consumed: false, ..Evict::edge() }.check());
    }

    #[test]
    fn records_no_longer_touched_are_never_evicted() {
        let e = Evict::edge();
        assert!(!Evict { grant_expires_at: e.grant_expires_at - 1, ..e }.check());
        // At the default timeout touches never happen, so nothing qualifies even
        // for a record idle since the epoch with a full 30 d grant ahead.
        let e = Evict::edge();
        assert!(!Evict {
            idle: DEFAULT_IDLE_TIMEOUT,
            last_active_at: 0,
            grant_expires_at: e.now + MAX_GRANT,
            ..e
        }
        .check());
    }

    /// A record with the longest grant `put_session` accepts, never touched since
    /// its creation and idle exactly as long as eviction requires under the 30 d
    /// default's granularity. Its grant is far enough ahead to pass the expiry
    /// condition at both timeouts below.
    fn long_grant_never_touched(idle: u64) -> bool {
        use crate::constants::MAX_GRANT_ACCEPTED;
        let created = Evict::NOW;
        let unreported = MAX_TOUCH_GRANULARITY + 2 * TOUCH_FLUSH_INTERVAL + MIN_EVICT_IDLE;
        evictable(created + unreported, created, created + MAX_GRANT_ACCEPTED, true, 0, idle)
    }

    #[test]
    fn nothing_is_evicted_while_touches_are_off() {
        // The longest timeout with touches on: the same record is evictable.
        assert!(touches_effective(2_570_039));
        assert!(long_grant_never_touched(2_570_039));
        // One second longer, backends stop touching, so its `last_active_at`
        // says nothing, however long the grant.
        assert!(!touches_effective(2_570_040));
        assert!(!long_grant_never_touched(2_570_040));
        assert!(!long_grant_never_touched(DEFAULT_IDLE_TIMEOUT));
    }

    #[test]
    fn recent_activity_or_floor_prevents_eviction() {
        let e = Evict::edge();
        assert!(!Evict { last_active_at: e.last_active_at + 1, ..e }.check());
        // A floor raised recently makes old activity untrustworthy.
        let e = Evict::edge();
        assert!(
            !Evict { last_active_at: 0, idle_floor_at: e.now - Evict::UNREPORTED + 1, ..e }.check()
        );
        let e = Evict::edge();
        assert!(Evict { last_active_at: 0, idle_floor_at: e.now - Evict::UNREPORTED, ..e }.check());
    }

    #[test]
    fn evictable_saturates_towards_keeping_the_session() {
        // Activity reported "in the future" counts as just now.
        let e = Evict::edge();
        assert!(!Evict { last_active_at: e.now + 10, ..e }.check());
        // An overflowing `now + span` can never be below the grant expiry.
        let e = Evict::edge();
        assert!(!Evict { now: u64::MAX - 1, grant_expires_at: u64::MAX, ..e }.check());
    }

    #[test]
    fn namespace_of_requires_a_full_key() {
        let key: Vec<u8> = (0..32).collect();
        let ns: [u8; 16] = (0..16).collect::<Vec<u8>>().try_into().unwrap();
        assert_eq!(namespace_of(&key), Some(ns));
        assert_eq!(namespace_of(&key[..31]), None);
        assert_eq!(namespace_of(&[0; 33]), None);
        assert_eq!(namespace_of(&key[..16]), None);
        assert_eq!(namespace_of(&[]), None);
    }
}
