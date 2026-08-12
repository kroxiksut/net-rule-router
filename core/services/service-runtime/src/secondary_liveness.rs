//! Secondary-tunnel liveness tracker.
//!
//! Turns a stream of per-adapter reachability-probe results into a stable
//! alive/dead verdict with HYSTERESIS: an adapter is declared dead only after
//! its probe has failed CONTINUOUSLY for a configured window, so a single
//! dropped ICMP echo (transient loss) never fail-closes a healthy secondary tunnel. A single
//! success resets the clock.
//!
//! Neutral + unit-testable: the caller injects `now: Instant` and the probe
//! results, so no real time or network is needed to test the hysteresis.
//!
//! `window_secs == 0` = feature DISABLED: `is_dead` is always `false`, so the
//! probe never fail-closes anything. This is the safe default (an ICMP-filtered
//! tunnel peer must not be able to block the user's traffic unless they opt in).
//!
//! **Baseline requirement:** a DEAD verdict additionally requires
//! that this next-hop answered the probe AT LEAST ONCE since the adapter was
//! (re)bound. Many legitimate gateways — corporate VPN concentrators, NAT
//! gateways of virtual adapters — silently drop ICMP echo; without the
//! baseline the probe would declare such a tunnel permanently dead the moment
//! it is bound, tear its routes down and (fail-closed) block its destinations,
//! even though it carries traffic fine. A peer that has NEVER answered is
//! *unprobeable*, not dead — the fail-safe direction, same as a probe that
//! cannot run. The inherent blind spot is accepted: a tunnel that answered
//! once and later goes ping-silent-but-alive still reads as dead — ICMP alone
//! cannot distinguish that from a real death.
//!
//! **Evidence freshness:** a DEAD verdict must be backed by probes that
//! actually RAN across the window. While an adapter is unresolvable (VPN
//! reconnecting: media Down, no IPv4) the probe cannot run, so no results
//! are recorded — but a naive failing-run clock would survive that silence:
//! the moment the adapter comes back Up, comparing "now" against a
//! first-failure timestamp from BEFORE the outage would see a window's
//! worth of "failure" and fail-close a tunnel that had just reconnected
//! fine. Two rules close this: a gap between recorded probes longer than
//! [`MAX_EVIDENCE_GAP`] starts a NEW incarnation (the failing run AND the
//! reachability baseline reset — the peer must re-prove itself), and
//! `is_dead` demands a recent record (no fresh evidence → no verdict).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracks, per interface index, the `Instant` of the first probe failure in the
/// current consecutive-failure run. Shared (`Arc`) between the probe tick
/// (writer via [`record`]) and the route coordinator (reader via [`is_dead`]).
///
/// [`record`]: SecondaryLivenessTracker::record
/// [`is_dead`]: SecondaryLivenessTracker::is_dead
pub struct SecondaryLivenessTracker {
    state: Mutex<TrackerState>,
    /// Consecutive-failure window before an adapter counts as dead, in seconds.
    /// `0` = disabled. Atomic so a live setting change is picked up without a
    /// lock.
    window_secs: AtomicU64,
}

#[derive(Default)]
struct TrackerState {
    /// `ifindex -> Instant of the FIRST failure in the current failing run`.
    /// Absent = the last probe succeeded (or the adapter was never probed).
    first_fail: HashMap<u32, Instant>,
    /// `ifindex -> consecutive successes still required before the adapter
    /// counts as RECOVERED`. A failing run only ends for the fast signal
    /// ([`SecondaryLivenessTracker::in_failing_run`]) after
    /// [`RECOVERY_SUCCESS_STREAK`] successes in a row — a single lucky echo
    /// through a flapping tunnel must not bounce consumers back onto it
    /// (observed: the DNS-over-secondary /32s re-asserted and reverted
    /// every few seconds for the whole session).
    recovery_needed: HashMap<u32, u32>,
    /// Interfaces whose next-hop has answered the probe at least once since
    /// they were (re)bound — the baseline a DEAD verdict requires (see the
    /// module doc). Cleared by [`SecondaryLivenessTracker::forget`] so a
    /// reused ifindex must re-prove itself.
    ever_reachable: HashSet<u32>,
    /// Interfaces for which the "verdict withheld — no baseline" info line was
    /// already emitted this failing run, so a silent gateway logs once per run
    /// instead of once per reconcile.
    baseline_hold_logged: HashSet<u32>,
    /// `ifindex -> Instant of the most recently recorded probe result` (either
    /// verdict). Backs the evidence-freshness rules (see the module doc):
    /// detects unprobeable gaps in [`SecondaryLivenessTracker::record`] and
    /// vetoes stale verdicts in [`SecondaryLivenessTracker::is_dead`].
    last_record: HashMap<u32, Instant>,
}

/// Consecutive successful probes required to leave a failing run. Failure
/// entry stays immediate (one failed probe re-arms the run).
const RECOVERY_SUCCESS_STREAK: u32 = 3;

/// Longest tolerated silence between two recorded probe results before the
/// tracker treats the interface as having been UNPROBEABLE in between (adapter
/// down / next-hop unresolvable / probe task stalled). The probe tick runs
/// every ~5 s (`service_tasks::SECONDARY_LIVENESS_INTERVAL`), so 20 s means
/// "at least three consecutive ticks produced nothing" — well past jitter and
/// the 1 s per-probe timeout. A gap longer than this resets the failing run
/// and the reachability baseline (new incarnation), and evidence older than
/// this can never support a DEAD verdict.
const MAX_EVIDENCE_GAP: Duration = Duration::from_secs(20);

impl SecondaryLivenessTracker {
    /// `window_secs == 0` disables the probe (never declares dead).
    pub fn new(window_secs: u64) -> Self {
        Self {
            state: Mutex::new(TrackerState::default()),
            window_secs: AtomicU64::new(window_secs),
        }
    }

    /// Update the window (live setting change). `0` disables + effectively
    /// clears any pending dead verdict on the next `is_dead` read.
    pub fn set_window_secs(&self, secs: u64) {
        self.window_secs.store(secs, Ordering::SeqCst);
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs.load(Ordering::SeqCst)
    }

    /// Whether the active-probe feature is on (window > 0).
    pub fn enabled(&self) -> bool {
        self.window_secs() > 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TrackerState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Record one probe result for `ifindex` observed at `now`.
    ///
    /// - `reachable == true` → clear the dead-verdict clock immediately, and
    ///   count one step toward recovery (the fast signal stays "failing" until
    ///   [`RECOVERY_SUCCESS_STREAK`] successes in a row).
    /// - `reachable == false` → start the failing run if not already running
    ///   (keep the EARLIEST failure so the window measures continuous failure)
    ///   and reset the recovery streak.
    ///
    /// A silence longer than [`MAX_EVIDENCE_GAP`] since the previous record
    /// means the interface was unprobeable in between (adapter down during a
    /// VPN reconnect, typically): whatever run or baseline was accumulating
    /// belongs to the PREVIOUS tunnel incarnation and is discarded before this
    /// result is applied.
    pub fn record(&self, ifindex: u32, reachable: bool, now: Instant) {
        let mut state = self.lock();
        let gap = state
            .last_record
            .get(&ifindex)
            .is_some_and(|prev| now.saturating_duration_since(*prev) > MAX_EVIDENCE_GAP);
        if gap {
            state.first_fail.remove(&ifindex);
            state.recovery_needed.remove(&ifindex);
            state.ever_reachable.remove(&ifindex);
            state.baseline_hold_logged.remove(&ifindex);
        }
        state.last_record.insert(ifindex, now);
        if reachable {
            state.first_fail.remove(&ifindex);
            state.ever_reachable.insert(ifindex);
            state.baseline_hold_logged.remove(&ifindex);
            if let Some(remaining) = state.recovery_needed.get_mut(&ifindex) {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    state.recovery_needed.remove(&ifindex);
                }
            }
        } else {
            state.first_fail.entry(ifindex).or_insert(now);
            state
                .recovery_needed
                .insert(ifindex, RECOVERY_SUCCESS_STREAK);
        }
    }

    /// Is `ifindex` currently DEAD — i.e. the probe has failed continuously for
    /// at least the window AND the next-hop has answered at least once since
    /// the adapter was bound (the baseline — see the module doc) AND the most
    /// recent probe result is fresh (recorded within [`MAX_EVIDENCE_GAP`] —
    /// stale evidence from before an unprobeable gap proves nothing about the
    /// tunnel that exists NOW)? Always `false` when disabled (`window == 0`).
    pub fn is_dead(&self, ifindex: u32, now: Instant) -> bool {
        let window = self.window_secs();
        if window == 0 {
            return false;
        }
        let mut state = self.lock();
        let Some(first_fail) = state.first_fail.get(&ifindex).copied() else {
            return false;
        };
        if now.saturating_duration_since(first_fail) < Duration::from_secs(window) {
            return false;
        }
        let fresh = state
            .last_record
            .get(&ifindex)
            .is_some_and(|last| now.saturating_duration_since(*last) <= MAX_EVIDENCE_GAP);
        if !fresh {
            // The probe has not run recently (adapter unresolvable / task
            // stalled). Whatever this run measured, it does not describe the
            // present — declaring dead here is how a freshly-reconnected
            // tunnel gets fail-closed the moment it comes back Up. The next
            // recorded probe restarts the clock (see `record`).
            return false;
        }
        if !state.ever_reachable.contains(&ifindex) {
            // Would be dead by the window, but the peer never answered: a
            // ping-silent gateway (corporate concentrator, virtual-adapter
            // NAT) is unprobeable, not dead. Say so once per failing run.
            if state.baseline_hold_logged.insert(ifindex) {
                tracing::info!(
                    target: "nrr::route-coordinator",
                    ifindex,
                    "secondary next-hop has never answered the liveness probe — treating it as unprobeable (alive), not dead; a gateway that drops ICMP echo cannot fail-close the tunnel",
                );
            }
            return false;
        }
        true
    }

    /// Forget `ifindex` (adapter unbound / no longer a secondary) so a stale
    /// failing run can't linger — including its reachability baseline: a
    /// reused ifindex belongs to a new incarnation and must re-prove itself.
    pub fn forget(&self, ifindex: u32) {
        let mut state = self.lock();
        state.first_fail.remove(&ifindex);
        state.recovery_needed.remove(&ifindex);
        state.ever_reachable.remove(&ifindex);
        state.baseline_hold_logged.remove(&ifindex);
        state.last_record.remove(&ifindex);
    }

    /// Whether `ifindex` is currently inside a failing probe run — its most
    /// recent probe failed, OR it has not yet produced
    /// [`RECOVERY_SUCCESS_STREAK`] consecutive successes since the last
    /// failure. This is the FAST signal for consumers that must not wait out
    /// the dead-verdict hysteresis (the DNS resolver routes: pinning the
    /// system's public resolvers into a tunnel whose last probe failed
    /// blackholes name resolution for the whole window) — and the asymmetry is
    /// deliberate: leaving the tunnel is instant, returning to it requires a
    /// stable run of successes so a flapping tunnel cannot bounce the
    /// resolvers back and forth every probe. `false` when disabled, never
    /// probed, or stably recovered.
    pub fn in_failing_run(&self, ifindex: u32) -> bool {
        if !self.enabled() {
            return false;
        }
        let state = self.lock();
        state.first_fail.contains_key(&ifindex) || state.recovery_needed.contains_key(&ifindex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_window_never_declares_dead() {
        let t = SecondaryLivenessTracker::new(0);
        let t0 = Instant::now();
        t.record(5, false, t0);
        // Even far in the "future", disabled → never dead.
        assert!(!t.is_dead(5, t0 + Duration::from_secs(10_000)));
        assert!(!t.enabled());
    }

    /// Record a failure every 10 s from `from` to `to` inclusive — the shape a
    /// live probe tick produces, so the failing run stays continuously
    /// evidenced (no unprobeable gap, evidence always fresh).
    fn fail_continuously(
        t: &SecondaryLivenessTracker,
        ifindex: u32,
        t0: Instant,
        from: u64,
        to: u64,
    ) {
        let mut s = from;
        while s <= to {
            t.record(ifindex, false, t0 + Duration::from_secs(s));
            s += 10;
        }
    }

    #[test]
    fn dead_only_after_continuous_failure_reaches_window() {
        let t = SecondaryLivenessTracker::new(60);
        let t0 = Instant::now();
        t.record(5, true, t0); // baseline: the peer has answered once
        fail_continuously(&t, 5, t0, 0, 50);
        // Before the window elapses: not dead (hysteresis absorbs it).
        assert!(!t.is_dead(5, t0 + Duration::from_secs(59)));
        // At/after the window (with the probe still ticking): dead.
        fail_continuously(&t, 5, t0, 60, 120);
        assert!(t.is_dead(5, t0 + Duration::from_secs(60)));
        assert!(t.is_dead(5, t0 + Duration::from_secs(120)));
    }

    #[test]
    fn a_single_success_resets_the_failing_run() {
        let t = SecondaryLivenessTracker::new(60);
        let t0 = Instant::now();
        t.record(5, false, t0);
        // A success at t0+30 clears the run…
        t.record(5, true, t0 + Duration::from_secs(30));
        assert!(!t.is_dead(5, t0 + Duration::from_secs(120)));
        // …and a fresh failure starts the clock over from t0+40.
        fail_continuously(&t, 5, t0, 40, 90);
        assert!(!t.is_dead(5, t0 + Duration::from_secs(99))); // only 59s of failure
        fail_continuously(&t, 5, t0, 100, 100);
        assert!(t.is_dead(5, t0 + Duration::from_secs(100))); // 60s of failure
    }

    #[test]
    fn repeated_failures_keep_the_earliest_timestamp() {
        let t = SecondaryLivenessTracker::new(60);
        let t0 = Instant::now();
        t.record(5, true, t0); // baseline
                               // Later failures must NOT push the first-fail time forward.
        fail_continuously(&t, 5, t0, 0, 60);
        assert!(t.is_dead(5, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn forget_clears_a_pending_dead_verdict() {
        let t = SecondaryLivenessTracker::new(60);
        let t0 = Instant::now();
        t.record(5, true, t0); // baseline
        t.record(5, false, t0);
        t.forget(5);
        assert!(!t.is_dead(5, t0 + Duration::from_secs(120)));
    }

    #[test]
    fn silent_from_birth_next_hop_is_never_declared_dead() {
        // Corporate VPN concentrators and virtual-adapter NAT gateways
        // commonly drop ICMP echo. A peer that has NEVER answered is
        // unprobeable, not dead: without a baseline the probe must not tear
        // routes down or fail-close, no matter how long the failures run.
        let t = SecondaryLivenessTracker::new(10);
        let t0 = Instant::now();
        t.record(7, false, t0);
        t.record(7, false, t0 + Duration::from_secs(60));
        assert!(
            !t.is_dead(7, t0 + Duration::from_secs(3600)),
            "no baseline → never dead"
        );
        // The fast failing-run signal is unaffected (consumers like the
        // DNS-over-secondary /32s still step aside while probes fail).
        assert!(t.in_failing_run(7));
        // Once the peer answers even once, the ordinary verdict applies.
        t.record(7, true, t0 + Duration::from_secs(3700));
        t.record(7, false, t0 + Duration::from_secs(3710));
        assert!(t.is_dead(7, t0 + Duration::from_secs(3720)));
    }

    #[test]
    fn forget_drops_the_reachability_baseline() {
        // A reused ifindex is a new incarnation: the old baseline must not
        // let a silent-from-birth successor be declared dead.
        let t = SecondaryLivenessTracker::new(10);
        let t0 = Instant::now();
        t.record(9, true, t0);
        t.forget(9);
        t.record(9, false, t0 + Duration::from_secs(100));
        assert!(
            !t.is_dead(9, t0 + Duration::from_secs(1000)),
            "baseline does not survive forget"
        );
    }

    #[test]
    fn recovery_needs_a_stable_success_streak() {
        let t = SecondaryLivenessTracker::new(60);
        let t0 = Instant::now();
        assert!(!t.in_failing_run(5), "never probed = not failing");
        t.record(5, false, t0);
        assert!(t.in_failing_run(5));
        // One success clears the DEAD clock but not the fast failing signal.
        t.record(5, true, t0 + Duration::from_secs(10));
        assert!(!t.is_dead(5, t0 + Duration::from_secs(120)));
        assert!(t.in_failing_run(5), "one lucky echo is not recovery");
        t.record(5, true, t0 + Duration::from_secs(20));
        assert!(t.in_failing_run(5));
        t.record(5, true, t0 + Duration::from_secs(30));
        assert!(!t.in_failing_run(5), "third consecutive success recovers");
        // A failure mid-streak re-arms the full requirement.
        t.record(5, false, t0 + Duration::from_secs(40));
        t.record(5, true, t0 + Duration::from_secs(50));
        t.record(5, true, t0 + Duration::from_secs(60));
        assert!(t.in_failing_run(5), "streak restarted after the failure");
        t.record(5, true, t0 + Duration::from_secs(70));
        assert!(!t.in_failing_run(5));
        // Forget clears everything.
        t.record(5, false, t0 + Duration::from_secs(80));
        t.forget(5);
        assert!(!t.in_failing_run(5));
    }

    #[test]
    fn window_change_takes_effect_immediately() {
        let t = SecondaryLivenessTracker::new(120);
        let t0 = Instant::now();
        t.record(5, true, t0); // baseline
        fail_continuously(&t, 5, t0, 0, 60);
        assert!(!t.is_dead(5, t0 + Duration::from_secs(60)));
        // Shorten the window live → the same failing run now counts as dead.
        t.set_window_secs(30);
        assert!(t.is_dead(5, t0 + Duration::from_secs(60)));
        // Disable → immediately not dead.
        t.set_window_secs(0);
        assert!(!t.is_dead(5, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn an_unprobeable_gap_resets_the_run_and_the_baseline() {
        // The VPN adapter dropped (media Down, no IPv4) for ~3 minutes
        // mid-run; no probes could run. The failing run from just
        // before the outage must NOT carry across it: the tunnel that comes
        // back Up is a new incarnation and gets a fresh window AND must
        // re-prove its reachability baseline before any DEAD verdict.
        let t = SecondaryLivenessTracker::new(10);
        let t0 = Instant::now();
        t.record(60, true, t0); // baseline (peer answered before the outage)
        t.record(60, false, t0 + Duration::from_secs(5));
        t.record(60, false, t0 + Duration::from_secs(10));
        // …adapter down, 3 minutes of silence…
        let revived = t0 + Duration::from_secs(190);
        t.record(60, false, revived); // first post-outage probe still fails
        assert!(
            !t.is_dead(60, revived + Duration::from_secs(1)),
            "the pre-outage failing run must not satisfy the window"
        );
        // Even a full window of post-outage failures is not DEAD yet: the gap
        // dropped the baseline, so the peer reads unprobeable (fail-safe).
        t.record(60, false, revived + Duration::from_secs(11));
        assert!(!t.is_dead(60, revived + Duration::from_secs(12)));
        // Once it answers again, the ordinary verdict applies from there.
        t.record(60, true, revived + Duration::from_secs(15));
        t.record(60, false, revived + Duration::from_secs(20));
        t.record(60, false, revived + Duration::from_secs(30));
        assert!(t.is_dead(60, revived + Duration::from_secs(30)));
    }

    #[test]
    fn stale_evidence_alone_never_declares_dead() {
        // The probe stopped running entirely (adapter unresolvable / task
        // stalled) mid-failing-run. Without a fresh record, the old run says
        // nothing about the present — `is_dead` must decline the verdict even
        // though the window has long elapsed.
        let t = SecondaryLivenessTracker::new(10);
        let t0 = Instant::now();
        t.record(60, true, t0);
        t.record(60, false, t0 + Duration::from_secs(5));
        t.record(60, false, t0 + Duration::from_secs(15));
        // Fresh + window elapsed → dead, as before.
        assert!(t.is_dead(60, t0 + Duration::from_secs(16)));
        // Same run, but the last record is now far in the past → not dead.
        assert!(!t.is_dead(60, t0 + Duration::from_secs(120)));
    }
}
