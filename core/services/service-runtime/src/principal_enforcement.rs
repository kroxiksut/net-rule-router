//! WHEN to enforce, and for WHOM — the neutral half of the enforcement loop.
//!
//! The mechanism is per-OS (nftables, WFP) and lives behind [`PolicyEnforcer`].
//! Who is present is per-OS too (logind, a tray connection) and lives behind
//! [`ActivePrincipalSource`]. What is left is policy, and it is the same
//! everywhere: ask who is here, plan for each of them, hand the whole set to the
//! platform in one pass.
//!
//! ## Two answers that must never be confused
//!
//! "Nobody is logged in" is an instruction: enforce nothing. "I could not ask"
//! is not — acting on it would tear down every user's policy at the moment the
//! system is least able to explain why. The cycle therefore leaves the platform
//! untouched when the authority is unavailable, and says so.
//!
//! ## Two mechanisms, applied in order
//!
//! Filters first, then routes. A route that steers traffic onto a link the
//! filters do not yet permit is a moment of blocked traffic; a filter that
//! permits a link no route points at is a moment of traffic taking the old path.
//! The second is the safer order to be caught mid-way in, and it is the order a
//! reconnect naturally wants.
//!
//! ## Why it applies on every tick, not only on change
//!
//! The plan is not the whole input: the interface a rule pins to is resolved
//! from live facts at apply time, so a link going down changes what should be
//! installed without changing the plan at all. Re-applying is idempotent by
//! construction on both platforms, which makes "apply every tick" the cheap and
//! correct option, and change detection a matter of what gets LOGGED.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use nrr_domain::user_principal::UserPrincipal;
use nrr_platform_api::active_principals::ActivePrincipalSource;
use nrr_platform_api::enforcement::{
    ApplyReport, ChannelAvailability, EnforcementPlan, PolicyEnforcer,
};

/// Produces one principal's neutral plan from the stored policy.
///
/// `None` means there is nothing to enforce for them — no stored policy, or no
/// enabled rules. That is a legitimate answer, not a failure: a user who has not
/// set up routing has no policy, and inventing an empty one would be a decision
/// nobody made.
pub trait PrincipalPlanSource: Send + Sync {
    /// `availability` is what the platform can actually send over at this
    /// instant. It is an INPUT to the plan, not a detail of applying it: with
    /// the secondary gone, the intent stops being "pin this traffic to the
    /// tunnel" and becomes "block it or let it out over the primary", and only
    /// the user's fail-closed setting decides which.
    fn plan_for(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> Option<PlannedPolicy>;

    /// Called once before the pass's first `plan_for`.
    ///
    /// Every principal in a pass is planned against ONE machine, so a source
    /// that reads live facts takes them once here rather than per principal —
    /// otherwise two users could be planned against two different readings of
    /// the same instant. Default: nothing to do.
    fn begin_pass(&self) {}
}

/// A plan together with how much of the user's asked-for protection it carries.
///
/// The second half travels WITH the plan rather than beside it, because the two
/// are read together or not at all: a plan whose shortfall is recorded somewhere
/// else is a plan that gets applied while the shortfall goes unmentioned.
pub struct PlannedPolicy {
    pub plan: EnforcementPlan,
    /// Whether the protection in the plan is what the settings asked for.
    /// `false` means the platform cannot arm part of it — the cycle then says so
    /// on every pass.
    pub protection_complete: bool,
    /// Destinations the leak-guard is holding in this plan. Zero is the normal
    /// state; a non-zero count is the visible sign that a secondary link is gone
    /// and its traffic is being blocked rather than leaking to the primary.
    pub fail_closed_blocks: usize,
}

/// What one pass did. Returned rather than only logged, so a test asserts the
/// decision instead of scraping output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The plans in force were applied. `principals` is who they belong to.
    Applied {
        principals: Vec<String>,
        report: ApplyReport,
        /// Whether the set of plans differs from the previous pass. Drives the
        /// log level only — never whether to apply.
        changed: bool,
        /// Principals whose plan carries LESS protection than their settings
        /// ask for. Reported every pass, not once: an operator reading a single
        /// line about this run must not take it for full coverage.
        unprotected: Vec<String>,
        /// Destinations the leak-guard is holding across all plans.
        guarded: usize,
        /// What the route pass did, when a route mechanism is wired.
        routes: Option<crate::route_apply::RouteApplyReport>,
    },
    /// The active set could not be read; the platform was left as it was.
    AuthorityUnavailable { reason: String },
    /// The platform refused the plans. Whatever was installed before is still
    /// installed — the failure is reported, not silently absorbed.
    EnforcementFailed { reason: String },
    /// The cycle has been torn down and refuses to install anything more. A
    /// task that hung past the shutdown drain would otherwise reinstate the
    /// policy AFTER the stop removed it, leaving a stopped service's filters in
    /// the kernel.
    Stopped,
}

/// The neutral enforcement cycle.
pub struct PrincipalEnforcementCycle {
    principals: Arc<dyn ActivePrincipalSource>,
    plans: Arc<dyn PrincipalPlanSource>,
    enforcer: Arc<dyn PolicyEnforcer>,
    /// Installs the plans' route intents. `None` leaves the route table alone —
    /// honest on a host with no route mechanism wired, and the cycle then says
    /// so rather than implying traffic is being steered.
    routes: Option<Arc<crate::route_apply::PlannedRouteApplier>>,
    /// The plans installed by the previous pass — and, because the lock is held
    /// for the WHOLE pass, the thing that serialises passes against each other.
    /// Three callers drive this cycle (the timer, an apply from the GUI, a link
    /// change), and two of them planning concurrently would let the slower one
    /// install its older view of the machine last.
    last_applied: Mutex<Option<Vec<EnforcementPlan>>>,
    /// Latched by [`PrincipalEnforcementCycle::teardown`]; never cleared.
    stopped: AtomicBool,
}

impl PrincipalEnforcementCycle {
    pub fn new(
        principals: Arc<dyn ActivePrincipalSource>,
        plans: Arc<dyn PrincipalPlanSource>,
        enforcer: Arc<dyn PolicyEnforcer>,
    ) -> Self {
        Self {
            principals,
            plans,
            enforcer,
            routes: None,
            last_applied: Mutex::new(None),
            stopped: AtomicBool::new(false),
        }
    }

    /// Attach the route applier. Builder-style because a host without a route
    /// mechanism is a legitimate configuration, not a broken one.
    #[must_use]
    pub fn with_routes(mut self, routes: Arc<crate::route_apply::PlannedRouteApplier>) -> Self {
        self.routes = Some(routes);
        self
    }

    /// The authority this cycle asks who is present, for logs.
    pub fn authority(&self) -> &'static str {
        self.principals.authority()
    }

    /// Run one pass. Passes are serialised: see `last_applied`.
    pub fn tick(&self) -> CycleOutcome {
        let mut last = self.last_applied.lock().unwrap_or_else(|p| p.into_inner());
        if self.stopped.load(Ordering::Acquire) {
            return CycleOutcome::Stopped;
        }
        let active = match self.principals.active_principals() {
            Ok(active) => active,
            Err(e) => {
                return CycleOutcome::AuthorityUnavailable {
                    reason: e.to_string(),
                }
            }
        };

        self.plans.begin_pass();
        let mut plans: Vec<EnforcementPlan> = Vec::new();
        let mut unprotected: Vec<String> = Vec::new();
        let mut guarded = 0usize;
        for principal in &active {
            let availability = self.enforcer.channel_availability(principal);
            let Some(planned) = self.plans.plan_for(principal, availability) else {
                continue;
            };
            if !planned.protection_complete {
                unprotected.push(principal.as_stored().to_owned());
            }
            guarded += planned.fail_closed_blocks;
            plans.push(planned.plan);
        }

        let changed = last.as_deref() != Some(plans.as_slice());

        match self.enforcer.enforce(&plans) {
            Ok(report) => {
                let principals = plans
                    .iter()
                    .map(|p| p.principal.as_stored().to_owned())
                    .collect();

                // Routes come after the filters that guard them. A failure here
                // is NOT fatal to the pass: the filters are installed and the
                // traffic they guard is contained; what is missing is the
                // steering, and the caller reports that rather than discarding
                // a policy that is already half in force.
                let routes = self.routes.as_ref().map(|applier| {
                    applier.apply(&plans).unwrap_or_else(|reason| {
                        crate::route_apply::RouteApplyReport {
                            failure: Some(reason),
                            ..Default::default()
                        }
                    })
                });

                *last = Some(plans);
                CycleOutcome::Applied {
                    principals,
                    report,
                    changed,
                    unprotected,
                    guarded,
                    routes,
                }
            }
            // Deliberately NOT recorded as applied: the next tick must try
            // again rather than believe the kernel holds something it refused.
            Err(e) => CycleOutcome::EnforcementFailed {
                reason: e.to_string(),
            },
        }
    }

    /// Run one pass and report it. `trigger` names what asked for the pass —
    /// the timer, a link change, an apply from the GUI — because the same
    /// outcome means different things depending on what provoked it.
    pub fn tick_logged(&self, trigger: &'static str) -> CycleOutcome {
        let outcome = self.tick();
        log_outcome(&outcome, trigger, self.authority());
        outcome
    }

    /// Remove everything this product installed. Called on graceful stop: a
    /// daemon that exits leaving its policy in the kernel leaves the machine
    /// enforcing rules nothing is maintaining any more.
    ///
    /// Filters first, then routes — the opposite order to applying them. A
    /// moment with routes but no filters still carries traffic over the link
    /// the user chose; the reverse leaves the leak-guard `drop` in place with
    /// nothing steering around it, which is a machine with no network.
    pub fn teardown(&self) -> Result<(), String> {
        // Held for the whole teardown, and the latch is set inside it: a pass
        // already under way finishes, no later one starts, and the last word on
        // the kernel's contents is this one.
        let _pass = self.last_applied.lock().unwrap_or_else(|p| p.into_inner());
        self.stopped.store(true, Ordering::Release);
        let filters = self.enforcer.teardown().map_err(|e| e.to_string());
        let routes = match self.routes.as_ref() {
            Some(applier) => applier.clear().map(|_| ()),
            None => Ok(()),
        };
        match (filters, routes) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(f), Err(r)) => Err(format!("{f}; {r}")),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }
}

/// Report one pass. Shared by every caller so a pass provoked by a link change
/// reads the same as the timer's, differing only in `trigger`.
pub fn log_outcome(outcome: &CycleOutcome, trigger: &'static str, authority: &'static str) {
    match outcome {
        CycleOutcome::Applied {
            principals,
            report,
            changed,
            unprotected,
            guarded,
            routes,
        } => {
            // Routes are the half that STEERS traffic. Their failure is
            // reported at error level even though the filters landed: with the
            // filters in force and no route, a rule meant to send a host over
            // the tunnel silently blocks it instead.
            if let Some(routes) = routes {
                if let Some(failure) = &routes.failure {
                    tracing::error!(
                        target: "nrr::routes",
                        trigger,
                        reason = %failure,
                        "routes could NOT be applied: traffic is filtered but not steered",
                    );
                }
                if !routes.unresolved.is_empty() {
                    tracing::warn!(
                        target: "nrr::routes",
                        trigger,
                        principals = ?routes.unresolved,
                        "no live secondary link to steer through; their routes were not installed",
                    );
                }
                if routes.added > 0 || routes.removed > 0 {
                    tracing::info!(
                        target: "nrr::routes",
                        trigger,
                        added = routes.added,
                        removed = routes.removed,
                        "system routes reconciled",
                    );
                }
            }
            // Every pass, never once: a user whose settings ask for more
            // protection than this platform can arm must not have that fact
            // scroll out of the log.
            if !unprotected.is_empty() {
                tracing::warn!(
                    target: "nrr::enforcement",
                    trigger,
                    principals = ?unprotected,
                    "the blanket block these settings ask for is NOT armed: traffic outside the routing rules is not blocked. The pass logs the reason when it decides",
                );
            }
            // Loud when the set of plans changed, quiet on the identical
            // re-apply that follows every ten seconds: a warning repeated
            // forever is one an operator learns to scroll past.
            for note in &report.notes {
                if *changed {
                    tracing::warn!(target: "nrr::enforcement", trigger, note = %note, "rule not enforced as written");
                } else {
                    tracing::debug!(target: "nrr::enforcement", trigger, note = %note, "rule not enforced as written");
                }
            }
            // Only a CHANGE is worth a line at info: re-applying the same policy
            // every ten seconds would otherwise bury the events that matter
            // under identical entries.
            if *changed {
                tracing::info!(
                    target: "nrr::enforcement",
                    trigger,
                    principals = ?principals,
                    applied = report.applied,
                    skipped = report.skipped,
                    guarded,
                    "policy applied for the principals present",
                );
            } else {
                tracing::debug!(
                    target: "nrr::enforcement",
                    trigger,
                    applied = report.applied,
                    "policy re-applied unchanged",
                );
            }
        }
        CycleOutcome::AuthorityUnavailable { reason } => tracing::warn!(
            target: "nrr::enforcement",
            trigger,
            authority,
            reason = %reason,
            "could not determine who is logged in; policy left exactly as it was (this is NOT the same as nobody being present)",
        ),
        CycleOutcome::EnforcementFailed { reason } => tracing::error!(
            target: "nrr::enforcement",
            trigger,
            reason = %reason,
            "policy could NOT be applied — the rules on file are not in effect",
        ),
        CycleOutcome::Stopped => tracing::info!(
            target: "nrr::enforcement",
            trigger,
            "policy was removed on stop; this pass installed nothing",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::active_principals::ActivePrincipalError;
    use nrr_platform_api::enforcement::EnforcementFailure;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScriptedPrincipals {
        answer: Option<Vec<UserPrincipal>>,
    }
    impl ActivePrincipalSource for ScriptedPrincipals {
        fn active_principals(&self) -> Result<Vec<UserPrincipal>, ActivePrincipalError> {
            self.answer
                .clone()
                .ok_or_else(|| ActivePrincipalError::new("loginctl is not available"))
        }
        fn authority(&self) -> &'static str {
            "scripted"
        }
    }

    /// Every principal gets a present-but-empty plan, except those listed as
    /// having no stored policy at all.
    struct PlanEveryone {
        without_policy: Vec<String>,
    }
    impl PrincipalPlanSource for PlanEveryone {
        fn plan_for(
            &self,
            principal: &UserPrincipal,
            _availability: ChannelAvailability,
        ) -> Option<PlannedPolicy> {
            if self
                .without_policy
                .iter()
                .any(|p| p == principal.as_stored())
            {
                return None;
            }
            Some(PlannedPolicy {
                plan: EnforcementPlan {
                    principal: principal.clone(),
                    flows: Vec::new(),
                    routes: Vec::new(),
                    policy_rules: Vec::new(),
                },
                protection_complete: true,
                fail_closed_blocks: 0,
            })
        }
    }

    struct RecordingEnforcer {
        calls: Mutex<Vec<Vec<String>>>,
        fail: bool,
        /// How many passes are inside `enforce` right now, and how often that
        /// was more than one.
        inside: AtomicUsize,
        overlaps: AtomicUsize,
        teardowns: AtomicUsize,
    }
    impl RecordingEnforcer {
        fn new(fail: bool) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail,
                inside: AtomicUsize::new(0),
                overlaps: AtomicUsize::new(0),
                teardowns: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }
    impl PolicyEnforcer for RecordingEnforcer {
        fn enforce(&self, plans: &[EnforcementPlan]) -> Result<ApplyReport, EnforcementFailure> {
            if self.inside.fetch_add(1, Ordering::AcqRel) > 0 {
                self.overlaps.fetch_add(1, Ordering::AcqRel);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            self.inside.fetch_sub(1, Ordering::AcqRel);
            self.calls.lock().unwrap_or_else(|p| p.into_inner()).push(
                plans
                    .iter()
                    .map(|p| p.principal.as_stored().to_owned())
                    .collect(),
            );
            if self.fail {
                return Err(EnforcementFailure::new("nft rejected the batch"));
            }
            Ok(ApplyReport {
                applied: plans.len(),
                skipped: 0,
                failed: 0,
                notes: Vec::new(),
            })
        }
        fn channel_availability(&self, _principal: &UserPrincipal) -> ChannelAvailability {
            ChannelAvailability {
                primary: true,
                secondary: true,
            }
        }

        fn teardown(&self) -> Result<(), EnforcementFailure> {
            self.teardowns.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    fn cycle(
        answer: Option<Vec<UserPrincipal>>,
        without_policy: Vec<String>,
        enforcer: Arc<RecordingEnforcer>,
    ) -> PrincipalEnforcementCycle {
        PrincipalEnforcementCycle::new(
            Arc::new(ScriptedPrincipals { answer }),
            Arc::new(PlanEveryone { without_policy }),
            enforcer,
        )
    }

    fn uid(n: u32) -> UserPrincipal {
        UserPrincipal::from_linux_uid(n)
    }

    /// The load-bearing distinction: a failed query is not "nobody". Applying an
    /// empty set here would strip every user's routing because the authority was
    /// unreachable for one tick.
    #[test]
    fn an_unreadable_authority_leaves_the_platform_untouched() {
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(None, Vec::new(), Arc::clone(&enforcer));

        assert!(matches!(
            c.tick(),
            CycleOutcome::AuthorityUnavailable { .. }
        ));
        assert!(
            enforcer.calls().is_empty(),
            "the enforcer must not be called at all when we do not know who is present",
        );
    }

    /// Nobody logged in IS an instruction — the empty set is applied, which is
    /// how the last user's policy comes down when they log out.
    #[test]
    fn nobody_present_applies_an_empty_set() {
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(Some(Vec::new()), Vec::new(), Arc::clone(&enforcer));

        assert!(matches!(c.tick(), CycleOutcome::Applied { .. }));
        assert_eq!(enforcer.calls(), vec![Vec::<String>::new()]);
    }

    /// Both users' plans reach the platform in ONE call. Two calls would let the
    /// second replace the first wherever the mechanism owns a shared object —
    /// which is exactly what an nftables table is.
    #[test]
    fn every_active_principal_is_enforced_in_a_single_pass() {
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(
            Some(vec![uid(1000), uid(1001)]),
            Vec::new(),
            Arc::clone(&enforcer),
        );

        c.tick();
        assert_eq!(
            enforcer.calls(),
            vec![vec!["unix:uid:1000".to_owned(), "unix:uid:1001".to_owned()]],
        );
    }

    /// A user with no stored policy is skipped without taking the others down.
    #[test]
    fn a_principal_without_policy_does_not_stop_the_others() {
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(
            Some(vec![uid(1000), uid(1001)]),
            vec!["unix:uid:1000".to_owned()],
            Arc::clone(&enforcer),
        );

        c.tick();
        assert_eq!(enforcer.calls(), vec![vec!["unix:uid:1001".to_owned()]]);
    }

    /// Change detection drives the log, not the apply: the second tick still
    /// applies, because what a plan resolves to can change while the plan does
    /// not.
    #[test]
    fn an_unchanged_set_is_still_applied_but_reported_as_unchanged() {
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer));

        assert!(matches!(
            c.tick(),
            CycleOutcome::Applied { changed: true, .. }
        ));
        assert!(matches!(
            c.tick(),
            CycleOutcome::Applied { changed: false, .. }
        ));
        assert_eq!(enforcer.calls().len(), 2);
    }

    /// A refused batch must not be remembered as applied, or the next tick would
    /// call it unchanged and quietly stop retrying.
    #[test]
    fn a_refused_batch_is_retried_on_the_next_tick() {
        let enforcer = Arc::new(RecordingEnforcer::new(true));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer));

        assert!(matches!(c.tick(), CycleOutcome::EnforcementFailed { .. }));
        assert!(matches!(c.tick(), CycleOutcome::EnforcementFailed { .. }));
        assert_eq!(enforcer.calls().len(), 2);
    }

    /// Three callers drive this cycle. Two of them planning against different
    /// moments and applying in the wrong order would leave the kernel holding
    /// the older view — the failure that has no symptom until traffic leaks.
    #[test]
    fn passes_never_overlap() {
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = Arc::new(cycle(
            Some(vec![uid(1000)]),
            Vec::new(),
            Arc::clone(&enforcer),
        ));

        let threads: Vec<_> = (0..3)
            .map(|_| {
                let c = Arc::clone(&c);
                std::thread::spawn(move || {
                    for _ in 0..4 {
                        c.tick();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("pass thread panicked");
        }

        assert_eq!(enforcer.overlaps.load(Ordering::Acquire), 0);
        assert_eq!(enforcer.calls().len(), 12);
    }

    /// Teardown removes the policy, and a task released after the stop drain
    /// must not put it back: a stopped service whose filters are still in the
    /// kernel is a machine nobody is maintaining.
    #[test]
    fn teardown_removes_the_policy_and_no_later_pass_reinstates_it() {
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer));

        c.tick();
        c.teardown().expect("teardown");
        assert_eq!(enforcer.teardowns.load(Ordering::Acquire), 1);

        assert!(matches!(c.tick(), CycleOutcome::Stopped));
        assert_eq!(enforcer.calls().len(), 1);
    }
}
