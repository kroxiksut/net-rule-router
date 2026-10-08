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
//!
//! ## Except after a refusal that cannot change on its own
//!
//! A refusal the platform calls persistent (a ruleset `nft` rejects, a missing
//! privilege) meets the same plans the same way on every tick. Those plans are
//! not handed over again until they change — new rules or a channel coming or
//! going — or someone asks explicitly ([`PrincipalEnforcementCycle::request_retry`]).
//! The event fixes the cause; a timer only repeats the refusal.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nrr_domain::user_principal::UserPrincipal;
use nrr_platform_api::active_principals::ActivePrincipalSource;
use nrr_platform_api::enforcement::{
    plan_delta, ApplyReport, ChannelAvailability, EnforcementPlan, PolicyEnforcer,
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
        /// What differs from the previous pass, when it changed — the only way
        /// to tell a real change from a plan that flaps between two states.
        delta: Option<String>,
        /// Principals whose plan carries LESS protection than their settings
        /// ask for. Reported every pass, not once: an operator reading a single
        /// line about this run must not take it for full coverage.
        unprotected: Vec<String>,
        /// Destinations the leak-guard is holding across all plans.
        guarded: usize,
        /// What the route pass did, when a route mechanism is wired.
        routes: Option<crate::route_apply::RouteApplyReport>,
    },
    /// Nothing the pass reads has changed since the policy in force was
    /// applied, so neither planning nor the platform was asked.
    Unchanged,
    /// The active set could not be read; the platform was left as it was.
    AuthorityUnavailable { reason: String },
    /// The platform refused the plans. Whatever was installed before is still
    /// installed — the failure is reported, not silently absorbed.
    /// `persistent`: the same plans will not be tried again until they change.
    EnforcementFailed { reason: String, persistent: bool },
    /// These exact plans were refused persistently before, and nothing has
    /// changed since; the platform was not asked again.
    RefusalStands { reason: String },
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
    /// Where a principal is told that the protection their settings ask for is
    /// not fully in force, or is in force because of somebody else's. The log
    /// alone was not enough: nobody reads the service log to find out why their
    /// IPv6 stopped working.
    events: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
    /// The plans installed by the previous pass — and, because the lock is held
    /// for the WHOLE pass, the thing that serialises passes against each other.
    /// Three callers drive this cycle (the timer, an apply from the GUI, a link
    /// change), and two of them planning concurrently would let the slower one
    /// install its older view of the machine last.
    /// Shared so the change can be described after the lock is released.
    last_applied: Mutex<Option<Arc<Vec<EnforcementPlan>>>>,
    /// Mirrors "this pass is holding destinations back" for readers that must
    /// not treat a rule host as covered while it is armed — today the rule
    /// hostname seeder's retry pacing. `None` leaves them on calm pacing.
    fail_closed_posture: Option<crate::app_enforcement_status::FailClosedPostureStatus>,
    /// Plans the platform refused persistently, with its reason. Only touched
    /// under the pass lock.
    refused: Mutex<Option<(Vec<EnforcementPlan>, String)>>,
    /// Set by [`PrincipalEnforcementCycle::request_retry`]; consumed by the next
    /// pass, which then hands refused plans over again.
    retry_requested: AtomicBool,
    /// Latched by [`PrincipalEnforcementCycle::teardown`]; never cleared.
    stopped: AtomicBool,
    /// Epoch seconds the last pass finished, whatever its outcome; starts at
    /// construction so a first pass that never returns still goes stale.
    last_pass_at: AtomicU64,
    /// What lets a pass asked for by a timer or an event be skipped when none of
    /// its inputs moved. `None` = every pass plans and applies.
    inputs: Option<crate::pass_inputs::PassInputs>,
    /// Breaks the connections a pass left on their old path. `None` leaves
    /// them to finish there.
    flow_reset: Option<Arc<crate::plan_flow_reset::PlanFlowReset>>,
    /// Told after each pass that found somebody present. Set once, after
    /// construction: its consumer is built from hooks that drive this cycle.
    presence_listener: std::sync::OnceLock<Arc<dyn Fn() + Send + Sync>>,
    /// Whether the last pass's authority named anybody.
    someone_present: AtomicBool,
}

/// One line counting what changed between two passes, per principal. Counts
/// only: the line has no principal of its own, so every user may read it, and
/// a destination in it would tell one user where another's rules send them.
fn describe_change(old: &[EnforcementPlan], new: &[EnforcementPlan]) -> String {
    // Principals by position, not name: the names are redacted elsewhere on
    // the same line, and free text would carry them past the redaction.
    let mut parts = Vec::new();
    for (n, plan) in new.iter().enumerate() {
        let Some(before) = old.iter().find(|p| p.principal == plan.principal) else {
            parts.push(format!("#{n}: new"));
            continue;
        };
        let flows = plan_delta(before, plan);
        let (routes_added, routes_removed) = route_delta(before, plan);
        parts.push(format!(
            "#{n}: flows +{} -{}{}, routes +{routes_added} -{routes_removed}",
            flows.added.len(),
            flows.removed.len(),
            if flows.reordered { " reordered" } else { "" },
        ));
    }
    let gone = old
        .iter()
        .filter(|plan| !new.iter().any(|p| p.principal == plan.principal))
        .count();
    if gone > 0 {
        parts.push(format!("{gone} gone"));
    }
    parts.join(" | ")
}

/// One example each way per changed principal, at debug and stamped with
/// that principal: the destination is theirs, and the audience scoping and
/// field redaction apply only to a line that says whose it is.
fn log_change_samples(old: &[EnforcementPlan], new: &[EnforcementPlan]) {
    if !tracing::enabled!(target: "nrr::enforcement", tracing::Level::DEBUG) {
        return;
    }
    for plan in new {
        let Some(before) = old.iter().find(|p| p.principal == plan.principal) else {
            continue;
        };
        let flows = plan_delta(before, plan);
        let sample = |f: &nrr_platform_api::enforcement::FlowRule| {
            format!("{:?} {:?} {:?}", f.verdict, f.precedence.class, f.flow.dst)
        };
        let added = flows.added.first().map(|&i| sample(&plan.flows[i]));
        let removed = flows.removed.first().map(|&i| sample(&before.flows[i]));
        if added.is_none() && removed.is_none() {
            continue;
        }
        tracing::debug!(
            target: "nrr::enforcement",
            sid = plan.principal.as_stored(),
            added_address = added.as_deref().unwrap_or("-"),
            removed_address = removed.as_deref().unwrap_or("-"),
            "plan change sample",
        );
    }
}

fn route_delta(old: &EnforcementPlan, new: &EnforcementPlan) -> (usize, usize) {
    use std::collections::HashSet;
    let before: HashSet<_> = old.routes.iter().collect();
    let after: HashSet<_> = new.routes.iter().collect();
    (
        after.difference(&before).count(),
        before.difference(&after).count(),
    )
}

/// Whether this plan asks for something the packet layer will apply to the
/// WHOLE machine.
///
/// The packet layer carries no user context (`FWPM_CONDITION_ALE_USER_ID` exists
/// only on the ALE layers), so a block emitted there is machine-wide no matter
/// whose plan produced it. `AllPackets` coverage on a Block is exactly that
/// shape.
fn plan_cuts_machine_wide(plan: &EnforcementPlan) -> bool {
    use nrr_platform_api::enforcement::{Coverage, Verdict};
    plan.flows
        .iter()
        .any(|f| f.verdict == Verdict::Block && f.coverage == Coverage::AllPackets)
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
            events: None,
            fail_closed_posture: None,
            last_applied: Mutex::new(None),
            refused: Mutex::new(None),
            retry_requested: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            last_pass_at: AtomicU64::new(epoch_secs()),
            inputs: None,
            flow_reset: None,
            presence_listener: std::sync::OnceLock::new(),
            someone_present: AtomicBool::new(false),
        }
    }

    /// Call `listener` after every pass that finds somebody present, with the
    /// pass lock released: the presence poll for a consumer no sign-in event
    /// reaches. A second listener is ignored.
    pub fn set_presence_listener(&self, listener: Arc<dyn Fn() + Send + Sync>) {
        let _ = self.presence_listener.set(listener);
    }

    /// Tear down, after each pass that changes what a destination's traffic
    /// does, the plan owner's connections that predate the change: a socket
    /// keeps the path it was opened on.
    #[must_use]
    pub fn with_flow_reset(mut self, reset: Arc<crate::plan_flow_reset::PlanFlowReset>) -> Self {
        self.flow_reset = Some(reset);
        self
    }

    /// Let passes asked for by a timer or an event skip when `inputs` say nothing
    /// changed. An apply the user asked for never skips.
    #[must_use]
    pub fn with_pass_inputs(mut self, inputs: crate::pass_inputs::PassInputs) -> Self {
        self.inputs = Some(inputs);
        self
    }

    /// Attach the push bus so coverage notices reach the principals they
    /// concern.
    #[must_use]
    pub fn with_events(mut self, events: Arc<crate::ipc_handlers::event_bus::EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// Publish "the guard is holding destinations back" so the rule-hostname
    /// seeder can tighten its retry pacing: while the guard blocks, a rule host
    /// with no cached address has nothing protecting it at all.
    #[must_use]
    pub fn with_fail_closed_posture_status(
        mut self,
        status: crate::app_enforcement_status::FailClosedPostureStatus,
    ) -> Self {
        self.fail_closed_posture = Some(status);
        self
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
        self.pass(false)
    }

    fn pass(&self, skip_if_unchanged: bool) -> CycleOutcome {
        let outcome = self.run_pass(skip_if_unchanged);
        self.last_pass_at.store(epoch_secs(), Ordering::Relaxed);
        if self.someone_present.load(Ordering::Acquire) {
            if let Some(listener) = self.presence_listener.get() {
                listener();
            }
        }
        outcome
    }

    /// Let the next pass hand over plans refused before — for an explicit
    /// request (an apply from the GUI), which may follow a fix the plans do not
    /// show, or somebody else removing what was installed.
    pub fn request_retry(&self) {
        self.retry_requested.store(true, Ordering::Release);
        self.enforcer.distrust_installed();
    }

    /// When the last pass finished, in epoch seconds — a watchdog's evidence
    /// that enforcement is not wedged (a hung `nft` holds the pass lock).
    pub fn last_pass_epoch_secs(&self) -> u64 {
        self.last_pass_at.load(Ordering::Relaxed)
    }

    fn run_pass(&self, skip_if_unchanged: bool) -> CycleOutcome {
        let mut last = self.last_applied.lock().unwrap_or_else(|p| p.into_inner());
        // The cycle's own stop flag is set by `teardown`, which runs after the
        // tasks are drained; the process-wide latch flips the moment the stop
        // is requested. Policy applied between the two outlives the daemon.
        if self.stopped.load(Ordering::Acquire) || crate::teardown_in_progress() {
            return CycleOutcome::Stopped;
        }
        let mut timings = crate::phase_timings::PhaseTimings::start();
        let active = match self.principals.active_principals() {
            Ok(active) => active,
            Err(e) => {
                self.someone_present.store(false, Ordering::Release);
                return CycleOutcome::AuthorityUnavailable {
                    reason: e.to_string(),
                };
            }
        };

        self.someone_present
            .store(!active.is_empty(), Ordering::Release);
        let availability: Vec<ChannelAvailability> = active
            .iter()
            .map(|principal| self.enforcer.channel_availability(principal))
            .collect();
        let fingerprint = self
            .inputs
            .as_ref()
            .and_then(|inputs| inputs.fingerprint(&(&active, &availability)));
        timings.mark("authority");
        if skip_if_unchanged && !self.retry_requested.load(Ordering::Acquire) {
            if let (Some(inputs), Some(fp)) = (self.inputs.as_ref(), fingerprint) {
                if inputs.is_settled(fp) {
                    return CycleOutcome::Unchanged;
                }
            }
        }
        self.plans.begin_pass();
        let mut plans: Vec<EnforcementPlan> = Vec::new();
        let mut unprotected: Vec<String> = Vec::new();
        let mut wants_machine_wide_cut: std::collections::BTreeMap<String, bool> =
            std::collections::BTreeMap::new();
        let mut guarded = 0usize;
        for (principal, availability) in active.iter().zip(availability.iter().copied()) {
            let Some(planned) = self.plans.plan_for(principal, availability) else {
                continue;
            };
            if !planned.protection_complete {
                unprotected.push(principal.as_stored().to_owned());
            }
            // What each principal's own plan asks of the packet layer. Used
            // below to find the ones who are about to lose ICMP and IPv6
            // because somebody ELSE asked for it.
            wants_machine_wide_cut.insert(
                principal.as_stored().to_owned(),
                plan_cuts_machine_wide(&planned.plan),
            );
            guarded += planned.fail_closed_blocks;
            plans.push(planned.plan);
        }

        let changed = last.as_deref().map(Vec::as_slice) != Some(plans.as_slice());
        timings.mark("plan");

        // Planning above is not instant, and a stop can land inside it.
        if crate::teardown_in_progress() {
            return CycleOutcome::Stopped;
        }
        let mut refused = self.refused.lock().unwrap_or_else(|p| p.into_inner());
        let retry_requested = self.retry_requested.swap(false, Ordering::AcqRel);
        if let Some((refused_plans, reason)) = refused.as_ref() {
            if !retry_requested && *refused_plans == plans {
                return CycleOutcome::RefusalStands {
                    reason: reason.clone(),
                };
            }
        }
        let result = self.enforcer.enforce(&plans);
        timings.mark("filters");
        *refused = match &result {
            Err(e) if e.is_persistent() => Some((plans.clone(), e.to_string())),
            _ => None,
        };
        drop(refused);
        // The plans this pass replaced and installed, when they differ; the
        // change is described once the pass lock is released.
        let mut replaced = None;
        let mut outcome = match result {
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
                timings.mark("routes");
                let routes_failed = routes.as_ref().is_some_and(|r| r.failure.is_some());

                if let Some(flow_reset) = self.flow_reset.as_ref() {
                    if routes_failed {
                        flow_reset.defer();
                    } else {
                        flow_reset.after_apply(
                            &plans,
                            changed,
                            |principal| {
                                active
                                    .iter()
                                    .zip(&availability)
                                    .any(|(p, a)| p == principal && a.secondary)
                            },
                            |principal| self.enforcer.flow_links(principal),
                        );
                    }
                    timings.mark("flow-reset");
                }

                if changed {
                    self.notify_coverage(&unprotected, &wants_machine_wide_cut);
                }
                if let Some(posture) = self.fail_closed_posture.as_ref() {
                    posture.set(guarded > 0);
                }
                let installed = Arc::new(plans);
                if let Some(previous) = last.replace(Arc::clone(&installed)) {
                    if changed {
                        replaced = Some((previous, installed));
                    }
                }
                // A failed route apply usually leaves the table as it was, so
                // nothing in the inputs would move to bring the retry back.
                if let Some(inputs) = self.inputs.as_ref() {
                    match fingerprint {
                        Some(fp) if !routes_failed => inputs.settle(fp),
                        _ => inputs.unsettle(),
                    }
                }
                CycleOutcome::Applied {
                    principals,
                    report,
                    changed,
                    delta: None,
                    unprotected,
                    guarded,
                    routes,
                }
            }
            // Deliberately NOT recorded as applied: the kernel does not hold
            // what it refused, whether or not the next tick tries again.
            Err(e) => {
                if let Some(inputs) = self.inputs.as_ref() {
                    inputs.unsettle();
                }
                CycleOutcome::EnforcementFailed {
                    persistent: e.is_persistent(),
                    reason: e.reason,
                }
            }
        };
        drop(last);
        if let Some((previous, installed)) = replaced {
            if let CycleOutcome::Applied { delta, .. } = &mut outcome {
                *delta = Some(describe_change(&previous, &installed));
            }
            log_change_samples(&previous, &installed);
        }
        crate::phase_timings::report_if_slow(
            &timings,
            "principal-enforcement",
            crate::phase_timings::slow_threshold_for(
                crate::service_tasks::PRINCIPAL_ENFORCEMENT_INTERVAL,
            ),
        );
        outcome
    }

    /// Run one pass and report it. `trigger` names what asked for the pass —
    /// the timer, a link change, an apply from the GUI — because the same
    /// outcome means different things depending on what provoked it.
    pub fn tick_logged(&self, trigger: &'static str) -> CycleOutcome {
        let outcome = self.tick();
        log_outcome(&outcome, trigger, self.authority());
        outcome
    }

    /// [`Self::tick_logged`] for a timer or an event that may have changed
    /// nothing: the pass is skipped when its inputs are the ones last applied.
    pub fn tick_if_changed_logged(&self, trigger: &'static str) -> CycleOutcome {
        let outcome = self.pass(true);
        log_outcome(&outcome, trigger, self.authority());
        outcome
    }

    /// Tell the principals who need to know, and only them.
    ///
    /// Published on a CHANGE, never on the identical re-apply that follows every
    /// ten seconds: a notice repeated forever is one the user learns to dismiss
    /// without reading.
    fn notify_coverage(
        &self,
        unprotected: &[String],
        wants_machine_wide_cut: &std::collections::BTreeMap<String, bool>,
    ) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        for sid in unprotected {
            bus.publish_for(
                sid.clone(),
                nrr_shared::ipc_payloads::StatusUpdateEvent::ProtectionCoverageChanged {
                    reason: "blanket-block-not-armed".to_string(),
                },
            );
        }
        // Somebody armed a cut the packet layer cannot scope. Everyone else
        // active loses ICMP and IPv6 without having asked for it, so they are
        // told - the alternative was that their network changed silently.
        let anybody_cuts = wants_machine_wide_cut.values().any(|v| *v);
        if !anybody_cuts {
            return;
        }
        for (sid, wants) in wants_machine_wide_cut {
            if !*wants {
                bus.publish_for(
                    sid.clone(),
                    nrr_shared::ipc_payloads::StatusUpdateEvent::ProtectionCoverageChanged {
                        reason: "machine-wide-cut-by-another-user".to_string(),
                    },
                );
            }
        }
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

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Report one pass. Shared by every caller so a pass provoked by a link change
/// reads the same as the timer's, differing only in `trigger`.
pub fn log_outcome(outcome: &CycleOutcome, trigger: &'static str, authority: &'static str) {
    match outcome {
        CycleOutcome::Applied {
            principals,
            report,
            changed,
            delta,
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
                        msg_key = "principal-routes-apply-failed",
                        trigger,
                        reason = %failure,
                        "routes could NOT be applied: traffic is filtered but not steered",
                    );
                }
                if !routes.unresolved.is_empty() {
                    tracing::warn!(
                        target: "nrr::routes",
                        msg_key = "principal-routes-unresolved-no-link",
                        trigger,
                        principals = ?routes.unresolved,
                        "no live secondary link to steer through; their routes were not installed",
                    );
                }
                if routes.added > 0 || routes.removed > 0 {
                    tracing::info!(
                        target: "nrr::routes",
                        msg_key = "system-routes-reconciled",
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
                    msg_key = "principal-blanket-block-not-armed",
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
                    tracing::warn!(target: "nrr::enforcement", msg_key = "principal-rule-not-enforced-as-written", trigger, note = %note, "rule not enforced as written");
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
                    msg_key = "policy-applied",
                    trigger,
                    principals = ?principals,
                    principal_count = principals.len(),
                    applied = report.applied,
                    skipped = report.skipped,
                    guarded,
                    change = delta.as_deref().unwrap_or("first pass"),
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
        CycleOutcome::Unchanged => tracing::trace!(
            target: "nrr::enforcement",
            trigger,
            "policy inputs unchanged; pass skipped",
        ),
        CycleOutcome::AuthorityUnavailable { reason } => tracing::warn!(
            target: "nrr::enforcement",
            msg_key = "principal-authority-unavailable",
            trigger,
            authority,
            reason = %reason,
            "could not determine who is logged in; policy left exactly as it was (this is NOT the same as nobody being present)",
        ),
        CycleOutcome::EnforcementFailed { reason, persistent } => tracing::error!(
            target: "nrr::enforcement",
            msg_key = "principal-enforcement-failed",
            trigger,
            reason = %reason,
            persistent,
            "policy could NOT be applied — the rules on file are not in effect",
        ),
        // Already logged at error when it was refused; once per tick is noise.
        CycleOutcome::RefusalStands { reason } => tracing::debug!(
            target: "nrr::enforcement",
            trigger,
            reason = %reason,
            "the same plans were refused before; waiting for a change to try again",
        ),
        CycleOutcome::Stopped => tracing::info!(
            target: "nrr::enforcement",
            msg_key = "principal-policy-removed-on-stop",
            trigger,
            "policy was removed on stop; this pass installed nothing",
        ),
    }
}

#[cfg(test)]
mod tests {

    /// The packet layer carries no user context, so a cut one principal asks
    /// for lands on everyone. Before this the others just lost ICMP and IPv6
    /// with nothing to explain it.
    #[test]
    fn a_machine_wide_cut_is_announced_to_the_principals_who_did_not_ask_for_it() {
        use nrr_platform_api::enforcement::{Coverage, Verdict};
        use nrr_shared::ipc_payloads::StatusUpdateEvent;

        let bus = std::sync::Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let asked = bus.subscribe_as("gui-a".into(), Some("S-1-A".into()), Some(0));
        let bystander = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), Some(0));

        let mut wants = std::collections::BTreeMap::new();
        wants.insert("S-1-A".to_string(), true);
        wants.insert("S-1-B".to_string(), false);

        let cycle = PrincipalEnforcementCycle::new(
            std::sync::Arc::new(ScriptedPrincipals {
                answer: Some(Vec::new()),
            }),
            std::sync::Arc::new(PlanEveryone {
                without_policy: Vec::new(),
            }),
            std::sync::Arc::new(RecordingEnforcer::new(false)),
        )
        .with_events(std::sync::Arc::clone(&bus));
        cycle.notify_coverage(&[], &wants);

        let for_asker = bus.peek_pending_for(&asked.subscription_id, 8);
        assert!(
            for_asker.is_empty(),
            "the principal who asked for the cut needs no notice",
        );
        let for_bystander = bus.peek_pending_for(&bystander.subscription_id, 8);
        assert!(
            for_bystander.iter().any(|e| matches!(
                &e.event,
                StatusUpdateEvent::ProtectionCoverageChanged { reason }
                    if reason == "machine-wide-cut-by-another-user"
            )),
            "the bystander must be told why their IPv6 stopped: {for_bystander:?}",
        );

        // A plan that blocks only at the connect layer is per-principal and
        // announces nothing.
        let ale_only = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid("S-1-A")
                .expect("sid"),
            flows: vec![nrr_platform_api::enforcement::FlowRule {
                verdict: Verdict::Block,
                precedence: nrr_platform_api::enforcement::Precedence {
                    class: nrr_platform_api::enforcement::PrecedenceClass::CatchAllBlock,
                    ordinal: 0,
                },
                flow: nrr_platform_api::enforcement::FlowMatch {
                    dst: nrr_platform_api::enforcement::DstMatch::Any,
                    dst_port: None,
                    protocol: None,
                },
                principal: nrr_platform_api::enforcement::PrincipalScope(None),
                app: nrr_platform_api::enforcement::AppScope::Any,
                egress: nrr_platform_api::enforcement::EgressConstraint::Any,
                coverage: Coverage::ConnectOnly,
            }],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        assert!(!plan_cuts_machine_wide(&ale_only));
    }
    use super::*;
    use nrr_platform_api::active_principals::ActivePrincipalError;

    /// The watchdog reads this; a failed pass still proves the loop turns.
    #[test]
    fn every_finished_pass_refreshes_the_heartbeat() {
        let cycle = PrincipalEnforcementCycle::new(
            std::sync::Arc::new(ScriptedPrincipals { answer: None }),
            std::sync::Arc::new(PlanEveryone {
                without_policy: Vec::new(),
            }),
            std::sync::Arc::new(RecordingEnforcer::new(false)),
        );
        assert!(
            cycle.last_pass_epoch_secs() > 0,
            "construction starts the clock"
        );
        cycle.last_pass_at.store(0, Ordering::Relaxed);
        assert!(matches!(
            cycle.tick(),
            CycleOutcome::AuthorityUnavailable { .. }
        ));
        assert!(cycle.last_pass_epoch_secs() > 0);
    }
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
        /// `Some` = every call is refused this way.
        fail: Mutex<Option<EnforcementFailure>>,
        /// How many passes are inside `enforce` right now, and how often that
        /// was more than one.
        inside: AtomicUsize,
        overlaps: AtomicUsize,
        teardowns: AtomicUsize,
        distrusts: AtomicUsize,
    }
    impl RecordingEnforcer {
        fn new(fail: bool) -> Self {
            Self::refusing(fail.then(|| EnforcementFailure::transient("nft hung")))
        }
        fn refusing(fail: Option<EnforcementFailure>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail: Mutex::new(fail),
                inside: AtomicUsize::new(0),
                overlaps: AtomicUsize::new(0),
                teardowns: AtomicUsize::new(0),
                distrusts: AtomicUsize::new(0),
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
            if let Some(failure) = self.fail.lock().unwrap_or_else(|p| p.into_inner()).clone() {
                return Err(failure);
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

        fn distrust_installed(&self) {
            self.distrusts.fetch_add(1, Ordering::AcqRel);
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

    /// An idle pass costs nothing once its inputs say nothing moved — but only
    /// a pass that may skip skips: the forced one (an apply the user asked for)
    /// always reaches the platform, and a moved input brings the pass back.
    #[test]
    fn a_pass_whose_inputs_did_not_move_is_skipped_unless_forced() {
        use std::sync::atomic::AtomicU64;
        let generation = Arc::new(AtomicU64::new(0));
        let source = Arc::clone(&generation);
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer)).with_pass_inputs(
            crate::pass_inputs::PassInputs::new().with_source(
                "test",
                Arc::new(move || Some(source.load(Ordering::Relaxed))),
            ),
        );

        assert!(matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::Applied { .. }
        ));
        assert!(matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::Unchanged
        ));
        assert_eq!(
            enforcer.calls().len(),
            1,
            "a skipped pass reached the platform"
        );

        assert!(
            matches!(c.tick(), CycleOutcome::Applied { .. }),
            "a forced pass skipped"
        );
        assert_eq!(enforcer.calls().len(), 2);

        generation.store(1, Ordering::Relaxed);
        assert!(matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::Applied { .. }
        ));
        assert_eq!(enforcer.calls().len(), 3);
    }

    /// Filters landing while the routes fail is not a settled pass: a failed
    /// route apply usually leaves the table as it was, so no input moves to
    /// bring the retry back before the periodic full pass.
    #[test]
    fn a_pass_whose_routes_failed_is_not_remembered_as_settled() {
        use nrr_platform_api::adapters::{AdapterEventSource, AdapterInfo};
        use nrr_platform_api::enforcement::{EgressBinding, EgressBindingSource};
        use nrr_platform_api::error::PlatformError;
        use std::sync::atomic::AtomicBool;

        struct Adapters(Arc<AtomicBool>);
        impl AdapterEventSource for Adapters {
            fn enumerate_all(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
                if self.0.load(Ordering::Acquire) {
                    Err(PlatformError::Transient {
                        operation: "enumerate",
                        detail: "busy".into(),
                    })
                } else {
                    Ok(Vec::new())
                }
            }
        }
        struct Unbound;
        impl EgressBindingSource for Unbound {
            fn bindings_for(&self, _: &UserPrincipal) -> EgressBinding {
                EgressBinding {
                    primary: None,
                    secondary: None,
                }
            }
        }

        let failing = Arc::new(AtomicBool::new(true));
        let enforcer = Arc::new(RecordingEnforcer::new(false));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer))
            .with_routes(Arc::new(crate::route_apply::PlannedRouteApplier::new(
                Arc::new(nrr_platform_api::MockWindowsApi::new()),
                Arc::new(Adapters(Arc::clone(&failing))),
                Arc::new(Unbound),
            )))
            .with_pass_inputs(
                crate::pass_inputs::PassInputs::new().with_source("test", Arc::new(|| Some(7))),
            );

        assert!(matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::Applied { routes: Some(ref r), .. } if r.failure.is_some()
        ));
        assert!(
            !matches!(c.tick_if_changed_logged("timer"), CycleOutcome::Unchanged),
            "the route retry waited for the periodic full pass",
        );

        failing.store(false, Ordering::Release);
        assert!(matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::Applied { routes: Some(ref r), .. } if r.failure.is_none()
        ));
        assert!(matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::Unchanged
        ));
    }

    /// The change line has no principal, so every user may read it: it counts
    /// what changed and never names where anybody's traffic goes.
    #[test]
    fn the_change_line_counts_and_names_no_destination() {
        use nrr_platform_api::enforcement::{
            AppScope, Coverage, DstMatch, EgressConstraint, EgressRef, FlowMatch, FlowRule,
            Precedence, PrecedenceClass, PrincipalScope, RouteIntent, RouteTableRef, Verdict,
        };
        let host = |last: u8| FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::RouteRule(nrr_shared::RouteRole::Secondary),
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(std::net::Ipv4Addr::new(203, 0, 113, last)),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(None),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        };
        let route = |last: u8| RouteIntent {
            dst: DstMatch::HostV4(std::net::Ipv4Addr::new(203, 0, 113, last)),
            egress: EgressRef::Secondary,
            metric: 1,
            table: RouteTableRef::Main,
        };
        let plan = |flows: Vec<FlowRule>, routes: Vec<RouteIntent>| EnforcementPlan {
            principal: uid(1000),
            flows,
            routes,
            policy_rules: Vec::new(),
        };
        let old = vec![plan(vec![host(1), host(2)], vec![route(1)])];
        let new = vec![plan(vec![host(2), host(3), host(4)], vec![route(3)])];

        let line = describe_change(&old, &new);
        assert_eq!(line, "#0: flows +2 -1, routes +1 -1");
        assert!(!line.contains("203.0.113"), "{line}");
    }

    /// The presence poll a consumer without a sign-in event relies on: told
    /// after a pass that finds somebody, never after one that finds nobody.
    #[test]
    fn the_presence_listener_hears_only_passes_that_find_somebody() {
        let heard = Arc::new(AtomicUsize::new(0));
        let listener = {
            let heard = Arc::clone(&heard);
            Arc::new(move || {
                heard.fetch_add(1, Ordering::AcqRel);
            })
        };
        let nobody = cycle(
            Some(Vec::new()),
            Vec::new(),
            Arc::new(RecordingEnforcer::new(false)),
        );
        nobody.set_presence_listener(listener.clone());
        nobody.tick();
        assert_eq!(heard.load(Ordering::Acquire), 0);

        let somebody = cycle(
            Some(vec![uid(1000)]),
            Vec::new(),
            Arc::new(RecordingEnforcer::new(false)),
        );
        somebody.set_presence_listener(listener);
        somebody.tick();
        assert_eq!(heard.load(Ordering::Acquire), 1);
    }

    /// A refused pass leaves nothing settled: the next one must try again
    /// rather than call the refused state applied.
    #[test]
    fn a_refused_pass_is_not_remembered_as_settled() {
        let enforcer = Arc::new(RecordingEnforcer::new(true));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer)).with_pass_inputs(
            crate::pass_inputs::PassInputs::new().with_source("test", Arc::new(|| Some(7))),
        );
        assert!(matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::EnforcementFailed { .. }
        ));
        assert!(!matches!(
            c.tick_if_changed_logged("timer"),
            CycleOutcome::Unchanged
        ));
    }

    /// A transient failure must not be remembered as applied, or the next tick
    /// would call it unchanged and quietly stop retrying.
    #[test]
    fn a_transient_failure_is_retried_on_the_next_tick() {
        let enforcer = Arc::new(RecordingEnforcer::new(true));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer));

        for _ in 0..2 {
            assert!(matches!(
                c.tick(),
                CycleOutcome::EnforcementFailed {
                    persistent: false,
                    ..
                }
            ));
        }
        assert_eq!(enforcer.calls().len(), 2);
    }

    /// Handing the same plans to a platform that refused them for good only
    /// spawns the same refusal every tick.
    #[test]
    fn a_persistent_refusal_waits_for_the_plans_to_change() {
        let enforcer = Arc::new(RecordingEnforcer::refusing(Some(
            EnforcementFailure::persistent("nft refused the ruleset"),
        )));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer));

        assert!(matches!(
            c.tick(),
            CycleOutcome::EnforcementFailed {
                persistent: true,
                ..
            }
        ));
        assert!(matches!(
            c.tick(),
            CycleOutcome::RefusalStands { reason } if reason == "nft refused the ruleset"
        ));
        assert_eq!(enforcer.calls().len(), 1);

        // A second user arriving changes the plans: that is worth an attempt.
        let c2 = PrincipalEnforcementCycle {
            principals: Arc::new(ScriptedPrincipals {
                answer: Some(vec![uid(1000), uid(1001)]),
            }),
            ..c
        };
        assert!(matches!(c2.tick(), CycleOutcome::EnforcementFailed { .. }));
        assert_eq!(enforcer.calls().len(), 2);
    }

    /// An explicit apply may follow a fix the plans cannot show (a package
    /// installed, a privilege granted); a success clears the refusal.
    #[test]
    fn a_requested_retry_hands_refused_plans_over_again() {
        let enforcer = Arc::new(RecordingEnforcer::refusing(Some(
            EnforcementFailure::persistent("not permitted"),
        )));
        let c = cycle(Some(vec![uid(1000)]), Vec::new(), Arc::clone(&enforcer));
        c.tick();
        assert!(matches!(c.tick(), CycleOutcome::RefusalStands { .. }));

        *enforcer.fail.lock().unwrap_or_else(|p| p.into_inner()) = None;
        assert_eq!(enforcer.distrusts.load(Ordering::Acquire), 0);
        c.request_retry();
        // The platform must re-check what it installed, not trust a cache.
        assert_eq!(enforcer.distrusts.load(Ordering::Acquire), 1);
        assert!(matches!(c.tick(), CycleOutcome::Applied { .. }));
        assert!(matches!(c.tick(), CycleOutcome::Applied { .. }));
        assert_eq!(enforcer.calls().len(), 3);
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

    /// A pass that puts a destination under a rule breaks the owner's
    /// connections to it; the identical re-apply that follows reads nothing.
    #[test]
    fn a_pass_that_steers_a_new_destination_tears_down_its_connections() {
        use nrr_platform_api::enforcement::{
            AppScope, Coverage, DstMatch, EgressConstraint, FlowMatch, FlowRule, Precedence,
            PrecedenceClass, PrincipalScope, Verdict,
        };
        use nrr_platform_api::fake_ip::stale_flows::{
            EstablishedFlow, MockStaleFlowReset, StaleFlowReset,
        };

        struct PlanOneHost;
        impl PrincipalPlanSource for PlanOneHost {
            fn plan_for(
                &self,
                principal: &UserPrincipal,
                _availability: ChannelAvailability,
            ) -> Option<PlannedPolicy> {
                let host = std::net::Ipv4Addr::new(203, 0, 113, 5);
                Some(PlannedPolicy {
                    plan: EnforcementPlan {
                        principal: principal.clone(),
                        flows: vec![FlowRule {
                            verdict: Verdict::Permit,
                            precedence: Precedence {
                                class: PrecedenceClass::RouteRule(nrr_shared::RouteRole::Secondary),
                                ordinal: 0,
                            },
                            flow: FlowMatch {
                                dst: DstMatch::HostV4(host),
                                dst_port: None,
                                protocol: None,
                            },
                            principal: PrincipalScope(Some(principal.clone())),
                            app: AppScope::Any,
                            egress: EgressConstraint::Any,
                            coverage: Coverage::ConnectOnly,
                        }],
                        routes: Vec::new(),
                        policy_rules: Vec::new(),
                    },
                    protection_complete: true,
                    fail_closed_blocks: 0,
                })
            }
        }

        let mock = Arc::new(MockStaleFlowReset::new());
        let mine = EstablishedFlow {
            local: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 1), 50_000),
            remote: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(203, 0, 113, 5), 443),
            owner: Some(uid(1000).as_stored().to_owned()),
            pid: None,
            image: None,
        };
        mock.set_flows(vec![mine.clone()]);
        let c = PrincipalEnforcementCycle::new(
            Arc::new(ScriptedPrincipals {
                answer: Some(vec![uid(1000)]),
            }),
            Arc::new(PlanOneHost),
            Arc::new(RecordingEnforcer::new(false)),
        )
        .with_flow_reset(Arc::new(crate::plan_flow_reset::PlanFlowReset::new(
            Arc::clone(&mock) as Arc<dyn StaleFlowReset>,
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new()),
        )));

        assert!(matches!(c.tick(), CycleOutcome::Applied { .. }));
        assert_eq!(mock.reset_flows(), vec![mine]);
        let read = mock.queried().len();
        c.tick();
        assert_eq!(mock.queried().len(), read);
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
