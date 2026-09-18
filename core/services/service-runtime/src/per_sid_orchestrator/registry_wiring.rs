//! Wiring the orchestrator to the active-SID registry, and the
//! `RoutePolicyApplyTrigger` impl that recompiles a SID's filters on a
//! mid-session policy write.

use super::*;

/// Wire `orchestrator` into `registry` so membership changes drive
/// install / remove cycles. The listener is held by an `Arc` inside
/// the registry; `orchestrator` must outlive the registry (production
/// wiring keeps both for the service lifetime).
///
/// Errors are dropped — they cannot propagate through the listener
/// signature. A future version may funnel them into a health-component
/// `Blocking` record.
pub fn wire_orchestrator_to_registry(
    orchestrator: Arc<PerSidApplyOrchestrator>,
    registry: &ActiveSidRegistry,
) {
    let orch = Arc::clone(&orchestrator);
    registry.add_listener(Arc::new(move |snapshot: &[String]| {
        // Errors at this layer are logged via tracing — there's no
        // back-channel to the original `on_connect` caller (which is
        // the IPC accept thread). The audit subsystem surfaces them
        // through `HealthComponent::Apply`.
        if let Err(e) = orch.reconcile(snapshot) {
            tracing::error!(
                target: "nrr::per_sid_orchestrator",
                "reconcile failed: {e:?}",
            );
        }
    }));
}

/// "who is the routing user with no tray connected?"
/// Production wiring answers with the route coordinator's console-session
/// fallback (`effective_routing_sid(&[])`), so the WFP half and the route half
/// agree on the enforced user even when no tray/GUI process is running.
pub type FallbackRoutingSidFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Production [`RoutePolicyApplyTrigger`].
///
/// Fired by `RoutePolicyUpdateHandler` after a successful per-SID policy
/// write. Recompiles the caller's WFP filters ONLY if the SID is currently
/// routing-active: tray-connected (`ActiveSidRegistry::active_sids`) or the
/// effective routing user under the configured fallback (console-session
/// user, service-driven scope). Without the fallback, a policy update
/// pushed from a GUI-only connection while the tray subscription was dead
/// was silently skipped (kill-switch re-enable never recompiled). For any
/// other inactive SID the new policy is
/// picked up when it next becomes routing-active via `reconcile`. Errors are
/// logged, never propagated — the policy is already durably written.
///
/// [`RoutePolicyApplyTrigger`]: crate::ipc_handlers::providers::RoutePolicyApplyTrigger
pub struct OrchestratorRoutePolicyApplyTrigger {
    orchestrator: Arc<PerSidApplyOrchestrator>,
    registry: Arc<ActiveSidRegistry>,
    fallback_routing_sid: Option<FallbackRoutingSidFn>,
    /// "is this SID routing-paused?". A
    /// policy edit (e.g. reset-to-baseline) by a paused user must NOT reinstall
    /// their WFP filters — the other three enforcement paths already subtract
    /// paused SIDs, but this trigger did not, so a paused console user's
    /// fail-closed block could snap back on. Fail-CLOSED to "paused" (skip the
    /// recompile) on a read error, mirroring the reconcile listener.
    paused_check: Option<TriggerPausedCheckFn>,
}

/// predicate: does `sid` have routing paused right now?
pub type TriggerPausedCheckFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

impl OrchestratorRoutePolicyApplyTrigger {
    pub fn new(
        orchestrator: Arc<PerSidApplyOrchestrator>,
        registry: Arc<ActiveSidRegistry>,
    ) -> Self {
        Self {
            orchestrator,
            registry,
            fallback_routing_sid: None,
            paused_check: None,
        }
    }

    /// attach the no-tray routing-user fallback.
    #[must_use]
    pub fn with_fallback_routing_sid(mut self, fallback: FallbackRoutingSidFn) -> Self {
        self.fallback_routing_sid = Some(fallback);
        self
    }

    /// attach the routing-pause predicate so
    /// a policy edit by a paused user does not reinstall their WFP filters.
    #[must_use]
    pub fn with_paused_check(mut self, check: TriggerPausedCheckFn) -> Self {
        self.paused_check = Some(check);
        self
    }
}

impl crate::ipc_handlers::providers::RoutePolicyApplyTrigger
    for OrchestratorRoutePolicyApplyTrigger
{
    fn on_policy_changed(&self, sid: &str) {
        let tray_active = self.registry.active_sids().iter().any(|s| s == sid);
        let console_active = !tray_active
            && self
                .fallback_routing_sid
                .as_ref()
                .and_then(|f| f())
                .as_deref()
                == Some(sid);
        if !tray_active && !console_active {
            // Not routing-active — the new policy applies when the SID next
            // becomes routing-active via the reconcile listener. Installing now
            // would create filters for a user nothing is enforcing for.
            return;
        }
        // a routing-PAUSED SID must not have
        // its filters reinstalled by a policy edit (reset-to-baseline, a rule
        // change). Pause means "no enforcement" — the same invariant the
        // reconcile listener and the recompute hook already honour. Fail-CLOSED
        // to paused on a read error (the predicate wraps that), so a transient
        // DB error can never re-arm a paused user's block-all.
        if self.paused_check.as_ref().is_some_and(|check| check(sid)) {
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                sid,
                "policy changed for a routing-paused SID — not recompiling filters (pause = no enforcement)",
            );
            return;
        }
        match self.orchestrator.recompile_for_sid(sid) {
            Ok(count) => tracing::info!(
                target: "nrr::per_sid_orchestrator",
                filter_count = count,
                "route policy changed: recompiled WFP filters for active SID",
            ),
            Err(e) => tracing::error!(
                target: "nrr::per_sid_orchestrator",
                "route policy recompile failed: {e:?}",
            ),
        }
    }
}
