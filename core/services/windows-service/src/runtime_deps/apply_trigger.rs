//! Builds the `RoutePolicyApplyTrigger` the IPC surface wires a policy
//! mutation to (WFP recompile, plus route recompute when available).

use super::*;

/// Build the `RoutePolicyApplyTrigger` wired to a
/// policy change. The base trigger recompiles the SID's WFP filters; when
/// a route coordinator is present it is wrapped so the same change also
/// recomputes the active user's system route table.
pub(super) fn build_apply_trigger(
    orch: &Arc<PerSidApplyOrchestrator>,
    sid_registry: &Arc<ActiveSidRegistry>,
    route_coordinator: Option<
        &Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
    pause_coordinator: Option<&Arc<nrr_service_runtime::routing_pause::RoutingPauseCoordinator>>,
) -> Arc<dyn nrr_service_runtime::ipc_handlers::providers::RoutePolicyApplyTrigger> {
    let mut orchestrator_trigger =
        OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(orch), Arc::clone(sid_registry));
    // A policy update from a GUI-only connection
    // (dead tray subscription) must still recompile for the console user.
    if let Some(coord) = route_coordinator {
        let coord = Arc::clone(coord);
        orchestrator_trigger = orchestrator_trigger
            .with_fallback_routing_sid(Arc::new(move || coord.effective_routing_sid(&[])));
    }
    // A policy edit by a routing-PAUSED user
    // must not reinstall their filters. Fail-CLOSED to paused on a pause-state
    // read error (skip the recompile) so a transient DB error never re-arms a
    // paused user's block-all.
    if let Some(pause) = pause_coordinator {
        let pause = Arc::clone(pause);
        orchestrator_trigger =
            orchestrator_trigger.with_paused_check(Arc::new(move |sid: &str| {
                match pause.paused_sids() {
                    Ok(paused) => paused.iter().any(|s| s == sid),
                    Err(_) => true,
                }
            }));
    }
    let base: Arc<dyn nrr_service_runtime::ipc_handlers::providers::RoutePolicyApplyTrigger> =
        Arc::new(orchestrator_trigger);
    match route_coordinator {
        Some(coord) => Arc::new(
            nrr_service_runtime::route_coordinator::RouteAndFilterApplyTrigger::new(
                base,
                Arc::clone(coord),
                Arc::clone(sid_registry),
            ),
        ),
        None => base,
    }
}
