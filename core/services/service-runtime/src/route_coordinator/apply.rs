//! Applying the plan: reconcile, tear down, adopt what a previous run left.
//!
//! Adoption is signature-based, so it works with no per-principal state at
//! all — which is what makes a crash recoverable on the next start.

use super::*;

impl SecondaryRouteCoordinator {
    /// Recompute and apply the system route table from `sid`'s effective rule
    /// book and resolved routing inputs (own revision, or baseline via the
    /// provider's read-through) — the table serving `sid` alone.
    ///
    /// `resolution.secondary == None` means the user has no usable secondary
    /// right now — every owned route is torn down so traffic falls back to the
    /// OS default routing (fail-closed blocking, when configured, is the WFP
    /// layer's job, not ours). The behavior mode decides the shape: mode A
    /// pulls secondary-bound rules into the tunnel as `/32`; mode B owns a
    /// split-default overlay via the secondary and carves primary-bound rules
    /// back onto the primary NIC.
    pub fn recompute_for(
        &self,
        sid: &str,
        resolution: &RouteResolution,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let plan = self.plan_user_routes(sid, resolution, None);
        match resolution.secondary {
            // The tunnel's own interior, refreshed while we already hold the
            // enumeration: the fake-IP answerer must never substitute an
            // address inside it.
            Some(_) => self.publish_secondary_subnets(sid),
            // The tunnel is gone, so its interior is nobody's subnet any more.
            None => crate::secondary_subnets::global_secondary_subnets().publish(Vec::new()),
        }
        self.publish_served_alone(sid, &plan);
        let (Some(secondary), true) = (plan.secondary, plan.planned) else {
            return self.reconciler.clear();
        };
        let out_routes = plan.routes;
        // Route-shape breakdown so the log alone answers "is mode-A selectivity
        // actually in place?" without Get-NetRoute: the counter-overlay
        // (unmatched → primary) only exists when a primary target resolved; a
        // `counter_overlay=0` + `primary=false` in PreferPrimary is the
        // smoking gun for "unmatched traffic is still riding the secondary".
        // Told apart by signature, not length: a rule network can be `/9`.
        let overlay_shapes: Vec<_> = out_routes
            .iter()
            .filter(|r| {
                crate::route_codegen::is_overlay_route(r)
                    && r.interface_index != secondary.interface_index
            })
            .map(|r| (r.destination, r.prefix_length))
            .collect();
        let counter_overlay = overlay_shapes.len();
        let secondary_routes = out_routes
            .iter()
            .filter(|r| r.prefix_length == 32 && r.interface_index == secondary.interface_index)
            .count();
        let network_routes = out_routes
            .iter()
            .filter(|r| r.metric == crate::route_codegen::NETWORK_ROUTE_METRIC)
            .count();
        let primary_present = resolution.primary.is_some();
        let delta = self.reconciler.reconcile(&out_routes)?;
        // ADD-ONLY, settled on hardware: we never remove the VPN's own
        // routes. Stripping its redirect `/1` pair made the client treat the
        // removal as a fault and reconnect, and in mode A it dropped
        // not-yet-resolved hosts (DoH-only names with no `/32`) to the primary
        // with the real IP. Mode-A selectivity rides a counter-overlay via the
        // primary instead — one bit longer than the VPN's catch-all, nothing
        // removed.
        if delta.is_noop() {
            // Steady state (no change this cycle) — debug, to keep the log
            // quiet once routing has converged.
            tracing::debug!(
                target: "nrr::route-coordinator",
                msg_key = "route-table-unchanged",
                sid = %sid,
                secondary_ifindex = secondary.interface_index,
                desired_routes = out_routes.len(),
                "route table reconciled (no change)",
            );
        } else {
            tracing::info!(
                target: "nrr::route-coordinator",
                msg_key = "route-table-reconciled",
                sid = %sid,
                mode = ?resolution.mode,
                primary = primary_present,
                secondary_ifindex = secondary.interface_index,
                desired_routes = out_routes.len(),
                secondary_routes,
                counter_overlay,
                network_routes,
                added = delta.added,
                removed = delta.removed,
                "route table reconciled",
            );
        }
        // Counter-overlay liveness audit (mode A): report every live route of
        // a shape the codegen planned as an overlay. Its length follows the
        // tunnel's catch-all (`/0` ⇒ `/1`, `/1` ⇒ `/2`), so a fixed length
        // would cry "missing" over halves that are in force. One on the VPN
        // ifindex, or none at all, means unmatched traffic still rides the
        // tunnel. Only on a real change, to avoid per-cycle cost.
        if !delta.is_noop() && matches!(resolution.mode, RouteBehaviorMode::PreferPrimary) {
            if let Ok(live) = self.api.get_ip_forward_table() {
                let mut any = false;
                for r in live
                    .iter()
                    .filter(|r| overlay_shapes.contains(&(r.destination, r.prefix_length)))
                {
                    any = true;
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        msg_key = "route-counter-overlay-live",
                        sid = %sid,
                        destination = %r.destination,
                        ifindex = r.interface_index,
                        next_hop = %r.next_hop,
                        metric = r.metric,
                        on_secondary = (r.interface_index == secondary.interface_index),
                        "live counter-overlay route",
                    );
                }
                if !any {
                    tracing::warn!(
                        target: "nrr::route-coordinator",
                        msg_key = "route-counter-overlay-missing",
                        sid = %sid,
                        "no counter-overlay route in the live table — mode-A selectivity is NOT in force; unmatched traffic will ride the VPN's redirect",
                    );
                }
            }
        }
        Ok(delta)
    }

    /// Tear down every owned route — no active user, or service stopping.
    pub fn clear(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.clear()
    }

    /// Seed the reconciler's owned set for startup orphan adoption (routes
    /// already in the OS table from a previous run). The next
    /// `recompute_for` deletes the ones the active user no longer wants.
    pub fn adopt_owned(&self, routes: Vec<RouteEntry>) {
        self.reconciler.adopt_owned(routes);
    }

    /// startup orphan cleanup. A crash or hard kill (NOT a
    /// graceful stop — that path runs the teardown hook) can leave our routes
    /// in the OS table with no in-memory owner. Enumerate the live table, adopt
    /// every route matching our signature, and stamp them owned so the first
    /// `recompute_active` reconciles them — keeping the ones the active user
    /// still wants and deleting the rest.
    ///
    /// Our signature is the uncommon [`crate::route_codegen::SECONDARY_ROUTE_METRIC`] on a shape the
    /// codegen emits: host routes AND the overlay halves, whose length follows
    /// the tunnel's catch-alls. An unadopted counter-overlay half would strand
    /// non-rule traffic on the primary after the service that wanted it is gone.
    ///
    /// The signature is a heuristic (the OS never tags routes as ours); a
    /// third-party route at the same metric would be adopted and then deleted
    /// if not re-desired. The metric is deliberately uncommon to make that
    /// vanishingly unlikely. Enumeration failure is non-fatal: we log and adopt
    /// nothing (the next reconcile still installs the desired set; a stale
    /// route would linger until then).
    pub fn adopt_orphans_from_table(&self) {
        let table = match self.api.get_ip_forward_table() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-orphan-enum-failed",
                    error = %e,
                    "route table enumeration failed during startup orphan adoption",
                );
                return;
            }
        };
        let orphans: Vec<RouteEntry> = table
            .into_iter()
            // Signature asked of the codegen, never restated here: a mode that
            // grows a shape a local copy does not know leaves those routes
            // unadopted after a crash, pointing traffic at a dead tunnel.
            .filter(crate::route_codegen::is_owned_route)
            .map(|mut r| {
                r.is_ours = true;
                r
            })
            .collect();
        if !orphans.is_empty() {
            tracing::info!(
                target: "nrr::route-coordinator",
                msg_key = "route-orphans-adopted",
                count = orphans.len(),
                "adopted orphaned secondary routes from a previous run",
            );
        }
        self.reconciler.adopt_owned(orphans);
    }

    /// Number of routes currently owned (for diagnostics/tests).
    pub fn owned_count(&self) -> usize {
        self.reconciler.owned_count()
    }
}
