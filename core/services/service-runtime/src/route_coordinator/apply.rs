//! Applying the plan: reconcile, tear down, adopt what a previous run left.
//!
//! Adoption is signature-based, so it works with no per-principal state at
//! all — which is what makes a crash recoverable on the next start.

use super::*;

impl SecondaryRouteCoordinator {
    /// Recompute and apply the system route table from `sid`'s effective rule
    /// book and resolved routing inputs (own revision, or baseline via the
    /// provider's read-through).
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
        self.remember_resolution(sid, resolution);
        let Some(secondary) = resolution.secondary else {
            // resolve() already logged the specific reason. The tunnel is gone,
            // so its interior is nobody's subnet any more — publish the empty
            // set rather than leave a stale one gating fake-IP answers.
            crate::secondary_subnets::global_secondary_subnets().publish(Vec::new());
            return self.reconciler.clear();
        };
        // The tunnel's own interior, refreshed while we already hold the
        // enumeration: the fake-IP answerer must never substitute an address
        // inside it (a VPN client authorizing against its own tunnel address is
        // the live case).
        self.publish_secondary_subnets(sid);
        let Some(snapshot) = self.rules_provider.active_rules_for(sid) else {
            // No effective rules for this principal → no routes.
            tracing::info!(
                target: "nrr::route-coordinator",
                sid = %sid,
                "no active rules for this user — no secondary routes",
            );
            return self.reconciler.clear();
        };
        // The tunnel's own redirect prefixes shape mode A's counter-overlay.
        // Read here, not cached: a client that reconnects may lay them out
        // differently, and the reconcile that follows must answer that layout.
        let tunnel_catch_alls = self
            .api
            .get_ip_forward_table()
            .map(|t| {
                let t = self.stamped_with_ownership(t);
                crate::route_codegen::tunnel_catch_all_prefixes(&t, secondary.interface_index)
            })
            .unwrap_or_default();
        let mut out = self.planned_routes(
            sid,
            resolution,
            &secondary,
            &snapshot.rule_book,
            &tunnel_catch_alls,
        );
        // DNS-over-secondary — the route half of the setting. Emitted here, not
        // in `generate_routes`, because it is not derived from the rule book:
        // it is service-owned infrastructure that must ride the same reconcile
        // (and the same teardown) as everything else we install.
        if self
            .dns_via_secondary
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
        {
            // Fast liveness check: the dead verdict above has a whole
            // hysteresis window of lag, and for that
            // window these `/32`s would blackhole every direct dial to the
            // public resolvers system-wide — including a VPN client's own
            // bootstrap DNS, which is exactly what has to work for the tunnel
            // to come back. One failed probe pulls the resolver routes; one
            // successful probe restores them on the next recompute.
            if self.liveness.in_failing_run(secondary.interface_index) {
                tracing::debug!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    secondary_ifindex = secondary.interface_index,
                    "DNS-over-secondary: last tunnel probe failed — leaving the public resolvers on the primary path until the tunnel answers again",
                );
            } else {
                let dns_routes = crate::route_codegen::dns_via_secondary_routes(
                    crate::dns_egress::PUBLIC_DNS_SERVERS,
                    &secondary,
                );
                tracing::debug!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    routes = dns_routes.len(),
                    secondary_ifindex = secondary.interface_index,
                    "DNS-over-secondary: routing the service's upstream resolvers through the tunnel",
                );
                out.routes.extend(dns_routes);
            }
        }
        if !out.diagnostics.is_empty() {
            // Counted by kind, not summed: a bare total can't distinguish a
            // missing primary from a cold DNS cache.
            let tally = diagnostic_tally(&out.diagnostics);
            tracing::debug!(
                target: "nrr::route-coordinator",
                sid = %sid,
                diagnostics = out.diagnostics.len(),
                routes = out.routes.len(),
                hostname_unresolved = tally.hostname_unresolved,
                suffix_empty = tally.suffix_empty,
                zone_empty = tally.zone_empty,
                app_rule_address_and_app_not_routed = tally.app_rule_address_and_app_not_routed,
                app_rule_unobserved = tally.app_rule_unobserved,
                app_rule_dest_claimed_by_main_link = tally.app_rule_dest_claimed_by_main_link,
                app_rule_dest_used_by_other_process = tally.app_rule_dest_used_by_other_process,
                address_claimed_by_main_link = tally.address_claimed_by_main_link,
                primary_exceptions_unavailable = tally.primary_exceptions_unavailable,
                "route codegen produced diagnostics",
            );
        }
        // Route-shape breakdown so the log alone answers "is mode-A selectivity
        // actually in place?" without Get-NetRoute: the `/2` counter-overlay
        // (unmatched → primary) only exists when a primary target resolved; a
        // `counter_overlay=0` + `primary=false` in PreferPrimary is the
        // smoking gun for "unmatched traffic is still riding the secondary".
        let counter_overlay = out.routes.iter().filter(|r| r.prefix_length == 2).count();
        let secondary_routes = out
            .routes
            .iter()
            .filter(|r| r.prefix_length == 32 && r.interface_index == secondary.interface_index)
            .count();
        let primary_present = resolution.primary.is_some();
        let delta = self.reconciler.reconcile(&out.routes)?;
        // ADD-ONLY, settled on hardware: we never remove the VPN's own
        // routes. Stripping its redirect `/1` pair made the client treat the
        // removal as a fault and reconnect, and in mode A it dropped
        // not-yet-resolved hosts (DoH-only names with no `/32`) to the primary
        // with the real IP. Mode-A selectivity rides a `/2` counter-overlay via
        // the primary instead — more specific than the VPN's `/1`, nothing
        // removed.
        if delta.is_noop() {
            // Steady state (no change this cycle) — debug, to keep the log
            // quiet once routing has converged.
            tracing::debug!(
                target: "nrr::route-coordinator",
                msg_key = "route-table-unchanged",
                sid = %sid,
                secondary_ifindex = secondary.interface_index,
                desired_routes = out.routes.len(),
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
                desired_routes = out.routes.len(),
                secondary_routes,
                counter_overlay,
                added = delta.added,
                removed = delta.removed,
                "route table reconciled",
            );
        }
        // Counter-overlay liveness audit (mode A): re-read the live table and
        // report EVERY `/2` route, so the log alone shows whether mode-A
        // selectivity is actually in force — our `/2` must sit on the PRIMARY
        // interface to out-specific the VPN's `/1`. A `/2` on the VPN ifindex
        // (or none at all) is the smoking gun for "unmatched still rides the
        // tunnel". Only on a real change, to avoid per-cycle cost.
        if !delta.is_noop() && matches!(resolution.mode, RouteBehaviorMode::PreferPrimary) {
            if let Ok(live) = self.api.get_ip_forward_table() {
                let mut any = false;
                for r in live.iter().filter(|r| r.prefix_length == 2) {
                    any = true;
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        destination = %r.destination,
                        ifindex = r.interface_index,
                        next_hop = %r.next_hop,
                        metric = r.metric,
                        on_secondary = (r.interface_index == secondary.interface_index),
                        "live /2 counter-overlay route",
                    );
                }
                if !any {
                    tracing::warn!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        "no /2 counter-overlay routes in the live table — mode-A selectivity is NOT in force; unmatched traffic will ride the VPN's redirect",
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
    /// Two route shapes carry our signature, both at the uncommon
    /// [`SECONDARY_ROUTE_METRIC`]: the `/32` secondary host routes (on the
    /// secondary NIC) AND the mode-A `/2` counter-overlay halves ([`COUNTER_OVERLAY`], on
    /// the primary NIC). We adopt BOTH: an unadopted `/2` overlay would strand
    /// all non-rule traffic on the primary indefinitely, even after the
    /// service that wanted it is gone.
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
                    "route table enumeration failed during startup orphan adoption: {e:?}",
                );
                return;
            }
        };
        let orphans: Vec<RouteEntry> = table
            .into_iter()
            .filter(|r| {
                // Shape asked of the codegen, never restated here: a mode that
                // grows a shape this list does not know leaves those routes
                // unadopted after a crash, pointing traffic at a dead tunnel
                // with nothing left to reclaim them.
                r.metric == crate::route_codegen::SECONDARY_ROUTE_METRIC
                    && crate::route_codegen::is_owned_shape(r.destination, r.prefix_length)
            })
            .map(|mut r| {
                r.is_ours = true;
                r
            })
            .collect();
        if !orphans.is_empty() {
            tracing::info!(
                target: "nrr::route-coordinator",
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
