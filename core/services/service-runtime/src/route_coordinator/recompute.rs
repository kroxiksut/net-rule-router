//! Who the route table currently belongs to, and the passes that rewrite it.
//!
//! The table is machine-wide, so exactly one principal owns it at a time; the
//! choice of that principal is what these methods decide before anything is
//! applied.

use super::*;

impl SecondaryRouteCoordinator {
    /// Recompute the route table for the **active console-session user**
    /// (Free single-active-user model). `active_sids` is the routing-active
    /// set from `ActiveSidRegistry`; in Free at most one is active. With
    /// none active the table is torn down (no user → no routes; M-1).
    ///
    /// Resolves the active user's secondary target (binding × live adapter
    /// info) itself, so the wiring layer only has to forward the trigger.
    /// Per-session routing for several concurrently-active users cannot be
    /// expressed in a machine-wide table; the first active SID owns it.
    pub fn recompute_active(
        &self,
        active_sids: &[String],
    ) -> Result<RouteReconcileDelta, PlatformError> {
        // Pick the routing user via the shared gate. `None` → tear down.
        let Some(sid) = self.effective_routing_sid(active_sids) else {
            tracing::info!(
                target: "nrr::route-coordinator",
                active_count = active_sids.len(),
                "no routing user to enforce (no tray, and either app-driven scope or no console session) — tearing down secondary routes",
            );
            return self.reconciler.clear();
        };
        // Safe-disable (ROUTE-half) — a paused routing user's routes must never
        // be (re)installed. This single choke point covers EVERY re-drive
        // (active-user listener, DNS warm-up / 30 s safety tick, apply-trigger,
        // boot). The stop-policy is honoured so the safety tick matches the
        // WFP half — `Teardown` full-clears, `Persist` keeps the `/32`
        // rule-routes and drops only NRR's overlays (idempotent), instead of
        // silently deleting the `/32`s `teardown_routes` kept.
        if let Some(check) = self.paused_check.as_ref() {
            match check(&sid) {
                PausedRouteDisposition::Active => {}
                PausedRouteDisposition::ClearAll => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        "routing paused for this user (teardown policy) — tearing down secondary routes",
                    );
                    return self.reconciler.clear();
                }
                PausedRouteDisposition::KeepSecondaryHosts => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        sid = %sid,
                        "routing paused for this user (persist policy) — keeping /32 rule-routes, dropping overlays only",
                    );
                    return self.teardown_keep_secondary_hosts();
                }
            }
        }
        if active_sids.is_empty() {
            tracing::debug!(
                target: "nrr::route-coordinator",
                sid = %sid,
                "no tray connected; service-driven scope → enforcing active console user's policy",
            );
        }
        // Per-cycle heartbeat — debug so it does not flood the log every
        // poll interval. State changes (routes added/removed, resolve
        // failures) still log loudly below.
        tracing::debug!(
            target: "nrr::route-coordinator",
            sid = %sid,
            active_count = active_sids.len(),
            "recompute_active for routing user",
        );
        let resolution = self.resolve(&sid);
        self.recompute_for(&sid, &resolution)
    }

    /// the SID whose policy is actually enforced for
    /// `active_sids`: the first connected-tray SID (M-1), or — under
    /// service-driven scope with no tray — the OS active console-session user
    /// (so a managed policy enforces even with no app running, from boot).
    /// `None` means "nothing to enforce" (app-driven with no tray, or no
    /// console session). SHARED by `recompute_active`, the FQDN seeder, the
    /// DNS-observation consumer, and the policy-change trigger so all four
    /// target the SAME user the route table is built for — otherwise
    /// ExactFqdn/Suffix/Zone rules never get seeded for the console user from
    /// boot and only ExactIp + a warm cache enforce.
    pub fn effective_routing_sid(&self, active_sids: &[String]) -> Option<String> {
        if let Some(s) = active_sids.first() {
            return Some(s.clone());
        }
        if (self.rule_scope_service_driven)() {
            return self.api.active_console_user_sid();
        }
        None
    }

    /// the SID SET whose WFP enforcement should be
    /// installed right now: every routing-active (tray-connected) SID, or —
    /// with no tray at all — the single effective routing user from
    /// [`Self::effective_routing_sid`] (console-session user under
    /// service-driven scope). Gives the WFP orchestrator the same no-tray
    /// fallback the route half already has, so enforcement self-arms from
    /// boot / survives a dead tray subscription instead of waiting for a
    /// tray connect. Multi-tray SIDs pass through unchanged (the fallback
    /// only fills an EMPTY set — it never overrides connected trays).
    pub fn effective_enforcement_sids(&self, tray_active: &[String]) -> Vec<String> {
        if !tray_active.is_empty() {
            return tray_active.to_vec();
        }
        self.effective_routing_sid(&[]).into_iter().collect()
    }

    /// unconditional teardown of every owned route,
    /// for graceful service stop. Unlike `recompute_active(&[])` this never
    /// falls back to the console user under service-driven scope: stopping the
    /// service must restore pristine networking in BOTH scopes.
    pub fn teardown(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.clear()
    }

    /// graceful-stop teardown that KEEPS the secondary
    /// `/32` rule-routes and removes only NRR's overlays, so rule-matched hosts
    /// keep egressing the secondary adapter after the service stops. VPN-type-aware
    /// without probing: removing the overlays lets the OS route the rest to the
    /// primary (gateway-less VPN) or the VPN's own default (full-tunnel VPN). See
    /// [`SecondaryRouteReconciler::retain_secondary_hosts`].
    pub fn teardown_keep_secondary_hosts(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.retain_secondary_hosts()
    }
}
