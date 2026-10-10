//! Who the route table currently serves, and the passes that rewrite it.
//!
//! The table is machine-wide, so it carries the union of every served user's
//! routes; where two users want one destination through different links, the
//! one served longer keeps it (see [`super::served`] and [`super::merge`]).

use super::*;

impl SecondaryRouteCoordinator {
    /// Recompute the route table for every served user: the tray-connected
    /// SIDs in `active_sids` and, under service-driven scope, everyone signed
    /// in at the console or remotely. With nobody served the table is torn
    /// down (no user → no routes).
    ///
    /// Resolves each user's secondary target (binding × live adapter info)
    /// itself, so the wiring layer only has to forward the trigger.
    pub fn recompute_active(
        &self,
        active_sids: &[String],
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let served = self.served_sids_fresh(active_sids);
        let sid = match served.as_slice() {
            [] => {
                tracing::info!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-no-routing-user",
                    active_count = active_sids.len(),
                    "no routing user to enforce (no tray, and either app-driven scope or nobody signed in) — tearing down secondary routes",
                );
                self.publish_served_nobody();
                return self.reconciler.clear();
            }
            [sid] => sid.clone(),
            several => {
                tracing::debug!(
                    target: "nrr::route-coordinator",
                    users = several.len(),
                    "recompute_active for every signed-in user",
                );
                return self.recompute_served(several);
            }
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
                        msg_key = "route-paused-teardown",
                        sid = %sid,
                        "routing paused for this user (teardown policy) — tearing down secondary routes",
                    );
                    self.publish_served_nobody();
                    return self.reconciler.clear();
                }
                PausedRouteDisposition::KeepSecondaryHosts => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        msg_key = "route-paused-persist",
                        sid = %sid,
                        "routing paused for this user (persist policy) — keeping /32 rule-routes, dropping overlays only",
                    );
                    return self.teardown_keep_rule_routes();
                }
            }
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

    /// The longest-served user: the one whose routing never yields to anyone.
    ///
    /// Only for what the machine can do for ONE user at a time — the DNS
    /// answers (a query carries no trace of who asked), the fake-IP relay, the
    /// upstream resolver's preferred link. Anything per user (routes, filters,
    /// seeding, learning) asks [`Self::served_sids`] instead.
    pub fn effective_routing_sid(&self, active_sids: &[String]) -> Option<String> {
        self.served_sids(active_sids).into_iter().next()
    }

    /// The SID set whose WFP enforcement should be installed right now: every
    /// served user (see [`Self::served_sids`]), so enforcement self-arms from
    /// boot and survives a dead tray subscription instead of waiting for a
    /// tray connect.
    pub fn effective_enforcement_sids(&self, tray_active: &[String]) -> Vec<String> {
        self.served_sids(tray_active)
    }

    /// unconditional teardown of every owned route,
    /// for graceful service stop. Unlike `recompute_active(&[])` this never
    /// falls back to the console user under service-driven scope: stopping the
    /// service must restore pristine networking in BOTH scopes.
    pub fn teardown(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.clear()
    }

    /// Graceful-stop teardown: rule routes stay, our overlays go, and the OS
    /// routes the rest to the primary or the VPN's own default. See
    /// [`SecondaryRouteReconciler::retain_rule_routes`].
    pub fn teardown_keep_rule_routes(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconciler.retain_rule_routes()
    }
}
