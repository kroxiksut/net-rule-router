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
        self.drop_machine_memo();
        let result = self.recompute_active_pass(active_sids);
        self.arm_machine_memo();
        result
    }

    fn recompute_active_pass(
        &self,
        active_sids: &[String],
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let _pass = self.pass_lock.lock().unwrap_or_else(|p| p.into_inner());
        // The pass's one reading of the links: everything below, and the
        // enforcement apply that follows, reads it back.
        let adapters = self.adapters_for_pass();
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
                let mut known: Vec<String> = active_sids.to_vec();
                known.extend(
                    self.api
                        .interactive_user_sign_ins()
                        .into_iter()
                        .map(|(sid, _)| sid),
                );
                self.publish_no_machine_facts(&known);
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
                    self.publish_no_machine_facts(std::slice::from_ref(&sid));
                    return self.reconciler.clear();
                }
                PausedRouteDisposition::KeepSecondaryHosts => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        msg_key = "route-paused-persist",
                        sid = %sid,
                        "routing paused for this user (persist policy) — keeping /32 rule-routes, dropping overlays only",
                    );
                    // Served alone: nobody else's tunnel carries them.
                    self.note_traffic_carried(&[], &[]);
                    self.publish_no_machine_facts(std::slice::from_ref(&sid));
                    return self.reconciler.retain_rule_routes();
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
        crate::kept_direct::retain_only(std::slice::from_ref(&sid));
        self.keep_machine_reads(std::slice::from_ref(&sid));
        let resolution = self.resolve_inner(&sid, None, adapters.as_deref().ok());
        // First contacts plan from this link from now on, not from the one the
        // last pass saw: the cache snapshot ahead takes long enough for a
        // tunnel recreated just now to be answered on its old interface.
        self.remember_resolution(&sid, &resolution);
        self.recompute_for_with(&sid, &resolution, adapters.ok())
    }

    /// A pass that returns before reading the machine leaves no foreign tunnel
    /// or kept-direct segment of the last one standing: doubt is "not foreign".
    /// The users' own links stay published: a paused user's VPN is still theirs.
    fn publish_no_machine_facts(&self, sids: &[String]) {
        let cell = crate::foreign_tunnels::global_foreign_tunnels();
        let own = self.links_kept_as_ours(cell.own_links(), sids);
        cell.publish_served(None, &[], &[], &own);
        crate::kept_direct::forget_all();
        self.keep_machine_reads(&[]);
    }

    /// `previous` plus the additional links of `sids`, from what the last
    /// passes resolved and what the stored bindings name now. Doubt keeps a
    /// link ours, so a link is only ever added here.
    pub(super) fn links_kept_as_ours(&self, mut ours: Vec<u32>, sids: &[String]) -> Vec<u32> {
        ours.extend(
            self.last_resolution
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .values()
                .filter_map(|r| r.secondary.map(|t| t.interface_index)),
        );
        if let Ok(adapters) = self.adapters_now() {
            for sid in sids {
                let policy = self.route_source.load_for_sid(sid);
                ours.extend(Self::additional_links(
                    policy.as_ref(),
                    &RouteResolution {
                        mode: RouteBehaviorMode::PreferPrimary,
                        primary: None,
                        secondary: None,
                    },
                    &adapters,
                ));
            }
        }
        ours.sort_unstable();
        ours.dedup();
        ours
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
        let _pass = self.pass_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.drop_machine_memo();
        self.reconciler.clear()
    }

    /// Graceful-stop teardown: rule routes stay, our overlays go, and the OS
    /// routes the rest to the primary or the VPN's own default. See
    /// [`SecondaryRouteReconciler::retain_rule_routes`].
    pub fn teardown_keep_rule_routes(&self) -> Result<RouteReconcileDelta, PlatformError> {
        let _pass = self.pass_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.drop_machine_memo();
        self.reconciler.retain_rule_routes()
    }

    /// [`Self::teardown`] for the stop, which must end: a pass still running
    /// after `wait` has wedged, and the routes then go by their signature,
    /// past the pass and the owned set it may be holding.
    pub fn teardown_within(&self, wait: Duration) -> Result<RouteReconcileDelta, PlatformError> {
        match crate::lifecycle_matrix::lock_within(&self.pass_lock, wait) {
            Some(_pass) => {
                self.drop_machine_memo();
                self.reconciler.clear()
            }
            None => self.sweep_signed_past_the_pass(false),
        }
    }

    /// [`Self::teardown_keep_rule_routes`] under the same bound as
    /// [`Self::teardown_within`]; past it only the overlays go.
    pub fn teardown_keep_rule_routes_within(
        &self,
        wait: Duration,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        match crate::lifecycle_matrix::lock_within(&self.pass_lock, wait) {
            Some(_pass) => {
                self.drop_machine_memo();
                self.reconciler.retain_rule_routes()
            }
            None => self.sweep_signed_past_the_pass(true),
        }
    }

    /// Remove our signed rows straight from the table, each on its own: no
    /// pass is left to want one back. `overlays_only` keeps the rule routes.
    fn sweep_signed_past_the_pass(
        &self,
        overlays_only: bool,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        use nrr_platform_api::route_signature::{is_overlay_route, signed_routes};
        tracing::warn!(
            target: "nrr::route-coordinator",
            msg_key = "route-teardown-pass-wedged",
            overlays_only,
            "a route pass is still running at the stop; removing our routes by their signature instead",
        );
        let rows = signed_routes(self.api.as_ref(), &|_: &RouteEntry| false)?;
        let mut removed = 0usize;
        let mut refused = None;
        for route in rows
            .iter()
            .filter(|r| !overlays_only || is_overlay_route(r))
        {
            match self.api.delete_ip_forward_entry(route) {
                Ok(()) => removed += 1,
                Err(e) if e.classify() == nrr_platform_api::ErrorClass::Idempotent => {}
                Err(e) => {
                    refused.get_or_insert(e);
                }
            }
        }
        match refused {
            None => Ok(RouteReconcileDelta { added: 0, removed }),
            Some(e) => Err(e),
        }
    }
}
