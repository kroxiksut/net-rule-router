//! One table, several users: each served user's plan, laid in longest-served
//! first (see [`super::merge`]), and what the rest of the service reads back
//! from the result.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use nrr_shared::ipc_payloads::RoutesHeldDto;

use super::merge::{merge_user_routes, MergedRouteView, RouteConflict};
use super::*;

/// What one user's rule book asks of the table right now.
pub(super) struct UserRoutePlan {
    pub routes: Vec<RouteEntry>,
    pub secondary: Option<SecondaryRouteTarget>,
    /// `false` when the plan stopped early: no usable secondary, or no rules.
    pub planned: bool,
}

/// Which destinations each later user lost, and to whom — kept so a conflict
/// is reported when it appears or changes, not on every pass.
pub(super) type ReportedConflicts = BTreeMap<(String, String), BTreeSet<(IpAddr, u8)>>;

impl SecondaryRouteCoordinator {
    /// The routes `sid` asks for under `resolution`. `table` is a reading the
    /// caller already holds; without one it is read here, after the early
    /// exits, so a user with nothing to route costs no table read.
    pub(super) fn plan_user_routes(
        &self,
        sid: &str,
        resolution: &RouteResolution,
        table: Option<&Result<Vec<RouteEntry>, PlatformError>>,
    ) -> UserRoutePlan {
        self.remember_resolution(sid, resolution);
        let Some(secondary) = resolution.secondary else {
            // resolve() already logged the specific reason.
            return UserRoutePlan {
                routes: Vec::new(),
                secondary: None,
                planned: false,
            };
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(sid) else {
            tracing::info!(
                target: "nrr::route-coordinator",
                msg_key = "route-no-active-rules",
                sid = %sid,
                "no active rules for this user — no secondary routes",
            );
            return UserRoutePlan {
                routes: Vec::new(),
                secondary: Some(secondary),
                planned: false,
            };
        };
        // The tunnel's own redirect prefixes shape mode A's counter-overlay.
        // Read here, not cached: a client that reconnects may lay them out
        // differently, and the reconcile that follows must answer that layout.
        let read;
        let table = match table {
            Some(table) => table,
            None => {
                read = self
                    .api
                    .get_ip_forward_table()
                    .map(|t| self.stamped_with_ownership(t));
                &read
            }
        };
        let tunnel_catch_alls = table
            .as_ref()
            .map(|t| crate::route_codegen::tunnel_catch_all_prefixes(t, secondary.interface_index))
            .unwrap_or_default();
        // The rest of the machine reading only when a network rule will use it:
        // the adapter enumeration is a cost the host-only book never pays.
        let networks = match table {
            Ok(t)
                if crate::route_codegen::network_routes::names_networks(
                    &snapshot.rule_book,
                    self.network_support,
                ) =>
            {
                self.network_facts_from(resolution, t, false)
            }
            _ => crate::route_codegen::network_routes::NetworkRouteFacts::from_catch_alls(
                &tunnel_catch_alls,
            ),
        };
        let mut out = self.planned_routes(
            sid,
            resolution,
            &secondary,
            &snapshot.rule_book,
            &tunnel_catch_alls,
            &networks,
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
            // One failed probe pulls the resolver routes: for the hysteresis
            // window of the dead verdict these `/32`s would blackhole every
            // direct dial to the public resolvers, a VPN client's own bootstrap
            // DNS included — exactly what has to work for the tunnel to return.
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
                network_yields_to_local_network = tally.network_yields_to_local_network,
                network_routed_around_tunnel_server = tally.network_routed_around_tunnel_server,
                network_claimed_by_main_link = tally.network_claimed_by_main_link,
                network_routes_capped = tally.network_routes_capped,
                "route codegen produced diagnostics",
            );
        }
        UserRoutePlan {
            routes: out.routes,
            secondary: Some(secondary),
            planned: true,
        }
    }

    /// The table for several served users at once, `served` longest-served
    /// first. A paused user contributes what their pause policy keeps: nothing
    /// under teardown, their rule routes from the last pass under persist.
    pub(super) fn recompute_served(
        &self,
        served: &[String],
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let table = self
            .api
            .get_ip_forward_table()
            .map(|t| self.stamped_with_ownership(t));
        let mut plans: Vec<(String, Vec<RouteEntry>)> = Vec::with_capacity(served.len());
        let mut links: Vec<(String, Option<u32>)> = Vec::with_capacity(served.len());
        let mut interiors: Vec<nrr_domain::ipv4_network::Ipv4Network> = Vec::new();
        for sid in served {
            let disposition = self
                .paused_check
                .as_ref()
                .map_or(PausedRouteDisposition::Active, |check| check(sid.as_str()));
            let routes = match disposition {
                PausedRouteDisposition::Active => {
                    let resolution = self.resolve(sid);
                    let plan = self.plan_user_routes(sid, &resolution, Some(&table));
                    if let (Some(secondary), Ok(t)) = (plan.secondary, table.as_ref()) {
                        interiors.extend(
                            primary_local_subnets(t, secondary.interface_index)
                                .into_iter()
                                .filter_map(|(net, prefix)| {
                                    nrr_domain::ipv4_network::Ipv4Network::new(net, prefix)
                                }),
                        );
                    }
                    links.push((sid.clone(), plan.secondary.map(|s| s.interface_index)));
                    plan.routes
                }
                PausedRouteDisposition::ClearAll => {
                    links.push((sid.clone(), None));
                    Vec::new()
                }
                PausedRouteDisposition::KeepSecondaryHosts => {
                    links.push((sid.clone(), None));
                    self.contribution_of(sid)
                        .into_iter()
                        .filter(|r| !crate::route_codegen::is_overlay_route(r))
                        .collect()
                }
            };
            if disposition != PausedRouteDisposition::Active {
                tracing::debug!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    disposition = ?disposition,
                    "routing paused for this user — contributing only what the pause policy keeps",
                );
            }
            plans.push((sid.clone(), routes));
        }
        // Every served tunnel's interior: the fake-IP answerer must substitute
        // an address inside none of them.
        interiors.sort_unstable();
        interiors.dedup();
        crate::secondary_subnets::global_secondary_subnets().publish(interiors);
        let mut merged = merge_user_routes(&plans);
        for (sid, link) in &links {
            merged.view.set_link(sid, *link);
        }
        let _ = self.note_conflicts(&merged.conflicts);
        let delta = self.reconciler.reconcile(&merged.routes)?;
        if delta.is_noop() {
            tracing::debug!(
                target: "nrr::route-coordinator",
                msg_key = "route-table-unchanged",
                users = served.len(),
                desired_routes = merged.routes.len(),
                "route table reconciled (no change)",
            );
        } else {
            tracing::info!(
                target: "nrr::route-coordinator",
                msg_key = "route-table-reconciled",
                users = served.len(),
                desired_routes = merged.routes.len(),
                conflicts = merged.conflicts.len(),
                added = delta.added,
                removed = delta.removed,
                "route table reconciled for every signed-in user",
            );
        }
        *self.contributions.lock().unwrap_or_else(|p| p.into_inner()) =
            std::mem::take(&mut merged.contributed);
        *self.merged_view.lock().unwrap_or_else(|p| p.into_inner()) = Arc::new(merged.view);
        Ok(delta)
    }

    /// Record that the table serves `sid` alone: nothing of theirs is
    /// contested, and an earlier conflict is over.
    pub(super) fn publish_served_alone(&self, sid: &str, plan: &UserRoutePlan) {
        let mut view = MergedRouteView::default();
        view.set_link(sid, plan.secondary.map(|s| s.interface_index));
        *self.merged_view.lock().unwrap_or_else(|p| p.into_inner()) = Arc::new(view);
        let mut contributions = self.contributions.lock().unwrap_or_else(|p| p.into_inner());
        contributions.clear();
        contributions.insert(sid.to_string(), plan.routes.clone());
        drop(contributions);
        let _ = self.note_conflicts(&[]);
    }

    /// Nobody is served: no contributions, no claims, no conflicts.
    pub(super) fn publish_served_nobody(&self) {
        *self.merged_view.lock().unwrap_or_else(|p| p.into_inner()) =
            Arc::new(MergedRouteView::default());
        self.contributions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        let _ = self.note_conflicts(&[]);
    }

    fn contribution_of(&self, sid: &str) -> Vec<RouteEntry> {
        self.contributions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default()
    }

    /// Does the machine table send `address` through another user's link than
    /// `sid`'s own? The service accounts' share of `sid`'s guard leaves such an
    /// address alone: system traffic to it follows the other user's route.
    pub fn routed_for_another_user(&self, sid: &str, block: nrr_shared::ip_block::IpBlock) -> bool {
        self.merged_view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .claimed_elsewhere(sid, block)
    }

    /// Log each later user's lost destinations once per change, naming who
    /// holds them, and once more when the conflict is over. Returns how many
    /// conflicts were newly reported.
    pub(super) fn note_conflicts(&self, conflicts: &[RouteConflict]) -> usize {
        let mut now: ReportedConflicts = BTreeMap::new();
        for c in conflicts {
            now.entry((c.sid.clone(), c.holder.clone()))
                .or_default()
                .insert((c.destination, c.prefix_length));
        }
        let mut reported = self
            .reported_conflicts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if *reported == now {
            return 0;
        }
        let mut newly = 0;
        for ((sid, holder), lost) in &now {
            if reported.get(&(sid.clone(), holder.clone())) == Some(lost) {
                continue;
            }
            let sample = lost
                .iter()
                .take(5)
                .map(|(ip, len)| format!("{ip}/{len}"))
                .collect::<Vec<_>>()
                .join(", ");
            newly += 1;
            tracing::warn!(
                target: "nrr::route-coordinator",
                msg_key = "route-users-conflict",
                sid = %sid,
                holder = %holder,
                count = lost.len(),
                destinations = %sample,
                "another signed-in user already routes these destinations through a different link; they keep it, and with leak protection on this user's traffic to them is blocked rather than sent the other way",
            );
        }
        for (sid, holder) in reported.keys() {
            if !now.contains_key(&(sid.clone(), holder.clone())) {
                tracing::info!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-users-conflict-cleared",
                    sid = %sid,
                    holder = %holder,
                    "route conflict between signed-in users is over — this user's routes are in the table again",
                );
            }
        }
        let before = held_per_user(&reported);
        let after = held_per_user(&now);
        for (sid, lost) in &after {
            if before.get(sid) != Some(lost) {
                self.publish_routes_held(sid, lost);
            }
        }
        for sid in before.keys().filter(|sid| !after.contains_key(*sid)) {
            self.publish_routes_held(sid, &BTreeSet::new());
        }
        *reported = now;
        newly
    }

    /// Tell `sid` — and only `sid` — which of their destinations another
    /// user's routing holds; an empty set ends the notice. Whose routing it is
    /// stays out: that is another person's session.
    fn publish_routes_held(&self, sid: &str, lost: &BTreeSet<(IpAddr, u8)>) {
        let report = RoutesHeldDto {
            count: lost.len() as u64,
            sample: lost
                .iter()
                .take(HELD_SAMPLE)
                .map(|(ip, len)| destination_text(*ip, *len))
                .collect(),
        };
        if !self
            .enforcement_status
            .record_routes_held(sid, report.clone())
        {
            return;
        }
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                nrr_shared::ipc_payloads::StatusUpdateEvent::RoutesHeldByAnotherUser {
                    sid: sid.to_string(),
                    count: report.count,
                    sample: report.sample,
                },
            );
        }
    }
}

/// How many held destinations the notice lists; the count says the rest.
const HELD_SAMPLE: usize = 5;

/// Each later user's lost destinations, whoever holds them.
fn held_per_user(conflicts: &ReportedConflicts) -> BTreeMap<String, BTreeSet<(IpAddr, u8)>> {
    let mut out: BTreeMap<String, BTreeSet<(IpAddr, u8)>> = BTreeMap::new();
    for ((sid, _holder), lost) in conflicts {
        out.entry(sid.clone())
            .or_default()
            .extend(lost.iter().copied());
    }
    out
}

/// An address alone for a host route, the network with its prefix otherwise.
fn destination_text(ip: IpAddr, prefix_length: u8) -> String {
    let host = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_length == host {
        ip.to_string()
    } else {
        format!("{ip}/{prefix_length}")
    }
}
