//! One table, several users: each served user's plan, laid in longest-served
//! first (see [`super::merge`]), and what the rest of the service reads back
//! from the result.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use nrr_shared::ipc_payloads::{RoutesHeldDto, TrafficCarriedDto};

use super::liveness::snapshot_or_live;
use super::merge::{merge_user_routes, MergedRouteView, RouteConflict};
use super::*;

/// What one user's rule book asks of the table right now.
pub(super) struct UserRoutePlan {
    pub routes: Vec<RouteEntry>,
    pub secondary: Option<SecondaryRouteTarget>,
    /// `false` when the plan stopped early: no usable secondary, or no rules.
    pub planned: bool,
    /// The book did not read: the routes in place stay, whatever they are.
    pub hold: bool,
    /// The user's foreign tunnels, when the plan read the machine to name them.
    pub foreign: Option<Vec<u32>>,
}

/// Which destinations each later user lost, and to whom — kept so a conflict
/// is reported when it appears or changes, not on every pass.
pub(super) type ReportedConflicts = BTreeMap<(String, String), BTreeSet<(IpAddr, u8)>>;

impl SecondaryRouteCoordinator {
    /// The routes `sid` asks for under `resolution`, from the pass's reading
    /// of the table and the links: the foreign-tunnel view needs both even for
    /// a user with nothing to route, so the caller reads them once.
    pub(super) fn plan_user_routes(
        &self,
        sid: &str,
        resolution: &RouteResolution,
        policy: Option<&PerSidPolicySnapshot>,
        table: &Result<Vec<RouteEntry>, PlatformError>,
        adapters: &[AdapterInfo],
        cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup,
    ) -> UserRoutePlan {
        self.remember_resolution(sid, resolution);
        let Some(secondary) = resolution.secondary else {
            // resolve() already logged the specific reason.
            return UserRoutePlan {
                routes: Vec::new(),
                secondary: None,
                planned: false,
                hold: false,
                foreign: None,
            };
        };
        use crate::per_sid_orchestrator::RulesRead;
        let read = match self.rules_provider.rules_read_for(sid) {
            RulesRead::Rules(snapshot) => Some(snapshot),
            // Settings but no revision route as an emptied book.
            RulesRead::NoPolicy if policy.is_some() => {
                Some(crate::per_sid_orchestrator::ActiveRulesSnapshot::default())
            }
            RulesRead::NoPolicy => None,
            // The last decoded book, if any; with none the owned routes stay
            // until it reads, as the filters do.
            RulesRead::Unreadable(_) => match self.rules_provider.active_rules_for(sid) {
                Some(snapshot) => Some(snapshot),
                None => {
                    return UserRoutePlan {
                        routes: Vec::new(),
                        secondary: Some(secondary),
                        planned: false,
                        hold: true,
                        foreign: None,
                    }
                }
            },
        };
        let Some(snapshot) = read else {
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
                hold: false,
                foreign: None,
            };
        };
        // The tunnel's own redirect prefixes shape mode A's counter-overlay,
        // from this pass's table: a client that reconnects may lay them out
        // differently, and the reconcile that follows must answer that layout.
        let tunnel_catch_alls = table.as_ref().map_or_else(
            |_| crate::route_codegen::ASSUMED_CATCH_ALLS.to_vec(),
            |t| crate::route_codegen::tunnel_catch_all_prefixes(t, secondary.interface_index),
        );
        // Host routes keep off attached networks and foreign tunnels, so the
        // links are read with the table, whatever the book holds.
        let (networks, foreign) = match table {
            Ok(t) => {
                let (facts, foreign) =
                    self.network_facts_from(sid, resolution, policy, t, adapters, false);
                self.note_machine_read(sid, true);
                (facts, Some(foreign))
            }
            _ => {
                // Unreadable table: nothing is named foreign or local.
                crate::kept_direct::forget(sid);
                self.note_machine_read(sid, false);
                (
                    crate::route_codegen::network_routes::NetworkRouteFacts::from_catch_alls(
                        &tunnel_catch_alls,
                    ),
                    None,
                )
            }
        };
        let mut out = self.planned_routes(
            sid,
            resolution,
            policy,
            &secondary,
            &snapshot.rule_book,
            cache,
            &tunnel_catch_alls,
            &networks,
        );
        // The route half of where the service's own queries go. Emitted here,
        // not in `generate_routes`: it is service-owned infrastructure that
        // must ride the same reconcile (and the same teardown) as everything
        // else we install.
        let resolvers = self.dns_via_secondary.as_ref().map_or(&[][..], |flag| {
            let setting_on = flag.load(std::sync::atomic::Ordering::Relaxed);
            let names_hosts = !setting_on
                && crate::rule_host_index::RuleHostIndex::build(&snapshot.rule_book.secondary)
                    .names_any_host();
            crate::dns_egress::resolvers_via_tunnel(setting_on, names_hosts)
        });
        if !resolvers.is_empty() {
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
                let dns_routes =
                    crate::route_codegen::dns_via_secondary_routes(resolvers, &secondary);
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
                private_kept_out_of_tunnel = tally.private_kept_out_of_tunnel,
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
            hold: false,
            foreign,
        }
    }

    /// The table for several served users at once, `served` longest-served
    /// first. A paused user contributes what their pause policy keeps: nothing
    /// under teardown, their rule routes from the last pass under persist.
    pub(super) fn recompute_served(
        &self,
        served: &[String],
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let writes = self.reconciler.write_count();
        let table = self
            .api
            .get_ip_forward_table()
            .map(|t| self.stamped_with_ownership(t));
        // One enumeration for every user's facts and the foreign-tunnel view.
        let adapters = self.adapters_for_facts();
        // One cache reading for every user's plan: the book walks run in memory,
        // not one SQLite query per host.
        let snapshot = self.fqdn_cache.snapshot_for_compute();
        let cache = snapshot_or_live(snapshot.as_deref(), self.fqdn_cache.as_ref());
        crate::kept_direct::retain_only(served);
        self.keep_machine_reads(served);
        let mut foreign: Vec<Vec<u32>> = Vec::with_capacity(served.len());
        let mut own_links: Vec<u32> = Vec::new();
        let mut plans: Vec<(String, Vec<RouteEntry>)> = Vec::with_capacity(served.len());
        let mut links: Vec<(String, Option<u32>)> = Vec::with_capacity(served.len());
        let mut interiors: Vec<nrr_domain::ipv4_network::Ipv4Network> = Vec::new();
        for sid in served {
            // One load of this user's policy serves every question of the pass.
            let policy = self.route_source.load_for_sid(sid);
            let disposition = self
                .paused_check
                .as_ref()
                .map_or(PausedRouteDisposition::Active, |check| check(sid.as_str()));
            let routes = match disposition {
                PausedRouteDisposition::Active => {
                    let resolution = self.resolve(sid);
                    let plan = self.plan_user_routes(
                        sid,
                        &resolution,
                        policy.as_ref(),
                        &table,
                        &adapters,
                        cache,
                    );
                    foreign.push(plan.foreign.clone().unwrap_or_else(|| {
                        self.foreign_tunnel_interfaces(
                            &resolution,
                            policy.as_ref(),
                            table.as_deref().ok(),
                            Some(&adapters),
                        )
                    }));
                    own_links.extend(Self::additional_links(
                        policy.as_ref(),
                        &resolution,
                        &adapters,
                    ));
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
                    if plan.hold {
                        self.contribution_of(sid)
                    } else {
                        plan.routes
                    }
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
                // A paused user's links are still theirs; the stored bindings
                // name them without a resolve.
                let unresolved = RouteResolution {
                    mode: RouteBehaviorMode::PreferPrimary,
                    primary: None,
                    secondary: None,
                };
                foreign.push(self.foreign_tunnel_interfaces(
                    &unresolved,
                    policy.as_ref(),
                    table.as_deref().ok(),
                    Some(&adapters),
                ));
                own_links.extend(Self::additional_links(
                    policy.as_ref(),
                    &unresolved,
                    &adapters,
                ));
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
        self.publish_foreign_tunnel_networks(
            table.as_deref().ok(),
            &adapters,
            &foreign,
            &own_links,
        );
        let mut merged = merge_user_routes(&plans);
        for (sid, link) in &links {
            merged.view.set_link(sid, *link);
        }
        let _ = self.note_conflicts(&merged.conflicts);
        self.note_traffic_carried(&merged.default_carried_by, &links);
        // The table this pass began with also checks the routes we keep.
        let seen = table
            .as_deref()
            .ok()
            .map(|rows| crate::route_reconciler::TableReading { writes, rows });
        let delta = self
            .reconciler
            .reconcile_seen(&merged.routes, writes, seen)?;
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
        self.note_traffic_carried(&[], &[]);
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
        self.note_traffic_carried(&[], &[]);
    }

    fn contribution_of(&self, sid: &str) -> Vec<RouteEntry> {
        self.contributions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default()
    }

    /// The user whose tunnel carries `sid`'s unnamed traffic, because that
    /// user's "everything through my tunnel" was in the table first. What the
    /// notice "your traffic goes through another user's connection" reads.
    pub fn default_carried_by(&self, sid: &str) -> Option<String> {
        self.merged_view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .default_carried_by(sid)
            .map(str::to_owned)
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
                count = lost.len(),
                addresses = %sample,
                "another signed-in user already routes these destinations through a different link; they keep it, and with leak protection on this user's traffic to them is blocked rather than sent the other way",
            );
        }
        for (sid, holder) in reported.keys() {
            if !now.contains_key(&(sid.clone(), holder.clone())) {
                tracing::info!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-users-conflict-cleared",
                    sid = %sid,
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

    /// Tell each user whose unrouted traffic rides another user's tunnel the
    /// connection that carries it — never whose it is — and end the notice
    /// for whoever it no longer applies to. `carried` is the merge's
    /// `(user, holder)` list, `links` each served user's own additional link.
    pub(super) fn note_traffic_carried(
        &self,
        carried: &[(String, String)],
        links: &[(String, Option<u32>)],
    ) {
        // Read only while somebody is carried: the common pass pays nothing.
        let infos = if carried.is_empty() {
            Vec::new()
        } else {
            self.adapters_now().unwrap_or_default()
        };
        let mut now: BTreeMap<&str, String> = BTreeMap::new();
        for (sid, holder) in carried {
            let link = links
                .iter()
                .find(|(user, _)| user == holder)
                .and_then(|(_, link)| *link);
            let live = link
                .and_then(|index| infos.iter().find(|info| info.index == index))
                .map(|info| preferred_display_name(info).to_string());
            let name = live
                .or_else(|| {
                    self.route_source
                        .load_for_sid(holder)?
                        .secondary
                        .map(|binding| binding.display_name)
                })
                .unwrap_or_default();
            now.insert(sid.as_str(), name);
        }
        for sid in self.enforcement_status.traffic_carried_principals() {
            if !now.contains_key(sid.as_str()) {
                self.publish_traffic_carried(
                    &sid,
                    TrafficCarriedDto {
                        carried: false,
                        link: String::new(),
                    },
                );
            }
        }
        for (sid, link) in now {
            self.publish_traffic_carried(
                sid,
                TrafficCarriedDto {
                    carried: true,
                    link,
                },
            );
        }
    }

    /// Record `report` for `sid` and, when it changed, push it to `sid` only.
    fn publish_traffic_carried(&self, sid: &str, report: TrafficCarriedDto) {
        if !self
            .enforcement_status
            .record_traffic_carried(sid, report.clone())
        {
            return;
        }
        tracing::info!(
            target: "nrr::route-coordinator",
            sid = %sid,
            carried = report.carried,
            link = %report.link,
            "whether this user's unrouted traffic leaves through another signed-in user's tunnel changed",
        );
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                nrr_shared::ipc_payloads::StatusUpdateEvent::TrafficCarriedByAnotherUser {
                    sid: sid.to_string(),
                    carried: report.carried,
                    link: report.link,
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
