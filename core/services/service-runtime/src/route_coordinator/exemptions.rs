//! What must survive the cut.
//!
//! The kill-switch and fail-closed exemption sets: bootstrap server IPs,
//! local subnets, the addresses a tunnel needs to come back up. Both read the
//! pass's one [`MachineReading`] and cache what they found, so a reconnect
//! blip does not drop an exemption — which is the whole reason they are
//! written the way they are.
//!
//! Same inherent impl, split across files.

use super::*;
use crate::killswitch_codegen::ForeignTunnelNetwork;

impl SecondaryRouteCoordinator {
    /// What policy may do about IPv6 for `sid`'s bindings this pass.
    ///
    /// Unreadable links answer [`Ipv6Guard::Off`] — the same posture every
    /// other resolver here takes when the machine will not say what it has:
    /// name nothing rather than pin on a guess.
    pub fn ipv6_guard(
        &self,
        sid: &str,
        reading: &MachineReading,
    ) -> crate::enforcement_planner::Ipv6Guard {
        use crate::enforcement_planner::Ipv6Guard;
        let Some(adapters) = reading.adapters() else {
            return Ipv6Guard::Off;
        };
        let secondary = self
            .resolve_from(sid, Some(reading))
            .secondary
            .and_then(|t| adapters.iter().find(|a| a.index == t.interface_index));
        Ipv6Guard::from_links(adapters, secondary, reading.routes().unwrap_or_default())
    }

    /// resolve everything the
    /// kill-switch needs about `sid`'s secondary interface: its LUID plus the
    /// system exemptions (VPN server IPs, primary local subnets).
    ///
    /// `None` when there is no usable secondary or its LUID can't be resolved
    /// (fail-open — no kill-switch this cycle). When `Some`, the server-IP set
    /// may still be empty (the caller's catch-all path refuses to arm in that
    /// case, to avoid trapping the tunnel's own reconnection); the
    /// per-destination path (mode A) ignores the exemptions entirely.
    ///
    /// Caches the last-known server IPs so a reconnect blip (bootstrap route
    /// briefly gone) does not drop the exemption.
    pub fn kill_switch_exemptions(
        &self,
        sid: &str,
        reading: &MachineReading,
    ) -> Option<KillSwitchResolution> {
        let resolution = self.resolve_from(sid, Some(reading));
        let secondary = resolution.secondary?;
        let secondary_luid = match self.api.interface_luid_for_index(secondary.interface_index) {
            Ok(l) if l != 0 => l,
            Ok(_) => return None,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-killswitch-luid-error",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    error = %e,
                    "kill-switch: could not resolve secondary LUID; staying off (fail-open)",
                );
                return None;
            }
        };
        // An unreadable route table is not an empty one. Arming on the empty
        // reading gives a kill-switch with no LAN, no DHCP and no printers
        // exempted — and nothing in the log to say why. Same posture as the
        // LUID failure above: stay off and let the next tick try again.
        let routes = match reading.routes_or_error() {
            Ok(routes) => routes.to_vec(),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-killswitch-table-unreadable",
                    sid = %sid,
                    error = %e,
                    "kill-switch: route table could not be read, so the local-network exemptions are unknown; staying off (fail-open)",
                );
                return None;
            }
        };
        let primary_gateway = resolution.primary.map(|p| p.gateway);
        let mut server_ips =
            bootstrap_server_ips(&routes, secondary.interface_index, primary_gateway);
        // Cache last-known server IPs (keyed by secondary ifindex). When the
        // live table yields none (VPN disconnected → bootstrap route gone),
        // fall back to the cache so the exemption — and thus reconnection —
        // survives.
        {
            let mut cache = self
                .server_ip_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if server_ips.is_empty() {
                if let Some(cached) = cache.get(&secondary.interface_index) {
                    server_ips = cached.clone();
                }
            } else if cache.get(&secondary.interface_index) != Some(&server_ips) {
                cache.insert(secondary.interface_index, server_ips.clone());
                // Written so the catch-all can arm after a restart; only on a
                // change, because the write moves the pass's `state` input and
                // a steady tunnel would otherwise force a full pass every tick.
                if let Some(persist) = self.server_ip_persist.as_ref() {
                    persist(&server_ips);
                }
            }
        }
        let mut local_subnets = resolution
            .primary
            .map(|p| exemptible_local_subnets(&routes, p.interface_index).v4)
            .unwrap_or_default();
        self.apply_local_network_policy(
            sid,
            &routes,
            reading.adapters().unwrap_or_default(),
            Some(secondary.interface_index),
            &mut local_subnets,
        );
        // Endpoints learned from a client's own dropped connections are NOT
        // folded in: a server exemption is machine-wide and address-keyed,
        // and the address a VPN client was dropped on can be a CDN front it
        // shares with the user's rule hosts. The client itself is exempted by
        // process instead (`vpn_client_registry`), which no other program
        // can ride.
        // The v6 halves come straight off the route table: an IPv6 endpoint
        // has no field in the model, and the `/128` bootstrap route the client
        // installs is what the machine itself states.
        let (bootstrap_server_ips_v6, mut local_subnets_v6) =
            v6_exemptions(&routes, resolution.primary, Some(secondary.interface_index));
        local_subnets_v6.extend(self.opened_public_v6(
            sid,
            &routes,
            resolution.primary.map(|p| p.interface_index),
        ));
        let policy = self.route_source.load_for_sid(sid);
        let (foreign_tunnel_luids, foreign_tunnel_networks) = self.foreign_tunnels_of(
            &resolution,
            policy.as_ref(),
            Some(&routes),
            reading.adapters(),
        );
        Some(KillSwitchResolution {
            secondary_luid,
            bootstrap_server_ips: server_ips,
            bootstrap_server_ips_v6,
            local_subnets,
            local_subnets_v6,
            foreign_tunnel_luids,
            foreign_tunnel_networks,
        })
    }

    /// LUIDs of tunnels the user runs that are not our additional route, and
    /// the networks their own routes carry, each with its tunnel's LUID.
    ///
    /// A machine can hold several: ours, and the corporate one the person
    /// needs for work. Cutting the second is the product breaking something
    /// it was never asked to manage, and from the outside it is
    /// indistinguishable from the corporate VPN failing on its own.
    ///
    /// `routes` or `adapters` is `None` when it could not be read. Nothing is
    /// then exempted: which link carries the default route is unknown, and
    /// [`foreign_tunnel_indexes`] resolves doubt to "not a foreign tunnel".
    fn foreign_tunnels_of(
        &self,
        resolution: &RouteResolution,
        policy: Option<&PerSidPolicySnapshot>,
        routes: Option<&[RouteEntry]>,
        adapters: Option<&[AdapterInfo]>,
    ) -> (Vec<u64>, Vec<ForeignTunnelNetwork>) {
        let mut luids = Vec::new();
        let mut networks = Vec::new();
        for index in self.foreign_tunnel_interfaces(resolution, policy, routes, adapters) {
            let Some(luid) = self
                .api
                .interface_luid_for_index(index)
                .ok()
                .filter(|luid| *luid != 0)
            else {
                continue;
            };
            luids.push(luid);
            networks.extend(
                crate::route_codegen::network_routes::foreign_tunnel_blocks(
                    routes.unwrap_or_default(),
                    &[index],
                )
                .into_iter()
                .map(|network| ForeignTunnelNetwork { luid, network }),
            );
        }
        (luids, networks)
    }

    /// Interface indexes of `sid`'s foreign tunnels, read off the machine now.
    /// Nothing is named while the links or the table cannot be read.
    pub fn foreign_tunnel_interface_indexes(&self, sid: &str) -> Vec<u32> {
        let resolution = self.resolve(sid);
        let (Ok(routes), Ok(adapters)) = (self.api.get_ip_forward_table(), self.adapters_now())
        else {
            return Vec::new();
        };
        let policy = self.route_source.load_for_sid(sid);
        self.foreign_tunnel_interfaces(&resolution, policy.as_ref(), Some(&routes), Some(&adapters))
    }

    /// `sid`'s foreign tunnels by interface index; none while the links or the
    /// table cannot be read. `policy` is the pass's one load of `sid`'s policy.
    pub(super) fn foreign_tunnel_interfaces(
        &self,
        resolution: &RouteResolution,
        policy: Option<&PerSidPolicySnapshot>,
        routes: Option<&[RouteEntry]>,
        adapters: Option<&[AdapterInfo]>,
    ) -> Vec<u32> {
        let (Some(routes), Some(adapters)) = (routes, adapters) else {
            return Vec::new();
        };
        let resolved: Vec<u32> = resolution
            .primary
            .iter()
            .chain(resolution.secondary.iter())
            .map(|t| t.interface_index)
            .collect();
        let bindings = policy
            .iter()
            .flat_map(|p| p.primary.iter().chain(p.secondary.iter()));
        let ours = own_link_indexes(adapters, &resolved, bindings);
        let resolved_secondary: Vec<u32> = resolution
            .secondary
            .iter()
            .map(|t| t.interface_index)
            .collect();
        let additional = own_link_indexes(
            adapters,
            &resolved_secondary,
            policy.iter().flat_map(|p| p.secondary.iter()),
        );
        foreign_tunnel_indexes(adapters, &ours, &additional, routes)
    }

    /// `sid`'s additional-route links: the secondary that resolved and every
    /// adapter its stored binding names, resolved this pass or not.
    pub(super) fn additional_links(
        policy: Option<&PerSidPolicySnapshot>,
        resolution: &RouteResolution,
        adapters: &[AdapterInfo],
    ) -> Vec<u32> {
        let resolved: Vec<u32> = resolution
            .secondary
            .iter()
            .map(|t| t.interface_index)
            .collect();
        own_link_indexes(
            adapters,
            &resolved,
            policy.iter().flat_map(|p| p.secondary.iter()),
        )
    }

    /// exemptions for the **fail-closed** block-all path
    /// (mode B) when the secondary cannot be resolved. Unlike
    /// [`Self::kill_switch_exemptions`] this never returns `None`: the whole
    /// point is to arm a block-all even when the secondary is gone. It resolves the
    /// PRIMARY (the working link) independently and returns its connected
    /// subnets so the block-all keeps LAN / local manageability, plus any
    /// cached VPN-server IPs (best-effort) so the tunnel can reconnect.
    pub fn fail_closed_exemptions(
        &self,
        sid: &str,
        reading: &MachineReading,
    ) -> FailClosedExemptions {
        let resolution = self.resolve_from(sid, Some(reading));
        // Unlike the kill-switch path this one cannot decline: the block-all is
        // armed either way. So an unreadable table falls back to the last
        // subnets this link was seen with — the same reasoning as the VPN-server
        // cache below. A stale LAN exemption permits a little more; an empty one
        // cuts the user's own network with nothing in the log.
        let (routes, table_read) = match reading.routes_or_error() {
            Ok(routes) => (routes.to_vec(), true),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-failclosed-table-unreadable",
                    sid = %sid,
                    error = %e,
                    "leak protection: route table could not be read; falling back to the last known local subnets",
                );
                (Vec::new(), false)
            }
        };
        let mut local_subnets = resolution
            .primary
            .map(|p| exemptible_local_subnets(&routes, p.interface_index).v4)
            .unwrap_or_default();
        if let Some(primary) = resolution.primary {
            let mut cache = self
                .local_subnet_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if table_read && !local_subnets.is_empty() {
                cache.insert(primary.interface_index, local_subnets.clone());
            } else if local_subnets.is_empty() {
                if let Some(cached) = cache.get(&primary.interface_index) {
                    local_subnets = cached.clone();
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        msg_key = "route-failclosed-cached-subnets",
                        sid = %sid,
                        subnet_count = local_subnets.len(),
                        "leak protection: using the last known local subnets so the block-all keeps LAN reachable",
                    );
                }
            }
        }
        self.apply_local_network_policy(
            sid,
            &routes,
            reading.adapters().unwrap_or_default(),
            resolution.secondary.map(|s| s.interface_index),
            &mut local_subnets,
        );
        // Best-effort: exempt every VPN-server IP we have ever cached (we do
        // not know which secondary ifindex applies when it is unresolved).
        // Exempting a stale server is harmless — it only permits a little more.
        //
        // union the PERSISTED server IPs (from a prior
        // run) with the live in-memory cache, deduped. After a service restart the
        // in-memory cache is empty until the VPN reconnects, so without the seed
        // the block-all would have no server hole and could not arm; the persisted
        // set keeps the tunnel able to reconnect through the fail-closed block.
        let bootstrap_server_ips = {
            let mut seen = std::collections::HashSet::new();
            let mut ips: Vec<Ipv4Addr> = self
                .server_ip_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .values()
                .flatten()
                .copied()
                .filter(|ip| seen.insert(*ip))
                .collect();
            if let Some(loader) = self.server_ip_loader.as_ref() {
                ips.extend(loader().into_iter().filter(|ip| seen.insert(*ip)));
            }
            // Learned endpoints stay out here for the reason given in
            // `kill_switch_exemptions`: an address is not a client.
            ips
        };
        // The liveness probe's ICMP target: the secondary's RAW next-hop,
        // resolved WITHOUT the liveness gate. A probe-DEAD verdict empties the
        // gated resolution — which is exactly when the block-all arms — yet the
        // probe must keep reaching the next-hop or its verdict can never flip
        // back to healthy and the block-all never disarms. The echo is
        // kernel-originated (no app-id), so only this destination exemption
        // can cover it.
        let policy = self.route_source.load_for_sid(sid);
        let probe_target_ips = match resolution.secondary {
            Some(t) => vec![t.gateway],
            None => policy
                .as_ref()
                .and_then(|policy| {
                    let binding = policy.secondary.as_ref()?;
                    let infos = reading.adapters()?;
                    self.resolve_binding_target(sid, binding, infos, "secondary", Some(reading))
                })
                .map(|t| vec![t.gateway])
                .unwrap_or_default(),
        };
        // A peerless tunnel forwards on-link; there is no probe target to exempt.
        let probe_target_ips: Vec<Ipv4Addr> = probe_target_ips
            .into_iter()
            .filter(|ip| !ip.is_unspecified())
            .collect();
        let (bootstrap_server_ips_v6, mut local_subnets_v6) = v6_exemptions(
            &routes,
            resolution.primary,
            resolution.secondary.map(|s| s.interface_index),
        );
        local_subnets_v6.extend(self.opened_public_v6(
            sid,
            &routes,
            resolution.primary.map(|p| p.interface_index),
        ));
        let (foreign_tunnel_luids, foreign_tunnel_networks) = self.foreign_tunnels_of(
            &resolution,
            policy.as_ref(),
            table_read.then_some(routes.as_slice()),
            reading.adapters(),
        );
        // Ignores the user's refusals on purpose: a refused network is closed
        // to the machine's own traffic, while this opens only the replies
        // forwarded into a guest. An unreadable table names nothing, as no
        // uplink can then be told apart.
        let guest_network_luids = match (table_read, reading.adapters()) {
            (true, Some(adapters)) => {
                let resolved: Vec<u32> = resolution
                    .primary
                    .iter()
                    .chain(resolution.secondary.iter())
                    .map(|t| t.interface_index)
                    .collect();
                let ours = own_link_indexes(
                    adapters,
                    &resolved,
                    policy
                        .iter()
                        .flat_map(|p| p.primary.iter().chain(p.secondary.iter())),
                );
                guest_network_indexes(adapters, &routes, &ours)
                    .into_iter()
                    .filter_map(|index| {
                        self.api
                            .interface_luid_for_index(index)
                            .ok()
                            .filter(|luid| *luid != 0)
                    })
                    .collect()
            }
            _ => Vec::new(),
        };
        FailClosedExemptions {
            bootstrap_server_ips,
            bootstrap_server_ips_v6,
            local_subnets,
            local_subnets_v6,
            foreign_tunnel_luids,
            foreign_tunnel_networks,
            // the resolver has no rule/codegen context;
            // the orchestrator fills known-primary IPs at the block-all call site.
            primary_dest_ips: Vec::new(),
            // the resolver returns the strict default; the orchestrator
            // overrides this from the per-SID policy at the block-all call site.
            allow_dns_over_primary: false,
            dns_servers: Vec::new(),
            // the orchestrator resolves the tunnel and fills this at the
            // block-all call site; the resolver has no LUID context.
            secondary_luid: 0,
            probe_target_ips,
            guest_network_luids,
        }
    }
}

/// The host side of the machine's guest networks (WSL, Hyper-V, Docker
/// Desktop), the interfaces a forwarded reply leaves by to reach a guest. Only
/// a hypervisor adapter that is up and can be no way out qualifies: never a
/// link the user bound (`ours`), a tunnel, our own adapter, one with a gateway
/// or a default route, or one the table names the uplink. An external virtual
/// switch carries the internet itself, and a permit on it would let every
/// guest out.
pub(crate) fn guest_network_indexes(
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    ours: &[u32],
) -> Vec<u32> {
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    let uplinks = nrr_platform_api::uplink::structural_uplinks(adapters, routes, &[]);
    adapters
        .iter()
        .filter(|a| a.oper_status == IfOperStatus::Up && a.interface_type != InterfaceType::Tunnel)
        .filter(|a| nrr_platform_api::adapters::is_virtual_machine_adapter(a))
        .filter(|a| !nrr_platform_api::uplink::is_own_fake_ip_adapter(a))
        .filter(|a| !ours.contains(&a.index) && !uplinks.contains(&a.index))
        .filter(|a| !a.has_gateway())
        .filter(|a| {
            !routes
                .iter()
                .any(|r| r.interface_index == a.index && r.prefix_length == 0)
        })
        .map(|a| a.index)
        .collect()
}

/// The links a user's own routing runs on: what resolved this pass, and every
/// adapter the stored bindings name by identity or by display name. A binding
/// that did not resolve this pass (liveness-gated, no next hop) is still the
/// user's link, never somebody else's tunnel.
pub(crate) fn own_link_indexes<'a>(
    adapters: &[AdapterInfo],
    resolved: &[u32],
    bindings: impl IntoIterator<Item = &'a PerSidBinding>,
) -> Vec<u32> {
    let mut ours: Vec<u32> = resolved.to_vec();
    for binding in bindings {
        ours.extend(
            adapters
                .iter()
                .filter(|a| {
                    let named = !binding.display_name.is_empty()
                        && (a.friendly_name == binding.display_name
                            || a.adapter_name == binding.display_name);
                    named || binding_matches_live(a, &binding.stable_id, &binding.known_stable_ids)
                })
                .map(|a| a.index),
        );
    }
    ours.sort_unstable();
    ours.dedup();
    ours
}

/// Adapters that may keep their egress under a block-all as somebody else's
/// tunnel: usable, named like a tunnel, and not a link the machine's own
/// traffic leaves by.
///
/// A permit on the uplink is no kill-switch at all, and a name cannot tell
/// one from a tunnel: many providers deliver the internet itself over PPPoE,
/// and a user may bind a link called "OpenVPN" as the primary. So the links
/// ours are bound to (`ours`) never qualify, nor does our own fake-IP adapter,
/// nor a link the table names the way out (`structural_uplinks`): the sole
/// holder of a default route in its family or, with no holder left, the link
/// carrying our tunnel's route to its server. With two holders (the physical
/// link plus a corporate full tunnel) the table cannot say which is which, and
/// the name decides as before.
///
/// `additional` are the user's additional-route links (a subset of `ours`).
/// Their defaults are left out of the count: our full tunnel holds `/0` beside
/// an L2TP/PPTP/SSTP home uplink, and counted, it would leave that uplink
/// unnamed for its name to call foreign. A bound primary still counts, so a
/// corporate tunnel holding a default beside it stays foreign.
///
/// The name decision is `text_indicates_vpn_tunnel`, the same one that keeps
/// a tunnel from being mistaken for a hypervisor network.
pub(crate) fn foreign_tunnel_indexes(
    adapters: &[AdapterInfo],
    ours: &[u32],
    additional: &[u32],
    routes: &[RouteEntry],
) -> Vec<u32> {
    let mut never = nrr_platform_api::uplink::structural_uplinks(adapters, routes, additional);
    never.extend_from_slice(additional);
    tunnel_like_indexes(adapters, ours, &never)
}

/// [`foreign_tunnel_indexes`] when the route table is unreadable: no uplink
/// can be told apart, so every tunnel-looking link that is not ours counts.
pub(crate) fn foreign_tunnel_indexes_without_routes(
    adapters: &[AdapterInfo],
    ours: &[u32],
) -> Vec<u32> {
    tunnel_like_indexes(adapters, ours, &[])
}

fn tunnel_like_indexes(adapters: &[AdapterInfo], ours: &[u32], spared: &[u32]) -> Vec<u32> {
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    // Live means up with an address. Not `classify_availability`: it leaves
    // tunnel-typed links out by design, and on Linux every tunnel (`wg0`,
    // `tun0`) is one, so no foreign tunnel would ever be seen there.
    adapters
        .iter()
        .filter(|a| a.oper_status == IfOperStatus::Up && a.has_ipv4_address())
        .filter(|a| {
            !nrr_platform_api::adapters::description_matches_virtual_software(&a.description)
        })
        .filter(|a| !nrr_platform_api::uplink::is_own_fake_ip_adapter(a))
        .filter(|a| !ours.contains(&a.index) && !spared.contains(&a.index))
        .filter(|a| {
            a.interface_type == InterfaceType::Tunnel
                || nrr_platform_api::adapters::text_indicates_vpn_tunnel(&format!(
                    "{} {}",
                    a.description, a.friendly_name
                ))
        })
        .map(|a| a.index)
        .collect()
}

/// The IPv6 exemptions both postures share: the tunnel's `/128` endpoints and
/// the private part of the primary link's attached prefixes.
///
/// `secondary_ifindex` is only the redirect-overlay hint — a bootstrap host
/// route is recognised by its next hop, so an unresolved tunnel still yields
/// its endpoints.
fn v6_exemptions(
    routes: &[nrr_platform_api::types::RouteEntry],
    primary: Option<crate::route_coordinator::SecondaryRouteTarget>,
    secondary_ifindex: Option<u32>,
) -> (Vec<std::net::Ipv6Addr>, Vec<(std::net::Ipv6Addr, u8)>) {
    let Some(primary) = primary else {
        return (Vec::new(), Vec::new());
    };
    let gateway = crate::route_reconciler::primary_gateway_v6(routes, primary.interface_index);
    (
        crate::route_reconciler::bootstrap_server_ips_v6(
            routes,
            secondary_ifindex.unwrap_or(0),
            gateway,
        ),
        exemptible_local_subnets(routes, primary.interface_index).v6,
    )
}
