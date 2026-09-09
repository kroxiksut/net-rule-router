//! What must survive the cut.
//!
//! The kill-switch and fail-closed exemption sets: bootstrap server IPs,
//! local subnets, the addresses a tunnel needs to come back up. Both walk
//! the route table once and cache what they found, so a reconnect blip does
//! not drop an exemption — which is the whole reason they are written the
//! way they are.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl SecondaryRouteCoordinator {
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
    /// Enumerates the route table once for both the bootstrap-server-IP and
    /// the local-subnet derivations, and caches the last-known server IPs so a
    /// reconnect blip (bootstrap route briefly gone) does not drop the
    /// exemption.
    pub fn kill_switch_exemptions(&self, sid: &str) -> Option<KillSwitchResolution> {
        let resolution = self.resolve(sid);
        let secondary = resolution.secondary?;
        let secondary_luid = match self.api.interface_luid_for_index(secondary.interface_index) {
            Ok(l) if l != 0 => l,
            Ok(_) => return None,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    "kill-switch: could not resolve secondary LUID; staying off (fail-open): {e:?}",
                );
                return None;
            }
        };
        // An unreadable route table is not an empty one. Arming on the empty
        // reading gives a kill-switch with no LAN, no DHCP and no printers
        // exempted — and nothing in the log to say why. Same posture as the
        // LUID failure above: stay off and let the next tick try again.
        let routes = match self.api.get_ip_forward_table() {
            Ok(routes) => routes,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "kill-switch: route table could not be read, so the local-network exemptions are unknown; staying off (fail-open): {e:?}",
                );
                return None;
            }
        };
        let routes = self.stamped_with_ownership(routes);
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
            } else {
                cache.insert(secondary.interface_index, server_ips.clone());
                // write-through so the observed server
                // IPs survive a service restart (the catch-all kill-switch will
                // not arm without a server exemption). Best-effort; the closure
                // logs+swallows any storage error. Invoked outside the DB lock.
                if let Some(persist) = self.server_ip_persist.as_ref() {
                    persist(&server_ips);
                }
            }
        }
        let mut local_subnets = resolution
            .primary
            .map(|p| primary_local_subnets(&routes, p.interface_index))
            .unwrap_or_default();
        self.apply_local_network_policy(
            sid,
            &routes,
            Some(secondary.interface_index),
            &mut local_subnets,
        );
        // Reactive VPN-endpoint learning — fold in any role-verified server IP
        // learned from a kill-switch drop (deduped against the route-observed
        // set above), so the catch-all pair (and the mirrored per-IP subtract
        // in `per_sid_orchestrator`) exempt it exactly like an observed one.
        if let Some(learned) = self.learned_vpn_endpoints.as_ref() {
            for ip in learned.current(std::time::SystemTime::now()) {
                if !server_ips.contains(&ip) {
                    server_ips.push(ip);
                }
            }
        }
        Some(KillSwitchResolution {
            secondary_luid,
            bootstrap_server_ips: server_ips,
            local_subnets,
            foreign_tunnel_luids: self.foreign_tunnel_luids(Some(secondary.interface_index)),
        })
    }

    /// LUIDs of tunnels the user runs that are not our additional route.
    ///
    /// A machine can hold several: ours, and the corporate one the person
    /// needs for work. Cutting the second is the product breaking something
    /// it was never asked to manage, and from the outside it is
    /// indistinguishable from the corporate VPN failing on its own.
    ///
    /// Only tunnels, and only usable ones. The name decision is
    /// `text_indicates_vpn_tunnel`, the same one that keeps a tunnel from
    /// being mistaken for a hypervisor network — one notion of "this is a
    /// tunnel", not two.
    fn foreign_tunnel_luids(&self, secondary_index: Option<u32>) -> Vec<u64> {
        let Ok(adapters) = self.api.get_adapter_infos() else {
            return Vec::new();
        };
        adapters
            .iter()
            .filter(|a| Some(a.index) != secondary_index)
            .filter(|a| {
                nrr_platform_api::classify_availability(a)
                    == Some(nrr_platform_api::AdapterAvailability::Available)
            })
            .filter(|a| {
                nrr_platform_api::adapters::text_indicates_vpn_tunnel(&format!(
                    "{} {}",
                    a.description, a.friendly_name
                ))
            })
            .filter_map(|a| self.api.interface_luid_for_index(a.index).ok())
            .filter(|luid| *luid != 0)
            .collect()
    }

    /// exemptions for the **fail-closed** block-all path
    /// (mode B) when the secondary cannot be resolved. Unlike
    /// [`Self::kill_switch_exemptions`] this never returns `None`: the whole
    /// point is to arm a block-all even when the secondary is gone. It resolves the
    /// PRIMARY (the working link) independently and returns its connected
    /// subnets so the block-all keeps LAN / local manageability, plus any
    /// cached VPN-server IPs (best-effort) so the tunnel can reconnect.
    pub fn fail_closed_exemptions(&self, sid: &str) -> FailClosedExemptions {
        let resolution = self.resolve(sid);
        // Unlike the kill-switch path this one cannot decline: the block-all is
        // armed either way. So an unreadable table falls back to the last
        // subnets this link was seen with — the same reasoning as the VPN-server
        // cache below. A stale LAN exemption permits a little more; an empty one
        // cuts the user's own network with nothing in the log.
        let (routes, table_read) = match self.api.get_ip_forward_table() {
            Ok(routes) => (routes, true),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "fail-closed: route table could not be read; falling back to the last known local subnets: {e:?}",
                );
                (Vec::new(), false)
            }
        };
        let mut local_subnets = resolution
            .primary
            .map(|p| primary_local_subnets(&routes, p.interface_index))
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
                        sid = %sid,
                        subnets = local_subnets.len(),
                        "fail-closed: using the last known local subnets so the block-all keeps LAN reachable",
                    );
                }
            }
        }
        self.apply_local_network_policy(
            sid,
            &routes,
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
            // Reactive VPN-endpoint learning — fold in any role-verified
            // server IP learned from a kill-switch drop, deduped against the
            // cached/persisted set above (see `kill_switch_exemptions` for the
            // twin merge on the secondary-resolved path).
            if let Some(learned) = self.learned_vpn_endpoints.as_ref() {
                ips.extend(
                    learned
                        .current(std::time::SystemTime::now())
                        .into_iter()
                        .filter(|ip| seen.insert(*ip)),
                );
            }
            ips
        };
        // The liveness probe's ICMP target: the secondary's RAW next-hop,
        // resolved WITHOUT the liveness gate. A probe-DEAD verdict empties the
        // gated resolution — which is exactly when the block-all arms — yet the
        // probe must keep reaching the next-hop or its verdict can never flip
        // back to healthy and the block-all never disarms  HW
        // diagnosis). The echo is kernel-originated (no app-id), so only this
        // destination exemption can cover it.
        let probe_target_ips = match resolution.secondary {
            Some(t) => vec![t.gateway],
            None => self
                .route_source
                .load_for_sid(sid)
                .and_then(|policy| {
                    let binding = policy.secondary.as_ref()?;
                    let infos = self.api.get_adapter_infos().ok()?;
                    self.resolve_binding_target(sid, binding, &infos, "secondary")
                })
                .map(|t| vec![t.gateway])
                .unwrap_or_default(),
        };
        // A peerless tunnel forwards on-link; there is no probe target to exempt.
        let probe_target_ips: Vec<Ipv4Addr> = probe_target_ips
            .into_iter()
            .filter(|ip| !ip.is_unspecified())
            .collect();
        FailClosedExemptions {
            bootstrap_server_ips,
            local_subnets,
            foreign_tunnel_luids: self
                .foreign_tunnel_luids(resolution.secondary.map(|s| s.interface_index)),
            // the resolver has no rule/codegen context;
            // the orchestrator fills known-primary IPs at the block-all call site.
            primary_dest_ips: Vec::new(),
            // the resolver returns the strict default; the orchestrator
            // overrides this from the per-SID policy at the block-all call site.
            allow_dns_over_primary: false,
            // the orchestrator fills known-direct IPs at the block-all
            // call site (it owns the registry and the secondary-dest subtraction).
            known_direct_ips: Vec::new(),
            // the orchestrator resolves the tunnel and fills this at the
            // block-all call site; the resolver has no LUID context.
            secondary_luid: 0,
            probe_target_ips,
        }
    }
}
