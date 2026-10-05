//! What a network rule's routes must respect on this machine: the tunnel's own
//! routes, the networks the interfaces sit on, and the tunnel's servers.
//!
//! Same inherent impl, split across files.

use std::net::IpAddr;

use super::*;
use crate::route_codegen::network_routes::NetworkRouteFacts;

impl SecondaryRouteCoordinator {
    /// The facts a submitted network rule is checked against
    /// ([`crate::route_codegen::network_routes::network_conflicts_with_links`]).
    ///
    /// Servers remembered from an earlier run count too: a rule accepted while
    /// the tunnel is down would otherwise seal its reconnect the moment it
    /// comes up. An unreadable table answers with no facts — the submission
    /// is not the place to fail on a transient read.
    pub fn network_route_facts(&self, sid: &str) -> NetworkRouteFacts {
        let resolution = self
            .last_resolution
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .copied()
            .unwrap_or_else(|| self.resolve(sid));
        match self.api.get_ip_forward_table() {
            Ok(routes) => {
                let routes = self.stamped_with_ownership(routes);
                self.network_facts_from(&resolution, &routes, true)
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    error = %e,
                    "route table could not be read; network rules are checked against no link facts",
                );
                NetworkRouteFacts::default()
            }
        }
    }

    /// The facts from one reading of the table. `remembered` adds the servers
    /// persisted by an earlier run, which costs a storage read — the
    /// submission check pays it, the reconcile does not.
    pub(super) fn network_facts_from(
        &self,
        resolution: &RouteResolution,
        routes: &[RouteEntry],
        remembered: bool,
    ) -> NetworkRouteFacts {
        let adapters = self.api.get_adapter_infos().unwrap_or_else(|e| {
            // Without adapters the attached networks are unknown; their own
            // routes are longer than any rule piece around them, so only a
            // rule INSIDE one loses its protection until the next read.
            tracing::warn!(
                target: "nrr::route-coordinator",
                error = %e,
                "adapters could not be read; network routes are planned without the attached networks",
            );
            Vec::new()
        });
        let tunnel = resolution.secondary.map(|s| s.interface_index);
        let servers = self.known_tunnel_servers(resolution, routes, remembered);
        NetworkRouteFacts::read(routes, &adapters, tunnel, servers)
    }

    /// Every tunnel server this coordinator knows: the live bootstrap routes,
    /// the ones cached across a reconnect, the learned ones, and (when asked)
    /// the persisted ones. Read-only — refreshing the caches is the
    /// kill-switch path's job.
    fn known_tunnel_servers(
        &self,
        resolution: &RouteResolution,
        routes: &[RouteEntry],
        remembered: bool,
    ) -> Vec<IpAddr> {
        let tunnel = resolution.secondary.map_or(0, |s| s.interface_index);
        let mut servers: Vec<IpAddr> =
            bootstrap_server_ips(routes, tunnel, resolution.primary.map(|p| p.gateway))
                .into_iter()
                .map(IpAddr::V4)
                .collect();
        if let Some(primary) = resolution.primary {
            let gateway =
                crate::route_reconciler::primary_gateway_v6(routes, primary.interface_index);
            servers.extend(
                crate::route_reconciler::bootstrap_server_ips_v6(routes, tunnel, gateway)
                    .into_iter()
                    .map(IpAddr::V6),
            );
        }
        servers.extend(
            self.server_ip_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .values()
                .flatten()
                .map(|ip| IpAddr::V4(*ip)),
        );
        if let Some(learned) = self.learned_vpn_endpoints.as_ref() {
            servers.extend(
                learned
                    .current(std::time::SystemTime::now())
                    .into_iter()
                    .map(IpAddr::V4),
            );
        }
        if remembered {
            if let Some(loader) = self.server_ip_loader.as_ref() {
                servers.extend(loader().into_iter().map(IpAddr::V4));
            }
        }
        servers
    }
}
