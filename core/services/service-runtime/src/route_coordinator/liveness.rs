//! Is the additional link actually carrying traffic? The probe, the gate it
//! feeds, and the first-contact route that beats the DNS answer.

use super::*;

impl SecondaryRouteCoordinator {
    /// active-probe liveness gate on the SECONDARY only
    /// (never the primary — the real link must never be probed / fail-closed).
    /// If the tunnel next-hop has been UNREACHABLE for the whole configured
    /// window, treat the secondary as unresolved so routes tear down and the
    /// kill-switch fail-closes — even though the adapter still enumerates
    /// Up+IPv4 (the dead-but-Up case route-table inspection can't catch, since
    /// NetRuleRouter owns/mutates the table). Disabled (window 0) → `is_dead` is
    /// always false → returns the raw target unchanged (no behaviour change).
    pub(super) fn gate_secondary_on_liveness(
        &self,
        sid: &str,
        raw: Option<SecondaryRouteTarget>,
    ) -> Option<SecondaryRouteTarget> {
        match raw {
            Some(t) if self.liveness.is_dead(t.interface_index, Instant::now()) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = t.interface_index,
                    next_hop = %t.gateway,
                    window_secs = self.liveness.window_secs(),
                    "secondary tunnel next-hop UNREACHABLE for the whole liveness window — treating the secondary as DEAD (kill-switch fail-closed), even though the adapter is still Up+IPv4",
                );
                None
            }
            other => other,
        }
    }

    /// probe each active user's bound secondary tunnel
    /// next-hop and feed the reachability result to the liveness tracker. Driven
    /// by the `secondary-liveness-tick` at a fast cadence while a secondary is
    /// bound. No-op when the feature is disabled (window 0) or no probe is wired.
    /// Uses the RAW resolution (NOT the liveness gate) so a currently-dead tunnel
    /// is still probed and can RECOVER once it answers again.
    pub fn probe_active_secondaries(&self, sids: &[String]) {
        if !self.liveness.enabled() {
            return;
        }
        let Some(probe) = self.reachability_probe.as_ref() else {
            return;
        };
        let infos = match self.api.get_adapter_infos() {
            Ok(i) => i,
            Err(_) => return,
        };
        for sid in sids {
            let Some(policy) = self.route_source.load_for_sid(sid) else {
                continue;
            };
            let Some(binding) = policy.secondary.as_ref() else {
                continue;
            };
            match self.resolve_binding_target(sid, binding, &infos, "secondary") {
                Some(t) => {
                    // A tunnel adapter that is recreated comes back under a NEW
                    // ifindex, and the liveness window is keyed by index. Left
                    // alone, the old index keeps whatever it had accumulated
                    // (nobody probes it again to clear it), and — worse — the
                    // new index may be one an unrelated adapter already filled
                    // with failures, which would declare a healthy tunnel dead
                    // on its first probe. Same reasoning as the `None` arm
                    // below: a different interface must re-prove its baseline.
                    let replaced = self
                        .probed_ifindex
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(sid.clone(), t.interface_index);
                    if let Some(old) = replaced.filter(|old| *old != t.interface_index) {
                        self.liveness.forget(old);
                        self.liveness.forget(t.interface_index);
                    }
                    // A peerless tunnel (on-link forwarding) has no next-hop to
                    // echo; an echo to 0.0.0.0 would fail every time and declare
                    // a working link dead. Nothing is recorded, so the window
                    // stays empty and the gate stays open.
                    if t.gateway.is_unspecified() {
                        continue;
                    }
                    let reachable = probe.is_reachable(t.gateway, LIVENESS_PROBE_TIMEOUT);
                    self.liveness
                        .record(t.interface_index, reachable, Instant::now());
                }
                None => {
                    // The bound secondary is unprobeable right now (adapter
                    // down / no IPv4 / no next-hop — a VPN mid-reconnect).
                    // Whatever failing run was accumulating no longer measures
                    // this tunnel: drop it, or the stale window declares the
                    // adapter DEAD the instant it comes back Up and the
                    // kill-switch fail-closes a freshly-reconnected tunnel
                    //  HW). The interface must re-prove its
                    // reachability baseline after it returns.
                    let forgotten = self
                        .probed_ifindex
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(sid);
                    if let Some(old) = forgotten {
                        self.liveness.forget(old);
                    }
                }
            }
        }
    }

    /// The routes `sid`'s rule book asks for under `resolution` — the one
    /// lowering a full recompute and a first-contact install share, so the two
    /// cannot disagree about an address.
    pub(super) fn planned_routes(
        &self,
        sid: &str,
        resolution: &RouteResolution,
        secondary: &SecondaryRouteTarget,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        tunnel_catch_alls: &[(Ipv4Addr, u8)],
    ) -> crate::route_codegen::RouteCodegenOutput {
        // shared-IP denylist from the same enforcement rule
        // book + live cache, keyed on this SID's policy, so the route table and
        // the WFP set decline the same shared IPs.
        let stored_policy = self.route_source.load_for_sid(sid);
        let shared_ip_policy = stored_policy
            .as_ref()
            .map(|p| p.shared_ip_policy)
            .unwrap_or_default();
        // Zone-vs-exact-address order comes from the same stored policy: the
        // routes and the filters must arbitrate one address identically.
        let zone_order = crate::address_ownership::ZoneVsIpOrder::from_zone_priority_over_ip(
            stored_policy
                .as_ref()
                .is_some_and(|p| p.zone_priority_over_ip),
        );
        let denied = crate::secondary_ip_policy::secondary_ip_denylist(
            &rule_book.secondary,
            self.fqdn_cache.as_ref(),
            shared_ip_policy,
        );
        generate_routes(
            resolution.mode,
            rule_book,
            resolution.primary.as_ref(),
            secondary,
            self.fqdn_cache.as_ref(),
            self.app_observations.as_ref(),
            &denied,
            zone_order,
            tunnel_catch_alls,
        )
    }

    pub(super) fn remember_resolution(&self, sid: &str, resolution: &RouteResolution) {
        let mut last = self
            .last_resolution
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if resolution.secondary.is_some() {
            last.insert(sid.to_string(), *resolution);
        } else {
            last.remove(sid);
        }
    }

    /// Routes `addresses` now, the way the next full recompute for `sid` will,
    /// so a rule host's first connect to a new address leaves through the link
    /// its rule names instead of racing that recompute. Plans from the
    /// resolution the last recompute used — nothing enumerates adapters on the
    /// DNS path — and installs only the `/32`s the planner asks for these
    /// addresses: one it declines (a shared address, a main-link claim) stays
    /// unrouted. Returns how many of `addresses` now have their route.
    pub fn route_first_contact(&self, sid: &str, addresses: &[Ipv4Addr]) -> usize {
        if addresses.is_empty() {
            return 0;
        }
        let Some(resolution) = self
            .last_resolution
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .copied()
        else {
            return 0;
        };
        let Some(secondary) = resolution.secondary else {
            return 0;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(sid) else {
            return 0;
        };
        let wanted: Vec<RouteEntry> = self
            .planned_routes(sid, &resolution, &secondary, &snapshot.rule_book, &[])
            .routes
            .into_iter()
            .filter(|r| {
                r.prefix_length == 32
                    && matches!(r.destination, std::net::IpAddr::V4(d) if addresses.contains(&d))
            })
            .collect();
        if wanted.is_empty() {
            return 0;
        }
        match self.reconciler.install_additional(&wanted) {
            Ok(_) => wanted.len(),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    error = ?e,
                    "first-contact routes did not install — the next recompute adds them",
                );
                0
            }
        }
    }
}
