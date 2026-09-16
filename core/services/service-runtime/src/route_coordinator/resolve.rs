//! Turning a stored binding into live OS identifiers — LUID, ifindex, source
//! address — and remembering the anchor that survives a rename.

use super::*;

impl SecondaryRouteCoordinator {
    /// resolve the secondary (VPN)
    /// interface LUID for `sid`, or `None` when there is no usable secondary
    /// target right now or its LUID cannot be resolved.
    ///
    /// The WFP kill-switch pins this LUID as the egress condition of its
    /// permit half (`FWPM_CONDITION_IP_LOCAL_INTERFACE`). Returning `None`
    /// makes the orchestrator fail **open** (no kill-switch this cycle)
    /// rather than installing a permit whose interface never matches —
    /// which would black-hole the protected set. Reuses [`Self::resolve`],
    /// so the "no secondary" reason is already logged there.
    pub fn resolve_secondary_luid(&self, sid: &str) -> Option<u64> {
        let secondary = self.resolve(sid).secondary?;
        match self.api.interface_luid_for_index(secondary.interface_index) {
            Ok(luid) if luid != 0 => Some(luid),
            Ok(_) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    "secondary interface resolved to a zero LUID — kill-switch stays off (fail-open)",
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    "could not resolve secondary interface LUID for kill-switch; staying off (fail-open): {e:?}",
                );
                None
            }
        }
    }

    /// the active user's primary/secondary
    /// egress interface indexes, for labelling observed connections
    /// (primary = direct/provider, secondary = VPN). Reuses [`Self::resolve`];
    /// a role yields `None` when it is unbound / unresolvable.
    pub fn resolve_egress_ifindexes(&self, sid: &str) -> (Option<u32>, Option<u32>) {
        let r = self.resolve(sid);
        (
            r.primary.map(|t| t.interface_index),
            r.secondary.map(|t| t.interface_index),
        )
    }

    /// `sid`'s usable additional link, in the shape the external-address
    /// announcer consumes: interface index, the adapter's own IPv4 (what a
    /// source-bound probe socket binds to) and its human-readable description.
    ///
    /// Reuses [`Self::resolve`] so "usable" means exactly what it means
    /// everywhere else — including the liveness gate: a tunnel the probe has
    /// declared dead is not a link whose external address is worth reporting.
    /// `None` while the secondary is unbound, unresolvable or has no IPv4.
    pub fn resolve_secondary_link(
        &self,
        sid: &str,
    ) -> Option<crate::secondary_external_address::SecondaryLink> {
        let target = self.resolve(sid).secondary?;
        let infos = self.api.get_adapter_infos().ok()?;
        let info = infos.iter().find(|i| i.index == target.interface_index)?;
        Some(crate::secondary_external_address::SecondaryLink {
            sid: sid.to_string(),
            interface_index: target.interface_index,
            source_ipv4: info.ipv4_addresses.first().copied()?,
            adapter_name: info.description.clone(),
        })
    }

    /// The active user's primary/secondary egress SOURCE addresses (the
    /// adapters' own IPv4 unicast addresses), for binding sockets that must
    /// leave over a specific role's link — the fake-IP relay dials with these.
    /// A role yields `None` when it is unbound, unresolvable, or its adapter
    /// currently has no IPv4 address.
    /// Interface index of the user's usable PRIMARY link, or `None` while it is
    /// unbound or unresolvable. Callers that must send over the link the policy
    /// routes traffic over — rather than over whichever link owns the OS default
    /// route — ask this.
    pub fn resolve_primary_interface_index(&self, sid: &str) -> Option<u32> {
        self.resolve(sid).primary.map(|t| t.interface_index)
    }

    pub fn resolve_egress_source_ips(&self, sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        let r = self.resolve(sid);
        let infos = match self.api.get_adapter_infos() {
            Ok(infos) => infos,
            Err(_) => return (None, None),
        };
        let source_of = |target: Option<SecondaryRouteTarget>| {
            target.and_then(|t| {
                infos
                    .iter()
                    .find(|i| i.index == t.interface_index)
                    .and_then(|i| i.ipv4_addresses.first().copied())
            })
        };
        (source_of(r.primary), source_of(r.secondary))
    }

    /// Resolve `sid`'s routing inputs (mode + primary/secondary targets) from
    /// its per-SID route policy and the live adapters. Logs WHY whenever a
    /// target can't be resolved — these silent exits once made the route side
    /// invisible in the log when "no route" was reported.
    pub(super) fn resolve(&self, sid: &str) -> RouteResolution {
        let Some(policy) = self.route_source.load_for_sid(sid) else {
            tracing::info!(
                target: "nrr::route-coordinator",
                sid = %sid,
                "no route policy for this user — no secondary routes will be applied",
            );
            // From outside this is indistinguishable from a working product: the
            // service runs, the tray is green, and nothing is routed. Acceptance
            // run 19 spent ten minutes in exactly this state (339 log lines, zero
            // filters) with no way for the user to see it.
            self.publish_enforcement_status(sid, "no-policy", "", Vec::new());
            return RouteResolution {
                mode: RouteBehaviorMode::PreferPrimary,
                primary: None,
                secondary: None,
            };
        };
        let mode = route_behavior_mode(policy.mode);
        let infos = match self.api.get_adapter_infos() {
            Ok(i) => i,
            Err(e) => {
                self.publish_enforcement_status(sid, "adapters-unreadable", "", Vec::new());
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "adapter enumeration failed; cannot resolve route targets: {e:?}",
                );
                return RouteResolution {
                    mode,
                    primary: None,
                    secondary: None,
                };
            }
        };
        let secondary = match policy.secondary.as_ref() {
            Some(b) => {
                let raw = self.resolve_binding_target(sid, b, &infos, "secondary");
                self.gate_secondary_on_liveness(sid, raw)
            }
            None => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "NO SECONDARY ADAPTER BOUND — assign primary+secondary in 'Interfaces & routes' and apply (needs elevation). Without a secondary target nothing is routed out the secondary NIC.",
                );
                self.offer_unassigned_tunnel(sid, &infos);
                None
            }
        };
        // Primary carries mode-A's `/2` counter-overlay (unmatched → real link,
        // not the tunnel) and mode-B's exception `/32`s.
        let mut primary = policy
            .primary
            .as_ref()
            .and_then(|b| self.resolve_binding_target(sid, b, &infos, "primary"));
        // Footgun fix: the common setup binds ONLY the secondary (VPN). Without
        // a primary, mode A's counter-overlay can't be emitted and unmatched
        // traffic silently rides the VPN's redirect. Derive the real primary
        // from the OS default route so "direct" actually routes direct.
        if primary.is_none() {
            if let Some(sec) = secondary.as_ref() {
                let routes = self.api.get_ip_forward_table().unwrap_or_default();
                match derive_primary_target(&routes, sec.interface_index) {
                    Some(derived) => {
                        tracing::info!(
                            target: "nrr::route-coordinator",
                            sid = %sid,
                            ifindex = derived.interface_index,
                            gateway = %derived.gateway,
                            "no primary adapter bound — derived the primary from the OS default route (unmatched traffic will egress the real link, not the tunnel)",
                        );
                        primary = Some(derived);
                    }
                    None => {
                        tracing::warn!(
                            target: "nrr::route-coordinator",
                            sid = %sid,
                            secondary_ifindex = sec.interface_index,
                            "no primary adapter bound and no OS default route to derive one — in 'direct' mode unmatched traffic stays on the secondary (VPN). Bind a primary adapter in 'Interfaces & routes'.",
                        );
                        // Nothing the service can do about this one: without a
                        // main link there is nowhere to send what the rules do
                        // not route, so the user has to name one.
                        self.publish_enforcement_status(
                            sid,
                            "no-primary-route",
                            "primary",
                            Vec::new(),
                        );
                    }
                }
            }
        }
        RouteResolution {
            mode,
            primary,
            secondary,
        }
    }

    /// Teach the binding the MAC of the adapter it just resolved to, so a later
    /// GUID and ifindex change (Wi-Fi or Bluetooth after sleep, a NIC that came
    /// back on another port) is recognised directly instead of relying on the
    /// name heal — which needs the name to be both unchanged and unique.
    ///
    /// Skipped for adapters whose MAC rotates with their GUID (see
    /// [`mac_anchor_id`]) and for a binding that already knows it, so the steady
    /// state costs one string compare per reconcile and no write.
    pub(super) fn remember_mac_anchor(
        &self,
        sid: &str,
        role: &str,
        binding: &PerSidBinding,
        info: &AdapterInfo,
    ) {
        let Some(anchor) = mac_anchor_id(info) else {
            return;
        };
        if binding.stable_id.eq_ignore_ascii_case(&anchor)
            || binding
                .known_stable_ids
                .iter()
                .any(|id| id.eq_ignore_ascii_case(&anchor))
        {
            return;
        }
        let Some(persist) = self.binding_anchor_persist.as_ref() else {
            return;
        };
        if !self.note_anchor_once(sid, role, &anchor) {
            return;
        }
        tracing::info!(
            target: "nrr::route-coordinator",
            sid = %sid,
            role = role,
            anchor = %anchor,
            adapter = %preferred_display_name(info),
            "remembered the adapter's MAC as a second identity for this binding",
        );
        persist(sid, role, &anchor);
    }
}
