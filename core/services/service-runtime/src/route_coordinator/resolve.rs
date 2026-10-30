//! Turning a stored binding into live OS identifiers — LUID, ifindex, source
//! address — and remembering the anchor that survives a rename.

use super::*;

/// How long a shared reading of the machine is trusted.
const MACHINE_MEMO_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// The state of the reading [`SecondaryRouteCoordinator::read_machine`] shares.
pub(super) enum MachineMemo {
    /// Every call reads: no pass has just finished.
    Off,
    /// A pass has finished; the next call reads and keeps the result.
    Armed,
    Held(std::time::Instant, MachineReading),
}

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
                    msg_key = "route-secondary-luid-zero",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    "secondary interface resolved to a zero LUID — kill-switch stays off (fail-open)",
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-secondary-luid-error",
                    sid = %sid,
                    ifindex = secondary.interface_index,
                    error = %e,
                    "could not resolve secondary interface LUID for kill-switch; staying off (fail-open)",
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
        // One enumeration for the resolution and the lookup: this runs on a
        // short tick for every user.
        let infos = self.adapters_now().ok()?;
        let target = self
            .resolve_inner(sid, None, Some(infos.as_slice()))
            .secondary?;
        let info = infos.iter().find(|i| i.index == target.interface_index)?;
        Some(crate::secondary_external_address::SecondaryLink {
            sid: sid.to_string(),
            interface_index: target.interface_index,
            source_ipv4: info.ipv4_addresses.first().copied()?,
            adapter_name: info.description.clone(),
            gateways: info.gateways.clone(),
        })
    }

    /// Interface index of the user's usable PRIMARY link, or `None` while it is
    /// unbound or unresolvable. Callers that must send over the link the policy
    /// routes traffic over — rather than over whichever link owns the OS default
    /// route — ask this.
    pub fn resolve_primary_interface_index(&self, sid: &str) -> Option<u32> {
        self.resolve(sid).primary.map(|t| t.interface_index)
    }

    /// Which link each of `sid`'s connections leaves through, against
    /// `machine`. A tunnel the liveness probe declared dead is still the link
    /// its sockets ride, so the bound secondary counts as theirs even then:
    /// otherwise its stranded connections would read as another link's and be
    /// spared.
    pub fn flow_links(
        &self,
        sid: &str,
        machine: &MachineReading,
    ) -> nrr_platform_api::fake_ip::stale_flows::FlowLinks {
        let Some(infos) = machine.adapters() else {
            return Default::default();
        };
        let r = self.resolve_from(sid, Some(machine));
        let secondary = r.secondary.map(|t| t.interface_index).or_else(|| {
            let policy = self.route_source.load_for_sid(sid)?;
            let binding = policy.secondary.as_ref()?;
            let primary = policy.primary.as_ref();
            self.resolve_binding_target(sid, binding, primary, infos, "secondary", Some(machine))
                .map(|t| t.interface_index)
        });
        nrr_platform_api::fake_ip::stale_flows::FlowLinks::from_adapters(
            infos,
            r.primary.map(|t| t.interface_index),
            secondary,
        )
    }

    /// The active user's primary/secondary egress SOURCE addresses (the
    /// adapters' own IPv4 unicast addresses), for binding sockets that must
    /// leave over a specific role's link — the fake-IP relay dials with these.
    /// A role yields `None` when it is unbound, unresolvable, or its adapter
    /// currently has no IPv4 address.
    pub fn resolve_egress_source_ips(&self, sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        let r = self.resolve(sid);
        let infos = match self.adapters_now() {
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

    /// Share the adapter list with the pass fingerprint: both re-read it only
    /// after `generation` moves. Returns the one cache.
    pub fn adapter_cache(
        &self,
        generation: nrr_platform_api::net_change::NetChangeGeneration,
    ) -> Arc<nrr_platform_api::net_change::ChangeCached<Vec<AdapterInfo>>> {
        let api = Arc::clone(&self.api);
        Arc::clone(self.adapter_cache.get_or_init(|| {
            Arc::new(nrr_platform_api::net_change::ChangeCached::new(
                generation,
                move || api.get_adapter_infos().ok(),
            ))
        }))
    }

    /// The adapters, from the cache while the network has not moved. Anything
    /// that is not the start of a pass reads this way.
    pub(super) fn adapters_now(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        match self.adapter_cache.get().and_then(|cache| cache.get()) {
            Some(adapters) => Ok(adapters),
            None => self.api.get_adapter_infos(),
        }
    }

    /// The adapters read past the cache, for the start of a pass: a pass
    /// asked for by a network event may run before the OS notice is counted,
    /// and must not plan from the list the event just outdated. The reading
    /// is kept, so the rest of the pass reads it back for free.
    pub(super) fn adapters_for_pass(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        match self.adapter_cache.get().and_then(|cache| cache.refresh()) {
            Some(adapters) => Ok(adapters),
            None => self.api.get_adapter_infos(),
        }
    }

    /// One reading of the links and the route table, for a pass that asks
    /// several of the questions below and must get one machine's answers.
    ///
    /// Right after a pass, the apply that follows asks several times (the plan,
    /// the unresolved-binding check): they share one reading, which a write of
    /// ours or the next pass drops.
    pub fn read_machine(&self) -> MachineReading {
        let mut memo = self.machine_memo.lock().unwrap_or_else(|p| p.into_inner());
        if let MachineMemo::Held(at, kept) = &*memo {
            if at.elapsed() < MACHINE_MEMO_TTL {
                return kept.clone();
            }
        }
        let reading = MachineReading::new(
            self.api.get_ip_forward_table(),
            self.adapters_now(),
            |route| self.reconciler.owns(route),
        );
        if !matches!(*memo, MachineMemo::Off) {
            *memo = MachineMemo::Held(std::time::Instant::now(), reading.clone());
        }
        reading
    }

    /// Our own write, or a pass about to start: what was read no longer holds.
    pub(super) fn drop_machine_memo(&self) {
        *self.machine_memo.lock().unwrap_or_else(|p| p.into_inner()) = MachineMemo::Off;
    }

    /// A pass has just finished: the next [`Self::read_machine`] reads, and the
    /// ones after it share that reading.
    pub(super) fn arm_machine_memo(&self) {
        *self.machine_memo.lock().unwrap_or_else(|p| p.into_inner()) = MachineMemo::Armed;
    }

    /// Resolve `sid`'s routing inputs (mode + primary/secondary targets) from
    /// its per-SID route policy and the live adapters. Logs WHY whenever a
    /// target can't be resolved, so "no route" is never a silent exit.
    pub(super) fn resolve(&self, sid: &str) -> RouteResolution {
        self.resolve_from(sid, None)
    }

    /// The sole default-route holder, by the name the interfaces list shows,
    /// from the pass's `reading` or the live machine.
    fn primary_suggestion(&self, reading: Option<&MachineReading>) -> Option<String> {
        let live;
        let adapters = match reading {
            Some(reading) => reading.adapters_or_error().ok()?,
            None => {
                live = self.adapters_now().ok()?;
                live.as_slice()
            }
        };
        let routes = self.routes_of(reading)?;
        crate::routing_setup::primary_suggestion(adapters, &routes)
    }

    /// [`Self::resolve`] against a pass's `reading`, or the live machine when
    /// there is none.
    pub(super) fn resolve_from(
        &self,
        sid: &str,
        reading: Option<&MachineReading>,
    ) -> RouteResolution {
        self.resolve_inner(sid, reading, None)
    }

    /// [`Self::resolve_from`] over `adapters` the caller has just enumerated,
    /// so a caller that needs them afterwards reads them once.
    pub(super) fn resolve_inner(
        &self,
        sid: &str,
        reading: Option<&MachineReading>,
        adapters: Option<&[AdapterInfo]>,
    ) -> RouteResolution {
        let Some(policy) = self.route_source.load_for_sid(sid) else {
            self.clear_no_secondary(sid);
            if self.note_no_policy_once(sid) {
                tracing::info!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-no-policy-for-user",
                    sid = %sid,
                    "no route policy for this user — no secondary routes will be applied",
                );
            }
            // From outside this is indistinguishable from a working product: the
            // service runs, the tray is green, and nothing is routed — without
            // this push the user has no way to see it. It names the connection
            // to confirm as main when the route table points at exactly one.
            let suggestion = self.primary_suggestion(reading);
            self.publish_enforcement_status(sid, "no-policy", "", suggestion.into_iter().collect());
            return RouteResolution {
                mode: RouteBehaviorMode::PreferPrimary,
                primary: None,
                secondary: None,
            };
        };
        self.clear_no_policy(sid);
        let mode = behavior_mode_for_codegen(&policy);
        let live;
        let infos = match (adapters, reading) {
            (Some(known), _) => Ok(known),
            (None, Some(reading)) => reading.adapters_or_error(),
            (None, None) => {
                live = self.adapters_now();
                live.as_deref()
            }
        };
        let infos = match infos {
            Ok(i) => i,
            Err(e) => {
                self.publish_enforcement_status(sid, "adapters-unreadable", "", Vec::new());
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-adapter-enum-failed",
                    sid = %sid,
                    error = %e,
                    "adapter enumeration failed; cannot resolve route targets",
                );
                return RouteResolution {
                    mode,
                    primary: None,
                    secondary: None,
                };
            }
        };
        self.clear_machine_wide_enforcement_status(sid);
        let secondary = match policy.secondary.as_ref() {
            Some(b) => {
                self.clear_no_secondary(sid);
                let raw = self.resolve_binding_target(
                    sid,
                    b,
                    policy.primary.as_ref(),
                    infos,
                    "secondary",
                    reading,
                );
                self.gate_secondary_on_liveness(sid, raw)
            }
            None => {
                if self.note_no_secondary_once(sid) {
                    tracing::warn!(
                        target: "nrr::route-coordinator",
                        msg_key = "route-no-secondary-bound",
                        sid = %sid,
                        "NO SECONDARY ADAPTER BOUND — assign primary+secondary in 'Connections' and apply (needs elevation). Without a secondary target nothing is routed out the secondary NIC.",
                    );
                }
                self.offer_unassigned_tunnel(sid, infos);
                None
            }
        };
        // Primary carries mode-A's `/2` counter-overlay (unmatched → real link,
        // not the tunnel) and mode-B's exception `/32`s.
        let mut primary = policy.primary.as_ref().and_then(|b| {
            self.resolve_binding_target(
                sid,
                b,
                policy.secondary.as_ref(),
                infos,
                "primary",
                reading,
            )
        });
        // Footgun fix: the common setup binds ONLY the secondary (VPN). Without
        // a primary, mode A's counter-overlay can't be emitted and unmatched
        // traffic silently rides the VPN's redirect. Derive the real primary
        // from the OS default route so "direct" actually routes direct.
        if primary.is_none() {
            if let Some(sec) = secondary.as_ref() {
                let routes = self.routes_of(reading).unwrap_or_default();
                let foreign_tunnels = super::exemptions::foreign_tunnel_indexes(
                    infos,
                    &[sec.interface_index],
                    &[sec.interface_index],
                    &routes,
                );
                match derive_primary_target(&routes, sec.interface_index, &foreign_tunnels) {
                    Some(derived) => {
                        // The derive repeats on every resolve; only a change is news.
                        if self.note_primary_derived_once(
                            sid,
                            derived.interface_index,
                            derived.gateway,
                        ) {
                            tracing::info!(
                                target: "nrr::route-coordinator",
                                msg_key = "route-primary-derived",
                                sid = %sid,
                                ifindex = derived.interface_index,
                                gateway = %derived.gateway,
                                "no primary adapter bound — derived the primary from the OS default route (unmatched traffic will egress the real link, not the tunnel)",
                            );
                        }
                        primary = Some(derived);
                    }
                    None => {
                        tracing::warn!(
                            target: "nrr::route-coordinator",
                            msg_key = "route-no-primary-derivable",
                            sid = %sid,
                            secondary_ifindex = sec.interface_index,
                            "no primary adapter bound and no OS default route to derive one — in 'direct' mode unmatched traffic stays on the secondary (VPN). Bind a primary adapter in 'Connections'.",
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
        // Off the pass's own reading only: a resolve without one would have to
        // read the table just to say this, and the next pass will.
        if let (Some(p), Some(routes)) = (primary, reading.and_then(|r| r.routes())) {
            self.warn_too_wide_local_networks(sid, routes, infos, p.interface_index);
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
            msg_key = "route-mac-anchor-remembered",
            sid = %sid,
            role = role,
            anchor = %anchor,
            adapter = %preferred_display_name(info),
            "remembered the adapter's MAC as a second identity for this binding",
        );
        persist(sid, role, &anchor);
    }
}
