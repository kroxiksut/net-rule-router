//! What sits behind each link: local subnets, unassigned tunnels, the policy
//! that decides which of them stay reachable, and the status the GUI reads.

use super::*;

impl SecondaryRouteCoordinator {
    /// The subnets that belong to the ADDITIONAL route itself — the tunnel's own
    /// interior.
    ///
    /// Read by the fake-IP answerer, which must never substitute a virtual
    /// address for one of these: they are reachable only from inside the tunnel,
    /// and a virtual address would send the caller to our TUN instead (the VPN
    /// client's own authorization endpoint is exactly such an address).
    pub fn publish_secondary_subnets(&self, sid: &str) {
        crate::secondary_subnets::global_secondary_subnets()
            .publish(self.secondary_local_networks(sid));
    }

    pub fn secondary_local_networks(&self, sid: &str) -> Vec<Ipv4Network> {
        let Some(secondary) = self.resolve(sid).secondary else {
            return Vec::new();
        };
        let routes = match self.api.get_ip_forward_table() {
            Ok(routes) => routes,
            Err(e) => {
                // Silence here reads downstream as "this link has no local
                // networks", which is a different statement entirely.
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "route table could not be read; reporting no local networks for the additional link: {e:?}",
                );
                return Vec::new();
            }
        };
        primary_local_subnets(&routes, secondary.interface_index)
            .into_iter()
            .filter_map(|(net, prefix)| Ipv4Network::new(net, prefix))
            .collect()
    }

    /// The local networks this principal's kill-switch can discover on its own:
    /// the main link's connected subnets and the host side of hypervisor
    /// adapters, each with the adapter it belongs to and whether it is the main
    /// link's. The settings screen lists exactly this, so what the user ticks
    /// and what the enforcement exempts are derived from one enumeration.
    pub fn discovered_local_networks(&self, sid: &str) -> Vec<(Ipv4Network, String, bool)> {
        let resolution = self.resolve(sid);
        let routes = match self.api.get_ip_forward_table() {
            Ok(routes) => routes,
            Err(e) => {
                // The settings screen lists exactly this, so an empty answer is
                // an empty screen. Say why rather than showing the user a
                // machine that appears to have no local networks.
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    sid = %sid,
                    "route table could not be read; the local-networks screen will show nothing: {e:?}",
                );
                return Vec::new();
            }
        };
        let Ok(adapters) = self.api.get_adapter_infos() else {
            return Vec::new();
        };
        let name_of = |ifindex: u32| {
            adapters
                .iter()
                .find(|info| info.index == ifindex)
                .map(|info| preferred_display_name(info).to_string())
                .unwrap_or_default()
        };
        let mut out: Vec<(Ipv4Network, String, bool)> = Vec::new();
        if let Some(primary) = resolution.primary {
            for (net, prefix) in primary_local_subnets(&routes, primary.interface_index) {
                if let Some(network) = Ipv4Network::new(net, prefix) {
                    out.push((network, name_of(primary.interface_index), true));
                }
            }
        }
        for info in adapters
            .iter()
            .filter(|info| Some(info.index) != resolution.secondary.map(|s| s.interface_index))
            .filter(|info| nrr_platform_api::adapters::is_virtual_machine_adapter(info))
        {
            for (net, prefix) in primary_local_subnets(&routes, info.index) {
                let Some(network) = Ipv4Network::new(net, prefix) else {
                    continue;
                };
                if out.iter().any(|(found, _, _)| *found == network) {
                    continue;
                }
                out.push((network, preferred_display_name(info).to_string(), false));
            }
        }
        out
    }

    /// Settle which LOCAL networks stay reachable while the kill-switch blocks
    /// everything else.
    ///
    /// A kill-switch exists to stop traffic escaping to the provider instead of
    /// the tunnel. Traffic to a hypervisor's host-only segment never leaves
    /// this machine, so blocking it protects nothing and takes the user's
    /// virtual machines away with the tunnel. The tunnel's own subnet is
    /// excluded, and a VPN adapter is never mistaken for a hypervisor one —
    /// both live in RFC1918 space, and that is exactly the confusion this must
    /// not make.
    ///
    /// The user has the last word in both directions: a network they named
    /// themselves is added (a hypervisor in NAT mode creates no host interface,
    /// so nothing here can discover it), and a network they refused is removed
    /// even if it was discovered automatically.
    /// Mark the rows the reconciler knows are ours.
    ///
    /// The route-table FFI cannot tell — it reports `is_ours = false` for
    /// everything — and the classifier's very first question is exactly that.
    /// Without the stamp our own mode-B exception routes (a `/32` pulled back
    /// to the primary NIC, so via the primary gateway) look precisely like a
    /// VPN's bootstrap host route: they were collected as "VPN server IPs",
    /// exempted from the block-all forever, and cached under the secondary's
    /// ifindex so they outlived the rules that created them.
    pub(super) fn stamped_with_ownership(&self, mut routes: Vec<RouteEntry>) -> Vec<RouteEntry> {
        for route in &mut routes {
            if !route.is_ours && self.reconciler.owns(route) {
                route.is_ours = true;
            }
        }
        routes
    }

    pub(super) fn apply_local_network_policy(
        &self,
        sid: &str,
        routes: &[RouteEntry],
        secondary_ifindex: Option<u32>,
        out: &mut Vec<(Ipv4Addr, u8)>,
    ) {
        let adapters = self.api.get_adapter_infos().unwrap_or_default();
        for subnet in crate::route_reconciler::virtual_machine_local_subnets(
            routes,
            &adapters,
            secondary_ifindex,
        ) {
            if !out.contains(&subnet) {
                out.push(subnet);
            }
        }
        let Some(policy) = self.local_networks.as_ref().map(|read| read(sid)) else {
            return;
        };
        // An answer was given about an ADAPTER, so it carries over to whatever
        // segment that adapter holds now. A refusal outranks a confirmation
        // through the retain below, which is the direction that never reopens
        // something the user closed.
        let mut allowed = policy.allowed.clone();
        let mut refused = policy.refused.clone();
        for (adapter, allow) in &policy.adapter_answers {
            for info in adapters
                .iter()
                .filter(|info| preferred_display_name(info) == adapter)
            {
                for (net, prefix) in primary_local_subnets(routes, info.index) {
                    let Some(network) = Ipv4Network::new(net, prefix) else {
                        continue;
                    };
                    if *allow {
                        allowed.push(network);
                    } else {
                        refused.push(network);
                    }
                }
            }
        }
        for network in &allowed {
            let pair = (network.network(), network.prefix_len());
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
        // Compared as NETWORKS, not as pairs: the route table and the user's
        // text can spell the same network differently.
        out.retain(|(net, prefix)| {
            Ipv4Network::new(*net, *prefix).is_none_or(|candidate| !refused.contains(&candidate))
        });
    }

    /// Tell subscribers whether this SID's policy is in force, and what to do
    /// when it is not. Published on CHANGE only: the resolve runs at reconcile
    /// cadence and an unchanged state is not news.
    /// Tell the user a tunnel is up while nothing is bound to the additional
    /// route — the setup where every rule that names the additional route
    /// silently does nothing, which reads as the product being broken.
    ///
    /// A corporate client is left alone: it usually belongs to an employer and
    /// is not a candidate for the additional route. See
    /// [`StatusUpdateEvent::UnassignedTunnelDetected`] for why the ambiguous,
    /// protocol-named clients count as personal.
    pub(super) fn offer_unassigned_tunnel(
        &self,
        sid: &str,
        infos: &[nrr_platform_api::adapters::AdapterInfo],
    ) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        let Some(name) = personal_tunnel_name(infos) else {
            return;
        };
        let key = format!("{sid}|{name}");
        let now = std::time::Instant::now();
        {
            let mut seen = self
                .unassigned_tunnel_notified
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(last) = seen.get(&key) {
                if now.duration_since(*last) < std::time::Duration::from_secs(24 * 60 * 60) {
                    return;
                }
            }
            seen.insert(key, now);
        }
        bus.publish_for(
            sid,
            nrr_shared::ipc_payloads::StatusUpdateEvent::UnassignedTunnelDetected {
                sid: sid.to_string(),
                adapter_name: name,
            },
        );
    }

    pub(super) fn publish_enforcement_status(
        &self,
        sid: &str,
        status: &str,
        role: &str,
        candidates: Vec<String>,
    ) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        // Keyed by role: one user can have a resolved secondary and a missing
        // primary at the same time, and a single per-SID latch made the two
        // states overwrite each other into an endless alternating push.
        let key = format!("{sid}|{role}");
        let fingerprint = format!("{status}|{}", candidates.join(","));
        {
            let mut seen = self
                .enforcement_status
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if seen.get(&key) == Some(&fingerprint) {
                return;
            }
            seen.insert(key, fingerprint);
        }
        bus.publish_for(
            sid,
            nrr_shared::ipc_payloads::StatusUpdateEvent::EnforcementStatusChanged {
                sid: sid.to_string(),
                status: status.to_string(),
                role: role.to_string(),
                candidates,
            },
        );
    }

    /// Resolve one route binding (primary or secondary) to a
    /// [`SecondaryRouteTarget`] against live `infos`. `None` when the bound
    /// adapter is missing, unusable, or has no gateway and no derivable
    /// next-hop. `role` ("primary"/"secondary") only labels the diagnostics.
    pub(super) fn resolve_binding_target(
        &self,
        sid: &str,
        binding: &PerSidBinding,
        infos: &[AdapterInfo],
        role: &str,
    ) -> Option<SecondaryRouteTarget> {
        // Granular resolution so the log names the EXACT reason: not-found
        // (id mismatch), down/no-IP, or up-but-no-gateway.
        // resolve by id, but only ACCEPT the by-id match when it is
        // actually usable (Available = up + IPv4). A found-but-DOWN bound adapter
        // (a GUID-churning VPN like swiftvpn can leave a stale/down TAP instance
        // enumerated while the freshly-connected one carries traffic) must NOT short-
        // circuit to fail-closed — it falls into the same name-heal below so we can
        // adopt a live same-name SIBLING. If the bound adapter is genuinely down with
        // no live sibling, the heal finds nothing and we still fail closed (correct).
        let by_id = infos
            .iter()
            .find(|i| binding_matches_live(i, &binding.stable_id, &binding.known_stable_ids));
        let info = match by_id
            .filter(|i| classify_availability(i) == Some(AdapterAvailability::Available))
        {
            Some(i) => i,
            None => {
                // Auto-heal: the stored GUID is gone (VPN reinstall/upgrade — same
                // adapter name, new GUID) OR the bound instance is present-but-down.
                // Match by the binding's saved display_name against live adapters,
                // but ONLY when EXACTLY ONE *usable* (Available) adapter matches, so we
                // never silently route through the wrong NIC. Iterator (not a
                // Vec of borrows) so the chosen `&AdapterInfo` borrows `infos`
                // directly and outlives this block.
                let mut healed = infos.iter().filter(|i| {
                    classify_availability(i) == Some(AdapterAvailability::Available)
                        && adapter_answers_to_saved_name(i, &binding.display_name)
                });
                let first = healed.next();
                let second = healed.next();
                let ambiguous = second.is_some();
                // Several live adapters answer to the saved name: picking one
                // would route the user's traffic through an adapter they never
                // chose, so the choice goes back to them instead of being made
                // silently or swallowed into a fail-closed nobody can explain.
                if let (Some(a), Some(b)) = (first, second) {
                    let candidates: Vec<String> = std::iter::once(a)
                        .chain(std::iter::once(b))
                        .chain(healed)
                        .map(|i| preferred_display_name(i).to_string())
                        .collect();
                    self.publish_enforcement_status(sid, "adapter-choice-needed", role, candidates);
                }
                match first {
                    Some(only) if !ambiguous => {
                        let healed_id = format!(
                            "win-adapter:{}",
                            only.adapter_name.trim().to_ascii_lowercase()
                        );
                        // The heal re-fires every reconcile while the binding
                        // stays stale; act once per distinct stale→healed mapping
                        // so the WARN does not flood the log AND we persist only
                        // once (until it changes).
                        if self.note_heal_once(sid, role, &binding.stable_id, &healed_id) {
                            tracing::warn!(
                                target: "nrr::route-coordinator",
                                sid = %sid,
                                role = role,
                                stale_id = %binding.stable_id,
                                healed_adapter = %only.description,
                                healed_id = %healed_id,
                                "stored binding id was stale (adapter reinstalled/renamed?) — auto-matched the live adapter by saved name; persisting the corrected id.",
                            );
                            // persist the corrected identity so the
                            // stale id does not resurface every restart (churn)
                            // and the GUI reflects the real adapter. Safe here:
                            // the settings DB was loaded and released before this
                            // heal, so the callback may re-open it to write.
                            if let Some(persist) = self.binding_heal_persist.as_ref() {
                                persist(sid, role, &healed_id, preferred_display_name(only));
                            }
                        }
                        only
                    }
                    _ => {
                        // Heal found 0 or >1 usable same-name adapters. Fail closed,
                        // naming the EXACT reason (HW-0712 C6): a genuinely-absent
                        // bound id vs a present-but-DOWN bound adapter whose live
                        // same-name sibling we could not uniquely identify.
                        match by_id {
                            Some(down) => {
                                if self.note_not_usable_once(sid, role, &binding.stable_id) {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        stable_id = %binding.stable_id,
                                        avail = ?classify_availability(down),
                                        oper_status = ?down.oper_status,
                                        has_ipv4 = down.has_ipv4_address(),
                                        name_match_ambiguous = ambiguous,
                                        "bound adapter found but NOT usable (down / no IPv4 / excluded type) and no unique live same-name adapter to heal to — failing closed",
                                    );
                                }
                                // Steady "still not usable" state is silent by
                                // design (0725 run 9: the per-reconcile debug
                                // heartbeat wrote 2500+ identical lines in ten
                                // minutes of verbose capture). The transition
                                // into the state warned above; the transition
                                // out re-arms via `clear_not_usable`.
                                //
                                // The user, however, must not be left guessing:
                                // failing closed here is what stops their rule
                                // traffic, and until this push existed the only
                                // trace was a log line. Deduped inside the
                                // publisher, so the steady state stays quiet.
                                self.publish_enforcement_status(
                                    sid,
                                    "secondary-down",
                                    role,
                                    Vec::new(),
                                );
                            }
                            None => {
                                // The user has to hear this one. The bound
                                // adapter is not among the live set and no
                                // live name answers for it — their rules stop
                                // and nothing else in the product says why.
                                // Until now this branch only wrote a log line,
                                // while its sibling (bound-but-down) published
                                // a status, so a vendor that replaced its
                                // adapter outright failed silently.
                                //
                                // Every usable adapter is offered as a
                                // candidate: we cannot know which one replaced
                                // the old one, and guessing is what the
                                // ambiguous branch above already refuses to do.
                                //
                                // Strictly the ZERO-match case. Several names
                                // answering is a different question, already
                                // asked above, and publishing both leaves the
                                // two statuses overwriting each other in the
                                // per-role latch — an endless alternating push.
                                if !ambiguous {
                                    let choices = replacement_candidates(infos, role);
                                    // "Removed" and "here but its driver
                                    // will not start" arrive identically —
                                    // as nothing — yet they need opposite
                                    // advice: pick another connection, or
                                    // repair a driver. Only the OS can tell
                                    // them apart, and only when asked.
                                    let status = self
                                        .device_status
                                        .as_ref()
                                        .and_then(|p| p.device_state(&binding.stable_id))
                                        .filter(|s| s.is_present_but_unusable())
                                        .map_or("adapter-gone", |_| "adapter-failed");
                                    self.publish_enforcement_status(sid, status, role, choices);
                                }
                                let live: Vec<String> = infos
                                    .iter()
                                    .map(|i| {
                                        format!(
                                            "win-adapter:{}",
                                            i.adapter_name.trim().to_ascii_lowercase()
                                        )
                                    })
                                    .collect();
                                // dedup: WARN once per distinct (bound id,
                                // live adapter set); a legitimately-absent secondary
                                // (VPN off) otherwise floods the log every reconcile.
                                let mut fp_parts = live.clone();
                                fp_parts.sort();
                                let live_fp = fp_parts.join(",");
                                if self.note_not_found_once(sid, role, &binding.stable_id, &live_fp)
                                {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        bound = %binding.stable_id,
                                        display_name = %binding.display_name,
                                        name_match_ambiguous = ambiguous,
                                        live_adapters = ?live,
                                        "bound adapter NOT FOUND among live adapters (id mismatch; name auto-heal found 0 or multiple matches)",
                                    );
                                } else {
                                    tracing::debug!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        bound = %binding.stable_id,
                                        "bound adapter still NOT FOUND (deduped; live adapter set unchanged)",
                                    );
                                }
                            }
                        }
                        return None;
                    }
                }
            }
        };
        // `info` is guaranteed Available here: the by-id match only accepted an
        // Available adapter, and the name-heal only adopts an Available sibling — so
        // the old post-match usability check was redundant and has been removed
        // A genuinely-down bound adapter with no live sibling already
        // returned None (fail-closed) above.
        //
        // The binding resolved to a usable adapter on this call — re-arm the
        // not-usable WARN latch so the next usable→not-usable transition logs
        // again instead of staying silently deduped forever.
        self.clear_not_usable(sid, role);
        self.publish_enforcement_status(sid, "ok", role, Vec::new());
        self.remember_mac_anchor(sid, role, binding, info);
        let gateway = match info.gateways.first().copied() {
            Some(gw) => gw,
            None => {
                // No classic adapter gateway. Common for OpenVPN / WireGuard
                // TUN links, which install split-default routes via the tunnel
                // peer instead of setting a gateway on the adapter. Derive that
                // peer from the OS route table so our routes travel exactly like
                // the link's own traffic, instead of tearing every route down
                // (the round-6 "NO gateway" dead end).
                let derived = self
                    .api
                    .get_ip_forward_table()
                    .ok()
                    .and_then(|t| derive_secondary_next_hop(&t, info.index));
                match derived {
                    Some(nh) => {
                        // Cache it so we can still route after slice-C2 strips
                        // the catch-all routes we derived it from. Refreshed on
                        // every successful derive (e.g. after a VPN reconnect).
                        // Caching it is what lets routing survive slice-C2
                        // stripping the catch-all routes we derived it from;
                        // the same write says whether this answer is news, so
                        // an unchanged next-hop stops repeating itself into the
                        // log every cycle.
                        if self.note_derived_next_hop(info.index, nh) {
                            tracing::debug!(
                                target: "nrr::route-coordinator",
                                sid = %sid,
                                role = role,
                                ifindex = info.index,
                                next_hop = %nh,
                                "bound adapter exposes no gateway; derived tunnel next-hop from its catch-all routes",
                            );
                        }
                        nh
                    }
                    None => {
                        // Derivation failed — typically because NetRuleRouter
                        // already owns the table and stripped the VPN's redirect
                        // overlay (the only catch-all we could derive from). Fall
                        // back to the last good next-hop for this interface.
                        let cached = self
                            .next_hop_cache
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .get(&info.index)
                            .copied();
                        match cached {
                            Some(nh) => {
                                tracing::debug!(
                                    target: "nrr::route-coordinator",
                                    sid = %sid,
                                    role = role,
                                    ifindex = info.index,
                                    next_hop = %nh,
                                    "no catch-all on interface (NetRuleRouter owns the table now) — using cached tunnel next-hop",
                                );
                                nh
                            }
                            None => {
                                // Log BOTH the stored (possibly stale) binding
                                // id AND the effective adapter we actually
                                // resolved to (healed-by-name id + ifindex), so
                                // the operator can see it operated on the LIVE
                                // adapter, not the stale GUID. The old log
                                // printed only `binding.stable_id` while working
                                // on `info.index`, which read like an adapter
                                // mismatch  HW diagnosis).
                                let effective_id = format!(
                                    "win-adapter:{}",
                                    info.adapter_name.trim().to_ascii_lowercase()
                                );
                                // Once per spell  HW: this state is
                                // a short burst while the VPN client is still
                                // installing its routes after media-up, and
                                // resolution runs many times per second — 55
                                // identical WARNs in 2.2 s without the latch).
                                if self.note_no_next_hop_once(sid, role) {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        stable_id = %binding.stable_id,
                                        effective_id = %effective_id,
                                        effective_adapter = %info.description,
                                        ifindex = info.index,
                                        ipv4 = ?info.ipv4_addresses,
                                        "bound adapter is UP but has NO gateway and no derivable or cached tunnel next-hop (only on-link routes) — cannot use it as a route target",
                                    );
                                } else {
                                    tracing::debug!(
                                        target: "nrr::route-coordinator",
                                        sid = %sid,
                                        role = role,
                                        ifindex = info.index,
                                        "still no derivable or cached tunnel next-hop (deduped)",
                                    );
                                }
                                return None;
                            }
                        }
                    }
                }
            }
        };
        // The binding resolved to a full route target — re-arm the
        // no-next-hop WARN latch for the next derivation outage.
        self.clear_no_next_hop(sid, role);
        // The IPv6 next hop is derived, never cached: unlike the v4 one it is
        // not what keeps the link usable, so a pass that cannot read the table
        // simply names no v6 route rather than steering on a stale peer.
        let gateway_v6 = self
            .api
            .get_ip_forward_table()
            .ok()
            .and_then(|t| derive_secondary_next_hop_v6(&t, info.index));
        Some(SecondaryRouteTarget {
            gateway,
            gateway_v6,
            interface_index: info.index,
        })
    }
}
