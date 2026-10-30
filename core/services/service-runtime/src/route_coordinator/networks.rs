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

    /// The tunnels foreign to every served user, and what they carry, for the
    /// readers that must keep out of them. `per_user` holds each served user's
    /// foreign tunnels, named from `table` and `adapters`. A link counts only
    /// when it is foreign to all of them: another user's additional link is no
    /// tunnel of this one's, but it is not the corporate network either.
    ///
    /// An unreadable table publishes nothing rather than leaving the last
    /// pass's facts standing: doubt is "not foreign". `own` are the served
    /// users' additional-route links, which the bindings name either way.
    pub(super) fn publish_foreign_tunnel_networks(
        &self,
        table: Option<&[RouteEntry]>,
        adapters: &[AdapterInfo],
        per_user: &[Vec<u32>],
        own: &[u32],
    ) {
        crate::foreign_tunnels::global_foreign_tunnels()
            .publish_served(table, adapters, per_user, own);
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
                    msg_key = "route-local-networks-unreadable-additional",
                    sid = %sid,
                    error = %e,
                    "route table could not be read; reporting no local networks for the additional link",
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
                    msg_key = "route-local-networks-unreadable-screen",
                    sid = %sid,
                    error = %e,
                    "route table could not be read; the local-networks screen will show nothing",
                );
                return Vec::new();
            }
        };
        let Ok(adapters) = self.adapters_now() else {
            return Vec::new();
        };
        crate::local_network_source::discovered(
            &routes,
            &adapters,
            crate::local_network_source::BoundLinks {
                primary: resolution.primary.map(|p| p.interface_index),
                secondary: resolution.secondary.map(|s| s.interface_index),
            },
        )
    }

    /// The public IPv6 prefixes the main link carries, each with what is
    /// decided about it. Exempt only on the user's "yes", or on auto-accept
    /// outside the blanket block (there it always asks), and never while a rule
    /// names something inside: the rule's traffic would leave past it.
    ///
    /// The rule check resolves the whole rule book, so a pass runs it only for
    /// a prefix that would otherwise be opened; `for_display` runs it for every
    /// prefix, for the settings list. Never per packet.
    pub fn public_v6_local_networks(
        &self,
        sid: &str,
        routes: &[RouteEntry],
        primary_ifindex: u32,
        for_display: bool,
    ) -> Vec<PublicV6Network> {
        if exemptible_local_subnets(routes, primary_ifindex)
            .public_v6
            .is_empty()
        {
            return Vec::new();
        }
        let answers = self
            .local_networks
            .as_ref()
            .map(|read| read(sid).answers_v6)
            .unwrap_or_default();
        let auto_accept = self.route_source.load_for_sid(sid).is_some_and(|p| {
            p.local_networks_auto_accept && !crate::per_sid_orchestrator::protects_everything(&p)
        });
        let ownership = std::cell::OnceCell::new();
        let names_rule = |block: nrr_shared::ip_block::IpBlock| {
            ownership
                .get_or_init(|| {
                    let rules = self.rules_provider.active_rules_for(sid)?;
                    let snapshot = self.fqdn_cache.snapshot_for_compute();
                    let cache = super::liveness::snapshot_or_live(
                        snapshot.as_deref(),
                        self.fqdn_cache.as_ref(),
                    );
                    Some(crate::address_ownership::AddressOwnership::resolve(
                        &rules.rule_book,
                        cache,
                    ))
                })
                .as_ref()
                .is_some_and(|o: &crate::address_ownership::AddressOwnership| o.names_inside(block))
        };
        crate::local_network_source::public_v6_networks(
            routes,
            primary_ifindex,
            &answers,
            auto_accept,
            for_display,
            names_rule,
        )
    }

    /// What the settings list shows beyond the exemptible private segments:
    /// the main link's public IPv6 prefixes with their state, and the segments
    /// too wide to be local at all, each with the main link's name. Empty when
    /// there is no main link or the table cannot be read.
    pub fn local_network_candidates(&self, sid: &str) -> LocalNetworkCandidates {
        let Some(primary) = self.resolve(sid).primary else {
            return LocalNetworkCandidates::default();
        };
        let Ok(routes) = self.api.get_ip_forward_table() else {
            return LocalNetworkCandidates::default();
        };
        let adapters = self.adapters_now().unwrap_or_default();
        crate::local_network_source::candidates(
            &routes,
            &adapters,
            primary.interface_index,
            self.public_v6_local_networks(sid, &routes, primary.interface_index, true),
        )
    }

    /// The opened public prefixes as exemption pairs.
    pub(super) fn opened_public_v6(
        &self,
        sid: &str,
        routes: &[RouteEntry],
        primary_ifindex: Option<u32>,
    ) -> Vec<(std::net::Ipv6Addr, u8)> {
        let Some(primary) = primary_ifindex else {
            return Vec::new();
        };
        crate::local_network_source::opened_pairs(
            &self.public_v6_local_networks(sid, routes, primary, false),
        )
    }

    /// The link `sid`'s `role` binding resolved to on the last pass that had one.
    fn last_resolved_link(&self, sid: &str, role: &str) -> Option<u32> {
        let last = self
            .last_resolution
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let resolution = last.get(sid)?;
        let target = if role == "secondary" {
            resolution.secondary
        } else {
            resolution.primary
        };
        target.map(|t| t.interface_index)
    }

    /// The route table from `reading`, or read live when there is none.
    /// `None` when it could not be read.
    pub(super) fn routes_of<'a>(
        &self,
        reading: Option<&'a MachineReading>,
    ) -> Option<std::borrow::Cow<'a, [RouteEntry]>> {
        match reading {
            Some(reading) => reading.routes().map(std::borrow::Cow::Borrowed),
            None => self
                .api
                .get_ip_forward_table()
                .ok()
                .map(std::borrow::Cow::Owned),
        }
    }

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
    pub(super) fn apply_local_network_policy(
        &self,
        sid: &str,
        routes: &[RouteEntry],
        adapters: &[AdapterInfo],
        secondary_ifindex: Option<u32>,
        out: &mut Vec<(Ipv4Addr, u8)>,
    ) {
        for subnet in crate::route_reconciler::virtual_machine_local_subnets(
            routes,
            adapters,
            secondary_ifindex,
        ) {
            if !out.contains(&subnet) {
                out.push(subnet);
            }
        }
        let Some(policy) = self.local_networks.as_ref().map(|read| read(sid)) else {
            return;
        };
        crate::local_network_source::apply_stored_answers(&policy, routes, adapters, out);
    }

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

    /// Tell the user the main link reported a segment too wide to be a local
    /// network — a hostile access point handing out a `/1`. The enforcement
    /// already refuses it; what the user needs to hear is that devices on that
    /// network stay cut while routed traffic is blocked, and why.
    ///
    pub(super) fn warn_too_wide_local_networks(
        &self,
        sid: &str,
        routes: &[RouteEntry],
        infos: &[AdapterInfo],
        primary_ifindex: u32,
    ) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        let too_wide = exemptible_local_subnets(routes, primary_ifindex).too_wide;
        if too_wide.is_empty() {
            return;
        }
        let adapter_name = infos
            .iter()
            .find(|info| info.index == primary_ifindex)
            .map(|info| preferred_display_name(info).to_string())
            .unwrap_or_default();
        self.too_wide_local_network_notified.publish(
            bus,
            sid,
            &adapter_name,
            &too_wide,
            std::time::Instant::now(),
        );
    }

    /// Tell subscribers whether this SID's policy is in force, and what to do
    /// when it is not. Published on CHANGE only: the resolve runs at reconcile
    /// cadence and an unchanged state is not news.
    pub(super) fn publish_enforcement_status(
        &self,
        sid: &str,
        status: &str,
        role: &str,
        candidates: Vec<String>,
    ) {
        self.enforcement_status
            .publish(self.events.as_deref(), sid, status, role, candidates);
    }

    /// The machine-wide report ends once a resolve gets past both its causes.
    pub(super) fn clear_machine_wide_enforcement_status(&self, sid: &str) {
        self.enforcement_status
            .clear_machine_wide(self.events.as_deref(), sid);
    }

    /// A bound adapter the user renamed is still found by id, but a later id
    /// change is recovered by name: store the name it carries now, under the
    /// same id. Journal only — the user renamed it themselves.
    fn refresh_renamed_binding(
        &self,
        sid: &str,
        role: &str,
        binding: &PerSidBinding,
        info: &AdapterInfo,
    ) {
        if adapter_answers_to_saved_name(info, &binding.display_name) {
            return;
        }
        let name = preferred_display_name(info);
        if name.trim().is_empty() || !self.note_rename_once(sid, role, &binding.stable_id, name) {
            return;
        }
        tracing::info!(
            target: "nrr::route-coordinator",
            sid = %sid,
            role = role,
            stable_id = %binding.stable_id,
            "the bound adapter carries a new name; storing it so a later id change is still recovered by name",
        );
        if let Some(persist) = self.binding_heal_persist.as_ref() {
            persist(sid, role, &binding.stable_id, name);
        }
    }

    /// Move a binding off its dead adapter onto the live one the VPN came up
    /// on — a copy of the same driver, or another driver's tunnel — saving
    /// the move once per distinct pair and telling the user where their
    /// additional connection went.
    fn follow_vpn(
        &self,
        sid: &str,
        role: &str,
        binding: &PerSidBinding,
        target: &AdapterInfo,
        same_driver: bool,
    ) {
        let healed_id = format!(
            "win-adapter:{}",
            target.adapter_name.trim().to_ascii_lowercase()
        );
        if !self.note_heal_once(sid, role, &binding.stable_id, &healed_id) {
            return;
        }
        let name = preferred_display_name(target);
        if same_driver {
            tracing::warn!(
                target: "nrr::route-coordinator",
                msg_key = "route-binding-moved-to-driver-copy",
                sid = %sid,
                role = role,
                stale_id = %binding.stable_id,
                healed_adapter = %name,
                healed_id = %healed_id,
                "bound adapter is off and the VPN came up on another copy of its driver — switched to that copy and saved it",
            );
        } else {
            tracing::warn!(
                target: "nrr::route-coordinator",
                msg_key = "route-binding-moved-to-tunnel",
                sid = %sid,
                role = role,
                stale_id = %binding.stable_id,
                healed_adapter = %name,
                healed_id = %healed_id,
                "bound adapter is off and the only live tunnel is another adapter — switched the additional connection to it and saved it",
            );
        }
        if let Some(persist) = self.binding_heal_persist.as_ref() {
            persist(sid, role, &healed_id, name);
        }
        if let (Some(bus), "secondary") = (self.events.as_ref(), role) {
            bus.publish_for(
                sid,
                nrr_shared::ipc_payloads::StatusUpdateEvent::AdditionalConnectionMoved {
                    sid: sid.to_string(),
                    adapter_name: name.to_string(),
                },
            );
        }
    }

    /// Resolve one route binding (primary or secondary) to a
    /// [`SecondaryRouteTarget`] against live `infos`. `None` when the bound
    /// adapter is missing, unusable, or has no gateway and no derivable
    /// next-hop. `role` is "primary" or "secondary"; a primary must also have a
    /// way out of its own ([`has_own_way_out`]).
    /// Next hops are derived from `reading`'s route table, or the live one.
    pub(super) fn resolve_binding_target(
        &self,
        sid: &str,
        binding: &PerSidBinding,
        other_role: Option<&PerSidBinding>,
        infos: &[AdapterInfo],
        role: &str,
        reading: Option<&MachineReading>,
    ) -> Option<SecondaryRouteTarget> {
        // Granular resolution so the log names the EXACT reason: not-found
        // (id mismatch), down/no-IP, or up-but-no-gateway.
        // resolve by id, but only ACCEPT the by-id match when it is
        // actually usable (Available = up + IPv4). A found-but-DOWN bound adapter
        // (a GUID-churning VPN like examplevpn can leave a stale/down TAP instance
        // enumerated while the freshly-connected one carries traffic) must NOT short-
        // circuit to fail-closed — it falls into the same name-heal below so we can
        // adopt a live same-name SIBLING. If the bound adapter is genuinely down with
        // no live sibling, the heal finds nothing and we still fail closed (correct).
        // The same check the leak-protection banner makes (`bound_adapter_usable`).
        let by_id = bound_adapter(infos, &binding.stable_id, &binding.known_stable_ids);
        let info = match by_id.filter(|i| BoundCandidate::usable(*i)) {
            Some(i) => {
                self.refresh_renamed_binding(sid, role, binding, i);
                i
            }
            None => {
                // Auto-heal: the stored GUID is gone (VPN reinstall/upgrade — same
                // adapter name, new GUID) OR the bound instance is present-but-down.
                // Match by the binding's saved display_name against live adapters,
                // but ONLY when EXACTLY ONE *usable* (Available) adapter matches, so we
                // never silently route through the wrong NIC. Iterator (not a
                // Vec of borrows) so the chosen `&AdapterInfo` borrows `infos`
                // directly and outlives this block.
                // A tunnel that is not the user's, matched only by words every
                // client on the same driver shares, is somebody else's.
                // Unreadable routes: the uplink cannot be told apart. Doubt keeps
                // the link this binding resolved to on the last pass as ours, so
                // a transient read error neither asks the user nor unbinds them;
                // another tunnel-looking link is still not adopted on a guess.
                let ours: Vec<u32> = by_id.map(|i| i.index).into_iter().collect();
                let additional: &[u32] = if role == "secondary" { &ours } else { &[] };
                let routes = self.routes_of(reading);
                let foreign: Vec<u32> = match routes.as_deref() {
                    Some(routes) => {
                        super::exemptions::foreign_tunnel_indexes(infos, &ours, additional, routes)
                    }
                    None => {
                        let mut kept = ours.clone();
                        kept.extend(self.last_resolved_link(sid, role));
                        super::exemptions::foreign_tunnel_indexes_without_routes(infos, &kept)
                    }
                };
                let named: Vec<&AdapterInfo> = infos
                    .iter()
                    .filter(|i| {
                        classify_availability(i) == Some(AdapterAvailability::Available)
                            && adapter_answers_to_saved_name(i, &binding.display_name)
                    })
                    .collect();
                let (accepted, refused): (Vec<&AdapterInfo>, Vec<&AdapterInfo>) =
                    named.into_iter().partition(|i| {
                        !foreign.contains(&i.index)
                            || adapter_carries_only_the_saved_brand(i, &binding.display_name)
                    });
                let mut healed = accepted.iter().copied();
                let first = healed.next();
                let second = healed.next();
                let ambiguous = second.is_some();
                // Every name-matching candidate was refused as a foreign tunnel:
                // the user decides, rather than a silent fail-closed.
                let refused_only = first.is_none() && !refused.is_empty();
                if refused_only {
                    let candidates: Vec<String> = refused
                        .iter()
                        .map(|i| preferred_display_name(i).to_string())
                        .collect();
                    self.publish_enforcement_status(sid, "adapter-choice-needed", role, candidates);
                }
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
                // Already asked above when names answered; a second status for
                // the role would take turns with that one on every pass.
                let mut asked = ambiguous || refused_only;
                let other_routes_link = |i: &AdapterInfo| {
                    other_role
                        .is_some_and(|b| binding_matches_live(i, &b.stable_id, &b.known_stable_ids))
                };
                // A VPN client on a stock driver brings up whichever copy of it
                // it likes: the one live copy of a dead bound adapter's driver
                // is where the VPN went.
                let copy = match (first, by_id) {
                    (None, Some(down)) if !asked => {
                        sole_live_driver_sibling(infos, down, other_routes_link)
                    }
                    _ => None,
                };
                // Failing that, the additional connection follows the VPN to
                // the one live tunnel that is nobody else's, whatever driver
                // it runs on; two leave the choice to the user. Only with the
                // route table read: without it the uplink cannot be told apart.
                let tunnels = match (first, copy, routes.as_deref()) {
                    (None, None, Some(routes)) if role == "secondary" && !asked => {
                        adoptable_tunnels(infos, &foreign, routes, other_routes_link)
                    }
                    _ => Vec::new(),
                };
                let tunnel = match tunnels.as_slice() {
                    [only] => Some(*only),
                    [] => None,
                    several => {
                        let candidates = several
                            .iter()
                            .map(|i| preferred_display_name(i).to_string())
                            .collect();
                        self.publish_enforcement_status(
                            sid,
                            "adapter-choice-needed",
                            role,
                            candidates,
                        );
                        asked = true;
                        None
                    }
                };
                match (first, copy.or(tunnel)) {
                    (_, Some(moved)) => {
                        self.follow_vpn(sid, role, binding, moved, copy.is_some());
                        moved
                    }
                    (Some(only), None) if !ambiguous => {
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
                                msg_key = "route-binding-healed-by-name",
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
                        // naming the EXACT reason: a genuinely-absent bound id vs
                        // a present-but-DOWN bound adapter whose live same-name
                        // sibling we could not uniquely identify.
                        match by_id {
                            Some(down) => {
                                if self.note_not_usable_once(sid, role, &binding.stable_id) {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        msg_key = "route-binding-down-no-heal",
                                        sid = %sid,
                                        role = role,
                                        stable_id = %binding.stable_id,
                                        avail = ?classify_availability(down),
                                        oper_status = ?down.oper_status,
                                        has_ipv4 = down.has_ipv4_address(),
                                        name_match_ambiguous = ambiguous,
                                        name_matched = accepted.len() + refused.len(),
                                        refused_foreign = refused.len(),
                                        "bound adapter found but NOT usable (down / no IPv4 / excluded type) and no unique live same-name adapter to heal to — failing closed",
                                    );
                                }
                                // The log warns on the transition only; the user
                                // hears it too, since failing closed stops their
                                // rule traffic. Deduped inside the publisher.
                                if !asked {
                                    self.publish_enforcement_status(
                                        sid,
                                        "secondary-down",
                                        role,
                                        Vec::new(),
                                    );
                                }
                            }
                            None => {
                                // The user has to hear this one. The bound
                                // adapter is not among the live set and no
                                // live name answers for it — their rules stop
                                // and nothing else in the product says why.
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
                                if !asked {
                                    // "Removed", "switched off by the user" and
                                    // "its driver will not start" all arrive as
                                    // nothing, yet need different advice. Only
                                    // the OS can tell them apart, and only when
                                    // asked. Switched off is the same state as
                                    // a link that is down: nothing to replace.
                                    let state = self
                                        .device_status
                                        .as_ref()
                                        .and_then(|p| p.device_state(&binding.stable_id));
                                    let (status, choices) = match state {
                                        Some(nrr_platform_api::device_status::DeviceState::Disabled) => {
                                            ("secondary-down", Vec::new())
                                        }
                                        Some(nrr_platform_api::device_status::DeviceState::FailedToStart) => {
                                            ("adapter-failed", replacement_candidates(infos, role))
                                        }
                                        _ => ("adapter-gone", replacement_candidates(infos, role)),
                                    };
                                    // Fail-closed already holds; only the advice waits.
                                    if status != "adapter-gone"
                                        || self.gone_long_enough(sid, role, &binding.stable_id)
                                    {
                                        self.publish_enforcement_status(sid, status, role, choices);
                                    } else {
                                        // Not up is what is known yet, shown
                                        // quietly; "gone" continues its grace.
                                        self.publish_enforcement_status(
                                            sid,
                                            "secondary-down",
                                            role,
                                            Vec::new(),
                                        );
                                    }
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
                                        msg_key = "route-binding-not-found",
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
        // Available adapter, and the name-heal only adopts an Available sibling.
        // A genuinely-down bound adapter with no live sibling already returned
        // None (fail-closed) above.
        //
        // The binding resolved to a usable adapter on this call — re-arm the
        // not-usable WARN latch so the next usable→not-usable transition logs
        // again instead of staying silently deduped forever.
        self.clear_not_usable(sid, role);
        // A main link with no way out would take every unrouted connection
        // into a dead end; the caller then falls back to the OS default route.
        // Not asked of the additional link: a tunnel has no routes until its
        // client installs them.
        if role == "primary"
            && self.routes_of(reading).is_some_and(|t| {
                !has_own_way_out(info, &t, |r| r.is_ours || self.reconciler.owns(r))
            })
        {
            if self.note_no_next_hop_once(sid, role) {
                tracing::warn!(
                    target: "nrr::route-coordinator",
                    msg_key = "route-primary-no-way-out",
                    sid = %sid,
                    ifindex = info.index,
                    adapter = %info.description,
                    "the main connection has no gateway and no route out — not routing through it",
                );
            }
            self.publish_enforcement_status(sid, "primary-no-way-out", role, Vec::new());
            return None;
        }
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
                // when no next-hop can be derived.
                let derived = self
                    .routes_of(reading)
                    .and_then(|t| derive_secondary_next_hop(&t, info.index));
                match derived {
                    Some(nh) => {
                        // Cached so routing survives whatever later strips the
                        // catch-all routes we derived this from (e.g. after a
                        // VPN reconnect); the same write says whether this
                        // answer is news, so an unchanged next-hop stops
                        // repeating itself into the log every cycle.
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
                                // adapter, not the stale GUID — the stale id
                                // alone reads like an adapter mismatch.
                                let effective_id = format!(
                                    "win-adapter:{}",
                                    info.adapter_name.trim().to_ascii_lowercase()
                                );
                                // Once per spell: this state is a short burst
                                // while the VPN client is still installing its
                                // routes after media-up, and resolution runs
                                // many times per second — without the latch
                                // this floods the log with near-identical WARNs.
                                if self.note_no_next_hop_once(sid, role) {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        msg_key = "route-binding-no-next-hop",
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
            .routes_of(reading)
            .and_then(|t| derive_secondary_next_hop_v6(&t, info.index));
        Some(SecondaryRouteTarget {
            gateway,
            gateway_v6,
            interface_index: info.index,
        })
    }
}
