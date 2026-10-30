//! The plan: what filters a SID's policy compiles to.
//!
//! One long method. It stays a method (it reads a dozen private fields, and a
//! child module of the defining module still sees them), in a file of its own
//! so it does not sit between the builder and the apply path. What leak
//! protection arms is decided by `nrr_domain::protection_posture`, not here.

use super::*;
use crate::enforcement_planner::ServiceAccountPosture;

impl PerSidApplyOrchestrator {
    /// `pub(super)` rather than private: the impl is split across files, so the
    /// parent module is now the caller. The visibility widened by exactly one
    /// module, which is what the split costs.
    pub(super) fn compute_filters_for_sid(
        &self,
        sid: &str,
        log_unresolved: bool,
        rules_override: Option<&ActiveRulesSnapshot>,
        intent: ComputeIntent,
    ) -> Result<ComputedFilterSet, OrchestratorError> {
        // The pass that dominates the periodic path (67% of it, measured) is
        // this one, and "2.8 s" is not something anyone can act on. Same
        // treatment as the recompute hook that calls it: the pass says which of
        // its parts spent the time, and only when it was slow.
        let mut timings = crate::phase_timings::PhaseTimings::start();
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        // the admin baseline is never enforced as its own
        // machine-wide filter set (see `install_for_sid`).
        if sid == nrr_domain::user_principal::BASELINE_PRINCIPAL {
            return Err(OrchestratorError::BaselineNotRoutable);
        }
        let policy = match self.policy_source.load_for_sid(sid) {
            Some(s) => s,
            None => {
                // A store that failed to answer is not "no policy": clearing
                // here would drop the guard it was keeping.
                if let Some(reason) = self.policy_source.read_failure_for(sid) {
                    return Err(OrchestratorError::PolicyUnreadable(reason));
                }
                if intent.publishes() {
                    // no enforceable policy → no
                    // app rules are unenforced; clear any stale unresolved-app set so
                    // the GUI banner does not keep listing a now-phantom app.
                    self.clear_app_enforcement_status(sid);
                    self.clear_pending_vpn_clients(sid);
                    // policy gone ⇒ any block-all is disarming.
                    let flushed = self.note_block_all_state(sid, false);
                    self.note_fail_closed_state(sid, false, flushed);
                    self.note_machine_wide_cut(sid, false);
                    // No policy ⇒ no kill-switch filters either; drop any stale
                    // entry so the registry never role-verifies a drop for a SID
                    // whose leak-guard is no longer armed.
                    self.update_killswitch_registry(sid, KillswitchBlockIds::default());
                    // Nothing routes or pins this user's IPv6: not "first plan pending".
                    crate::ipv6_disposition::global_ipv6_dispositions().forget(sid);
                }
                // Routing needs connections; a deny does not.
                return self.compute_deny_filters_without_policy(
                    sid,
                    log_unresolved,
                    rules_override,
                    intent,
                );
            }
        };
        // ONE read of the FQDN cache for the whole pass. Every mechanism below
        // — codegen, address ownership, the shared-IP census, the kill-switch
        // trim — used to query it independently, per rule and per hostname, so
        // a pass over a real rule book cost tens of thousands of round trips
        // against the connection the live DNS observation path writes to. It
        // also means the pass now sees ONE state of the cache instead of a
        // slightly newer one at every lookup.
        timings.mark("policy");
        let cache_snapshot = self.fqdn_cache.snapshot_for_compute();
        let fqdn_cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup = match &cache_snapshot {
            Some(snapshot) => snapshot.as_ref(),
            None => self.fqdn_cache.as_ref(),
        };
        // an activation dispatch runs BEFORE the
        // active-revision pointer commits (all-or-nothing: revert must stay
        // possible), so a storage read here would still see the PREVIOUS
        // revision. The dispatcher passes the revision content it is applying;
        // every other caller reads the active pointer as before.
        timings.mark("cache");
        let rules = match rules_override
            .cloned()
            .map_or_else(|| self.rules_provider.rules_read_for(sid), RulesRead::Rules)
        {
            RulesRead::Rules(r) => r,
            // Not "no rules": whatever is installed stays until the book reads.
            RulesRead::Unreadable(reason) => {
                return Err(OrchestratorError::RulesUnreadable(reason));
            }
            // Settings but no revision: protection asks nothing of the rules,
            // so it holds exactly as over an emptied book.
            RulesRead::NoPolicy => ActiveRulesSnapshot::default(),
        };
        // surface the DELIVERED app-match patterns (exactly what
        // reached this SID's ACTIVE rule set). A "no exe matched" report can then
        // be triaged: pattern ABSENT here ⇒ the GUI edit never reached the service
        // (a delivery/persist problem, C1 family); pattern PRESENT but later logged
        // as unresolved ⇒ a resolver/enumeration problem. Logged once per apply
        // (`log_unresolved`), never on a reconcile tick.
        if log_unresolved {
            self.note_cross_set_duplicates(sid, &rules.rule_book);
            let app_pattern = |r: &nrr_domain::canonical::CanonicalRule| -> Option<String> {
                r.app_match.as_ref().map(|a| a.pattern.as_str().to_string())
            };
            let primary_apps: Vec<String> = rules
                .rule_book
                .primary
                .rules()
                .iter()
                .filter_map(app_pattern)
                .collect();
            let secondary_apps: Vec<String> = rules
                .rule_book
                .secondary
                .rules()
                .iter()
                .filter_map(app_pattern)
                .collect();
            self.note_new_app_rules(sid, &secondary_apps);
            if !primary_apps.is_empty() || !secondary_apps.is_empty() {
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-plan-app-rules-delivered",
                    sid,
                    primary_app_rules = primary_apps.join(", "),
                    secondary_app_rules = secondary_apps.join(", "),
                    "delivered app-match rules for this SID (apply)",
                );
            }
        }

        timings.mark("rules");
        let behavior_mode = behavior_mode_for_codegen(&policy);
        // shared-IP denylist from the SAME enforcement rule
        // book + live cache the codegen reads, so the WFP set and the route
        // table decline the same shared IPs coherently.
        let mut secondary_ip_denylist = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            fqdn_cache,
            policy.shared_ip_policy,
        );
        // Fake-IP: fold fake-IP into the plan. Computed
        // against the ORIGINAL denylist (which doubles as the shared-IP census),
        // BEFORE its suppress-set is merged in: the /32 permits of shared real
        // addresses are suppressed via the denylist, and the pool permit is
        // appended after codegen. The context is resolved
        // LIVE for this compute; a `None` / disabled context is a no-op, so the
        // non-fake-IP path is byte-for-byte unchanged.
        timings.mark("census");
        let fake_ip_context = (self.fake_ip_context)();
        // Fake-IP UDP relay — process-wide live flag, read fresh on
        // every compute (mirrors how the fake-IP context itself is resolved
        // live above) so a toggle takes effect on the very next replan.
        let udp_relay_enabled =
            crate::fake_ip::global_udp_relay_enabled().load(std::sync::atomic::Ordering::Relaxed);
        let fake_ip_augmentation = fake_ip_context.as_ref().map(|ctx| {
            crate::fake_ip::augment_codegen_for_fake_ip(
                sid,
                ctx,
                &rules.rule_book.secondary,
                fqdn_cache,
                &secondary_ip_denylist,
                udp_relay_enabled,
            )
        });
        if let Some(aug) = &fake_ip_augmentation {
            secondary_ip_denylist.extend(aug.denylist_additions.iter().copied());
        }
        //  — republish this SID's user-confirmed link-provider
        // executables before anything resolves an app pattern. Two consumers
        // read the registry: the app-path resolver, which materializes a
        // confirmed client's `ALE_APP_ID` permit even though the process has
        // never run (breaking the "permit only exists once the client is up"
        // chicken-and-egg), and the fake-IP relay, which keeps that client's own
        // flows off the link it is establishing. Publishing here — inside the
        // compute, ahead of `generate_filters` — is what makes the resolver see
        // the current pick with no extra wiring, and clearing it (the user
        // un-confirms) revokes both on the very next compute.
        if intent.publishes() {
            crate::vpn_client_registry::global_confirmed_vpn_clients()
                .publish(sid, &policy.link_provider_exe_paths);
            crate::fake_ip::global_rule_networks().publish(sid, &rules.rule_book);
        }
        timings.mark("fake-ip");
        // One reading of the machine for the whole pass, and each resolver asked
        // at most once: every one of them used to enumerate the adapters and
        // the route table for itself, a dozen OS reads per compute.
        let machine = (self.machine_reader)();
        let kill_switch_cell = std::cell::OnceCell::new();
        let kill_switch =
            || kill_switch_cell.get_or_init(|| (self.kill_switch_resolver)(sid, &machine));
        let fail_closed_cell = std::cell::OnceCell::new();
        let fail_closed_base = || {
            fail_closed_cell.get_or_init(|| (self.fail_closed_exemptions_resolver)(sid, &machine))
        };
        // What the machine's links can carry decides whether policy names IPv6
        // at all. Resolved per pass, not per session: a tunnel that comes up
        // with a v6 address changes the answer.
        let ipv6 = (self.ipv6_guard_resolver)(sid, &machine);
        if intent.publishes() {
            crate::ipv6_disposition::global_ipv6_dispositions().set(sid, ipv6);
        }
        // One answer per question about program destinations for the whole
        // pass, as for the cache: the filters, the arbiter and the pins below
        // must describe the same destinations while the observer writes.
        let observations = crate::app_observation_lookup::PassObservations::over(
            std::sync::Arc::clone(&self.app_observations),
        );
        // The rule filters installed, what the pass reads about them and what
        // it reports are the neutral plan's, taken before the fake-IP filters
        // join.
        #[cfg(windows)]
        let neutral = self.neutral_route_filters(
            sid,
            &rules.rule_book,
            fqdn_cache,
            &observations,
            &secondary_ip_denylist,
            policy.zone_priority_over_ip,
            policy.app_rules_take_all_addresses,
            ipv6,
        );
        // The codegen runs only where something still reads it: a principal the
        // plan cannot name, the sampled comparison, and every test pass. Every
        // pass running both doubled the cost of an apply.
        #[cfg(windows)]
        let compare = neutral.as_ref().is_some_and(|n| {
            self.compare_due(
                sid,
                super::shadow_compare::shadow_compare_fingerprint(&n.filters),
            )
        });
        #[cfg(windows)]
        let codegen_wanted = neutral.is_none() || compare || cfg!(test);
        #[cfg(not(windows))]
        let codegen_wanted = true;
        let codegen = codegen_wanted.then(|| {
            generate_filters(CodegenInput {
                sid,
                rule_book: &rules.rule_book,
                fqdn_cache,
                app_observations: &observations,
                app_resolver: self.app_resolver.as_ref(),
                secondary_ip_denylist: &secondary_ip_denylist,
                // The routes and the address arbiter read the stored flag; the
                // filters must answer the same question.
                zone_priority_over_ip: policy.zone_priority_over_ip,
                app_rules_take_all_addresses: policy.app_rules_take_all_addresses,
                families: ipv6.families(),
                packet_blocks: super::PACKET_BLOCKS,
            })
        });
        // With a plan, the pass reads only what the plan wrote, starting from
        // nothing: a test pass then runs the same code as a live one, and the
        // codegen is no more than the reference it is held to.
        #[cfg(windows)]
        let (mut codegen_out, neutral_findings) = match neutral {
            Some(neutral) => {
                if let (true, Some(reference)) = (compare, codegen.as_ref()) {
                    self.report_comparison(sid, &neutral.filters, &reference.filters);
                }
                let mut out = crate::wfp_codegen::CodegenOutput::default();
                let report =
                    neutral.describe(&mut out, self.app_resolver.as_ref(), codegen.as_ref());
                let findings = super::findings::PassFindings::from_plan(&report);
                #[cfg(test)]
                if let Some(reference) = codegen.as_ref() {
                    assert_eq!(
                        super::findings::PassFindings::from_plan(&report).normalized(),
                        super::findings::PassFindings::from_codegen(&reference.diagnostics)
                            .normalized(),
                        "the plan reports what the codegen reported"
                    );
                }
                (out, Some(findings))
            }
            None => (codegen.unwrap_or_default(), None),
        };
        #[cfg(not(windows))]
        let (mut codegen_out, neutral_findings) = (
            codegen.unwrap_or_default(),
            None::<super::findings::PassFindings>,
        );
        // Before the fake-IP blocks join: only what the rules compiled to.
        let rule_blocks = rule_block_ids(&codegen_out.filters);
        if let Some(aug) = fake_ip_augmentation {
            codegen_out.filters.extend(aug.extra_filters);
        }
        // What the rules report besides their filters: rules that enforce
        // nothing yet (logged, published for the GUI banner, their hosts asked
        // of DNS), contradictions, caps reached. WARN, not INFO: a rule that
        // silently enforces nothing is worth a look.
        let super::findings::PassFindings {
            unresolved_apps,
            over_capped,
            mut unresolved_hosts,
            truncated_suffixes,
            mut claimed_by_main,
            mut shared_with_others,
            unrouted_apps,
            unsupported_shapes,
            networks_over_cap,
            conflicts: rule_conflicts,
        } = neutral_findings.unwrap_or_else(|| {
            super::findings::PassFindings::from_codegen(&codegen_out.diagnostics)
        });
        // log app-enforcement diagnostics ONLY on a real
        // (re)apply (`install_for_sid`, `log_unresolved = true`), NEVER on the
        // background reconcile / leak-guard tick (`reconcile_secondary_coverage`),
        // which fires every few seconds and re-derived the SAME set 658× last
        // session → 35,532 identical lines (95% of the whole operational log). One
        // aggregated line per apply instead of one-per-rule. The
        // `AppEnforcementStatus` set (the GUI banner source) is refreshed every
        // tick below regardless, so the user-facing signal never goes stale — this
        // trims log volume only, not enforcement or the GUI notice.
        if log_unresolved {
            // Only on a real apply: the reconcile tick re-derives the same set
            // every few seconds, and a DNS round-trip per host at that cadence
            // would be a self-inflicted query storm.
            if !unresolved_hosts.is_empty() {
                if let Some(sink) = self.unresolved_hosts_sink.as_ref() {
                    unresolved_hosts.sort();
                    unresolved_hosts.dedup();
                    let total = unresolved_hosts.len();
                    let dropped = total.saturating_sub(UNRESOLVED_HOST_RESOLVE_CAP);
                    unresolved_hosts.truncate(UNRESOLVED_HOST_RESOLVE_CAP);
                    tracing::info!(
                        target: "nrr::wfp-codegen",
                        msg_key = "persid-plan-unresolved-hosts-dns-query",
                        sid = %sid,
                        hosts = unresolved_hosts.len(),
                        dropped,
                        "rule hosts have no confirmed address — asking DNS for them so the rules start enforcing without waiting for something else to resolve them",
                    );
                    sink(unresolved_hosts);
                }
            }
            if !unresolved_apps.is_empty() {
                tracing::warn!(
                    target: "nrr::app-resolver",
                    msg_key = "persid-plan-app-rules-unresolved",
                    sid = %sid,
                    count = unresolved_apps.len(),
                    apps = %unresolved_apps.join(", "),
                    "application rules not enforced: no installed/running exe matched (checked App Paths, running processes, Program Files) — the per-app filters were not built",
                );
            }
            if !claimed_by_main.is_empty() {
                claimed_by_main.sort();
                claimed_by_main.dedup();
                let shown: Vec<String> = claimed_by_main
                    .iter()
                    .take(8)
                    .map(|(app, ip)| format!("{app} → {ip}"))
                    .collect();
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "persid-plan-app-claimed-by-main",
                    sid = %sid,
                    count = claimed_by_main.len(),
                    conflicts = %shown.join(", "),
                    "an application rule is talking to addresses your main-link rules name: those stay on the main link. The app keeps the additional link for everything else",
                );
            }
            if !shared_with_others.is_empty() {
                log_app_destinations_shared(
                    sid,
                    &mut shared_with_others,
                    policy.leak_protection.is_on(),
                );
            }
            if !over_capped.is_empty() {
                tracing::warn!(
                    target: "nrr::app-resolver",
                    msg_key = "persid-plan-app-rules-overcapped",
                    sid = %sid,
                    count = over_capped.len(),
                    apps = %over_capped.join(", "),
                    "application rules PARTIALLY enforced: exe name/glob resolved to more paths than the per-app filter cap (app: cap/resolved)",
                );
            }
            if !unsupported_shapes.is_empty() {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "persid-plan-rule-shape-unsupported",
                    sid = %sid,
                    count = unsupported_shapes.len(),
                    rules = %unsupported_shapes.join(", "),
                    "rules not enforced: they limit an address to one application, which enforcement cannot scope yet, so they were skipped rather than applied to every application",
                );
            }
            {
                let over_cap = crate::rule_conflicts::over_cap_networks(&networks_over_cap);
                crate::production_principal_plan::log_networks_over_cap(sid, &over_cap);
            }
            for (rule_id, suffix, cap) in &truncated_suffixes {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "persid-plan-suffix-truncated",
                    sid = %sid,
                    rule_id = %rule_id,
                    suffix = %suffix,
                    cap = *cap,
                    "suffix/zone rule matched more than cap cached hosts; only the cap most-recently-seen were given permits — narrow the rule or upgrade for uncapped zones",
                );
            }
        }
        if let Some(status) = self
            .app_enforcement_status
            .as_ref()
            .filter(|_| intent.publishes())
        {
            status.set_unresolved(sid, unresolved_apps.clone());
            status.set_unrouted(sid, &unrouted_apps);
            let mut conflicts =
                crate::rule_conflicts::rule_conflict_dtos(&rule_conflicts, &rules.rule_book);
            conflicts.extend(crate::rule_conflicts::protected_rule_dtos(
                &self.rules_provider.withheld_rules_for(sid),
            ));
            status.set_rule_conflicts(sid, conflicts);
        }
        timings.mark("codegen");
        let mut filters = codegen_out.filters;
        // Reactive VPN-endpoint learning — every kill-switch/fail-closed BLOCK
        // filter spec id emitted for THIS sid below is collected here (rule
        // filters above are never included), then published to the shared
        // registry at the end of this compute (see `update_killswitch_registry`).
        let mut killswitch_block_ids = KillswitchBlockIds {
            rule_blocks,
            ..KillswitchBlockIds::default()
        };
        // The user's one choice; `nrr_domain::protection_posture` turns it, the
        // default route and the tunnel's state into what is armed below. On
        // means it arms even with no secondary bound: that user gets
        // rules-only egress, which is what they asked for.
        let protection = policy.leak_protection;
        let leak_guard_armed = protection.is_on();
        // whether THIS compute produced a blanket set (feeds the arming-edge
        // OS resolver-cache flush at the end of the function; per-destination
        // pins never flush).
        let mut block_all_armed = false;
        // whether that blanket stands because the additional link is gone
        let mut outage_hold = false;
        // whether THIS compute left the guard blocking with the additional link
        // unresolved (either posture) — see `note_fail_closed_state`.
        let mut fail_closed_armed = false;
        // A per-app block carries no destination, so it needs the same floor a
        // blanket block does — see `destination_less_block_floor` below.
        let mut app_block_emitted = false;
        if leak_guard_armed {
            let protocols = crate::killswitch_codegen::KillSwitchProtocols::from_bits(
                policy.kill_switch_protocols,
            );
            // The tunnel clients are exempt from the kill-switch by app id, so
            // the handshake that brings the tunnel back is never what the
            // guard drops. Concrete on-disk paths only: the built-in globs are
            // resolved in the codegen (`vpn_default_exempt_paths`), because a
            // glob stamped into `ALE_APP_ID` installs nothing. Emitted only in
            // the blocking branches below — a permit over nothing blocked is
            // standing volume for nothing.
            //
            // Three sources say "this is a tunnel client": a built-in VPN
            // pattern resolved to it, the user confirmed it as their link
            // provider, or our own kill-switch drop verified its role. A name
            // is something anyone can give a file, so the first and the third
            // are trusted only from a place the user could not have written
            // to; the rest wait for the user's word. An app the user merely
            // routes to the main link is NOT a client: its own rule permit
            // sits below the kill-switch block band, so a host the tunnel
            // owns stays blocked for it while the tunnel is down.
            let learned_vpn_client_paths: Vec<String> = self
                .vpn_client_apps_provider
                .as_ref()
                .map(|provider| provider())
                .unwrap_or_default();
            let trust = crate::vpn_client_trust::split_by_trust(
                self.app_resolver.as_ref(),
                &policy.link_provider_exe_paths,
                codegen_out
                    .vpn_default_exempt_paths
                    .iter()
                    .cloned()
                    .chain(policy.link_provider_exe_paths.iter().cloned())
                    .chain(learned_vpn_client_paths),
            );
            if intent.publishes() {
                let pending = crate::vpn_client_trust::pending_with_bundles(
                    self.app_resolver.as_ref(),
                    &trust.pending,
                );
                let changed =
                    crate::vpn_client_trust::global_pending_vpn_clients().publish(sid, &pending);
                if changed {
                    if !pending.is_empty() {
                        tracing::info!(
                            target: "nrr::per_sid_orchestrator",
                            msg_key = "persid-plan-vpn-client-awaiting-confirmation",
                            sid,
                            count = pending.len(),
                            apps = %trust.pending.join(", "),
                            "programs named like VPN clients sit outside the protected program folders — not exempted from leak protection until confirmed as the link provider",
                        );
                    }
                    // The whole list, an empty one included: the window
                    // withdraws its question when the last client is confirmed.
                    if let Some(bus) = self.events.as_ref() {
                        bus.publish_for(
                            sid,
                            nrr_shared::ipc_payloads::StatusUpdateEvent::VpnClientAwaitingConfirmation {
                                sid: sid.to_string(),
                                clients: pending,
                            },
                        );
                    }
                }
            }
            // What every exemption below spares, the service accounts' set
            // included: the clients themselves and nothing else.
            let tunnel_clients: Vec<String> = trust.accepted;
            // "smart" kill-switch shared-IP
            // handling (the default). An IP the shared-IP census has ALSO seen
            // on a direct (non-rule) hostname is removed from the kill-switch
            // pin/block set: IP-level blocking cannot separate co-tenants, and
            // strict pinning of CDN front-end IPs
            // (shared by ai-site/video-site secondary rules and www.search.example)
            // was seen killing search.example in every browser — plus the VPN client's own
            // bootstrap. The trade-off is explicit: while excluded, those IPs
            // are not leak-protected (secondary-rule traffic to them can egress
            // the primary when the secondary is down). `strict` restores the
            // historic pin-everything posture. ROUTING (`/32` via the secondary
            // while it is up) is untouched — this governs only the kill-switch
            // and fail-closed block sets. Whether an UNPINNED shared IP may
            // also be RESCUED by a block-all exemption is a separate, fake-IP-
            // gated decision — see `never_exempt_secondary_ips` below.
            // The same arbiter the two codegens read: an address the user's own
            // MAIN-link rules name is never blocked, in either mode. This is not
            // the shared-IP trade-off below — it is a direct contradiction
            // between two of the user's rules, and a block is neither of the two
            // things they asked for.
            let ownership = crate::address_ownership::AddressOwnership::resolve_for(
                &rules.rule_book,
                fqdn_cache,
                crate::address_ownership::OwnershipSettings::from_policy(
                    policy.zone_priority_over_ip,
                    policy.app_rules_take_all_addresses,
                ),
                crate::wfp_codegen::current_rule_shape_support(),
                &observations,
            );
            // The machine's OWN local networks are never pinned to the tunnel.
            // An application rule learns its destinations by watching, and a
            // NAS, a printer or a hypervisor's host address is exactly what it
            // will touch; pinned, that address is unreachable for the whole SID
            // the moment the tunnel drops - the device is one hop away on a
            // cable. Note this is NOT "skip RFC1918": a corporate tunnel to a
            // 10.x network is a legitimate destination. The distinction is
            // whether the address sits in a subnet the PRIMARY link is
            // connected to. Read from the fail-closed floor while the tunnel is
            // unresolved: that is when a block would cut the device.
            let (local_subnets, local_subnets_v6) = match kill_switch().as_ref() {
                Some(r) => (r.local_subnets.clone(), r.local_subnets_v6.clone()),
                None => {
                    let floor = fail_closed_base();
                    (floor.local_subnets.clone(), floor.local_subnets_v6.clone())
                }
            };
            let infrastructure = {
                let (v4, v6) = match kill_switch().as_ref() {
                    Some(r) => (&r.bootstrap_server_ips, &r.bootstrap_server_ips_v6),
                    None => {
                        let floor = fail_closed_base();
                        (&floor.bootstrap_server_ips, &floor.bootstrap_server_ips_v6)
                    }
                };
                crate::enforcement_planner::LinkInfrastructure {
                    tunnel_servers: v4
                        .iter()
                        .map(|ip| std::net::IpAddr::V4(*ip))
                        .chain(v6.iter().map(|ip| std::net::IpAddr::V6(*ip)))
                        .collect(),
                    link_resolvers: self.primary_dns(),
                }
            };
            // An address only an APPLICATION rule brought in is not pinned
            // per-destination: the app's own egress-conditional pair (or its
            // unconditional fail-closed block) already governs every flow of
            // that process, and ~12 standing filters per pinned address turned
            // hours of P2P peer churn into a thousands-strong standing filter
            // set, far past what the platform is meant to hold. An address an ADDITIONAL address rule
            // also names stays pinned — there the pin is the only guard. Gated
            // on the app pair being armable at all (TCP/UDP selected); with
            // neither selected the historic per-destination posture stands.
            // App observations are IPv4 today, so this set is too — it is
            // SUBTRACTED from the pin set, and an empty v6 half simply pins
            // what an app rule would have covered had it seen the family.
            let app_covered: std::collections::HashSet<std::net::Ipv4Addr> =
                if protocols.wants_ale_block() {
                    codegen_out
                        .app_observed_secondary_ips
                        .iter()
                        .copied()
                        .filter(|ip| {
                            !ownership
                                .additional_named()
                                .contains(&std::net::IpAddr::V4(*ip))
                        })
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
            let protectable: Vec<std::net::IpAddr> = codegen_out
                .secondary_dest_ips
                .iter()
                .copied()
                .filter(|ip| ownership.may_block(*ip))
                .filter(|ip| {
                    !crate::enforcement_planner::on_attached_segment(
                        *ip,
                        &local_subnets,
                        &local_subnets_v6,
                    )
                })
                .filter(|ip| {
                    !infrastructure.spares(
                        *ip,
                        crate::enforcement_planner::names_address_literally(
                            &rules.rule_book.secondary,
                            *ip,
                        ),
                    )
                })
                .filter(|ip| match ip {
                    std::net::IpAddr::V4(v4) => !app_covered.contains(v4),
                    std::net::IpAddr::V6(_) => true,
                })
                .collect();
            let trim = (protectable.len() != codegen_out.secondary_dest_ips.len()).then(|| {
                (
                    protectable.len(),
                    codegen_out.secondary_dest_ips.len() - protectable.len(),
                    app_covered.len(),
                )
            });
            if self.pin_trim_changed(sid, trim) {
                if let Some((kept, dropped, app_covered)) = trim {
                    tracing::info!(
                        target: "nrr::per_sid_orchestrator",
                        msg_key = "persid-plan-pin-set-trimmed",
                        sid,
                        kept,
                        dropped,
                        app_covered,
                        "kill-switch pin set trimmed: main-route-claimed addresses (blocking one kills a destination the user routed the other way) and app-observed destinations (their app's own pair is the guard)",
                    );
                }
            }
            // The shared-address census is IPv4: it counts direct hosts seen
            // on an address, and nothing observes v6 co-tenancy yet. A v6
            // address is therefore never "shared" and stays pinned.
            let (ks_dest_ips, ks_shared_excluded_ips): (
                Vec<std::net::IpAddr>,
                Vec<std::net::IpAddr>,
            ) = if policy.kill_switch_strict_shared_ips {
                (protectable, Vec::new())
            } else {
                let shared = fqdn_cache.shared_direct_ips();
                if shared.is_empty() {
                    (protectable, Vec::new())
                } else {
                    let (kept, excluded): (Vec<_>, Vec<_>) =
                        protectable.into_iter().partition(|ip| match ip {
                            std::net::IpAddr::V4(v4) => !shared.contains(v4),
                            std::net::IpAddr::V6(_) => true,
                        });
                    (kept, excluded)
                }
            };
            if let Some(status) = self
                .shared_ip_exemption_status
                .as_ref()
                .filter(|_| intent.publishes())
            {
                let prev = status.count();
                status.set(&only_v4_of(&ks_shared_excluded_ips));
                if prev != ks_shared_excluded_ips.len() as u32 && !ks_shared_excluded_ips.is_empty()
                {
                    tracing::info!(
                        target: "nrr::per_sid_orchestrator",
                        msg_key = "persid-plan-shared-ip-excluded",
                        sid,
                        excluded = ks_shared_excluded_ips.len(),
                        pinned = ks_dest_ips.len(),
                        "smart kill-switch: shared IPs excluded from the pin/block set (each is also used by a direct host; strict mode pins them regardless)",
                    );
                }
            }
            //  — is hostname-level (fake-IP) enforcement actually
            // covering rule hosts THIS compute? `fake_ip_context` is resolved
            // live above and, in production, is `Some` (with an enabled scope)
            // only when the toggle is on, the enforcement mode is Resolver,
            // AND the TUN relay stack is running — the desired-AND-running
            // signal, not merely the persisted toggle.
            let fake_ip_name_enforcement_active = fake_ip_context
                .as_ref()
                .is_some_and(|ctx| ctx.scope.is_enabled());
            // The subtraction base for every exemption set below (known-primary
            // transport permits): an IP in this set must
            // NEVER be rescued by an exemption while the secondary is down.
            // Two modes:
            //
            // - Fake-IP EFFECTIVE → subtract only the IPs actually PINNED this
            //   compute (`ks_dest_ips`, the  relaxation). A
            //   census-shared IP the smart kill-switch declined to pin stays
            //   exemptible, so its direct co-tenant (workspace.search.example
            //   sharing a front-end IP with a secondary rule host) is not
            //   blocked to death on a link that carries nothing. Safe ONLY
            //   because the rule host itself is still enforced BY NAME: the
            //   fake-IP answerer hands it a virtual address and the relay owns
            //   the flow, so the shared real IP is a side channel the rule
            //   host does not use.
            // - Fake-IP NOT effective (toggle off, non-Resolver mode, or the
            //   datapath is down) → strict subtraction of ALL secondary
            //   destination IPs, census-shared included. The IP pin/block set is
            //   then the ONLY enforcement, and an exempted shared IP is a real
            //   leak, not a side channel: 39 connections to assistant.example
            //   front-ends (rule host fail-closed) once egressed the primary in
            //   ~10 minutes through exactly this hole, because assistant's IPs are
            //   census-shared with direct hosts.
            //
            //   One carve-out: an address whose direct tenant a MAIN-route rule
            //   claims. Blocking it cannot divert that tenant into the tunnel —
            //   the user's own rule sends it the other way — so the block only
            //   kills it (search.example against a named `aistudio.search.example` on
            //   the shared front-end). Two rules of the user's own contradict
            //   each other on one address; honouring the main-route one costs a
            //   possible leak of the other while the link is down, and honouring
            //   the pin costs a dead site every second of the day. Strict mode
            //   keeps the pin-everything posture for anyone who wants the
            //   opposite trade.
            //
            // The smart PIN partition above stays smart in BOTH modes —
            // re-pinning shared IPs is what killed search.example;
            // only the exemption subtraction tightens. A fake-IP transition
            // triggers an immediate replan (the settings write hook on
            // toggle/mode flips, the datapath watchdog on health flips), so
            // this gate is re-evaluated promptly, never left waiting for an
            // unrelated recompute.
            // Every exemption this set is subtracted from is IPv4 (the
            // packet-layer primary permits), so the
            // set is too: there is no v6 exemption for a v6 address to have to
            // stay out of.
            let never_exempt_secondary_ips: std::collections::HashSet<std::net::Ipv4Addr> =
                if fake_ip_name_enforcement_active {
                    // App-observed destinations ride along even though they are
                    // no longer pinned: their guard is the per-app block, and an
                    // exemption permit outranks it — rescuing one would hand the
                    // app a primary-egress path while the tunnel is down.
                    only_v4_of(&ks_dest_ips)
                        .into_iter()
                        .chain(app_covered.iter().copied())
                        .collect()
                } else if policy.kill_switch_strict_shared_ips {
                    only_v4_of(&codegen_out.secondary_dest_ips)
                        .into_iter()
                        .collect()
                } else {
                    let main_route_claimed = fqdn_cache.shared_direct_ips_primary_ruled();
                    only_v4_of(&codegen_out.secondary_dest_ips)
                        .into_iter()
                        .filter(|ip| !main_route_claimed.contains(ip))
                        .collect()
                };
            // known-primary destination IPs
            // that earn a packet-layer permit under a block-all so ping/ICMP to a
            // positively primary-routed host is not cut. Subtract the
            // never-exempt secondary set: while the secondary is down (the only
            // time the block-all arms) those IPs must stay blocked
            // (fail-closed), never rescued via the primary permit.
            // Asked of the ARBITER, not of the filter codegen. Both answer
            // "is this address named by a main-link rule", and they answered
            // differently: the codegen lists what it managed to emit a permit
            // for (subject to its own fan-out caps), the arbiter lists what the
            // user's rules actually name. Two answers to one question is how
            // address-ownership bugs happen; this is the same
            // arbiter the route, filter and kill-switch codegens read.
            // Sorted so the emitted exemption set is stable across recomputes.
            let known_primary_dest_ips: Vec<std::net::Ipv4Addr> = {
                let mut named: Vec<std::net::Ipv4Addr> = ownership
                    .main_named()
                    .iter()
                    .filter_map(|ip| match ip {
                        std::net::IpAddr::V4(v4) => Some(*v4),
                        std::net::IpAddr::V6(_) => None,
                    })
                    .filter(|ip| !never_exempt_secondary_ips.contains(ip))
                    .collect();
                named.sort_unstable();
                named
            };
            // The exemption record BOTH postures read. Built once here so the
            // catch-all (tunnel up) and the fail-closed block-all (tunnel gone)
            // cannot spare different things: the catch-all used to carry a
            // smaller set, so a host the user carved out onto the main link
            // stopped answering ping the moment the tunnel came up.
            let shared_exemptions =
                |resolution: &crate::killswitch_codegen::KillSwitchResolution| {
                    FailClosedExemptions {
                        bootstrap_server_ips: resolution.bootstrap_server_ips.clone(),
                        bootstrap_server_ips_v6: resolution.bootstrap_server_ips_v6.clone(),
                        foreign_tunnel_luids: resolution.foreign_tunnel_luids.clone(),
                        foreign_tunnel_networks: resolution.foreign_tunnel_networks.clone(),
                        local_subnets: resolution.local_subnets.clone(),
                        local_subnets_v6: resolution.local_subnets_v6.clone(),
                        primary_dest_ips: known_primary_dest_ips.clone(),
                        // A block-all-only relaxation: while the tunnel is up, name
                        // resolution belongs in it.
                        allow_dns_over_primary: false,
                        dns_servers: Vec::new(),
                        // The catch-all never blocks the tunnel next-hop, so the
                        // liveness probe needs no hole through it.
                        probe_target_ips: Vec::new(),
                        secondary_luid: resolution.secondary_luid,
                        // Only the forwarded blanket reads it; filled where
                        // that is armed.
                        guest_network_luids: Vec::new(),
                    }
                };
            // A resolution with no usable LUID has no egress to hold anything
            // to: that tunnel is down.
            match kill_switch().clone().filter(|r| r.secondary_luid != 0) {
                Some(resolution) => {
                    let posture = nrr_domain::protection_posture(behavior_mode, protection, true);
                    let holds = crate::enforcement_planner::NetworkHolds::for_pass(
                        &ownership,
                        &ks_dest_ips,
                        || resolution.never_blocked_networks(),
                    );
                    // The catch-all without a server exemption or a trusted
                    // client would seal the tunnel's own reconnect. The rule
                    // destinations are then held to the tunnel as under "routed
                    // sites", never blocked outright on a live tunnel, and the
                    // user hears that the rest is not covered.
                    let catch_all_refused = posture
                        == nrr_domain::ProtectionPosture::CatchAllThroughTunnel
                        && resolution.bootstrap_server_ips.is_empty()
                        && tunnel_clients.is_empty();
                    let ks = if posture == nrr_domain::ProtectionPosture::CatchAllThroughTunnel
                        && !catch_all_refused
                    {
                        let ks = crate::killswitch_codegen::catch_all_kill_switch_filters_for(
                            sid,
                            &resolution,
                            &shared_exemptions(&resolution),
                            protocols,
                            !tunnel_clients.is_empty(),
                        );
                        // The catch-all IS a block-all: the DNS gate and the
                        // banner must see it as one.
                        block_all_armed = !ks.is_empty();
                        ks
                    } else {
                        let mut ks = crate::killswitch_codegen::kill_switch_filters(
                            sid,
                            &ks_dest_ips,
                            resolution.secondary_luid,
                            protocols,
                        );
                        ks.extend(crate::killswitch_codegen::kill_switch_network_filters(
                            sid,
                            &holds,
                            resolution.secondary_luid,
                            protocols,
                        ));
                        // Secondary-routed apps are pinned to the tunnel too (ALE
                        // only). Main-named addresses need no rescue: the app
                        // block sits below the primary rule band, unless the app
                        // takes all its addresses.
                        let app_pair = crate::killswitch_codegen::app_kill_switch_filters_for(
                            sid,
                            &codegen_out.secondary_app_patterns,
                            resolution.secondary_luid,
                            protocols,
                            policy.app_rules_take_all_addresses,
                        );
                        app_block_emitted |= !app_pair.is_empty();
                        ks.extend(app_pair);
                        ks
                    };
                    // Under the blanket through the tunnel, what the machine
                    // forwards is held to it too, over the floor the owner's
                    // blanket spares; otherwise it would take the main link
                    // from the packet the tunnel drops on until the next pass.
                    let forwarded_floor =
                        (block_all_armed && policy.guard_forwarded_traffic).then(|| {
                            let mut floor = shared_exemptions(&resolution);
                            floor
                                .guest_network_luids
                                .clone_from(&fail_closed_base().guest_network_luids);
                            floor
                        });
                    // The service accounts get the pins whenever the owner's
                    // guard is on — the address pairs, never the blanket.
                    let shares = self.owner_shares(
                        sid,
                        intent,
                        OwnerGuard {
                            posture: ServiceAccountPosture::Pin,
                            destinations: &ks_dest_ips,
                            holds: &holds,
                            tunnel_servers: OwnerGuard::servers_of(
                                &resolution.bootstrap_server_ips,
                                &resolution.bootstrap_server_ips_v6,
                            ),
                            local_subnets: OwnerGuard::subnets_of(
                                &resolution.local_subnets,
                                &resolution.local_subnets_v6,
                            ),
                            secondary_luid: resolution.secondary_luid,
                            protocols,
                            guard_forwarded: policy.guard_forwarded_traffic,
                            foreign_networks: &resolution.foreign_tunnel_networks,
                            block_all: forwarded_floor.as_ref(),
                            main_networks: &codegen_out.primary_dest_networks,
                        },
                        &tunnel_clients,
                    );
                    collect_service_account_block_ids(&shares.service, &mut killswitch_block_ids);
                    filters.extend(shares.service);
                    filters.extend(shares.forwarded);
                    // A blanket block covers every network, so only a
                    // per-destination posture leaves any of them open.
                    if intent.publishes() {
                        let blanket = crate::enforcement_planner::NetworkHolds::default();
                        let in_force = if block_all_armed { &blanket } else { &holds };
                        self.network_hold_log.note(sid, in_force);
                    }
                    let latch = if catch_all_refused {
                        "catch-all-refused"
                    } else if ks.is_empty() {
                        "nothing-to-hold"
                    } else {
                        "active"
                    };
                    let changed = self.posture_changed_for(intent, sid, latch);
                    if changed && catch_all_refused {
                        tracing::warn!(
                            target: "nrr::per_sid_orchestrator",
                            msg_key = "persid-plan-blanket-block-refused",
                            sid,
                            "the settings ask for a blanket block, but no tunnel-server address could be read and no trusted VPN client is known: arming it would seal the tunnel's own reconnect, so only the rule destinations are held to the tunnel",
                        );
                        if let Some(bus) = self.events.as_ref() {
                            bus.publish_for(
                                sid,
                                nrr_shared::ipc_payloads::StatusUpdateEvent::ProtectionCoverageChanged {
                                    reason: "blanket-block-not-armed".to_string(),
                                },
                            );
                        }
                    }
                    if ks.is_empty() {
                        // A cold cache leaves nothing to pin yet. Nothing is
                        // blocked in its place: the tunnel is up, and an
                        // unconditional block would cut what it carries.
                        if changed {
                            tracing::info!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                "leak protection on, tunnel up, nothing to hold to it yet",
                            );
                        }
                    } else {
                        if changed {
                            tracing::info!(
                                target: "nrr::per_sid_orchestrator",
                                msg_key = "persid-plan-kill-switch-active",
                                sid,
                                mode = ?behavior_mode,
                                kill_switch_filters = ks.len(),
                                pinned_addresses = ks_dest_ips.len(),
                                "kill-switch active — pinned egress-conditional filters",
                            );
                        } else {
                            tracing::debug!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                kill_switch_filters = ks.len(),
                                pinned_addresses = ks_dest_ips.len(),
                                "kill-switch active — pinned egress-conditional filters",
                            );
                        }
                        collect_block_ids(&ks, &mut killswitch_block_ids);
                        filters.extend(ks);
                        // The catch-all blocks every off-tunnel flow, the VPN
                        // client's own control traffic over the main link
                        // included, so the clients are exempted at arming. The
                        // pins need no such permit: it would only weaken them.
                        if block_all_armed {
                            filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                                sid,
                                &tunnel_clients,
                            ));
                        }
                    }
                }
                None => {
                    // The secondary (VPN) interface could not be resolved at
                    // all. A boot where the link's client has not started yet
                    // looks exactly like a tunnel that dropped, and both answer
                    // the same way: what protection holds waits rather than
                    // takes the main link. The wait is visible — `secondary-down`
                    // reaches the window and the tray.
                    let effective_block_all =
                        nrr_domain::protection_posture(behavior_mode, protection, false)
                            == nrr_domain::ProtectionPosture::BlockAll;
                    let mut exemptions = fail_closed_base().clone();
                    // opt-in: keep name resolution working over the primary link
                    // while the block-all is engaged (port-scoped UDP/TCP 53).
                    exemptions.allow_dns_over_primary = policy.allow_dns_over_primary;
                    // Port 53 reaches the machine's own resolvers and no other host.
                    exemptions.dns_servers = self.primary_dns();
                    // known-primary hosts get a packet-layer permit so ping/ICMP
                    // to them survives the block-all (TCP/UDP already escapes at
                    // the ALE rule permit).
                    exemptions.primary_dest_ips = known_primary_dest_ips.clone();
                    block_all_armed = effective_block_all;
                    outage_hold = effective_block_all;
                    // The networks the tunnel's rules name are pinned whatever
                    // the posture: the blanket sits below the main-link rule
                    // band, the holds above it, and only the holds keep a
                    // main-link program off a network the tunnel owns. The log
                    // still reads "blanket" — nothing is too wide or spared
                    // under a block-all.
                    let pinned_holds = crate::enforcement_planner::NetworkHolds::for_pass(
                        &ownership,
                        &ks_dest_ips,
                        || exemptions.never_blocked_networks(),
                    );
                    let holds = if effective_block_all {
                        crate::enforcement_planner::NetworkHolds::default()
                    } else {
                        pinned_holds.clone()
                    };
                    if intent.publishes() {
                        self.network_hold_log.note(sid, &holds);
                    }
                    // Armed for BOTH shapes: the per-destination one covers only
                    // the addresses already known, which is exactly the state a
                    // DNS answer or a seeder backoff must not ignore.
                    fail_closed_armed = true;
                    let mut fc = self.fail_closed_filters(
                        sid,
                        &ks_dest_ips,
                        &pinned_holds,
                        &exemptions,
                        protocols,
                        FailClosedPosture {
                            block_all: effective_block_all,
                        },
                    );
                    // A secondary-routed app is cut whole while its link is
                    // unresolved: the per-IP set no longer carries its observed
                    // destinations, and its unobserved ones would otherwise
                    // egress the primary until the observer caught up.
                    let app_blocks = crate::killswitch_codegen::fail_closed_block_apps_for(
                        sid,
                        &codegen_out.secondary_app_patterns,
                        protocols,
                        policy.app_rules_take_all_addresses,
                    );
                    app_block_emitted |= !app_blocks.is_empty();
                    fc.extend(app_blocks);
                    // Address blocks only for the service accounts, even when
                    // the owner's posture is a blanket; forwarded traffic takes
                    // the blanket with it.
                    let shares = self.owner_shares(
                        sid,
                        intent,
                        OwnerGuard {
                            posture: ServiceAccountPosture::Block,
                            destinations: &ks_dest_ips,
                            holds: &pinned_holds,
                            tunnel_servers: OwnerGuard::servers_of(
                                &exemptions.bootstrap_server_ips,
                                &exemptions.bootstrap_server_ips_v6,
                            ),
                            local_subnets: OwnerGuard::subnets_of(
                                &exemptions.local_subnets,
                                &exemptions.local_subnets_v6,
                            ),
                            secondary_luid: 0,
                            protocols,
                            guard_forwarded: policy.guard_forwarded_traffic,
                            foreign_networks: &exemptions.foreign_tunnel_networks,
                            block_all: effective_block_all.then_some(&exemptions),
                            main_networks: &codegen_out.primary_dest_networks,
                        },
                        &tunnel_clients,
                    );
                    collect_service_account_block_ids(&shares.service, &mut killswitch_block_ids);
                    filters.extend(shares.service);
                    filters.extend(shares.forwarded);
                    // Full level on a posture change or a heartbeat (the shape is
                    // part of the posture); the ~5 s re-derivations in between
                    // drop to debug — a long block-all with no line after the
                    // first reads as "silently stuck", hence the heartbeat.
                    let posture = if effective_block_all {
                        "unresolved-fail-closed-block-all"
                    } else {
                        "unresolved-fail-closed-per-ip"
                    };
                    match self.posture_log_event_for(intent, sid, posture) {
                        PostureLogEvent::Transition => {
                            tracing::warn!(
                                target: "nrr::per_sid_orchestrator",
                                msg_key = "persid-plan-secondary-unresolved-fail-closed",
                                sid,
                                mode = ?behavior_mode,
                                block_all = effective_block_all,
                                fail_closed_filters = fc.len(),
                                "secondary interface unresolved — leak protection holds traffic",
                            );
                            // Ask for the re-resolve on the arming edge: the
                            // common cause is a tunnel adapter just recreated with
                            // a new GUID, which the name heal finds at once.
                            if let Some(requests) =
                                self.rebind_requests.as_ref().filter(|_| intent.publishes())
                            {
                                requests.request("fail-closed-armed");
                            }
                        }
                        PostureLogEvent::Heartbeat { elapsed } => {
                            tracing::warn!(
                                target: "nrr::per_sid_orchestrator",
                                msg_key = "persid-plan-secondary-unresolved-heartbeat",
                                sid,
                                mode = ?behavior_mode,
                                block_all = effective_block_all,
                                fail_closed_filters = fc.len(),
                                elapsed_minutes = elapsed.as_secs() / 60,
                                "secondary interface still unresolved — leak protection still holds traffic (heartbeat)",
                            );
                            // After a resume the binding can stay unresolvable
                            // until something re-runs the name heal.
                            if let Some(requests) =
                                self.rebind_requests.as_ref().filter(|_| intent.publishes())
                            {
                                requests.request("fail-closed-heartbeat");
                            }
                        }
                        PostureLogEvent::Steady => {
                            tracing::debug!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                block_all = effective_block_all,
                                fail_closed_filters = fc.len(),
                                "secondary interface unresolved — leak protection holds traffic",
                            );
                        }
                    }
                    collect_block_ids(&fc, &mut killswitch_block_ids);
                    filters.extend(fc);
                    // The secondary is DOWN here, so a VPN client is
                    // bootstrapping over the primary; permit it through the
                    // block so the tunnel can establish.
                    filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                        sid,
                        &tunnel_clients,
                    ));
                }
            }
        }
        if app_block_emitted {
            let floor = self.destination_less_block_floor(
                sid,
                &filters,
                kill_switch().as_ref(),
                &|| fail_closed_base().clone(),
                ipv6.families() == crate::enforcement_planner::FamilyScope::Both,
            );
            filters.extend(floor);
        }
        timings.mark("kill-switch");
        // leak-guard disarmed ⇒ reset the posture latch so a
        // later re-arm logs at full level again (recorded silently).
        if !leak_guard_armed {
            let _ = self.posture_changed_for(intent, sid, "off");
            // Nothing is pinned while disarmed, so no shared-IP
            // exclusions either; clear the GUI warning.
            if let Some(status) = self
                .shared_ip_exemption_status
                .as_ref()
                .filter(|_| intent.publishes())
            {
                status.set(&[]);
            }
        }
        // Whatever posture blocked above, a corporate tunnel beside ours keeps
        // the networks it carries.
        if crate::killswitch_codegen::has_posture_block(&filters) {
            let (networks, own_luid) = match kill_switch() {
                Some(resolution) => (
                    resolution.foreign_tunnel_networks.clone(),
                    resolution.secondary_luid,
                ),
                None => (fail_closed_base().foreign_tunnel_networks.clone(), 0),
            };
            if !networks.is_empty() {
                let present: std::collections::HashSet<nrr_platform_api::types::WfpFilterId> =
                    filters.iter().map(|f| f.id).collect();
                let counted = crate::killswitch_codegen::foreign_tunnel_permits_counted(
                    sid, &filters, &networks, own_luid,
                );
                if intent.publishes() {
                    self.note_foreign_networks_cut(sid, counted.cut);
                }
                filters.extend(
                    counted
                        .filters
                        .into_iter()
                        .filter(|f| !present.contains(&f.id)),
                );
            }
        }
        // Another VPN's handshake, through a blanket only: the per-destination
        // guard cuts nothing but rule hosts.
        if block_all_armed {
            filters.extend(crate::killswitch_codegen::vpn_handshake_filters(
                sid,
                &crate::vpn_gateway_confirm::global_vpn_gateways().confirmed_addresses(sid),
            ));
        }
        // DoH/DoT lockdown. Independent of the kill-switch pins
        // above: block browser DNS-over-HTTPS to the resolver set (443/IP) + DNS-
        // over-TLS globally (853) so the observer sees plaintext DNS again (the
        // plaintext-DNS blind-spot class). Applied when enabled AND in scope — always,
        // or (the default) only while leak protection is on. The blocks sit in their own weight band above
        // rule permits but below the exemptions, so they never break the tunnel or
        // a primary-routed app. The resolver IPs are already resolved by the
        // composition root (host entries via the FQDN cache).
        if crate::doh_lockdown_policy::doh_lockdown_active(
            policy.doh_lockdown_auto,
            policy.doh_lockdown_enabled,
            policy.doh_lockdown_scope,
            protection.is_on(),
            crate::rule_book_facts::needs_names_seen(
                &rules.rule_book,
                policy.mode == super::PerSidBehaviorMode::PreferSecondaryWhenAvailable,
            ),
        ) {
            let doh = crate::killswitch_codegen::doh_dot_block_filters(
                sid,
                &policy.doh_resolver_ips,
                true, // DoT (853) is a global block whenever the lockdown is active
            );
            if !doh.is_empty() {
                tracing::debug!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    doh_filters = doh.len(),
                    resolver_ips = policy.doh_resolver_ips.len(),
                    scope = policy.doh_lockdown_scope.as_slug(),
                    "DoH/DoT lockdown blocks emitted",
                );
                // Its own band: a resolver drop is neither the tunnel's doing
                // nor a rule of the user's, and only an id set can tell the
                // notice path which of the two it is not.
                killswitch_block_ids.dns_lockdown.extend(
                    doh.iter()
                        .filter(|s| s.action == WfpAction::Block)
                        .map(|s| s.id.raw),
                );
                // The lockdown is the user's own protection: it also binds what
                // leaves through a corporate tunnel, whose permits would
                // otherwise outrank it for a resolver that tunnel routes.
                let (tunnels, own_luid) = match kill_switch() {
                    Some(resolution) => (
                        crate::killswitch_codegen::foreign_luids_of(
                            &resolution.foreign_tunnel_luids,
                            &resolution.foreign_tunnel_networks,
                        ),
                        resolution.secondary_luid,
                    ),
                    None => (
                        crate::killswitch_codegen::foreign_luids_of(
                            &fail_closed_base().foreign_tunnel_luids,
                            &fail_closed_base().foreign_tunnel_networks,
                        ),
                        0,
                    ),
                };
                let vetoes = crate::killswitch_codegen::doh_foreign_vetoes(
                    sid, &doh, &filters, &tunnels, own_luid,
                );
                killswitch_block_ids
                    .dns_lockdown
                    .extend(vetoes.iter().map(|s| s.id.raw));
                filters.extend(doh);
                filters.extend(vetoes);
            }
        }
        // Standing-volume watchdog. Four 0xEF crashes established that the BFE
        // host degrades over hours under thousands of standing filters.
        //
        // The line sits above the volume a healthy session actually reaches and
        // below the zone those crashes came from. A measured 6h47m run settled
        // at ~2860 and then SHED to ~2430 once the six-hour confirmation window
        // started retiring addresses — a plateau, not a climb — while the
        // crashes came at ~3700. A line at 1000 was crossed half an hour into
        // every session and said nothing about the rest of it.
        const STANDING_FILTER_ALARM: usize = 3200;
        if intent.publishes() {
            // What the standing set is MADE OF, whatever its size. The alarm
            // only speaks above the line, and by then the composition is
            // history: this is the line that says which emitter grew, and when.
            // Debug, and deduped on the breakdown itself — a recompute that
            // changes nothing has nothing to report.
            let breakdown = crate::wfp_bands::render_standing_volume(&filters);
            let changed = {
                let mut seen = self
                    .standing_volume_last
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                seen.get(sid) != Some(&breakdown) && {
                    seen.insert(sid.to_string(), breakdown.clone());
                    true
                }
            };
            if changed {
                tracing::debug!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    filters = filters.len(),
                    by_band = %breakdown,
                    "standing WFP filter set changed composition",
                );
            }
        }
        if intent.publishes() {
            let mut alarmed = self
                .standing_volume_alarmed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Re-armed on each new HIGH-WATER MARK, not once per session. The
            // rising-edge-only version fired at the first crossing and then went
            // quiet for six hours, which is exactly the window it exists to
            // report on: the second thousand filters is the interesting one.
            let previous = alarmed.get(sid).copied().unwrap_or(0);
            if filters.len() > STANDING_FILTER_ALARM && filters.len() > previous {
                alarmed.insert(sid.to_string(), filters.len());
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-plan-standing-filter-alarm",
                    sid,
                    filters = filters.len(),
                    previous_peak = previous,
                    threshold = STANDING_FILTER_ALARM,
                    // A total says a number is high and nothing about who
                    // produced it. The first packed run measured 2260 with the
                    // kill switch at 176 and DoH at 34 — the remaining ~2000
                    // were the rule band, and finding that out took a hand
                    // count.
                    by_band = %crate::wfp_bands::render_standing_volume(&filters),
                    "standing WFP filter volume above the alarm line and still rising — packing regression? Alarm only: dropping guards would trade the BFE crash for a leak",
                );
            } else if filters.len() <= STANDING_FILTER_ALARM && alarmed.remove(sid).is_some() {
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-plan-standing-filter-recovered",
                    sid,
                    filters = filters.len(),
                    "standing WFP filter volume back under the alarm line",
                );
            }
            drop(alarmed);
            note_machine_volume(
                crate::standing_volume::global_standing_volume().record(
                    sid,
                    filters.len(),
                    nrr_platform_api::enforcement::EnforcementCapabilities::current()
                        .standing_filter_alarm,
                ),
            );
        }
        // edge-triggered OS resolver-cache flush; a no-op
        // unless the block-all state changed since the previous compute.
        if intent.publishes() {
            let flushed = self.note_block_all_state(sid, block_all_armed);
            self.note_outage_hold(sid, outage_hold);
            self.note_fail_closed_state(sid, fail_closed_armed, flushed);
            // Both postures cut at the packet layer, which has no user
            // condition — see `note_machine_wide_cut`.
            self.note_machine_wide_cut(sid, block_all_armed);
            self.update_killswitch_registry(sid, killswitch_block_ids);
        }
        timings.mark("publish");
        crate::phase_timings::report_if_slow(
            &timings,
            "compute-filters",
            std::time::Duration::from_secs(1),
        );
        Ok(ComputedFilterSet::Install(ComputedPlan {
            filters,
            unresolved_apps,
        }))
    }

    /// Says, once per change, that networks of other tunnels passed the cap and
    /// stay cut: a silent cut reads as a dead corporate network.
    fn note_foreign_networks_cut(&self, sid: &str, cut: (usize, usize)) {
        let mut seen = self
            .foreign_cut_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Principals are few; the bound only guards a pathological churn.
        if seen.len() >= 256 && !seen.contains_key(sid) {
            seen.clear();
        }
        let previous = seen.insert(sid.to_string(), cut);
        if cut != (0, 0) && previous != Some(cut) {
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "foreign-tunnel-networks-over-cap",
                sid,
                count = cut.0 + cut.1,
                cap = crate::wfp_bands::FOREIGN_TUNNEL_MAX_NETWORKS,
                "networks of other tunnels past the per-tunnel cap stay under the guard",
            );
        }
    }

    /// The loopback / link-local / LAN / tunnel-server floor for a block with no
    /// destination condition, minus what a blanket posture already emitted.
    ///
    /// Such a block matches everything its scope sends off the tunnel, so
    /// without the floor a pinned app cannot reach 127.0.0.1, its router or a
    /// NAS even while the tunnel is up. The floor is the one the blanket
    /// postures carry, so both spare exactly the same things; its ids match
    /// theirs, which is how a posture that already carries it is recognised.
    fn destination_less_block_floor(
        &self,
        sid: &str,
        emitted: &[WfpFilterSpec],
        kill_switch: Option<&KillSwitchResolution>,
        fail_closed: &dyn Fn() -> FailClosedExemptions,
        ipv6: bool,
    ) -> Vec<WfpFilterSpec> {
        let exemptions = match kill_switch {
            Some(resolution) => FailClosedExemptions {
                bootstrap_server_ips: resolution.bootstrap_server_ips.clone(),
                bootstrap_server_ips_v6: resolution.bootstrap_server_ips_v6.clone(),
                local_subnets: resolution.local_subnets.clone(),
                local_subnets_v6: resolution.local_subnets_v6.clone(),
                ..FailClosedExemptions::default()
            },
            None => fail_closed(),
        };
        let present: std::collections::HashSet<nrr_platform_api::types::WfpFilterId> =
            emitted.iter().map(|f| f.id).collect();
        let mut floor = crate::killswitch_codegen::destination_less_floor(sid, &exemptions);
        if ipv6 {
            floor.extend(crate::killswitch_codegen::destination_less_floor_v6(
                sid,
                &exemptions.bootstrap_server_ips_v6,
                &exemptions.local_subnets_v6,
            ));
        }
        floor
            .into_iter()
            .filter(|f| !present.contains(&f.id))
            .collect()
    }
}

/// One line per apply naming the app-rule destinations other programs share:
/// pinning one would move those programs too, so it stays off the tunnel, and
/// with the guard on the app's own traffic to it is dropped, not sent direct.
fn log_app_destinations_shared(
    sid: &str,
    shared: &mut Vec<(String, std::net::Ipv4Addr)>,
    guarded: bool,
) {
    shared.sort();
    shared.dedup();
    let shown: Vec<String> = shared
        .iter()
        .take(8)
        .map(|(app, ip)| format!("{app} → {ip}"))
        .collect();
    if guarded {
        tracing::warn!(
            target: "nrr::wfp-codegen",
            msg_key = "persid-plan-app-dest-shared-guarded",
            sid = %sid,
            count = shared.len(),
            conflicts = %shown.join(", "),
            "application rule addresses are used by other programs too, so they stay off the additional link; with leak protection on the application cannot reach them while that link is up",
        );
    } else {
        tracing::info!(
            target: "nrr::wfp-codegen",
            msg_key = "persid-plan-app-dest-shared",
            sid = %sid,
            count = shared.len(),
            conflicts = %shown.join(", "),
            "application rule addresses are used by other programs too, so they stay off the additional link and the application reaches them over the main link",
        );
    }
}

/// The machine total's log line: every signed-in user's set counts towards the
/// filtering service's limit, which no single user's count shows.
pub(super) fn note_machine_volume(edge: crate::standing_volume::MachineEdge) {
    use crate::standing_volume::MachineEdge;
    match edge {
        MachineEdge::Rising {
            total,
            previous_peak,
        } => tracing::warn!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-plan-machine-filter-alarm",
            filters = total,
            previous_peak,
            "standing WFP filters on the machine, all users together, above the alarm line and still rising",
        ),
        MachineEdge::Recovered { total } => tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-plan-machine-filter-recovered",
            filters = total,
            "standing WFP filters on the machine back under the alarm line",
        ),
        MachineEdge::Steady => {}
    }
}
