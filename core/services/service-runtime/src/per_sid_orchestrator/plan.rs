//! The plan: what filters a SID's policy compiles to.
//!
//! One method, and it was 1193 lines of the orchestrator — longer than most
//! files in this crate. It stays a method (it reads a dozen private fields, and
//! a child module of the defining module still sees them), but it no longer
//! sits between the builder and the apply path where nobody could scroll past
//! it.
//!
//! Behaviour is unchanged: the body is the same statements in the same order.

use super::*;

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
                if intent.publishes() {
                    // no enforceable policy → no
                    // app rules are unenforced; clear any stale unresolved-app set so
                    // the GUI banner does not keep listing a now-phantom app.
                    self.clear_app_enforcement_status();
                    // policy gone ⇒ any block-all is disarming.
                    self.note_block_all_state(sid, false);
                    self.note_fail_closed_state(sid, false);
                    // No policy ⇒ no kill-switch filters either; drop any stale
                    // entry so the registry never role-verifies a drop for a SID
                    // whose leak-guard is no longer armed.
                    self.update_killswitch_registry(sid, KillswitchBlockIds::default());
                }
                return Ok(ComputedFilterSet::NoPolicy);
            }
        };
        // ONE read of the FQDN cache for the whole pass. Every mechanism below
        // — codegen, address ownership, the shared-IP census, the kill-switch
        // trim — used to query it independently, per rule and per hostname, so
        // a pass over a real rule book cost tens of thousands of round trips
        // against the connection the live DNS observation path writes to. It
        // also means the pass now sees ONE state of the cache instead of a
        // slightly newer one at every lookup.
        let cache_snapshot = self.fqdn_cache.snapshot_for_compute();
        let fqdn_cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup = match &cache_snapshot {
            Some(snapshot) => snapshot,
            None => self.fqdn_cache.as_ref(),
        };
        // an activation dispatch runs BEFORE the
        // active-revision pointer commits (all-or-nothing: revert must stay
        // possible), so a storage read here would still see the PREVIOUS
        // revision. The dispatcher passes the revision content it is applying;
        // every other caller reads the active pointer as before.
        let rules = match rules_override
            .cloned()
            .or_else(|| self.rules_provider.active_rules_for(sid))
        {
            Some(r) => r,
            None => {
                if intent.publishes() {
                    self.clear_app_enforcement_status();
                    // rules gone ⇒ any block-all is disarming.
                    self.note_block_all_state(sid, false);
                    self.note_fail_closed_state(sid, false);
                    self.update_killswitch_registry(sid, KillswitchBlockIds::default());
                }
                return Ok(ComputedFilterSet::NoActiveRules);
            }
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
                r.app_match.as_ref().map(|a| match &a.pattern {
                    nrr_domain::canonical::CanonicalAppPattern::Exact(s)
                    | nrr_domain::canonical::CanonicalAppPattern::Glob(s) => s.clone(),
                })
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
                    sid,
                    primary_app_rules = primary_apps.join(", "),
                    secondary_app_rules = secondary_apps.join(", "),
                    "delivered app-match rules for this SID (apply)",
                );
            }
        }

        // swap: route the policy's behaviour-mode through the codegen.
        let behavior_mode = behavior_mode_for_codegen(&policy, rules.behavior_mode);
        // shared-IP denylist from the SAME enforcement rule
        // book + live cache the codegen reads, so the WFP set and the route
        // table decline the same shared IPs coherently.
        let mut secondary_ip_denylist = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            fqdn_cache,
            policy.shared_ip_policy,
        );
        // Block D (fake-IP, slice 5) — fold fake-IP into the plan. Computed
        // against the ORIGINAL denylist (which doubles as the shared-IP census),
        // BEFORE its suppress-set is merged in: the /32 permits of shared real
        // addresses are suppressed via the denylist, and the pool permit is
        // appended after codegen. The context is resolved
        // LIVE for this compute; a `None` / disabled context is a no-op, so the
        // non-fake-IP path is byte-for-byte unchanged.
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
        }
        let mut codegen_out = generate_filters(CodegenInput {
            sid,
            rule_book: &rules.rule_book,
            behavior_mode,
            fqdn_cache,
            app_observations: self.app_observations.as_ref(),
            app_resolver: self.app_resolver.as_ref(),
            secondary_ip_denylist: &secondary_ip_denylist,
            zone_priority_over_ip: false,
        });
        // Shadow-compare the neutral pipeline against the live one, BEFORE the
        // fake-IP augmentation is folded in (the planner does not model it yet).
        // Compares only, never applies: the point of this step is to learn on
        // real traffic whether the two agree, while the path that actually
        // enforces stays exactly as it was.
        //
        // Guarded rather than stubbed off-Windows: there is no WFP filter set to
        // compare against there, and a no-op body would read as "checked, agreed".
        #[cfg(windows)]
        self.shadow_compare_neutral_plan(
            sid,
            behavior_mode,
            &rules.rule_book,
            &codegen_out.filters,
        );
        if let Some(aug) = fake_ip_augmentation {
            codegen_out.filters.extend(aug.extra_filters);
        }
        // surface app rules whose exe could not be resolved to
        // a path (app not installed / not running / not in App Paths) so they are
        // not silently unenforced. The rule's observation /32 mirrors (if any)
        // still apply; only the direct per-process ALE_APP_ID filter is absent.
        // Besides the WARN log we publish the set into the shared
        // `AppEnforcementStatus` (when wired) so the SnapshotInitial handler
        // can drive a GUI banner. WARN (not INFO): a rule that silently
        // enforces nothing is worth a look, not just a diagnostic trail.
        let mut unresolved_apps: Vec<String> = Vec::new();
        let mut over_capped: Vec<String> = Vec::new();
        // Rule hosts enforcement could not act on because the cache holds no
        // confirmed address for them. Handed to the DNS side so a rule the user
        // just added stops depending on the browser happening to re-resolve.
        let mut unresolved_hosts: Vec<String> = Vec::new();
        // suffix/zone rules whose cached-hostname fan-out
        // hit `SUFFIX_FANOUT_BACKSTOP`, meaning the cache holds at least as many
        // subdomains as the cap and some were silently dropped from enforcement.
        let mut truncated_suffixes: Vec<(String, String, usize)> = Vec::new();
        // Destinations an app rule wanted but a main-route rule already names.
        // The user wrote two rules that disagree about one address; they must
        // hear which one won, or the app will look mis-routed for no visible
        // reason.
        let mut claimed_by_main: Vec<(String, std::net::Ipv4Addr)> = Vec::new();
        for diag in &codegen_out.diagnostics {
            match diag {
                crate::wfp_codegen::CodegenDiagnostic::AppUnresolved { app, .. } => {
                    unresolved_apps.push(app.clone());
                }
                crate::wfp_codegen::CodegenDiagnostic::HostnameUnresolved { hostname, .. } => {
                    unresolved_hosts.push(hostname.clone());
                }
                // A suffix/zone with nothing cached under it: the apex is the
                // one name worth asking about — every subdomain the user
                // actually visits arrives through ordinary observation.
                crate::wfp_codegen::CodegenDiagnostic::SuffixEmpty { suffix, .. } => {
                    unresolved_hosts.push(suffix.clone());
                }
                crate::wfp_codegen::CodegenDiagnostic::ZoneEmpty { zone, .. } => {
                    unresolved_hosts.push(zone.clone());
                }
                crate::wfp_codegen::CodegenDiagnostic::AppOverCapped {
                    app, resolved, cap, ..
                } => {
                    over_capped.push(format!("{app} ({cap}/{resolved})"));
                }
                crate::wfp_codegen::CodegenDiagnostic::AppDestinationClaimedByPrimary {
                    app,
                    ip,
                    ..
                } => {
                    claimed_by_main.push((app.clone(), *ip));
                }
                crate::wfp_codegen::CodegenDiagnostic::SuffixTruncated {
                    rule_id,
                    suffix,
                    cap,
                } => {
                    truncated_suffixes.push((rule_id.clone(), suffix.clone(), *cap));
                }
                _ => {}
            }
        }
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
                    sid = %sid,
                    count = claimed_by_main.len(),
                    conflicts = %shown.join(", "),
                    "an application rule is talking to addresses your main-link rules name: those                      stay on the main link. The app keeps the additional link for everything else",
                );
            }
            if !over_capped.is_empty() {
                tracing::warn!(
                    target: "nrr::app-resolver",
                    sid = %sid,
                    count = over_capped.len(),
                    apps = %over_capped.join(", "),
                    "application rules PARTIALLY enforced: exe name/glob resolved to more paths than the per-app filter cap (app: cap/resolved)",
                );
            }
            for (rule_id, suffix, cap) in &truncated_suffixes {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
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
            status.set_unresolved(unresolved_apps.clone());
        }
        let mut filters = codegen_out.filters;
        // Reactive VPN-endpoint learning — every kill-switch/fail-closed BLOCK
        // filter spec id emitted for THIS sid below is collected here (rule
        // filters above are never included), then published to the shared
        // registry at the end of this compute (see `update_killswitch_registry`).
        let mut killswitch_block_ids = KillswitchBlockIds::default();
        // The master kill-switch toggle is the whole gate: enabling it IS the
        // request to block rather than leak, so it arms even with no secondary
        // adapter bound. A user who turns it on before assigning one — or after
        // the adapter is uninstalled — gets rules-only egress, which is the
        // posture they asked for; the fail-OPEN escape hatch stays
        // `kill_switch_fail_closed = false`, not a disarmed guard.
        let leak_guard_armed = policy.kill_switch_enabled;
        // Closing the IPv6 family is about rules that point at the additional
        // route: a host with an AAAA record could otherwise take it while its
        // v4 is pinned or blocked. With no such rule there is nothing to
        // bypass, so the family stays up. (The catch-all postures cut v6 as
        // part of cutting everything — that is decided in their own codegen.)
        let ipv6_cut_wanted =
            policy.block_ipv6_when_protected && !rules.rule_book.secondary.is_empty();
        // whether THIS compute produced a fail-closed
        // block-all set (feeds the arming-edge OS resolver-cache flush at the
        // end of the function; per-IP pinning and fail-open never flush).
        let mut block_all_armed = false;
        // whether THIS compute left the guard blocking with the additional link
        // unresolved (either posture) — see `note_fail_closed_state`.
        let mut fail_closed_armed = false;
        if leak_guard_armed {
            // `fail_closed` (default) → block rather than leak when the leak-proof
            // kill-switch cannot arm because the secondary is unresolvable.
            let fail_closed = policy.kill_switch_fail_closed;
            let protocols = crate::killswitch_codegen::KillSwitchProtocols::from_bits(
                policy.kill_switch_protocols,
            );
            // the Mode-A coverage strategy decides how a
            // routed domain's UN-SEEDED edge IP is handled when the secondary is
            // unresolved (VPN down). `FailClosedUnknown` escalates the fail-closed
            // block to the catch-all so that un-seeded IP is BLOCKED rather than
            // leaked to the primary (the  chatgpt-over-primary leak while
            // the VPN was closed). This only escalates in PreferPrimary (Mode A) —
            // the other modes already catch-all — and only in the `None`
            // (secondary-unresolved) branch below; while the secondary is UP the
            // per-IP pin is correct and a catch-all would wrongly cut the primary.
            // `ZoneWidening` is not yet implemented (needs suffix/zone routing) and
            // falls back to per-IP with a one-line notice; `FailClosedUnknown` is
            // the default since HW-0714.
            use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
            let mode_a_fail_closed_unknown = behavior_mode == RouteBehaviorMode::PreferPrimary
                && policy.mode_a_coverage_strategy == ModeACoverageStrategy::FailClosedUnknown;
            if policy.mode_a_coverage_strategy == ModeACoverageStrategy::ZoneWidening {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    "mode-A coverage strategy 'zone-widening' selected but not yet enforced — falling back to per-IP pinning",
                );
            }
            // apps the user explicitly routed to the PRIMARY adapter
            // are EXEMPT from the kill-switch: an always-permit by app-id so a VPN
            // client placed on primary can always reach its server and the tunnel
            // comes up instead of being blocked (the bootstrap deadlock fix). The
            // built-in common-VPN-client exemptions are merged in so this works out
            // of the box; the user's own primary-app rules augment the set. Deduped
            // so a path named by both sources emits a single filter (ids are
            // path-derived).
            //
            // the built-in exemptions are the RESOLVED
            // on-disk exe paths (`codegen_out.vpn_default_exempt_paths`), NOT the
            // raw `DEFAULT_VPN_EXEMPT_PATTERNS` globs. The WFP `ALE_APP_ID` condition
            // keys on a real file path, so a glob stamped verbatim into `app_pattern`
            // never installed a permit (the apply layer silently skipped it) — the
            // chicken-and-egg that trapped the VPN under the kill-switch. Both
            // sources here are now concrete paths, so no `app_pattern` carrying a
            // glob (`*`) can ever leave the fail-closed set.
            //
            // fix — these permits are emitted ONLY inside the BLOCKING
            // branches below (`None` = secondary unresolved, the empty Some
            // path, and — since  — the armed mode-B catch-all), NOT
            // unconditionally. A permit-only exemption is pointless where
            // nothing is blocked (fail-open, or mode A with the secondary UP
            // and routing normally). Computed once here; each blocking branch
            // below folds them in with
            // `primary_app_exempt_filters(sid, &exempt_patterns)`.
            // the user-confirmed link-provider apps join the
            // exemption set: concrete paths from `route_link_provider_apps`,
            // strictly more precise than the built-in glob resolutions.
            //  — VERIFIED VPN clients join too: exe paths learned
            // from role-verified kill-switch drops (see
            // `crate::vpn_client_registry`), covering clients the glob
            // resolver never finds on disk. Deduped case-insensitively —
            // Windows paths; filter ids are path-derived, so two casings of
            // one path would otherwise emit two filters.
            let learned_vpn_client_paths: Vec<String> = self
                .vpn_client_apps_provider
                .as_ref()
                .map(|provider| provider())
                .unwrap_or_default();
            let exempt_patterns: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                codegen_out
                    .vpn_default_exempt_paths
                    .iter()
                    .cloned()
                    .chain(codegen_out.primary_app_patterns.iter().cloned())
                    .chain(policy.link_provider_exe_paths.iter().cloned())
                    .chain(learned_vpn_client_paths)
                    .filter(|p| seen.insert(p.to_ascii_lowercase()))
                    .collect()
            };
            // "smart" kill-switch shared-IP
            // handling (the default). An IP the shared-IP census has ALSO seen
            // on a direct (non-rule) hostname is removed from the kill-switch
            // pin/block set: IP-level blocking cannot separate co-tenants, and
            // the 0719 HW run showed strict pinning of Google front-end IPs
            // (shared by gemini/youtube secondary rules and www.google.com)
            // killing google.com in every browser — plus the VPN client's own
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
            let ownership = crate::address_ownership::AddressOwnership::resolve_with_order(
                &rules.rule_book,
                fqdn_cache,
                crate::address_ownership::ZoneVsIpOrder::from_zone_priority_over_ip(
                    policy.zone_priority_over_ip,
                ),
            );
            // The machine's OWN local networks are never pinned to the tunnel.
            // An application rule learns its destinations by watching, and a
            // NAS, a printer or a hypervisor's host address is exactly what it
            // will touch; pinned, that address is unreachable for the whole SID
            // the moment the tunnel drops - the device is one hop away on a
            // cable. Note this is NOT "skip RFC1918": a corporate tunnel to a
            // 10.x network is a legitimate destination. The distinction is
            // whether the address sits in a subnet the PRIMARY link is
            // connected to.
            let local_subnets = (self.kill_switch_resolver)(sid)
                .map(|r| r.local_subnets)
                .unwrap_or_default();
            // An address only an APPLICATION rule brought in is not pinned
            // per-destination: the app's own egress-conditional pair (or its
            // unconditional fail-closed block) already governs every flow of
            // that process, and ~12 standing filters per pinned address turned
            // hours of P2P peer churn into a thousands-strong standing filter
            // set, far past what the platform is meant to hold. An address an ADDITIONAL address rule
            // also names stays pinned — there the pin is the only guard. Gated
            // on the app pair being armable at all (TCP/UDP selected); with
            // neither selected the historic per-destination posture stands.
            let app_covered: std::collections::HashSet<std::net::Ipv4Addr> =
                if protocols.wants_ale_block() {
                    codegen_out
                        .app_observed_secondary_ips
                        .iter()
                        .copied()
                        .filter(|ip| !ownership.additional_named().contains(ip))
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
            let protectable: Vec<std::net::Ipv4Addr> = codegen_out
                .secondary_dest_ips
                .iter()
                .copied()
                .filter(|ip| ownership.may_block(*ip))
                .filter(|ip| !in_any_subnet(*ip, &local_subnets))
                .filter(|ip| !app_covered.contains(ip))
                .collect();
            if protectable.len() != codegen_out.secondary_dest_ips.len() {
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    kept = protectable.len(),
                    dropped = codegen_out.secondary_dest_ips.len() - protectable.len(),
                    app_covered = app_covered.len(),
                    "kill-switch pin set trimmed: main-route-claimed addresses (blocking one kills a destination the user routed the other way) and app-observed destinations (their app's own pair is the guard)",
                );
            }
            let (ks_dest_ips, ks_shared_excluded_ips): (
                Vec<std::net::Ipv4Addr>,
                Vec<std::net::Ipv4Addr>,
            ) = if policy.kill_switch_strict_shared_ips {
                (protectable, Vec::new())
            } else {
                let shared = fqdn_cache.shared_direct_ips();
                if shared.is_empty() {
                    (protectable, Vec::new())
                } else {
                    let (kept, excluded): (Vec<_>, Vec<_>) =
                        protectable.into_iter().partition(|ip| !shared.contains(ip));
                    (kept, excluded)
                }
            };
            if let Some(status) = self
                .shared_ip_exemption_status
                .as_ref()
                .filter(|_| intent.publishes())
            {
                let prev = status.count();
                status.set(&ks_shared_excluded_ips);
                if prev != ks_shared_excluded_ips.len() as u32 && !ks_shared_excluded_ips.is_empty()
                {
                    tracing::info!(
                        target: "nrr::per_sid_orchestrator",
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
            // transport permits, known-direct rescues): an IP in this set must
            // NEVER be rescued by an exemption while the secondary is down.
            // Two modes:
            //
            // - Fake-IP EFFECTIVE → subtract only the IPs actually PINNED this
            //   compute (`ks_dest_ips`, the  relaxation). A
            //   census-shared IP the smart kill-switch declined to pin stays
            //   exemptible, so its direct co-tenant (workspace.google.com
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
            //   leak, not a side channel: 39 connections to chatgpt.com
            //   front-ends (rule host fail-closed) once egressed the primary in
            //   ~10 minutes through exactly this hole, because chatgpt's IPs are
            //   census-shared with direct hosts.
            //
            //   One carve-out: an address whose direct tenant a MAIN-route rule
            //   claims. Blocking it cannot divert that tenant into the tunnel —
            //   the user's own rule sends it the other way — so the block only
            //   kills it (google.com against a named `aistudio.google.com` on
            //   the shared front-end). Two rules of the user's own contradict
            //   each other on one address; honouring the main-route one costs a
            //   possible leak of the other while the link is down, and honouring
            //   the pin costs a dead site every second of the day. Strict mode
            //   keeps the pin-everything posture for anyone who wants the
            //   opposite trade.
            //
            // The smart PIN partition above stays smart in BOTH modes —
            // re-pinning shared IPs is what killed google.com in the 0719 run;
            // only the exemption subtraction tightens. A fake-IP transition
            // triggers an immediate replan (the settings write hook on
            // toggle/mode flips, the datapath watchdog on health flips), so
            // this gate is re-evaluated promptly, never left waiting for an
            // unrelated recompute.
            let never_exempt_secondary_ips: std::collections::HashSet<std::net::Ipv4Addr> =
                if fake_ip_name_enforcement_active {
                    // App-observed destinations ride along even though they are
                    // no longer pinned: their guard is the per-app block, and an
                    // exemption permit outranks it — rescuing one would hand the
                    // app a primary-egress path while the tunnel is down.
                    ks_dest_ips
                        .iter()
                        .copied()
                        .chain(app_covered.iter().copied())
                        .collect()
                } else if policy.kill_switch_strict_shared_ips {
                    codegen_out.secondary_dest_ips.iter().copied().collect()
                } else {
                    let main_route_claimed = fqdn_cache.shared_direct_ips_primary_ruled();
                    codegen_out
                        .secondary_dest_ips
                        .iter()
                        .copied()
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
            // the address-ownership bugs of 23.08 happened; this is the same
            // arbiter the route, filter and kill-switch codegens read.
            // Sorted so the emitted exemption set is stable across recomputes.
            let known_primary_dest_ips: Vec<std::net::Ipv4Addr> = {
                let mut named: Vec<std::net::Ipv4Addr> = ownership
                    .main_named()
                    .iter()
                    .copied()
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
                        local_subnets: resolution.local_subnets.clone(),
                        primary_dest_ips: known_primary_dest_ips.clone(),
                        known_direct_ips: self
                            .known_direct
                            .as_ref()
                            .map(|registry| {
                                registry
                                    .snapshot()
                                    .into_iter()
                                    .filter(|ip| !never_exempt_secondary_ips.contains(ip))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        // A block-all-only relaxation: while the tunnel is up, name
                        // resolution belongs in it.
                        allow_dns_over_primary: false,
                        // The catch-all never blocks the tunnel next-hop, so the
                        // liveness probe needs no hole through it.
                        probe_target_ips: Vec::new(),
                        secondary_luid: 0,
                    }
                };
            match (self.kill_switch_resolver)(sid) {
                Some(resolution) => {
                    // Mode A (PreferPrimary) protects only the selected secondary
                    // destinations; mode B arms the catch-all (all off-tunnel).
                    let ks = match behavior_mode {
                        RouteBehaviorMode::PreferPrimary => {
                            let mut ks = crate::killswitch_codegen::kill_switch_filters(
                                sid,
                                &ks_dest_ips,
                                resolution.secondary_luid,
                                protocols,
                            );
                            //  — also pin secondary-routed apps to the
                            // secondary adapter egress (ALE layer only — no per-app ICMP).
                            // Main-named addresses need no rescue permits: the
                            // app block sits below the primary rule band, so the
                            // primary rules' own permits carry them.
                            ks.extend(crate::killswitch_codegen::app_kill_switch_filters(
                                sid,
                                &codegen_out.secondary_app_patterns,
                                resolution.secondary_luid,
                                protocols,
                            ));
                            ks
                        }
                        RouteBehaviorMode::PreferSecondaryWhenAvailable
                        | RouteBehaviorMode::StrictSecondaryFailClosed => {
                            let ks = crate::killswitch_codegen::catch_all_kill_switch_filters(
                                sid,
                                &resolution,
                                &shared_exemptions(&resolution),
                                protocols,
                            );
                            // The catch-all IS a block-all: everything not
                            // leaving through the tunnel is dropped. It was not
                            // recorded as one, so `any_block_all_armed()`
                            // answered false while it was live - the DNS gate
                            // then handed out answers for direct hosts the
                            // catch-all was cutting, and the transition INTO
                            // this posture read as a disarm (a needless DNS
                            // flush, and the GUI banner going out under a live
                            // block).
                            block_all_armed = !ks.is_empty();
                            ks
                        }
                    };
                    if ks.is_empty() {
                        // Leak-proof pair could not arm — honour the failure
                        // posture instead of silently allowing.
                        if fail_closed {
                            // The secondary is UP in this branch, so nothing is
                            // escalated: the per-IP guard is the whole posture.
                            block_all_armed = false;
                            let exemptions = FailClosedExemptions {
                                bootstrap_server_ips: resolution.bootstrap_server_ips.clone(),
                                local_subnets: resolution.local_subnets.clone(),
                                // Inert here — this branch calls fail_closed_filters
                                // with block_all=false (per-IP path), which ignores
                                // primary_dest_ips; primary IPs are never blocked
                                // per-IP. Set for struct completeness only.
                                primary_dest_ips: known_primary_dest_ips.clone(),
                                // Secondary is UP here (this is the per-IP path,
                                // block_all=false below) — DNS-over-primary is a
                                // block-all-only relaxation, so never set here.
                                allow_dns_over_primary: false,
                                // per-IP path never blocks direct hosts,
                                // so there is nothing to exempt.
                                known_direct_ips: Vec::new(),
                                // Per-IP path never blocks the tunnel next-hop
                                // (only enumerated rule destinations), so the
                                // liveness probe needs no hole here.
                                probe_target_ips: Vec::new(),
                                // The v6 cut this path may emit still has to let
                                // the tunnel itself out.
                                secondary_luid: resolution.secondary_luid,
                            };
                            // review fix — the secondary (VPN) is UP here
                            // (`Some`); `ks` is empty only because there is nothing
                            // to pin yet (cold FQDN cache for zone/suffix rules).
                            // Do NOT escalate to the catch-all block-all in this
                            // branch — that would cut ALL egress while the secondary adapter is
                            // healthy (and, with an off-subnet DNS, deadlock the
                            // cache warm-up so it never lifts). Keep the per-IP
                            // leak-guard (an empty dest set ⇒ a harmless no-op).
                            // The catch-all is reserved for the `None` branch,
                            // where the secondary is genuinely unresolved.
                            let mut fc = self.fail_closed_filters(
                                sid,
                                behavior_mode,
                                &ks_dest_ips,
                                &exemptions,
                                protocols,
                                FailClosedPosture {
                                    block_all: false,
                                    block_ipv6: ipv6_cut_wanted,
                                },
                            );
                            // App-observed destinations left the per-IP pin set,
                            // so a secondary-routed app is cut here by its own
                            // unconditional block instead — same coverage the
                            // egress pair would give with a usable tunnel.
                            fc.extend(crate::killswitch_codegen::fail_closed_block_apps(
                                sid,
                                &codegen_out.secondary_app_patterns,
                                protocols,
                            ));
                            // full-level only on posture change;
                            // the ~5 s reconcile re-deriving the same state
                            // logs at debug (NDJSON flood → archive-cap burn).
                            if self.posture_changed_for(intent, sid, "pair-empty-fail-closed") {
                                tracing::warn!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    fail_closed_filters = fc.len(),
                                    "kill-switch could not arm the leak-proof pair — FAIL-CLOSED (blocking)",
                                );
                            } else {
                                tracing::debug!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    fail_closed_filters = fc.len(),
                                    "kill-switch could not arm the leak-proof pair — FAIL-CLOSED (blocking)",
                                );
                            }
                            collect_block_ids(&fc, &mut killswitch_block_ids);
                            filters.extend(fc);
                            //  — this branch blocks too (per-IP in
                            // mode A, catch-all in mode B), so the VPN-client /
                            // primary-app exemptions must ride along, exactly
                            // as in the `None` (secondary-unresolved) branch
                            // below. Previously promised by the comment above
                            // `exempt_patterns` but never emitted here.
                            filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                                sid,
                                &exempt_patterns,
                            ));
                        } else if self.posture_changed_for(intent, sid, "pair-empty-fail-open") {
                            tracing::warn!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                "kill-switch requested but not armed this cycle (fail-open)",
                            );
                        } else {
                            tracing::debug!(
                                target: "nrr::per_sid_orchestrator",
                                sid,
                                mode = ?behavior_mode,
                                "kill-switch requested but not armed this cycle (fail-open)",
                            );
                        }
                    } else {
                        if self.posture_changed_for(intent, sid, "active") {
                            tracing::info!(
                                target: "nrr::per_sid_orchestrator",
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
                        //  — the mode-B catch-all blocks EVERY
                        // off-tunnel flow while the tunnel is UP, and that
                        // includes the VPN client's own primary-side control
                        // traffic (server handshake, connectivity checks
                        // against ROTATING provider IPs — the hidemy.name 72 s
                        // hang-per-drop class). The client's egress IS the
                        // tunnel's transport, so the app exemption set is
                        // emitted here too — proactively, at arming — not only
                        // in the fail-closed branches below. Mode A is
                        // excluded: its armed set is per-destination pins, no
                        // catch-all, so an unconditional app permit would only
                        // weaken the pinned-destination guarantee.
                        if behavior_mode != RouteBehaviorMode::PreferPrimary {
                            filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                                sid,
                                &exempt_patterns,
                            ));
                        }
                        // IPv6 with the tunnel UP and per-destination pins in
                        // place — the one posture that never closed the family.
                        // A host with an AAAA record keeps a way out we never
                        // pinned (Free resolves A only), so the same site can
                        // travel the tunnel over v4 and the main link over v6.
                        // Closing the family is the honest answer; leaving the
                        // rule applied to half the host is not. Opt-out per
                        // principal for a network that genuinely needs v6.
                        //
                        // Only in `PreferPrimary`: the other modes arm the
                        // catch-all, which emits this very set already, and a
                        // second copy would be identical filters twice.
                        if behavior_mode == RouteBehaviorMode::PreferPrimary && ipv6_cut_wanted {
                            let v6_cut = crate::killswitch_codegen::catch_all_v6_filters(
                                sid,
                                resolution.secondary_luid,
                            );
                            collect_block_ids(&v6_cut, &mut killswitch_block_ids);
                            filters.extend(v6_cut);
                        }
                    }
                }
                None => {
                    // The secondary (VPN) interface could not be resolved at
                    // all. A boot where the link's client has not started yet
                    // looks exactly like a tunnel that dropped, and both answer
                    // the same way: the rule destinations wait rather than take
                    // the main link. The wait is visible — `secondary-down`
                    // reaches the window and the tray.
                    if fail_closed {
                        let mut exemptions = (self.fail_closed_exemptions_resolver)(sid);
                        // opt-in: keep name resolution working over
                        // the primary link while the block-all is engaged (adds a
                        // port-scoped UDP/TCP-53 permit). Strict default = blocks DNS too.
                        exemptions.allow_dns_over_primary = policy.allow_dns_over_primary;
                        // known-primary hosts get a
                        // packet-layer permit so ping/ICMP to them survives the block-all
                        // (TCP/UDP already escapes at the ALE rule permit).
                        exemptions.primary_dest_ips = known_primary_dest_ips.clone();
                        // known-direct destinations (Mode-B steered
                        // answers + FCrDNS non-rule confirmations) get an ALE exempt +
                        // packet permit so plain primary-path sites survive the
                        // block-all. Subtract the never-exempt secondary set: while
                        // the secondary is down those IPs must stay blocked, never
                        // rescued via a direct-host permit (defense in depth — the
                        // provers already excluded pinned addresses). The base is
                        // two-mode (see `never_exempt_secondary_ips`): with fake-IP
                        // effective a census-shared IP the smart kill-switch declined
                        // to pin stays exemptible (its direct co-tenant remains
                        // reachable on the primary); with fake-IP off the strict base
                        // keeps it blocked — this exemption was the exact egress path
                        // of the  chatgpt.com leak.
                        if let Some(registry) = self.known_direct.as_ref() {
                            exemptions.known_direct_ips = registry
                                .snapshot()
                                .into_iter()
                                .filter(|ip| !never_exempt_secondary_ips.contains(ip))
                                .collect();
                        }
                        // a `FailClosedUnknown` Mode-A strategy
                        // escalates to the catch-all here (secondary unresolved) so a
                        // routed domain's un-seeded edge IP is blocked rather than
                        // leaked to the primary. `kill_switch_block_all` still forces
                        // it regardless of the strategy.
                        let effective_block_all =
                            policy.kill_switch_block_all || mode_a_fail_closed_unknown;
                        // The secondary is genuinely unresolved here, and in
                        // the tunnel-default modes everything the user sends is
                        // supposed to leave through it — so the escalation is
                        // the mode's own meaning, not an extra setting. Decided
                        // here rather than inside `fail_closed_filters`, so the
                        // posture the caller reports and the filters it gets
                        // cannot say different things.
                        let effective_block_all = effective_block_all
                            || behavior_mode != RouteBehaviorMode::PreferPrimary;
                        block_all_armed = effective_block_all;
                        // Armed for BOTH shapes: with the default per-IP posture
                        // the block set covers only the addresses already known,
                        // which is exactly the state a DNS answer or a seeder
                        // backoff must not ignore.
                        fail_closed_armed = true;
                        let mut fc = self.fail_closed_filters(
                            sid,
                            behavior_mode,
                            &ks_dest_ips,
                            &exemptions,
                            protocols,
                            FailClosedPosture {
                                block_all: effective_block_all,
                                block_ipv6: ipv6_cut_wanted,
                            },
                        );
                        // A secondary-routed app is cut whole while its link is
                        // unresolved: the per-IP set no longer carries its
                        // observed destinations, and its UN-observed ones never
                        // had a block in this branch at all — first contact used
                        // to egress the primary until the observer caught up.
                        fc.extend(crate::killswitch_codegen::fail_closed_block_apps(
                            sid,
                            &codegen_out.secondary_app_patterns,
                            protocols,
                        ));
                        // Full-level only on a posture change or a heartbeat (the
                        // block-all/per-IP split is part of the posture, so a
                        // coverage escalation still re-logs immediately); steady
                        // ~5 s re-derivations in between drop to debug (this line
                        // alone fired 1000+ times in a single 26-minute block-all
                        // session — logging every one would burn the archive log
                        // cap, but a multi-minute block-all with zero warns after
                        // the opening line is not distinguishable from "silently
                        // stuck", hence the periodic heartbeat).
                        let posture = if effective_block_all {
                            "unresolved-fail-closed-block-all"
                        } else {
                            "unresolved-fail-closed-per-ip"
                        };
                        match self.posture_log_event_for(intent, sid, posture) {
                            PostureLogEvent::Transition => {
                                tracing::warn!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    block_all = effective_block_all,
                                    mode_a_fail_closed_unknown,
                                    fail_closed_filters = fc.len(),
                                    "secondary interface unresolved — kill-switch FAIL-CLOSED (blocking)",
                                );
                                // Ask for the re-resolve HERE, on the arming
                                // edge — not only on the heartbeat a minute
                                // later. The common cause is a tunnel adapter
                                // that was just recreated with a new GUID: the
                                // name heal finds it immediately, and every
                                // second spent waiting is a second the user
                                // spends with their traffic blocked for no
                                // remaining reason.
                                if let Some(requests) =
                                    self.rebind_requests.as_ref().filter(|_| intent.publishes())
                                {
                                    requests.request("fail-closed-armed");
                                }
                            }
                            PostureLogEvent::Heartbeat { elapsed } => {
                                tracing::warn!(
                                    target: "nrr::per_sid_orchestrator",
                                    sid,
                                    mode = ?behavior_mode,
                                    block_all = effective_block_all,
                                    mode_a_fail_closed_unknown,
                                    fail_closed_filters = fc.len(),
                                    elapsed_minutes = elapsed.as_secs() / 60,
                                    "secondary interface still unresolved — kill-switch FAIL-CLOSED still blocking (heartbeat)",
                                );
                                // Announcing is not enough: after a resume the
                                // binding can stay unresolvable until something
                                // re-runs the name heal against live adapters.
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
                                    mode_a_fail_closed_unknown,
                                    fail_closed_filters = fc.len(),
                                    "secondary interface unresolved — kill-switch FAIL-CLOSED (blocking)",
                                );
                            }
                        }
                        collect_block_ids(&fc, &mut killswitch_block_ids);
                        filters.extend(fc);
                        // C4 — the secondary (VPN) is DOWN here, so a VPN client is
                        // bootstrapping over the primary; permit it through the block
                        // so the tunnel can establish (else fail-closed deadlocks it).
                        filters.extend(crate::killswitch_codegen::primary_app_exempt_filters(
                            sid,
                            &exempt_patterns,
                        ));
                    } else if self.posture_changed_for(intent, sid, "unresolved-fail-open") {
                        tracing::warn!(
                            target: "nrr::per_sid_orchestrator",
                            sid,
                            "kill-switch requested but secondary interface unresolved — leaving it off (fail-open)",
                        );
                    } else {
                        tracing::debug!(
                            target: "nrr::per_sid_orchestrator",
                            sid,
                            "kill-switch requested but secondary interface unresolved — leaving it off (fail-open)",
                        );
                    }
                }
            }
        }
        // leak-guard disarmed ⇒ reset the posture latch so a
        // later re-arm logs at full level again (recorded silently).
        if !leak_guard_armed {
            // Strict still emits its default block (that is the mode, not the
            // guard), so it still needs the exemptions the guard used to carry.
            if behavior_mode == RouteBehaviorMode::StrictSecondaryFailClosed {
                if let Some(resolution) = (self.kill_switch_resolver)(sid) {
                    let exemptions = FailClosedExemptions {
                        bootstrap_server_ips: resolution.bootstrap_server_ips.clone(),
                        local_subnets: resolution.local_subnets.clone(),
                        primary_dest_ips: Vec::new(),
                        allow_dns_over_primary: false,
                        known_direct_ips: Vec::new(),
                        probe_target_ips: Vec::new(),
                        secondary_luid: resolution.secondary_luid,
                    };
                    filters.extend(crate::killswitch_codegen::default_block_exemptions(
                        sid,
                        &exemptions,
                    ));
                }
            }
            let _ = self.posture_changed_for(intent, sid, "off");
            // П0-A — nothing is pinned while disarmed, so no shared-IP
            // exclusions either; clear the GUI warning.
            if let Some(status) = self
                .shared_ip_exemption_status
                .as_ref()
                .filter(|_| intent.publishes())
            {
                status.set(&[]);
            }
        }
        // DoH/DoT lockdown. Independent of the kill-switch pins
        // above: block browser DNS-over-HTTPS to the resolver set (443/IP) + DNS-
        // over-TLS globally (853) so the observer sees plaintext DNS again (the
        // dzen.ru blind-spot class). Applied when enabled AND in scope — always,
        // or (the default) only while the kill-switch master toggle is on ("only
        // under leak protection"). The blocks sit in their own weight band above
        // rule permits but below the exemptions, so they never break the tunnel or
        // a primary-routed app. The resolver IPs are already resolved by the
        // composition root (host entries via the FQDN cache).
        if policy.doh_lockdown_enabled
            && (matches!(
                policy.doh_lockdown_scope,
                nrr_storage::doh_lockdown::DohLockdownScope::Always
            ) || policy.kill_switch_enabled)
        {
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
                filters.extend(doh);
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
                    sid,
                    filters = filters.len(),
                    previous_peak = previous,
                    threshold = STANDING_FILTER_ALARM,
                    "standing WFP filter volume above the alarm line and still rising — packing regression? Alarm only: dropping guards would trade the BFE crash for a leak",
                );
            } else if filters.len() <= STANDING_FILTER_ALARM && alarmed.remove(sid).is_some() {
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    filters = filters.len(),
                    "standing WFP filter volume back under the alarm line",
                );
            }
        }
        // edge-triggered OS resolver-cache flush; a no-op
        // unless the block-all state changed since the previous compute.
        if intent.publishes() {
            self.note_block_all_state(sid, block_all_armed);
            self.note_fail_closed_state(sid, fail_closed_armed);
            // Both postures cut at the packet layer, which has no user
            // condition — see `note_machine_wide_cut`.
            self.note_machine_wide_cut(sid, block_all_armed || ipv6_cut_wanted);
            self.update_killswitch_registry(sid, killswitch_block_ids);
        }
        Ok(ComputedFilterSet::Install(ComputedPlan {
            filters,
            unresolved_apps,
        }))
    }
}
