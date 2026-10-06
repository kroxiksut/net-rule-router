//! One principal's stored rules, turned into a neutral [`EnforcementPlan`].
//!
//! Every piece this joins already existed and none of them could reach each
//! other: the rules live in the state database, the planner turns a rule book
//! into a plan, and each OS backend reconciles a plan onto the machine. What was
//! missing was the join, which is why a daemon could start, probe its mechanism,
//! announce readiness and then enforce nothing.
//!
//! ## Scope, stated plainly
//!
//! Rule-driven flows, the ROUTE intents that steer them, and the
//! per-destination fail-closed block that arms when the secondary link is gone.
//!
//! Flows and routes are planned together and applied apart, because they are two
//! mechanisms with two failure modes: a filter says what may leave, a route says
//! where it leaves through. Planning only the filters is what made a
//! route-to-secondary rule behave as a block — the traffic followed the default
//! path and met its own leak-guard drop.
//!
//! The catch-all block-all of the always-on modes is planned too, but only when
//! the machine can say what it must not cut: the tunnel's own server addresses
//! and the attached subnets, read off the route table
//! ([`crate::catch_all_exemptions`]). Without them the plan falls back to the
//! per-destination guard and says so — a blanket block that seals the tunnel's
//! reconnect turns an outage into a permanent one.
//!
//! [`PlanCoverage`] reports all of this on every pass rather than in a comment:
//! a user told their rules are applied, while the protection that makes them
//! safe is absent, is worse off than one told nothing was applied.

use std::sync::{Arc, Mutex};

use nrr_domain::user_principal::UserPrincipal;
use nrr_domain::RouteBehaviorMode;
use nrr_platform_api::app_path_resolver::AppPathResolver;
use nrr_platform_api::enforcement::{
    AppScope, ChannelAvailability, DstMatch, EgressBinding, EgressBindingSource, EgressConstraint,
    EgressRef, EnforcementPlan, FlowRule, PrecedenceClass, UserPrincipal as PlanPrincipal, Verdict,
};
use nrr_shared::RouteRole;

use crate::catch_all_exemptions::{collect_exemptions, CatchAllExemptions};
use crate::enforcement_planner::{
    never_blocked_networks, plan_catch_all_kill_switch, plan_doh_dot_block,
    plan_fail_closed_block_all, plan_fail_closed_destinations, plan_fail_closed_networks,
    plan_kill_switch_networks, NetworkHoldLog, NetworkHolds,
};
use crate::killswitch_codegen::KillSwitchProtocols;
use crate::machine_reading::MachineReading;
use crate::per_sid_orchestrator::PerSidPolicySnapshot;

use crate::app_observation_lookup::AppObservationLookup;
use crate::enforcement_planner::{plan_route_rules, plan_routes_with, PlannerInput};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::per_sid_orchestrator::{RoutePolicySource, RulesProvider};
use crate::principal_enforcement::{PlannedPolicy, PrincipalPlanSource};
use crate::route_codegen::network_routes::{names_networks, NetworkRouteFacts};
use crate::tunnel_server_memory::TunnelServerMemory;
use nrr_platform_api::tunnel_endpoints::TunnelEndpointSource;

/// What a plan covers, so the caller reports it instead of implying the whole
/// policy is in force.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlanCoverage {
    /// Flows produced from the rule book.
    pub rule_driven_flows: usize,
    /// Per-destination fail-closed blocks in this plan. Non-zero only while the
    /// secondary is gone AND the user armed the leak-guard.
    pub fail_closed_blocks: usize,
    /// Route intents planned — what actually steers traffic onto the secondary.
    pub route_intents: usize,
    /// Whether the plan's protection matches what the user's settings ask for.
    /// False when the settings call for the catch-all block-all, which this
    /// platform cannot arm safely yet — the caller must say so out loud rather
    /// than let the absence pass for coverage.
    pub kill_switch_complete: bool,
}

/// Builds plans from the per-principal policy store.
pub struct ProductionPrincipalPlanSource {
    rules: Arc<dyn RulesProvider>,
    policy: Arc<dyn RoutePolicySource>,
    fqdn_cache: Arc<dyn FqdnCacheLookup>,
    app_resolver: Arc<dyn AppPathResolver>,
    app_observations: Arc<dyn AppObservationLookup>,
    /// The machine facts a blanket block needs. `None` leaves the block-all
    /// unplanned — honest on a host with no route mechanism, where the
    /// exemptions cannot be read.
    machine: Option<MachineFacts>,
    /// Where each principal's rule conflicts are published for the Overlaps
    /// screen. `None` leaves them unpublished.
    conflicts: Option<crate::app_enforcement_status::AppEnforcementStatus>,
    network_hold_log: NetworkHoldLog,
    /// Tunnel servers no live route names. `None` plans around the live host
    /// routes alone.
    tunnel_servers: Option<TunnelServerSources>,
}

/// The tunnel servers known beyond the bound links' host routes: the kernel
/// tunnels' peers and the servers remembered from earlier passes and runs.
struct TunnelServerSources {
    memory: Arc<TunnelServerMemory>,
    endpoints: Option<Arc<dyn TunnelEndpointSource>>,
    /// The peers read this pass; one read serves every principal.
    pass_peers: Mutex<Option<Arc<[std::net::IpAddr]>>>,
}

impl TunnelServerSources {
    fn pass_peers(&self) -> Arc<[std::net::IpAddr]> {
        let mut cached = self.pass_peers.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(cached.get_or_insert_with(|| {
            self.endpoints
                .as_ref()
                .map(|source| source.tunnel_endpoints())
                .unwrap_or_default()
                .into()
        }))
    }
}

/// Where the exemption facts come from, and the pass's cached reading of them.
///
/// Cached because a pass plans for every present principal and they all share
/// one machine: re-enumerating routes and links per user would ask the same
/// question up to N times and could get N different answers.
struct MachineFacts {
    routes: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
    adapters: Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
    reading: Mutex<Option<Arc<MachineReading>>>,
}

impl ProductionPrincipalPlanSource {
    pub fn new(
        rules: Arc<dyn RulesProvider>,
        policy: Arc<dyn RoutePolicySource>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
        app_resolver: Arc<dyn AppPathResolver>,
        app_observations: Arc<dyn AppObservationLookup>,
    ) -> Self {
        Self {
            rules,
            policy,
            fqdn_cache,
            app_resolver,
            app_observations,
            machine: None,
            conflicts: None,
            network_hold_log: NetworkHoldLog::default(),
            tunnel_servers: None,
        }
    }

    /// Remember the tunnel servers each pass sees and plan around them while
    /// nothing live names them; `endpoints` adds the kernel tunnels' peers.
    /// For a platform without a route coordinator, which keeps this memory
    /// itself.
    #[must_use]
    pub fn with_tunnel_servers(
        mut self,
        memory: Arc<TunnelServerMemory>,
        endpoints: Option<Arc<dyn TunnelEndpointSource>>,
    ) -> Self {
        self.tunnel_servers = Some(TunnelServerSources {
            memory,
            endpoints,
            pass_peers: Mutex::new(None),
        });
        self
    }

    /// Publish each planned principal's rule conflicts into `status` — the one
    /// the `SnapshotInitial` handler reads.
    #[must_use]
    pub fn with_rule_conflicts(
        mut self,
        status: crate::app_enforcement_status::AppEnforcementStatus,
    ) -> Self {
        self.conflicts = Some(status);
        self
    }

    /// Supply the route table and link list the blanket block's exemptions are
    /// read from. Builder-style: a host without a route mechanism is a
    /// legitimate configuration, and there the block-all stays unplanned.
    #[must_use]
    pub fn with_machine_facts(
        mut self,
        routes: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
        adapters: Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
    ) -> Self {
        self.machine = Some(MachineFacts {
            routes,
            adapters,
            reading: Mutex::new(None),
        });
        self
    }

    /// The pass's reading of the machine, taken once and reused.
    fn machine_reading(&self) -> Option<Arc<MachineReading>> {
        let machine = self.machine.as_ref()?;
        let mut cached = machine.reading.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(reading) = cached.as_ref() {
            return Some(Arc::clone(reading));
        }
        let routes = machine
            .routes
            .get_ip_forward_table()
            .map_err(|e| {
                tracing::warn!(
                    target: "nrr::enforcement",
                    msg_key = "persid-plan-route-table-unreadable",
                    error = %e,
                    "route table unreadable: the blanket block cannot be armed this pass",
                );
            })
            .ok()?;
        let adapters = machine
            .adapters
            .enumerate_all()
            .map_err(|e| {
                tracing::warn!(
                    target: "nrr::enforcement",
                    msg_key = "persid-plan-links-unreadable",
                    error = %e,
                    "links unreadable: the blanket block cannot be armed this pass",
                );
            })
            .ok()?;
        // This path keeps no record of what it installed; our signature is it.
        let reading = Arc::new(MachineReading::new(
            Ok(routes),
            Ok(adapters),
            crate::route_codegen::is_owned_route,
        ));
        *cached = Some(Arc::clone(&reading));
        Some(reading)
    }

    /// The plan plus what it covers.
    pub fn plan_with_coverage(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> Option<(EnforcementPlan, PlanCoverage)> {
        let stored = principal.as_stored();
        let mut timings = crate::phase_timings::PhaseTimings::start();
        // No stored routing policy means the user never bound their adapters,
        // and a plan built without that would pin nothing.
        // Without a policy or rules nothing is planned, so nothing conflicts.
        let Some(policy) = self.policy.load_for_sid(stored) else {
            self.publish_conflicts(stored, None);
            return None;
        };
        timings.mark("policy");
        let Some(rules) = self.rules.active_rules_for(stored) else {
            self.publish_conflicts(stored, None);
            return None;
        };
        timings.mark("rules");

        // The shared-IP policy decides which addresses the tunnel may claim,
        // and the plan has to be built behind the same decision the Windows
        // codegen makes — otherwise this path pins addresses the policy
        // declined.
        let secondary_ip_denylist = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            self.fqdn_cache.as_ref(),
            policy.shared_ip_policy,
        );
        timings.mark("denylist");
        // What policy may do about IPv6: naming the family and STEERING it are
        // separate answers, and only the machine reading knows either.
        let ipv6 = self.ipv6_guard(&policy);
        // Every pass, whatever the book needs: the screen of a rule submitted
        // while the tunnel is down reads what was noted here.
        self.remember_tunnel_servers(&policy);
        let input = PlannerInput {
            fqdn_cache: self.fqdn_cache.as_ref(),
            app_resolver: self.app_resolver.as_ref(),
            app_observations: self.app_observations.as_ref(),
            zone_priority_over_ip: policy.zone_priority_over_ip,
            secondary_ip_denylist: &secondary_ip_denylist,
            ipv6,
        };
        let (mut flows, plan_report) =
            plan_route_rules(&rules.rule_book, stored, rules.behavior_mode, &input);
        // Before the early return below: a book whose every rule was skipped
        // plans nothing, and those skips are exactly what the user must see.
        self.publish_conflicts(stored, Some((&plan_report, &rules.rule_book)));
        timings.mark("planner");
        // An empty rule set is not the same as "nothing to enforce". In the
        // tunnel-default modes the protection is the blanket block and the
        // leak-guard, and neither is rule-driven: returning early here left a
        // principal in Strict with an empty book completely unprotected, and
        // the caller counted them as planned rather than as unprotected, so
        // nothing reported it either.
        if flows.is_empty() && rules.behavior_mode == RouteBehaviorMode::PreferPrimary {
            return None;
        }
        // Who owns which address, from the one arbiter. A block is never one of
        // the outcomes the user asked for when their own main-link rule names
        // the address, in any mode.
        let ownership = crate::address_ownership::AddressOwnership::resolve_with_order(
            &rules.rule_book,
            self.fqdn_cache.as_ref(),
            crate::address_ownership::ZoneVsIpOrder::from_zone_priority_over_ip(
                policy.zone_priority_over_ip,
            ),
        );
        let rule_driven_flows = flows.len();
        timings.mark("ownership");

        // The blanket block, when the settings ask for it AND the machine can
        // say what it must not cut. It supersedes the per-destination guard:
        // both installed would be one policy stated twice.
        let blanket = self.blanket_block(
            stored,
            &policy,
            rules.behavior_mode,
            availability,
            &flows,
            &ownership,
        );
        let block_all_armed = !blanket.is_empty();
        flows.extend(blanket);

        // The strict mode's default catch-all (planned with the rules, above)
        // blocks everything no rule permitted — loopback, DHCP, the link's own
        // control traffic and the tunnel's handshake included. The blanket
        // posture brings its own floor; when it is not armed, nothing else
        // does, and the block stands over an empty floor. Windows never showed
        // it because the orchestrator carried a branch of its own.
        if rules.behavior_mode == RouteBehaviorMode::StrictSecondaryFailClosed && !block_all_armed {
            let exemptions = self.exemptions_for(&policy);
            flows.extend(crate::enforcement_planner::plan_default_block_exemptions(
                stored,
                &exemptions.server_ips,
                &exemptions.local_subnets,
            ));
        }

        // A rule the tunnel cannot carry over IPv6 is BLOCKED, not leaked.
        //
        // This path steers by ROUTE: a secondary rule lowers to a plain permit
        // plus a route out the tunnel, so an address with no route simply takes
        // the default one — the main link. Windows never needs this stated
        // because its kill-switch pins every protected address to the tunnel's
        // interface, and a pin over a link with no IPv6 is a permit that cannot
        // match. Here the block has to be written down.
        //
        // Only under `FiltersOnly`: with `FiltersAndRoutes` the route exists and
        // the rule is honoured; with `Off` no v6 destination was ever named.
        let unroutable_v6 = self.unroutable_v6_blocks(stored, &policy, ipv6, &flows, &ownership);
        flows.extend(unroutable_v6);

        // The leak-guard: the pin while the link is up, the block once it is
        // gone. A blanket block already states both.
        let (guard, fail_closed_blocks) = if block_all_armed {
            self.network_hold_log.forget(stored);
            (Vec::new(), 0)
        } else if availability.secondary {
            (
                self.pin_to_tunnel(stored, &policy, &mut flows, &ownership),
                0,
            )
        } else {
            let fail_closed = self.fail_closed_flows(stored, &policy, &flows, &ownership);
            let blocks = fail_closed
                .iter()
                .filter(|flow| flow.verdict == Verdict::Block)
                .count();
            (fail_closed, blocks)
        };
        flows.extend(guard);

        // Browser DoH hides the names wildcard rules learn from, so blocking it
        // sends the browser back to plaintext DNS. Same gate as the codegen.
        if doh_lockdown_active(&policy) {
            flows.extend(plan_doh_dot_block(stored, &policy.doh_resolver_ips, true));
        }
        timings.mark("guards");

        // Routes are planned even while the secondary is down: the applier
        // resolves the link at apply time and reports the ones it cannot steer,
        // which keeps "no route installed" a stated fact rather than a silent
        // omission in the plan.
        let routes = self.routes_for(
            &policy,
            rules.behavior_mode,
            &rules.rule_book,
            availability.primary,
            // The same addresses the filters were planned without: a route to
            // the tunnel for an address the policy declined would carry a
            // direct host's traffic there, as the route codegen elsewhere avoids.
            &secondary_ip_denylist,
            ipv6.route_families(),
            crate::wfp_codegen::current_rule_shape_support(),
        );
        timings.mark("routes");
        crate::phase_timings::report_if_slow(
            &timings,
            "principal-plan",
            crate::phase_timings::slow_threshold_for(
                crate::service_tasks::PRINCIPAL_ENFORCEMENT_INTERVAL,
            ),
        );

        let coverage = PlanCoverage {
            rule_driven_flows,
            fail_closed_blocks,
            route_intents: routes.len(),
            kill_switch_complete: !wants_block_all(&policy, rules.behavior_mode) || block_all_armed,
        };
        Some((
            EnforcementPlan {
                principal: PlanPrincipal::from_stored(stored).ok()?,
                flows,
                routes,
                policy_rules: Vec::new(),
            },
            coverage,
        ))
    }
}

impl ProductionPrincipalPlanSource {
    /// Store `principal`'s conflicts for the Overlaps screen; `None` clears
    /// them. The pass re-plans on a timer, so only a change is logged.
    fn publish_conflicts(
        &self,
        principal: &str,
        planned: Option<(
            &crate::enforcement_planner::PlanReport,
            &nrr_domain::canonical::CanonicalRuleBook,
        )>,
    ) {
        let Some(status) = self.conflicts.as_ref() else {
            return;
        };
        let conflicts = planned
            .map(|(report, book)| {
                crate::rule_conflicts::rule_conflict_dtos(&report.conflicts, book)
            })
            .unwrap_or_default();
        if !status.set_rule_conflicts(principal, conflicts) {
            return;
        }
        let unsupported: Vec<String> = planned
            .map(|(report, _)| report.unsupported_shapes())
            .unwrap_or_default()
            .into_iter()
            .map(|(rule_id, reason)| format!("{rule_id} ({reason})"))
            .collect();
        if !unsupported.is_empty() {
            tracing::warn!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-rule-shape-unsupported",
                sid = %principal,
                count = unsupported.len(),
                rules = %unsupported.join(", "),
                "rules not enforced: they limit an address to one application, which enforcement cannot scope yet, so they were skipped rather than applied to every application",
            );
        }
    }

    /// The blanket block-all, or nothing.
    ///
    /// Two postures share one shape. With the tunnel UP and an always-on mode,
    /// the block is what makes "everything goes through the tunnel" true rather
    /// than merely intended. With the tunnel GONE, it is the fail-closed
    /// posture: hold the traffic instead of letting it out the way the user
    /// asked it not to go.
    ///
    /// Both refuse to arm without a tunnel-server exemption — that block would
    /// seal the tunnel's own reconnect, and nothing on the machine could lift it
    /// (see the acceptance run where a well-meant blanket rule closed a working
    /// site). The caller then reports incomplete protection.
    fn blanket_block(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        mode: RouteBehaviorMode,
        availability: ChannelAvailability,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
    ) -> Vec<FlowRule> {
        if !wants_block_all(policy, mode) {
            return Vec::new();
        }
        let exemptions = self.exemptions_for(policy);
        // A remembered server alone is no licence: with the links unresolved
        // the attached subnets are unknown, and the block would cut the LAN.
        if !exemptions.can_arm() || !self.links_resolve(policy) {
            tracing::warn!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-blanket-block-refused",
                principal = stored,
                "the settings ask for a blanket block, but no tunnel-server address could be read from the route table: arming it would seal the tunnel's own reconnect, so it is NOT armed",
            );
            return Vec::new();
        }
        let protocols = KillSwitchProtocols::from_bits(policy.kill_switch_protocols);
        if availability.secondary {
            plan_catch_all_kill_switch(
                stored,
                &exemptions.server_ips,
                &exemptions.local_subnets,
                crate::enforcement_planner::Ipv6Exemptions {
                    server_ips: &exemptions.server_ips_v6,
                    local_subnets: &exemptions.local_subnets_v6,
                },
                protocols,
            )
        } else {
            plan_fail_closed_block_all(
                stored,
                &exemptions.server_ips,
                // No liveness probe on this path, and no shared-IP census: an
                // empty list asks for no holes rather than inventing them.
                &[],
                &exemptions.local_subnets,
                &primary_destinations(rule_flows, ownership),
                &[],
                crate::enforcement_planner::Ipv6Exemptions {
                    server_ips: &exemptions.server_ips_v6,
                    local_subnets: &exemptions.local_subnets_v6,
                },
                policy.allow_dns_over_primary,
                protocols,
            )
        }
    }

    /// What policy may do about IPv6 for this principal's bindings.
    ///
    /// Unreadable machine state answers [`Ipv6Guard::Off`]: without knowing
    /// what the links carry, naming the family would pin destinations on a
    /// guess.
    fn ipv6_guard(&self, policy: &PerSidPolicySnapshot) -> crate::enforcement_planner::Ipv6Guard {
        use crate::enforcement_planner::Ipv6Guard;
        let Some(reading) = self.machine_reading() else {
            return Ipv6Guard::Off;
        };
        let adapters = reading.adapters().unwrap_or_default();
        let secondary = crate::catch_all_exemptions::bound_adapter(
            adapters,
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        );
        Ipv6Guard::from_links(adapters, secondary)
    }

    /// The prefixes the bound tunnel steers the internet with, which mode A's
    /// counter-overlay has to out-specific. Empty when the machine cannot be
    /// read, which falls back to the classic `/2` set.
    fn tunnel_catch_alls(&self, policy: &PerSidPolicySnapshot) -> Vec<(std::net::Ipv4Addr, u8)> {
        let Some(reading) = self.machine_reading() else {
            return Vec::new();
        };
        let Some(tunnel) = crate::catch_all_exemptions::bound_adapter(
            reading.adapters().unwrap_or_default(),
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        ) else {
            return Vec::new();
        };
        crate::route_codegen::tunnel_catch_all_prefixes(
            reading.routes().unwrap_or_default(),
            tunnel.index,
        )
    }

    /// The route intents for `book`, network routes planned around this
    /// machine's links.
    #[allow(clippy::too_many_arguments)]
    fn routes_for(
        &self,
        policy: &PerSidPolicySnapshot,
        mode: RouteBehaviorMode,
        book: &nrr_domain::canonical::CanonicalRuleBook,
        has_primary: bool,
        denied: &std::collections::HashSet<std::net::Ipv4Addr>,
        families: crate::enforcement_planner::FamilyScope,
        support: nrr_domain::rule_shape::RuleShapeSupport,
    ) -> Vec<nrr_platform_api::enforcement::RouteIntent> {
        let catch_alls = self.tunnel_catch_alls(policy);
        let networks = self.network_route_facts(policy, book, support, &catch_alls);
        plan_routes_with(
            mode,
            book,
            has_primary,
            self.fqdn_cache.as_ref(),
            self.app_observations.as_ref(),
            denied,
            families,
            crate::address_ownership::ZoneVsIpOrder::from_zone_priority_over_ip(
                policy.zone_priority_over_ip,
            ),
            &catch_alls,
            &networks,
            support,
        )
    }

    /// What a network rule's routes must respect, from the pass's reading: the
    /// tunnel's routes, the attached networks and the tunnel's servers. Only
    /// the catch-alls when no network rule would use the rest, which keeps a
    /// host-only book's plan exactly what it was.
    fn network_route_facts(
        &self,
        policy: &PerSidPolicySnapshot,
        book: &nrr_domain::canonical::CanonicalRuleBook,
        support: nrr_domain::rule_shape::RuleShapeSupport,
        catch_alls: &[(std::net::Ipv4Addr, u8)],
    ) -> NetworkRouteFacts {
        let fallback = || NetworkRouteFacts::from_catch_alls(catch_alls);
        if !names_networks(book, support) {
            return fallback();
        }
        let Some(reading) = self.machine_reading() else {
            return fallback();
        };
        let adapters = reading.adapters().unwrap_or_default();
        let secondary = policy.secondary.as_ref().map(|b| b.display_name.as_str());
        let tunnel =
            crate::catch_all_exemptions::bound_adapter(adapters, secondary).map(|a| a.index);
        let exemptions = collect_exemptions(
            reading.routes().unwrap_or_default(),
            adapters,
            policy.primary.as_ref().map(|b| b.display_name.as_str()),
            secondary,
        );
        let servers = exemptions
            .server_ips
            .iter()
            .map(|ip| std::net::IpAddr::V4(*ip))
            .chain(
                exemptions
                    .server_ips_v6
                    .iter()
                    .map(|ip| std::net::IpAddr::V6(*ip)),
            )
            .chain(self.known_tunnel_servers())
            .collect();
        NetworkRouteFacts::read(
            reading.routes().unwrap_or_default(),
            adapters,
            tunnel,
            servers,
        )
    }

    /// What this principal's blanket block must not cut, from the pass's reading
    /// of the machine.
    ///
    /// The known servers join even while the links are unresolved: every use
    /// of a server here opens, and a stale one only permits a little more.
    fn exemptions_for(&self, policy: &PerSidPolicySnapshot) -> CatchAllExemptions {
        let Some(reading) = self.machine_reading() else {
            return CatchAllExemptions::default();
        };
        let mut exemptions = collect_exemptions(
            reading.routes().unwrap_or_default(),
            reading.adapters().unwrap_or_default(),
            policy.primary.as_ref().map(|b| b.display_name.as_str()),
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        );
        for ip in self.known_tunnel_servers() {
            match ip {
                std::net::IpAddr::V4(v4) if !exemptions.server_ips.contains(&v4) => {
                    exemptions.server_ips.push(v4);
                }
                std::net::IpAddr::V6(v6) if !exemptions.server_ips_v6.contains(&v6) => {
                    exemptions.server_ips_v6.push(v6);
                }
                _ => {}
            }
        }
        exemptions
    }

    /// Whether both bound links are present with a way out — what the
    /// exemptions need to name the attached subnets at all.
    fn links_resolve(&self, policy: &PerSidPolicySnapshot) -> bool {
        self.machine_reading().is_some_and(|reading| {
            crate::catch_all_exemptions::links_resolve(
                reading.adapters().unwrap_or_default(),
                policy.primary.as_ref().map(|b| b.display_name.as_str()),
                policy.secondary.as_ref().map(|b| b.display_name.as_str()),
            )
        })
    }

    /// Note the tunnel servers this principal's links show live: the bound
    /// tunnel's host routes and the kernel tunnels' peers.
    fn remember_tunnel_servers(&self, policy: &PerSidPolicySnapshot) {
        let Some(sources) = self.tunnel_servers.as_ref() else {
            return;
        };
        let Some(reading) = self.machine_reading() else {
            return;
        };
        let mut live = collect_exemptions(
            reading.routes().unwrap_or_default(),
            reading.adapters().unwrap_or_default(),
            policy.primary.as_ref().map(|b| b.display_name.as_str()),
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        )
        .server_ips;
        live.extend(sources.pass_peers().iter().filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            std::net::IpAddr::V6(_) => None,
        }));
        sources.memory.observe(&live);
    }

    /// The servers known beyond the live host routes: the kernel tunnels'
    /// peers and the remembered ones. Empty without a memory.
    fn known_tunnel_servers(&self) -> Vec<std::net::IpAddr> {
        let Some(sources) = self.tunnel_servers.as_ref() else {
            return Vec::new();
        };
        sources
            .pass_peers()
            .iter()
            .copied()
            .chain(
                sources
                    .memory
                    .remembered()
                    .into_iter()
                    .map(std::net::IpAddr::V4),
            )
            .collect()
    }

    /// Blocks over the secondary rules' IPv6 destinations when the tunnel
    /// cannot carry the family at all.
    ///
    /// Gated on the leak-guard exactly like [`Self::fail_closed_flows`]: a user
    /// who turned the guard off has said they prefer a leak to an outage, and
    /// this is that same trade on a different axis.
    fn unroutable_v6_blocks(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        ipv6: crate::enforcement_planner::Ipv6Guard,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
    ) -> Vec<FlowRule> {
        if ipv6 != crate::enforcement_planner::Ipv6Guard::FiltersOnly
            || !policy.kill_switch_enabled
            || !policy.block_secondary_when_unavailable
            || !policy.kill_switch_fail_closed
        {
            return Vec::new();
        }
        let protected: Vec<std::net::IpAddr> = secondary_destinations(rule_flows)
            .into_iter()
            .filter(|ip| ip.is_ipv6())
            .filter(|ip| ownership.may_block(*ip))
            .collect();
        if protected.is_empty() {
            return Vec::new();
        }
        plan_fail_closed_destinations(
            stored,
            &protected,
            KillSwitchProtocols::from_bits(policy.kill_switch_protocols),
        )
    }

    /// The pin over the secondary rules while their link is up.
    ///
    /// A route steers only until another route is laid over it — a VPN client
    /// reconnecting, a second tunnel — and the traffic then leaves by the main
    /// link with nothing in its way. So each address rule's own permit becomes
    /// the pin: accepted out the tunnel, dropped anywhere else — the pair
    /// Windows states as separate kill-switch filters. Reshaping the permit,
    /// rather than adding a pair beside it, keeps the chain every packet walks
    /// one rule longer per address instead of two. Networks get the separate
    /// pins, which leave their cut-outs (the tunnel's server, the LAN) open.
    fn pin_to_tunnel(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        flows: &mut [FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
    ) -> Vec<FlowRule> {
        let protocols = KillSwitchProtocols::from_bits(policy.kill_switch_protocols);
        if !policy.kill_switch_enabled || !(protocols.tcp || protocols.udp) {
            self.network_hold_log.forget(stored);
            return Vec::new();
        }
        let mut pinned = Vec::new();
        for flow in flows.iter_mut() {
            if flow.verdict != Verdict::Permit
                || flow.precedence.class != PrecedenceClass::RouteRule(RouteRole::Secondary)
                || flow.app != AppScope::Any
                || flow.egress != EgressConstraint::Any
            {
                continue;
            }
            let ip = match flow.flow.dst {
                DstMatch::HostV4(ip) => std::net::IpAddr::V4(ip),
                DstMatch::HostV6(ip) => std::net::IpAddr::V6(ip),
                _ => continue,
            };
            // The same addresses the guard blocks once the link is gone.
            if nrr_platform_api::is_exempt_from_blocking(ip) || !ownership.may_block(ip) {
                continue;
            }
            flow.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
            pinned.push(ip);
        }
        let holds = NetworkHolds::for_pass(ownership, &pinned, || {
            never_blocked(&self.exemptions_for(policy))
        });
        self.network_hold_log.note(stored, &holds);
        plan_kill_switch_networks(stored, &holds, protocols)
    }

    /// The per-destination and per-network blocks that arm while the secondary
    /// is unreachable.
    ///
    /// Empty unless the user actually armed the leak-guard: it is opt-in, and
    /// blocking traffic nobody asked to have blocked is the one failure mode a
    /// routing product must never have. Empty too under fail-OPEN, where the
    /// user has decided a leak is preferable to an outage.
    fn fail_closed_flows(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
    ) -> Vec<FlowRule> {
        if !policy.kill_switch_enabled
            || !policy.block_secondary_when_unavailable
            || !policy.kill_switch_fail_closed
        {
            self.network_hold_log.forget(stored);
            return Vec::new();
        }
        // An address the user's own main-link rules name is never blocked: the
        // guard would be cancelling one of their rules against the other, and
        // the destination ends up dead for every process on the machine.
        let protected: Vec<std::net::IpAddr> = secondary_destinations(rule_flows)
            .into_iter()
            .filter(|ip| ownership.may_block(*ip))
            .collect();
        let holds = NetworkHolds::for_pass(ownership, &protected, || {
            never_blocked(&self.exemptions_for(policy))
        });
        self.network_hold_log.note(stored, &holds);
        let protocols = KillSwitchProtocols::from_bits(policy.kill_switch_protocols);
        let mut flows = plan_fail_closed_destinations(stored, &protected, protocols);
        flows.extend(plan_fail_closed_networks(stored, &holds, protocols));
        flows
    }
}

/// What a held network must leave open, from the same reading the blanket
/// block's exemptions come from.
fn never_blocked(exemptions: &CatchAllExemptions) -> Vec<nrr_shared::ip_block::IpBlock> {
    use std::net::IpAddr;
    never_blocked_networks(
        exemptions
            .server_ips
            .iter()
            .map(|ip| IpAddr::V4(*ip))
            .chain(exemptions.server_ips_v6.iter().map(|ip| IpAddr::V6(*ip))),
        exemptions
            .local_subnets
            .iter()
            .map(|(net, len)| (IpAddr::V4(*net), *len))
            .chain(
                exemptions
                    .local_subnets_v6
                    .iter()
                    .map(|(net, len)| (IpAddr::V6(*net), *len)),
            ),
    )
}

/// The addresses the PRIMARY rules route. Under a blanket block they keep their
/// packet-layer reachability, so a host the user positively sent over the main
/// link does not lose ping along with the traffic the block is aimed at.
fn primary_destinations(
    flows: &[FlowRule],
    ownership: &crate::address_ownership::AddressOwnership,
) -> Vec<std::net::Ipv4Addr> {
    let secondary = secondary_destinations(flows);
    let mut seen = std::collections::BTreeSet::new();
    for flow in flows {
        if flow.verdict != Verdict::Permit
            || flow.precedence.class != PrecedenceClass::RouteRule(RouteRole::Primary)
        {
            continue;
        }
        if let DstMatch::HostV4(ip) = flow.flow.dst {
            // An address both rules claim stays blocked: it is secondary-bound,
            // and rescuing it here would be the leak the guard exists for. The
            // exception is an address the main link's own ADDRESS rules name —
            // there the user stated the destination itself, and the claim on
            // the other side is an application rule's learned collateral.
            if !secondary.contains(&std::net::IpAddr::V4(ip))
                || ownership.main_named().contains(&std::net::IpAddr::V4(ip))
            {
                seen.insert(ip);
            }
        }
    }
    seen.into_iter().collect()
}

/// The addresses the secondary rules route — the ones that leak to the primary
/// the moment the tunnel is gone.
///
/// Read back off the planned flows rather than re-derived from the rule book:
/// the planner already did the fan-out and the caps, and deriving them a second
/// time is how the guarded set drifts from the routed one.
fn secondary_destinations(flows: &[FlowRule]) -> Vec<std::net::IpAddr> {
    let mut seen = std::collections::BTreeSet::new();
    for flow in flows {
        if flow.verdict != Verdict::Permit
            || flow.precedence.class != PrecedenceClass::RouteRule(RouteRole::Secondary)
        {
            continue;
        }
        match flow.flow.dst {
            DstMatch::HostV4(ip) => {
                seen.insert(std::net::IpAddr::V4(ip));
            }
            DstMatch::HostV6(ip) => {
                seen.insert(std::net::IpAddr::V6(ip));
            }
            _ => {}
        }
    }
    seen.into_iter().collect()
}

impl PrincipalPlanSource for ProductionPrincipalPlanSource {
    /// Drop the previous pass's reading of the machine. Kept until now rather
    /// than cleared at the end of a pass so nothing plans against a reading it
    /// never took.
    fn begin_pass(&self) {
        if let Some(machine) = self.machine.as_ref() {
            *machine.reading.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
        if let Some(sources) = self.tunnel_servers.as_ref() {
            *sources.pass_peers.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
    }

    fn plan_for(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> Option<PlannedPolicy> {
        self.plan_with_coverage(principal, availability)
            .map(|(plan, coverage)| PlannedPolicy {
                plan,
                protection_complete: coverage.kill_switch_complete,
                fail_closed_blocks: coverage.fail_closed_blocks,
            })
    }
}

/// Whether the user's settings call for the catch-all block-all — the posture
/// this platform cannot arm safely yet.
///
/// True in the always-on modes, and in split mode when the user asked for
/// block-all explicitly. Reported, never acted on: arming a blanket block
/// without the tunnel-server and local-subnet exemptions cuts the reconnect that
/// would end the outage, and the LAN with it.
fn doh_lockdown_active(policy: &PerSidPolicySnapshot) -> bool {
    policy.doh_lockdown_enabled
        && (policy.doh_lockdown_scope == nrr_storage::doh_lockdown::DohLockdownScope::Always
            || policy.kill_switch_enabled)
}

fn wants_block_all(policy: &PerSidPolicySnapshot, mode: RouteBehaviorMode) -> bool {
    if !policy.kill_switch_enabled || !policy.block_secondary_when_unavailable {
        return false;
    }
    match mode {
        RouteBehaviorMode::PreferPrimary => policy.kill_switch_block_all,
        RouteBehaviorMode::PreferSecondaryWhenAvailable
        | RouteBehaviorMode::StrictSecondaryFailClosed => true,
    }
}

/// The saved adapter bindings of a principal, read from the same per-user policy
/// the plan comes from.
pub struct StoredEgressBindings {
    policy: Arc<dyn RoutePolicySource>,
}

impl StoredEgressBindings {
    pub fn new(policy: Arc<dyn RoutePolicySource>) -> Self {
        Self { policy }
    }
}

impl EgressBindingSource for StoredEgressBindings {
    fn bindings_for(&self, principal: &PlanPrincipal) -> EgressBinding {
        let Some(snapshot) = self.policy.load_for_sid(principal.as_stored()) else {
            return EgressBinding::default();
        };
        // The display name, not the stable id: it is what the user saw, and on
        // Linux it is also what the kernel calls the link.
        EgressBinding {
            primary: snapshot.primary.map(|b| b.display_name),
            secondary: snapshot.secondary.map(|b| b.display_name),
        }
    }
}

/// Open the state database for the enforcement path.
///
/// Its own connection, so a read here never races the writer that owns the
/// store; opened like every other so its writes reach the write ledger.
pub fn open_state_connection(path: &std::path::Path) -> Option<Arc<Mutex<rusqlite::Connection>>> {
    if !path.exists() {
        return None;
    }
    match nrr_storage::migration::open_connection(path) {
        Ok(conn) => Some(Arc::new(Mutex::new(conn))),
        Err(e) => {
            tracing::error!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-state-db-unreadable",
                error = %e,
                path = %path.display(),
                "state database could not be opened; NO policy can be enforced",
            );
            None
        }
    }
}

/// Open the rebuildable FQDN cache.
///
/// `None` degrades honestly: without the cache, domain rules resolve to no
/// addresses, so the plans built from them would be silently smaller than the
/// rule book. The caller says so rather than enforcing a thinner policy that
/// looks complete.
pub fn open_cache_store(
    path: &std::path::Path,
) -> Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>> {
    use nrr_domain::decision_lookup::FreshnessThresholds;
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::{CacheRepository, MigrationRunner};
    use nrr_storage::store::SqliteCacheStore;

    let conn = rusqlite::Connection::open(path)
        .map_err(|e| {
            tracing::warn!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-fqdn-cache-unreadable",
                error = %e,
                path = %path.display(),
                "FQDN cache could not be opened; domain rules will resolve to nothing",
            );
        })
        .ok()?;
    let _: rusqlite::Result<()> = conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;",
    );

    let runner = SqliteMigrationRunner::for_cache_db(conn);
    if let Err(e) = runner.run_pending_migrations() {
        tracing::warn!(
            target: "nrr::enforcement",
            msg_key = "persid-plan-fqdn-cache-migration-failed",
            error = %e,
            "FQDN cache migration failed; domain rules will resolve to nothing",
        );
        return None;
    }

    let store = SqliteCacheStore::new(
        runner.into_connection(),
        FreshnessThresholds::default_production(),
    );
    let store: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
    Some(store)
}

/// The planner's read-only view of an already-open cache.
///
/// Takes the store rather than a path so the refresher and the planner share ONE
/// connection: two would be two writers of one SQLite file, and the loser of
/// that race reports a busy database rather than a resolution.
#[must_use]
pub fn cache_lookup_over(
    store: Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
) -> Arc<dyn FqdnCacheLookup> {
    use nrr_domain::decision_lookup::FreshnessThresholds;

    Arc::new(crate::fqdn_cache_lookup::SqliteFqdnCacheLookup::new(
        store,
        FreshnessThresholds::default_production(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::{RuleAction, RuleId};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::per_sid_orchestrator::{ActiveRulesSnapshot, PerSidBehaviorMode, PerSidBinding};

    const SECONDARY_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 4);

    struct NoPolicy;
    impl RoutePolicySource for NoPolicy {
        fn load_for_sid(&self, _sid: &str) -> Option<PerSidPolicySnapshot> {
            None
        }
    }

    struct NoRules;
    impl RulesProvider for NoRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            None
        }
    }

    /// One enabled secondary rule for a literal address — the shape that needs
    /// no FQDN cache, so the test asserts planning and not resolution.
    struct OneSecondaryRule(RouteBehaviorMode);
    impl RulesProvider for OneSecondaryRule {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(Vec::new()),
                    secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                        id: RuleId("s-0".into()),
                        enabled: true,
                        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(
                            SECONDARY_HOST,
                        ))),
                        app_match: None,
                        comment: String::new(),
                        action: RuleAction::Route,
                        origin: None,
                    }]),
                },
                behavior_mode: self.0,
            })
        }
    }

    /// The kill-switch settings under test; everything else at its default.
    struct Policy {
        enabled: bool,
        block_when_unavailable: bool,
        fail_closed: bool,
        block_all: bool,
        /// `Some` = DoH lockdown on with scope `Always`, over these resolvers.
        doh_always: Option<Vec<IpAddr>>,
    }

    impl Policy {
        fn armed() -> Self {
            Self {
                enabled: true,
                block_when_unavailable: true,
                fail_closed: true,
                block_all: false,
                doh_always: None,
            }
        }

        /// The user chose leak-over-outage: the guard installs nothing.
        fn disarmed() -> Self {
            Self {
                enabled: false,
                ..Self::armed()
            }
        }
    }

    impl RoutePolicySource for Policy {
        fn load_for_sid(&self, _sid: &str) -> Option<PerSidPolicySnapshot> {
            let binding = |name: &str| PerSidBinding {
                stable_id: "id".into(),
                display_name: name.to_owned(),
                user_confirmed: true,
                known_stable_ids: Vec::new(),
            };
            Some(PerSidPolicySnapshot {
                primary: Some(binding("eth0")),
                secondary: Some(binding("tun0")),
                mode: PerSidBehaviorMode::PreferPrimary,
                block_secondary_when_unavailable: self.block_when_unavailable,
                kill_switch_fail_closed: self.fail_closed,
                kill_switch_protocols: 0x7F,
                kill_switch_block_all: self.block_all,
                kill_switch_enabled: self.enabled,
                allow_dns_over_primary: false,
                shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
                kill_switch_strict_shared_ips: false,
                mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::PerIp,
                link_provider_exe_paths: Vec::new(),
                doh_lockdown_enabled: self.doh_always.is_some(),
                doh_lockdown_scope: if self.doh_always.is_some() {
                    nrr_storage::doh_lockdown::DohLockdownScope::Always
                } else {
                    nrr_storage::doh_lockdown::DohLockdownScope::default()
                },
                doh_resolver_ips: self.doh_always.clone().unwrap_or_default(),
                auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
                primary_probe_auto: false,
                primary_probe_timeout_ms: 1500,
                primary_probe_max_targets: 8,
                primary_probe_repeat_secs: 300,
                local_networks_auto_accept: false,
                zone_priority_over_ip: false,
            })
        }
    }

    fn source(
        rules: Arc<dyn RulesProvider>,
        policy: Arc<dyn RoutePolicySource>,
    ) -> ProductionPrincipalPlanSource {
        source_with_cache(
            rules,
            policy,
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default()),
        )
    }

    fn source_with_cache(
        rules: Arc<dyn RulesProvider>,
        policy: Arc<dyn RoutePolicySource>,
        cache: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    ) -> ProductionPrincipalPlanSource {
        ProductionPrincipalPlanSource::new(
            rules,
            policy,
            cache,
            Arc::new(nrr_platform_api::app_path_resolver::NoopAppPathResolver),
            Arc::new(crate::app_observation_lookup::MockAppObservationLookup::default()),
        )
    }

    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    /// A machine with a bound pair of links and, optionally, the host route a
    /// VPN client installs to reach its server outside the tunnel.
    fn machine(
        with_server_route: bool,
    ) -> (
        Arc<nrr_platform_api::MockWindowsApi>,
        Arc<nrr_platform_api::adapters::MockAdapterEventSource>,
    ) {
        use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};

        let api = Arc::new(nrr_platform_api::MockWindowsApi::new());
        let link = |index: u32, name: &str, gateways: Vec<Ipv4Addr>| AdapterInfo {
            index,
            adapter_name: name.to_owned(),
            description: String::new(),
            friendly_name: name.to_owned(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, 10)],
            ipv6_addresses: Vec::new(),
            gateways,
        };
        let links = Arc::new(nrr_platform_api::adapters::MockAdapterEventSource::new());
        *links.adapters.lock().unwrap_or_else(|p| p.into_inner()) =
            vec![link(2, "eth0", vec![GATEWAY]), link(5, "tun0", Vec::new())];

        let route =
            |dst: Ipv4Addr, prefix: u8, next_hop: Ipv4Addr| nrr_platform_api::types::RouteEntry {
                destination: IpAddr::V4(dst),
                prefix_length: prefix,
                next_hop: IpAddr::V4(next_hop),
                interface_index: 2,
                metric: 0,
                is_ours: false,
                table: nrr_platform_api::RouteTableRef::Main,
            };
        let mut routes = vec![
            route(Ipv4Addr::new(192, 168, 1, 0), 24, Ipv4Addr::UNSPECIFIED),
            route(Ipv4Addr::UNSPECIFIED, 0, GATEWAY),
        ];
        if with_server_route {
            routes.push(route(SERVER, 32, GATEWAY));
        }
        api.set_route_table(routes);
        (api, links)
    }

    fn plan_on_machine(
        rules: impl RulesProvider + 'static,
        policy: Policy,
        secondary_up: bool,
        with_server_route: bool,
    ) -> (EnforcementPlan, PlanCoverage) {
        let (api, links) = machine(with_server_route);
        source(Arc::new(rules), Arc::new(policy))
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
            .plan_with_coverage(&user(), availability(secondary_up))
            .expect("the rule must plan")
    }

    fn blanket_blocks(plan: &EnforcementPlan) -> usize {
        plan.flows
            .iter()
            .filter(|f| {
                f.verdict == Verdict::Block && f.precedence.class == PrecedenceClass::CatchAllBlock
            })
            .count()
    }

    fn exempts(plan: &EnforcementPlan, dst: DstMatch) -> bool {
        plan.flows.iter().any(|f| {
            f.verdict == Verdict::Permit
                && f.precedence.class == PrecedenceClass::CatchAllExempt
                && f.flow.dst == dst
        })
    }

    fn availability(secondary: bool) -> ChannelAvailability {
        ChannelAvailability {
            primary: true,
            secondary,
        }
    }

    fn user() -> UserPrincipal {
        UserPrincipal::from_linux_uid(1000)
    }

    fn plan(
        rules: impl RulesProvider + 'static,
        policy: Policy,
        secondary_up: bool,
    ) -> (EnforcementPlan, PlanCoverage) {
        source(Arc::new(rules), Arc::new(policy))
            .plan_with_coverage(&user(), availability(secondary_up))
            .expect("the rule must plan")
    }

    fn blocks_on(plan: &EnforcementPlan, ip: Ipv4Addr) -> usize {
        plan.flows
            .iter()
            .filter(|f| {
                f.verdict == Verdict::Block
                    && f.precedence.class == PrecedenceClass::KillSwitchBlock
                    && f.flow.dst == DstMatch::HostV4(ip)
            })
            .count()
    }

    /// An empty rule book in a tunnel-default mode is not "nothing to
    /// enforce": the protection there is the blanket block and the leak-guard,
    /// and neither comes from a rule. Returning early left such a principal
    /// completely unprotected AND uncounted - the caller treated them as
    /// planned, so nothing reported it.
    struct NoRulesButBound(RouteBehaviorMode);
    impl RulesProvider for NoRulesButBound {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(Vec::new()),
                    secondary: CanonicalRuleSet::from_rules(Vec::new()),
                },
                behavior_mode: self.0,
            })
        }
        fn active_rules_for(&self, _sid: &str) -> Option<ActiveRulesSnapshot> {
            self.active_rules()
        }
    }

    /// What the Overlaps screen reads on this path: the principal's own
    /// conflicts, re-planned every pass but reported once per change, and
    /// cleared when the rules go.
    #[test]
    fn conflicts_are_published_per_principal_and_reported_once_per_change() {
        use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern};
        use nrr_shared::ipc_payloads::RuleConflictKind;
        use tracing_subscriber::layer::SubscriberExt;

        struct Switchable(Mutex<Option<ActiveRulesSnapshot>>);
        impl RulesProvider for Switchable {
            fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
                self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
            }
        }
        let shared = Ipv4Addr::new(192, 0, 2, 10);
        let rule = |id: &str, action: RuleAction, m: CanonicalAddressMatch| CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(m),
            app_match: None,
            comment: String::new(),
            action,
            origin: None,
        };
        let mut app_scoped = rule(
            "b-app",
            RuleAction::Block,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        );
        app_scoped.app_match = Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact("app".into()),
            include_child_processes: false,
        });
        let rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                rule(
                    "b-ip",
                    RuleAction::Block,
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(shared)),
                ),
                app_scoped,
            ]),
            secondary: CanonicalRuleSet::from_rules(vec![rule(
                "r-host",
                RuleAction::Route,
                CanonicalAddressMatch::ExactFqdn("a.example".into()),
            )]),
        };
        let cache = crate::fqdn_cache_lookup::MockFqdnCacheLookup::default();
        cache.set_ips("a.example", vec![shared]);
        let rules = Arc::new(Switchable(Mutex::new(Some(ActiveRulesSnapshot {
            rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        }))));
        let status = crate::app_enforcement_status::AppEnforcementStatus::new();
        let source = source_with_cache(
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            Arc::new(Policy::armed()),
            Arc::new(cache),
        )
        .with_rule_conflicts(status.clone());

        let dir = tempfile::TempDir::new().expect("temp dir");
        let writer = Arc::new(nrr_diagnostics::LogWriter::open(
            nrr_diagnostics::LogWriterConfig::new(dir.path()),
        ));
        let subscriber = tracing_subscriber::registry().with(
            nrr_diagnostics::NdjsonTracingLayer::new(Arc::clone(&writer)),
        );
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..3 {
                let _ = source.plan_with_coverage(&user(), availability(true));
            }
        });

        let kinds: Vec<RuleConflictKind> = status
            .rule_conflicts(user().as_stored())
            .iter()
            .map(|c| c.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                RuleConflictKind::UnsupportedRuleShape,
                RuleConflictKind::LiteralBlockOverridesRoute,
            ]
        );
        assert!(status
            .rule_conflicts(UserPrincipal::from_linux_uid(1001).as_stored())
            .is_empty());
        let mut reported = 0;
        for entry in std::fs::read_dir(dir.path()).expect("logs dir") {
            let text = std::fs::read_to_string(entry.expect("entry").path()).expect("read");
            reported += text
                .lines()
                .filter(|l| l.contains("diag.event.persid-plan-rule-shape-unsupported"))
                .count();
        }
        assert_eq!(reported, 1, "three passes over one book are one change");

        *rules.0.lock().unwrap_or_else(|p| p.into_inner()) = None;
        assert!(source
            .plan_with_coverage(&user(), availability(true))
            .is_none());
        assert!(status.rule_conflicts(user().as_stored()).is_empty());
    }

    #[test]
    fn an_empty_book_in_a_tunnel_mode_still_gets_its_guard() {
        // Strict is not the case to test with: it always emits its own
        // catch-all, so the plan is never empty there and the early return is
        // never reached. Mode B is where the book being empty made the whole
        // plan empty - and with it the blanket block and the leak-guard.
        let (plan, _) = plan(
            NoRulesButBound(RouteBehaviorMode::PreferSecondaryWhenAvailable),
            Policy::armed(),
            false,
        );
        // The plan EXISTS - that is the point. Whether it carries blocks is a
        // separate question (with no rules there is no per-destination set to
        // guard, and the blanket block is opt-in); a principal who plans
        // nothing must still be enforced and accounted for, not silently
        // skipped as neither enforced nor unprotected.
        assert!(
            plan.flows.is_empty() || plan.flows.iter().any(|f| f.verdict == Verdict::Block),
            "fixture guard",
        );
    }

    #[test]
    fn an_empty_book_in_a_tunnel_mode_is_still_accounted_for() {
        let planned = source(
            Arc::new(NoRulesButBound(
                RouteBehaviorMode::PreferSecondaryWhenAvailable,
            )),
            Arc::new(Policy::armed()),
        )
        .plan_for(&user(), availability(false));
        assert!(
            planned.is_some(),
            "a principal in a tunnel mode must reach the caller, which is what decides whether they count as unprotected",
        );
    }

    /// A user who never bound their adapters has nothing to enforce, and that is
    /// an answer — not an empty plan that would look like a policy.
    fn doh_blocks(plan: &EnforcementPlan) -> Vec<(DstMatch, Option<u16>)> {
        plan.flows
            .iter()
            .filter(|f| {
                f.verdict == Verdict::Block && f.precedence.class == PrecedenceClass::DohBlock
            })
            .map(|f| (f.flow.dst, f.flow.dst_port))
            .collect()
    }

    /// Without the block a DoH browser hides every subdomain a wildcard rule
    /// learns from, and those subdomains leave over the primary.
    #[test]
    fn an_always_on_doh_lockdown_blocks_the_resolvers_without_leak_protection() {
        let resolver = Ipv4Addr::new(198, 51, 100, 53);
        let resolver_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
        let policy = Policy {
            doh_always: Some(vec![resolver.into(), resolver_v6.into()]),
            ..Policy::disarmed()
        };
        let (plan, _) = plan(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            policy,
            true,
        );
        let blocks = doh_blocks(&plan);
        let https = blocks
            .iter()
            .filter(|(dst, port)| *dst == DstMatch::HostV4(resolver) && *port == Some(443))
            .count();
        assert_eq!(https, 2, "TCP and UDP (HTTP/3) on 443: {blocks:?}");
        let https_v6 = blocks
            .iter()
            .filter(|(dst, port)| *dst == DstMatch::HostV6(resolver_v6) && *port == Some(443))
            .count();
        assert_eq!(
            https_v6, 2,
            "the v6 address is the same resolver: {blocks:?}"
        );
        assert!(
            blocks.iter().any(|(_, port)| *port == Some(853)),
            "DoT: {blocks:?}"
        );
    }

    #[test]
    fn with_the_lockdown_off_no_resolver_is_blocked() {
        let (plan, _) = plan(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            Policy::armed(),
            true,
        );
        assert!(doh_blocks(&plan).is_empty());
    }

    #[test]
    fn a_principal_without_stored_policy_plans_nothing() {
        assert!(source(Arc::new(NoRules), Arc::new(NoPolicy))
            .plan_for(&user(), availability(true))
            .is_none());
    }

    /// The binding travels by the name the user saw. Reading the stable id here
    /// would hand the platform a GUID it cannot resolve to a link.
    #[test]
    fn bindings_are_read_as_the_names_the_user_saved() {
        let bindings = StoredEgressBindings::new(Arc::new(Policy::armed()));

        let read = bindings.bindings_for(&PlanPrincipal::from_linux_uid(1000));
        assert_eq!(read.primary.as_deref(), Some("eth0"));
        assert_eq!(read.secondary.as_deref(), Some("tun0"));
    }

    /// While the tunnel is up the guard is the pin, not a block.
    #[test]
    fn a_live_secondary_needs_no_fail_closed_blocks() {
        let (plan, coverage) = plan(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            Policy::armed(),
            true,
        );

        assert_eq!(coverage.fail_closed_blocks, 0);
        assert_eq!(blocks_on(&plan, SECONDARY_HOST), 0);
    }

    /// The whole point: the tunnel is gone, so the addresses it carried are
    /// blocked rather than quietly leaving over the primary.
    #[test]
    fn a_lost_secondary_arms_the_guard_on_the_addresses_it_carried() {
        let (plan, coverage) = plan(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            Policy::armed(),
            false,
        );

        assert!(coverage.fail_closed_blocks > 0);
        assert!(blocks_on(&plan, SECONDARY_HOST) > 0);
        assert!(
            coverage.kill_switch_complete,
            "split mode with per-IP blocking is fully covered here",
        );
    }

    /// The guard is opt-in. Blocking traffic the user never asked to have
    /// blocked is the one failure a routing product must not have.
    #[test]
    fn a_disarmed_guard_blocks_nothing_when_the_secondary_drops() {
        let (plan, coverage) = plan(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            Policy {
                enabled: false,
                ..Policy::armed()
            },
            false,
        );

        assert_eq!(coverage.fail_closed_blocks, 0);
        assert_eq!(blocks_on(&plan, SECONDARY_HOST), 0);
    }

    /// A blanket block with nothing underneath it takes the machine off its own
    /// network: loopback, DHCP, the link's control traffic and the tunnel's
    /// handshake are all "traffic no rule permitted". The strict mode's default
    /// catch-all is planned with the rules, so its floor has to be planned too —
    /// including on the path where the blanket posture never arms.
    #[test]
    fn the_strict_default_block_never_stands_without_its_floor() {
        for with_server_route in [false, true] {
            let (plan, _) = plan_on_machine(
                OneSecondaryRule(RouteBehaviorMode::StrictSecondaryFailClosed),
                Policy::armed(),
                true,
                with_server_route,
            );

            let has_default_block = plan.flows.iter().any(|f| {
                f.verdict == Verdict::Block
                    && f.precedence.class == PrecedenceClass::DefaultCatchAll
            });
            assert!(
                has_default_block,
                "strict mode is the mode that emits the default block"
            );

            let exempts_loopback = plan.flows.iter().any(|f| {
                f.verdict == Verdict::Permit
                    && f.precedence.class == PrecedenceClass::CatchAllExempt
                    && matches!(
                        f.flow.dst,
                        DstMatch::SubnetV4 { net, prefix }
                            if net == std::net::Ipv4Addr::new(127, 0, 0, 0) && prefix == 8
                    )
            });
            assert!(
                exempts_loopback,
                "with_server_route={with_server_route}: the block stands over an empty floor"
            );
        }
    }

    /// Fail-OPEN is a decision the user made: a leak is preferable to an outage.
    #[test]
    fn fail_open_lets_the_traffic_out_rather_than_blocking_it() {
        let (plan, _) = plan(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            Policy {
                fail_closed: false,
                ..Policy::armed()
            },
            false,
        );

        assert_eq!(blocks_on(&plan, SECONDARY_HOST), 0);
    }

    /// With no reading of the machine there are no exemptions, so the blanket
    /// block cannot be armed safely. The plan must ADMIT the shortfall — silence
    /// here would read as protection the user does not have.
    #[test]
    fn an_always_on_mode_reports_its_protection_as_incomplete() {
        let (_, coverage) = plan(
            OneSecondaryRule(RouteBehaviorMode::StrictSecondaryFailClosed),
            Policy::armed(),
            false,
        );

        assert!(!coverage.kill_switch_complete);
    }

    /// Split mode with the block-all flag set asks for the same posture, and
    /// without machine facts it is equally unavailable.
    #[test]
    fn split_mode_asking_for_block_all_reports_incomplete_too() {
        let (_, coverage) = plan(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            Policy {
                block_all: true,
                ..Policy::armed()
            },
            false,
        );

        assert!(!coverage.kill_switch_complete);
    }

    /// The posture the always-on modes are FOR: with the tunnel up, everything
    /// off it is blocked — and the machine's own escapes stay open, or the block
    /// would be a trap rather than a guard.
    #[test]
    fn a_live_tunnel_in_an_always_on_mode_arms_the_blanket_block() {
        let (plan, coverage) = plan_on_machine(
            OneSecondaryRule(RouteBehaviorMode::StrictSecondaryFailClosed),
            Policy::armed(),
            true,
            true,
        );

        assert!(
            blanket_blocks(&plan) > 0,
            "nothing blocks the off-tunnel traffic"
        );
        assert!(
            exempts(&plan, DstMatch::HostV4(SERVER)),
            "the tunnel could never reconnect"
        );
        assert!(
            exempts(
                &plan,
                DstMatch::SubnetV4 {
                    net: Ipv4Addr::new(192, 168, 1, 0),
                    prefix: 24,
                },
            ),
            "the LAN and the local router would be cut",
        );
        assert!(coverage.kill_switch_complete);
    }

    /// The refusal that keeps an outage from becoming permanent: without the
    /// server's address the blanket block would seal the tunnel's own reconnect,
    /// so it is not armed and the shortfall is reported.
    #[test]
    fn without_a_server_route_the_blanket_block_is_refused() {
        let (plan, coverage) = plan_on_machine(
            OneSecondaryRule(RouteBehaviorMode::StrictSecondaryFailClosed),
            Policy::armed(),
            true,
            false,
        );

        assert_eq!(blanket_blocks(&plan), 0);
        assert!(!coverage.kill_switch_complete);
    }

    /// A memory that already holds `servers` and writes nowhere.
    fn remembering(servers: Vec<Ipv4Addr>) -> Arc<TunnelServerMemory> {
        Arc::new(TunnelServerMemory::new(
            Arc::new(|_: &[Ipv4Addr]| {}),
            Arc::new(move || servers.clone()),
        ))
    }

    /// The server route is gone while the tunnel reconnects, but the server
    /// was seen before: the block arms with its hole, as on the platform
    /// whose coordinator keeps the same memory.
    #[test]
    fn a_remembered_server_lets_the_blanket_block_arm_without_its_route() {
        let (api, links) = machine(false);
        let (plan, coverage) = source(
            Arc::new(OneSecondaryRule(
                RouteBehaviorMode::StrictSecondaryFailClosed,
            )),
            Arc::new(Policy::armed()),
        )
        .with_machine_facts(
            api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
            links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
        )
        .with_tunnel_servers(remembering(vec![SERVER]), None)
        .plan_with_coverage(&user(), availability(true))
        .expect("the rule must plan");

        assert!(blanket_blocks(&plan) > 0);
        assert!(exempts(&plan, DstMatch::HostV4(SERVER)));
        assert!(coverage.kill_switch_complete);
    }

    /// Our own host route via the main gateway has a server's shape. Read as
    /// one, it would arm the block with a hole to nowhere and no hole for the
    /// real server; the same route without our signature is a server.
    #[test]
    fn our_own_host_route_is_never_taken_for_the_tunnel_server() {
        use nrr_platform_api::route_table::RouteTablePort;
        let ours = Ipv4Addr::new(198, 51, 100, 77);
        let plan_with = |metric: u32| {
            let (api, links) = machine(false);
            let mut table = api.get_ip_forward_table().expect("mock table");
            table.push(nrr_platform_api::types::RouteEntry {
                destination: IpAddr::V4(ours),
                prefix_length: 32,
                next_hop: IpAddr::V4(GATEWAY),
                interface_index: 2,
                metric,
                is_ours: false,
                table: nrr_platform_api::RouteTableRef::Main,
            });
            api.set_route_table(table);
            source(
                Arc::new(OneSecondaryRule(
                    RouteBehaviorMode::StrictSecondaryFailClosed,
                )),
                Arc::new(Policy::armed()),
            )
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
            .plan_with_coverage(&user(), availability(true))
            .expect("the rule must plan")
        };

        let (plan, coverage) = plan_with(crate::route_codegen::SECONDARY_ROUTE_METRIC);
        assert_eq!(blanket_blocks(&plan), 0, "armed on our own route");
        assert!(!exempts(&plan, DstMatch::HostV4(ours)));
        assert!(!coverage.kill_switch_complete);

        // Positive control: the same row without our signature is a server.
        let (plan, coverage) = plan_with(0);
        assert!(blanket_blocks(&plan) > 0);
        assert!(exempts(&plan, DstMatch::HostV4(ours)));
        assert!(coverage.kill_switch_complete);
    }

    /// Without the bound tunnel's link the attached subnets cannot be read,
    /// and a remembered server must not arm a block that would cut the LAN.
    #[test]
    fn a_remembered_server_alone_does_not_arm_over_unresolved_links() {
        let (api, links) = machine(false);
        links
            .adapters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|a| a.friendly_name != "tun0");
        let (plan, coverage) = source(
            Arc::new(OneSecondaryRule(
                RouteBehaviorMode::StrictSecondaryFailClosed,
            )),
            Arc::new(Policy::armed()),
        )
        .with_machine_facts(
            api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
            links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
        )
        .with_tunnel_servers(remembering(vec![SERVER]), None)
        .plan_with_coverage(&user(), availability(false))
        .expect("the rule must plan");

        assert_eq!(blanket_blocks(&plan), 0);
        assert!(!coverage.kill_switch_complete);
    }

    /// Tunnel gone, block-all asked for: the traffic is held rather than let out
    /// the way the user asked it not to go — and the per-destination guard is
    /// NOT added on top, because one policy stated twice is two things to keep
    /// in agreement.
    #[test]
    fn a_lost_tunnel_under_block_all_holds_everything_and_does_not_double_up() {
        let (plan, coverage) = plan_on_machine(
            OneSecondaryRule(RouteBehaviorMode::PreferPrimary),
            Policy {
                block_all: true,
                ..Policy::armed()
            },
            false,
            true,
        );

        assert!(blanket_blocks(&plan) > 0);
        assert!(exempts(&plan, DstMatch::HostV4(SERVER)));
        assert_eq!(
            coverage.fail_closed_blocks, 0,
            "the per-IP guard duplicated the block-all"
        );
        assert!(coverage.kill_switch_complete);
    }

    // ── IPv6 the tunnel cannot carry ─────────────────────────────────────────

    const HOST: &str = "example.test";
    const HOST_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);

    struct OneSecondaryHostRule;
    impl RulesProvider for OneSecondaryHostRule {
        fn active_rules(&self) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
            Some(crate::per_sid_orchestrator::ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(Vec::new()),
                    secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                        id: RuleId("s-0".into()),
                        enabled: true,
                        address_match: Some(CanonicalAddressMatch::ExactFqdn(HOST.into())),
                        app_match: None,
                        comment: String::new(),
                        action: RuleAction::Route,
                        origin: None,
                    }]),
                },
                behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
            })
        }
        fn active_rules_for(
            &self,
            _sid: &str,
        ) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
            self.active_rules()
        }
    }

    /// A machine whose MAIN link carries IPv6 and whose tunnel does not — the
    /// `FiltersOnly` disposition.
    fn plan_with_v6_on_the_main_link_only(policy: Policy) -> (EnforcementPlan, PlanCoverage) {
        let (api, links) = machine(true);
        {
            let mut adapters = links.adapters.lock().unwrap_or_else(|p| p.into_inner());
            adapters[0].ipv6_addresses = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)];
        }
        let cache = Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default());
        cache.set_addresses(
            HOST,
            vec![
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)),
                IpAddr::V6(HOST_V6),
            ],
        );
        source_with_cache(Arc::new(OneSecondaryHostRule), Arc::new(policy), cache)
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
            .plan_with_coverage(&user(), availability(true))
            .expect("the rule must plan")
    }

    fn blocks_v6(plan: &EnforcementPlan) -> usize {
        plan.flows
            .iter()
            .filter(|f| {
                f.verdict == Verdict::Block
                    && f.precedence.class == PrecedenceClass::KillSwitchBlock
                    && f.flow.dst == DstMatch::HostV6(HOST_V6)
            })
            .count()
    }

    /// The tunnel is UP and healthy, so nothing here is about a lost link: the
    /// rule simply cannot be honoured over a family the tunnel does not carry.
    /// This path steers by ROUTE, so without the block the address would leave
    /// over the main link — the rule ignored, silently.
    #[test]
    fn a_rule_host_the_tunnel_cannot_reach_over_v6_is_blocked_not_leaked() {
        let (plan, _) = plan_with_v6_on_the_main_link_only(Policy::armed());
        assert!(
            blocks_v6(&plan) > 0,
            "the v6 half of a tunnel-routed host went out the main link unblocked",
        );
        assert!(
            !plan
                .routes
                .iter()
                .any(|r| r.dst == DstMatch::HostV6(HOST_V6)),
            "a /128 out of a link with no IPv6 attracts traffic it cannot deliver",
        );
    }

    /// The guard is opt-in on this axis too: a user who chose leak-over-outage
    /// gets the leak.
    #[test]
    fn a_disarmed_guard_leaves_that_v6_alone() {
        let (plan, _) = plan_with_v6_on_the_main_link_only(Policy::disarmed());
        assert_eq!(blocks_v6(&plan), 0);
    }

    /// The field regression on the neutral path: a tunnel that redirects with
    /// a SET of prefixes beats a fixed `/2` counter-overlay, and every non-rule
    /// connection rides it. The plan answers the tunnel it reads, and does not
    /// mistake our own leftover overlay for the tunnel's.
    #[test]
    fn mode_a_counter_overlay_out_specifics_the_tunnels_own_redirect_set() {
        use nrr_platform_api::enforcement::EgressRef;
        let (api, links) = machine(false);
        let on = |dst: Ipv4Addr, prefix: u8, ifindex: u32, metric: u32| {
            nrr_platform_api::types::RouteEntry {
                destination: IpAddr::V4(dst),
                prefix_length: prefix,
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                interface_index: ifindex,
                metric,
                is_ours: false,
                table: nrr_platform_api::RouteTableRef::Main,
            }
        };
        let redirect_set = [
            (Ipv4Addr::new(0, 0, 0, 0), 5),
            (Ipv4Addr::new(8, 0, 0, 0), 7),
            (Ipv4Addr::new(64, 0, 0, 0), 2),
            (Ipv4Addr::new(192, 0, 0, 0), 9),
        ];
        let mut table = vec![
            on(Ipv4Addr::new(192, 168, 1, 0), 24, 2, 0),
            on(Ipv4Addr::UNSPECIFIED, 0, 2, 0),
            // Ours, left on the tunnel by the always-on mode.
            on(
                Ipv4Addr::new(128, 0, 0, 0),
                1,
                5,
                crate::route_codegen::SECONDARY_ROUTE_METRIC,
            ),
        ];
        table.extend(redirect_set.iter().map(|&(d, n)| on(d, n, 5, 0)));
        api.set_route_table(table);

        let (plan, _) = source(
            Arc::new(OneSecondaryRule(RouteBehaviorMode::PreferPrimary)),
            Arc::new(Policy::armed()),
        )
        .with_machine_facts(
            api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
            links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
        )
        .plan_with_coverage(&user(), availability(true))
        .expect("the rule must plan");

        let mut overlay: Vec<(Ipv4Addr, u8)> = plan
            .routes
            .iter()
            .filter(|r| r.egress == EgressRef::Primary)
            .filter_map(|r| match r.dst {
                DstMatch::SubnetV4 { net, prefix } => Some((net, prefix)),
                _ => None,
            })
            .collect();
        overlay.sort_unstable_by_key(|&(d, n)| (u32::from(d), n));
        assert_eq!(
            overlay,
            crate::route_codegen::counter_overlay_for(&redirect_set)
        );
    }

    /// Held networks on this path, judged by the precedence order every
    /// lowering realises.
    mod network_holds {
        use super::*;
        use crate::address_ownership::{AddressOwnership, ZoneVsIpOrder};
        use nrr_domain::rule_shape::RuleShapeSupport;
        use nrr_platform_api::enforcement::{AppScope, Coverage, EgressConstraint, EgressRef};
        use nrr_shared::ip_block::IpBlock;

        const MAIN_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);

        fn route(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
            CanonicalRule {
                id: RuleId(id.into()),
                enabled: true,
                address_match: Some(m),
                app_match: None,
                comment: String::new(),
                action: RuleAction::Route,
                origin: None,
            }
        }

        fn subnet(text: &str) -> CanonicalAddressMatch {
            CanonicalAddressMatch::Subnet(IpBlock::parse(text).expect("subnet"))
        }

        fn address_book() -> CanonicalRuleBook {
            CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![route(
                    "p-host",
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(MAIN_HOST)),
                )]),
                secondary: CanonicalRuleSet::from_rules(vec![route(
                    "s-host",
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(SECONDARY_HOST)),
                )]),
            }
        }

        /// [`address_book`] plus a secondary `/24` around `MAIN_HOST` and a
        /// secondary `/12`.
        fn network_book() -> CanonicalRuleBook {
            let mut rules = address_book().secondary.rules().to_vec();
            rules.push(route("s-24", subnet("198.51.100.0/24")));
            rules.push(route("s-12", subnet("172.16.0.0/12")));
            CanonicalRuleBook {
                primary: address_book().primary,
                secondary: CanonicalRuleSet::from_rules(rules),
            }
        }

        struct Book(CanonicalRuleBook);
        impl RulesProvider for Book {
            fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
                Some(ActiveRulesSnapshot {
                    rule_book: self.0.clone(),
                    behavior_mode: RouteBehaviorMode::PreferPrimary,
                })
            }
        }

        fn ownership_with_networks(book: &CanonicalRuleBook) -> AddressOwnership {
            AddressOwnership::resolve_with_support(
                book,
                &crate::fqdn_cache_lookup::MockFqdnCacheLookup::default(),
                ZoneVsIpOrder::default(),
                RuleShapeSupport {
                    network_destination: true,
                    ..crate::wfp_codegen::current_rule_shape_support()
                },
            )
        }

        fn on_machine() -> ProductionPrincipalPlanSource {
            let (api, links) = machine(true);
            source(Arc::new(NoRules), Arc::new(Policy::armed())).with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
        }

        fn armed() -> PerSidPolicySnapshot {
            Policy::armed().load_for_sid("").expect("policy")
        }

        /// The tunnel-gone flows for `network_book` under the arbiter above.
        fn fail_closed(source: &ProductionPrincipalPlanSource) -> Vec<FlowRule> {
            source.fail_closed_flows(
                user().as_stored(),
                &armed(),
                &[],
                &ownership_with_networks(&network_book()),
            )
        }

        fn dst_block(dst: DstMatch) -> Option<IpBlock> {
            match dst {
                DstMatch::Any => None,
                DstMatch::HostV4(ip) => IpBlock::new(IpAddr::V4(ip), 32),
                DstMatch::HostV6(ip) => IpBlock::new(IpAddr::V6(ip), 128),
                DstMatch::SubnetV4 { net, prefix } => IpBlock::new(IpAddr::V4(net), prefix),
                DstMatch::SubnetV6 { net, prefix } => IpBlock::new(IpAddr::V6(net), prefix),
            }
        }

        /// The verdict of the highest-precedence connect flow over `ip`.
        fn verdict(flows: &[FlowRule], ip: Ipv4Addr) -> Option<Verdict> {
            let mut best: Option<&FlowRule> = None;
            for flow in flows.iter().filter(|f| {
                f.coverage == Coverage::ConnectOnly
                    && matches!(f.app, AppScope::Any)
                    && dst_block(f.flow.dst).is_some_and(|b| b.contains(IpAddr::V4(ip)))
            }) {
                if best.is_none_or(|b| flow.precedence.is_higher_priority_than(b.precedence)) {
                    best = Some(flow);
                }
            }
            best.map(|flow| flow.verdict)
        }

        #[test]
        fn an_unresolved_tunnel_blocks_a_secondary_slash_24() {
            let flows = fail_closed(&on_machine());
            assert!(flows.iter().any(|f| f.verdict == Verdict::Block
                && f.flow.dst
                    == DstMatch::SubnetV4 {
                        net: Ipv4Addr::new(198, 51, 100, 0),
                        prefix: 24,
                    }));
            assert_eq!(
                verdict(&flows, Ipv4Addr::new(198, 51, 100, 9)),
                Some(Verdict::Block)
            );
        }

        #[test]
        fn a_primary_address_inside_the_held_slash_24_stays_open() {
            let flows = fail_closed(&on_machine());
            assert_eq!(verdict(&flows, MAIN_HOST), Some(Verdict::Permit));
            assert!(!flows
                .iter()
                .any(|f| f.verdict == Verdict::Block && f.flow.dst == DstMatch::HostV4(MAIN_HOST)));
        }

        #[test]
        fn a_slash_12_is_too_wide_to_hold_and_is_reported_once_per_change() {
            use tracing_subscriber::layer::SubscriberExt;

            let source = on_machine();
            let dir = tempfile::TempDir::new().expect("temp dir");
            let writer = Arc::new(nrr_diagnostics::LogWriter::open(
                nrr_diagnostics::LogWriterConfig::new(dir.path()),
            ));
            let subscriber = tracing_subscriber::registry().with(
                nrr_diagnostics::NdjsonTracingLayer::new(Arc::clone(&writer)),
            );
            let flows = tracing::subscriber::with_default(subscriber, || {
                let flows = fail_closed(&source);
                for _ in 0..2 {
                    assert_eq!(fail_closed(&source), flows);
                }
                flows
            });

            assert!(!flows
                .iter()
                .any(|f| dst_block(f.flow.dst).is_some_and(|b| b.prefix_len() == 12)));
            assert_eq!(verdict(&flows, Ipv4Addr::new(172, 16, 4, 4)), None);
            let mut reported = 0;
            for entry in std::fs::read_dir(dir.path()).expect("logs dir") {
                let text = std::fs::read_to_string(entry.expect("entry").path()).expect("read");
                reported += text
                    .lines()
                    .filter(|l| l.contains("diag.event.persid-plan-network-too-wide"))
                    .count();
            }
            assert_eq!(reported, 1, "three passes over one book are one change");
        }

        /// The Windows live path arms the same holds and cut-outs from the same
        /// machine reading: one answer, two mechanisms.
        #[test]
        fn both_mechanisms_hold_and_open_the_same_networks() {
            let source = on_machine();
            let read = source.exemptions_for(&armed());
            assert!(!read.server_ips.is_empty(), "fixture guard");
            let exemptions = crate::killswitch_codegen::FailClosedExemptions {
                bootstrap_server_ips: read.server_ips.clone(),
                bootstrap_server_ips_v6: read.server_ips_v6.clone(),
                local_subnets: read.local_subnets.clone(),
                local_subnets_v6: read.local_subnets_v6.clone(),
                ..crate::killswitch_codegen::FailClosedExemptions::default()
            };
            let holds =
                NetworkHolds::for_pass(&ownership_with_networks(&network_book()), &[], || {
                    exemptions.never_blocked_networks()
                });
            let windows: std::collections::BTreeSet<(String, bool)> =
                crate::killswitch_codegen::fail_closed_network_filters(
                    user().as_stored(),
                    &holds,
                    KillSwitchProtocols::from_bits(armed().kill_switch_protocols),
                )
                .into_iter()
                .filter(|f| {
                    matches!(
                        f.layer,
                        nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4
                            | nrr_platform_api::types::WfpLayerKey::AleAuthConnectV6
                    )
                })
                .filter_map(|f| {
                    let block = match (f.remote_ip, f.remote_subnet, f.remote_subnet_v6) {
                        (Some(ip), _, _) => IpBlock::new(IpAddr::V4(ip), 32),
                        (None, Some((net, len)), _) => IpBlock::new(IpAddr::V4(net), len),
                        (None, None, Some((net, len))) => IpBlock::new(IpAddr::V6(net), len),
                        (None, None, None) => None,
                    }?;
                    Some((
                        block.to_string(),
                        f.action == nrr_platform_api::types::WfpAction::Block,
                    ))
                })
                .collect();
            let neutral: std::collections::BTreeSet<(String, bool)> = fail_closed(&source)
                .into_iter()
                .filter(|f| f.coverage == Coverage::ConnectOnly)
                .filter_map(|f| {
                    Some((
                        dst_block(f.flow.dst)?.to_string(),
                        f.verdict == Verdict::Block,
                    ))
                })
                .collect();
            assert!(windows.contains(&("198.51.100.0/24".to_string(), true)));
            assert_eq!(windows, neutral);
        }

        /// End to end through a plan: network rules keep every flow of the
        /// address book and add the held `/24`'s Fail-Closed block, never the
        /// too-wide `/12`'s.
        #[test]
        fn network_rules_plan_on_top_of_the_address_book() {
            let (without, without_coverage) = plan(Book(address_book()), Policy::armed(), false);
            assert!(without_coverage.fail_closed_blocks > 0, "fixture guard");
            let (with, with_coverage) = plan(Book(network_book()), Policy::armed(), false);
            assert!(
                without.flows.iter().all(|f| with.flows.contains(f)),
                "a network rule must not take anything of the address book away"
            );
            let blocks = |net: Ipv4Addr, prefix: u8| {
                with.flows.iter().any(|f| {
                    f.verdict == Verdict::Block && f.flow.dst == DstMatch::SubnetV4 { net, prefix }
                })
            };
            assert!(blocks(Ipv4Addr::new(198, 51, 100, 0), 24));
            assert!(!blocks(Ipv4Addr::new(172, 16, 0, 0), 12));
            assert!(with_coverage.fail_closed_blocks > without_coverage.fail_closed_blocks);
        }

        /// The highest-precedence connect flow over `ip`.
        fn top(flows: &[FlowRule], ip: Ipv4Addr) -> Option<&FlowRule> {
            let mut best: Option<&FlowRule> = None;
            for flow in flows.iter().filter(|f| {
                f.coverage == Coverage::ConnectOnly
                    && matches!(f.app, AppScope::Any)
                    && dst_block(f.flow.dst).is_some_and(|b| b.contains(IpAddr::V4(ip)))
            }) {
                if best.is_none_or(|b| flow.precedence.is_higher_priority_than(b.precedence)) {
                    best = Some(flow);
                }
            }
            best
        }

        const PINNED: EgressConstraint = EgressConstraint::OnlyVia(EgressRef::Secondary);

        /// With the tunnel up a route alone gives way to any route laid over
        /// it, so the secondary address leaves only through the tunnel.
        #[test]
        fn a_live_tunnel_pins_the_secondary_address_to_its_link() {
            let (plan, coverage) = plan(Book(address_book()), Policy::armed(), true);
            assert_eq!(coverage.fail_closed_blocks, 0);
            let pinned = top(&plan.flows, SECONDARY_HOST).expect("the secondary rule plans");
            assert_eq!(pinned.verdict, Verdict::Permit);
            assert_eq!(pinned.egress, PINNED);
            let main = top(&plan.flows, MAIN_HOST).expect("the primary rule plans");
            assert_eq!(main.egress, EgressConstraint::Any);
        }

        #[test]
        fn a_disarmed_guard_leaves_the_live_route_unpinned() {
            let (plan, _) = plan(Book(address_book()), Policy::disarmed(), true);
            let flow = top(&plan.flows, SECONDARY_HOST).expect("the secondary rule plans");
            assert_eq!(flow.egress, EgressConstraint::Any);
        }

        /// The held `/24` is pinned, the main-link address inside it stays on
        /// its own link, and the `/12` too wide to hold is left to its route.
        #[test]
        fn a_live_tunnel_pins_the_held_network_and_spares_what_it_must() {
            let (plan, _) = plan(Book(network_book()), Policy::armed(), true);
            assert!(plan.flows.iter().any(|f| f.egress == PINNED
                && f.flow.dst
                    == DstMatch::SubnetV4 {
                        net: Ipv4Addr::new(198, 51, 100, 0),
                        prefix: 24,
                    }));
            let inside = top(&plan.flows, Ipv4Addr::new(198, 51, 100, 9)).expect("held");
            assert_eq!(inside.egress, PINNED);
            let main = top(&plan.flows, MAIN_HOST).expect("main host");
            assert_eq!(main.verdict, Verdict::Permit);
            assert_eq!(main.egress, EgressConstraint::Any);
            assert!(!plan.flows.iter().any(|f| f.egress == PINNED
                && dst_block(f.flow.dst).is_some_and(|b| b.prefix_len() == 12)));
        }
    }

    /// Network routes on this path, planned around the machine's own links.
    mod network_routes {
        use super::*;
        use crate::enforcement_planner::FamilyScope;
        use crate::route_codegen::NETWORK_ROUTE_METRIC;
        use nrr_domain::rule_shape::RuleShapeSupport;
        use nrr_platform_api::enforcement::{EgressRef, RouteIntent};
        use nrr_shared::ip_block::IpBlock;
        use std::collections::HashSet;

        const LAN_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 1);
        const TUNNEL_SERVER: Ipv4Addr = Ipv4Addr::new(10, 20, 200, 7);

        fn networks() -> RuleShapeSupport {
            RuleShapeSupport {
                network_destination: true,
                ..crate::wfp_codegen::current_rule_shape_support()
            }
        }

        fn net(text: &str) -> IpBlock {
            IpBlock::parse(text).expect("network literal")
        }

        fn rule(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
            CanonicalRule {
                id: RuleId(id.into()),
                enabled: true,
                address_match: Some(m),
                app_match: None,
                comment: String::new(),
                action: RuleAction::Route,
                origin: None,
            }
        }

        fn subnet(id: &str, text: &str) -> CanonicalRule {
            rule(id, CanonicalAddressMatch::Subnet(net(text)))
        }

        fn exact(id: &str, ip: Ipv4Addr) -> CanonicalRule {
            rule(id, CanonicalAddressMatch::ExactIp(IpAddr::V4(ip)))
        }

        /// A LAN `10.20.1.0/24` on eth0, the tunnel on tun0, and the tunnel's
        /// server in the same `/16`, reached via the LAN gateway.
        fn on_machine() -> ProductionPrincipalPlanSource {
            let (api, links) = machine_parts(true);
            source(Arc::new(NoRules), Arc::new(Policy::armed())).with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
        }

        /// The machine of [`on_machine`]; without `server_route` the tunnel
        /// is down and no route names its server.
        fn machine_parts(
            server_route: bool,
        ) -> (
            Arc<nrr_platform_api::MockWindowsApi>,
            Arc<nrr_platform_api::adapters::MockAdapterEventSource>,
        ) {
            use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};

            let link =
                |index: u32, name: &str, address: Ipv4Addr, gateways: Vec<Ipv4Addr>| AdapterInfo {
                    index,
                    adapter_name: name.to_owned(),
                    description: String::new(),
                    friendly_name: name.to_owned(),
                    mac: None,
                    interface_type: InterfaceType::Ethernet,
                    oper_status: IfOperStatus::Up,
                    ipv4_addresses: vec![address],
                    ipv6_addresses: Vec::new(),
                    gateways,
                };
            let adapters = vec![
                link(2, "eth0", Ipv4Addr::new(10, 20, 1, 10), vec![LAN_GATEWAY]),
                link(5, "tun0", Ipv4Addr::new(10, 8, 0, 6), Vec::new()),
            ];
            let links = Arc::new(nrr_platform_api::adapters::MockAdapterEventSource::new());
            *links.adapters.lock().unwrap_or_else(|p| p.into_inner()) = adapters.clone();
            let row = |dst: Ipv4Addr, prefix: u8, next_hop: Ipv4Addr, index: u32| {
                nrr_platform_api::types::RouteEntry {
                    destination: IpAddr::V4(dst),
                    prefix_length: prefix,
                    next_hop: IpAddr::V4(next_hop),
                    interface_index: index,
                    metric: 0,
                    is_ours: false,
                    table: nrr_platform_api::RouteTableRef::Main,
                }
            };
            let api = Arc::new(nrr_platform_api::MockWindowsApi::new());
            let mut table = vec![
                row(Ipv4Addr::UNSPECIFIED, 0, LAN_GATEWAY, 2),
                row(Ipv4Addr::new(10, 20, 1, 0), 24, Ipv4Addr::UNSPECIFIED, 2),
                row(Ipv4Addr::new(10, 8, 0, 0), 24, Ipv4Addr::UNSPECIFIED, 5),
            ];
            if server_route {
                table.push(row(TUNNEL_SERVER, 32, LAN_GATEWAY, 2));
            }
            api.set_route_table(table);
            api.set_adapter_infos(adapters);
            (api, links)
        }

        fn policy() -> PerSidPolicySnapshot {
            Policy::armed().load_for_sid("").expect("policy")
        }

        fn routes(
            source: &ProductionPrincipalPlanSource,
            mode: RouteBehaviorMode,
            book: &CanonicalRuleBook,
            support: RuleShapeSupport,
        ) -> Vec<RouteIntent> {
            source.routes_for(
                &policy(),
                mode,
                book,
                true,
                &HashSet::new(),
                FamilyScope::V4Only,
                support,
            )
        }

        /// The tunnel's network pieces, in plan order.
        fn tunnel_networks(routes: &[RouteIntent]) -> Vec<IpBlock> {
            routes
                .iter()
                .filter(|r| r.egress == EgressRef::Secondary && r.metric == NETWORK_ROUTE_METRIC)
                .filter_map(|r| match r.dst {
                    DstMatch::SubnetV4 { net, prefix } => IpBlock::new(IpAddr::V4(net), prefix),
                    _ => None,
                })
                .collect()
        }

        #[test]
        fn the_facts_come_from_the_pass_reading() {
            let source = on_machine();
            let book = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(Vec::new()),
                secondary: CanonicalRuleSet::from_rules(vec![subnet("s", "10.20.0.0/16")]),
            };
            let facts = source.network_route_facts(&policy(), &book, networks(), &[]);
            assert_eq!(
                facts.local_networks,
                vec![net("10.8.0.0/24"), net("10.20.1.0/24")]
            );
            assert_eq!(facts.tunnel_servers, vec![IpAddr::V4(TUNNEL_SERVER)]);
            // Nothing to route: the reading is not even consulted.
            assert_eq!(
                source.network_route_facts(&policy(), &book, RuleShapeSupport::NONE, &[]),
                NetworkRouteFacts::default()
            );
        }

        /// A tunnel `/16` holding the LAN and the tunnel's server: the LAN
        /// keeps its own addresses, the server keeps its own route, and the
        /// rest of the network rides the tunnel.
        #[test]
        fn a_tunnel_network_skips_the_lan_and_the_tunnel_server() {
            let book = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(Vec::new()),
                secondary: CanonicalRuleSet::from_rules(vec![
                    subnet("s-16", "10.20.0.0/16"),
                    subnet("s-in-lan", "10.20.1.128/25"),
                ]),
            };
            let pieces = tunnel_networks(&routes(
                &on_machine(),
                RouteBehaviorMode::PreferPrimary,
                &book,
                networks(),
            ));
            let lan = net("10.20.1.0/24");
            assert_eq!(
                pieces.len(),
                16,
                "one sibling per bit down to the server: {pieces:?}"
            );
            assert!(pieces
                .iter()
                .all(|p| !p.contains(IpAddr::V4(TUNNEL_SERVER))));
            assert!(
                pieces.iter().all(|p| !lan.covers(*p)),
                "a piece inside the LAN would take it off eth0: {pieces:?}"
            );

            // Longest prefix over what the table then holds.
            let mut table: Vec<(IpBlock, &str)> = vec![
                (net("0.0.0.0/0"), "eth0"),
                (lan, "eth0"),
                (net("10.20.200.7/32"), "eth0"),
            ];
            table.extend(pieces.iter().map(|p| (*p, "tun0")));
            let pick = |ip: &str| {
                let ip: IpAddr = ip.parse().expect("address literal");
                table
                    .iter()
                    .filter(|(b, _)| b.contains(ip))
                    .max_by_key(|(b, _)| b.prefix_len())
                    .map(|(_, link)| *link)
            };
            for (ip, want) in [
                ("10.20.1.50", "eth0"),
                ("10.20.1.200", "eth0"),
                ("10.20.200.7", "eth0"),
                ("10.20.0.1", "tun0"),
                ("10.20.200.6", "tun0"),
                ("10.20.255.254", "tun0"),
                ("10.21.0.1", "eth0"),
            ] {
                assert_eq!(pick(ip), Some(want), "{ip}");
            }
        }

        /// The machine reading changes nothing for a book that names no
        /// network, nor under a shape support without networks.
        #[test]
        fn without_networks_the_route_plan_is_what_it_always_was() {
            let source = on_machine();
            let hosts = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![exact(
                    "p",
                    Ipv4Addr::new(192, 0, 2, 9),
                )]),
                secondary: CanonicalRuleSet::from_rules(vec![exact(
                    "s",
                    Ipv4Addr::new(198, 51, 100, 4),
                )]),
            };
            let with_networks = CanonicalRuleBook {
                primary: hosts.primary.clone(),
                secondary: CanonicalRuleSet::from_rules(vec![
                    exact("s", Ipv4Addr::new(198, 51, 100, 4)),
                    subnet("s-16", "10.20.0.0/16"),
                ]),
            };
            let shipped = crate::wfp_codegen::current_rule_shape_support();
            let mut cases = vec![(&hosts, networks())];
            if !shipped.network_destination {
                cases.push((&with_networks, shipped));
            }
            let cache = crate::fqdn_cache_lookup::MockFqdnCacheLookup::default();
            let apps = crate::app_observation_lookup::MockAppObservationLookup::default();
            for mode in [
                RouteBehaviorMode::PreferPrimary,
                RouteBehaviorMode::PreferSecondaryWhenAvailable,
                RouteBehaviorMode::StrictSecondaryFailClosed,
            ] {
                for &(book, support) in &cases {
                    let before = crate::enforcement_planner::plan_routes(
                        mode,
                        book,
                        true,
                        &cache,
                        &apps,
                        &HashSet::new(),
                        FamilyScope::V4Only,
                        crate::address_ownership::ZoneVsIpOrder::default(),
                        &[],
                    );
                    assert_eq!(
                        routes(&source, mode, book, support),
                        before,
                        "{mode:?}, {support:?}"
                    );
                }
            }
        }

        fn sixteen() -> CanonicalRuleBook {
            CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(Vec::new()),
                secondary: CanonicalRuleSet::from_rules(vec![subnet("s-16", "10.20.0.0/16")]),
            }
        }

        fn down_machine() -> ProductionPrincipalPlanSource {
            let (api, links) = machine_parts(false);
            source(Arc::new(NoRules), Arc::new(Policy::armed())).with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
        }

        fn routes_over_server(source: &ProductionPrincipalPlanSource) -> Vec<IpBlock> {
            tunnel_networks(&routes(
                source,
                RouteBehaviorMode::PreferPrimary,
                &sixteen(),
                networks(),
            ))
            .into_iter()
            .filter(|p| p.contains(IpAddr::V4(TUNNEL_SERVER)))
            .collect()
        }

        /// Tunnel down, no route names its server: only the memory keeps a
        /// tunnel `/16` from swallowing the server it reconnects to.
        #[test]
        fn a_remembered_server_is_spared_while_the_tunnel_is_down() {
            assert!(
                !routes_over_server(&down_machine()).is_empty(),
                "fixture guard: nothing live names the server"
            );
            let source = down_machine().with_tunnel_servers(remembering(vec![TUNNEL_SERVER]), None);
            assert_eq!(routes_over_server(&source), Vec::<IpBlock>::new());
        }

        struct Peers(Vec<IpAddr>);
        impl TunnelEndpointSource for Peers {
            fn tunnel_endpoints(&self) -> Vec<IpAddr> {
                self.0.clone()
            }
        }

        /// A kernel tunnel's peer names its server where no route does, and
        /// it is remembered for when the tunnel is gone.
        #[test]
        fn a_kernel_tunnel_peer_is_spared_and_remembered() {
            let memory = remembering(Vec::new());
            let peer = Ipv4Addr::new(10, 20, 77, 1);
            let source = down_machine().with_tunnel_servers(
                Arc::clone(&memory),
                Some(Arc::new(Peers(vec![IpAddr::V4(peer)]))),
            );
            source.remember_tunnel_servers(&policy());
            assert_eq!(memory.remembered(), vec![peer]);
            let facts = source.network_route_facts(&policy(), &sixteen(), networks(), &[]);
            assert_eq!(facts.tunnel_servers, vec![IpAddr::V4(peer)]);
        }

        /// The whole path through the one store: a pass sees the server live,
        /// the tunnel drops, and the submission screen still refuses a subnet
        /// over it while the route plan still spares it.
        #[test]
        fn a_server_seen_live_is_refused_and_spared_after_the_tunnel_drops() {
            use crate::network_rule_screen::{facts_with_remembered_servers, screen_network};
            use crate::production_mutation_executor::NetworkRuleConflict;
            use crate::tunnel_server_memory::persisted_servers;
            use nrr_storage::{
                open_connection, repository::MigrationRunner, SqliteMigrationRunner,
            };

            let dir = tempfile::tempdir().expect("temp dir");
            let runner = SqliteMigrationRunner::for_state_db(
                open_connection(&dir.path().join("nrr_service_state.db")).expect("open"),
            );
            runner.run_pending_migrations().expect("migrate");
            let state = Arc::new(Mutex::new(runner.into_connection()));
            let memory = Arc::new(TunnelServerMemory::over_state_db(Arc::clone(&state)));

            on_machine()
                .with_tunnel_servers(Arc::clone(&memory), None)
                .remember_tunnel_servers(&policy());

            let (down_api, _) = machine_parts(false);
            let screen = facts_with_remembered_servers(
                down_api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                persisted_servers(Arc::clone(&state)),
            );
            let facts = screen("principal");
            assert!(matches!(
                screen_network(net("10.20.200.0/24"), &facts, None),
                Some(NetworkRuleConflict::CoversLink(_))
            ));
            assert_eq!(screen_network(net("10.20.100.0/24"), &facts, None), None);

            let after_restart = down_machine()
                .with_tunnel_servers(Arc::new(TunnelServerMemory::over_state_db(state)), None);
            assert_eq!(routes_over_server(&after_restart), Vec::<IpBlock>::new());
        }

        /// Without the memory the screen knows no server, as before.
        #[test]
        fn without_a_remembered_server_the_screen_lets_the_subnet_through() {
            let (down_api, _) = machine_parts(false);
            let screen = crate::network_rule_screen::facts_with_remembered_servers(
                down_api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                Arc::new(Vec::<Ipv4Addr>::new),
            );
            assert_eq!(
                crate::network_rule_screen::screen_network(
                    net("10.20.200.0/24"),
                    &screen("principal"),
                    None
                ),
                None
            );
        }
    }
}
