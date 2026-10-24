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
//! Which guard arms is [`nrr_domain::protection_posture`]'s answer, the table
//! the Windows engine reads too. The blanket postures are planned only when
//! the machine can say what they must not cut: the tunnel's own server
//! addresses and the attached subnets, read off the route table
//! ([`crate::catch_all_exemptions`]). Without them the plan falls back to the
//! per-destination guard and says so — a blanket block that seals the tunnel's
//! reconnect turns an outage into a permanent one.
//!
//! [`PlanCoverage`] reports all of this on every pass rather than in a comment:
//! a user told their rules are applied, while the protection that makes them
//! safe is absent, is worse off than one told nothing was applied.

use std::sync::{Arc, Mutex};

use nrr_domain::user_principal::UserPrincipal;
use nrr_domain::{protection_posture, ProtectionPosture, RouteBehaviorMode};
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
use crate::per_sid_orchestrator::{ActiveRulesSnapshot, PerSidPolicySnapshot};

use crate::app_observation_lookup::AppObservationLookup;
use crate::enforcement_planner::{plan_route_rules, plan_routes_with, PlannerInput};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::per_sid_orchestrator::{behavior_mode_for_codegen, RoutePolicySource, RulesProvider};
use crate::principal_enforcement::{PlannedPolicy, PrincipalPlanSource};
use crate::route_codegen::network_routes::NetworkRouteFacts;
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
    /// The secondary is gone and the user's leak-guard holds its traffic back,
    /// whether or not any destination needed a block: with every known address
    /// spared, a cold cache or the blanket block, the count above is zero
    /// while a rule host's name must still not be asked of the main link.
    pub guard_holding: bool,
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
    /// The main link's DNS servers, for the service-account guard. `None`
    /// plans no service-account rule.
    service_accounts: Option<crate::per_sid_orchestrator::PrimaryDnsServersFn>,
    service_account_dns_log: crate::enforcement_planner::ServiceAccountDnsLog,
    /// Tables only we write; every route in them is ours.
    own_tables: Option<OwnTablesFn>,
    /// Where the smart leak-guard reports the shared addresses it left
    /// unpinned, for the GUI's strictness warning. `None` reports nowhere.
    shared_ip_exemptions: Option<crate::app_enforcement_status::SharedIpExemptionStatus>,
    /// The push channel for what a pass finds out about the machine. `None`
    /// tells nobody.
    events: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
    too_wide_notices: crate::catch_all_exemptions::TooWideLocalNetworkNotices,
    /// The user's answers about local networks, laid over the exemptions.
    /// `None` exempts what the machine reports and nothing the user decided.
    local_networks: Option<Arc<crate::local_network_source::PolicyLocalNetworkSource>>,
    /// The route-table owner this pass was told of. `None` until a pass says;
    /// then every principal is planned as if it were the owner.
    pass_owner: Mutex<Option<Option<UserPrincipal>>>,
    /// Each planned user's links this pass, published as one view at its end.
    pass_links: Mutex<std::collections::BTreeMap<String, PassLinks>>,
    /// Users a pass has published a machine reading for. Until then a first
    /// contact cannot tell a LAN or another tunnel's address from a remote one.
    machine_read: Mutex<std::collections::HashSet<String>>,
}

/// One user's foreign tunnels and additional-route links, from the pass's
/// reading.
struct PassLinks {
    foreign: Vec<u32>,
    own: Vec<u32>,
}

/// Whether a route table is one only this product writes.
pub type OwnTablesFn = Arc<dyn Fn(&nrr_platform_api::RouteTableRef) -> bool + Send + Sync>;

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
            service_accounts: None,
            service_account_dns_log: crate::enforcement_planner::ServiceAccountDnsLog::default(),
            own_tables: None,
            shared_ip_exemptions: None,
            events: None,
            too_wide_notices: Default::default(),
            local_networks: None,
            pass_owner: Mutex::new(None),
            pass_links: Mutex::new(Default::default()),
            machine_read: Mutex::new(Default::default()),
        }
    }

    /// Whether `stored` speaks for the service accounts this pass.
    fn is_route_table_owner(&self, stored: &str) -> bool {
        match &*self.pass_owner.lock().unwrap_or_else(|p| p.into_inner()) {
            None => true,
            Some(owner) => owner.as_ref().is_some_and(|o| o.as_stored() == stored),
        }
    }

    /// Attach the push channel, so a user hears what the pass found about
    /// their links — a reported local segment too wide to be one, today.
    #[must_use]
    pub fn with_event_bus(mut self, events: Arc<crate::ipc_handlers::event_bus::EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// Honour the networks the user kept or refused: the blanket block's
    /// exemptions follow the same answers the "Local networks" list shows.
    #[must_use]
    pub fn with_local_networks(
        mut self,
        source: Arc<crate::local_network_source::PolicyLocalNetworkSource>,
    ) -> Self {
        self.local_networks = Some(source);
        self
    }

    /// Publish the addresses the smart leak-guard spares into `status` — the
    /// one the `SnapshotInitial` handler reads for its strictness warning.
    #[must_use]
    pub fn with_shared_ip_exemption_status(
        mut self,
        status: crate::app_enforcement_status::SharedIpExemptionStatus,
    ) -> Self {
        self.shared_ip_exemptions = Some(status);
        self
    }

    /// Tables only we write — per-user ones. Without this, our own routes
    /// there read as the tunnel's: a host route via the main gateway as a
    /// tunnel server, an overlay half as the tunnel's catch-all.
    #[must_use]
    pub fn with_own_route_tables(mut self, own: OwnTablesFn) -> Self {
        self.own_tables = Some(own);
        self
    }

    /// Plan the guard's service-account twins into every plan; the lowering
    /// keeps only the route-table owner's. `primary_dns` names the main link's
    /// resolvers, which stay open for system traffic.
    #[must_use]
    pub fn with_service_accounts(
        mut self,
        primary_dns: crate::per_sid_orchestrator::PrimaryDnsServersFn,
    ) -> Self {
        self.service_accounts = Some(primary_dns);
        self
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
        // This path keeps no record of what it installed; our signature and
        // our tables are it.
        let own_tables = self.own_tables.as_deref();
        let reading = Arc::new(MachineReading::new(Ok(routes), Ok(adapters), |r| {
            crate::route_codegen::is_owned_route(r) || own_tables.is_some_and(|own| own(&r.table))
        }));
        *cached = Some(Arc::clone(&reading));
        Some(reading)
    }

    /// The plan plus what it covers.
    pub fn plan_with_coverage(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> Option<(EnforcementPlan, PlanCoverage)> {
        self.plan_over(principal, availability, || {
            self.rules.active_rules_for(principal.as_stored())
        })
    }

    /// [`Self::plan_with_coverage`] over the book `read_rules` yields, so a
    /// caller that already read it to tell "unreadable" from "none" plans that
    /// same read rather than a second one that may fail.
    fn plan_over(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
        read_rules: impl FnOnce() -> Option<ActiveRulesSnapshot>,
    ) -> Option<(EnforcementPlan, PlanCoverage)> {
        let stored = principal.as_stored();
        let mut timings = crate::phase_timings::PhaseTimings::start();
        // No stored routing policy means the user never bound their adapters,
        // and a plan built without that would pin nothing.
        // Without a policy or rules nothing is planned, so nothing conflicts.
        let Some(policy) = self.policy.load_for_sid(stored) else {
            // A store that did not answer is not "no policy": the plan in force
            // is carried, so its IPv6 board and conflicts must stay published.
            if self.policy.read_failure_for(stored).is_some() {
                return None;
            }
            publish_ipv6_disposition(stored, None);
            // Routing needs connections; a deny does not.
            return self.plan_denies_without_policy(principal, read_rules);
        };
        timings.mark("policy");
        self.note_pass_links(stored, &policy);
        let Some(rules) = read_rules() else {
            publish_ipv6_disposition(stored, None);
            self.publish_conflicts(stored, None);
            return None;
        };
        timings.mark("rules");
        // The user's mode, from the same policy row the Windows planner reads;
        // the rules snapshot only carries a placeholder.
        let behavior_mode = behavior_mode_for_codegen(&policy);
        let posture = protection_posture(
            behavior_mode,
            policy.leak_protection,
            availability.secondary,
        );
        // One reading of the cache for the whole plan: the book walks below ask
        // it per host, and against SQLite each ask is a locked query.
        let snapshot = self.fqdn_cache.snapshot_for_compute();
        let cache =
            crate::fqdn_cache_lookup::snapshot_or_live(snapshot.as_ref(), self.fqdn_cache.as_ref());

        // The shared-IP policy decides which addresses the tunnel may claim,
        // and the plan has to be built behind the same decision the Windows
        // codegen makes — otherwise this path pins addresses the policy
        // declined.
        let secondary_ip_denylist = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            cache,
            policy.shared_ip_policy,
        );
        timings.mark("denylist");
        // What policy may do about IPv6: naming the family and STEERING it are
        // separate answers, and only the machine reading knows either.
        let ipv6 = self.ipv6_guard(&policy);
        publish_ipv6_disposition(stored, Some(ipv6));
        // Every pass, whatever the book needs: the screen of a rule submitted
        // while the tunnel is down reads what was noted here.
        self.remember_tunnel_servers(stored, &policy);
        self.warn_too_wide_local_networks(stored, &policy);
        // Where observations are kept per user, this user's programs alone
        // decide where their application rules send traffic.
        let own_observations = self.app_observations.for_principal(stored);
        let observations = own_observations
            .as_deref()
            .unwrap_or(self.app_observations.as_ref());
        let input = PlannerInput {
            fqdn_cache: cache,
            app_resolver: self.app_resolver.as_ref(),
            app_observations: observations,
            zone_priority_over_ip: policy.zone_priority_over_ip,
            app_rules_take_all_addresses: policy.app_rules_take_all_addresses,
            secondary_ip_denylist: &secondary_ip_denylist,
            ipv6,
            packet_blocks: self.rules.rules_are_baseline_for(stored),
        };
        let (mut flows, plan_report) = plan_route_rules(&rules.rule_book, stored, &input);
        // Before the early return below: a book whose every rule was skipped
        // plans nothing, and those skips are exactly what the user must see.
        self.publish_conflicts(stored, Some((&plan_report, &rules.rule_book)));
        timings.mark("planner");
        // An empty rule set is not "nothing to enforce" wherever the protection
        // is not rule-driven: the tunnel-default route, and the hold of
        // "everything" once the tunnel is gone.
        if flows.is_empty()
            && behavior_mode == RouteBehaviorMode::PreferPrimary
            && !is_blanket(posture)
        {
            return None;
        }
        // Who owns which address, from the one arbiter. A block is never one of
        // the outcomes the user asked for when their own main-link rule names
        // the address, in any mode.
        let ownership = crate::address_ownership::AddressOwnership::resolve_for(
            &rules.rule_book,
            cache,
            crate::address_ownership::OwnershipSettings::from_policy(
                policy.zone_priority_over_ip,
                policy.app_rules_take_all_addresses,
            ),
            crate::wfp_codegen::current_rule_shape_support(),
            observations,
        );
        let rule_driven_flows = flows.len();
        timings.mark("ownership");

        // The blanket block, when the posture asks for it AND the machine can
        // say what it must not cut. It supersedes the per-destination guard:
        // both installed would be one policy stated twice.
        let blanket = self.blanket_block(stored, &policy, posture, &flows, &ownership);
        let block_all_armed = !blanket.is_empty();
        let forwarded_blanket =
            if block_all_armed && !availability.secondary && policy.guard_forwarded_traffic {
                self.forwarded_blanket(stored, &policy, &flows, &ownership)
            } else {
                Vec::new()
            };
        // With the tunnel gone a secondary permit has no link to pin it to and
        // ranks above the hold: it would carry exactly what the hold is for out
        // the main link.
        if block_all_armed && !availability.secondary {
            flows.retain(|f| {
                !(f.verdict == Verdict::Permit
                    && f.precedence.class == PrecedenceClass::RouteRule(RouteRole::Secondary))
            });
        }
        flows.extend(blanket);
        flows.extend(forwarded_blanket);

        // The addresses the leak-guard may act on, under the same shared-address
        // rule as the Windows guard: smart spares what a direct host shares.
        // The main link's own segments too, read once: nothing to read when off.
        let floor = if matches!(posture, ProtectionPosture::Open) {
            CatchAllExemptions::default()
        } else {
            self.exemptions_for(stored, &policy)
        };
        let spared = Spared {
            shared: self.shared_ips_spared(&policy, cache),
            infrastructure: crate::enforcement_planner::LinkInfrastructure {
                tunnel_servers: floor
                    .server_ips
                    .iter()
                    .map(|ip| std::net::IpAddr::V4(*ip))
                    .chain(
                        floor
                            .server_ips_v6
                            .iter()
                            .map(|ip| std::net::IpAddr::V6(*ip)),
                    )
                    .collect(),
                link_resolvers: self.primary_dns(),
            },
            secondary_literals: rules
                .rule_book
                .secondary
                .rules()
                .iter()
                .filter(|rule| rule.enabled)
                .filter_map(|rule| match rule.address_match {
                    Some(nrr_domain::canonical::CanonicalAddressMatch::ExactIp(ip)) => Some(ip),
                    _ => None,
                })
                .collect(),
            floor,
        };

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
        let unroutable_v6 =
            self.unroutable_v6_blocks(stored, &policy, ipv6, &flows, &ownership, &spared);
        flows.extend(unroutable_v6);

        // The per-destination guard: the pin while the link is up, the block
        // once it is gone. An armed blanket already states both; a blanket the
        // machine refused falls back to it.
        let per_destination = !block_all_armed && !matches!(posture, ProtectionPosture::Open);
        let (guard, fail_closed_blocks) = match posture {
            ProtectionPosture::PinRuleDestinations | ProtectionPosture::CatchAllThroughTunnel
                if per_destination =>
            {
                (
                    self.pin_to_tunnel(stored, &policy, &mut flows, &ownership, &spared),
                    0,
                )
            }
            ProtectionPosture::BlockRuleDestinations | ProtectionPosture::BlockAll
                if per_destination =>
            {
                let fail_closed =
                    self.fail_closed_flows(stored, &policy, &flows, &ownership, &spared);
                let blocks = fail_closed
                    .iter()
                    .filter(|flow| flow.verdict == Verdict::Block)
                    .count();
                (fail_closed, blocks)
            }
            _ => {
                self.network_hold_log.forget(stored);
                (Vec::new(), 0)
            }
        };
        flows.extend(guard);
        self.publish_shared_ip_exemptions(stored, per_destination, &flows, &ownership, &spared);
        let service =
            self.service_account_flows(stored, &policy, posture, &flows, &ownership, &spared);
        flows.extend(service);
        // Whatever blocked above, a corporate tunnel beside ours keeps the
        // networks it carries.
        let foreign = crate::enforcement_planner::plan_foreign_tunnel_permits(
            stored,
            &flows,
            &self.foreign_tunnels_for(&policy),
        );
        flows.extend(foreign);
        // Another VPN's handshake, before the lockdown joins `flows`. nft has
        // no per-program match: the IKE daemons are known by the system uids
        // they run as.
        let handshake = crate::enforcement_planner::plan_vpn_handshake_permits(
            stored,
            &flows,
            &crate::vpn_gateway_confirm::global_vpn_gateways().confirmed_addresses(stored),
        );
        let ike = crate::enforcement_planner::plan_ike_service_permits(
            &flows,
            crate::enforcement_planner::IkeServiceMatch::AnyServiceProgram,
        );
        // A policy-based IPsec VPN has no interface for the foreign permits
        // above: its networks are spared by the kernel's own IPsec decision.
        let ipsec = crate::enforcement_planner::plan_ipsec_policy_permits(stored, &flows);
        flows.extend(handshake);
        flows.extend(ike);
        flows.extend(ipsec);

        // Browser DoH hides the names wildcard rules learn from, so blocking it
        // sends the browser back to plaintext DNS. Same gate as the codegen.
        if doh_lockdown_active(&policy, &rules.rule_book) {
            let doh = plan_doh_dot_block(stored, &policy.doh_resolver_ips, true);
            // A corporate link's permits would outrank the lockdown for a
            // resolver that link routes; the lockdown is restated above them.
            let vetoes = crate::enforcement_planner::plan_doh_foreign_vetoes(stored, &doh, &flows);
            flows.extend(doh);
            flows.extend(vetoes);
        }
        timings.mark("guards");

        // Routes are planned even while the secondary is down: the applier
        // resolves the link at apply time and reports the ones it cannot steer,
        // which keeps "no route installed" a stated fact rather than a silent
        // omission in the plan.
        let routes = self.routes_for(
            stored,
            &policy,
            behavior_mode,
            &rules.rule_book,
            availability.primary,
            cache,
            observations,
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

        let guard_holding = matches!(
            posture,
            ProtectionPosture::BlockRuleDestinations | ProtectionPosture::BlockAll
        );
        let coverage = PlanCoverage {
            rule_driven_flows,
            fail_closed_blocks,
            guard_holding,
            route_intents: routes.len(),
            kill_switch_complete: !is_blanket(posture) || block_all_armed,
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
    /// The plan of a user with no route policy: their denies, through the same
    /// planner as everyone's, and nothing that needs a connection.
    fn plan_denies_without_policy(
        &self,
        principal: &UserPrincipal,
        read_rules: impl FnOnce() -> Option<ActiveRulesSnapshot>,
    ) -> Option<(EnforcementPlan, PlanCoverage)> {
        let stored = principal.as_stored();
        let Some(rules) =
            read_rules().filter(|r| crate::rule_book_facts::has_deny_rules(&r.rule_book))
        else {
            self.publish_conflicts(stored, None);
            return None;
        };
        let snapshot = self.fqdn_cache.snapshot_for_compute();
        let cache =
            crate::fqdn_cache_lookup::snapshot_or_live(snapshot.as_ref(), self.fqdn_cache.as_ref());
        let secondary_ip_denylist = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            cache,
            nrr_domain::shared_ip::SharedIpPolicy::default(),
        );
        let ipv6 = match self.machine_reading() {
            Some(reading) => crate::enforcement_planner::Ipv6Guard::from_links(
                reading.adapters().unwrap_or_default(),
                None,
                &[],
            ),
            None => crate::enforcement_planner::Ipv6Guard::Off,
        };
        let own_observations = self.app_observations.for_principal(stored);
        let input = PlannerInput {
            fqdn_cache: cache,
            app_resolver: self.app_resolver.as_ref(),
            app_observations: own_observations
                .as_deref()
                .unwrap_or(self.app_observations.as_ref()),
            zone_priority_over_ip: false,
            app_rules_take_all_addresses: false,
            secondary_ip_denylist: &secondary_ip_denylist,
            ipv6,
            packet_blocks: self.rules.rules_are_baseline_for(stored),
        };
        let (mut flows, report) = plan_route_rules(&rules.rule_book, stored, &input);
        self.publish_conflicts(stored, Some((&report, &rules.rule_book)));
        // A permit rides a route or carves a hole in a guard; neither exists
        // here, and a narrower rule inside a deny is already cut out of it.
        flows.retain(|f| f.verdict == Verdict::Block);
        if flows.is_empty() {
            return None;
        }
        let coverage = PlanCoverage {
            rule_driven_flows: flows.len(),
            fail_closed_blocks: 0,
            guard_holding: false,
            route_intents: 0,
            kill_switch_complete: true,
        };
        Some((
            EnforcementPlan {
                principal: PlanPrincipal::from_stored(stored).ok()?,
                flows,
                routes: Vec::new(),
                policy_rules: Vec::new(),
            },
            coverage,
        ))
    }
}

/// One line naming the network rules carved past the cap, which were skipped.
/// Both planners call it.
pub(crate) fn log_networks_over_cap(principal: &str, rules: &[String]) {
    if rules.is_empty() {
        return;
    }
    tracing::warn!(
        target: "nrr::enforcement",
        msg_key = "persid-plan-network-carving-over-cap",
        sid = %principal,
        count = rules.len(),
        rules = %rules.join(", "),
        "network rules hold more narrower rules than can be carved out, so their filters are skipped and the narrower rules inside keep working (rule: pieces/cap)",
    );
}

impl ProductionPrincipalPlanSource {
    /// Store `principal`'s conflicts for the Overlaps screen and its app rules
    /// that found no program; `None` clears both. The pass re-plans on a
    /// timer, so only a change is logged.
    fn publish_conflicts(
        &self,
        principal: &str,
        planned: Option<(
            &crate::enforcement_planner::PlanReport,
            &nrr_domain::canonical::CanonicalRuleBook,
        )>,
    ) {
        // A pre-flight plans a revision that is not in force.
        if crate::applying_revision_overlay::previewing() {
            return;
        }
        let Some(status) = self.conflicts.as_ref() else {
            return;
        };
        status.set_unresolved(
            principal,
            planned
                .map(|(report, _)| report.unresolved_apps.clone())
                .unwrap_or_default(),
        );
        let conflicts = planned
            .map(|(report, book)| {
                let mut conflicts =
                    crate::rule_conflicts::rule_conflict_dtos(&report.conflicts, book);
                conflicts.extend(crate::rule_conflicts::protected_rule_dtos(
                    &self.rules.withheld_rules_for(principal),
                ));
                conflicts
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
        let over_cap = planned
            .map(|(report, _)| crate::rule_conflicts::over_cap_networks(&report.conflicts))
            .unwrap_or_default();
        log_networks_over_cap(principal, &over_cap);
    }

    /// The blanket block-all, or nothing.
    ///
    /// Two postures share one shape. With the tunnel UP and the tunnel as the
    /// default route, the block is what makes "everything goes through the
    /// tunnel" true rather than merely intended. With the tunnel GONE, it holds
    /// the traffic instead of letting it out the way the user asked it not to go.
    ///
    /// Both refuse to arm without a tunnel-server exemption — that block would
    /// seal the tunnel's own reconnect, and nothing on the machine could lift
    /// it. The caller then falls back to the per-destination guard and reports
    /// incomplete protection.
    fn blanket_block(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        posture: ProtectionPosture,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
    ) -> Vec<FlowRule> {
        if !is_blanket(posture) {
            return Vec::new();
        }
        let exemptions = self.exemptions_for(stored, policy);
        // A remembered server alone is no licence: without the primary the
        // attached subnets are unknown, and the block would cut the LAN.
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
        if matches!(posture, ProtectionPosture::CatchAllThroughTunnel) {
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
            crate::enforcement_planner::plan_fail_closed_block_all_with_dns(
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
                &self.primary_dns(),
                protocols,
            )
        }
    }

    /// The blanket for what the machine forwards, once the tunnel is gone and
    /// the owner's own blanket is armed. The main-link rule permits that let
    /// the owner's direct hosts out are the owner's alone, so the direct hosts
    /// and the main link's resolvers are stated here as the floor's own.
    fn forwarded_blanket(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
    ) -> Vec<FlowRule> {
        let exemptions = self.exemptions_for(stored, policy);
        let mut direct = primary_destinations(rule_flows, ownership);
        direct.extend(self.primary_dns().into_iter().filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        }));
        direct.sort_unstable();
        direct.dedup();
        let mut blanket = plan_fail_closed_block_all(
            stored,
            &exemptions.server_ips,
            &[],
            &exemptions.local_subnets,
            &[],
            &direct,
            crate::enforcement_planner::Ipv6Exemptions {
                server_ips: &exemptions.server_ips_v6,
                local_subnets: &exemptions.local_subnets_v6,
            },
            false,
            &[],
            KillSwitchProtocols::ALL,
        );
        blanket.extend(primary_network_permits(rule_flows));
        // The blanket spares no foreign tunnel whole; the narrowed permits
        // below are all a guest keeps through one.
        crate::enforcement_planner::plan_forwarded_block_all_with_foreign(
            blanket,
            &self.foreign_tunnels_for(policy),
        )
    }

    /// The main link's resolvers of both families, the only hosts the DNS
    /// permit may name; a v6-only network keeps its resolvers too.
    fn primary_dns(&self) -> Vec<std::net::IpAddr> {
        self.service_accounts
            .as_ref()
            .map(|primary_dns| primary_dns())
            .unwrap_or_default()
    }

    /// What policy may do about IPv6 for this principal's bindings.
    ///
    /// Unreadable machine state answers [`Ipv6Guard::Off`]: without knowing
    /// what the links carry, naming the family would pin destinations on a
    /// guess.
    fn ipv6_guard(&self, policy: &PerSidPolicySnapshot) -> crate::enforcement_planner::Ipv6Guard {
        use crate::enforcement_planner::Ipv6Guard;
        match self.machine_reading() {
            Some(reading) => Self::ipv6_guard_from(Some(reading), policy),
            // Links that cannot be read are not links without IPv6: under leak
            // protection the family is named so a rule host's v6 addresses are
            // pinned, never left open for this pass.
            None if self.machine.is_some() && policy.leak_protection.is_on() => {
                Ipv6Guard::FiltersOnly
            }
            None => Ipv6Guard::Off,
        }
    }

    /// [`Self::ipv6_guard`] from the last pass's reading, taking none: `Off`
    /// before any pass has read the machine, and while one is reading it —
    /// the lock is held across the enumeration, which a DNS answer must not
    /// wait out.
    fn ipv6_guard_last_read(
        &self,
        policy: &PerSidPolicySnapshot,
    ) -> crate::enforcement_planner::Ipv6Guard {
        let Some(machine) = self.machine.as_ref() else {
            return crate::enforcement_planner::Ipv6Guard::Off;
        };
        let reading = match machine.reading.try_lock() {
            Ok(cached) => cached.clone(),
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().clone(),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        Self::ipv6_guard_from(reading, policy)
    }

    fn ipv6_guard_from(
        reading: Option<Arc<MachineReading>>,
        policy: &PerSidPolicySnapshot,
    ) -> crate::enforcement_planner::Ipv6Guard {
        use crate::enforcement_planner::Ipv6Guard;
        let Some(reading) = reading else {
            return Ipv6Guard::Off;
        };
        let adapters = reading.adapters().unwrap_or_default();
        let secondary = crate::catch_all_exemptions::bound_adapter(
            adapters,
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        );
        Ipv6Guard::from_links(adapters, secondary, reading.routes().unwrap_or_default())
    }

    /// The prefixes the bound tunnel steers the internet with, which mode A's
    /// counter-overlay has to out-specific. A machine that cannot be read is
    /// taken to hold the classic redirect pair; a tunnel not up takes nothing.
    fn tunnel_catch_alls(&self, policy: &PerSidPolicySnapshot) -> Vec<(std::net::Ipv4Addr, u8)> {
        let assumed = || crate::route_codegen::ASSUMED_CATCH_ALLS.to_vec();
        let Some(reading) = self.machine_reading() else {
            return assumed();
        };
        let (Some(adapters), Some(routes)) = (reading.adapters(), reading.routes()) else {
            return assumed();
        };
        let Some(tunnel) = crate::catch_all_exemptions::bound_adapter(
            adapters,
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        ) else {
            return Vec::new();
        };
        crate::route_codegen::tunnel_catch_all_prefixes(routes, tunnel.index)
    }

    /// The route intents for `book`, network routes planned around this
    /// machine's links.
    #[allow(clippy::too_many_arguments)]
    fn routes_for(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        mode: RouteBehaviorMode,
        book: &nrr_domain::canonical::CanonicalRuleBook,
        has_primary: bool,
        cache: &dyn FqdnCacheLookup,
        observations: &dyn AppObservationLookup,
        denied: &std::collections::HashSet<std::net::Ipv4Addr>,
        families: crate::enforcement_planner::FamilyScope,
        support: nrr_domain::rule_shape::RuleShapeSupport,
    ) -> Vec<nrr_platform_api::enforcement::RouteIntent> {
        let catch_alls = self.tunnel_catch_alls(policy);
        let networks = self.network_route_facts(stored, policy, &catch_alls);
        plan_routes_with(
            mode,
            book,
            has_primary,
            cache,
            observations,
            denied,
            families,
            crate::address_ownership::OwnershipSettings::from_policy(
                policy.zone_priority_over_ip,
                policy.app_rules_take_all_addresses,
            ),
            &catch_alls,
            &networks,
            support,
        )
    }

    /// The `/32`s and `/128`s to the additional link that the next pass for
    /// `principal` would plan for `addresses` — the only routes a first contact
    /// can be early for, so a rule host's first connect leaves through the
    /// link its rule names. On the answer path: no machine reading of its own,
    /// network rules planned around nothing, since a first contact is a host,
    /// and the cache cut down to `addresses`. Nothing before a pass has read the
    /// machine; a v6 address only when the last pass found the link carrying
    /// the family.
    pub fn first_contact_routes(
        &self,
        principal: &PlanPrincipal,
        availability: ChannelAvailability,
        addresses: &[std::net::IpAddr],
    ) -> Vec<nrr_platform_api::enforcement::RouteIntent> {
        use crate::enforcement_planner::FamilyScope;
        if addresses.is_empty() || !availability.secondary {
            return Vec::new();
        }
        let stored = principal.as_stored();
        // Before a pass has read the machine, a LAN or another tunnel's
        // address would plan into our tunnel: wait for the pass.
        if !self
            .machine_read
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(stored)
        {
            return Vec::new();
        }
        let Some(policy) = self.policy.load_for_sid(stored) else {
            return Vec::new();
        };
        let families = if addresses.iter().any(std::net::IpAddr::is_ipv6) {
            self.ipv6_guard_last_read(&policy).route_families()
        } else {
            FamilyScope::V4Only
        };
        if !addresses.iter().any(|ip| families.admits(*ip)) {
            return Vec::new();
        }
        let Some(rules) = self.rules.active_rules_for(stored) else {
            return Vec::new();
        };
        // The cache cut down to these addresses: the plan decides about them
        // as over the whole cache, at the cost of the few hosts on them.
        let scoped = self
            .fqdn_cache
            .snapshot_for_compute()
            .map(|full| full.scoped_to(addresses));
        let cache =
            crate::fqdn_cache_lookup::snapshot_or_live(scoped.as_ref(), self.fqdn_cache.as_ref());
        let denied = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            cache,
            policy.shared_ip_policy,
        );
        let own_observations = self.app_observations.for_principal(stored);
        plan_routes_with(
            behavior_mode_for_codegen(&policy),
            &rules.rule_book,
            availability.primary,
            cache,
            own_observations
                .as_deref()
                .unwrap_or(self.app_observations.as_ref()),
            &denied,
            families,
            crate::address_ownership::OwnershipSettings::from_policy(
                policy.zone_priority_over_ip,
                policy.app_rules_take_all_addresses,
            ),
            &[],
            &crate::kept_direct::published_facts(stored),
            crate::wfp_codegen::current_rule_shape_support(),
        )
        .into_iter()
        .filter(|route| {
            let host = match route.dst {
                DstMatch::HostV4(ip) => std::net::IpAddr::V4(ip),
                DstMatch::HostV6(ip) => std::net::IpAddr::V6(ip),
                _ => return false,
            };
            route.egress == EgressRef::Secondary && addresses.contains(&host)
        })
        .collect()
    }

    /// What a network rule's routes must respect, from the pass's reading: the
    /// tunnel's routes, the attached networks and the tunnel's servers. Only
    /// the catch-alls when the machine cannot be read. Host routes use the
    /// attached networks and foreign tunnels too, so the reading is not gated
    /// on the book.
    fn network_route_facts(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        catch_alls: &[(std::net::Ipv4Addr, u8)],
    ) -> NetworkRouteFacts {
        let fallback = || NetworkRouteFacts::from_catch_alls(catch_alls);
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
            .chain(self.known_tunnel_servers(stored))
            .collect();
        let routes = reading.routes().unwrap_or_default();
        let foreign: Vec<u32> = match reading.routes() {
            Some(routes) => {
                let ours =
                    crate::route_coordinator::own_link_indexes(adapters, &[], bindings_of(policy));
                let additional = crate::route_coordinator::own_link_indexes(
                    adapters,
                    &[],
                    policy.secondary.iter(),
                );
                crate::route_coordinator::foreign_tunnel_indexes(
                    adapters,
                    &ours,
                    &additional,
                    routes,
                )
            }
            None => Vec::new(),
        };
        let facts = NetworkRouteFacts::read(routes, adapters, tunnel, servers)
            .with_foreign_tunnels(routes, &foreign);
        crate::kept_direct::publish(stored, &facts);
        self.machine_read
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(stored.to_owned());
        facts
    }

    /// Name `stored`'s foreign tunnels and own links from the pass's reading,
    /// for [`Self::publish_pass_links`]. Nothing is recorded while the machine
    /// cannot be read: doubt is "not foreign".
    fn note_pass_links(&self, stored: &str, policy: &PerSidPolicySnapshot) {
        let Some(reading) = self.machine_reading() else {
            return;
        };
        let (Some(adapters), Some(routes)) = (reading.adapters(), reading.routes()) else {
            return;
        };
        let ours = crate::route_coordinator::own_link_indexes(adapters, &[], bindings_of(policy));
        let own =
            crate::route_coordinator::own_link_indexes(adapters, &[], policy.secondary.iter());
        let foreign =
            crate::route_coordinator::foreign_tunnel_indexes(adapters, &ours, &own, routes);
        self.pass_links
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(stored.to_owned(), PassLinks { foreign, own });
    }

    /// Publish the pass's links into `cell`, once for every planned user. A
    /// pass that planned nobody, or could not read the machine, leaves the
    /// cell as it was.
    fn publish_pass_links(&self, cell: &crate::foreign_tunnels::ForeignTunnelCell) {
        let links = std::mem::take(&mut *self.pass_links.lock().unwrap_or_else(|p| p.into_inner()));
        if links.is_empty() {
            return;
        }
        let Some(reading) = self.machine_reading() else {
            return;
        };
        let foreign: Vec<Vec<u32>> = links.values().map(|l| l.foreign.clone()).collect();
        let own: Vec<u32> = links.values().flat_map(|l| l.own.iter().copied()).collect();
        cell.publish_served(
            reading.routes(),
            reading.adapters().unwrap_or_default(),
            &foreign,
            &own,
        );
    }

    /// The tunnels beside this principal's bound links, from the pass's
    /// reading; none when the machine cannot be read.
    fn foreign_tunnels_for(
        &self,
        policy: &PerSidPolicySnapshot,
    ) -> Vec<crate::enforcement_planner::ForeignTunnelLink> {
        let Some(reading) = self.machine_reading() else {
            return Vec::new();
        };
        let Some(adapters) = reading.adapters() else {
            return Vec::new();
        };
        crate::catch_all_exemptions::foreign_tunnel_links(
            reading.routes(),
            adapters,
            policy.primary.as_ref(),
            policy.secondary.as_ref(),
        )
    }

    /// What this principal's blanket block must not cut, from the pass's reading
    /// of the machine.
    ///
    /// The known servers join even while the links are unresolved: every use
    /// of a server here opens, and a stale one only permits a little more.
    fn exemptions_for(&self, stored: &str, policy: &PerSidPolicySnapshot) -> CatchAllExemptions {
        let Some(reading) = self.machine_reading() else {
            return CatchAllExemptions::default();
        };
        let mut exemptions = collect_exemptions(
            reading.routes().unwrap_or_default(),
            reading.adapters().unwrap_or_default(),
            policy.primary.as_ref().map(|b| b.display_name.as_str()),
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        );
        // Unresolved links yield no exemptions at all, and the answers do not
        // change that.
        if let Some(networks) = self
            .local_networks
            .as_ref()
            .filter(|_| self.links_resolve(policy))
        {
            networks.apply_to_exemptions(
                stored,
                policy,
                reading.routes().unwrap_or_default(),
                reading.adapters().unwrap_or_default(),
                &mut exemptions,
            );
        }
        for ip in self.known_tunnel_servers(stored) {
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

    /// Tell the user about a reported segment too wide to be local; the
    /// exemptions have already left it out. Same latch as the Windows
    /// coordinator, named by the link the user bound.
    fn warn_too_wide_local_networks(&self, stored: &str, policy: &PerSidPolicySnapshot) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        let Some(primary) = policy.primary.as_ref() else {
            return;
        };
        let too_wide = self.exemptions_for(stored, policy).too_wide;
        self.too_wide_notices.publish(
            bus,
            stored,
            &primary.display_name,
            &too_wide,
            std::time::Instant::now(),
        );
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
    fn remember_tunnel_servers(&self, stored: &str, policy: &PerSidPolicySnapshot) {
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
        sources.memory.observe(stored, &live);
    }

    /// The servers known beyond the live host routes: the kernel tunnels'
    /// peers and the ones remembered for this principal alone. Never an address a dropped connection
    /// named: a CDN front a rule host shares would become a hole in the guard.
    /// The only thing a drop may earn is the client's own process.
    fn known_tunnel_servers(&self, stored: &str) -> Vec<std::net::IpAddr> {
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
                    .remembered(stored)
                    .into_iter()
                    .map(std::net::IpAddr::V4),
            )
            .collect()
    }

    /// Blocks over the secondary rules' IPv6 destinations when the tunnel
    /// cannot carry the family at all.
    ///
    /// Gated on leak protection: a user who turned it off has said they prefer
    /// a leak to an outage, and this is that same trade on a different axis.
    fn unroutable_v6_blocks(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        ipv6: crate::enforcement_planner::Ipv6Guard,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
        spared: &Spared,
    ) -> Vec<FlowRule> {
        if ipv6 != crate::enforcement_planner::Ipv6Guard::FiltersOnly
            || !policy.leak_protection.is_on()
        {
            return Vec::new();
        }
        let protected: Vec<std::net::IpAddr> = guarded_destinations(rule_flows, ownership, spared)
            .0
            .into_iter()
            .filter(|ip| ip.is_ipv6())
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
        spared: &Spared,
    ) -> Vec<FlowRule> {
        let protocols = KillSwitchProtocols::from_bits(policy.kill_switch_protocols);
        if !(protocols.tcp || protocols.udp) {
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
            if nrr_platform_api::is_exempt_from_blocking(ip)
                || !ownership.may_block(ip)
                || is_spared(ip, spared)
            {
                continue;
            }
            flow.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
            pinned.push(ip);
        }
        let holds = NetworkHolds::for_pass(ownership, &pinned, || never_blocked(&spared.floor));
        self.network_hold_log.note(stored, &holds);
        plan_kill_switch_networks(stored, &holds, protocols)
    }

    /// The per-destination and per-network blocks that arm while the secondary
    /// is unreachable. The posture is the gate, as on Windows.
    fn fail_closed_flows(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
        spared: &Spared,
    ) -> Vec<FlowRule> {
        let (protected, _) = guarded_destinations(rule_flows, ownership, spared);
        let holds = NetworkHolds::for_pass(ownership, &protected, || never_blocked(&spared.floor));
        self.network_hold_log.note(stored, &holds);
        let protocols = KillSwitchProtocols::from_bits(policy.kill_switch_protocols);
        let mut flows = plan_fail_closed_destinations(stored, &protected, protocols);
        flows.extend(plan_fail_closed_networks(stored, &holds, protocols));
        flows
    }
}

/// Leave `guard` where the DNS path reads it for `stored`'s AAAA answers;
/// `None` is "nothing routes or pins this principal's IPv6". A preview leaves
/// the board alone, as on Windows.
fn publish_ipv6_disposition(stored: &str, guard: Option<crate::enforcement_planner::Ipv6Guard>) {
    if crate::applying_revision_overlay::previewing() {
        return;
    }
    let board = crate::ipv6_disposition::global_ipv6_dispositions();
    match guard {
        Some(guard) => board.set(stored, guard),
        None => board.forget(stored),
    }
}

/// The IPv4 addresses the shared-address census has seen serving a direct host.
type SharedIps = std::collections::HashSet<std::net::Ipv4Addr>;

impl ProductionPrincipalPlanSource {
    /// What the leak-guard leaves alone because a direct host shares it: a
    /// block there cuts that host for every program, and the tunnel-bound
    /// site still has its route. Empty under the strict setting. The census
    /// counts IPv4 co-tenancy only, so a v6 address is never spared.
    fn shared_ips_spared(
        &self,
        policy: &PerSidPolicySnapshot,
        cache: &dyn FqdnCacheLookup,
    ) -> SharedIps {
        if policy.kill_switch_strict_shared_ips {
            return SharedIps::new();
        }
        cache.shared_direct_ips()
    }

    /// Report the spared addresses while the per-destination guard is what
    /// protects them; under a blanket block or no protection nothing was left
    /// out.
    fn publish_shared_ip_exemptions(
        &self,
        stored: &str,
        per_destination: bool,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
        spared: &Spared,
    ) {
        if crate::applying_revision_overlay::previewing() {
            return;
        }
        let Some(status) = self.shared_ip_exemptions.as_ref() else {
            return;
        };
        let (protected, excluded) = if per_destination {
            guarded_destinations(rule_flows, ownership, spared)
        } else {
            (Vec::new(), Vec::new())
        };
        let previous = status.count();
        status.set(&excluded);
        if previous != excluded.len() as u32 && !excluded.is_empty() {
            tracing::info!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-shared-ip-excluded",
                sid = stored,
                excluded = excluded.len(),
                pinned = protected.len(),
                "smart kill-switch: shared IPs excluded from the pin/block set (each is also used by a direct host; strict mode pins them regardless)",
            );
        }
    }

    /// The service accounts' share of this principal's guard: the pins while
    /// the tunnel is up, the address blocks once it is gone — never the
    /// blanket either posture may give the user.
    fn service_account_flows(
        &self,
        stored: &str,
        policy: &PerSidPolicySnapshot,
        posture: ProtectionPosture,
        rule_flows: &[FlowRule],
        ownership: &crate::address_ownership::AddressOwnership,
        spared: &Spared,
    ) -> Vec<FlowRule> {
        use crate::enforcement_planner::{
            plan_forwarded_flows_with_foreign, plan_service_account_flows_with_foreign,
            service_account_guard, ServiceAccountInput, ServiceAccountPosture,
        };
        let Some(primary_dns) = self.service_accounts.as_ref() else {
            return Vec::new();
        };
        // Lowering keeps only the owner's; the others' would be built for nothing.
        if !self.is_route_table_owner(stored) {
            return Vec::new();
        }
        let posture = match posture {
            ProtectionPosture::Open => return Vec::new(),
            ProtectionPosture::PinRuleDestinations | ProtectionPosture::CatchAllThroughTunnel => {
                ServiceAccountPosture::Pin
            }
            ProtectionPosture::BlockRuleDestinations | ProtectionPosture::BlockAll => {
                ServiceAccountPosture::Block
            }
        };
        let (protected, _) = guarded_destinations(rule_flows, ownership, spared);
        let exemptions = &spared.floor;
        let holds = NetworkHolds::for_pass(ownership, &protected, || never_blocked(exemptions));
        let servers: Vec<std::net::IpAddr> = exemptions
            .server_ips
            .iter()
            .map(|ip| std::net::IpAddr::V4(*ip))
            .chain(
                exemptions
                    .server_ips_v6
                    .iter()
                    .map(|ip| std::net::IpAddr::V6(*ip)),
            )
            .collect();
        let local: Vec<nrr_shared::ip_block::IpBlock> = exemptions
            .local_subnets
            .iter()
            .map(|(net, len)| (std::net::IpAddr::V4(*net), *len))
            .chain(
                exemptions
                    .local_subnets_v6
                    .iter()
                    .map(|(net, len)| (std::net::IpAddr::V6(*net), *len)),
            )
            .filter_map(|(net, len)| nrr_shared::ip_block::IpBlock::new(net, len))
            .collect();
        let dns = primary_dns();
        let Some(guard) = service_account_guard(&ServiceAccountInput {
            is_route_table_owner: true,
            posture: Some(posture),
            destinations: &protected,
            holds: &holds,
            tunnel_servers: &servers,
            local_subnets: &local,
            primary_dns: &dns,
        }) else {
            return Vec::new();
        };
        self.service_account_dns_log.note(&guard.dns_spared);
        // No per-program match on this platform: the service's own traffic
        // leaves by its mark, and the tunnel's servers are subtracted above.
        let foreign = self.foreign_tunnels_for(policy);
        let mut flows = plan_service_account_flows_with_foreign(
            stored,
            &guard,
            KillSwitchProtocols::from_bits(policy.kill_switch_protocols),
            &[],
            &foreign,
        );
        if policy.guard_forwarded_traffic {
            flows.extend(plan_forwarded_flows_with_foreign(stored, &guard, &foreign));
        }
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

/// What the leak-guard leaves alone: an address a direct host shares, and the
/// main link's own segments, where a rule host keeps its direct route.
#[derive(Default)]
struct Spared {
    shared: SharedIps,
    /// The floor the blanket would keep open; empty while protection is off.
    floor: CatchAllExemptions,
    /// The tunnel's servers and the main link's resolvers.
    infrastructure: crate::enforcement_planner::LinkInfrastructure,
    /// Addresses the additional route's rules name literally.
    secondary_literals: Vec<std::net::IpAddr>,
}

impl Spared {
    fn on_local_segment(&self, ip: std::net::IpAddr) -> bool {
        crate::enforcement_planner::on_attached_segment(
            ip,
            &self.floor.local_subnets,
            &self.floor.local_subnets_v6,
        )
    }
}

/// Whether the leak-guard leaves `ip` alone.
fn is_spared(ip: std::net::IpAddr, spared: &Spared) -> bool {
    spared.on_local_segment(ip)
        || spared
            .infrastructure
            .spares(ip, spared.secondary_literals.contains(&ip))
        || match ip {
            std::net::IpAddr::V4(v4) => spared.shared.contains(&v4),
            std::net::IpAddr::V6(_) => false,
        }
}

/// The networks the PRIMARY rules route, as their own permits. Already carved
/// around every narrower claim, and kept in the rule band, so the forwarded
/// blanket opens them as it does for the owner and a tunnel-bound address
/// inside stays held.
fn primary_network_permits(flows: &[FlowRule]) -> impl Iterator<Item = FlowRule> + '_ {
    flows
        .iter()
        .filter(|flow| {
            flow.verdict == Verdict::Permit
                && flow.precedence.class == PrecedenceClass::RouteRule(RouteRole::Primary)
                && flow.app == AppScope::Any
                && matches!(
                    flow.flow.dst,
                    DstMatch::SubnetV4 { .. } | DstMatch::SubnetV6 { .. }
                )
        })
        .cloned()
}

/// The secondary destinations the guard may pin or block, and the ones the
/// shared-address rule left out of them. An address the user's own main-link
/// rules name is never in either: blocking it cancels one of their rules
/// against the other.
fn guarded_destinations(
    flows: &[FlowRule],
    ownership: &crate::address_ownership::AddressOwnership,
    spared: &Spared,
) -> (Vec<std::net::IpAddr>, Vec<std::net::Ipv4Addr>) {
    let mut protected = Vec::new();
    let mut excluded = Vec::new();
    for ip in secondary_destinations(flows) {
        if !ownership.may_block(ip) || spared.on_local_segment(ip) {
            continue;
        }
        match ip {
            std::net::IpAddr::V4(v4) if spared.shared.contains(&v4) => excluded.push(v4),
            _ => protected.push(ip),
        }
    }
    (protected, excluded)
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
        *self.pass_owner.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.pass_links
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    fn end_pass(&self) {
        self.publish_pass_links(&crate::foreign_tunnels::global_foreign_tunnels());
    }

    fn set_route_table_owner(&self, owner: Option<&UserPrincipal>) {
        *self.pass_owner.lock().unwrap_or_else(|p| p.into_inner()) = Some(owner.cloned());
    }

    fn plan_for(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> Option<PlannedPolicy> {
        self.plan_with_coverage(principal, availability)
            .map(planned_policy)
    }

    /// A book that cannot be read is said so before any plan is drawn: the
    /// plan built from "no rules" would have removed what is installed.
    fn plan_read_for(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> crate::principal_enforcement::PlanRead {
        use crate::per_sid_orchestrator::RulesRead;
        use crate::principal_enforcement::PlanRead;
        // One read decides both: a book that fails between a readability check
        // and the plan's own read would plan as "no rules".
        let rules = match self.rules.rules_read_for(principal.as_stored()) {
            RulesRead::Unreadable(reason) => return PlanRead::Unreadable(reason),
            RulesRead::Rules(snapshot) => Some(snapshot),
            RulesRead::NoPolicy => None,
        };
        let planned = self
            .plan_over(principal, availability, || rules)
            .map(planned_policy);
        // A policy that could not be read answered like an absent one, and the
        // denies-only plan it produced would withdraw the rest.
        if let Some(reason) = self.policy.read_failure_for(principal.as_stored()) {
            return PlanRead::Unreadable(reason);
        }
        match planned {
            Some(planned) => PlanRead::Planned(planned),
            None => PlanRead::NoPolicy,
        }
    }
}

fn planned_policy((plan, coverage): (EnforcementPlan, PlanCoverage)) -> PlannedPolicy {
    PlannedPolicy {
        plan,
        protection_complete: coverage.kill_switch_complete,
        fail_closed_blocks: coverage.fail_closed_blocks,
        guard_holding: coverage.guard_holding,
    }
}

fn doh_lockdown_active(
    policy: &PerSidPolicySnapshot,
    rule_book: &nrr_domain::canonical::CanonicalRuleBook,
) -> bool {
    crate::doh_lockdown_policy::doh_lockdown_active(
        policy.doh_lockdown_auto,
        policy.doh_lockdown_enabled,
        policy.doh_lockdown_scope,
        policy.leak_protection.is_on(),
        crate::rule_book_facts::needs_names_seen(
            rule_book,
            policy.mode
                == crate::per_sid_orchestrator::PerSidBehaviorMode::PreferSecondaryWhenAvailable,
        ),
    )
}

/// The postures that hold everything rather than the rules' destinations.
fn is_blanket(posture: ProtectionPosture) -> bool {
    matches!(
        posture,
        ProtectionPosture::BlockAll | ProtectionPosture::CatchAllThroughTunnel
    )
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

/// The links a principal bound, for the "ours" every foreign-tunnel question
/// starts from.
fn bindings_of(
    policy: &PerSidPolicySnapshot,
) -> impl Iterator<Item = &crate::per_sid_orchestrator::PerSidBinding> {
    policy.primary.iter().chain(policy.secondary.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::{LeakProtection, RuleAction, RuleId};
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
    struct OneSecondaryRule;
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
            })
        }
    }

    /// The settings under test; everything else at its default.
    struct Policy {
        mode: PerSidBehaviorMode,
        protection: LeakProtection,
        dns_over_primary: bool,
        strict_shared_ips: bool,
        /// `Some` = DoH lockdown on with scope `Always`, over these resolvers.
        doh_always: Option<Vec<IpAddr>>,
        auto_accept: bool,
        /// The forwarded-traffic answer is anything but "do not protect".
        guard_forwarded: bool,
    }

    impl Policy {
        /// Main connection by default, the routed sites protected.
        fn armed() -> Self {
            Self {
                mode: PerSidBehaviorMode::PreferPrimary,
                protection: LeakProtection::Sites,
                dns_over_primary: false,
                strict_shared_ips: false,
                doh_always: None,
                auto_accept: false,
                guard_forwarded: true,
            }
        }

        /// Main connection by default, everything protected.
        fn everything() -> Self {
            Self {
                protection: LeakProtection::Everything,
                ..Self::armed()
            }
        }

        /// The additional connection by default, everything protected.
        fn prefer_secondary() -> Self {
            Self {
                mode: PerSidBehaviorMode::PreferSecondaryWhenAvailable,
                protection: LeakProtection::Everything,
                ..Self::armed()
            }
        }

        /// The user chose leak-over-outage: the guard installs nothing.
        fn disarmed() -> Self {
            Self {
                protection: LeakProtection::Off,
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
                mode: self.mode,
                leak_protection: self.protection,
                kill_switch_protocols: 0x7F,
                allow_dns_over_primary: self.dns_over_primary,
                shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
                kill_switch_strict_shared_ips: self.strict_shared_ips,
                link_provider_exe_paths: Vec::new(),
                doh_lockdown_enabled: self.doh_always.is_some(),
                doh_lockdown_scope: if self.doh_always.is_some() {
                    nrr_storage::doh_lockdown::DohLockdownScope::Always
                } else {
                    nrr_storage::doh_lockdown::DohLockdownScope::default()
                },
                doh_lockdown_auto: false,
                doh_resolver_ips: self.doh_always.clone().unwrap_or_default(),
                auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
                primary_probe_auto: false,
                primary_probe_timeout_ms: 1500,
                primary_probe_max_targets: 8,
                primary_probe_repeat_secs: 300,
                local_networks_auto_accept: self.auto_accept,
                zone_priority_over_ip: false,
                app_rules_take_all_addresses: false,
                guard_forwarded_traffic: self.guard_forwarded,
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
    struct NoRulesButBound;
    impl RulesProvider for NoRulesButBound {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(Vec::new()),
                    secondary: CanonicalRuleSet::from_rules(Vec::new()),
                },
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
            override_requested: false,
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
            secondary: CanonicalRuleSet::from_rules(vec![
                rule(
                    "r-host",
                    RuleAction::Route,
                    CanonicalAddressMatch::ExactFqdn("a.example".into()),
                ),
                CanonicalRule {
                    address_match: None,
                    app_match: Some(CanonicalAppMatch {
                        pattern: CanonicalAppPattern::Exact("not-installed-app".into()),
                        include_child_processes: false,
                        override_requested: false,
                    }),
                    ..rule(
                        "r-app",
                        RuleAction::Route,
                        CanonicalAddressMatch::ExactFqdn("unused.example".into()),
                    )
                },
            ]),
        };
        let cache = crate::fqdn_cache_lookup::MockFqdnCacheLookup::default();
        cache.set_ips("a.example", vec![shared]);
        let rules = Arc::new(Switchable(Mutex::new(Some(ActiveRulesSnapshot {
            rule_book,
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
        assert_eq!(
            status.unresolved(user().as_stored()),
            vec!["not-installed-app".to_string()],
            "an app rule with no program behind it is the user's own banner"
        );
        assert!(status
            .unresolved(UserPrincipal::from_linux_uid(1001).as_stored())
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
        assert!(status.unresolved(user().as_stored()).is_empty());
    }

    #[test]
    fn an_empty_book_in_a_tunnel_mode_still_gets_its_guard() {
        // The tunnel-default route is where an empty book made the whole plan
        // empty - and with it the blanket block and the leak-guard.
        let (plan, _) = plan(NoRulesButBound, Policy::prefer_secondary(), false);
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
            Arc::new(NoRulesButBound),
            Arc::new(Policy::prefer_secondary()),
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
        let (plan, _) = plan(OneSecondaryRule, policy, true);
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
        let (plan, _) = plan(OneSecondaryRule, Policy::armed(), true);
        assert!(doh_blocks(&plan).is_empty());
    }

    #[test]
    fn a_principal_without_stored_policy_plans_nothing() {
        assert!(source(Arc::new(NoRules), Arc::new(NoPolicy))
            .plan_for(&user(), availability(true))
            .is_none());
    }

    /// A deny on a literal address beside a routing rule on another.
    struct DenyAndRoute;
    impl RulesProvider for DenyAndRoute {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            let rule = |id: &str, ip: Ipv4Addr, action| CanonicalRule {
                id: RuleId(id.into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip))),
                app_match: None,
                comment: String::new(),
                action,
                origin: None,
            };
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![rule(
                        "deny-0",
                        Ipv4Addr::new(203, 0, 113, 99),
                        RuleAction::Block,
                    )]),
                    secondary: CanonicalRuleSet::from_rules(vec![rule(
                        "s-0",
                        SECONDARY_HOST,
                        RuleAction::Route,
                    )]),
                },
            })
        }
    }

    #[test]
    fn a_principal_without_stored_policy_still_gets_their_denies() {
        let plan = source(Arc::new(DenyAndRoute), Arc::new(NoPolicy))
            .plan_for(&user(), availability(true))
            .expect("the deny needs no route policy")
            .plan;
        assert!(!plan.flows.is_empty());
        assert!(plan.flows.iter().all(|f| f.verdict == Verdict::Block));
        assert!(plan.routes.is_empty());
    }

    #[test]
    fn a_principal_without_stored_policy_and_without_denies_plans_nothing() {
        assert!(source(Arc::new(OneSecondaryRule), Arc::new(NoPolicy))
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

    /// A planned principal leaves its IPv6 disposition where the DNS path
    /// reads it; a preview of a revision does not, and a principal without a
    /// policy row reads `Off`, never "first plan pending".
    #[test]
    fn a_plan_publishes_its_ipv6_disposition_and_a_preview_does_not() {
        use crate::enforcement_planner::Ipv6Guard;
        // Its own principal: the board is process-wide.
        let principal = UserPrincipal::from_linux_uid(4242);
        let stored = principal.as_stored();
        let board = crate::ipv6_disposition::global_ipv6_dispositions();
        let planner = source(Arc::new(OneSecondaryRule), Arc::new(Policy::armed()));
        let expected = planner.ipv6_guard(&Policy::armed().load_for_sid(stored).expect("policy"));
        let other = if expected == Ipv6Guard::Off {
            Ipv6Guard::FiltersOnly
        } else {
            Ipv6Guard::Off
        };

        board.set(stored, other);
        let dir = tempfile::TempDir::new().expect("temp dir");
        let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open");
        {
            let _preview =
                crate::applying_revision_overlay::preview_on_this_thread(&conn, stored, "{}");
            assert!(
                crate::applying_revision_overlay::previewing(),
                "fixture guard"
            );
            let _ = planner.plan_with_coverage(&principal, availability(true));
        }
        assert_eq!(board.of(stored), Some(other), "a preview published");

        let _ = planner.plan_with_coverage(&principal, availability(true));
        assert_eq!(board.of(stored), Some(expected));

        board.set(stored, other);
        let _ = source(Arc::new(OneSecondaryRule), Arc::new(NoPolicy))
            .plan_with_coverage(&principal, availability(true));
        assert_eq!(board.of(stored), Some(Ipv6Guard::Off));
    }

    /// While the tunnel is up the guard is the pin, not a block.
    #[test]
    fn a_live_secondary_needs_no_fail_closed_blocks() {
        let (plan, coverage) = plan(OneSecondaryRule, Policy::armed(), true);

        assert_eq!(coverage.fail_closed_blocks, 0);
        assert_eq!(blocks_on(&plan, SECONDARY_HOST), 0);
        assert!(!coverage.guard_holding);
    }

    /// The guard holds with nothing to block — every address spared, a cold
    /// cache: a rule host's name must still not be asked of the main link.
    #[test]
    fn a_lost_secondary_holds_even_with_no_destination_to_block() {
        // Mode B: an empty book still plans, which is the zero-block case.
        let (_, coverage) = plan(NoRulesButBound, Policy::prefer_secondary(), false);

        assert_eq!(coverage.fail_closed_blocks, 0);
        assert!(coverage.guard_holding);
    }

    /// The whole point: the tunnel is gone, so the addresses it carried are
    /// blocked rather than quietly leaving over the primary.
    #[test]
    fn a_lost_secondary_arms_the_guard_on_the_addresses_it_carried() {
        let (plan, coverage) = plan(OneSecondaryRule, Policy::armed(), false);

        assert!(coverage.fail_closed_blocks > 0);
        assert!(blocks_on(&plan, SECONDARY_HOST) > 0);
        assert!(
            coverage.kill_switch_complete,
            "split mode with per-IP blocking is fully covered here",
        );
    }

    /// A tunnel host inside a main-link network: the narrower rule carries
    /// it, so the guard holds it when the tunnel is gone, and leaves the
    /// network's other addresses to the main link.
    struct HostInsideMainNetwork;
    impl RulesProvider for HostInsideMainNetwork {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            let rule = |id: &str, m: CanonicalAddressMatch| CanonicalRule {
                id: RuleId(id.into()),
                enabled: true,
                address_match: Some(m),
                app_match: None,
                comment: String::new(),
                action: RuleAction::Route,
                origin: None,
            };
            let network = nrr_shared::ip_block::IpBlock::parse("203.0.113.0/24").expect("net");
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![rule(
                        "p-net",
                        CanonicalAddressMatch::Subnet(network),
                    )]),
                    secondary: CanonicalRuleSet::from_rules(vec![rule(
                        "s-host",
                        CanonicalAddressMatch::ExactFqdn("secret.example".into()),
                    )]),
                },
            })
        }
    }

    #[test]
    fn a_lost_secondary_holds_a_tunnel_host_inside_a_main_link_network() {
        let host = Ipv4Addr::new(203, 0, 113, 5);
        let cache = Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new());
        cache.set_ips("secret.example", vec![host]);
        let (plan, coverage) = source_with_cache(
            Arc::new(HostInsideMainNetwork),
            Arc::new(Policy::armed()),
            cache,
        )
        .plan_with_coverage(&user(), availability(false))
        .expect("the rules must plan");

        assert!(coverage.fail_closed_blocks > 0);
        assert!(
            blocks_on(&plan, host) > 0,
            "the tunnel host leaks over the main link"
        );
        assert_eq!(blocks_on(&plan, Ipv4Addr::new(203, 0, 113, 9)), 0);
    }

    /// The guard is opt-in. Blocking traffic the user never asked to have
    /// blocked is the one failure a routing product must not have.
    #[test]
    fn a_disarmed_guard_blocks_nothing_when_the_secondary_drops() {
        let (plan, coverage) = plan(OneSecondaryRule, Policy::disarmed(), false);

        assert_eq!(coverage.fail_closed_blocks, 0);
        assert_eq!(blocks_on(&plan, SECONDARY_HOST), 0);
        assert!(!coverage.guard_holding);
    }

    /// What a plan holds, read off its flows.
    #[derive(Debug, PartialEq, Eq)]
    enum Held {
        Nothing,
        /// The rule hosts may leave only through the tunnel.
        Pins,
        /// The rule hosts are blocked.
        RuleBlocks,
        /// Everything is held but the floor.
        Everything,
        /// Everything that does not leave through the tunnel is held.
        EverythingOffTunnel,
    }

    fn held(plan: &EnforcementPlan) -> Held {
        let tunnel_egress = plan.flows.iter().any(|f| {
            f.verdict == Verdict::Permit
                && f.precedence.class == PrecedenceClass::CatchAllExempt
                && f.flow.dst == DstMatch::Any
                && f.egress == EgressConstraint::OnlyVia(EgressRef::Secondary)
        });
        let pinned = plan.flows.iter().any(|f| {
            f.flow.dst == DstMatch::HostV4(SECONDARY_HOST)
                && f.egress == EgressConstraint::OnlyVia(EgressRef::Secondary)
        });
        match (blanket_blocks(plan) > 0, tunnel_egress) {
            (true, true) => Held::EverythingOffTunnel,
            (true, false) => Held::Everything,
            _ if blocks_on(plan, SECONDARY_HOST) > 0 => Held::RuleBlocks,
            _ if pinned => Held::Pins,
            _ => Held::Nothing,
        }
    }

    /// The one decision table, end to end on this platform: default route ×
    /// leak protection × tunnel up or down. The mode comes from the policy row
    /// the Windows planner reads too, never the rules snapshot's placeholder.
    #[test]
    fn each_default_route_and_protection_holds_what_the_table_says() {
        use LeakProtection::{Everything, Off, Sites};
        use PerSidBehaviorMode::{
            PreferPrimary as Main, PreferSecondaryWhenAvailable as Additional,
        };
        let table = [
            (Main, Off, true, Held::Nothing),
            (Main, Off, false, Held::Nothing),
            (Main, Sites, true, Held::Pins),
            (Main, Sites, false, Held::RuleBlocks),
            (Main, Everything, true, Held::Pins),
            (Main, Everything, false, Held::Everything),
            (Additional, Off, true, Held::Nothing),
            (Additional, Off, false, Held::Nothing),
            // Not offered under this route; stored, it means everything.
            (Additional, Sites, true, Held::EverythingOffTunnel),
            (Additional, Sites, false, Held::Everything),
            (Additional, Everything, true, Held::EverythingOffTunnel),
            (Additional, Everything, false, Held::Everything),
        ];
        for (mode, protection, up, expected) in table {
            let case = format!("{mode:?} / {protection:?} / tunnel up: {up}");
            let policy = Policy {
                mode,
                protection,
                ..Policy::armed()
            };
            let (plan, coverage) = plan_on_machine(OneSecondaryRule, policy, up, true);
            assert_eq!(held(&plan), expected, "{case}");
            assert_eq!(
                coverage.guard_holding,
                matches!(expected, Held::RuleBlocks | Held::Everything),
                "{case}"
            );
            assert_eq!(
                coverage.fail_closed_blocks > 0,
                expected == Held::RuleBlocks,
                "{case}: a blanket and the per-address blocks are one policy stated twice"
            );
            assert!(coverage.kill_switch_complete, "{case}");
        }
    }

    /// "Everything" under the main-connection route while the tunnel is up:
    /// the rule hosts are pinned to it and nothing else is held, so the sites
    /// the main connection carries keep working.
    #[test]
    fn everything_under_the_main_route_leaves_the_main_links_internet_open_while_the_tunnel_is_up()
    {
        let (plan, coverage) = plan_on_machine(OneSecondaryRule, Policy::everything(), true, true);

        assert_eq!(blanket_blocks(&plan), 0, "the main link's internet is cut");
        assert!(
            !plan
                .flows
                .iter()
                .any(|f| f.verdict == Verdict::Block && f.flow.dst == DstMatch::Any),
            "unmatched traffic is blocked: {:?}",
            plan.flows
        );
        assert_eq!(held(&plan), Held::Pins);
        assert!(!coverage.guard_holding);
        assert!(coverage.kill_switch_complete);
    }

    /// The hold of "everything" keeps name resolution over the main connection
    /// open when the user allowed it, under either default route, and only then.
    #[test]
    fn a_lost_tunnel_under_everything_keeps_dns_over_the_main_link_only_when_allowed() {
        use nrr_platform_api::enforcement::PrincipalScope;
        const RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
        for mode in [
            PerSidBehaviorMode::PreferPrimary,
            PerSidBehaviorMode::PreferSecondaryWhenAvailable,
        ] {
            for allowed in [true, false] {
                let (api, links) = machine(true);
                let policy = Policy {
                    mode,
                    dns_over_primary: allowed,
                    ..Policy::everything()
                };
                let (plan, _) = source(Arc::new(OneSecondaryRule), Arc::new(policy))
                    .with_machine_facts(
                        api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                        links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
                    )
                    .with_service_accounts(Arc::new(|| vec![IpAddr::V4(RESOLVER)]))
                    .plan_with_coverage(&user(), availability(false))
                    .expect("the rule must plan");

                assert_eq!(held(&plan), Held::Everything, "{mode:?}");
                let dns_open = plan.flows.iter().any(|f| {
                    f.verdict == Verdict::Permit
                        && f.precedence.class == PrecedenceClass::CatchAllExempt
                        && !matches!(
                            f.principal,
                            PrincipalScope::ServiceAccounts | PrincipalScope::Forwarded
                        )
                        && f.flow.dst == DstMatch::HostV4(RESOLVER)
                        && f.flow.dst_port == Some(53)
                });
                assert_eq!(dns_open, allowed, "{mode:?}, allowed: {allowed}");
            }
        }
    }

    const SERVER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);

    /// The blanket judges both families on a backend with one chain, so it
    /// leaves the IPv6 link scope and the tunnel's v6 endpoint open.
    #[test]
    fn the_blanket_leaves_the_ipv6_link_scope_and_the_tunnels_v6_server_open() {
        struct V6Peer;
        impl TunnelEndpointSource for V6Peer {
            fn tunnel_endpoints(&self) -> Vec<IpAddr> {
                vec![IpAddr::V6(SERVER_V6)]
            }
        }
        for up in [true, false] {
            let (api, links) = machine(true);
            let (plan, _) = source(
                Arc::new(OneSecondaryRule),
                Arc::new(Policy::prefer_secondary()),
            )
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
            .with_tunnel_servers(remembering(Vec::new()), Some(Arc::new(V6Peer)))
            .plan_with_coverage(&user(), availability(up))
            .expect("the rule must plan");

            assert!(blanket_blocks(&plan) > 0, "fixture guard: the blanket arms");
            for dst in [
                DstMatch::SubnetV6 {
                    net: Ipv6Addr::LOCALHOST,
                    prefix: 128,
                },
                DstMatch::SubnetV6 {
                    net: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
                    prefix: 10,
                },
                DstMatch::SubnetV6 {
                    net: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0),
                    prefix: 16,
                },
                DstMatch::SubnetV6 {
                    net: SERVER_V6,
                    prefix: 128,
                },
            ] {
                assert!(
                    exempts(&plan, dst),
                    "tunnel up: {up}: the blanket cuts {dst:?}"
                );
            }
        }
    }

    /// A dropped connection may teach the guard a client PROCESS, never an
    /// address: a CDN front a rule host shares would become a hole. A rule
    /// host a VPN client dialled through the guard stays blocked.
    #[test]
    fn a_rule_host_a_vpn_client_dialled_stays_blocked_while_the_tunnel_is_down() {
        for policy in [
            Policy::armed(),
            Policy::everything(),
            Policy::prefer_secondary(),
        ] {
            let (plan, coverage) = plan_on_machine(OneSecondaryRule, policy, false, true);
            assert!(
                !exempts(&plan, DstMatch::HostV4(SECONDARY_HOST)),
                "a rule host is never a hole in the guard"
            );
            assert!(blanket_blocks(&plan) > 0 || blocks_on(&plan, SECONDARY_HOST) > 0);
            assert!(coverage.kill_switch_complete);
        }
    }

    /// A "local" segment half the internet wide is left out of the exemptions;
    /// the user is told which link reported it, once per latch window per
    /// segment, through the latch the Windows coordinator shares.
    #[test]
    fn a_too_wide_local_segment_is_reported_once_per_latch_window() {
        use crate::catch_all_exemptions::TOO_WIDE_NOTICE_WINDOW;
        use nrr_platform_api::route_table::RouteTablePort;
        use nrr_shared::ipc_payloads::StatusUpdateEvent;

        let (api, links) = machine(true);
        let mut routes = api.get_ip_forward_table().expect("mock routes");
        routes.push(nrr_platform_api::types::RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 1,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface_index: 2,
            metric: 0,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        });
        api.set_route_table(routes);
        let bus = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let sid = user().as_stored().to_string();
        let sub = bus.subscribe_as("test".to_string(), Some(sid.clone()), None);
        let source = source(
            Arc::new(OneSecondaryRule),
            Arc::new(Policy::prefer_secondary()),
        )
        .with_machine_facts(
            api as Arc<dyn RouteTablePort>,
            links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
        )
        .with_event_bus(Arc::clone(&bus));
        for _ in 0..3 {
            source.begin_pass();
            source
                .plan_with_coverage(&user(), availability(true))
                .expect("the rule must plan");
        }

        let pending = bus.peek_pending_for(&sub.subscription_id, 10);
        assert_eq!(pending.len(), 1, "three passes, one notice: {pending:?}");
        match &pending[0].event {
            StatusUpdateEvent::LocalNetworkTooWide {
                sid: told,
                adapter_name,
                network,
            } => {
                assert_eq!(told, &sid);
                assert_eq!(adapter_name, "eth0");
                assert_eq!(network, "0.0.0.0/1");
            }
            other => panic!("expected LocalNetworkTooWide, got {other:?}"),
        }
        assert!(
            !exempts(
                &source
                    .plan_with_coverage(&user(), availability(true))
                    .expect("the rule must plan")
                    .0,
                DstMatch::SubnetV4 {
                    net: Ipv4Addr::UNSPECIFIED,
                    prefix: 1,
                },
            ),
            "half the internet is not a local network"
        );

        // The latch opens again once its window has passed.
        let segment = nrr_shared::ip_block::IpBlock::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)
            .expect("a /1 is a block");
        let later =
            std::time::Instant::now() + TOO_WIDE_NOTICE_WINDOW + std::time::Duration::from_secs(1);
        assert_eq!(
            source
                .too_wide_notices
                .publish(&bus, &sid, "eth0", &[segment], later),
            1
        );
    }

    const SHARED_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 5);

    /// A first contact gets only its own `/32`s to the additional link,
    /// planned as the pass would plan them, nothing while that link is down,
    /// and nothing before a pass has read the machine: until then a LAN or
    /// another tunnel's address cannot be told from a remote one.
    #[test]
    fn a_first_contact_is_routed_only_for_its_own_addresses_on_a_live_link() {
        let (api, links) = machine(false);
        let source = source(Arc::new(OneSecondaryRule), Arc::new(Policy::armed()))
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            );
        let host = IpAddr::V4(SECONDARY_HOST);
        let stranger = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        assert!(
            source
                .first_contact_routes(&user(), availability(true), &[host])
                .is_empty(),
            "before a pass has read the machine, a first contact waits for it",
        );
        let _ = source.plan_with_coverage(&user(), availability(true));
        let routes = source.first_contact_routes(&user(), availability(true), &[host, stranger]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].dst, DstMatch::HostV4(SECONDARY_HOST));
        assert_eq!(routes[0].egress, EgressRef::Secondary);
        assert!(source
            .first_contact_routes(&user(), availability(true), &[stranger])
            .is_empty());
        assert!(source
            .first_contact_routes(&user(), availability(false), &[host])
            .is_empty());
    }

    /// A book that answers its readability check and then fails, as a store
    /// going away between two reads would.
    struct ReadsOnce(std::sync::atomic::AtomicBool);
    impl RulesProvider for ReadsOnce {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            if self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                None
            } else {
                OneSecondaryRule.active_rules()
            }
        }
    }

    /// The plan is drawn from the read that found the book readable: a second
    /// read failing in between must not plan as "no rules", which would
    /// withdraw what is installed.
    #[test]
    fn a_book_read_once_is_planned_from_that_read() {
        use crate::principal_enforcement::PlanRead;
        let source = source(
            Arc::new(ReadsOnce(Default::default())),
            Arc::new(Policy::armed()),
        );
        match source.plan_read_for(&user(), availability(true)) {
            PlanRead::Planned(planned) => assert!(!planned.plan.flows.is_empty()),
            _ => panic!("a book that read must be planned, not taken for none"),
        }
    }

    /// The v6 twin: a `/128` only for the host's own addresses, only while the
    /// link is up, and only where the last pass found the link carrying IPv6.
    /// A link with no v6 next hop gets none — a `/128` there black-holes the
    /// address instead of leaving it to the block the pass plans.
    #[test]
    fn a_v6_first_contact_is_routed_only_for_its_own_addresses_on_a_live_v6_link() {
        let source_on = |tunnel_v6: bool| {
            let (api, links) = machine(true);
            {
                let mut adapters = links.adapters.lock().unwrap_or_else(|p| p.into_inner());
                adapters[0].ipv6_addresses = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)];
                if tunnel_v6 {
                    adapters[1].ipv6_addresses =
                        vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 5, 0, 0, 0, 1)];
                }
            }
            if tunnel_v6 {
                // A live v6 link has a way out: the client's on-link `::/0`.
                use nrr_platform_api::route_table::RouteTablePort;
                let mut routes = api.get_ip_forward_table().expect("routes");
                routes.push(nrr_platform_api::types::RouteEntry {
                    destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    prefix_length: 0,
                    next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    interface_index: 5,
                    metric: 0,
                    is_ours: false,
                    table: nrr_platform_api::RouteTableRef::Main,
                });
                api.set_route_table(routes);
            }
            let cache = Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default());
            cache.set_addresses(HOST, vec![IpAddr::V6(HOST_V6)]);
            source_with_cache(
                Arc::new(OneSecondaryHostRule),
                Arc::new(Policy::armed()),
                cache,
            )
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
        };
        let host = IpAddr::V6(HOST_V6);
        let stranger = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99));

        let source = source_on(true);
        assert!(
            source
                .first_contact_routes(&user(), availability(true), &[host])
                .is_empty(),
            "the answer path reads no links: before a pass has, v6 waits for it",
        );
        let (plan, _) = source
            .plan_with_coverage(&user(), availability(true))
            .expect("the rule must plan");
        assert!(plan
            .routes
            .iter()
            .any(|r| r.dst == DstMatch::HostV6(HOST_V6)));
        let routes = source.first_contact_routes(&user(), availability(true), &[host, stranger]);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].dst, DstMatch::HostV6(HOST_V6));
        assert_eq!(routes[0].egress, EgressRef::Secondary);
        assert!(source
            .first_contact_routes(&user(), availability(true), &[stranger])
            .is_empty());
        assert!(source
            .first_contact_routes(&user(), availability(false), &[host])
            .is_empty());

        let source = source_on(false);
        let _ = source.plan_with_coverage(&user(), availability(true));
        assert!(
            source
                .first_contact_routes(&user(), availability(true), &[host])
                .is_empty(),
            "a /128 out of a link with no IPv6 attracts traffic it cannot deliver",
        );
    }

    /// Two literal secondary rules; the census has seen `SHARED_HOST` serving
    /// a direct host too.
    struct TwoSecondaryRules;
    impl RulesProvider for TwoSecondaryRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            let route = |id: &str, ip: Ipv4Addr| CanonicalRule {
                id: RuleId(id.into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip))),
                app_match: None,
                comment: String::new(),
                action: RuleAction::Route,
                origin: None,
            };
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(Vec::new()),
                    secondary: CanonicalRuleSet::from_rules(vec![
                        route("s-0", SECONDARY_HOST),
                        route("s-1", SHARED_HOST),
                    ]),
                },
            })
        }
    }

    struct SharedCensus(crate::fqdn_cache_lookup::MockFqdnCacheLookup);
    impl FqdnCacheLookup for SharedCensus {
        fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
            self.0.ips_for_hostname(hostname)
        }
        fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
            self.0.hostnames_under_suffix(suffix, limit)
        }
        fn shared_direct_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
            std::iter::once(SHARED_HOST).collect()
        }
    }

    /// The smart guard spares an address a direct host shares — a block there
    /// cuts that host for every program — and the strict setting pins it
    /// regardless: the trade the Windows guard offers under the same switch.
    #[test]
    fn the_strict_shared_address_setting_changes_what_the_guard_pins_and_blocks() {
        let plan_with = |strict: bool, secondary_up: bool| {
            let status = crate::app_enforcement_status::SharedIpExemptionStatus::new();
            let policy = Policy {
                strict_shared_ips: strict,
                ..Policy::armed()
            };
            let (plan, _) = source_with_cache(
                Arc::new(TwoSecondaryRules),
                Arc::new(policy),
                Arc::new(SharedCensus(Default::default())),
            )
            .with_shared_ip_exemption_status(status.clone())
            .plan_with_coverage(&user(), availability(secondary_up))
            .expect("the rules must plan");
            (plan, status)
        };
        let pinned_via_tunnel = |plan: &EnforcementPlan, ip: Ipv4Addr| {
            plan.flows.iter().any(|f| {
                f.flow.dst == DstMatch::HostV4(ip)
                    && f.egress == EgressConstraint::OnlyVia(EgressRef::Secondary)
            })
        };

        let (smart_down, status) = plan_with(false, false);
        assert!(blocks_on(&smart_down, SECONDARY_HOST) > 0);
        assert_eq!(
            blocks_on(&smart_down, SHARED_HOST),
            0,
            "the shared address is spared"
        );
        assert_eq!(status.addresses(), vec![SHARED_HOST.to_string()]);

        let (strict_down, status) = plan_with(true, false);
        assert!(
            blocks_on(&strict_down, SHARED_HOST) > 0,
            "strict pins it regardless"
        );
        assert_eq!(status.count(), 0);

        let (smart_up, _) = plan_with(false, true);
        assert!(pinned_via_tunnel(&smart_up, SECONDARY_HOST));
        assert!(
            !pinned_via_tunnel(&smart_up, SHARED_HOST),
            "the pin would cut the direct host"
        );

        let (strict_up, _) = plan_with(true, true);
        assert!(pinned_via_tunnel(&strict_up, SHARED_HOST));
    }

    /// Protection of the routed sites alone arms the guard, so a tunnel that
    /// removes its interface on disconnect cannot leave the user leaking over
    /// the primary.
    #[test]
    fn routed_sites_protection_alone_blocks_when_the_secondary_drops() {
        let (plan, coverage) = plan(OneSecondaryRule, Policy::armed(), false);

        assert!(coverage.fail_closed_blocks > 0);
        assert!(blocks_on(&plan, SECONDARY_HOST) > 0);
    }

    /// With no reading of the machine there are no exemptions, so the blanket
    /// block cannot be armed safely. The plan must ADMIT the shortfall — silence
    /// here would read as protection the user does not have — and still hold
    /// the rule hosts.
    #[test]
    fn an_always_on_mode_reports_its_protection_as_incomplete() {
        let (plan, coverage) = plan(OneSecondaryRule, Policy::prefer_secondary(), false);

        assert!(!coverage.kill_switch_complete);
        assert!(blocks_on(&plan, SECONDARY_HOST) > 0);
        assert!(coverage.guard_holding);
    }

    /// The main-connection route with everything protected asks for the same
    /// hold once the tunnel is gone, and without machine facts it is equally
    /// unavailable.
    #[test]
    fn split_mode_protecting_everything_reports_incomplete_too() {
        let (_, coverage) = plan(OneSecondaryRule, Policy::everything(), false);

        assert!(!coverage.kill_switch_complete);
    }

    /// The posture the always-on modes are FOR: with the tunnel up, everything
    /// off it is blocked — and the machine's own escapes stay open, or the block
    /// would be a trap rather than a guard.
    #[test]
    fn a_live_tunnel_in_an_always_on_mode_arms_the_blanket_block() {
        let (plan, coverage) =
            plan_on_machine(OneSecondaryRule, Policy::prefer_secondary(), true, true);

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

    /// The plan of a tunnel-default principal on [`machine`], with the stored
    /// local-network answers laid over its exemptions, and the public prefix
    /// the main link carries besides the LAN.
    fn plan_with_local_answers(
        answers: crate::route_coordinator::LocalNetworkPolicy,
        auto_accept: bool,
    ) -> EnforcementPlan {
        let (api, links) = machine(true);
        let mut routes =
            nrr_platform_api::route_table::RouteTablePort::get_ip_forward_table(api.as_ref())
                .expect("routes");
        routes.push(nrr_platform_api::types::RouteEntry {
            destination: IpAddr::V6(PUBLIC_V6.0),
            prefix_length: PUBLIC_V6.1,
            next_hop: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            interface_index: 2,
            metric: 0,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        });
        api.set_route_table(routes);
        let routes_port: Arc<dyn nrr_platform_api::route_table::RouteTablePort> = api;
        let links_port: Arc<dyn nrr_platform_api::adapters::AdapterEventSource> = links;
        let policy = || Policy {
            auto_accept,
            ..Policy::prefer_secondary()
        };
        let networks = crate::local_network_source::PolicyLocalNetworkSource::new(
            Arc::clone(&routes_port),
            Arc::clone(&links_port),
            Arc::new(policy()),
            Arc::new(OneSecondaryRule),
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default()),
            Arc::new(move |_: &str| answers.clone()),
        );
        source(Arc::new(OneSecondaryRule), Arc::new(policy()))
            .with_machine_facts(routes_port, links_port)
            .with_local_networks(Arc::new(networks))
            .plan_with_coverage(&user(), availability(true))
            .expect("the rule must plan")
            .0
    }

    const PUBLIC_V6: (std::net::Ipv6Addr, u8) = (
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0),
        64,
    );

    fn lan() -> DstMatch {
        DstMatch::SubnetV4 {
            net: Ipv4Addr::new(192, 168, 1, 0),
            prefix: 24,
        }
    }

    fn public_prefix() -> DstMatch {
        DstMatch::SubnetV6 {
            net: PUBLIC_V6.0,
            prefix: PUBLIC_V6.1,
        }
    }

    /// The user said no to the home network: it is blocked with the rest, and
    /// a network they typed in stays reachable.
    #[test]
    fn a_refused_local_network_is_blocked_and_a_typed_one_stays_direct() {
        use crate::route_coordinator::LocalNetworkPolicy;
        let plan = plan_with_local_answers(LocalNetworkPolicy::default(), false);
        assert!(exempts(&plan, lan()), "an unanswered LAN is kept");

        let plan = plan_with_local_answers(
            LocalNetworkPolicy {
                refused: vec![
                    nrr_domain::ipv4_network::Ipv4Network::parse("192.168.1.0/24").expect("net"),
                ],
                allowed: vec![
                    nrr_domain::ipv4_network::Ipv4Network::parse("10.9.0.0/16").expect("net")
                ],
                ..Default::default()
            },
            false,
        );
        assert!(!exempts(&plan, lan()), "a refused network stays blocked");
        assert!(
            exempts(
                &plan,
                DstMatch::SubnetV4 {
                    net: Ipv4Addr::new(10, 9, 0, 0),
                    prefix: 16,
                },
            ),
            "the network the user named is kept direct",
        );
    }

    /// A public IPv6 prefix is the user's to vouch for: closed until they say
    /// yes. Under "everything" auto-accept does not stand in for that answer.
    #[test]
    fn a_public_v6_prefix_opens_only_on_the_users_answer_under_everything() {
        use crate::route_coordinator::LocalNetworkPolicy;
        let block = nrr_shared::ip_block::IpBlock::new(IpAddr::V6(PUBLIC_V6.0), PUBLIC_V6.1)
            .expect("block");
        assert!(!exempts(
            &plan_with_local_answers(LocalNetworkPolicy::default(), false),
            public_prefix()
        ));
        let yes = LocalNetworkPolicy {
            answers_v6: vec![(block, true)],
            ..Default::default()
        };
        assert!(exempts(
            &plan_with_local_answers(yes, false),
            public_prefix()
        ));
        let no = LocalNetworkPolicy {
            answers_v6: vec![(block, false)],
            ..Default::default()
        };
        assert!(!exempts(
            &plan_with_local_answers(no, true),
            public_prefix()
        ));
        assert!(
            !exempts(
                &plan_with_local_answers(LocalNetworkPolicy::default(), true),
                public_prefix()
            ),
            "a silent answer would be a silent exemption"
        );
    }

    /// The refusal that keeps an outage from becoming permanent: without the
    /// server's address the blanket block would seal the tunnel's own reconnect,
    /// so it is not armed and the shortfall is reported. The rule hosts stay
    /// pinned to the live tunnel rather than blocked outright: a block there
    /// would cut them through a working tunnel.
    #[test]
    fn without_a_server_route_the_blanket_block_is_refused() {
        let (plan, coverage) =
            plan_on_machine(OneSecondaryRule, Policy::prefer_secondary(), true, false);

        assert_eq!(blanket_blocks(&plan), 0);
        assert!(!coverage.kill_switch_complete);
        assert_eq!(held(&plan), Held::Pins);
    }

    /// A memory that already holds `servers` and writes nowhere.
    fn remembering(servers: Vec<Ipv4Addr>) -> Arc<TunnelServerMemory> {
        Arc::new(TunnelServerMemory::new(
            Arc::new(|_: &str, _: &[Ipv4Addr]| {}),
            Arc::new(move |_: &str| servers.clone()),
        ))
    }

    /// The server route is gone while the tunnel reconnects, but the server
    /// was seen before: the block arms with its hole, as on the platform
    /// whose coordinator keeps the same memory.
    #[test]
    fn a_remembered_server_lets_the_blanket_block_arm_without_its_route() {
        let (api, links) = machine(false);
        let (plan, coverage) = source(
            Arc::new(OneSecondaryRule),
            Arc::new(Policy::prefer_secondary()),
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

    /// A policy store that answers nothing, for the reason given.
    struct NothingBecause(Option<&'static str>);
    impl RoutePolicySource for NothingBecause {
        fn load_for_sid(&self, _sid: &str) -> Option<PerSidPolicySnapshot> {
            None
        }
        fn read_failure_for(&self, _sid: &str) -> Option<String> {
            self.0.map(str::to_owned)
        }
    }

    /// "No policy" removes what is installed; "the policy did not read" keeps it.
    #[test]
    fn a_policy_that_did_not_read_is_not_a_policy_that_is_absent() {
        use crate::principal_enforcement::PlanRead;
        let read = |reason: Option<&'static str>| {
            source(Arc::new(OneSecondaryRule), Arc::new(NothingBecause(reason)))
                .plan_read_for(&user(), availability(true))
        };
        assert!(matches!(
            read(None),
            PlanRead::NoPolicy | PlanRead::Planned(_)
        ));
        assert!(matches!(
            read(Some("disk I/O error")),
            PlanRead::Unreadable(reason) if reason == "disk I/O error"
        ));
    }

    /// The plan carried over a failed policy read still pins what it pinned:
    /// the failed read must not tell the DNS path that nothing does.
    #[test]
    fn a_policy_that_did_not_read_leaves_the_ipv6_board_as_the_carried_plan_set_it() {
        use crate::enforcement_planner::Ipv6Guard;
        use crate::principal_enforcement::PlanRead;
        // Its own principal: the board is process-wide.
        let principal = UserPrincipal::from_linux_uid(4243);
        let board = crate::ipv6_disposition::global_ipv6_dispositions();
        board.set(principal.as_stored(), Ipv6Guard::FiltersOnly);

        let read = source(
            Arc::new(OneSecondaryRule),
            Arc::new(NothingBecause(Some("database is locked"))),
        )
        .plan_read_for(&principal, availability(true));

        assert!(matches!(read, PlanRead::Unreadable(_)));
        assert_eq!(
            board.of(principal.as_stored()),
            Some(Ipv6Guard::FiltersOnly)
        );
    }

    fn bob() -> UserPrincipal {
        UserPrincipal::from_linux_uid(1001)
    }

    /// A tunnel server one user's links showed is that user's alone: another
    /// user's blanket block must not arm on a hole their tunnel never had.
    #[test]
    fn a_server_remembered_for_one_user_does_not_arm_another_users_block() {
        let alice = user();
        let remembered_for = alice.as_stored().to_owned();
        let memory = Arc::new(TunnelServerMemory::new(
            Arc::new(|_: &str, _: &[Ipv4Addr]| {}),
            Arc::new(move |sid: &str| {
                if sid == remembered_for {
                    vec![SERVER]
                } else {
                    Vec::new()
                }
            }),
        ));
        let plan_for = |principal: &UserPrincipal| {
            let (api, links) = machine(false);
            source(
                Arc::new(OneSecondaryRule),
                Arc::new(Policy::prefer_secondary()),
            )
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
            .with_tunnel_servers(Arc::clone(&memory), None)
            .plan_with_coverage(principal, availability(true))
            .expect("the rule must plan")
        };

        let (own, own_coverage) = plan_for(&alice);
        assert!(blanket_blocks(&own) > 0);
        assert!(exempts(&own, DstMatch::HostV4(SERVER)));
        assert!(own_coverage.kill_switch_complete);

        let (other, other_coverage) = plan_for(&bob());
        assert_eq!(blanket_blocks(&other), 0, "armed on another user's server");
        assert!(!exempts(&other, DstMatch::HostV4(SERVER)));
        assert!(!other_coverage.kill_switch_complete);
    }

    fn service_account_flows_of(plan: &EnforcementPlan) -> usize {
        use nrr_platform_api::enforcement::PrincipalScope;
        plan.flows
            .iter()
            .filter(|f| {
                matches!(
                    f.principal,
                    PrincipalScope::ServiceAccounts | PrincipalScope::Forwarded
                )
            })
            .count()
    }

    /// Lowering keeps only the route-table owner's service-account rules, so
    /// the others' are not built at all.
    #[test]
    fn only_the_route_table_owners_plan_carries_service_account_rules() {
        let plan_told = |told: Option<Option<UserPrincipal>>| {
            let source = source(Arc::new(OneSecondaryRule), Arc::new(Policy::armed()))
                .with_service_accounts(Arc::new(Vec::new));
            source.begin_pass();
            if let Some(owner) = told {
                source.set_route_table_owner(owner.as_ref());
            }
            source
                .plan_with_coverage(&user(), availability(true))
                .expect("the rule must plan")
                .0
        };

        let as_owner = plan_told(Some(Some(user())));
        assert!(
            service_account_flows_of(&as_owner) > 0,
            "fixture guard: the owner's guard speaks for the service accounts"
        );
        assert_eq!(
            service_account_flows_of(&plan_told(None)),
            service_account_flows_of(&as_owner)
        );
        assert_eq!(service_account_flows_of(&plan_told(Some(Some(bob())))), 0);
        assert_eq!(service_account_flows_of(&plan_told(Some(None))), 0);
    }

    /// What the machine forwards for containers and guests is held with the
    /// owner's own traffic once the tunnel is gone, and left alone when the
    /// user answered "do not protect".
    #[test]
    fn forwarded_traffic_is_held_with_the_owner_unless_left_unprotected() {
        use nrr_platform_api::enforcement::PrincipalScope;
        let forwarded_blocks = |policy: Policy| -> Vec<FlowRule> {
            let (api, links) = machine(true);
            let (plan, _) = source(Arc::new(OneSecondaryRule), Arc::new(policy))
                .with_machine_facts(
                    api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                    links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
                )
                .with_service_accounts(Arc::new(Vec::new))
                .plan_with_coverage(&user(), availability(false))
                .expect("the rule must plan");
            plan.flows
                .into_iter()
                .filter(|f| f.principal == PrincipalScope::Forwarded && f.verdict == Verdict::Block)
                .collect()
        };

        let sites = forwarded_blocks(Policy::armed());
        assert!(
            sites
                .iter()
                .any(|f| f.flow.dst == DstMatch::HostV4(SECONDARY_HOST)),
            "a container reaches the routed site over the main link: {sites:?}"
        );
        let everything = forwarded_blocks(Policy::everything());
        assert!(
            everything
                .iter()
                .any(|f| f.precedence.class == PrecedenceClass::CatchAllBlock),
            "a container keeps the internet the owner lost: {everything:?}"
        );

        for policy in [Policy::armed(), Policy::everything()] {
            let unprotected = forwarded_blocks(Policy {
                guard_forwarded: false,
                ..policy
            });
            assert!(unprotected.is_empty(), "{unprotected:?}");
        }
    }

    struct MessengerRule;
    impl RulesProvider for MessengerRule {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(Vec::new()),
                    secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                        id: RuleId("s-app".into()),
                        enabled: true,
                        address_match: None,
                        app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                            pattern: nrr_domain::canonical::CanonicalAppPattern::Exact(
                                "messenger.exe".into(),
                            ),
                            include_child_processes: false,
                            override_requested: false,
                        }),
                        comment: String::new(),
                        action: RuleAction::Route,
                        origin: None,
                    }]),
                },
            })
        }
    }

    /// Where programs are observed per user, a user's application rule routes
    /// the addresses their own programs used and nobody else's: the routes,
    /// like the filters, read the user's own store.
    #[test]
    fn an_application_rule_routes_what_the_users_own_programs_used() {
        use crate::app_observation_lookup::AppObservationStore;
        let (alice_ip, bob_ip) = (
            Ipv4Addr::new(198, 51, 100, 9),
            Ipv4Addr::new(198, 51, 100, 10),
        );
        let store = Arc::new(AppObservationStore::per_principal());
        for (principal, ip) in [(user(), alice_ip), (bob(), bob_ip)] {
            let own = store
                .scope_for(Some(principal.as_stored()))
                .expect("own store");
            assert!(own.record("messenger.exe", ip));
        }
        let source = ProductionPrincipalPlanSource::new(
            Arc::new(MessengerRule),
            Arc::new(Policy::armed()),
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default()),
            Arc::new(nrr_platform_api::app_path_resolver::NoopAppPathResolver),
            store,
        );
        let routed = |principal: &UserPrincipal| -> Vec<Ipv4Addr> {
            let (plan, _) = source
                .plan_with_coverage(principal, availability(true))
                .expect("the rule must plan");
            plan.routes
                .iter()
                .filter_map(|r| match r.dst {
                    DstMatch::HostV4(ip) => Some(ip),
                    _ => None,
                })
                .collect()
        };

        let alices = routed(&user());
        assert!(
            alices.contains(&alice_ip),
            "own destination routed: {alices:?}"
        );
        assert!(
            !alices.contains(&bob_ip),
            "another user's destination: {alices:?}"
        );
        let bobs = routed(&bob());
        assert!(bobs.contains(&bob_ip), "own destination routed: {bobs:?}");
        assert!(
            !bobs.contains(&alice_ip),
            "another user's destination: {bobs:?}"
        );
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
                Arc::new(OneSecondaryRule),
                Arc::new(Policy::prefer_secondary()),
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

    /// A user's own table holds a primary exception: a host route via the
    /// main gateway, a server's shape. Every route in that table is ours, so
    /// it is never taken for the tunnel server.
    #[test]
    fn a_host_route_in_a_per_user_table_is_never_a_tunnel_server() {
        use nrr_platform_api::route_table::RouteTablePort;
        let ours = Ipv4Addr::new(198, 51, 100, 78);
        let users_table = nrr_platform_api::RouteTableRef::Tagged(0x8000_03E8);
        let plan_with = |own: Option<OwnTablesFn>| {
            let (api, links) = machine(false);
            let mut table = api.get_ip_forward_table().expect("mock table");
            table.push(nrr_platform_api::types::RouteEntry {
                destination: IpAddr::V4(ours),
                prefix_length: 32,
                next_hop: IpAddr::V4(GATEWAY),
                interface_index: 2,
                metric: 0,
                is_ours: false,
                table: users_table.clone(),
            });
            api.set_route_table(table);
            let source = source(
                Arc::new(OneSecondaryRule),
                Arc::new(Policy::prefer_secondary()),
            )
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            );
            let source = match own {
                Some(own) => source.with_own_route_tables(own),
                None => source,
            };
            source
                .plan_with_coverage(&user(), availability(true))
                .expect("the rule must plan")
        };

        let own: OwnTablesFn = {
            let users_table = users_table.clone();
            Arc::new(move |t: &nrr_platform_api::RouteTableRef| *t == users_table)
        };
        let (plan, _) = plan_with(Some(own));
        assert!(!exempts(&plan, DstMatch::HostV4(ours)));

        // Positive control: the same row in a table not ours is a server.
        let (plan, _) = plan_with(None);
        assert!(exempts(&plan, DstMatch::HostV4(ours)));
    }

    /// WireGuard and AmneziaWG take their link down with them. The LAN is read
    /// off the primary, so a remembered server arms the hold with both holes.
    #[test]
    fn a_remembered_server_arms_the_hold_after_the_tunnel_link_is_gone() {
        let (api, links) = machine(false);
        links
            .adapters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|a| a.friendly_name != "tun0");
        let (plan, coverage) = source(
            Arc::new(OneSecondaryRule),
            Arc::new(Policy::prefer_secondary()),
        )
        .with_machine_facts(
            api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
            links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
        )
        .with_tunnel_servers(remembering(vec![SERVER]), None)
        .plan_with_coverage(&user(), availability(false))
        .expect("the rule must plan");

        assert!(blanket_blocks(&plan) > 0);
        assert!(exempts(&plan, DstMatch::HostV4(SERVER)));
        assert!(exempts(
            &plan,
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(192, 168, 1, 0),
                prefix: 24
            }
        ));
        assert!(coverage.kill_switch_complete);
    }

    /// Without the primary the attached subnets cannot be read, and a
    /// remembered server must not arm a block that would cut the LAN.
    #[test]
    fn a_remembered_server_alone_does_not_arm_without_the_primary() {
        let (api, links) = machine(false);
        links
            .adapters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|a| a.friendly_name != "eth0");
        let (plan, coverage) = source(
            Arc::new(OneSecondaryRule),
            Arc::new(Policy::prefer_secondary()),
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

    /// A policy-based IPsec VPN keeps its private networks wherever the main
    /// link is blanket-blocked, and nothing is spared where nothing cuts them.
    #[test]
    fn ipsec_protected_networks_are_spared_only_under_the_blanket_block() {
        let spared = |plan: &EnforcementPlan| -> Vec<FlowRule> {
            plan.flows
                .iter()
                .filter(|f| f.egress == EgressConstraint::UnderIpsecPolicy)
                .cloned()
                .collect()
        };
        for (policy, up) in [
            (Policy::prefer_secondary(), true),
            (Policy::everything(), false),
        ] {
            let (plan, _) = plan_on_machine(OneSecondaryRule, policy, up, true);
            assert!(blanket_blocks(&plan) > 0, "fixture: the blanket is armed");
            let spared = spared(&plan);
            assert!(!spared.is_empty(), "the IPsec networks are cut");
            for flow in &spared {
                assert_eq!(flow.verdict, Verdict::Permit);
                assert_eq!(flow.precedence.class, PrecedenceClass::CatchAllExempt);
                assert_eq!(
                    flow.principal,
                    nrr_platform_api::enforcement::PrincipalScope::User(user())
                );
                assert!(
                    !matches!(flow.flow.dst, DstMatch::Any),
                    "never to any destination"
                );
            }
        }
        for (policy, up) in [
            (Policy::armed(), true),
            (Policy::armed(), false),
            (Policy::disarmed(), true),
            (Policy::disarmed(), false),
        ] {
            let (plan, _) = plan_on_machine(OneSecondaryRule, policy, up, true);
            assert!(spared(&plan).is_empty(), "{:?}", spared(&plan));
        }
    }

    /// Tunnel gone, everything protected: the traffic is held rather than let
    /// out the way the user asked it not to go — and the per-destination guard
    /// is NOT added on top, because one policy stated twice is two things to
    /// keep in agreement.
    #[test]
    fn a_lost_tunnel_under_everything_holds_everything_and_does_not_double_up() {
        let (plan, coverage) = plan_on_machine(OneSecondaryRule, Policy::everything(), false, true);

        assert!(blanket_blocks(&plan) > 0);
        assert!(exempts(&plan, DstMatch::HostV4(SERVER)));
        assert_eq!(
            coverage.fail_closed_blocks, 0,
            "the per-IP guard duplicated the block-all"
        );
        assert!(
            coverage.guard_holding,
            "no block counted, but the guard holds"
        );
        assert!(coverage.kill_switch_complete);
        assert!(
            !plan.flows.iter().any(|f| f.verdict == Verdict::Permit
                && f.precedence.class == PrecedenceClass::RouteRule(RouteRole::Secondary)),
            "a secondary permit outranks the hold and lets its sites out the main link"
        );
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

        let (plan, _) = source(Arc::new(OneSecondaryRule), Arc::new(Policy::armed()))
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
                &Spared {
                    floor: source.exemptions_for(user().as_stored(), &armed()),
                    ..Spared::default()
                },
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

        /// With the tunnel gone and everything held, a container still reaches
        /// a network the main link's rules route, but neither a tunnel-bound
        /// address inside it nor the rest of the internet.
        #[test]
        fn the_forwarded_blanket_keeps_main_link_networks_open() {
            use nrr_platform_api::enforcement::PrincipalScope;
            const INSIDE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
            let book = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![route(
                    "p-24",
                    subnet("203.0.113.0/24"),
                )]),
                secondary: CanonicalRuleSet::from_rules(vec![route(
                    "s-host",
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(INSIDE)),
                )]),
            };
            let (api, links) = machine(true);
            let (plan, _) = source(Arc::new(Book(book)), Arc::new(Policy::everything()))
                .with_machine_facts(
                    api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                    links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
                )
                .with_service_accounts(Arc::new(Vec::new))
                .plan_with_coverage(&user(), availability(false))
                .expect("the rules must plan");
            let forwarded: Vec<FlowRule> = plan
                .flows
                .into_iter()
                .filter(|f| f.principal == PrincipalScope::Forwarded)
                .collect();
            // The blanket matches any destination, so it is judged here too.
            let judged = |ip: Ipv4Addr| {
                forwarded
                    .iter()
                    .filter(|f| {
                        f.coverage == Coverage::ConnectOnly
                            && (f.flow.dst == DstMatch::Any
                                || dst_block(f.flow.dst)
                                    .is_some_and(|b| b.contains(IpAddr::V4(ip))))
                    })
                    .reduce(|best, flow| {
                        if flow.precedence.is_higher_priority_than(best.precedence) {
                            flow
                        } else {
                            best
                        }
                    })
                    .map(|flow| flow.verdict)
            };
            assert_eq!(
                judged(Ipv4Addr::new(203, 0, 113, 50)),
                Some(Verdict::Permit),
                "{forwarded:?}"
            );
            assert_eq!(judged(INSIDE), Some(Verdict::Block), "{forwarded:?}");
            assert_eq!(
                judged(Ipv4Addr::new(192, 0, 2, 80)),
                Some(Verdict::Block),
                "{forwarded:?}"
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
            let read = source.exemptions_for("", &armed());
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

        /// "Everything", tunnel gone: the blanket sits below the main-link
        /// band, so nothing of the main link may cover the tunnel's network.
        /// A main-link program's observed address inside it and a wider
        /// main-link network around it both leave it to the blanket.
        #[test]
        fn a_main_link_program_does_not_reach_a_tunnel_network_while_the_tunnel_is_down() {
            use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern};
            const MAIL: &str = "mail";
            let inside = Ipv4Addr::new(198, 51, 100, 9);
            let own = Ipv4Addr::new(192, 0, 2, 50);
            let wide_main = Ipv4Addr::new(198, 51, 7, 7);
            let program = CanonicalRule {
                address_match: None,
                app_match: Some(CanonicalAppMatch {
                    pattern: CanonicalAppPattern::Exact(MAIL.into()),
                    include_child_processes: false,
                    override_requested: false,
                }),
                ..route("p-app", subnet("192.0.2.0/24"))
            };
            let book = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![
                    program,
                    route("p-16", subnet("198.51.0.0/16")),
                ]),
                secondary: CanonicalRuleSet::from_rules(vec![route(
                    "s-24",
                    subnet("198.51.100.0/24"),
                )]),
            };
            let apps = Arc::new(crate::app_observation_lookup::MockAppObservationLookup::default());
            apps.set_ips(MAIL, vec![inside, own]);
            let (api, links) = machine(true);
            let source = ProductionPrincipalPlanSource::new(
                Arc::new(Book(book)),
                Arc::new(Policy::everything()),
                Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default()),
                Arc::new(nrr_platform_api::app_path_resolver::NoopAppPathResolver),
                apps,
            )
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            );
            let (plan, _) = source
                .plan_with_coverage(&user(), availability(false))
                .expect("the rules must plan");

            assert!(
                blanket_blocks(&plan) > 0,
                "fixture guard: the blanket is armed"
            );
            assert_eq!(
                top(&plan.flows, own).map(|f| f.verdict),
                Some(Verdict::Permit),
                "fixture guard: the program's own address passes"
            );
            assert_eq!(
                top(&plan.flows, wide_main).map(|f| f.verdict),
                Some(Verdict::Permit),
                "the wider main-link network keeps the rest of itself"
            );
            assert!(
                top(&plan.flows, inside).is_none_or(|f| f.verdict == Verdict::Block),
                "a main-link pass covers the tunnel's network: {:?}",
                top(&plan.flows, inside)
            );
        }

        /// A name of the tunnel's rules resolving onto the main link's own
        /// segment (split horizon, a home NAS) keeps its direct route, so the
        /// guard neither pins nor blocks it; a host elsewhere stays guarded.
        #[test]
        fn a_rule_host_on_the_home_network_is_neither_pinned_nor_blocked() {
            let nas = Ipv4Addr::new(192, 168, 1, 5);
            let book = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(Vec::new()),
                secondary: CanonicalRuleSet::from_rules(vec![
                    route(
                        "s-nas",
                        CanonicalAddressMatch::ExactFqdn("nas.home.example".into()),
                    ),
                    route(
                        "s-host",
                        CanonicalAddressMatch::ExactIp(IpAddr::V4(SECONDARY_HOST)),
                    ),
                ]),
            };
            let cache = Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default());
            cache.set_ips("nas.home.example", vec![nas]);
            for up in [true, false] {
                let (api, links) = machine(true);
                let (plan, _) = source_with_cache(
                    Arc::new(Book(book.clone())),
                    Arc::new(Policy::armed()),
                    Arc::clone(&cache) as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
                )
                .with_machine_facts(
                    api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                    links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
                )
                .plan_with_coverage(&user(), availability(up))
                .expect("the rules must plan");

                let guarded = |ip: Ipv4Addr| {
                    plan.flows.iter().any(|f| {
                        f.flow.dst == DstMatch::HostV4(ip)
                            && (f.verdict == Verdict::Block || f.egress == PINNED)
                    })
                };
                assert!(guarded(SECONDARY_HOST), "tunnel up: {up}: fixture guard");
                assert!(!guarded(nas), "tunnel up: {up}: the NAS is cut");
                assert!(
                    !plan.routes.iter().any(|r| r.dst == DstMatch::HostV4(nas)
                        && r.egress == nrr_platform_api::enforcement::EgressRef::Secondary),
                    "tunnel up: {up}: the NAS is routed into the tunnel"
                );
            }
        }

        /// A name of the tunnel's rules resolving to the tunnel's own server is
        /// neither pinned nor routed into the tunnel: either one seals the
        /// tunnel's reconnect.
        #[test]
        fn a_rule_host_on_the_tunnels_server_is_neither_pinned_nor_routed_into_it() {
            let book = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(Vec::new()),
                secondary: CanonicalRuleSet::from_rules(vec![
                    route(
                        "s-zone-host",
                        CanonicalAddressMatch::ExactFqdn("vpn.attacker.example".into()),
                    ),
                    route(
                        "s-host",
                        CanonicalAddressMatch::ExactIp(IpAddr::V4(SECONDARY_HOST)),
                    ),
                ]),
            };
            let cache = Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default());
            cache.set_ips("vpn.attacker.example", vec![SERVER]);
            let (api, links) = machine(true);
            let (plan, _) = source_with_cache(
                Arc::new(Book(book)),
                Arc::new(Policy::armed()),
                Arc::clone(&cache) as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
            )
            .with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
            .plan_with_coverage(&user(), availability(true))
            .expect("the rules must plan");
            let pinned = |ip: Ipv4Addr| {
                plan.flows.iter().any(|f| {
                    f.flow.dst == DstMatch::HostV4(ip)
                        && f.egress == EgressConstraint::OnlyVia(EgressRef::Secondary)
                })
            };
            assert!(pinned(SECONDARY_HOST), "fixture guard: the guard pins");
            assert!(!pinned(SERVER), "the tunnel's server is held to the tunnel");
            assert!(
                !plan.routes.iter().any(|r| r.dst == DstMatch::HostV4(SERVER)
                    && r.egress == nrr_platform_api::enforcement::EgressRef::Secondary),
                "the tunnel's server is routed into the tunnel"
            );
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
                "principal",
                &policy(),
                mode,
                book,
                true,
                source.fqdn_cache.as_ref(),
                source.app_observations.as_ref(),
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

        /// A corporate WireGuard link beside the bound ones, carrying a
        /// `/24` of its own.
        fn machine_with_corporate_tunnel() -> ProductionPrincipalPlanSource {
            use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
            let (api, links) = machine_parts(true);
            let corporate = AdapterInfo {
                index: 9,
                adapter_name: "corp0".to_owned(),
                description: "WireGuard Tunnel".to_owned(),
                friendly_name: "corp0".to_owned(),
                mac: None,
                interface_type: InterfaceType::Ethernet,
                oper_status: IfOperStatus::Up,
                ipv4_addresses: vec![Ipv4Addr::new(172, 31, 0, 2)],
                ipv6_addresses: Vec::new(),
                gateways: Vec::new(),
            };
            let mut adapters = links.adapters.lock().unwrap_or_else(|p| p.into_inner());
            adapters.push(corporate);
            api.set_adapter_infos(adapters.clone());
            drop(adapters);
            let mut table =
                nrr_platform_api::route_table::RouteTablePort::get_ip_forward_table(api.as_ref())
                    .expect("table");
            table.push(nrr_platform_api::types::RouteEntry {
                destination: IpAddr::V4(Ipv4Addr::new(172, 31, 0, 0)),
                prefix_length: 24,
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                interface_index: 9,
                metric: 0,
                is_ours: false,
                table: nrr_platform_api::RouteTableRef::Main,
            });
            api.set_route_table(table);
            source(Arc::new(NoRules), Arc::new(Policy::armed())).with_machine_facts(
                api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                links as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            )
        }

        #[test]
        fn a_pass_publishes_the_corporate_tunnel_and_the_users_own_link_once() {
            let source = machine_with_corporate_tunnel();
            let cell = crate::foreign_tunnels::ForeignTunnelCell::new();
            source.begin_pass();
            source.note_pass_links("principal", &policy());
            source.note_pass_links("other", &policy());
            source.publish_pass_links(&cell);
            assert_eq!(cell.interfaces(), Some(vec![9]));
            assert_eq!(cell.own_links(), vec![5], "the bound tunnel is ours");
            assert!(cell.carries(Ipv4Addr::new(172, 31, 0, 8)));
        }

        #[test]
        fn a_pass_that_planned_nobody_leaves_the_cell_as_it_was() {
            let source = machine_with_corporate_tunnel();
            let cell = crate::foreign_tunnels::ForeignTunnelCell::new();
            source.begin_pass();
            source.publish_pass_links(&cell);
            assert_eq!(cell.interfaces(), None);
        }

        #[test]
        fn the_facts_come_from_the_pass_reading() {
            let source = on_machine();
            let facts = source.network_route_facts("principal", &policy(), &[]);
            assert_eq!(
                facts.local_networks,
                vec![net("10.8.0.0/24"), net("10.20.1.0/24")]
            );
            assert_eq!(facts.tunnel_servers, vec![IpAddr::V4(TUNNEL_SERVER)]);
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
            source.remember_tunnel_servers("principal", &policy());
            assert_eq!(memory.remembered("principal"), vec![peer]);
            let facts = source.network_route_facts("principal", &policy(), &[]);
            assert_eq!(facts.tunnel_servers, vec![IpAddr::V4(peer)]);
        }

        /// The whole path through the one store: a pass sees the server live,
        /// the tunnel drops, and the submission screen still refuses a subnet
        /// over it while the route plan still spares it.
        #[test]
        fn a_server_seen_live_is_refused_and_spared_after_the_tunnel_drops() {
            use crate::network_rule_screen::{facts_with_remembered_servers, screen_network};
            use crate::production_mutation_executor::NetworkRuleConflict;
            use crate::tunnel_server_memory::persisted_servers_by_principal;
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
                .remember_tunnel_servers("principal", &policy());

            let (down_api, _) = machine_parts(false);
            let screen = facts_with_remembered_servers(
                down_api as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                persisted_servers_by_principal(Arc::clone(&state)),
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
                Arc::new(|_: &str| Vec::<Ipv4Addr>::new()),
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
