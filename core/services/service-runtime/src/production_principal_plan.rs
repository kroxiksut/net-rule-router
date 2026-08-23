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
    ChannelAvailability, DstMatch, EgressBinding, EgressBindingSource, EnforcementPlan, FlowRule,
    PrecedenceClass, UserPrincipal as PlanPrincipal, Verdict,
};
use nrr_shared::RouteRole;

use crate::catch_all_exemptions::{collect_exemptions, CatchAllExemptions};
use crate::enforcement_planner::{
    plan_catch_all_kill_switch, plan_fail_closed_block_all, plan_fail_closed_destinations,
};
use crate::killswitch_codegen::KillSwitchProtocols;
use crate::per_sid_orchestrator::PerSidPolicySnapshot;

use crate::app_observation_lookup::AppObservationLookup;
use crate::enforcement_planner::{plan_route_rules, plan_routes, PlannerInput};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::per_sid_orchestrator::{RoutePolicySource, RulesProvider};
use crate::principal_enforcement::{PlannedPolicy, PrincipalPlanSource};

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

struct MachineReading {
    routes: Vec<nrr_platform_api::types::RouteEntry>,
    adapters: Vec<nrr_platform_api::adapters::AdapterInfo>,
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
        }
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
                    error = %e,
                    "links unreadable: the blanket block cannot be armed this pass",
                );
            })
            .ok()?;
        let reading = Arc::new(MachineReading { routes, adapters });
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
        // No stored routing policy means the user never bound their adapters,
        // and a plan built without that would pin nothing.
        let policy = self.policy.load_for_sid(stored)?;
        let rules = self.rules.active_rules_for(stored)?;

        let input = PlannerInput {
            fqdn_cache: self.fqdn_cache.as_ref(),
            app_resolver: self.app_resolver.as_ref(),
            app_observations: self.app_observations.as_ref(),
        };
        let mut flows = plan_route_rules(&rules.rule_book, stored, rules.behavior_mode, &input);
        if flows.is_empty() {
            return None;
        }
        let rule_driven_flows = flows.len();

        // The blanket block, when the settings ask for it AND the machine can
        // say what it must not cut. It supersedes the per-destination guard:
        // both installed would be one policy stated twice.
        let blanket =
            self.blanket_block(stored, &policy, rules.behavior_mode, availability, &flows);
        let block_all_armed = !blanket.is_empty();
        flows.extend(blanket);

        // The leak-guard, armed only while the link it guards against is gone.
        // While the secondary is up, every secondary rule is already a pinned
        // pair — permit over that link, block the same destination anywhere
        // else — so the guard would be adding rules that change nothing.
        let fail_closed = if availability.secondary || block_all_armed {
            Vec::new()
        } else {
            self.fail_closed_flows(stored, &policy, &flows)
        };
        let fail_closed_blocks = fail_closed.len();
        flows.extend(fail_closed);

        // Routes are planned even while the secondary is down: the applier
        // resolves the link at apply time and reports the ones it cannot steer,
        // which keeps "no route installed" a stated fact rather than a silent
        // omission in the plan.
        let routes = plan_routes(
            rules.behavior_mode,
            &rules.rule_book,
            availability.primary,
            self.fqdn_cache.as_ref(),
            // No shared-IP census on this path yet, so nothing is declined. An
            // empty denylist is the permissive answer, and the census exists to
            // TAKE addresses away — its absence cannot invent a block.
            &std::collections::HashSet::new(),
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
    ) -> Vec<FlowRule> {
        if !wants_block_all(policy, mode) {
            return Vec::new();
        }
        let exemptions = self.exemptions_for(policy);
        if !exemptions.can_arm() {
            tracing::warn!(
                target: "nrr::enforcement",
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
                &primary_destinations(rule_flows),
                &[],
                policy.allow_dns_over_primary,
                protocols,
            )
        }
    }

    /// What this principal's blanket block must not cut, from the pass's reading
    /// of the machine.
    fn exemptions_for(&self, policy: &PerSidPolicySnapshot) -> CatchAllExemptions {
        let Some(reading) = self.machine_reading() else {
            return CatchAllExemptions::default();
        };
        collect_exemptions(
            &reading.routes,
            &reading.adapters,
            policy.primary.as_ref().map(|b| b.display_name.as_str()),
            policy.secondary.as_ref().map(|b| b.display_name.as_str()),
        )
    }

    /// The per-destination blocks that arm while the secondary is unreachable.
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
    ) -> Vec<FlowRule> {
        if !policy.kill_switch_enabled
            || !policy.block_secondary_when_unavailable
            || !policy.kill_switch_fail_closed
        {
            return Vec::new();
        }
        let protected = secondary_destinations(rule_flows);
        if protected.is_empty() {
            return Vec::new();
        }
        plan_fail_closed_destinations(
            stored,
            &protected,
            KillSwitchProtocols::from_bits(policy.kill_switch_protocols),
        )
    }
}

/// The addresses the PRIMARY rules route. Under a blanket block they keep their
/// packet-layer reachability, so a host the user positively sent over the main
/// link does not lose ping along with the traffic the block is aimed at.
fn primary_destinations(flows: &[FlowRule]) -> Vec<std::net::Ipv4Addr> {
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
            // and rescuing it here would be the leak the guard exists for.
            if !secondary.contains(&ip) {
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
fn secondary_destinations(flows: &[FlowRule]) -> Vec<std::net::Ipv4Addr> {
    let mut seen = std::collections::BTreeSet::new();
    for flow in flows {
        if flow.verdict != Verdict::Permit
            || flow.precedence.class != PrecedenceClass::RouteRule(RouteRole::Secondary)
        {
            continue;
        }
        if let DstMatch::HostV4(ip) = flow.flow.dst {
            seen.insert(ip);
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
/// Its own connection, matching the storage-layer pragmas, so a read here never
/// races the writer that owns the store.
pub fn open_state_connection(path: &std::path::Path) -> Option<Arc<Mutex<rusqlite::Connection>>> {
    if !path.exists() {
        return None;
    }
    match rusqlite::Connection::open(path) {
        Ok(conn) => {
            let _: rusqlite::Result<()> =
                conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
            Some(Arc::new(Mutex::new(conn)))
        }
        Err(e) => {
            tracing::error!(
                target: "nrr::enforcement",
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
    use std::net::Ipv4Addr;

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
                        address_match: Some(CanonicalAddressMatch::ExactIp(SECONDARY_HOST)),
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
    }

    impl Policy {
        fn armed() -> Self {
            Self {
                enabled: true,
                block_when_unavailable: true,
                fail_closed: true,
                block_all: false,
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
                doh_lockdown_enabled: false,
                doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
                doh_resolver_ips: Vec::new(),
                auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
                primary_probe_auto: false,
                primary_probe_timeout_ms: 1500,
                primary_probe_max_targets: 8,
                primary_probe_repeat_secs: 300,
                block_ipv6_when_protected: false,
            })
        }
    }

    fn source(
        rules: Arc<dyn RulesProvider>,
        policy: Arc<dyn RoutePolicySource>,
    ) -> ProductionPrincipalPlanSource {
        ProductionPrincipalPlanSource::new(
            rules,
            policy,
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::default()),
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
            gateways,
        };
        let links = Arc::new(nrr_platform_api::adapters::MockAdapterEventSource::new());
        *links.adapters.lock().unwrap_or_else(|p| p.into_inner()) =
            vec![link(2, "eth0", vec![GATEWAY]), link(5, "tun0", Vec::new())];

        let route =
            |dst: Ipv4Addr, prefix: u8, next_hop: Ipv4Addr| nrr_platform_api::types::RouteEntry {
                destination: dst,
                prefix_length: prefix,
                next_hop,
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

    /// A user who never bound their adapters has nothing to enforce, and that is
    /// an answer — not an empty plan that would look like a policy.
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

    /// While the tunnel is up the guard adds nothing: the secondary rule is
    /// already a pinned pair — permit over that link, block the same destination
    /// anywhere else. Duplicating it would grow the ruleset without changing a
    /// single verdict.
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
}
