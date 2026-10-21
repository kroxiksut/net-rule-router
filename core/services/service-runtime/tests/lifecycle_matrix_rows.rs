//! Each row of the lifecycle table, run through the code that carries it out.
//!
//! The table (`lifecycle_matrix::expected_after`) says what must stand on the
//! machine after an edge. Here the edge is driven through the enforcement cycle,
//! the production plan source and route applier, over a kernel that holds what
//! it was given, and every cell the edge exercises is held to the table. A
//! cell that says `Reconcile` must match what a clean start would install on
//! the machine as it now stands. DNS cells are held by
//! `lifecycle_matrix_runtime.rs`; cells only hardware shows are `LIVE_CHECKS`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::user_principal::UserPrincipal;
use nrr_domain::{LeakProtection, RuleAction, RuleId};
use nrr_platform_api::active_principals::{
    ActivePrincipalError, ActivePrincipalSource, PresentPrincipal,
};
use nrr_platform_api::adapters::{
    AdapterInfo, IfOperStatus, InterfaceType, MockAdapterEventSource,
};
use nrr_platform_api::enforcement::{
    ApplyReport, ChannelAvailability, EnforcementFailure, EnforcementPlan, FlowRule,
    PolicyEnforcer, Verdict,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::power::{
    PowerEvent, PowerEventCallback, PowerEventObserver, PowerEventSubscription,
};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::types::RouteEntry;
use nrr_platform_api::MockWindowsApi;
use nrr_service_runtime::lifecycle_matrix::{
    after_crash_plan, expected_after, leak_guard_armed_at, orphaned_blocks_at_start, stop_plan,
    Disposition, LifecycleEdge, LifecycleInputs, OrphanedBlocks, StopReason,
};
use nrr_service_runtime::pass_inputs::{hashed, PassInputs};
use nrr_service_runtime::per_sid_orchestrator::{
    ActiveRulesSnapshot, PerSidBehaviorMode, PerSidBinding, PerSidPolicySnapshot,
    RoutePolicySource, RulesProvider,
};
use nrr_service_runtime::power_resume::PowerResumeRearm;
use nrr_service_runtime::principal_enforcement::{
    CycleOutcome, PlanRead, PlannedPolicy, PrincipalEnforcementCycle, PrincipalPlanSource,
};
use nrr_service_runtime::production_principal_plan::{
    ProductionPrincipalPlanSource, StoredEgressBindings,
};
use nrr_service_runtime::route_apply::PlannedRouteApplier;

/// The one host the rule book sends over the additional link.
const RULE_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 4);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const ETH: u32 = 2;
const TUN: u32 = 5;
/// The tunnel's index once the VPN client has re-created it after a wake.
const TUN_AFTER_WAKE: u32 = 9;

const ARMED: LifecycleInputs = LifecycleInputs {
    leak_guard_armed: true,
    keep_rule_routes_on_stop: false,
};
const UNARMED: LifecycleInputs = LifecycleInputs {
    leak_guard_armed: false,
    keep_rule_routes_on_stop: false,
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn uid(n: u32) -> UserPrincipal {
    UserPrincipal::from_linux_uid(n)
}

// ── The machine ──────────────────────────────────────────────────────────────

/// What was removed, in order, across both mechanisms.
#[derive(Default)]
struct Journal(Mutex<Vec<&'static str>>);

impl Journal {
    fn note(&self, what: &'static str) {
        lock(&self.0).push(what);
    }
    fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *lock(&self.0))
    }
}

/// The packet filter: holds the last set of plans it was handed, as nft and
/// WFP do, until it is handed another, torn down or flushed from outside.
#[derive(Default)]
struct Kernel {
    installed: Mutex<Vec<EnforcementPlan>>,
    tunnel_up: AtomicBool,
    /// Moves whenever what is installed changes: the pass input a real
    /// backend reports for its own table.
    generation: AtomicU64,
    teardowns: AtomicUsize,
    journal: Arc<Journal>,
}

impl Kernel {
    fn flush_from_outside(&self) {
        lock(&self.installed).clear();
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

impl PolicyEnforcer for Kernel {
    fn enforce(&self, plans: &[EnforcementPlan]) -> Result<ApplyReport, EnforcementFailure> {
        let mut installed = lock(&self.installed);
        if installed.as_slice() != plans {
            *installed = plans.to_vec();
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        Ok(ApplyReport {
            applied: plans.len(),
            skipped: 0,
            failed: 0,
            notes: Vec::new(),
        })
    }

    fn channel_availability(&self, _principal: &UserPrincipal) -> ChannelAvailability {
        ChannelAvailability {
            primary: true,
            secondary: self.tunnel_up.load(Ordering::SeqCst),
        }
    }

    fn teardown(&self) -> Result<(), EnforcementFailure> {
        lock(&self.installed).clear();
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.teardowns.fetch_add(1, Ordering::SeqCst);
        self.journal.note("filters-removed");
        Ok(())
    }
}

/// The route table, noting each removal in the shared journal.
struct Routes {
    inner: MockWindowsApi,
    journal: Arc<Journal>,
}

impl RouteTablePort for Routes {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        RouteTablePort::get_ip_forward_table(&self.inner)
    }
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        RouteTablePort::create_ip_forward_entry(&self.inner, entry)
    }
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        self.journal.note("route-removed");
        RouteTablePort::delete_ip_forward_entry(&self.inner, entry)
    }
    fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        RouteTablePort::get_adapter_infos(&self.inner)
    }
    fn unicast_ip_addresses(&self) -> Result<Vec<(IpAddr, u32)>, PlatformError> {
        RouteTablePort::unicast_ip_addresses(&self.inner)
    }
    fn interactive_user_sids(&self) -> Vec<String> {
        RouteTablePort::interactive_user_sids(&self.inner)
    }
    fn interactive_user_sign_ins(&self) -> Vec<(String, Option<u64>)> {
        RouteTablePort::interactive_user_sign_ins(&self.inner)
    }
    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
        RouteTablePort::interface_luid_for_index(&self.inner, ifindex)
    }
}

/// Who is signed in, in sign-in order.
#[derive(Default)]
struct Seats(Mutex<Vec<PresentPrincipal>>);

impl ActivePrincipalSource for Seats {
    fn active_principals(&self) -> Result<Vec<UserPrincipal>, ActivePrincipalError> {
        Ok(self
            .present_principals()?
            .into_iter()
            .map(|p| p.principal)
            .collect())
    }
    fn present_principals(&self) -> Result<Vec<PresentPrincipal>, ActivePrincipalError> {
        Ok(lock(&self.0).clone())
    }
    fn authority(&self) -> &'static str {
        "seats"
    }
}

/// Each user's leak-protection choice; everything else at its default, both
/// links bound.
#[derive(Default)]
struct Policies(Mutex<BTreeMap<String, LeakProtection>>);

impl RoutePolicySource for Policies {
    fn load_for_sid(&self, sid: &str) -> Option<PerSidPolicySnapshot> {
        let protection = *lock(&self.0).get(sid)?;
        let binding = |name: &str| PerSidBinding {
            stable_id: name.to_owned(),
            display_name: name.to_owned(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        };
        Some(PerSidPolicySnapshot {
            primary: Some(binding("eth0")),
            secondary: Some(binding("tun0")),
            mode: PerSidBehaviorMode::PreferPrimary,
            leak_protection: protection,
            kill_switch_protocols: 0x7F,
            allow_dns_over_primary: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            kill_switch_strict_shared_ips: false,
            link_provider_exe_paths: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            doh_lockdown_auto: false,
            doh_resolver_ips: Vec::new(),
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            app_rules_take_all_addresses: false,
            guard_forwarded_traffic: true,
        })
    }
}

/// One rule for everyone: the rule host over the additional link. A literal
/// address, so the rows test planning and not resolution.
struct OneSecondaryRule;

impl RulesProvider for OneSecondaryRule {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        Some(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(Vec::new()),
                secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: RuleId("s-0".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(RULE_HOST))),
                    app_match: None,
                    comment: String::new(),
                    action: RuleAction::Route,
                    origin: None,
                }]),
            },
        })
    }
}

fn link(index: u32, name: &str, gateways: Vec<Ipv4Addr>) -> AdapterInfo {
    AdapterInfo {
        index,
        adapter_name: name.to_owned(),
        description: String::new(),
        friendly_name: name.to_owned(),
        mac: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: IfOperStatus::Up,
        ipv4_addresses: Vec::new(),
        ipv6_addresses: Vec::new(),
        gateways,
    }
}

/// One user's share of what the kernel holds.
#[derive(Clone, Debug, Default, PartialEq)]
struct Held {
    /// Permits and pins.
    filters: Vec<FlowRule>,
    /// What leak protection blocks.
    blocks: Vec<FlowRule>,
}

impl Held {
    fn of(plans: &[EnforcementPlan], n: u32) -> Self {
        let (blocks, filters) = plans
            .iter()
            .filter(|p| p.principal == uid(n))
            .flat_map(|p| p.flows.iter().cloned())
            .partition(|f| f.verdict == Verdict::Block);
        Self { filters, blocks }
    }
}

/// Everything a row reads, before or after its edge.
#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    held: BTreeMap<u32, Held>,
    /// The interfaces the rule host is routed through.
    routes: Vec<u32>,
}

impl Snapshot {
    fn held(&self, n: u32) -> Held {
        self.held.get(&n).cloned().unwrap_or_default()
    }
}

/// The machine a service instance runs on. A new [`Self::service`] is a new
/// instance on the same machine: a restart, or a start after a crash.
struct Machine {
    kernel: Arc<Kernel>,
    routes: Arc<Routes>,
    links: Arc<MockAdapterEventSource>,
    seats: Arc<Seats>,
    policies: Arc<Policies>,
    paused: Arc<Mutex<Vec<String>>>,
    keep_paused_routes: Arc<AtomicBool>,
    journal: Arc<Journal>,
    /// Bumped on every link change: the adapters pass input.
    links_generation: Arc<AtomicU64>,
    users: Mutex<BTreeSet<u32>>,
}

impl Machine {
    fn new(tunnel_up: bool, users: &[(u32, LeakProtection)]) -> Self {
        let journal = Arc::new(Journal::default());
        let machine = Self {
            kernel: Arc::new(Kernel {
                journal: Arc::clone(&journal),
                ..Kernel::default()
            }),
            routes: Arc::new(Routes {
                inner: MockWindowsApi::new(),
                journal: Arc::clone(&journal),
            }),
            links: Arc::new(MockAdapterEventSource::new()),
            seats: Arc::default(),
            policies: Arc::default(),
            paused: Arc::default(),
            keep_paused_routes: Arc::default(),
            journal,
            links_generation: Arc::default(),
            users: Mutex::default(),
        };
        machine.set_tunnel(tunnel_up.then_some(TUN));
        for (n, protection) in users {
            machine.sign_in(*n, *protection);
        }
        machine
    }

    /// `Some(index)`: the tunnel is up at that interface. `None`: it is gone.
    fn set_tunnel(&self, tunnel: Option<u32>) {
        self.kernel
            .tunnel_up
            .store(tunnel.is_some(), Ordering::SeqCst);
        let mut links = vec![link(ETH, "eth0", vec![GATEWAY])];
        links.extend(tunnel.map(|index| link(index, "tun0", Vec::new())));
        *lock(&self.links.adapters) = links;
        self.links_generation.fetch_add(1, Ordering::SeqCst);
    }

    fn tunnel(&self) -> Option<u32> {
        lock(&self.links.adapters)
            .iter()
            .find(|l| l.friendly_name == "tun0")
            .map(|l| l.index)
    }

    fn sign_in(&self, n: u32, protection: LeakProtection) {
        lock(&self.policies.0).insert(uid(n).as_stored().to_owned(), protection);
        lock(&self.users).insert(n);
        let mut seats = lock(&self.seats.0);
        let order = seats.len() as u64 + 1;
        seats.push(PresentPrincipal {
            principal: uid(n),
            at_seat: false,
            signed_in_at: Some(order),
        });
    }

    fn sign_out_everyone(&self) {
        lock(&self.seats.0).clear();
    }

    fn pause(&self, n: u32, keep_rule_routes: bool) {
        lock(&self.paused).push(uid(n).as_stored().to_owned());
        self.keep_paused_routes
            .store(keep_rule_routes, Ordering::SeqCst);
    }

    fn plans(&self) -> Arc<ProductionPrincipalPlanSource> {
        Arc::new(ProductionPrincipalPlanSource::new(
            Arc::new(OneSecondaryRule),
            Arc::clone(&self.policies) as Arc<dyn RoutePolicySource>,
            Arc::new(nrr_service_runtime::fqdn_cache_lookup::MockFqdnCacheLookup::new()),
            Arc::new(nrr_platform_api::app_path_resolver::NoopAppPathResolver),
            Arc::new(
                nrr_service_runtime::app_observation_lookup::MockAppObservationLookup::default(),
            ),
        ))
    }

    fn service(&self) -> PrincipalEnforcementCycle {
        self.service_with(self.plans())
    }

    fn service_with(&self, plans: Arc<dyn PrincipalPlanSource>) -> PrincipalEnforcementCycle {
        let applier = PlannedRouteApplier::new(
            Arc::clone(&self.routes) as Arc<dyn RouteTablePort>,
            Arc::clone(&self.links) as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
            Arc::new(StoredEgressBindings::new(
                Arc::clone(&self.policies) as Arc<dyn RoutePolicySource>
            )),
        );
        let paused = Arc::clone(&self.paused);
        let keep = Arc::clone(&self.keep_paused_routes);
        PrincipalEnforcementCycle::new(
            Arc::clone(&self.seats) as Arc<dyn ActivePrincipalSource>,
            plans,
            Arc::clone(&self.kernel) as Arc<dyn PolicyEnforcer>,
        )
        .with_routes(Arc::new(applier))
        .with_paused_principals(Arc::new(move || lock(&paused).clone()))
        .with_keep_routes_when_paused(Arc::new(move || keep.load(Ordering::SeqCst)))
    }

    /// The pass inputs the Linux wiring gives the cycle, cut to the ones these
    /// rows move: the links, the route table and the kernel's own table.
    fn pass_inputs(&self) -> PassInputs {
        let links = Arc::clone(&self.links_generation);
        let kernel = Arc::clone(&self.kernel);
        let routes = Arc::clone(&self.routes);
        PassInputs::new()
            .with_source(
                "adapters",
                Arc::new(move || Some(links.load(Ordering::SeqCst))),
            )
            .with_own_writes_source(
                "routes",
                hashed(move || RouteTablePort::get_ip_forward_table(routes.as_ref())),
            )
            .with_own_writes_source(
                "nft",
                Arc::new(move || Some(kernel.generation.load(Ordering::SeqCst))),
            )
    }

    fn snapshot(&self) -> Snapshot {
        let installed = lock(&self.kernel.installed).clone();
        Snapshot {
            held: lock(&self.users)
                .iter()
                .map(|n| (*n, Held::of(&installed, *n)))
                .collect(),
            routes: self.rule_host_links(),
        }
    }

    fn rule_host_links(&self) -> Vec<u32> {
        let mut links: Vec<u32> = RouteTablePort::get_ip_forward_table(self.routes.as_ref())
            .expect("route table")
            .into_iter()
            .filter(|r| r.destination == IpAddr::V4(RULE_HOST))
            .map(|r| r.interface_index)
            .collect();
        links.sort_unstable();
        links
    }

    /// What a clean start installs on a machine standing as this one does now:
    /// the meaning of every `Reconcile` cell.
    fn clean_start(&self) -> Snapshot {
        let witness = Self::new(false, &[]);
        witness.set_tunnel(self.tunnel());
        *lock(&witness.policies.0) = lock(&self.policies.0).clone();
        *lock(&witness.seats.0) = lock(&self.seats.0).clone();
        *lock(&witness.paused) = lock(&self.paused).clone();
        *lock(&witness.users) = lock(&self.users).clone();
        witness.keep_paused_routes.store(
            self.keep_paused_routes.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        assert!(matches!(
            witness.service().tick(),
            CycleOutcome::Applied { .. }
        ));
        witness.snapshot()
    }
}

// ── Holding a row to the table ───────────────────────────────────────────────

/// Which cells a row's scenarios actually exercised.
#[derive(Default)]
struct Exercised(BTreeSet<&'static str>);

impl Exercised {
    /// One cell. `Keep` and `Remove` say nothing about state that was never
    /// there, so a cell with nothing before it is recorded as not exercised;
    /// [`Self::all`] then fails a row whose scenarios never set it up.
    fn cell<T: PartialEq + Debug>(
        &mut self,
        row: &str,
        cell: &'static str,
        expected: Disposition,
        before: &[T],
        after: &[T],
        clean_start: &[T],
    ) {
        match expected {
            Disposition::Keep if !before.is_empty() => {
                assert_eq!(after, before, "{row}: {cell} must be kept as it was");
            }
            Disposition::Remove if !before.is_empty() => {
                assert!(after.is_empty(), "{row}: {cell} must be removed: {after:?}");
            }
            Disposition::Reconcile => {
                assert_eq!(
                    after, clean_start,
                    "{row}: {cell} must be what a clean start installs now"
                );
            }
            Disposition::Keep | Disposition::Remove => return,
        }
        self.0.insert(cell);
    }

    /// Filters, blocks and routes of `n` on `machine` against the table's
    /// answer for `edge`.
    fn row(
        &mut self,
        row: &str,
        edge: LifecycleEdge,
        inputs: LifecycleInputs,
        n: u32,
        before: &Snapshot,
        machine: &Machine,
    ) {
        let want = expected_after(edge, inputs);
        let (after, clean_start) = (machine.snapshot(), machine.clean_start());
        let (b, a, c) = (before.held(n), after.held(n), clean_start.held(n));
        self.cell(
            row,
            "filters",
            want.user_filters,
            &b.filters,
            &a.filters,
            &c.filters,
        );
        self.cell(
            row,
            "blocks",
            want.fail_closed_blocks,
            &b.blocks,
            &a.blocks,
            &c.blocks,
        );
        self.cell(
            row,
            "routes",
            want.routes,
            &before.routes,
            &after.routes,
            &clean_start.routes,
        );
    }

    fn all(&self, row: &str, cells: &[&str]) {
        for cell in cells {
            assert!(self.0.contains(cell), "{row}: no scenario exercised {cell}");
        }
    }
}

const EVERY_CELL: &[&str] = &["filters", "blocks", "routes"];

/// The routes are removed before the filters: between the two the rule host
/// is blocked, never leaked.
fn assert_routes_went_first(row: &str, journal: &[&str]) {
    let last_route = journal.iter().rposition(|s| *s == "route-removed");
    let filters = journal.iter().position(|s| *s == "filters-removed");
    if let (Some(route), Some(filters)) = (last_route, filters) {
        assert!(
            route < filters,
            "{row}: filters went before routes: {journal:?}"
        );
    }
}

// ── The rows ─────────────────────────────────────────────────────────────────

#[test]
fn a_start_installs_what_each_present_users_rules_ask_for() {
    let mut seen = Exercised::default();
    for tunnel_up in [true, false] {
        let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
        let before = machine.snapshot();

        assert!(matches!(
            machine.service().tick(),
            CycleOutcome::Applied { .. }
        ));

        let after = machine.snapshot();
        assert_ne!(after.held(1000), Held::default(), "the rule plans nothing");
        seen.row(
            "start",
            LifecycleEdge::Start,
            ARMED,
            1000,
            &before,
            &machine,
        );
    }
    seen.all("start", EVERY_CELL);
}

/// The dead instance's blocks stay in force through the restart, and the
/// first pass of the new one takes them over: nothing strips them first.
#[test]
fn a_start_after_a_crash_keeps_the_dead_instances_blocks_under_leak_protection() {
    assert_eq!(
        orphaned_blocks_at_start(true),
        OrphanedBlocks::AdoptOnFirstPass
    );
    let mut seen = Exercised::default();
    for tunnel_up in [false, true] {
        let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
        machine.service().tick();
        let before = machine.snapshot();

        let restarted = machine.service();
        assert_eq!(
            machine.snapshot(),
            before,
            "a new instance strips nothing on its own"
        );
        restarted.tick();

        let after = machine.snapshot();
        assert_eq!(machine.kernel.teardowns.load(Ordering::SeqCst), 0);
        if !tunnel_up {
            assert!(
                !after.held(1000).blocks.is_empty(),
                "the rule host must stay blocked"
            );
        }
        seen.row(
            "start after a crash",
            LifecycleEdge::StartAfterCrash,
            ARMED,
            1000,
            &before,
            &machine,
        );
    }
    seen.all("start after a crash", EVERY_CELL);
}

/// With nobody protected any more, what a dead instance blocked does not
/// outlive the first pass. On Linux that pass is the strip: the nft table
/// survives the crash and is replaced whole.
#[test]
fn a_start_after_a_crash_lifts_the_blocks_once_nobody_has_leak_protection() {
    assert_eq!(orphaned_blocks_at_start(false), OrphanedBlocks::StripNow);
    let machine = Machine::new(false, &[(1000, LeakProtection::Sites)]);
    machine.service().tick();
    let before = machine.snapshot();
    assert!(!before.held(1000).blocks.is_empty());
    // Turned off, and the service died before a pass could act on it.
    lock(&machine.policies.0).insert(uid(1000).as_stored().to_owned(), LeakProtection::Off);

    machine.service().tick();

    let mut seen = Exercised::default();
    seen.row(
        "start after a crash, unprotected",
        LifecycleEdge::StartAfterCrash,
        UNARMED,
        1000,
        &before,
        &machine,
    );
    seen.all("start after a crash, unprotected", &["blocks"]);
}

/// A stop on purpose takes everything off, routes first, filters last, and no
/// later pass puts any of it back.
#[test]
fn a_service_stop_removes_routes_then_filters_and_follows_the_route_setting() {
    let mut seen = Exercised::default();
    for (tunnel_up, keep) in [(true, false), (true, true), (false, false)] {
        let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
        let service = machine.service();
        service.tick();
        let before = machine.snapshot();
        machine.journal.take();
        let inputs = LifecycleInputs {
            keep_rule_routes_on_stop: keep,
            ..ARMED
        };

        service
            .teardown_with(stop_plan(StopReason::ServiceStop, inputs))
            .expect("teardown");

        let row = format!("service stop (keep routes: {keep})");
        let after = machine.snapshot();
        assert_routes_went_first(&row, &machine.journal.take());
        seen.row(
            &row,
            LifecycleEdge::Stop(StopReason::ServiceStop),
            inputs,
            1000,
            &before,
            &machine,
        );
        assert!(matches!(service.tick(), CycleOutcome::Stopped));
        assert_eq!(
            machine.snapshot(),
            after,
            "a pass after the stop installed something"
        );
    }
    seen.all("service stop", EVERY_CELL);
}

/// A machine going down keeps every filter and route to the end, whoever is
/// protected; the cycle is latched all the same.
#[test]
fn a_machine_shutdown_takes_nothing_off() {
    let mut seen = Exercised::default();
    for (tunnel_up, inputs) in [(true, ARMED), (false, ARMED), (true, UNARMED)] {
        let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
        let service = machine.service();
        service.tick();
        let before = machine.snapshot();
        machine.journal.take();

        service
            .teardown_with(stop_plan(StopReason::MachineShutdown, inputs))
            .expect("teardown");

        assert!(machine.journal.take().is_empty(), "something was removed");
        assert_eq!(machine.kernel.teardowns.load(Ordering::SeqCst), 0);
        seen.row(
            "machine shutdown",
            LifecycleEdge::Stop(StopReason::MachineShutdown),
            inputs,
            1000,
            &before,
            &machine,
        );
        assert!(matches!(service.tick(), CycleOutcome::Stopped));
    }
    seen.all("machine shutdown", EVERY_CELL);
}

/// A state database holding `protections`, one user each.
fn state_db(protections: &[LeakProtection]) -> (tempfile::TempDir, std::path::PathBuf) {
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::route_bindings::{BindingSource, RouteBindingsRepository, RoutePolicyRecord};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nrr_service_state.db");
    let conn = nrr_storage::migration::open_connection(&path).expect("open");
    let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrations");
    let conn = runner.into_connection();
    let repo = RouteBindingsRepository::new(&conn);
    for (i, protection) in protections.iter().enumerate() {
        let record = RoutePolicyRecord {
            leak_protection: *protection,
            ..RoutePolicyRecord::empty(BindingSource::UserAssigned)
        };
        repo.update_for_sid(&format!("S-1-5-21-1-1-1-{}", 1001 + i), &record, 1)
            .expect("store the policy");
    }
    drop(conn);
    (dir, path)
}

/// Both OSes' after-crash verbs read the stored choices, plan with
/// `after_crash_plan` and sweep. Here the plan is carried out by the same
/// teardown on the machine a crashed instance left.
#[test]
fn spent_restarts_keep_blocks_only_while_a_stored_choice_asks_for_them() {
    use LeakProtection::{Everything, Off, Sites};
    let mut seen = Exercised::default();
    for (stored, armed) in [
        (vec![Sites], true),
        (vec![Off, Everything], true),
        (vec![Off], false),
        (Vec::new(), false),
    ] {
        let (_dir, path) = state_db(&stored);
        assert_eq!(leak_guard_armed_at(&path), armed, "{stored:?}");
        let inputs = LifecycleInputs {
            leak_guard_armed: leak_guard_armed_at(&path),
            keep_rule_routes_on_stop: false,
        };
        for tunnel_up in [true, false] {
            let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
            machine.service().tick();
            let before = machine.snapshot();

            let after_crash = machine.service();
            after_crash
                .teardown_with(after_crash_plan(inputs))
                .expect("sweep");

            seen.row(
                "restarts spent",
                LifecycleEdge::RestartsExhausted,
                inputs,
                1000,
                &before,
                &machine,
            );
        }
    }
    seen.all("restarts spent", EVERY_CELL);
}

/// Nobody left: filters and routes go in the same pass, never one without the
/// other.
#[test]
fn the_last_user_signing_out_takes_filters_and_routes_together() {
    let mut seen = Exercised::default();
    for tunnel_up in [true, false] {
        let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
        let service = machine.service();
        service.tick();
        let before = machine.snapshot();

        machine.sign_out_everyone();
        service.tick();

        seen.row(
            "last user signed out",
            LifecycleEdge::LastUserSignedOut,
            ARMED,
            1000,
            &before,
            &machine,
        );
    }
    seen.all("last user signed out", EVERY_CELL);
}

/// A newcomer is served by the next pass; the user already signed in keeps
/// exactly what they had.
#[test]
fn a_user_signing_in_gets_their_policy_and_nobody_else_changes() {
    let mut seen = Exercised::default();
    for tunnel_up in [true, false] {
        let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
        let service = machine.service();
        service.tick();
        let before = machine.snapshot();

        machine.sign_in(1001, LeakProtection::Sites);
        service.tick();

        let after = machine.snapshot();
        assert_eq!(
            after.held(1000),
            before.held(1000),
            "the first user's policy moved"
        );
        assert_ne!(
            after.held(1001),
            Held::default(),
            "the newcomer got nothing"
        );
        seen.row(
            "user signed in",
            LifecycleEdge::UserSignedIn,
            ARMED,
            1001,
            &before,
            &machine,
        );
    }
    seen.all("user signed in", EVERY_CELL);
}

/// A pause takes that user's filters and blocks down and nobody else's; their
/// rule routes stay only when the stop setting keeps them.
#[test]
fn a_pause_takes_down_only_that_users_policy() {
    let mut seen = Exercised::default();
    for tunnel_up in [true, false] {
        let machine = Machine::new(
            tunnel_up,
            &[(1000, LeakProtection::Sites), (1001, LeakProtection::Sites)],
        );
        let service = machine.service();
        service.tick();
        let before = machine.snapshot();

        machine.pause(1000, false);
        service.tick();

        let after = machine.snapshot();
        assert_eq!(
            after.held(1001),
            before.held(1001),
            "another user's policy moved"
        );
        let want = expected_after(LifecycleEdge::UserPaused, ARMED);
        let (b, a) = (before.held(1000), after.held(1000));
        seen.cell(
            "pause",
            "filters",
            want.user_filters,
            &b.filters,
            &a.filters,
            &[],
        );
        seen.cell(
            "pause",
            "blocks",
            want.fail_closed_blocks,
            &b.blocks,
            &a.blocks,
            &[],
        );
    }
    // Routes: a lone user, so the table is theirs alone.
    for keep in [true, false] {
        let machine = Machine::new(true, &[(1000, LeakProtection::Sites)]);
        let service = machine.service();
        service.tick();
        let before = machine.snapshot();
        let inputs = LifecycleInputs {
            keep_rule_routes_on_stop: keep,
            ..ARMED
        };

        machine.pause(1000, keep);
        service.tick();

        let after = machine.snapshot();
        let want = expected_after(LifecycleEdge::UserPaused, inputs);
        seen.cell(
            "pause",
            "routes",
            want.routes,
            &before.routes,
            &after.routes,
            &[],
        );
        assert!(after.held(1000).filters.is_empty());
    }
    seen.all("pause", EVERY_CELL);
}

/// A tunnel re-created under another interface while the machine slept: the
/// wake's re-arm runs the pass that moves the rule host onto it.
#[test]
fn a_wake_re_pins_the_rule_host_to_the_link_as_it_now_is() {
    struct Lid(Mutex<Option<PowerEventCallback>>);
    impl PowerEventObserver for Lid {
        fn subscribe(
            &self,
            on_event: PowerEventCallback,
        ) -> Result<PowerEventSubscription, PlatformError> {
            *lock(&self.0) = Some(on_event);
            Ok(PowerEventSubscription::inert())
        }
    }

    let machine = Machine::new(true, &[(1000, LeakProtection::Sites)]);
    let service = Arc::new(machine.service().with_pass_inputs(machine.pass_inputs()));
    service.tick_if_changed_logged("timer");
    let before = machine.snapshot();
    assert_eq!(before.routes, vec![TUN]);

    // The Linux wiring's recompute hook, which the wake re-arm fires.
    let hook = {
        let service = Arc::clone(&service);
        Arc::new(move || {
            service.tick_if_changed_logged("recompute");
        })
    };
    let lid = Lid(Mutex::new(None));
    let _rearm = PowerResumeRearm::start(&lid, hook, Duration::from_millis(20)).expect("subscribe");
    let on_event = lock(&lid.0).clone().expect("subscribed");

    on_event(PowerEvent::Suspend);
    machine.set_tunnel(Some(TUN_AFTER_WAKE));
    on_event(PowerEvent::Resume);

    let deadline = Instant::now() + Duration::from_secs(10);
    while machine.rule_host_links() != vec![TUN_AFTER_WAKE] && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut seen = Exercised::default();
    seen.row(
        "resume from sleep",
        LifecycleEdge::ResumeFromSleep,
        ARMED,
        1000,
        &before,
        &machine,
    );
    seen.all("resume from sleep", &["filters", "routes"]);
}

/// The tunnel drops: the next pass re-plans against the dead link. Under leak
/// protection that pass is what blocks the rule host; without it nothing is
/// blocked.
#[test]
fn a_lost_tunnel_is_re_planned_and_blocks_only_under_leak_protection() {
    let mut seen = Exercised::default();
    for (protection, inputs) in [
        (LeakProtection::Sites, ARMED),
        (LeakProtection::Off, UNARMED),
    ] {
        let machine = Machine::new(true, &[(1000, protection)]);
        let service = machine.service();
        service.tick();
        let before = machine.snapshot();

        machine.set_tunnel(None);
        service.tick();

        let after = machine.snapshot();
        assert_eq!(
            !after.held(1000).blocks.is_empty(),
            protection.is_on(),
            "{protection}: blocks after the drop: {:?}",
            after.held(1000).blocks,
        );
        seen.row(
            "additional link down",
            LifecycleEdge::SecondaryDown,
            inputs,
            1000,
            &before,
            &machine,
        );
    }
    seen.all("additional link down", EVERY_CELL);
}

/// Another program flushes the filter table. A pass that would be skipped as
/// unchanged sees its own table move and puts it back on the next tick.
#[test]
fn a_filter_table_flushed_from_outside_is_back_after_one_tick() {
    let machine = Machine::new(false, &[(1000, LeakProtection::Sites)]);
    let service = machine.service().with_pass_inputs(machine.pass_inputs());
    assert!(matches!(
        service.tick_if_changed_logged("timer"),
        CycleOutcome::Applied { .. }
    ));
    assert!(matches!(
        service.tick_if_changed_logged("timer"),
        CycleOutcome::Unchanged
    ));
    let before = machine.snapshot();

    machine.kernel.flush_from_outside();
    assert!(matches!(
        service.tick_if_changed_logged("timer"),
        CycleOutcome::Applied { .. }
    ));

    let mut seen = Exercised::default();
    seen.row(
        "external reset",
        LifecycleEdge::ExternalReset,
        ARMED,
        1000,
        &before,
        &machine,
    );
    seen.all("external reset", &["filters", "blocks"]);
}

/// The route half of the same row: a route deleted while its link stays up is
/// back after the next tick, and nothing else in the table moves.
#[test]
fn a_route_removed_from_outside_is_back_after_one_tick() {
    let machine = Machine::new(true, &[(1000, LeakProtection::Sites)]);
    let service = machine.service().with_pass_inputs(machine.pass_inputs());
    service.tick_if_changed_logged("timer");
    let before = machine.snapshot();
    assert_eq!(before.routes, vec![TUN]);
    let table = || -> std::collections::HashSet<RouteEntry> {
        RouteTablePort::get_ip_forward_table(machine.routes.as_ref())
            .expect("table")
            .into_iter()
            .collect()
    };
    let table_before = table();

    for route in RouteTablePort::get_ip_forward_table(&machine.routes.inner).expect("table") {
        if route.destination == IpAddr::V4(RULE_HOST) {
            RouteTablePort::delete_ip_forward_entry(&machine.routes.inner, &route).expect("delete");
        }
    }
    machine.journal.take();
    service.tick_if_changed_logged("timer");

    assert_eq!(
        table(),
        table_before,
        "the same route is back, nothing else"
    );
    assert!(
        !machine.journal.take().contains(&"route-removed"),
        "putting a route back removes none of ours",
    );
    let mut seen = Exercised::default();
    seen.row(
        "external reset",
        LifecycleEdge::ExternalReset,
        ARMED,
        1000,
        &before,
        &machine,
    );
    seen.all("external reset", &["routes"]);
}

/// Plans like the production source, except that the pass `armed` for panics
/// inside planning, as a hostile input reaching the planner would.
struct PanicsOnce {
    inner: Arc<ProductionPrincipalPlanSource>,
    armed: AtomicBool,
}

impl PanicsOnce {
    fn trip(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            panic!("planning blew up");
        }
    }
}

impl PrincipalPlanSource for PanicsOnce {
    fn plan_for(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> Option<PlannedPolicy> {
        self.trip();
        self.inner.plan_for(principal, availability)
    }
    fn plan_read_for(
        &self,
        principal: &UserPrincipal,
        availability: ChannelAvailability,
    ) -> PlanRead {
        self.trip();
        self.inner.plan_read_for(principal, availability)
    }
    fn begin_pass(&self) {
        self.inner.begin_pass();
    }
    fn end_pass(&self) {
        self.inner.end_pass();
    }
    fn set_route_table_owner(&self, owner: Option<&UserPrincipal>) {
        self.inner.set_route_table_owner(owner);
    }
}

/// A panic costs the pass it happened in. What the last pass installed stays
/// as it was (the supervisor catches the panic the same way, see
/// `a_task_that_keeps_panicking_retires_into_its_component`), and the next
/// pass runs as if nothing happened.
#[test]
fn a_panic_in_a_pass_leaves_the_machine_as_it_was() {
    let mut seen = Exercised::default();
    for tunnel_up in [true, false] {
        let machine = Machine::new(tunnel_up, &[(1000, LeakProtection::Sites)]);
        let plans = Arc::new(PanicsOnce {
            inner: machine.plans(),
            armed: AtomicBool::new(false),
        });
        let service = machine.service_with(Arc::clone(&plans) as Arc<dyn PrincipalPlanSource>);
        service.tick();
        let before = machine.snapshot();

        plans.armed.store(true, Ordering::SeqCst);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| service.tick()));
        assert!(caught.is_err(), "the pass did not panic");

        assert_eq!(machine.kernel.teardowns.load(Ordering::SeqCst), 0);
        seen.row(
            "task panic",
            LifecycleEdge::TaskPanic,
            ARMED,
            1000,
            &before,
            &machine,
        );
        assert!(matches!(service.tick(), CycleOutcome::Applied { .. }));
        assert_eq!(
            machine.snapshot(),
            machine.clean_start(),
            "the next pass did not recover"
        );
    }
    seen.all("task panic", EVERY_CELL);
}
