//! The stop rows and the blocked start, through the supervised runtime itself:
//! the stop reason reaching the teardown, DNS handed back before the filters
//! are touched, and a start that cannot run applying and removing nothing.
//!
//! One test, run phase by phase: the runtime's stop latch is process-wide, so
//! two runtimes in one test binary would stop each other.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use nrr_domain::enforcement_mode::EnforcementMode;
use nrr_domain::user_principal::UserPrincipal;
use nrr_platform_api::active_principals::{ActivePrincipalError, ActivePrincipalSource};
use nrr_platform_api::dns::AddressFamily;
use nrr_platform_api::dns_redirect::{RedirectHandle, RedirectState, SystemDnsRedirectPort};
use nrr_platform_api::enforcement::{
    ApplyReport, ChannelAvailability, EnforcementFailure, EnforcementPlan, PolicyEnforcer,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::{AdapterMonitor, MockAdapterEventSource};
use nrr_service_runtime::bootstrap::{bootstrap, BootstrapConfig};
use nrr_service_runtime::dns_listener::DnsInterceptListener;
use nrr_service_runtime::dns_resolver::{
    FactSink, ReconcileOutcome, ResolveError, ResolvedAddresses, RuleHostOracle, SyncReconciler,
    UpstreamResolver,
};
use nrr_service_runtime::dns_resolver_service::{DnsResolverController, DnsResolverService};
use nrr_service_runtime::health::HealthAggregator;
use nrr_service_runtime::ipc_handlers::operation_status_store::OperationStatusStore;
use nrr_service_runtime::lifecycle::{teardown_reason, ServiceController, StopToken};
use nrr_service_runtime::lifecycle_matrix::{
    expected_after, stop_plan, Disposition, LifecycleEdge, LifecycleInputs, StopReason,
    TeardownStep, TEARDOWN_ORDER,
};
use nrr_service_runtime::managers::{AcceptOutcome, IpcAcceptor, IpcBindError, IpcServer};
use nrr_service_runtime::principal_enforcement::{
    PlannedPolicy, PrincipalEnforcementCycle, PrincipalPlanSource,
};
use nrr_service_runtime::service_stability::ServiceStabilityConfig;
use nrr_service_runtime::state::ServiceRuntimeState;
use nrr_service_runtime::supervised_runtime::{
    run_supervised_runtime, RouteRecomputeHook, SupervisedRuntimeDeps,
};
use nrr_storage::StorageProfile;

const ARMED: LifecycleInputs = LifecycleInputs {
    leak_guard_armed: true,
    keep_rule_routes_on_stop: false,
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn user() -> UserPrincipal {
    UserPrincipal::from_linux_uid(1000)
}

/// What happened to DNS and the filters, in order.
#[derive(Default)]
struct Journal(Mutex<Vec<&'static str>>);

impl Journal {
    fn note(&self, what: &'static str) {
        lock(&self.0).push(what);
    }
    fn seen(&self) -> Vec<&'static str> {
        lock(&self.0).clone()
    }
}

#[derive(Default)]
struct Kernel {
    installed: Mutex<Vec<EnforcementPlan>>,
    enforces: AtomicUsize,
    teardowns: AtomicUsize,
    journal: Arc<Journal>,
}

impl PolicyEnforcer for Kernel {
    fn enforce(&self, plans: &[EnforcementPlan]) -> Result<ApplyReport, EnforcementFailure> {
        self.enforces.fetch_add(1, Ordering::SeqCst);
        *lock(&self.installed) = plans.to_vec();
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
            secondary: true,
        }
    }
    fn teardown(&self) -> Result<(), EnforcementFailure> {
        lock(&self.installed).clear();
        self.teardowns.fetch_add(1, Ordering::SeqCst);
        self.journal.note("filters-removed");
        Ok(())
    }
}

struct OneUser;

impl ActivePrincipalSource for OneUser {
    fn active_principals(&self) -> Result<Vec<UserPrincipal>, ActivePrincipalError> {
        Ok(vec![user()])
    }
    fn authority(&self) -> &'static str {
        "one-user"
    }
}

fn plan_of(principal: &UserPrincipal) -> EnforcementPlan {
    EnforcementPlan {
        principal: principal.clone(),
        flows: Vec::new(),
        routes: Vec::new(),
        policy_rules: Vec::new(),
    }
}

struct OnePlan;

impl PrincipalPlanSource for OnePlan {
    fn plan_for(
        &self,
        principal: &UserPrincipal,
        _availability: ChannelAvailability,
    ) -> Option<PlannedPolicy> {
        Some(PlannedPolicy {
            plan: plan_of(principal),
            protection_complete: true,
            fail_closed_blocks: 0,
            guard_holding: false,
        })
    }
}

/// The system DNS, pointed at our listener or given back.
struct Redirect(Arc<Journal>);

impl SystemDnsRedirectPort for Redirect {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        self.0.note("dns-redirected");
        Ok(RedirectHandle {
            marker: "lifecycle".to_owned(),
            listener,
        })
    }
    fn restore(&self, _handle: &RedirectHandle) -> Result<(), PlatformError> {
        self.0.note("dns-restored");
        Ok(())
    }
    fn verify(&self, _handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        Ok(RedirectState::Active)
    }
}

struct NoRuleHosts;
impl RuleHostOracle for NoRuleHosts {
    fn is_rule_host(&self, _hostname: &str) -> bool {
        false
    }
}
struct NoUpstream;
impl UpstreamResolver for NoUpstream {
    fn resolve_within(
        &self,
        _hostname: &str,
        _family: AddressFamily,
        _budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        Err(ResolveError::NoRecords)
    }
}
struct NoFacts;
impl FactSink for NoFacts {
    fn record(&self, _hostname: &str, _resolved: &ResolvedAddresses) {}
}
struct Installed;
impl SyncReconciler for Installed {
    fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
        ReconcileOutcome::Installed
    }
}

fn resolver(journal: &Arc<Journal>) -> Arc<DnsResolverController> {
    let controller = Arc::new(DnsResolverController::new());
    let journal = Arc::clone(journal);
    controller.set_factory(Arc::new(move || {
        let listener = DnsInterceptListener::new(
            Arc::new(NoRuleHosts),
            Arc::new(NoUpstream),
            Arc::new(NoFacts),
            Arc::new(Installed),
            "127.0.0.1:5353".parse().expect("addr"),
            Duration::from_millis(150),
            Duration::from_millis(500),
        );
        Ok(DnsResolverService::new(
            listener,
            Arc::new(Redirect(Arc::clone(&journal))),
            "127.0.0.1:0".parse().expect("addr"),
        ))
    }));
    controller
}

#[derive(Default)]
struct States(Mutex<Vec<ServiceRuntimeState>>);

impl ServiceController for States {
    fn report(&self, state: ServiceRuntimeState) {
        lock(&self.0).push(state);
    }
}

struct InertServer;
impl IpcServer for InertServer {
    fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
        Ok(Box::new(InertAcceptor))
    }
}
struct InertAcceptor;
impl IpcAcceptor for InertAcceptor {
    fn accept_one(&self) -> AcceptOutcome {
        std::thread::sleep(Duration::from_millis(20));
        AcceptOutcome::ShutdownRequested
    }
    fn request_shutdown(&self) {}
    fn join_workers(&self) {}
}

/// The runtime's wiring for these rows: the cycle, the resolver, and the stop
/// hook as both OS wirings build it, everything else absent.
fn deps(
    dir: &std::path::Path,
    cycle: &Arc<PrincipalEnforcementCycle>,
    dns: &Arc<DnsResolverController>,
) -> SupervisedRuntimeDeps {
    let teardown: RouteRecomputeHook = {
        let cycle = Arc::clone(cycle);
        Arc::new(move || {
            let _ = cycle.teardown_with(stop_plan(teardown_reason(), ARMED));
        })
    };
    SupervisedRuntimeDeps {
        auto_rules_engine: None,
        auto_rule_probe: None,
        app_destination_memory: None,
        conn_history: None,
        secondary_external_address: None,
        routing_pause_terms: None,
        health: Arc::new(HealthAggregator::new()),
        liveness: None,
        ipc_server: Arc::new(InertServer),
        adapter_monitor: Arc::new(AdapterMonitor::new(
            Arc::new(MockAdapterEventSource::default()),
            500,
        )),
        operation_results: Arc::new(OperationStatusStore::default()),
        mutation_tokens: None,
        stability: ServiceStabilityConfig::default(),
        logs_dir: dir.join("logs"),
        log_retention: nrr_diagnostics::LogRetentionPolicy::default(),
        cleanup_scope: nrr_diagnostics::ManualCleanupScope::default(),
        audit_dir: dir.join("audit"),
        audit_retention: nrr_diagnostics::AuditRetentionPolicy::default(),
        state_db_conn: None,
        principal_enforcement: Some(Arc::clone(cycle)),
        traffic_tick: None,
        activation_coordinator: None,
        revision_watch: None,
        dns_refresh_orchestrator: None,
        route_recompute_hook: None,
        observation_recompute_hook: None,
        route_teardown_hook: Some(teardown),
        rule_hostname_seeder: None,
        active_routing_sid: None,
        dns_observation_source: None,
        dns_observation_consumer: None,
        conn_observation_source: None,
        conn_observation_consumer: None,
        dns_resolver_controller: Some(Arc::clone(dns)),
        dns_resolver_mode: Arc::new(|| EnforcementMode::Resolver),
        sign_in_gate: None,
        fake_ip_shutdown: None,
        conn_observer_shutdown: None,
        event_bus: None,
        network_change_observer: None,
        secondary_liveness_hook: None,
        power_event_observer: None,
        logon_session_observer: None,
        rebind_requests: None,
        app_observation: None,
        live_connection_refresh: None,
        dns_observation: None,
        present_principals: None,
    }
}

/// Whether `cond` came true in time. Never panics: the caller still has to
/// stop the runtime, or the test hangs instead of failing.
fn came_true(cond: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !cond() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

/// What one run showed, while it ran and after it stopped.
struct Run {
    installed_while_running: Vec<EnforcementPlan>,
    enforces_while_running: usize,
    journal_while_running: Vec<&'static str>,
    installed_after: Vec<EnforcementPlan>,
    teardowns: usize,
    journal: Vec<&'static str>,
    states: Vec<ServiceRuntimeState>,
}

/// Start a runtime over a machine whose filters hold `left_behind`, let it come
/// up (or block), then stop it for `reason`.
fn run(blocked: bool, left_behind: Vec<EnforcementPlan>, reason: StopReason) -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut artifacts = bootstrap(&BootstrapConfig::new(StorageProfile::TestTemp(
        dir.path().to_path_buf(),
    )));
    if blocked {
        artifacts
            .report
            .block("lifecycle-test", "this start cannot reach running");
    }
    let journal = Arc::new(Journal::default());
    let kernel = Arc::new(Kernel {
        installed: Mutex::new(left_behind),
        journal: Arc::clone(&journal),
        ..Kernel::default()
    });
    let cycle = Arc::new(PrincipalEnforcementCycle::new(
        Arc::new(OneUser),
        Arc::new(OnePlan),
        Arc::clone(&kernel) as Arc<dyn PolicyEnforcer>,
    ));
    let dns = resolver(&journal);
    let deps = deps(dir.path(), &cycle, &dns);
    let states = Arc::new(States::default());
    let stop = StopToken::new();
    let watcher = {
        let (kernel, journal, states, stop) = (
            Arc::clone(&kernel),
            Arc::clone(&journal),
            Arc::clone(&states),
            stop.clone(),
        );
        std::thread::spawn(move || {
            let up = if blocked {
                let up =
                    came_true(|| lock(&states.0).contains(&ServiceRuntimeState::RecoveryRequired));
                // Long enough for a task that should not exist to have run.
                std::thread::sleep(Duration::from_millis(500));
                up
            } else {
                came_true(|| {
                    kernel.enforces.load(Ordering::SeqCst) > 0
                        && journal.seen().contains(&"dns-redirected")
                })
            };
            let seen = (
                lock(&kernel.installed).clone(),
                kernel.enforces.load(Ordering::SeqCst),
                journal.seen(),
            );
            stop.request_stop_for(reason);
            (up, seen)
        })
    };
    run_supervised_runtime(states.as_ref(), &stop, artifacts, deps);
    let (up, (installed_while_running, enforces_while_running, journal_while_running)) =
        watcher.join().expect("watcher thread");
    assert!(up, "the runtime never came up (blocked: {blocked})");

    let installed_after = lock(&kernel.installed).clone();
    let states = lock(&states.0).clone();
    Run {
        installed_while_running,
        enforces_while_running,
        journal_while_running,
        installed_after,
        teardowns: kernel.teardowns.load(Ordering::SeqCst),
        journal: journal.seen(),
        states,
    }
}

fn assert_dns(row: &str, expected: Disposition, run: &Run) {
    let restored = run.journal.contains(&"dns-restored");
    match expected {
        Disposition::Remove => assert!(
            restored,
            "{row}: DNS was not handed back: {:?}",
            run.journal
        ),
        Disposition::Keep | Disposition::Reconcile => {
            assert!(!restored, "{row}: DNS was handed back: {:?}", run.journal);
        }
    }
}

fn assert_filters(row: &str, expected: Disposition, run: &Run) {
    match expected {
        Disposition::Remove => {
            assert!(run.installed_after.is_empty(), "{row}: filters left");
            assert_eq!(run.teardowns, 1, "{row}");
        }
        Disposition::Keep => {
            assert_eq!(run.installed_after, run.installed_while_running, "{row}");
            assert_eq!(run.teardowns, 0, "{row}");
        }
        Disposition::Reconcile => unreachable!("{row}: a stop does not re-plan"),
    }
}

#[test]
fn the_runtime_carries_out_the_stop_rows_and_a_blocked_start() {
    assert_eq!(TEARDOWN_ORDER[0], TeardownStep::RestoreDns);

    for reason in [StopReason::ServiceStop, StopReason::MachineShutdown] {
        let row = format!("{reason:?}");
        let run = run(false, Vec::new(), reason);
        let want = expected_after(LifecycleEdge::Stop(reason), ARMED);

        assert!(
            !run.installed_while_running.is_empty(),
            "{row}: nothing applied"
        );
        assert_eq!(
            run.states.last(),
            Some(&ServiceRuntimeState::Stopped),
            "{row}"
        );
        assert_dns(&row, want.dns_redirect, &run);
        assert_filters(&row, want.user_filters, &run);
        // DNS first, then the filters.
        if let (Some(dns), Some(filters)) = (
            run.journal.iter().position(|s| *s == "dns-restored"),
            run.journal.iter().position(|s| *s == "filters-removed"),
        ) {
            assert!(dns < filters, "{row}: {:?}", run.journal);
        }
    }

    // A start that cannot run applies nothing, takes nothing of the dead
    // instance off and never points DNS at a listener. Its stop is a stop.
    let dead_instance = vec![plan_of(&user())];
    let run = run(true, dead_instance.clone(), StopReason::ServiceStop);
    let want = expected_after(LifecycleEdge::BlockedStart, ARMED);
    assert!(run.states.contains(&ServiceRuntimeState::RecoveryRequired));
    assert!(!run.states.contains(&ServiceRuntimeState::Running));
    assert_eq!(run.enforces_while_running, 0, "a blocked start applied");
    assert_eq!(want.user_filters, Disposition::Keep);
    assert_eq!(
        run.installed_while_running, dead_instance,
        "a blocked start removed filters"
    );
    assert_eq!(want.dns_redirect, Disposition::Remove);
    assert!(
        run.journal_while_running.is_empty(),
        "a blocked start touched DNS: {:?}",
        run.journal_while_running
    );
}
