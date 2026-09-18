use super::*;
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::managers::{AcceptError, AcceptErrorCategory};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn the_automatic_pass_runs_on_the_users_window_and_not_at_all_without_consent() {
    let off = AutoProbeCadence {
        enabled: false,
        repeat: Duration::from_secs(300),
    };
    let on = AutoProbeCadence {
        enabled: true,
        repeat: Duration::from_secs(300),
    };
    let now = Instant::now();

    assert!(
        !auto_probe_is_due(off, None, now),
        "no opt-in, no connections leaving the machine"
    );
    assert!(auto_probe_is_due(on, None, now), "first pass is due");
    assert!(
        !auto_probe_is_due(on, Some(now), now + Duration::from_secs(299)),
        "inside the window the pass waits"
    );
    assert!(auto_probe_is_due(
        on,
        Some(now),
        now + Duration::from_secs(300)
    ));
}

/// A host that has never been measured overrides the window. Until it is
/// probed it carries "not checked on the main route", and that is exactly
/// how an address the main link serves perfectly well reads as a problem —
/// so a fresh candidate must not wait out up to five minutes for its first
/// verdict.
#[test]
fn a_candidate_the_last_pass_did_not_cover_probes_at_once() {
    let on = AutoProbeCadence {
        enabled: true,
        repeat: Duration::from_secs(300),
    };
    let start = Instant::now();
    let just_probed = Some(start);
    let inside_window = start + Duration::from_secs(30);

    assert!(
        !auto_probe_should_run(on, just_probed, inside_window, 1, false),
        "the same host inside the window is not re-measured"
    );
    assert!(
        auto_probe_should_run(on, just_probed, inside_window, 2, true),
        "a host the last pass never saw has no verdict at all"
    );
}

/// The override is not a way around the switch: with the automatic pass
/// turned off there is nothing to run, new candidate or not.
#[test]
fn a_fresh_candidate_does_not_start_a_pass_the_user_turned_off() {
    let off = AutoProbeCadence {
        enabled: false,
        repeat: Duration::from_secs(300),
    };
    assert!(!auto_probe_should_run(off, None, Instant::now(), 3, true));
}

/// The defect this pins: the window used to advance on every DUE tick,
/// probed or not. The inbox is empty almost all the time, so a suggestion
/// appearing between two due marks waited out a whole window — and while it
/// waited it carried no main-link verdict, which is what makes a shared CDN
/// that answers perfectly well look unreachable and land on the offer list.
#[test]
fn an_empty_inbox_does_not_spend_the_probe_window() {
    let on = AutoProbeCadence {
        enabled: true,
        repeat: Duration::from_secs(300),
    };
    let start = Instant::now();

    // Ticks every 10 s. Nothing is waiting for the first four minutes.
    let mut last: Option<Instant> = None;
    for step in 0..24 {
        let now = start + Duration::from_secs(step * 10);
        assert!(
            !auto_probe_should_run(on, last, now, 0, false),
            "an empty inbox never runs a pass"
        );
        if auto_probe_should_run(on, last, now, 0, false) {
            last = Some(now);
        }
    }

    // The moment a suggestion appears the pass runs — it did not have to
    // wait for a window that empty ticks had already eaten.
    let appeared = start + Duration::from_secs(240);
    assert!(auto_probe_should_run(on, last, appeared, 1, false));
    last = Some(appeared);

    // And having run, it holds the user's window like before.
    // The same candidate the pass already covered, so only the clock can
    // release it.
    assert!(!auto_probe_should_run(
        on,
        last,
        appeared + Duration::from_secs(299),
        1,
        false
    ));
    assert!(auto_probe_should_run(
        on,
        last,
        appeared + Duration::from_secs(300),
        1,
        false
    ));
}

fn fresh_health() -> Arc<HealthAggregator> {
    Arc::new(HealthAggregator::new())
}

#[test]
fn health_aggregator_task_has_correct_shape() {
    let task = build_health_aggregator_task(fresh_health());
    assert_eq!(task.id.0, TASK_ID_HEALTH_AGGREGATOR);
    assert_eq!(task.class, TaskClass::Recoverable);
    assert_eq!(task.interval, Some(HEALTH_AGGREGATOR_INTERVAL));
    assert_eq!(task.max_restarts, RECOVERABLE_DEFAULT_MAX_RESTARTS);
}

#[test]
fn route_reconcile_safety_task_shape_and_fires_hook_each_tick() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_hook = Arc::clone(&calls);
    let hook: crate::supervised_runtime::RouteRecomputeHook = Arc::new(move || {
        calls_in_hook.fetch_add(1, Ordering::SeqCst);
    });
    let mut task = build_route_reconcile_safety_task(hook);
    assert_eq!(task.id.0, TASK_ID_ROUTE_RECONCILE_SAFETY);
    assert_eq!(task.class, TaskClass::Recoverable);
    assert_eq!(task.interval, Some(ROUTE_RECONCILE_SAFETY_INTERVAL));
    assert_eq!(task.max_restarts, RECOVERABLE_DEFAULT_MAX_RESTARTS);
    // Each tick drives exactly one idempotent recompute.
    let stop = StopToken::new();
    assert_eq!((task.tick)(&stop), TaskOutcome::Continue);
    assert_eq!((task.tick)(&stop), TaskOutcome::Continue);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn diagnostics_cleanup_task_is_optional_with_one_hour_interval() {
    let task = build_diagnostics_cleanup_task(
        PathBuf::from("/tmp/nonexistent"),
        LogRetentionPolicy::default(),
        ManualCleanupScope::default(),
    );
    assert_eq!(task.id.0, TASK_ID_DIAGNOSTICS_CLEANUP);
    assert_eq!(task.class, TaskClass::Optional);
    assert_eq!(task.interval, Some(DIAGNOSTICS_CLEANUP_INTERVAL));
}

#[test]
fn operation_results_gc_task_runs_gc_on_underlying_store() {
    let store = Arc::new(OperationStatusStore::default());
    let mut task = build_operation_results_gc_task(Arc::clone(&store), None);
    // Tick once to verify it doesn't panic on an empty store.
    let stop = StopToken::new();
    let outcome = (task.tick)(&stop);
    assert_eq!(outcome, TaskOutcome::Continue);
    assert_eq!(task.id.0, TASK_ID_OPERATION_RESULTS_GC);
    assert_eq!(task.class, TaskClass::Optional);
}

#[test]
fn the_housekeeping_tick_collects_expired_confirmation_tokens() {
    // A dry-run mints its token without elevation, outside the mutation
    // queue and without a rate limit, parking a payload until confirmed.
    // Nothing collected them, so a client looping dry-runs grew the
    // service's memory for as long as it ran.
    use crate::ipc_handlers::mutation_token_store::MutationTokenStore;
    let store = Arc::new(OperationStatusStore::default());
    let tokens = Arc::new(MutationTokenStore::new());
    tokens.issue(
        crate::ipc_handlers::mutation_token_store::StoredMutation {
            kind: crate::ipc_handlers::payloads::MutationKind::RulesUpdate,
            payload: serde_json::json!({}),
            correlation_id: None,
            issuer_sid: "S-1-A".into(),
            caller_is_elevated: false,
        },
        Instant::now() - std::time::Duration::from_secs(1),
    );
    assert_eq!(tokens.len(), 1);

    let mut task = build_operation_results_gc_task(Arc::clone(&store), Some(Arc::clone(&tokens)));
    let stop = StopToken::new();
    let _ = (task.tick)(&stop);
    assert_eq!(tokens.len(), 0, "the expired token must be collected");
}

#[test]
fn dns_refresh_task_has_optional_class_and_60s_interval() {
    use nrr_domain::decision_lookup::FreshnessThresholds;
    use nrr_platform_api::dns::MockDnsResolver;
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::{CacheRepository, MigrationRunner};
    use nrr_storage::store::SqliteCacheStore;
    use rusqlite::Connection;

    let resolver: Arc<dyn nrr_platform_api::dns::DnsResolverPort> =
        Arc::new(MockDnsResolver::new());
    let conn = Connection::open_in_memory().expect("in-memory");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let store = SqliteCacheStore::new(
        runner.into_connection(),
        FreshnessThresholds::default_production(),
    );
    let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
    let orch = Arc::new(crate::dns_refresh::DnsRefreshOrchestrator::new(
        resolver, cache,
    ));

    let mut task = build_dns_refresh_task(Arc::clone(&orch), None);
    let stop = StopToken::new();
    let outcome = (task.tick)(&stop);
    assert_eq!(outcome, TaskOutcome::Continue);
    assert_eq!(task.id.0, TASK_ID_DNS_REFRESH);
    assert_eq!(task.class, TaskClass::Optional);
    assert_eq!(task.interval, Some(DNS_REFRESH_INTERVAL));
}

/// Mock IPC server / acceptor for the bundle tests. The server hands
/// out acceptors that return a programmable sequence of `AcceptOutcome`
/// values, then loop on `ShutdownRequested` so tests can drive the
/// state machine without real Win32 calls.
#[derive(Default)]
struct MockServer {
    binds: AtomicUsize,
    // Pre-programmed sequence. Each acceptor pops items as it ticks;
    // when empty, returns ShutdownRequested.
    scripted: Mutex<Vec<AcceptOutcome>>,
    bind_should_fail: AtomicUsize, // remaining bind failures
    // Shared with every acceptor this server hands out, so a test can see
    // what the tasks did to an acceptor it never holds itself.
    shutdown_calls: Arc<AtomicUsize>,
    join_calls: Arc<AtomicUsize>,
}

impl MockServer {
    fn with_outcomes(outs: Vec<AcceptOutcome>) -> Arc<Self> {
        Arc::new(Self {
            binds: AtomicUsize::new(0),
            scripted: Mutex::new(outs),
            bind_should_fail: AtomicUsize::new(0),
            shutdown_calls: Arc::new(AtomicUsize::new(0)),
            join_calls: Arc::new(AtomicUsize::new(0)),
        })
    }
    fn fail_first_bind(self: &Arc<Self>, count: usize) {
        self.bind_should_fail.store(count, Ordering::SeqCst);
    }
}

impl IpcServer for MockServer {
    fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        let prev = self.bind_should_fail.load(Ordering::SeqCst);
        if prev > 0 {
            self.bind_should_fail.store(prev - 1, Ordering::SeqCst);
            return Err(IpcBindError::Other("scripted bind failure".into()));
        }
        let drained = std::mem::take(&mut *self.scripted.lock().unwrap_or_else(|p| p.into_inner()));
        Ok(Box::new(MockAcceptor {
            outcomes: Mutex::new(drained.into_iter().collect()),
            join_calls: Arc::clone(&self.join_calls),
            shutdown_calls: Arc::clone(&self.shutdown_calls),
        }))
    }
}

struct MockAcceptor {
    outcomes: Mutex<std::collections::VecDeque<AcceptOutcome>>,
    join_calls: Arc<AtomicUsize>,
    shutdown_calls: Arc<AtomicUsize>,
}
impl IpcAcceptor for MockAcceptor {
    fn accept_one(&self) -> AcceptOutcome {
        let mut g = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        g.pop_front().unwrap_or(AcceptOutcome::ShutdownRequested)
    }
    fn request_shutdown(&self) {
        self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
    }
    fn join_workers(&self) {
        self.join_calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// The accept loop cannot wake itself: it is parked in the transport's
/// blocking accept. The watcher is the thread that CAN notice a stop, and it
/// has to do the waking from `on_stop` — the runner exits the loop without a
/// further tick when the stop lands during its sleep, which is the usual
/// case. Before this, a stop left the accept loop parked for the whole
/// budget and the supervisor detached it.
#[test]
fn the_watchers_teardown_wakes_the_accept_loop_and_the_accept_task_drains() {
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let mut bundle = build_ipc_accept_task_bundle(
        server_dyn,
        fresh_health(),
        &ServiceStabilityConfig::default(),
    )
    .expect("bind succeeds");

    let watcher_teardown = bundle
        .shutdown_watcher
        .on_stop
        .take()
        .expect("the watcher must carry a teardown hook");
    watcher_teardown();
    assert_eq!(
        server.shutdown_calls.load(Ordering::SeqCst),
        1,
        "the watcher's teardown must ask the acceptor to unblock"
    );

    let accept_teardown = bundle
        .accept
        .on_stop
        .take()
        .expect("the accept task must carry a teardown hook");
    accept_teardown();
    assert_eq!(
        server.join_calls.load(Ordering::SeqCst),
        1,
        "the accept task's teardown joins the connection workers once"
    );
}

#[test]
fn ipc_bundle_recoverable_policy_maps_to_recoverable_task_class() {
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig {
        ipc_accept_policy: IpcAcceptFailurePolicy::Recoverable {
            max_restarts: 7,
            backoff_base: Duration::from_millis(100),
            backoff_cap: Duration::from_secs(5),
        },
    };
    let bundle =
        build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind succeeds");
    assert_eq!(bundle.accept.id.0, TASK_ID_IPC_ACCEPT_LOOP);
    assert_eq!(bundle.accept.class, TaskClass::Recoverable);
    assert_eq!(bundle.accept.max_restarts, 7);
    assert_eq!(bundle.accept.interval, None);
    assert_eq!(bundle.shutdown_watcher.id.0, TASK_ID_IPC_SHUTDOWN_WATCHER);
    assert_eq!(bundle.shutdown_watcher.class, TaskClass::Optional);
    assert_eq!(server.binds.load(Ordering::SeqCst), 1);
}

#[test]
fn ipc_bundle_critical_policy_maps_to_critical_task_class() {
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig {
        ipc_accept_policy: IpcAcceptFailurePolicy::Critical,
    };
    let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    assert_eq!(bundle.accept.class, TaskClass::Critical);
    assert_eq!(bundle.accept.max_restarts, 0);
}

#[test]
fn ipc_bundle_clamps_huge_max_restarts_into_u8() {
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig {
        ipc_accept_policy: IpcAcceptFailurePolicy::Recoverable {
            max_restarts: 10_000,
            backoff_base: Duration::from_millis(100),
            backoff_cap: Duration::from_secs(5),
        },
    };
    let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    assert_eq!(bundle.accept.max_restarts, u8::MAX);
}

#[test]
fn ipc_bundle_carries_backoff_schedule_from_recoverable_policy() {
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig {
        ipc_accept_policy: IpcAcceptFailurePolicy::Recoverable {
            max_restarts: 30,
            backoff_base: Duration::from_millis(250),
            backoff_cap: Duration::from_secs(15),
        },
    };
    let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    assert_eq!(
        bundle.accept.backoff,
        BackoffSchedule::new(Duration::from_millis(250), Duration::from_secs(15))
    );
    // Sanity: delay_for_attempt actually reflects the wired values.
    assert_eq!(
        bundle.accept.backoff.delay_for_attempt(1),
        Duration::from_millis(250)
    );
    assert_eq!(
        bundle.accept.backoff.delay_for_attempt(100),
        Duration::from_secs(15)
    );
}

#[test]
fn ipc_bundle_uses_default_backoff_for_critical_policy() {
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig {
        ipc_accept_policy: IpcAcceptFailurePolicy::Critical,
    };
    let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    // Critical never uses the recoverable arm so the value is moot;
    // but we surface defaults rather than Duration::ZERO so logs /
    // telemetry have a sane value if anyone reads it.
    assert_eq!(bundle.accept.backoff, BackoffSchedule::default());
}

#[test]
fn ipc_bundle_propagates_initial_bind_error() {
    let server = MockServer::with_outcomes(vec![]);
    server.fail_first_bind(1);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig::default();
    let result = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg);
    assert!(matches!(result, Err(IpcBindError::Other(_))));
}

#[test]
fn ipc_accept_tick_returns_continue_on_connected() {
    let server = MockServer::with_outcomes(vec![AcceptOutcome::Connected]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig::default();
    let mut bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    let stop = StopToken::new();
    let outcome = (bundle.accept.tick)(&stop);
    assert_eq!(outcome, TaskOutcome::Continue);
}

#[test]
fn ipc_accept_tick_returns_done_on_shutdown_requested() {
    let server = MockServer::with_outcomes(vec![AcceptOutcome::ShutdownRequested]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig::default();
    let mut bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    let stop = StopToken::new();
    let outcome = (bundle.accept.tick)(&stop);
    assert_eq!(outcome, TaskOutcome::Done);
}

#[test]
fn ipc_accept_tick_short_circuits_when_stop_already_requested() {
    // Empty outcome script — if the tick read it, accept_one would
    // fall through to ShutdownRequested and then to Done. We want to
    // verify the explicit stop check at the start of the tick fires
    // before that, returning Done without calling accept_one.
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig::default();
    let mut bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    let stop = StopToken::new();
    stop.request_stop();
    let outcome = (bundle.accept.tick)(&stop);
    assert_eq!(outcome, TaskOutcome::Done);
}

#[test]
fn ipc_accept_tick_rebinds_on_err_and_returns_failed() {
    // First tick returns Err → tick rebinds → returns Failed.
    // Bind counter should go from 1 (initial) to 2 (rebind).
    let server = MockServer::with_outcomes(vec![AcceptOutcome::Err(AcceptError {
        category: AcceptErrorCategory::PipeCreate,
        message: "boom".into(),
    })]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig::default();
    let mut bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    let stop = StopToken::new();
    let outcome = (bundle.accept.tick)(&stop);
    assert!(matches!(outcome, TaskOutcome::Failed(_)));
    assert_eq!(server.binds.load(Ordering::SeqCst), 2);
}

#[test]
fn ipc_accept_tick_reports_blocking_when_rebind_fails() {
    let server = MockServer::with_outcomes(vec![AcceptOutcome::Err(AcceptError {
        category: AcceptErrorCategory::PipeCreate,
        message: "boom".into(),
    })]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig::default();
    let health = fresh_health();
    // Initial bind during bundle build must succeed; we arm the
    // failure for the rebind that will follow the Err outcome.
    let mut bundle =
        build_ipc_accept_task_bundle(server_dyn, Arc::clone(&health), &cfg).expect("first bind");
    server.fail_first_bind(1);
    let stop = StopToken::new();
    let outcome = (bundle.accept.tick)(&stop);
    assert!(matches!(outcome, TaskOutcome::Failed(_)));
    let snap = health.snapshot();
    let ipc = snap
        .components
        .iter()
        .find(|c| c.component == HealthComponent::Ipc)
        .expect("ipc component");
    assert_eq!(ipc.severity, ServiceHealthSeverity::Blocking);
    assert!(ipc.message.contains("rebind failed"));
}

#[test]
fn ipc_shutdown_watcher_returns_done_when_stop_fires() {
    let server = MockServer::with_outcomes(vec![]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let cfg = ServiceStabilityConfig::default();
    let mut bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
    let stop = StopToken::new();
    // Pre-stop: watcher returns Continue.
    assert_eq!((bundle.shutdown_watcher.tick)(&stop), TaskOutcome::Continue);
    stop.request_stop();
    // Post-stop: watcher returns Done.
    assert_eq!((bundle.shutdown_watcher.tick)(&stop), TaskOutcome::Done);
}

/// The join that makes application rules work at all: what the program
/// connected to becomes what the rule routes.
#[test]
fn an_observed_connection_becomes_a_destination_the_rule_can_route() {
    use crate::app_observation_lookup::AppObservationLookup;
    use nrr_platform_api::conn_observe::{
        ConnectionObservation, ConnectionProgress, ConnectionVerdict,
        MockConnectionObservationSource, TransportProtocol,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let source = Arc::new(MockConnectionObservationSource::new());
    let observed = |path: Option<&str>, ip: Ipv4Addr| ConnectionObservation {
        pid: 42,
        process_path: path.map(str::to_owned),
        user_sid: Some("unix:uid:1000".to_owned()),
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000),
        remote: SocketAddr::new(IpAddr::V4(ip), 443),
        verdict: ConnectionVerdict::Unknown,
        drop_filter_id: None,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    };
    source.push(observed(
        Some("/usr/bin/messenger"),
        Ipv4Addr::new(23, 10, 20, 154),
    ));
    // Nothing to attribute this one to: counted for nobody, or it would widen
    // every enabled app rule.
    source.push(observed(None, Ipv4Addr::new(203, 0, 113, 9)));

    let store = Arc::new(crate::app_observation_lookup::AppObservationStore::new());
    let wiring = AppObservationWiring {
        source: source.clone(),
        store: Arc::clone(&store),
    };

    assert_eq!(fold_observations(&wiring), 1);
    assert_eq!(
        store.ips_for_app("messenger"),
        vec![Ipv4Addr::new(23, 10, 20, 154)],
    );

    // A destination already known is not news: re-driving policy for it
    // would make every poll of a busy program a policy pass.
    source.push(observed(
        Some("/usr/bin/messenger"),
        Ipv4Addr::new(23, 10, 20, 154),
    ));
    assert_eq!(fold_observations(&wiring), 0);
}

/// The refresh pass reads the open connections and restamps only what the
/// store already holds.
#[test]
fn the_live_refresh_pass_restamps_held_destinations_only() {
    use crate::app_observation_lookup::AppObservationLookup;
    use nrr_platform_api::conn_observe::live::{LiveConnection, MockLiveConnectionSource};
    use std::net::Ipv4Addr;

    let store = Arc::new(crate::app_observation_lookup::AppObservationStore::new());
    store.record("/usr/bin/messenger", Ipv4Addr::new(203, 0, 113, 7));
    let source = Arc::new(MockLiveConnectionSource::default());
    source.set(vec![
        LiveConnection {
            process_path: "/usr/bin/messenger".to_string(),
            remote: Ipv4Addr::new(203, 0, 113, 7),
        },
        LiveConnection {
            process_path: "/usr/bin/messenger".to_string(),
            remote: Ipv4Addr::new(203, 0, 113, 99),
        },
    ]);
    let wiring = LiveConnectionRefreshWiring {
        source,
        store: Arc::clone(&store),
    };

    assert_eq!(refresh_live_destinations(&wiring), 1);
    assert_eq!(
        store.ips_for_app("messenger"),
        vec![Ipv4Addr::new(203, 0, 113, 7)],
        "an open connection to an unknown address teaches nothing"
    );
}

/// A resolution belongs to the machine, not to a user: every present
/// principal's rules must get a look at it, or one user's domain rule would
/// learn addresses and another's would not.
#[test]
fn an_observed_resolution_is_applied_for_every_present_principal() {
    use nrr_platform_api::active_principals::{ActivePrincipalError, ActivePrincipalSource};
    use nrr_platform_api::dns_observe::MockDnsObservationSource;
    use nrr_platform_api::enforcement::UserPrincipal;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    struct TwoUsers;
    impl ActivePrincipalSource for TwoUsers {
        fn active_principals(&self) -> Result<Vec<UserPrincipal>, ActivePrincipalError> {
            Ok(vec![
                UserPrincipal::from_linux_uid(1000),
                UserPrincipal::from_linux_uid(1001),
            ])
        }
        fn authority(&self) -> &'static str {
            "scripted"
        }
    }

    let source = Arc::new(MockDnsObservationSource::new());
    source.push("example.com", vec![Ipv4Addr::new(23, 10, 20, 138)]);

    let applied: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&applied);
    let wiring = DnsObservationWiring {
        source,
        consume_for: Arc::new(move |principal, observations| {
            assert_eq!(observations.len(), 1);
            recorder
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(principal.to_owned());
        }),
        principals: Arc::new(TwoUsers),
    };

    let mut task = build_dns_observation_task(wiring);
    let stop = crate::lifecycle::StopToken::new();
    (task.tick)(&stop);

    assert_eq!(
        *applied.lock().unwrap_or_else(|p| p.into_inner()),
        vec!["unix:uid:1000".to_owned(), "unix:uid:1001".to_owned()],
    );
}
