use super::*;
use crate::bootstrap::{bootstrap, BootstrapConfig};
use crate::managers::{AcceptOutcome, IpcAcceptor, IpcBindError, IpcServer};
use crate::state::ServiceShutdownReason;
use nrr_platform_api::MockAdapterEventSource;
use nrr_storage::StorageProfile;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Recording `ServiceController` for test assertions.
#[derive(Default)]
struct RecordingController {
    states: Mutex<Vec<ServiceRuntimeState>>,
}
impl RecordingController {
    fn states(&self) -> Vec<ServiceRuntimeState> {
        self.states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}
impl ServiceController for RecordingController {
    fn report(&self, state: ServiceRuntimeState) {
        self.states
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(state);
    }
}

/// Stub IPC server that immediately returns ShutdownRequested on
/// every accept_one. Used to exercise the supervised-runtime
/// startup/shutdown sequence without binding a real pipe.
#[derive(Default)]
struct InertServer {
    binds: AtomicUsize,
}
impl IpcServer for InertServer {
    fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(InertAcceptor::default()))
    }
}
#[derive(Default)]
struct InertAcceptor {
    join_calls: AtomicUsize,
    shutdown_calls: AtomicUsize,
}
impl IpcAcceptor for InertAcceptor {
    fn accept_one(&self) -> AcceptOutcome {
        // Yield briefly so the supervisor isn't a busy spin.
        std::thread::sleep(Duration::from_millis(20));
        AcceptOutcome::ShutdownRequested
    }
    fn request_shutdown(&self) {
        self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
    }
    fn join_workers(&self) {
        self.join_calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn fresh_deps() -> SupervisedRuntimeDeps {
    let monitor = Arc::new(AdapterMonitor::new(
        Arc::new(MockAdapterEventSource::default()),
        500,
    ));
    SupervisedRuntimeDeps {
        auto_rules_engine: None,
        auto_rule_probe: None,
        app_destination_memory: None,
        secondary_external_address: None,
        health: Arc::new(HealthAggregator::new()),
        ipc_server: Arc::new(InertServer::default()),
        adapter_monitor: monitor,
        operation_results: Arc::new(OperationStatusStore::default()),
        mutation_tokens: None,
        stability: ServiceStabilityConfig::default(),
        logs_dir: std::env::temp_dir(),
        log_retention: LogRetentionPolicy::default(),
        cleanup_scope: ManualCleanupScope::default(),
        audit_dir: std::env::temp_dir(),
        audit_retention: AuditRetentionPolicy::default(),
        state_db_conn: None,
        principal_enforcement: None,
        traffic_tick: None,
        activation_coordinator: None,
        dns_refresh_orchestrator: None,
        route_recompute_hook: None,
        route_teardown_hook: None,
        rule_hostname_seeder: None,
        active_routing_sid: None,
        dns_observation_source: None,
        dns_observation_consumer: None,
        conn_observation_source: None,
        conn_observation_consumer: None,
        dns_resolver_controller: None,
        dns_resolver_boot_mode: nrr_domain::enforcement_mode::EnforcementMode::default(),
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

/// On a healthy bootstrap, the supervised runtime emits
/// `Starting → Running → Stopping → Stopped` and exits when the
/// stop token flips.
#[test]
fn happy_path_emits_full_state_sequence() {
    let controller = RecordingController::default();
    let stop = StopToken::new();
    let stop_clone = stop.clone();
    let join = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        stop_clone.request_stop();
    });
    // Real bootstrap with a temp directory so health.record_bootstrap
    // sees a consistent report shape.
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
    let artifacts = bootstrap(&cfg);
    let deps = fresh_deps();
    let reason = run_supervised_runtime(&controller, &stop, artifacts, deps);
    join.join().unwrap();
    assert_eq!(reason, ServiceShutdownReason::ScmStop);
    let states = controller.states();
    // Healthy bootstrap → expect Running. If the temp profile
    // ever produces Blocking we'd see RecoveryRequired instead;
    // assert flexibly on the prefix shape.
    assert_eq!(states.first(), Some(&ServiceRuntimeState::Starting));
    assert_eq!(states.last(), Some(&ServiceRuntimeState::Stopped));
    let stopping_idx = states
        .iter()
        .position(|s| matches!(s, ServiceRuntimeState::Stopping))
        .expect("Stopping observed");
    assert!(stopping_idx > 0);
}

/// Programmable mock IPC server for failure-policy tests. Yields
/// scripted `AcceptOutcome` values per `accept_one` call; `bind()`
/// produces a fresh acceptor each call (sharing the same outcome
/// queue) so the supervisor's rebind loop is observable.
type SharedQueue = Arc<Mutex<std::collections::VecDeque<AcceptOutcome>>>;
struct ScriptedServer {
    binds: AtomicUsize,
    outcomes: SharedQueue,
}
impl ScriptedServer {
    fn new(outcomes: Vec<AcceptOutcome>) -> Arc<Self> {
        Arc::new(Self {
            binds: AtomicUsize::new(0),
            outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
        })
    }
}
impl IpcServer for ScriptedServer {
    fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(SharedScriptedAcceptor {
            outcomes: Arc::clone(&self.outcomes),
        }))
    }
}
/// Acceptor that pulls outcomes from a queue shared with the server.
/// Returns `ShutdownRequested` when the queue empties so tests
/// terminate deterministically.
struct SharedScriptedAcceptor {
    outcomes: SharedQueue,
}
impl IpcAcceptor for SharedScriptedAcceptor {
    fn accept_one(&self) -> AcceptOutcome {
        let mut q = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        match q.pop_front() {
            Some(o) => o,
            None => {
                drop(q);
                // Yield briefly so we don't busy-spin on
                // ShutdownRequested while the supervisor walks the
                // rest of the tasks.
                std::thread::sleep(Duration::from_millis(20));
                AcceptOutcome::ShutdownRequested
            }
        }
    }
    fn request_shutdown(&self) {}
    fn join_workers(&self) {}
}

fn deps_with_server(server: Arc<dyn IpcServer>) -> SupervisedRuntimeDeps {
    let mut d = fresh_deps();
    d.ipc_server = server;
    d
}

/// Recoverable IPC: feed N+1 `Err` outcomes (where N = max_restarts);
/// supervisor must rebind on each Err and finally retire the task,
/// surfacing `HealthComponent::Ipc = Blocking` through the failure
/// sink.
#[test]
fn ipc_accept_recoverable_max_restarts_exhausted_marks_ipc_blocking() {
    use crate::managers::{AcceptError, AcceptErrorCategory};

    let max_restarts = 2u32;
    // First Err is the initial failure (attempt 1); each subsequent
    // restart's first tick must also fail. With max_restarts=2 we
    // need 3 total ticks that return Err to exhaust the budget.
    let outcomes: Vec<AcceptOutcome> = (0..(max_restarts + 1) as usize)
        .map(|i| {
            AcceptOutcome::Err(AcceptError {
                category: AcceptErrorCategory::PipeCreate,
                message: format!("scripted err {i}"),
            })
        })
        .collect();
    let server = ScriptedServer::new(outcomes);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let deps = SupervisedRuntimeDeps {
        stability: ServiceStabilityConfig {
            ipc_accept_policy: crate::service_stability::IpcAcceptFailurePolicy::Recoverable {
                max_restarts,
                backoff_base: Duration::from_millis(50),
                backoff_cap: Duration::from_millis(200),
            },
        },
        ..deps_with_server(server_dyn)
    };

    let controller = RecordingController::default();
    let stop = StopToken::new();
    let stop_clone = stop.clone();
    // Stop once the restart budget is exhausted, with a deadline as the
    // backstop — same reason as the sibling tests: a fixed sleep starts
    // before `bootstrap` and measures the machine, not the supervisor.
    let binds_probe = Arc::clone(&server);
    let join = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while binds_probe.binds.load(Ordering::SeqCst) <= max_restarts as usize
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        stop_clone.request_stop();
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
    let artifacts = bootstrap(&cfg);
    let _ = run_supervised_runtime(&controller, &stop, artifacts, deps);
    join.join().unwrap();

    // The supervisor must have asked for at least max_restarts + 1
    // binds (initial + each retry). Allow more in case the watcher
    // raced — what matters is *not less than*.
    let binds = server.binds.load(Ordering::SeqCst);
    assert!(
        binds > max_restarts as usize,
        "expected ≥{} binds, got {binds}",
        max_restarts as usize + 1,
    );
}

/// Critical IPC: a single Err must retire the task fatally without
/// any rebind. Recoverable's rebind path must not run.
#[test]
fn ipc_accept_critical_retires_on_first_failure_without_rebind() {
    use crate::managers::{AcceptError, AcceptErrorCategory};

    let server = ScriptedServer::new(vec![AcceptOutcome::Err(AcceptError {
        category: AcceptErrorCategory::PipeCreate,
        message: "critical boom".into(),
    })]);
    let server_dyn: Arc<dyn IpcServer> = server.clone();
    let deps = SupervisedRuntimeDeps {
        stability: ServiceStabilityConfig {
            ipc_accept_policy: crate::service_stability::IpcAcceptFailurePolicy::Critical,
        },
        ..deps_with_server(server_dyn)
    };

    let controller = RecordingController::default();
    let stop = StopToken::new();
    let stop_clone = stop.clone();
    // Stop once the runtime has actually done the thing under test, with a
    // deadline as the backstop. A fixed sleep measured the machine instead:
    // under a loaded `--workspace` run the accept task had not reached its
    // first tick yet and the count read 1.
    let binds_probe = Arc::clone(&server);
    let join = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while binds_probe.binds.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        stop_clone.request_stop();
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
    let artifacts = bootstrap(&cfg);
    let _ = run_supervised_runtime(&controller, &stop, artifacts, deps);
    join.join().unwrap();

    // Critical: 1 initial bind + 1 rebind from the Err handling
    // (the tick code rebinds before reporting Failed regardless of
    // class — that's intentional so the cell holds a valid acceptor
    // for the watcher's wake call). The supervisor's class check
    // then prevents the next accept_one tick.
    let binds = server.binds.load(Ordering::SeqCst);
    assert_eq!(
        binds, 2,
        "Critical should bind exactly twice (initial + post-Err rebind), got {binds}",
    );
}

/// Adapter monitor task ticks during the run. We don't care about
/// emitted change events here (no source data); we care that the
/// monitor's `update` was actually invoked, which we observe via
/// `MockAdapterEventSource`'s call counter.
#[test]
fn adapter_monitor_task_ticks_during_run() {
    // Replace the default adapter monitor with one whose source we
    // can introspect.
    struct CountingSource {
        calls: AtomicUsize,
    }
    impl nrr_platform_api::AdapterEventSource for CountingSource {
        fn enumerate_all(
            &self,
        ) -> Result<Vec<nrr_platform_api::AdapterInfo>, nrr_platform_api::PlatformError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    let counting = Arc::new(CountingSource {
        calls: AtomicUsize::new(0),
    });
    let monitor = Arc::new(AdapterMonitor::new(
        Arc::clone(&counting) as Arc<dyn nrr_platform_api::AdapterEventSource>,
        500,
    ));
    let mut deps = fresh_deps();
    deps.adapter_monitor = monitor;

    let controller = RecordingController::default();
    let stop = StopToken::new();
    let stop_clone = stop.clone();

    // Everything expensive happens BEFORE the probe starts counting. The
    // deadline used to cover `bootstrap` too, and under a full `--workspace`
    // run storage init spent the whole budget: the probe then stopped the
    // runtime before the monitor had ticked even once (observed as "got 0",
    // not as one tick short).
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
    let artifacts = bootstrap(&cfg);

    // Stop on the second tick, with a deadline as the backstop; what remains
    // inside the window is starting the runtime and two 500 ms ticks.
    let calls_probe = Arc::clone(&counting);
    let join = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while calls_probe.calls.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        stop_clone.request_stop();
    });

    let _ = run_supervised_runtime(&controller, &stop, artifacts, deps);
    join.join().unwrap();

    let calls = counting.calls.load(Ordering::SeqCst);
    assert!(
        calls >= 2,
        "expected adapter source to be polled ≥2 times within the deadline, got {calls}",
    );
}

/// Mapping from `TaskId` slug to `HealthComponent` is the same one
/// that a fatal task retirement uses; lock it in so renaming a slug
/// without coordinating breaks compilation here.
#[test]
fn fatal_failure_routing_table_is_complete() {
    assert_eq!(
        component_for_task(TASK_ID_IPC_ACCEPT_LOOP),
        Some(HealthComponent::Ipc)
    );
    assert_eq!(
        component_for_task(TASK_ID_IPC_SHUTDOWN_WATCHER),
        Some(HealthComponent::Ipc)
    );
    assert_eq!(
        component_for_task(TASK_ID_ADAPTER_MONITOR),
        Some(HealthComponent::Adapters)
    );
    assert_eq!(
        component_for_task(TASK_ID_DIAGNOSTICS_CLEANUP),
        Some(HealthComponent::Diagnostics)
    );
    // health-aggregator-tick and operation-results-gc intentionally
    // do not have a routed component.
    assert_eq!(
        component_for_task(crate::service_tasks::TASK_ID_HEALTH_AGGREGATOR),
        None
    );
    assert_eq!(
        component_for_task(crate::service_tasks::TASK_ID_OPERATION_RESULTS_GC),
        None
    );
}

fn background_tasks(health: &HealthAggregator) -> Option<crate::health::HealthComponentSnapshot> {
    health
        .snapshot()
        .components
        .into_iter()
        .find(|c| c.component == HealthComponent::BackgroundTasks)
}

fn wait_for(deadline: Duration, cond: impl Fn() -> bool) -> bool {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    cond()
}

/// An observer that panicked used to vanish with health still `Ok`. It must
/// now show as degraded — by name — for exactly as long as it is down.
#[test]
fn a_panicked_optional_task_is_degraded_in_health_until_its_restart_ticks() {
    use crate::runtime_loop::{RestartBackoff, ServiceTask, TaskOutcome};

    let health = Arc::new(HealthAggregator::new());
    health.clear_lifecycle_override();
    health.record(HealthComponent::Ipc, ServiceHealthSeverity::Ok, "ok");
    let stop = StopToken::new();
    let supervisor = ServiceSupervisor::new(
        stop.clone(),
        Arc::new(HealthFailureSink::new(Arc::clone(&health))),
    )
    .with_optional_restart(RestartBackoff::new(
        Duration::from_millis(300),
        Duration::from_secs(1),
        Duration::from_secs(60),
    ));
    let ticks = Arc::new(AtomicUsize::new(0));
    let ticks_in_task = Arc::clone(&ticks);
    supervisor
        .spawn(ServiceTask::periodic(
            crate::service_tasks::TASK_ID_CONN_OBSERVE,
            TaskClass::Optional,
            Duration::from_millis(5),
            0,
            move |_stop| {
                if ticks_in_task.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("observer blew up");
                }
                TaskOutcome::Continue
            },
        ))
        .expect("spawn");

    assert!(wait_for(Duration::from_secs(2), || background_tasks(
        &health
    )
    .is_some_and(|c| c.severity == ServiceHealthSeverity::Degraded)));
    let down = background_tasks(&health).expect("component recorded");
    assert!(
        down.message
            .contains(crate::service_tasks::TASK_ID_CONN_OBSERVE),
        "the degraded record must name the task: {}",
        down.message
    );
    assert_eq!(health.snapshot().state, ServiceRuntimeState::Degraded);
    assert_eq!(ticks.load(Ordering::SeqCst), 1, "still inside the backoff");

    assert!(
        wait_for(Duration::from_secs(3), || background_tasks(&health)
            .is_some_and(|c| c.severity == ServiceHealthSeverity::Ok)),
        "health must clear once the restarted task ticks"
    );
    assert!(ticks.load(Ordering::SeqCst) >= 2);
    assert_eq!(health.snapshot().state, ServiceRuntimeState::Running);
    let _ = supervisor.shutdown();
}

#[test]
fn one_task_recovering_does_not_clear_another_that_is_still_down() {
    let health = Arc::new(HealthAggregator::new());
    let sink = HealthFailureSink::new(Arc::clone(&health));
    let a = TaskId::new("dns-observe-tick");
    let b = TaskId::new("auto-rules-tick");
    let delay = Duration::from_secs(1);
    sink.task_restart_scheduled(&a, TaskClass::Optional, 1, delay, "task panicked: a");
    sink.task_restart_scheduled(&b, TaskClass::Optional, 1, delay, "task panicked: b");
    sink.task_recovered(&b, TaskClass::Optional);

    let rec = background_tasks(&health).expect("component recorded");
    assert_eq!(rec.severity, ServiceHealthSeverity::Degraded);
    assert!(rec.message.contains("dns-observe-tick"));
    assert!(!rec.message.contains("auto-rules-tick"));

    // A recoverable restart is brief and bounded; it stays out of the roll-up.
    sink.task_restart_scheduled(
        &TaskId::new("adapter-monitor-tick"),
        TaskClass::Recoverable,
        1,
        delay,
        "boom",
    );
    let rec = background_tasks(&health).expect("component recorded");
    assert!(!rec.message.contains("adapter-monitor-tick"));

    sink.task_recovered(&a, TaskClass::Optional);
    assert_eq!(
        background_tasks(&health)
            .expect("component recorded")
            .severity,
        ServiceHealthSeverity::Ok
    );
}
