//! The IPC accept loop and the shutdown watcher that wakes it — the one pair of
//! tasks that share state, which is why they are built as a bundle.
//!
//! Split out of `service_tasks`; the code is unchanged.

use super::*;

// ── IPC accept loop + shutdown watcher ───────────────────────────────────────

/// Shared cell holding the currently-bound `IpcAcceptor`. Replaced
/// atomically when the accept tick rebinds after an `Err` outcome.
/// Both the accept tick (reads to call `accept_one`) and the shutdown
/// watcher (reads to call `request_shutdown`) hold an `Arc` of this cell.
struct IpcAcceptorCell {
    inner: Mutex<Arc<dyn IpcAcceptor>>,
}

impl IpcAcceptorCell {
    fn new(initial: Arc<dyn IpcAcceptor>) -> Self {
        Self {
            inner: Mutex::new(initial),
        }
    }

    /// Snapshot the currently-installed acceptor as an `Arc` clone.
    /// Cheap (one mutex acquire + Arc bump). The mutex is released
    /// before the caller invokes any blocking method on the acceptor.
    fn current(&self) -> Arc<dyn IpcAcceptor> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(&*g)
    }

    /// Replace the installed acceptor. Used by the accept tick after a
    /// successful rebind in response to `AcceptOutcome::Err`.
    fn replace(&self, new: Arc<dyn IpcAcceptor>) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        *g = new;
    }
}

/// Bundle returned by `build_ipc_accept_task_bundle`. The caller is
/// responsible for spawning **both** tasks on the supervisor — the
/// accept task on its own carries no shutdown affordance, because
/// `IpcAcceptor::accept_one` blocks indefinitely until a client connects
/// or `request_shutdown` is called.
pub struct IpcAcceptTaskBundle {
    pub accept: ServiceTask,
    pub shutdown_watcher: ServiceTask,
}

/// Build the IPC accept-loop and matching shutdown-watcher tasks.
///
/// `bind()` is called eagerly so a misconfigured security descriptor
/// surfaces here instead of deep inside the supervisor's first tick.
/// The resulting `IpcAcceptor` is shared with the watcher via an
/// `IpcAcceptorCell`; every successful rebind in response to
/// `AcceptOutcome::Err` updates the cell so the watcher always signals
/// the *current* listener.
///
/// `TaskClass` and `max_restarts` are derived from
/// `ServiceStabilityConfig.ipc_accept_policy`:
/// - `Recoverable { max_restarts, backoff_base, backoff_cap }` →
///   `Recoverable`, with `max_restarts` clamped into `u8` (the
///   supervisor's restart-attempt counter type) and a per-task
///   `BackoffSchedule` derived from `backoff_base` / `backoff_cap`.
/// - `Critical` → `Critical`, `max_restarts = 0`, default backoff
///   schedule (Critical ignores both, but the fields are populated for
///   telemetry consistency).
///
/// Per-task backoff: the supervisor uses
/// `(backoff_base × attempt).min(backoff_cap)` saturating instead of a
/// hardcoded `100 ms × attempt cap 1 s` schedule.
pub fn build_ipc_accept_task_bundle(
    server: Arc<dyn IpcServer>,
    health: Arc<HealthAggregator>,
    config: &ServiceStabilityConfig,
) -> Result<IpcAcceptTaskBundle, IpcBindError> {
    let (class, max_restarts, accept_backoff) = match &config.ipc_accept_policy {
        IpcAcceptFailurePolicy::Critical => (TaskClass::Critical, 0u8, BackoffSchedule::default()),
        IpcAcceptFailurePolicy::Recoverable {
            max_restarts,
            backoff_base,
            backoff_cap,
        } => {
            let clamped = (*max_restarts).min(u8::MAX as u32) as u8;
            (
                TaskClass::Recoverable,
                clamped,
                BackoffSchedule::new(*backoff_base, *backoff_cap),
            )
        }
    };

    // Eager bind — surfaces misconfiguration to the caller.
    let initial: Arc<dyn IpcAcceptor> = Arc::from(server.bind()?);
    let cell = Arc::new(IpcAcceptorCell::new(initial));

    health.record(
        HealthComponent::Ipc,
        ServiceHealthSeverity::Ok,
        "ipc accept loop bound",
    );

    // Surface the resolved schedule in NDJSON on every bundle build
    // (= service start + every full rebind cycle). Pairs with the
    // "service_stability_config loaded"
    // log emitted by `runtime_deps.rs` so an operator can confirm the
    // wiring end-to-end without provoking IPC failures.
    tracing::info!(
        target: "nrr::stability",
        task = TASK_ID_IPC_ACCEPT_LOOP,
        class = ?class,
        max_restarts,
        backoff_base_ms = u64::try_from(accept_backoff.base.as_millis())
            .unwrap_or(u64::MAX),
        backoff_cap_ms = u64::try_from(accept_backoff.cap.as_millis())
            .unwrap_or(u64::MAX),
        "ipc-accept-loop task scheduled with backoff",
    );

    // ── Accept task ─────────────────────────────────────────────────────
    let accept_cell = Arc::clone(&cell);
    let accept_server = Arc::clone(&server);
    let accept_health = Arc::clone(&health);
    let accept_tick = move |stop: &StopToken| {
        if stop.is_stop_requested() {
            // Drain the current acceptor's workers before exiting so
            // any in-flight request finishes cleanly.
            let acc = accept_cell.current();
            acc.request_shutdown();
            acc.join_workers();
            return TaskOutcome::Done;
        }

        let acc = accept_cell.current();
        match acc.accept_one() {
            AcceptOutcome::Connected | AcceptOutcome::Idle => TaskOutcome::Continue,
            AcceptOutcome::ShutdownRequested => {
                acc.join_workers();
                TaskOutcome::Done
            }
            AcceptOutcome::Err(err) => {
                accept_health.record(
                    HealthComponent::Ipc,
                    ServiceHealthSeverity::Degraded,
                    format!("ipc accept failed: {err}"),
                );
                // Drop our reference to the failed acceptor so the
                // worker handles can wind down. The cell still holds
                // one Arc — replace it after we get a fresh listener.
                drop(acc);
                match accept_server.bind() {
                    Ok(b) => {
                        accept_cell.replace(Arc::from(b));
                        // Returning `Failed` so the supervisor's policy
                        // decides whether to keep going (Recoverable)
                        // or retire (Critical / budget exhausted).
                        TaskOutcome::Failed(format!("accept failed: {err}; rebound"))
                    }
                    Err(rebind_err) => {
                        accept_health.record(
                            HealthComponent::Ipc,
                            ServiceHealthSeverity::Blocking,
                            format!("ipc rebind failed: {rebind_err}"),
                        );
                        TaskOutcome::Failed(format!(
                            "accept failed: {err}; rebind failed: {rebind_err}"
                        ))
                    }
                }
            }
        }
    };
    let accept = ServiceTask {
        id: TaskId::new(TASK_ID_IPC_ACCEPT_LOOP),
        class,
        // Event-driven: one tick = one accept_one call, which itself blocks
        // until a client connects or the shutdown event fires. Supervisor
        // sleeps a token 50 ms between ticks if interval is None — fine
        // here, since accept_one is the time-consuming step.
        interval: None,
        max_restarts,
        backoff: accept_backoff,
        tick: Box::new(accept_tick),
        // Draining on the way out, not inside a tick: whichever way the loop
        // ended, the workers get their signal and are joined once.
        on_stop: Some(Box::new({
            let cell = Arc::clone(&cell);
            move || {
                let acc = cell.current();
                acc.request_shutdown();
                acc.join_workers();
            }
        })),
    };

    // ── Shutdown watcher ────────────────────────────────────────────────
    // Why a second task exists at all: the accept task cannot wake itself. It is
    // parked in the transport's blocking accept, and nothing in its own thread
    // runs until a client connects. This one sleeps, so a stop reaches it
    // immediately — and it does the waking from `on_stop`, which is the only
    // place guaranteed to run (the loop exits without a further tick when the
    // stop arrives during the sleep, which is the usual case).
    let watcher_cell = Arc::clone(&cell);
    let watcher_stop_cell = Arc::clone(&cell);
    let watcher = ServiceTask::periodic(
        TASK_ID_IPC_SHUTDOWN_WATCHER,
        TaskClass::Optional,
        IPC_SHUTDOWN_WATCHER_INTERVAL,
        0,
        move |stop| {
            if stop.is_stop_requested() {
                let acc = watcher_cell.current();
                acc.request_shutdown();
                TaskOutcome::Done
            } else {
                TaskOutcome::Continue
            }
        },
    )
    .with_on_stop(move || watcher_stop_cell.current().request_shutdown());

    Ok(IpcAcceptTaskBundle {
        accept,
        shutdown_watcher: watcher,
    })
}
