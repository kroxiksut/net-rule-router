//! Main runtime loop, task supervision, shutdown model.
//!
//! ## Runtime model
//!
//! **Sync threads, no async runtime.** Reasons pinned in this scaffold:
//!
//! - `nrr-storage` is sync-only by design — wrapping every call in
//!   `spawn_blocking` of a tokio runtime adds binary size and
//!   complexity for no observable benefit on a single-instance service
//!   that handles a few requests per second.
//! - The `windows-service` crate's lifecycle callbacks already run on a
//!   thread the SCM dispatcher owns; layering an async runtime on top
//!   would make shutdown ordering harder to reason about.
//! - The IPC server protocol layer is request/response — no
//!   streaming — so per-request blocking is fine.
//!
//! Async stays behind ports if a future apply layer needs it; this
//! supervisor stays sync.
//!
//! ## Task taxonomy
//!
//! Every `ServiceTask` has a `class`:
//!
//! - **`Critical`** — failure flips the service to `RecoveryRequired`
//!   without restart attempts. Reserved for things that, if broken,
//!   make further runtime activity unsafe (apply controller, IPC
//!   server in dispatch mode).
//! - **`Recoverable`** — fail → mark `Degraded`, restart up to N times
//!   with backoff. Used for periodic refreshers (cache, health pull).
//! - **`Optional`** — fail → log + drop the task; service stays
//!   `Running`. Used for diagnostics cleanup.
//!
//! ## Shutdown ordering
//!
//! The supervisor walks tasks in **reverse start order** on shutdown,
//! with a hard cap of `STOP_TIMEOUT`. The canonical ordering for the
//! production wiring:
//!
//! 1. IPC: stop accepting mutating ops (read-only continues until step 3).
//! 2. Apply controller: stop new attempts, mark in-flight as interrupted.
//! 3. File watcher: stop event emission.
//! 4. Cache scheduler: stop refresh ticks.
//! 5. Diagnostics cleanup: stop ticks.
//! 6. Audit / log writer: flush.
//! 7. Storage: close DB connections.
//!
//! Steps 1–5 are wired here as `ServiceTask` registrations; 6/7 are
//! consumed by `BootstrapArtifacts` drop in the entrypoint.
//!
//! ## Mutation queue priority
//!
//! The `MutationQueue` is FIFO. The supervisor doesn't run the IPC
//! accept-loop directly — that lives in the transport layer in
//! `nrr-windows-service`. What we *do* run here is the dispatch
//! priority: when multiple internal tasks compete for the queue slot
//! (apply orchestrator, recovery action), we drain in priority order:
//!
//! `RecoverySafeDisable > IntegrityRecovery > ActiveApply > UserMutation > CacheRefresh > DiagnosticsCleanup`
//!
//! Implementation today: `OperationPriority` enum with `Ord` so callers
//! can sort their pending work; the actual scheduler picks the highest
//! every iteration.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::lifecycle::{StopToken, STOP_TIMEOUT};

// ── Task taxonomy ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaskClass {
    Critical,
    Recoverable,
    Optional,
}

/// Operation priority used by the in-process scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationPriority {
    /// Lowest priority; runs whenever nothing else is pending.
    DiagnosticsCleanup,
    CacheRefresh,
    UserMutation,
    ActiveApply,
    IntegrityRecovery,
    /// Highest priority; runs ahead of everything.
    RecoverySafeDisable,
}

/// What a `ServiceTask` callback returns each tick / iteration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskOutcome {
    /// Task did its work and is happy to be ticked again.
    Continue,
    /// Task wants to be torn down (no error). The supervisor
    /// removes it without flipping health.
    Done,
    /// Task crashed. Supervisor restarts according to `TaskClass`.
    Failed(String),
}

/// Stable slug-style id so logs / health snapshots have a name to
/// attach. `HealthAggregator` consumes these on failure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TaskId(pub String);

impl TaskId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// What a periodic task does on each tick. Sync, may sleep — but must
/// observe `StopToken` and return reasonably promptly. The supervisor
/// re-invokes it after `interval` until it returns `Done` / `Failed` /
/// the stop token flips.
pub type TickFn = Box<dyn FnMut(&StopToken) -> TaskOutcome + Send>;

/// Per-task restart back-off schedule used by `TaskClass::Recoverable`
/// in the supervisor's failure handler. The default (`100 ms × attempt`,
/// capped at `1 s`) applies to any task constructed via
/// `ServiceTask::periodic` without an explicit override.
///
/// `ipc-accept-loop` derives `base`/`cap` from user-configurable
/// settings — fed in from `ServiceStabilityConfig.ipc_accept_policy` so
/// an operator can tune the budget without a rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BackoffSchedule {
    pub base: Duration,
    pub cap: Duration,
}

impl BackoffSchedule {
    pub const fn new(base: Duration, cap: Duration) -> Self {
        Self { base, cap }
    }

    /// Saturating-arithmetic computation of `(base × attempt).min(cap)`.
    /// `attempt` is the supervisor's 1-based restart counter; the
    /// returned duration is what `sleep_observing_stop` will sleep
    /// before re-invoking the task.
    pub fn delay_for_attempt(&self, attempt: u8) -> Duration {
        let base_ms = u64::try_from(self.base.as_millis()).unwrap_or(u64::MAX);
        let cap_ms = u64::try_from(self.cap.as_millis()).unwrap_or(u64::MAX);
        let scaled = base_ms.saturating_mul(u64::from(attempt));
        Duration::from_millis(scaled.min(cap_ms))
    }
}

impl Default for BackoffSchedule {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(100),
            cap: Duration::from_secs(1),
        }
    }
}

/// One supervised task.
pub struct ServiceTask {
    pub id: TaskId,
    pub class: TaskClass,
    /// `None` for event-driven tasks (the supervisor only invokes them
    /// when the event source pings). Periodic tasks use `Some(d)`.
    pub interval: Option<Duration>,
    pub max_restarts: u8,
    /// Recoverable failure back-off schedule. Defaults to a
    /// `100ms × attempt` ramp capped at `1s`. Set explicitly by
    /// `build_ipc_accept_task_bundle` — other task builders may opt in
    /// over time.
    pub backoff: BackoffSchedule,
    pub tick: TickFn,
}

impl ServiceTask {
    pub fn periodic(
        id: impl Into<String>,
        class: TaskClass,
        interval: Duration,
        max_restarts: u8,
        tick: impl FnMut(&StopToken) -> TaskOutcome + Send + 'static,
    ) -> Self {
        Self {
            id: TaskId::new(id),
            class,
            interval: Some(interval),
            max_restarts,
            backoff: BackoffSchedule::default(),
            tick: Box::new(tick),
        }
    }

    /// Chainable override for the failure back-off schedule. Returns
    /// `self` for ergonomic builder-style construction at the task
    /// definition site.
    pub fn with_backoff(mut self, backoff: BackoffSchedule) -> Self {
        self.backoff = backoff;
        self
    }
}

// ── Failure recording ────────────────────────────────────────────────────────

/// Trait by which the supervisor reports failures back to the host so
/// `HealthAggregator` and audit can react. Kept narrow on purpose —
/// the supervisor does not know about audit/health internals; it just
/// notifies.
pub trait TaskFailureSink: Send + Sync {
    fn task_failed(&self, id: &TaskId, class: TaskClass, attempt: u8, message: &str);
    fn task_terminated_fatal(&self, id: &TaskId, message: &str);
}

#[derive(Default)]
pub struct CountingFailureSink {
    pub failures: AtomicU64,
    pub fatal: AtomicU64,
}

impl TaskFailureSink for CountingFailureSink {
    fn task_failed(&self, _id: &TaskId, _class: TaskClass, _attempt: u8, _message: &str) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }
    fn task_terminated_fatal(&self, _id: &TaskId, _message: &str) {
        self.fatal.fetch_add(1, Ordering::SeqCst);
    }
}

// ── Supervisor ───────────────────────────────────────────────────────────────

/// Owns thread handles for every running task plus the shared
/// `StopToken` it hands them. Drop calls `shutdown()` so unit tests
/// can rely on RAII teardown.
pub struct ServiceSupervisor {
    stop: StopToken,
    handles: Mutex<Vec<JoinHandle<()>>>,
    started: AtomicBool,
    sink: Arc<dyn TaskFailureSink>,
    /// Maximum total wait time during shutdown. Defaults to
    /// `STOP_TIMEOUT` from block 14.2.
    stop_timeout: Duration,
}

impl ServiceSupervisor {
    pub fn new(stop: StopToken, sink: Arc<dyn TaskFailureSink>) -> Self {
        Self {
            stop,
            handles: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
            sink,
            stop_timeout: STOP_TIMEOUT,
        }
    }

    pub fn with_stop_timeout(mut self, d: Duration) -> Self {
        self.stop_timeout = d;
        self
    }

    /// Spawn one task. Returns `Err` if the supervisor has already
    /// been shut down (`StopToken` already flipped).
    pub fn spawn(&self, mut task: ServiceTask) -> Result<(), &'static str> {
        if self.stop.is_stop_requested() {
            return Err("supervisor already shutting down");
        }
        self.started.store(true, Ordering::SeqCst);
        let stop = self.stop.clone();
        let sink = Arc::clone(&self.sink);
        let id = task.id.clone();
        let class = task.class;
        let max_restarts = task.max_restarts;
        let interval = task.interval;
        let backoff = task.backoff;
        let handle = thread::Builder::new()
            .name(format!("nrr-task-{}", id.0))
            .spawn(move || {
                let mut attempt: u8 = 0;
                while !stop.is_stop_requested() {
                    let outcome = (task.tick)(&stop);
                    match outcome {
                        TaskOutcome::Continue => {
                            attempt = 0;
                            if let Some(d) = interval {
                                sleep_observing_stop(&stop, d);
                            } else {
                                // Event-driven task without an interval
                                // and without external wakeups: avoid a
                                // busy spin — yield briefly.
                                sleep_observing_stop(&stop, Duration::from_millis(50));
                            }
                        }
                        TaskOutcome::Done => break,
                        TaskOutcome::Failed(msg) => {
                            attempt = attempt.saturating_add(1);
                            sink.task_failed(&id, class, attempt, &msg);
                            match class {
                                TaskClass::Critical => {
                                    sink.task_terminated_fatal(&id, &msg);
                                    break;
                                }
                                TaskClass::Recoverable => {
                                    if attempt > max_restarts {
                                        sink.task_terminated_fatal(&id, &msg);
                                        break;
                                    }
                                    // Per-task back-off. Default schedule =
                                    // 100 ms × attempt capped at 1 s;
                                    // `ipc-accept-loop` derives base / cap
                                    // from ServiceStabilityConfig.
                                    sleep_observing_stop(&stop, backoff.delay_for_attempt(attempt));
                                }
                                TaskClass::Optional => {
                                    // Drop quietly.
                                    break;
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|_| "thread spawn failed")?;
        if let Ok(mut guard) = self.handles.lock() {
            guard.push(handle);
        }
        Ok(())
    }

    /// Trigger graceful shutdown: flip the stop token, then wait up to
    /// `stop_timeout` for every spawned thread to finish. Returns the
    /// number of threads that exited cleanly within the budget plus the
    /// names of the threads that had to be detached.
    ///
    /// The wait is fair across tasks: all handles are polled together
    /// until the deadline, so one thread stuck in a blocking OS call
    /// cannot consume the budget before already-finished threads are
    /// counted (a sequential join used to mark those as detached too,
    /// overstating the problem and hiding the real straggler).
    pub fn shutdown(&self) -> ShutdownReport {
        self.stop.request_stop();
        if !self.started.load(Ordering::SeqCst) {
            return ShutdownReport {
                total: 0,
                clean: 0,
                detached: Vec::new(),
            };
        }
        let mut pending: Vec<JoinHandle<()>> = match self.handles.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => {
                return ShutdownReport {
                    total: 0,
                    clean: 0,
                    detached: vec!["<handles mutex poisoned>".to_owned()],
                }
            }
        };
        let total = pending.len();
        let deadline = Instant::now() + self.stop_timeout;
        let mut clean = 0usize;
        loop {
            let (done, rest): (Vec<_>, Vec<_>) =
                pending.into_iter().partition(JoinHandle::is_finished);
            // `join` on a finished thread returns immediately.
            for handle in done {
                let _ = handle.join();
                clean += 1;
            }
            pending = rest;
            if pending.is_empty() || Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let detached: Vec<String> = pending
            .iter()
            .map(|h| h.thread().name().unwrap_or("<unnamed>").to_owned())
            .collect();
        // Dropping `pending` detaches the stragglers — the OS reclaims
        // them at process exit.
        ShutdownReport {
            total,
            clean,
            detached,
        }
    }
}

impl Drop for ServiceSupervisor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShutdownReport {
    pub total: usize,
    pub clean: usize,
    /// Thread names of tasks that did not finish within the budget.
    pub detached: Vec<String>,
}

impl ShutdownReport {
    pub fn timed_out(&self) -> bool {
        !self.detached.is_empty()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Sleep up to `total`, returning early if the stop token flips. Used
/// by both the periodic loop and the post-failure backoff path so a
/// stop request is observed within ~50ms even mid-sleep.
fn sleep_observing_stop(stop: &StopToken, total: Duration) {
    let granularity = Duration::from_millis(50);
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if stop.is_stop_requested() {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(granularity));
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn counting_sink() -> Arc<CountingFailureSink> {
        Arc::new(CountingFailureSink::default())
    }

    #[test]
    fn periodic_task_runs_until_stop_then_exits() {
        let stop = StopToken::new();
        let sink = counting_sink();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), sink.clone() as Arc<dyn TaskFailureSink>);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        supervisor
            .spawn(ServiceTask::periodic(
                "echo",
                TaskClass::Recoverable,
                Duration::from_millis(20),
                1,
                move |_stop| {
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                    TaskOutcome::Continue
                },
            ))
            .unwrap();
        thread::sleep(Duration::from_millis(120));
        let report = supervisor.shutdown();
        assert_eq!(report.total, 1);
        assert!(report.clean >= 1, "report = {report:?}");
        assert!(counter.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn long_task_does_not_block_supervisor_shutdown() {
        // Task sleeps in 50ms increments observing the stop token —
        // supervisor.shutdown() should return within ~stop_timeout
        // even though the task body would otherwise have slept 5s.
        let stop = StopToken::new();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), counting_sink() as Arc<dyn TaskFailureSink>)
                .with_stop_timeout(Duration::from_secs(2));
        supervisor
            .spawn(ServiceTask::periodic(
                "long",
                TaskClass::Recoverable,
                Duration::from_secs(5),
                1,
                |stop| {
                    sleep_observing_stop(stop, Duration::from_secs(5));
                    TaskOutcome::Continue
                },
            ))
            .unwrap();
        let started = Instant::now();
        let report = supervisor.shutdown();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(report.clean, 1);
    }

    #[test]
    fn recoverable_task_is_restarted_then_retired_after_max_attempts() {
        let stop = StopToken::new();
        let sink = counting_sink();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), sink.clone() as Arc<dyn TaskFailureSink>);
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();
        supervisor
            .spawn(ServiceTask::periodic(
                "flaky",
                TaskClass::Recoverable,
                Duration::from_millis(5),
                2,
                move |_stop| {
                    attempts_clone.fetch_add(1, Ordering::SeqCst);
                    TaskOutcome::Failed("boom".into())
                },
            ))
            .unwrap();
        thread::sleep(Duration::from_millis(500));
        let _ = supervisor.shutdown();
        // 1 fail + 2 restarts = 3 attempts, then fatal.
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(sink.failures.load(Ordering::SeqCst), 3);
        assert_eq!(sink.fatal.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn critical_task_failure_terminates_immediately() {
        let stop = StopToken::new();
        let sink = counting_sink();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), sink.clone() as Arc<dyn TaskFailureSink>);
        supervisor
            .spawn(ServiceTask::periodic(
                "critical",
                TaskClass::Critical,
                Duration::from_millis(5),
                3, // ignored for Critical
                |_stop| TaskOutcome::Failed("apply layer broken".into()),
            ))
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        let _ = supervisor.shutdown();
        assert_eq!(sink.fatal.load(Ordering::SeqCst), 1);
        assert_eq!(sink.failures.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn optional_task_failure_is_silent_drop() {
        let stop = StopToken::new();
        let sink = counting_sink();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), sink.clone() as Arc<dyn TaskFailureSink>);
        supervisor
            .spawn(ServiceTask::periodic(
                "optional",
                TaskClass::Optional,
                Duration::from_millis(5),
                3,
                |_stop| TaskOutcome::Failed("cleanup glitched".into()),
            ))
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        let _ = supervisor.shutdown();
        // One failure recorded, no fatal.
        assert_eq!(sink.failures.load(Ordering::SeqCst), 1);
        assert_eq!(sink.fatal.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cannot_spawn_after_shutdown() {
        let stop = StopToken::new();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), counting_sink() as Arc<dyn TaskFailureSink>);
        let _ = supervisor.shutdown();
        let res = supervisor.spawn(ServiceTask::periodic(
            "after",
            TaskClass::Recoverable,
            Duration::from_millis(5),
            0,
            |_| TaskOutcome::Continue,
        ));
        assert!(res.is_err());
    }

    #[test]
    fn priority_ordering_matches_documented_table() {
        // Highest first.
        let mut prios = vec![
            OperationPriority::DiagnosticsCleanup,
            OperationPriority::CacheRefresh,
            OperationPriority::UserMutation,
            OperationPriority::ActiveApply,
            OperationPriority::IntegrityRecovery,
            OperationPriority::RecoverySafeDisable,
        ];
        prios.sort_by(|a, b| b.cmp(a));
        assert_eq!(
            prios,
            vec![
                OperationPriority::RecoverySafeDisable,
                OperationPriority::IntegrityRecovery,
                OperationPriority::ActiveApply,
                OperationPriority::UserMutation,
                OperationPriority::CacheRefresh,
                OperationPriority::DiagnosticsCleanup,
            ]
        );
    }

    #[test]
    fn shutdown_drop_is_idempotent() {
        let stop = StopToken::new();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), counting_sink() as Arc<dyn TaskFailureSink>);
        let r1 = supervisor.shutdown();
        let r2 = supervisor.shutdown();
        assert_eq!(r1.total, 0);
        assert_eq!(r2.total, 0);
    }

    #[test]
    fn done_outcome_terminates_task_without_failure() {
        let stop = StopToken::new();
        let sink = counting_sink();
        let supervisor =
            ServiceSupervisor::new(stop.clone(), sink.clone() as Arc<dyn TaskFailureSink>);
        let done_after = Arc::new(AtomicUsize::new(0));
        let done_clone = done_after.clone();
        supervisor
            .spawn(ServiceTask::periodic(
                "self-done",
                TaskClass::Recoverable,
                Duration::from_millis(5),
                1,
                move |_stop| {
                    let n = done_clone.fetch_add(1, Ordering::SeqCst);
                    if n >= 2 {
                        TaskOutcome::Done
                    } else {
                        TaskOutcome::Continue
                    }
                },
            ))
            .unwrap();
        thread::sleep(Duration::from_millis(200));
        let _ = supervisor.shutdown();
        assert_eq!(sink.failures.load(Ordering::SeqCst), 0);
        assert_eq!(sink.fatal.load(Ordering::SeqCst), 0);
        assert!(done_after.load(Ordering::SeqCst) >= 3);
    }

    // ── Per-task backoff ─────────────────────────────────────────────────

    #[test]
    fn backoff_schedule_default_matches_legacy_100ms_cap_1s() {
        let s = BackoffSchedule::default();
        assert_eq!(s.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(s.delay_for_attempt(5), Duration::from_millis(500));
        // 10×100 = 1000 = cap exactly.
        assert_eq!(s.delay_for_attempt(10), Duration::from_millis(1000));
        // 20×100 = 2000 → clamped to cap (1000).
        assert_eq!(s.delay_for_attempt(20), Duration::from_millis(1000));
    }

    #[test]
    fn backoff_schedule_honours_custom_base_and_cap() {
        let s = BackoffSchedule::new(Duration::from_millis(250), Duration::from_secs(10));
        assert_eq!(s.delay_for_attempt(1), Duration::from_millis(250));
        // 4×250 = 1000 < cap (10_000) → exact.
        assert_eq!(s.delay_for_attempt(4), Duration::from_millis(1000));
        // 40×250 = 10_000 = cap exactly.
        assert_eq!(s.delay_for_attempt(40), Duration::from_millis(10_000));
        // 60×250 = 15_000 → clamped to cap.
        assert_eq!(s.delay_for_attempt(60), Duration::from_millis(10_000));
    }

    #[test]
    fn backoff_schedule_saturates_under_extreme_inputs() {
        // base + attempt that would overflow u64×u8 → saturated to cap.
        let s = BackoffSchedule::new(Duration::from_millis(u64::MAX), Duration::from_millis(1000));
        assert_eq!(s.delay_for_attempt(255), Duration::from_millis(1000));
    }

    #[test]
    fn service_task_periodic_constructs_with_default_backoff() {
        let task = ServiceTask::periodic(
            "x",
            TaskClass::Recoverable,
            Duration::from_millis(1),
            1,
            |_stop| TaskOutcome::Continue,
        );
        assert_eq!(task.backoff, BackoffSchedule::default());
    }

    #[test]
    fn service_task_with_backoff_overrides_default() {
        let custom = BackoffSchedule::new(Duration::from_millis(500), Duration::from_secs(30));
        let task = ServiceTask::periodic(
            "x",
            TaskClass::Recoverable,
            Duration::from_millis(1),
            1,
            |_stop| TaskOutcome::Continue,
        )
        .with_backoff(custom);
        assert_eq!(task.backoff, custom);
    }
}
