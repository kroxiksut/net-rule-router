//! Service lifecycle primitives that the SCM/console
//! entrypoint binary in `nrr-windows-service` plugs into.
//!
//! Two layers:
//!
//! 1. Identity / install metadata constants. Single source of truth so
//!    the SCM install hook, the Event Log source registration and any
//!    smoke script all see the same names.
//! 2. Process-internal lifecycle wiring: `StopToken` (cooperative
//!    cancellation handed to background tasks), `LifecycleEvent` enum
//!    (control codes the SCM dispatcher feeds in), `ServiceController`
//!    trait (status reporter — abstracted so console mode and SCM mode
//!    share the same runtime body), and `run_runtime` (the loop body
//!    that the binary hands a controller + stop token to).
//!
//! Crucially, `nrr-service-runtime` itself has zero `windows-service` /
//! `windows-sys` dependency — the crate's deny-list still holds. The
//! Windows-only adapters live in `nrr-windows-service`; we only define
//! the trait surface they implement.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bootstrap::{bootstrap, BootstrapArtifacts, BootstrapConfig};
use crate::state::{ServiceRuntimeState, ServiceShutdownReason};

// ── Service identity / install metadata ──────────────────────────────────────

/// Internal service name used by SCM. Stable across versions — changing it
/// breaks every operator script. Derived from the product identity so this
/// name cannot drift away from the systemd unit name or the installer.
pub const SERVICE_NAME: &str = nrr_shared::product_identity::WINDOWS_SERVICE_NAME;

/// Display name shown in the Services MMC console.
pub const SERVICE_DISPLAY_NAME: &str = nrr_shared::product_identity::WINDOWS_SERVICE_DISPLAY_NAME;

/// Description shown in the Services MMC console.
pub const SERVICE_DESCRIPTION: &str = nrr_shared::product_identity::WINDOWS_SERVICE_DESCRIPTION;

/// Event Log source name registered under
/// `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\<source>`
/// during install. Used by the SCM-mode `ReportEvent` writer.
pub const EVENT_SOURCE_NAME: &str = nrr_shared::product_identity::WINDOWS_EVENT_SOURCE_NAME;

/// Maximum time the bootstrap pipeline is allowed before
/// the runtime must report `Running`/`Degraded` to SCM. Past this
/// budget the dispatcher reports `Stopped` with `BootstrapBlocking`
/// and SCM applies its recovery actions.
pub const START_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum time `Stopping` is allowed before background tasks are
/// detached and the process exits. Apply locks must be released
/// before this fires, enforced by a watchdog.
///
/// Sized to fit INSIDE the SCM / `stop` CLI stop window
/// (`scm::stop_service(15)` waits 15 s for `STOPPED`). Cooperative
/// tasks honour the stop token in tens of milliseconds; a task still
/// running after a few seconds is blocked on a non-cooperative syscall
/// (e.g. a synchronous named-pipe accept) and will not drain at 30 s
/// either — waiting that long only delays the inevitable detach past
/// the client's 15 s budget, which surfaced as "Service binary exited
/// with code 1" on Stop. Detaching at 5 s lets the runtime report
/// `Stopped` and exit 0 well within the window; the stragglers are
/// killed when the process exits (each holds its own `Arc`, so detach
/// is memory-safe).
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Autostart policy slug we will install with. `delayed-automatic` is
/// the recommended baseline for MVP because the policy apply layer
/// depends on the network stack already being up; `automatic` would
/// cause the first apply attempt to race the network ready notification.
pub const AUTOSTART_POLICY: &str = "delayed-automatic";

// ── Stop token ────────────────────────────────────────────────────────────────

/// Cooperative cancellation handle. Cloned freely; flipping it via
/// `request_stop()` makes every clone observe `is_stop_requested() ==
/// true`. Used by background tasks (refresh watcher, IPC
/// listener, runtime loop) to bail out promptly when
/// SCM sends `Stop`.
#[derive(Clone, Debug)]
pub struct StopToken {
    flag: Arc<AtomicBool>,
}

impl StopToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal every clone of this token to stop. Idempotent.
    pub fn request_stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether `request_stop()` has been called on any clone.
    pub fn is_stop_requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

impl Default for StopToken {
    fn default() -> Self {
        Self::new()
    }
}

// ── Lifecycle events ─────────────────────────────────────────────────────────

/// Control codes the SCM dispatcher (or the console mode Ctrl+C
/// handler) translates into. We deliberately keep the set narrow:
/// `Pause`/`Continue` are not exposed because routing policy state
/// would become ambiguous mid-pause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LifecycleEvent {
    /// SCM `SERVICE_CONTROL_STOP`.
    Stop,
    /// SCM `SERVICE_CONTROL_SHUTDOWN`. Behaviourally identical to
    /// `Stop` in our model — the runtime drains the same way — but the
    /// shutdown audit event records a different reason.
    Shutdown,
    /// SCM `SERVICE_CONTROL_INTERROGATE`. The dispatcher just re-emits
    /// the current status; the runtime does no work.
    Interrogate,
}

impl LifecycleEvent {
    /// Map a control event to the shutdown reason the runtime should
    /// audit when it later transitions to `Stopped`. Returns `None` for
    /// `Interrogate` (no shutdown).
    pub const fn shutdown_reason(self) -> Option<ServiceShutdownReason> {
        match self {
            Self::Stop => Some(ServiceShutdownReason::ScmStop),
            Self::Shutdown => Some(ServiceShutdownReason::SystemShutdown),
            Self::Interrogate => None,
        }
    }
}

// ── Service controller trait ─────────────────────────────────────────────────

/// Status-reporter abstraction. SCM mode implements this with
/// `windows-service`'s `ServiceStatusHandle`; console mode implements
/// it with `eprintln!` so dev builds get the same observability without
/// the SCM glue. The runtime body never knows which side it talks to.
pub trait ServiceController: Send + Sync {
    /// Report a runtime state to the controller. Maps internally to
    /// the SCM `ServiceState` enum.
    /// `Degraded` and `RecoveryRequired` map to `Running` at the SCM
    /// level (no native equivalent); the GUI sees the real severity
    /// via the `HealthReporter`.
    fn report(&self, state: ServiceRuntimeState);
}

// ── Runtime loop body ────────────────────────────────────────────────────────

/// Run the service runtime body. Hosts the eventual main loop;
/// the current scaffold just walks the state machine
/// in order and exits when the stop token flips.
///
/// The function is intentionally generic over `ServiceController` so
/// unit tests can inject a recording fake.
pub fn run_runtime(controller: &dyn ServiceController, stop: &StopToken) -> ServiceShutdownReason {
    run_runtime_with_bootstrap(controller, stop, None)
}

/// Same as `run_runtime` but with an explicit bootstrap config. The
/// SCM entrypoint passes `Some(BootstrapConfig::new(StorageProfile::ProductionService))`;
/// console-mode tests pass a `TestTemp` config so they don't write
/// into `%ProgramData%`. Passing `None` skips bootstrap entirely —
/// useful for the lifecycle unit tests that only care about the
/// state-transition shape.
pub fn run_runtime_with_bootstrap(
    controller: &dyn ServiceController,
    stop: &StopToken,
    bootstrap_config: Option<&BootstrapConfig>,
) -> ServiceShutdownReason {
    controller.report(ServiceRuntimeState::Starting);
    let artifacts: Option<BootstrapArtifacts> = bootstrap_config.map(bootstrap);
    run_runtime_with_artifacts(controller, stop, artifacts)
}

/// Run the service runtime body with pre-built [`BootstrapArtifacts`].
///
/// This is the entry point used by `nrr-windows-service` so that side
/// effects that need bootstrap output (e.g. installing the
/// `NdjsonTracingLayer` global subscriber from `nrr-diagnostics`) can
/// happen *between* `bootstrap()` and the runtime loop.
///
/// `artifacts == None` skips bootstrap entirely (matching the historical
/// `run_runtime_with_bootstrap(_, _, None)` behaviour) — used by
/// lifecycle unit tests that only care about the state-transition shape.
pub fn run_runtime_with_artifacts(
    controller: &dyn ServiceController,
    stop: &StopToken,
    artifacts: Option<BootstrapArtifacts>,
) -> ServiceShutdownReason {
    // Bootstrap pipeline. When the report carries a
    // `Blocking` severity we go straight to `RecoveryRequired` →
    // `Stopping` → `Stopped`: SCM still sees `Running` for
    // RecoveryRequired, but the runtime
    // does no privileged work and the GUI/tray snapshot reflects the
    // failure.
    let blocked = artifacts
        .as_ref()
        .map(|a| !a.is_ready_to_run())
        .unwrap_or(false);

    if blocked {
        controller.report(ServiceRuntimeState::RecoveryRequired);
    } else {
        controller.report(ServiceRuntimeState::Running);
    }

    // Cooperative wait. The real event-driven
    // loop is not wired yet; for now we sleep in short increments so a stop request is
    // observed within ~100ms.
    while !stop.is_stop_requested() {
        std::thread::sleep(Duration::from_millis(100));
    }

    controller.report(ServiceRuntimeState::Stopping);
    // TODO:: drain background tasks, flush audit/logs,
    // release apply locks before reporting Stopped.
    controller.report(ServiceRuntimeState::Stopped);
    // Keep `artifacts` alive until shutdown so any background ports
    // (e.g. `Arc<LogWriter>` shared with the global tracing subscriber)
    // are not torn down mid-run.
    drop(artifacts);
    ServiceShutdownReason::ScmStop
}

// TODO:: Windows Event Log writer.
//
// Source registration: install hook writes
// `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\NetRuleRouter`
// (`EventMessageFile` = service binary path, `TypesSupported` =
// EVENTLOG_INFORMATION_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_ERROR_TYPE).
// Runtime writer: `windows-sys::Win32::System::EventLog::ReportEventW`,
// called on Start / Stop / Degraded / Critical transitions. Lives in
// `nrr-windows-service` because it needs `windows-sys`; trait surface
// stays here so the runtime body remains transport-agnostic.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingController {
        states: Mutex<Vec<ServiceRuntimeState>>,
    }

    impl ServiceController for RecordingController {
        fn report(&self, state: ServiceRuntimeState) {
            #[allow(clippy::unwrap_used)]
            self.states.lock().unwrap().push(state);
        }
    }

    #[test]
    fn stop_token_is_observed_by_clones() {
        let token = StopToken::new();
        let clone = token.clone();
        assert!(!clone.is_stop_requested());
        token.request_stop();
        assert!(clone.is_stop_requested());
    }

    #[test]
    fn shutdown_reason_mapping_is_complete() {
        assert_eq!(
            LifecycleEvent::Stop.shutdown_reason(),
            Some(ServiceShutdownReason::ScmStop)
        );
        assert_eq!(
            LifecycleEvent::Shutdown.shutdown_reason(),
            Some(ServiceShutdownReason::SystemShutdown)
        );
        assert_eq!(LifecycleEvent::Interrogate.shutdown_reason(), None);
    }

    #[test]
    fn run_runtime_emits_full_state_sequence_and_exits_on_stop() {
        let controller = RecordingController::default();
        let stop = StopToken::new();
        let stop_clone = stop.clone();
        // Trigger stop quickly so the test doesn't hang.
        let join = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            stop_clone.request_stop();
        });
        let reason = run_runtime(&controller, &stop);
        join.join().unwrap();

        assert_eq!(reason, ServiceShutdownReason::ScmStop);
        let states = controller.states.lock().unwrap().clone();
        assert_eq!(
            states,
            vec![
                ServiceRuntimeState::Starting,
                ServiceRuntimeState::Running,
                ServiceRuntimeState::Stopping,
                ServiceRuntimeState::Stopped,
            ]
        );
    }
}
