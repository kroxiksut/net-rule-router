//! SCM dispatcher, control handler and status reporter — the parts that run
//! this process from the inside and therefore cannot live anywhere else.
//!
//! The *outside* half (register, remove, start, stop, query) moved to
//! `nrr_platform_windows::service_control`, behind the neutral
//! `ServiceControlPort`, so the administrative console drives exactly the code
//! path these verbs drive. What remains here are the lifecycle FLOWS: the steps
//! around the OS call that the OS knows nothing about, such as backing up the
//! state database before a binary update.
//!
//! Uses the `windows-service` crate:
//!
//! - `service_dispatcher::start` connects this binary to SCM.
//! - `define_windows_service!` generates the FFI shim that SCM calls.
//! - `service_control_handler::register` installs our handler; we map
//!   SCM control codes onto `LifecycleEvent` and flip the
//!   `StopToken` accordingly.
//! - `ServiceStatusHandle::set_service_status` is the status reporter
//!   the runtime sees through the `ServiceController` trait.
//!
//! Mapping from `ServiceRuntimeState` to SCM's `ServiceState`:
//!
//! - `Starting` → `StartPending`
//! - `Running` / `Degraded` / `RecoveryRequired` / `Disabled` →
//!   `Running` (degraded states are visible via the GUI's
//!   `HealthReporter`, not via SCM)
//! - `Stopping` → `StopPending`
//! - `Stopped` → `Stopped`
//!
//! Supported control codes: `Stop`, `Shutdown`, `Interrogate`, `PowerEvent`.
//! `Pause` and `Continue` are not advertised — the policy state machine has no
//! coherent "paused" state.

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use nrr_platform_api::service_control::{ServiceControlError, ServiceControlPort};
use nrr_platform_windows::service_control::WindowsServiceControl;
use nrr_service_runtime::{
    run_bootstrap, run_supervised_runtime, BootstrapConfig, InstallConfig, InstallOutcome,
    LifecycleEvent, ServiceController, ServiceRuntimeState, StopToken, UninstallConfig,
    UninstallOutcome, UpdateConfig, UpdateOutcome, SERVICE_NAME,
};
use nrr_storage::StorageProfile;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

/// Errors returned by the SCM-mode entrypoint. `NotLaunchedBySCM` is
/// the canonical "I was started from a shell" signal that triggers
/// console-mode fallback.
#[derive(Debug)]
pub enum ScmError {
    /// `service_dispatcher::start` returned ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.
    NotLaunchedBySCM,
    /// SCM dispatcher returned a different error.
    Dispatch(String),
    /// Service control handler registration / status reporting failed.
    Handler(String),
    /// Install / uninstall went wrong.
    Manager(String),
}

impl std::fmt::Display for ScmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLaunchedBySCM => write!(f, "not launched by SCM"),
            Self::Dispatch(s) => write!(f, "SCM dispatcher: {s}"),
            Self::Handler(s) => write!(f, "service control handler: {s}"),
            Self::Manager(s) => write!(f, "SCM manager: {s}"),
        }
    }
}

impl std::error::Error for ScmError {}

impl From<ServiceControlError> for ScmError {
    fn from(err: ServiceControlError) -> Self {
        Self::Manager(err.to_string())
    }
}

/// The service manager, reached through the neutral port.
fn control() -> impl ServiceControlPort {
    WindowsServiceControl::new()
}

// ── Dispatcher entrypoint ────────────────────────────────────────────────────

define_windows_service!(ffi_service_main, scm_service_main);

/// Connect to SCM and block here until SCM tells us to stop. Returns
/// `Err(NotLaunchedBySCM)` when invoked from a non-SCM parent so the
/// caller can fall back to console mode.
pub fn run_under_scm() -> Result<(), ScmError> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(()),
        Err(windows_service::Error::Winapi(io_err)) => {
            // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
            if io_err.raw_os_error() == Some(1063) {
                Err(ScmError::NotLaunchedBySCM)
            } else {
                Err(ScmError::Dispatch(io_err.to_string()))
            }
        }
        Err(e) => Err(ScmError::Dispatch(e.to_string())),
    }
}

/// Real entrypoint invoked by SCM through `define_windows_service!`.
/// Sets up the control handler, runs the runtime, reports the final
/// `Stopped` status. Errors are intentionally swallowed at this layer
/// because SCM has already disconnected stdin/stdout — there is no
/// useful place to surface them.
fn scm_service_main(_args: Vec<OsString>) {
    // First thing in the process under SCM: without this, a panic during
    // startup leaves no trace anywhere.
    capture_stderr();
    let _ = run_scm_inner();
}

/// Send stderr to a file in the log directory. Resolves the directory
/// directly rather than waiting for bootstrap, because the failures worth
/// catching happen before bootstrap returns.
fn capture_stderr() {
    let Ok(topology) =
        nrr_storage::resolve_storage_topology(&nrr_storage::StorageProfile::ProductionService)
    else {
        return;
    };
    if let Some(path) = crate::stderr_capture::redirect_stderr_to_logs(&topology.logs_dir) {
        eprintln!("nrr-service: stderr capture started at {}", path.display());
    }
}

fn run_scm_inner() -> Result<(), ScmError> {
    let stop = StopToken::new();
    let stop_for_handler = stop.clone();
    let (tx, rx) = mpsc::channel::<LifecycleEvent>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = tx.send(LifecycleEvent::Stop);
                stop_for_handler.request_stop();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Shutdown => {
                let _ = tx.send(LifecycleEvent::Shutdown);
                stop_for_handler.request_stop();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            // A wake leaves every binding resolved against a network that is
            // gone; this is the only notification that survives the sleep.
            ServiceControl::PowerEvent(param) => {
                crate::power_scm::dispatch(param);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| ScmError::Handler(e.to_string()))?;

    // Build a controller that reports state to SCM. The runtime body
    // calls `report` synchronously; SCM accepts repeated `Running`
    // pings without complaint, so no batching needed.
    struct ScmController {
        handle: windows_service::service_control_handler::ServiceStatusHandle,
        /// Bumped on every pending report. SCM reads a rising checkpoint as
        /// "still making progress"; a fixed one lets it decide we are wedged.
        checkpoint: std::sync::atomic::AtomicU32,
    }
    impl ServiceController for ScmController {
        fn report(&self, state: ServiceRuntimeState) {
            let scm_state = match state {
                ServiceRuntimeState::Starting => ServiceState::StartPending,
                ServiceRuntimeState::Running
                | ServiceRuntimeState::Degraded
                | ServiceRuntimeState::RecoveryRequired
                | ServiceRuntimeState::Disabled => ServiceState::Running,
                ServiceRuntimeState::Stopping => ServiceState::StopPending,
                ServiceRuntimeState::Stopped => ServiceState::Stopped,
            };
            let controls_accepted = match scm_state {
                ServiceState::Running => {
                    ServiceControlAccept::STOP
                        | ServiceControlAccept::SHUTDOWN
                        | ServiceControlAccept::POWER_EVENT
                }
                _ => ServiceControlAccept::empty(),
            };
            let pending = matches!(
                scm_state,
                ServiceState::StartPending | ServiceState::StopPending
            );
            let checkpoint = if pending {
                self.checkpoint
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1
            } else {
                self.checkpoint
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                0
            };
            let _ = self.handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: scm_state,
                controls_accepted,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint,
                // A pending state with no hint tells SCM to expect an immediate
                // answer, which is how a slow boot reads as a hung one.
                wait_hint: if pending {
                    Duration::from_secs(30)
                } else {
                    Duration::from_secs(0)
                },
                process_id: None,
            });
        }
    }

    let controller = ScmController {
        handle: status_handle,
        checkpoint: std::sync::atomic::AtomicU32::new(0),
    };
    // Production bootstrap profile (`%ProgramData%`-rooted service-owned
    // topology). The topology resolver itself is profile-agnostic.
    let cfg = BootstrapConfig::new(StorageProfile::ProductionService);

    // Bootstrap first, then install the global NDJSON tracing subscriber
    // so the operational `LogWriter` is wired to all `tracing::*` events
    // from this point onward. Run the supervised runtime body so the
    // bootstrap artefacts (and the `Arc<LogWriter>` shared with the
    // global subscriber) live for the full runtime duration.
    let artifacts = run_bootstrap(&cfg);
    // Carries the live tracing-reload handle out of this block so it can
    // be threaded into `build_supervised_runtime_deps` below, letting a
    // mid-session verbose-logging Save apply without a service restart.
    // `None` when there's no log writer (degraded boot) —
    // `ProductionServiceStability` already tolerates a missing seam.
    let mut verbosity_handle: Option<nrr_service_runtime::TracingVerbosityHandle> = None;
    if let Some(writer) = artifacts.log_writer.as_ref() {
        // See main.rs::read_verbose_logging_flag for rationale. Same
        // probe; same fall-back to false on any error.
        let verbose = crate::read_verbose_logging_flag(&artifacts.topology.state_db_path);
        let (_outcome, handle) = nrr_service_runtime::install_ndjson_tracing_with_verbose(
            std::sync::Arc::clone(writer),
            verbose,
        );
        verbosity_handle = Some(handle);
        tracing::info!(
            target: "nrr::stability",
            verbose,
            "operational NDJSON verbosity",
        );
    }

    // Crash recovery hook (mirrors console mode).
    let lkg_available = nrr_service_runtime::probe_lkg_available(&artifacts.topology.state_db_path);
    let recovery_outcome = nrr_service_runtime::run_crash_recovery_on_startup(
        &artifacts.topology.data_dir,
        artifacts.audit_writer.clone(),
        std::sync::Arc::new(nrr_service_runtime::ProductionIdGenerator::new()),
        lkg_available,
    );
    tracing::info!(
        target: "nrr::recovery",
        outcome = ?recovery_outcome,
        lkg_available,
        "crash recovery probe complete",
    );
    let mut artifacts = artifacts;
    if let nrr_service_runtime::CrashRecoveryOutcome::ManualActionRequired { .. }
    | nrr_service_runtime::CrashRecoveryOutcome::Aborted { .. } = recovery_outcome
    {
        artifacts.report.blocking = true;
    }

    // Persist-on-stop — defensive standalone strip of any orphaned
    // block/fail-closed/kill-switch WFP filter a hard-killed prior instance
    // left behind. Runs before deps are built so a kill-switch is removed even
    // on a recovery-BLOCKED boot (where the orchestrator — and its own startup
    // strip — is never constructed). Idempotent on a healthy boot.
    // Each stage announces itself: a boot that stops answering is otherwise a
    // silent 280-line gap between "crash recovery probe complete" and the first
    // line the dependency build emits.
    // Everything this product enforces goes through the filtering engine, so a
    // stopped one explains an otherwise baffling boot before it happens.
    match nrr_platform_windows::service_control::filtering_engine_running() {
        Some(true) => {}
        Some(false) => tracing::error!(
            target: "nrr::boot",
            "the Windows Base Filtering Engine (BFE) service is not running — nothing can be enforced \
             until it is started; every filter operation from here on will fail or hang",
        ),
        None => tracing::warn!(
            target: "nrr::boot",
            "could not read the state of the Windows Base Filtering Engine (BFE) service",
        ),
    }

    tracing::info!(target: "nrr::boot", stage = "strip-orphaned-filters", "boot stage entered");
    crate::runtime_deps::strip_orphaned_block_filters_standalone();

    tracing::info!(target: "nrr::boot", stage = "build-deps", "boot stage entered");
    let deps = crate::runtime_deps::build_supervised_runtime_deps(&artifacts, verbosity_handle);
    tracing::info!(target: "nrr::boot", stage = "run-runtime", "boot stage entered");
    let _ = run_supervised_runtime(&controller, &stop, artifacts, deps);

    // Drain any control events that arrived after Stop so we don't
    // leave them dangling in the channel.
    while rx.try_recv().is_ok() {}

    Ok(())
}

// ── Install / uninstall ──────────────────────────────────────────────────────

/// Register the service with SCM using the given `config`. Requires admin.
pub fn install_service_with_config(config: &InstallConfig) -> Result<InstallOutcome, ScmError> {
    Ok(control().install(config)?)
}

/// Register the service using defaults derived from the current executable.
pub fn install_service() -> Result<(), ScmError> {
    let binary_path =
        std::env::current_exe().map_err(|e| ScmError::Manager(format!("current_exe: {e}")))?;
    install_service_with_config(&InstallConfig::production_defaults(binary_path))?;
    Ok(())
}

/// Stop/drain the service and back up the state DB in preparation for a
/// binary update. Does NOT replace the binary or restart the service —
/// those steps are the installer's responsibility.
pub fn update_service(config: &UpdateConfig) -> Result<UpdateOutcome, ScmError> {
    control().stop(Duration::from_secs(config.drain_timeout_secs))?;

    let state_db_backup = if config.backup_state_db {
        let topology = nrr_storage::resolve_storage_topology(&StorageProfile::ProductionService)
            .map_err(|e| ScmError::Manager(format!("resolve topology: {e}")))?;
        let src = topology.state_db_path.clone();
        if src.exists() {
            let backup = src.with_extension("db.bak");
            std::fs::copy(&src, &backup)
                .map_err(|e| ScmError::Manager(format!("backup state DB: {e}")))?;
            Some(backup)
        } else {
            None
        }
    } else {
        None
    };

    // The caller (installer) now replaces the binary and starts the service
    // again; the new binary isn't in place yet, so neither happens here.
    Ok(UpdateOutcome {
        state_db_backup,
        service_restarted: false,
    })
}

/// Unregister the service and optionally remove service-owned data.
///
/// Removing the service alone leaves the data in place, so nothing has to be
/// rescued ahead of the removal: a diagnostics archive can still be built from
/// the files afterwards. Purging is the application-removal path, and there the
/// operator asked for the data to go.
pub fn uninstall_service_with_config(
    config: &UninstallConfig,
) -> Result<UninstallOutcome, ScmError> {
    let report = control().uninstall(&config.port_spec())?;

    Ok(UninstallOutcome {
        data_removed: report.data_removed,
        rule_files_preserved: config.preserve_user_rule_files,
    })
}

/// Start the registered service and wait briefly for it to reach `Running`.
pub fn start_service(timeout_secs: u64) -> Result<(), ScmError> {
    Ok(control().start(Duration::from_secs(timeout_secs))?)
}

/// Stop the registered service and wait for `Stopped`.
pub fn stop_service(timeout_secs: u64) -> Result<(), ScmError> {
    Ok(control().stop(Duration::from_secs(timeout_secs))?)
}
