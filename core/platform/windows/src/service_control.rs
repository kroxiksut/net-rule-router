//! Windows implementation of the service-control port: the Service Control
//! Manager.
//!
//! This is mechanism only — every decision about *whether* an operation may run
//! and *what the user is told* lives in the caller. The module was extracted
//! from the service binary so the administrative console can drive the same
//! code path the service's own verbs and the elevation broker drive; a binary
//! crate cannot be linked into another binary.
//!
//! Not here: the SCM *dispatcher* (`service_dispatcher::start` and the control
//! handler). That one runs the service's own process from the inside and stays
//! in the service binary.

#![cfg(windows)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nrr_platform_api::service_control::{
    RecoveryPolicy, ServiceControlError, ServiceControlPort, ServiceInstallReport,
    ServiceInstallSpec, ServiceRunState, ServiceStartMode, ServiceStatusReport,
    ServiceUninstallReport, ServiceUninstallSpec,
};
use nrr_shared::product_identity::{
    WINDOWS_SERVICE_DESCRIPTION, WINDOWS_SERVICE_DISPLAY_NAME, WINDOWS_SERVICE_NAME,
};
use nrr_storage::StorageProfile;
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
    ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// Poll cadence while waiting for a state transition.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Best-effort drain budget applied when uninstall has to stop a running
/// service first. Uninstall proceeds even if the service is slow to go down —
/// SCM marks a still-running service for deletion on exit.
const UNINSTALL_STOP_BUDGET: Duration = Duration::from_secs(10);

/// Subdirectories of the service-owned data root that install creates.
const DATA_SUBDIRS: &[&str] = &["", "logs", "audit", "backup"];

/// Windows service control over SCM.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsServiceControl;

impl WindowsServiceControl {
    /// Control the product's own service.
    pub const fn new() -> Self {
        Self
    }
}

/// The Windows service every packet filter in this product ultimately talks to.
pub const BASE_FILTERING_ENGINE_SERVICE: &str = "BFE";

/// Is the filtering engine running? `None` when the question cannot be answered
/// (no rights to ask, SCM unreachable) — absence of an answer is not an answer.
///
/// Windows-only by nature: there is no equivalent to interrogate elsewhere, so
/// this stays out of the neutral port.
#[must_use]
pub fn filtering_engine_running() -> Option<bool> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager
        .open_service(BASE_FILTERING_ENGINE_SERVICE, ServiceAccess::QUERY_STATUS)
        .ok()?;
    let status = service.query_status().ok()?;
    Some(status.current_state == ServiceState::Running)
}

impl ServiceControlPort for WindowsServiceControl {
    fn install(
        &self,
        spec: &ServiceInstallSpec,
    ) -> Result<ServiceInstallReport, ServiceControlError> {
        // Step 1 — the privileged handle, before anything is written.
        //
        // Registration is what this install cannot do without, and it is the
        // step that refuses an unelevated caller. Taken first, an access-denied
        // leaves the machine exactly as it was; taken after the directory tree,
        // it left a `%ProgramData%` tree behind for an install that never
        // happened, which the next attempt then treats as pre-existing and
        // declines to lock down.
        let manager =
            open_manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

        // Step 2 — data directories. Still before `create_service`, so a
        // failure here leaves no half-registered service behind.
        let mut dirs_created = Vec::new();
        if spec.create_data_dirs {
            let root = service_data_root()?;
            for subdir in DATA_SUBDIRS {
                let path = if subdir.is_empty() {
                    root.clone()
                } else {
                    root.join(subdir)
                };
                if !path.exists() {
                    std::fs::create_dir_all(&path).map_err(|e| ServiceControlError::Mechanism {
                        detail: format!("create dir {}: {e}", path.display()),
                    })?;
                    dirs_created.push(path);
                }
            }
        }

        let info = ServiceInfo {
            name: OsString::from(WINDOWS_SERVICE_NAME),
            display_name: OsString::from(WINDOWS_SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: match spec.start_mode {
                ServiceStartMode::WithWindows => ServiceStartType::AutoStart,
                ServiceStartMode::OnAppLaunch => ServiceStartType::OnDemand,
            },
            error_control: ServiceErrorControl::Normal,
            executable_path: spec.binary_path.clone(),
            launch_arguments: vec![],
            // Every filter this product installs goes through the Base Filtering
            // Engine, and its API calls block rather than fail while BFE is still
            // coming up — an auto-start service that races it at OS boot can sit
            // in START_PENDING until the SCM gives up. Declaring the dependency
            // hands the ordering to the SCM.
            dependencies: vec![ServiceDependency::Service(OsString::from("BFE"))],
            account_name: spec.account_name.as_ref().map(OsString::from),
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .map_err(map_service_error)?;

        // Step 3 — description.
        service
            .set_description(WINDOWS_SERVICE_DESCRIPTION)
            .map_err(map_service_error)?;

        // Step 4 — crash recovery actions. Best-effort: a service that is
        // registered but lacks failure actions is still a working install, and
        // the report says which of the two happened.
        let recovery_configured = configure_recovery(&service, &spec.recovery).is_ok();

        // Step 5 — lock down the data directory. Only when this install created
        // the tree: rewriting the permissions of a tree someone else owns is not
        // an install's business.
        let acl_applied = if spec.create_data_dirs {
            let root = service_data_root()?;
            Some(apply_data_dir_acl(&root).is_ok())
        } else {
            None
        };

        // Step 6 — event-source registration, so lifecycle records show up under
        // our name instead of as "description cannot be found". Best-effort for
        // the same reason as recovery actions: a service that logs plainly is
        // still an installed service.
        let event_source_registered = crate::event_log::register_event_source().is_ok();

        Ok(ServiceInstallReport {
            data_dirs_created: dirs_created,
            recovery_configured,
            acl_applied,
            event_source_registered: Some(event_source_registered),
        })
    }

    fn uninstall(
        &self,
        spec: &ServiceUninstallSpec,
    ) -> Result<ServiceUninstallReport, ServiceControlError> {
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(map_service_error)?;

        let status = service.query_status().map_err(map_service_error)?;
        let mut stopped = status.current_state == ServiceState::Stopped;
        if !stopped {
            // The stop request's own refusal matters: a service that will not
            // accept control right now, or one this caller may not stop, never
            // reaches STOPPED, and waiting out the full budget to discover that
            // just turns a clear refusal into a timeout.
            if service.stop().is_ok() {
                stopped = wait_for_stopped(&service, UNINSTALL_STOP_BUDGET).is_ok();
            } else {
                // The request itself was refused. It can still be mid-stop from
                // somebody else's request, so give the state one look rather
                // than the whole budget.
                stopped = service
                    .query_status()
                    .map(|s| s.current_state == ServiceState::Stopped)
                    .unwrap_or(false);
            }
        }

        // Between the stop and the delete is the only moment this can be done:
        // an instance that was hard-killed or that timed out its drain still
        // has its filters and its DNS redirect on the machine, and the boot
        // sweep that heals them dies with the registration. Missing it leaves a
        // machine with no internet or no name resolution and nothing installed
        // that could put it right.
        //
        // ONLY when the service really did stop. Sweeping under a live service
        // is worse than not sweeping at all: its next pass puts everything back,
        // the delete then succeeds, and the machine keeps orphaned filters and
        // an NRPT rule pointing at a resolver that no longer exists — with
        // nothing installed that would sweep them at boot. The report says which
        // of the two happened rather than claiming the machine is clean.
        let machine_state_cleared = if stopped {
            Some(sweep_enforcement_state())
        } else {
            Some(false)
        };

        service.delete().map_err(map_service_error)?;

        // Leaving the source registered would keep an orphan key pointing at a
        // service that no longer exists.
        let _ = crate::event_log::deregister_event_source();

        let data_removed = if spec.remove_service_owned_data {
            let root = service_data_root()?;
            if root.exists() {
                std::fs::remove_dir_all(&root).map_err(|e| ServiceControlError::Mechanism {
                    detail: format!("remove data dir {}: {e}", root.display()),
                })?;
                true
            } else {
                false
            }
        } else {
            false
        };

        Ok(ServiceUninstallReport {
            data_removed,
            machine_state_cleared,
        })
    }

    fn start(&self, timeout: Duration) -> Result<(), ServiceControlError> {
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::START,
            )
            .map_err(map_service_error)?;

        // Already running: nothing to do. A start already in flight is NOT
        // "done" — the poll below waits for it, so a caller that asked for a
        // running service gets one or an error, never a maybe.
        let status = service.query_status().map_err(map_service_error)?;
        if status.current_state == ServiceState::Running {
            return Ok(());
        }

        service
            .start::<&str>(&[])
            .map_err(|e| match map_service_error(e) {
                ServiceControlError::Mechanism { detail } => ServiceControlError::Mechanism {
                    detail: format!("start: {detail}"),
                },
                other => other,
            })?;

        // Poll so an elevated child can confirm the transition before it exits,
        // which gives whoever polls status afterwards a clean hand-off instead
        // of a race.
        //
        // Only RUNNING ends the wait. `StartPending` is the state `start()`
        // has just put the service into, so accepting it made the first poll
        // succeed unconditionally: a service wedged in START_PENDING, or one
        // that died a second later, reported itself started and the timeout
        // branch was unreachable. STOPPED is equally terminal, and sooner —
        // the service ran and gave up, and no amount of further waiting
        // changes that.
        let deadline = Instant::now() + timeout;
        loop {
            let status = service.query_status().map_err(map_service_error)?;
            match status.current_state {
                ServiceState::Running => return Ok(()),
                ServiceState::Stopped => {
                    return Err(ServiceControlError::Mechanism {
                        detail: "start: the service stopped again on its own;                                  its own log says why"
                            .to_string(),
                    })
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(ServiceControlError::Timeout {
                    operation: "start",
                    seconds: timeout.as_secs(),
                });
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn stop(&self, timeout: Duration) -> Result<(), ServiceControlError> {
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
            )
            .map_err(map_service_error)?;

        let status = service.query_status().map_err(map_service_error)?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }

        let _ = service.stop();
        wait_for_stopped(&service, timeout)
    }

    fn query(&self) -> Result<Option<ServiceStatusReport>, ServiceControlError> {
        // Read-only, and every call below is open to unprivileged callers: this
        // is the question a user asks when nothing else works.
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = match manager.open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
        ) {
            Ok(service) => service,
            Err(e) => {
                return match map_service_error(e) {
                    ServiceControlError::NotInstalled => Ok(None),
                    other => Err(other),
                }
            }
        };

        let status = service.query_status().map_err(map_service_error)?;
        let run_state = match status.current_state {
            ServiceState::Stopped => ServiceRunState::Stopped,
            ServiceState::StartPending => ServiceRunState::StartPending,
            ServiceState::Running => ServiceRunState::Running,
            ServiceState::StopPending => ServiceRunState::StopPending,
            _ => ServiceRunState::Other,
        };

        // Config is a bonus: a service whose status reads fine but whose config
        // cannot be read is still installed and still running.
        let (start_mode, binary_path) = match service.query_config() {
            Ok(config) => (
                match config.start_type {
                    ServiceStartType::AutoStart => Some(ServiceStartMode::WithWindows),
                    ServiceStartType::OnDemand => Some(ServiceStartMode::OnAppLaunch),
                    _ => None,
                },
                Some(config.executable_path),
            ),
            Err(_) => (None, None),
        };

        Ok(Some(ServiceStatusReport {
            run_state,
            start_mode,
            binary_path,
            running_since: status.process_id.and_then(process_start_time),
        }))
    }
}

/// Creation time of a running process, or `None` when it cannot be read (the
/// process exited between the two calls, or the token lacks the right). Only
/// ever used to answer "is the binary on disk newer than what is running", so a
/// missing answer means "do not claim anything", never "assume stale".
#[allow(unsafe_code)]
fn process_start_time(pid: u32) -> Option<std::time::SystemTime> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: `OpenProcess` returns a handle we close below on every path; the
    // access mask is the least privileged one that allows `GetProcessTimes`.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all four `FILETIME`s are valid writable locals for the call, and
    // `handle` is the live handle opened above.
    let read = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    // SAFETY: closing the handle opened above, exactly once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    read.ok()?;
    Some(filetime_to_system_time(creation))
}

/// FILETIME is 100-nanosecond ticks since 1601-01-01 UTC; `SystemTime` counts
/// from the Unix epoch, 11644473600 seconds later.
fn filetime_to_system_time(ft: windows::Win32::Foundation::FILETIME) -> std::time::SystemTime {
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const EPOCH_DIFFERENCE_SECONDS: u64 = 11_644_473_600;
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    let seconds = ticks / TICKS_PER_SECOND;
    let nanos = ((ticks % TICKS_PER_SECOND) * 100) as u32;
    std::time::UNIX_EPOCH
        + std::time::Duration::new(seconds.saturating_sub(EPOCH_DIFFERENCE_SECONDS), nanos)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn open_manager(access: ServiceManagerAccess) -> Result<ServiceManager, ServiceControlError> {
    ServiceManager::local_computer(None::<&str>, access).map_err(map_service_error)
}

/// Absolute path of the service-owned data root.
fn service_data_root() -> Result<PathBuf, ServiceControlError> {
    nrr_storage::resolve_storage_topology(&StorageProfile::ProductionService)
        .map(|topology| topology.data_dir)
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("resolve storage topology: {e}"),
        })
}

/// Translate an SCM failure into the neutral taxonomy. Only two OS codes carry
/// meaning a caller can act on — everything else is reported verbatim.
fn map_service_error(err: windows_service::Error) -> ServiceControlError {
    // ERROR_ACCESS_DENIED = 5, ERROR_SERVICE_DOES_NOT_EXIST = 1060.
    if let windows_service::Error::Winapi(io_err) = &err {
        match io_err.raw_os_error() {
            Some(5) => return ServiceControlError::AccessDenied,
            Some(1060) => return ServiceControlError::NotInstalled,
            _ => {}
        }
    }
    ServiceControlError::Mechanism {
        detail: err.to_string(),
    }
}

/// Configure SCM failure actions for an already-registered service.
fn configure_recovery(
    service: &Service,
    policy: &RecoveryPolicy,
) -> Result<(), ServiceControlError> {
    use windows_service::service::{ServiceFailureActions, ServiceFailureResetPeriod};

    let mut actions: Vec<ServiceAction> = Vec::new();
    for i in 0..policy.max_auto_restarts {
        let delay_ms = if i == 0 {
            policy.first_restart_delay_ms
        } else {
            policy.second_restart_delay_ms
        };
        actions.push(ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_millis(delay_ms as u64),
        });
    }
    // Trailing "no action" entry: further failures leave the service stopped
    // for an operator instead of looping.
    actions.push(ServiceAction {
        action_type: ServiceActionType::None,
        delay: Duration::ZERO,
    });

    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(
                policy.reset_period_secs as u64,
            )),
            reboot_msg: None,
            command: None,
            actions: Some(actions),
        })
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("set failure actions: {e}"),
        })
}

/// Restrict the service-owned data directory to the security baseline.
///
/// SYSTEM and Administrators only — no `Users` entry anywhere under the tree —
/// with inheritance replaced rather than augmented. The state DB carries every
/// SID's rule set, their route bindings and their session list; the audit
/// directory is the tamper-evident record of who changed what; and the
/// operational log names the hosts each user's rules and traffic touched.
/// `storage::bootstrap` states the intended shape in so many words — "Users
/// (none)" — and this is the code that has to make it true.
///
/// `logs` used to carry `Users:(OI)(CI)RX` so the GUI could open the folder and
/// the launcher could attach the raw lines to a diagnostics archive. That made
/// one machine-wide file, holding every user's hostnames, readable by every
/// account — and it made the per-caller scoping of the log READS pointless,
/// because the same lines were a double-click away. Both readers moved: the
/// service answers `logs.list` scoped to the caller, puts the raw section into
/// the archive itself, and hands the finished archive to its requester
/// (`file_handoff`).
///
/// `icacls.exe` ships with every supported Windows release and its command line
/// is human-auditable in an install log, which is worth more here than saving a
/// process spawn on a once-per-install operation.
/// Absolute path of a `System32` tool.
///
/// `Command::new("icacls")` resolves through the process search path, which on
/// Windows includes the current directory — and this runs elevated, during an
/// install. `%SystemRoot%` names the directory Windows means; the bare name is
/// only a fallback for an environment stripped of it.
fn system32_tool(exe: &str) -> std::path::PathBuf {
    match std::env::var_os("SystemRoot") {
        Some(root) => std::path::PathBuf::from(root).join("System32").join(exe),
        None => std::path::PathBuf::from(exe),
    }
}

pub fn apply_data_dir_acl(root: &Path) -> Result<(), ServiceControlError> {
    let root_str = root
        .to_str()
        .ok_or_else(|| ServiceControlError::Mechanism {
            detail: format!("non-UTF8 data dir path: {}", root.display()),
        })?;
    run_icacls(&[
        root_str,
        "/inheritance:r",
        "/grant",
        "NT AUTHORITY\\SYSTEM:(OI)(CI)F",
        "/grant",
        "BUILTIN\\Administrators:(OI)(CI)F",
    ])?;

    Ok(())
}

/// One `icacls` invocation, with its output folded into an error on failure.
fn run_icacls(args: &[&str]) -> Result<(), ServiceControlError> {
    use std::process::Command;

    let output = Command::new(system32_tool("icacls.exe"))
        .args(args)
        .output()
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("invoke icacls: {e}"),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ServiceControlError::Mechanism {
            detail: format!(
                "icacls failed (exit={:?}): stderr={stderr} stdout={stdout}",
                output.status.code()
            ),
        });
    }
    Ok(())
}

/// Poll SCM until the service reports `Stopped` or the budget expires.
fn wait_for_stopped(service: &Service, timeout: Duration) -> Result<(), ServiceControlError> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = service.query_status().map_err(map_service_error)?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ServiceControlError::Timeout {
                operation: "stop",
                seconds: timeout.as_secs(),
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Longest the uninstall sweep waits on the filtering engine before giving up
/// and saying so.
const SWEEP_BUDGET: Duration = Duration::from_secs(30);

/// Run `work` on a worker thread and give up on it after `budget`.
///
/// `None` means it did not answer in time. The thread is abandoned rather than
/// cancelled — a blocked RPC into the filtering engine cannot be interrupted,
/// and this runs in a short-lived process that is about to exit anyway.
fn within<T, F>(budget: Duration, work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    if std::thread::Builder::new()
        .name("nrr-uninstall-sweep".to_string())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .is_err()
    {
        return None;
    }
    rx.recv_timeout(budget).ok()
}

/// Remove the two things this product leaves on the machine that can lock a
/// user out: WFP filters under our provider, and the Mode-B NRPT redirect
/// pointing all name resolution at a loopback listener that is about to stop
/// existing. Both sweeps are scoped to our own marker/provider, so an admin's
/// or another product's objects are never touched.
///
/// Routes are deliberately not swept here: ours are non-persistent and clear on
/// the next reboot, and adopting them needs the reconciler from the service
/// layer, which this crate must not depend on.
///
/// Returns `false` if either sweep could not run — the caller reports it rather
/// than failing the removal, because a registered service is the worse outcome.
fn sweep_enforcement_state() -> bool {
    let api: std::sync::Arc<dyn nrr_platform_api::windows_api::WindowsApiPort> =
        std::sync::Arc::new(crate::windows_api::ProductionWindowsApi);
    // Budgeted: opening the engine and sweeping it are both RPC into the Base
    // Filtering Engine, and a wedged engine answers neither. Removal must not
    // be the command that hangs — a service left registered is the worse
    // outcome, and our filters are not persistent, so a reboot clears whatever
    // this could not.
    let filters_swept = within(SWEEP_BUDGET, move || {
        crate::wfp::WfpSession::open(api)
            .and_then(|session| session.cleanup_all())
            .is_ok()
    })
    .unwrap_or(false);
    // Only once the filters are gone: the sub-layer cannot be deleted while
    // anything still references it. Its own handle rather than the session's —
    // that one belongs to the neutral layer and does not hand out its token.
    if filters_swept {
        if let Ok(token) = crate::win32_ffi::wfp_engine::engine_open() {
            if let Err(e) = crate::win32_ffi::wfp_sublayer::delete_sublayer(&token) {
                tracing::warn!(
                    target: "nrr::wfp",
                    error = %e,
                    "could not remove the WFP sub-layer; a reboot clears it",
                );
            }
            let _ = crate::win32_ffi::wfp_engine::engine_close(token);
        }
    }
    // Machine-wide engine options, including ones an instance that was killed
    // rather than stopped left changed — it wrote down what they held.
    crate::conn_observe::wfp_events::restore_engine_options();
    // The autostart entry, for whoever is running the removal.
    //
    // Per-user by nature (`HKCU`), so this reaches exactly one hive: the
    // caller's. Another account that also enabled autostart keeps its entry,
    // and reaching it would mean walking other users' registry — invasive, and
    // still blind to anyone not logged in. The residue is inert (it names an
    // executable that no longer exists), so the honest split is: clear what we
    // can reach here, and leave the rest to a per-user uninstall action.
    if let Err(e) = nrr_platform_api::autostart::AutostartRegistryPort::delete_value(
        &crate::autostart::ProductionAutostartRegistry,
    ) {
        tracing::debug!(
            target: "nrr::autostart",
            error = ?e,
            "no autostart entry of ours to remove for this user",
        );
    }
    let dns_swept =
        crate::dns_redirect::clear_orphan_redirect(&crate::dns_redirect::TransactedNrptStore)
            .is_ok();
    filters_swept && dns_swept
}
