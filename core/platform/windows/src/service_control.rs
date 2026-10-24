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
use nrr_platform_api::service_placement::{
    plan_copy, registers_protected_copy, CopyPlan, RegisteredFrom,
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
/// How long an ended service process takes to read as stopped.
const KILL_SETTLE: Duration = Duration::from_secs(10);

/// The most a pending service's own wait hint may stretch a start wait: past
/// it, a hint reads as a hang rather than a slow step.
const MAX_WAIT_HINT: Duration = Duration::from_secs(120);

/// Best-effort drain budget applied when uninstall has to stop a running
/// service first. Uninstall proceeds even if the service is slow to go down —
/// SCM marks a still-running service for deletion on exit.
const UNINSTALL_STOP_BUDGET: Duration = Duration::from_secs(10);

/// Subdirectories of the service-owned data root that install creates.
const DATA_SUBDIRS: &[&str] = &[
    "",
    "logs",
    nrr_platform_api::service_control::AUDIT_SUBDIR,
    "backup",
];

/// Delete the data tree at `root`; without `with_audit` the audit trail and the
/// root holding it stay.
fn remove_data_tree(root: &std::path::Path, with_audit: bool) -> Result<(), ServiceControlError> {
    let failed = |path: &std::path::Path, e: std::io::Error| ServiceControlError::Mechanism {
        detail: format!("remove data {}: {e}", path.display()),
    };
    if with_audit {
        return std::fs::remove_dir_all(root).map_err(|e| failed(root, e));
    }
    let entries = std::fs::read_dir(root).map_err(|e| failed(root, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| failed(root, e))?;
        if entry
            .file_name()
            .eq_ignore_ascii_case(nrr_platform_api::service_control::AUDIT_SUBDIR)
        {
            continue;
        }
        let path = entry.path();
        let removed = if entry.file_type().map_err(|e| failed(&path, e))?.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.map_err(|e| failed(&path, e))?;
    }
    Ok(())
}

/// How long an install that updates the protected copy waits for the service
/// to stop (past it, nothing is replaced), and then for it to start again.
const COPY_UPDATE_STOP_BUDGET: Duration = Duration::from_secs(30);
const COPY_UPDATE_START_BUDGET: Duration = Duration::from_secs(30);

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

/// The file a deliberate stop leaves in the service data root; a stop without
/// it is restarted by SCM. Writable by administrators only: anyone else could
/// switch that restart off. `scripts/lib/service-paths.ps1` writes the same
/// file for the scripts and the installer.
const DELIBERATE_STOP_MARKER: &str = "deliberate-stop";

/// How long a marker speaks for a stop. A stop that never arrived must not
/// silence a later unasked one.
const DELIBERATE_STOP_FRESHNESS: Duration = Duration::from_secs(120);

/// Beside the deliberate-stop marker: the stop is an installer's, which starts
/// the service again on new files, so the stop leaves protection in place for
/// the new instance. Administrators only, like the other marker: anyone else
/// could make a stop keep its blocks. `scripts/lib/service-paths.ps1` writes
/// the same file.
const UPGRADE_STOP_MARKER: &str = "upgrade-stop";

/// The marker path, only while the data root is a real directory a trusted
/// account owns: anyone may create folders in ProgramData, and a planted root
/// or a link in it would steer an elevated write onto another file.
fn deliberate_stop_marker() -> Option<PathBuf> {
    marker_in_data_root(DELIBERATE_STOP_MARKER)
}

fn marker_in_data_root(name: &str) -> Option<PathBuf> {
    let root = service_data_root().ok()?;
    let meta = std::fs::symlink_metadata(&root).ok()?;
    let is_link =
        std::os::windows::fs::MetadataExt::file_attributes(&meta) & REPARSE_POINT_ATTRIBUTE != 0;
    if !meta.is_dir() || is_link {
        return None;
    }
    if !crate::trusted_location::owner_is_trusted(&root).unwrap_or(false) {
        return None;
    }
    Some(root.join(name))
}

/// `FILE_ATTRIBUTE_REPARSE_POINT`: a junction or symbolic link.
const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

/// Say that the next stop is wanted and must not be undone by a restart. The
/// file is created anew, never opened through whatever already has its name.
fn mark_deliberate_stop() {
    let Some(path) = deliberate_stop_marker() else {
        return;
    };
    let Some(program_data) = crate::system_shell::program_data_directory() else {
        return;
    };
    let _ = std::fs::remove_file(&path);
    let _ = crate::pinned_file::create_new(&program_data, &path);
}

/// Say that the next stop is an upgrade's.
fn mark_upgrade_stop() {
    let Some(path) = marker_in_data_root(UPGRADE_STOP_MARKER) else {
        return;
    };
    let Some(program_data) = crate::system_shell::program_data_directory() else {
        return;
    };
    let _ = std::fs::remove_file(&path);
    let _ = crate::pinned_file::create_new(&program_data, &path);
}

/// Whether the stop under way is an installer's. Consumes the marker; a stale
/// one counts for nothing, so an upgrade that never stopped the service cannot
/// make a later stop keep its blocks.
#[must_use]
pub fn take_upgrade_stop_marker() -> bool {
    let Some(path) = marker_in_data_root(UPGRADE_STOP_MARKER) else {
        return false;
    };
    let fresh = std::fs::symlink_metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .and_then(|meta| meta.modified().ok())
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|age| age <= DELIBERATE_STOP_FRESHNESS);
    let _ = std::fs::remove_file(&path);
    fresh
}

/// Ask SCM for a wanted stop. A refused request (a service still starting
/// accepts no control) takes its mark back: left behind, it would excuse the
/// next stop nobody asked for and keep the service down.
fn stop_deliberately(service: &windows_service::service::Service) -> windows_service::Result<()> {
    mark_deliberate_stop();
    let asked = service.stop().map(drop);
    if asked.is_err() {
        if let Some(path) = deliberate_stop_marker() {
            let _ = std::fs::remove_file(path);
        }
    }
    asked
}

/// Whether the stop under way was asked for by one of our own verbs. Consumes
/// the marker; a stale one counts for nothing.
#[must_use]
pub fn take_deliberate_stop_marker() -> bool {
    let Some(path) = deliberate_stop_marker() else {
        return false;
    };
    let fresh = std::fs::symlink_metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .and_then(|meta| meta.modified().ok())
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|age| age <= DELIBERATE_STOP_FRESHNESS);
    let _ = std::fs::remove_file(&path);
    fresh
}

/// Left by a stop that found the service already down: SCM may hold a restart
/// scheduled after a crash, and nothing cancels a scheduled restart. The start
/// it makes reads this and ends at once.
const STAY_STOPPED_MARKER: &str = "stay-stopped";

fn mark_stay_stopped() {
    let Some(path) = marker_in_data_root(STAY_STOPPED_MARKER) else {
        return;
    };
    let Some(program_data) = crate::system_shell::program_data_directory() else {
        return;
    };
    let _ = std::fs::remove_file(&path);
    let _ = crate::pinned_file::create_new(&program_data, &path);
}

/// An asked-for start outranks an earlier "stay stopped": every path that
/// requests a start calls this first. The marker sits in the administrators-
/// only data root, so an unprivileged caller's call is a no-op by design.
pub fn clear_stay_stopped() {
    if let Some(path) = marker_in_data_root(STAY_STOPPED_MARKER) {
        let _ = std::fs::remove_file(path);
    }
}

/// Who asked for a stop. Only the verb may leave a crashed service down: an
/// install replacing the copy starts it again or leaves it as found, and a
/// marker written there would eat the next start anyone requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopCaller {
    Verb,
    Install,
}

/// Whether a stop that found the service crashed asks it to stay down.
fn stays_stopped(caller: StopCaller, found_crashed: bool) -> bool {
    found_crashed && caller == StopCaller::Verb
}

/// Whether this start is a restart SCM scheduled before a stop asked the
/// service to stay down. Consumes the marker.
#[must_use]
pub fn take_stay_stopped_marker() -> bool {
    let Some(path) = marker_in_data_root(STAY_STOPPED_MARKER) else {
        return false;
    };
    let written = std::fs::symlink_metadata(&path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .and_then(|meta| meta.modified().ok());
    let _ = std::fs::remove_file(&path);
    let boot = crate::event_log::current_boot_started_at_ms()
        .map(|ms| std::time::UNIX_EPOCH + Duration::from_millis(ms));
    written.is_some_and(|written| stay_stopped_applies(written, std::time::SystemTime::now(), boot))
}

/// Only while a scheduled restart can still fire (its longest delay plus a
/// minute), and never across a boot: a boot starts the service on purpose.
fn stay_stopped_applies(
    written: std::time::SystemTime,
    now: std::time::SystemTime,
    boot: Option<std::time::SystemTime>,
) -> bool {
    let longest_delay = failure_action_plan(&RecoveryPolicy::production())
        .into_iter()
        .map(|(_, delay)| delay)
        .max()
        .unwrap_or_default();
    let fresh = now
        .duration_since(written)
        .is_ok_and(|age| age <= longest_delay + Duration::from_secs(60));
    fresh && boot.is_some_and(|boot| written >= boot)
}

/// Why the service was stopped by something other than its own verbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaskedStop {
    /// The filtering engine went down and took the service with it.
    EngineDown,
    Other,
}

const UNASKED_STOP_ENGINE_MARKER: &str = "unasked-stop-engine";
const UNASKED_STOP_OTHER_MARKER: &str = "unasked-stop-other";

/// How long such a note stays worth reporting: SCM restarts the service within
/// a minute, and a note older than a reboot says nothing about this start.
const UNASKED_STOP_NOTE_FRESHNESS: Duration = Duration::from_secs(900);

/// Leave a note for the next start about a stop nobody asked for, so the
/// restarted service can say why it was down. Best effort.
pub fn note_unasked_stop(cause: UnaskedStop) {
    let name = match cause {
        UnaskedStop::EngineDown => UNASKED_STOP_ENGINE_MARKER,
        UnaskedStop::Other => UNASKED_STOP_OTHER_MARKER,
    };
    let Some(path) = marker_in_data_root(name) else {
        return;
    };
    let Some(program_data) = crate::system_shell::program_data_directory() else {
        return;
    };
    let _ = std::fs::remove_file(&path);
    let _ = crate::pinned_file::create_new(&program_data, &path);
}

/// The cause the previous run left with [`note_unasked_stop`], if fresh.
/// Consumes the notes.
#[must_use]
pub fn take_unasked_stop_note() -> Option<UnaskedStop> {
    let mut found = None;
    for (name, cause) in [
        (UNASKED_STOP_ENGINE_MARKER, UnaskedStop::EngineDown),
        (UNASKED_STOP_OTHER_MARKER, UnaskedStop::Other),
    ] {
        let Some(path) = marker_in_data_root(name) else {
            continue;
        };
        let fresh = std::fs::symlink_metadata(&path)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .and_then(|meta| meta.modified().ok())
            .and_then(|at| at.elapsed().ok())
            .is_some_and(|age| age <= UNASKED_STOP_NOTE_FRESHNESS);
        let _ = std::fs::remove_file(&path);
        if fresh && found.is_none() {
            found = Some(cause);
        }
    }
    found
}

/// The service's recovery actions, switched off until [`RecoveryHold::release`]
/// or drop. The SCM restarts a process that ends without reporting itself
/// stopped, so ending a hung service with these on would bring it back in the
/// middle of the cleanup that follows.
pub struct RecoveryHold {
    saved: Option<(windows_service::service::ServiceFailureActions, bool)>,
}

/// Switch the recovery actions off, remembering them.
pub fn hold_recovery() -> Result<RecoveryHold, ServiceControlError> {
    use windows_service::service::{ServiceFailureActions, ServiceFailureResetPeriod};
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(map_service_error)?;
    let actions = service
        .get_failure_actions()
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("read failure actions: {}", winapi_detail(&e)),
        })?;
    let non_crash = service
        .get_failure_actions_on_non_crash_failures()
        .unwrap_or(true);
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::ZERO),
            reboot_msg: None,
            command: None,
            actions: Some(Vec::new()),
        })
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("suspend failure actions: {}", winapi_detail(&e)),
        })?;
    let _ = service.set_failure_actions_on_non_crash_failures(false);
    Ok(RecoveryHold {
        saved: Some((actions, non_crash)),
    })
}

/// What happens to the recovery actions a stop took off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryAfterStop {
    /// The service stays down; it puts them back on its next start.
    LeaveOff,
    /// The stop did not happen: the running service needs them back now.
    PutBack,
}

fn recovery_after_stop(stop_succeeded: bool) -> RecoveryAfterStop {
    if stop_succeeded {
        RecoveryAfterStop::LeaveOff
    } else {
        RecoveryAfterStop::PutBack
    }
}

/// Whether the registered failure actions are the empty set a deliberate stop
/// (or an interrupted cleanup) leaves behind.
fn recovery_missing(actions: &windows_service::service::ServiceFailureActions) -> bool {
    actions.actions.as_ref().is_none_or(Vec::is_empty)
}

/// At service start: put the recovery actions back if a stop took them off.
/// Returns whether they had to be restored.
pub fn restore_recovery_if_missing(binary: &Path) -> Result<bool, ServiceControlError> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .map_err(map_service_error)?;
    let current = service
        .get_failure_actions()
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("read failure actions: {}", winapi_detail(&e)),
        })?;
    if !recovery_missing(&current) {
        return Ok(false);
    }
    configure_recovery(&service, &RecoveryPolicy::production(), binary)?;
    Ok(true)
}

impl RecoveryHold {
    /// Keep the recovery actions off.
    fn leave_off(mut self) {
        self.saved = None;
    }

    /// Put the recovery actions back.
    pub fn release(mut self) -> Result<(), ServiceControlError> {
        self.restore()
    }

    fn restore(&mut self) -> Result<(), ServiceControlError> {
        let Some((actions, non_crash)) = self.saved.take() else {
            return Ok(());
        };
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        // Restart actions are refused on a handle without START access.
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
            )
            .map_err(map_service_error)?;
        service
            .update_failure_actions(actions)
            .map_err(|e| ServiceControlError::Mechanism {
                detail: format!("restore failure actions: {}", winapi_detail(&e)),
            })?;
        service
            .set_failure_actions_on_non_crash_failures(non_crash)
            .map_err(|e| ServiceControlError::Mechanism {
                detail: format!(
                    "restore failure actions on non-crash failures: {}",
                    winapi_detail(&e)
                ),
            })
    }
}

impl Drop for RecoveryHold {
    fn drop(&mut self) {
        let _ = self.restore();
    }
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

        // SCM will start this file as LocalSystem on every boot, and a DLL
        // beside it loads before the system copy: a binary ordinary accounts
        // can change is registered as a protected copy instead.
        let binary_path = match self.place_binary(&manager, &spec.binary_path)? {
            Placement::Register(path) => path,
            Placement::AlreadyRegistered => return Ok(refresh_registration(&manager, spec)),
        };

        // Step 2 — data directories, locked down before anything is registered.
        // A tree that already exists is locked down too: `%ProgramData%` lets
        // any user create it first and stay its owner.
        let mut dirs_created = Vec::new();
        let mut acl_applied = None;
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
            acl_applied = Some(adopt_data_tree(&root, &dirs_created)?);
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
            executable_path: binary_path.clone(),
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
        let recovery_configured =
            configure_recovery(&service, &spec.recovery, &binary_path).is_ok();

        // Step 5 — event-source registration, so lifecycle records show up under
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
                ServiceAccess::QUERY_STATUS
                    | ServiceAccess::QUERY_CONFIG
                    | ServiceAccess::STOP
                    | ServiceAccess::DELETE,
            )
            .map_err(map_service_error)?;
        // Read while the registration exists: it says whether the protected
        // copy is what this service ran.
        let registered_binary = service.query_config().ok().map(|config| {
            nrr_platform_api::autostart::executable_of_command_line(
                &config.executable_path.to_string_lossy(),
            )
        });

        let status = service.query_status().map_err(map_service_error)?;
        let mut stopped = status.current_state == ServiceState::Stopped;
        if !stopped {
            // The stop request's own refusal matters: a service that will not
            // accept control right now, or one this caller may not stop, never
            // reaches STOPPED, and waiting out the full budget to discover that
            // just turns a clear refusal into a timeout.
            if stop_deliberately(&service).is_ok() {
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

        // A process that did not stop still runs from the copy.
        if stopped {
            remove_protected_copy(registered_binary.as_deref());
        }

        let data_removed = if spec.remove_service_owned_data {
            let root = service_data_root()?;
            if root.exists() {
                remove_data_tree(&root, spec.remove_audit_trail)?;
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

        // A start already in flight is NOT "done" — the poll below waits for
        // it, so a caller that asked for a running service gets one or an
        // error, never a maybe.
        let mut status = service.query_status().map_err(map_service_error)?;
        let step = start_step(status.current_state);
        if step == StartStep::AlreadyRunning {
            return Ok(());
        }
        if step == StartStep::LetStopFinish {
            // A stop in flight (SCM recovery, a peer's restart) rejects a start.
            wait_for_stopped(&service, timeout)?;
            status = service.query_status().map_err(map_service_error)?;
        }
        if matches!(step, StartStep::Request | StartStep::LetStopFinish) {
            // An asked-for start outranks an earlier "stay stopped".
            clear_stay_stopped();
            if let Err(e) = service.start::<&str>(&[]) {
                if !is_already_running(&e) {
                    return Err(match map_service_error(e) {
                        ServiceControlError::Mechanism { detail } => {
                            ServiceControlError::Mechanism {
                                detail: format!("start: {detail}"),
                            }
                        }
                        other => other,
                    });
                }
            }
        }

        // Poll so an elevated child can confirm the transition before it exits,
        // which gives whoever polls status afterwards a clean hand-off instead
        // of a race.
        //
        // Only RUNNING ends the wait: accepting START_PENDING made a wedged
        // service read as started. STOPPED is terminal too — the service ran
        // and gave up.
        //
        // A pending service names how long its next step may take (wait hint)
        // and moves its checkpoint as it goes; the wait honours that, as the
        // service manager does, so a start slower than `timeout` but still
        // reporting is not called a failure.
        let waited_since = Instant::now();
        let deadline = waited_since + timeout;
        let mut progress = (status.checkpoint, waited_since);
        loop {
            let status = service.query_status().map_err(map_service_error)?;
            match status.current_state {
                ServiceState::Running => return Ok(()),
                ServiceState::Stopped => {
                    return Err(ServiceControlError::Mechanism {
                        detail: "start: the service stopped again on its own; its own log says why"
                            .to_string(),
                    })
                }
                _ => {}
            }
            let now = Instant::now();
            if status.checkpoint != progress.0 {
                progress = (status.checkpoint, now);
            }
            if start_wait_over(now, deadline, progress.1, status.wait_hint) {
                return Err(ServiceControlError::Timeout {
                    operation: "start",
                    seconds: waited_since.elapsed().as_secs(),
                });
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn stop(&self, timeout: Duration) -> Result<(), ServiceControlError> {
        self.stop_as(timeout, StopCaller::Verb)
    }

    fn kill(&self) -> Result<(), ServiceControlError> {
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .map_err(map_service_error)?;
        let status = service.query_status().map_err(map_service_error)?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        // A stop under way can leave the process gone before the state says so.
        let Some(pid) = status.process_id else {
            return wait_for_stopped(&service, KILL_SETTLE);
        };
        if !crate::win32_ffi::process::terminate(pid) {
            return Err(ServiceControlError::Mechanism {
                detail: format!("process {pid} could not be ended"),
            });
        }
        wait_for_stopped(&service, KILL_SETTLE)
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
                // SCM hands back the command line, quoted and with any arguments.
                Some(nrr_platform_api::autostart::executable_of_command_line(
                    &config.executable_path.to_string_lossy(),
                )),
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

/// When this process was created: what a slow start is measured from, since the
/// image load and the service manager's dispatch come before `main`.
pub fn own_process_start_time() -> Option<std::time::SystemTime> {
    process_start_time(std::process::id())
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

// в”Ђв”Ђ Helpers в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn open_manager(access: ServiceManagerAccess) -> Result<ServiceManager, ServiceControlError> {
    ServiceManager::local_computer(None::<&str>, access).map_err(map_service_error)
}

/// The service data root under `%ProgramData%` as the shell registers it. The
/// storage layer resolves the same tree from an environment string, and an
/// install elevated on a user's behalf carries that user's environment: a root
/// the two disagree on is refused rather than touched.
fn service_data_root() -> Result<PathBuf, ServiceControlError> {
    let program_data = program_data()?;
    let root = program_data.join(nrr_platform_api::paths::product_dir_leaf());
    let resolved = nrr_storage::resolve_storage_topology(&StorageProfile::ProductionService)
        .map(|topology| topology.data_dir)
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("resolve storage topology: {e}"),
        })?;
    if !same_lexical_path(&resolved, &root) {
        return Err(ServiceControlError::InvalidState {
            detail: format!(
                "data directory {} is not {}; refusing to touch it",
                resolved.display(),
                root.display()
            ),
        });
    }
    ensure_under(&root, &program_data)?;
    Ok(root)
}

fn program_data() -> Result<PathBuf, ServiceControlError> {
    crate::system_shell::program_data_directory().ok_or_else(|| ServiceControlError::Mechanism {
        detail: "cannot resolve the ProgramData folder".to_string(),
    })
}

fn ensure_under_program_data(root: &Path) -> Result<(), ServiceControlError> {
    ensure_under(root, &program_data()?)
}

/// Lexically, and again through the file system where the root exists: a link
/// anywhere on the way would point the tree outside `ProgramData`.
fn ensure_under(root: &Path, program_data: &Path) -> Result<(), ServiceControlError> {
    let refuse = || ServiceControlError::InvalidState {
        detail: format!(
            "data directory {} is not under {}; refusing to touch it",
            root.display(),
            program_data.display()
        ),
    };
    if !is_within(root, program_data) {
        return Err(refuse());
    }
    if let (Ok(real_root), Ok(real_base)) = (
        std::fs::canonicalize(root),
        std::fs::canonicalize(program_data),
    ) {
        if !is_within(&real_root, &real_base) {
            return Err(refuse());
        }
    }
    Ok(())
}

/// Component-wise and case-insensitive: a folder inside `ProgramData` is
/// within it, a sibling whose name merely starts the same is not. A `..` is
/// refused outright: only the file system resolves it, so a lexical match
/// says nothing about where it leads.
fn is_within(path: &Path, base: &Path) -> bool {
    use std::path::Component;
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
    lower(path).starts_with(lower(base))
}

fn same_lexical_path(a: &Path, b: &Path) -> bool {
    is_within(a, b) && is_within(b, a)
}

/// Who besides SYSTEM, Administrators and TrustedInstaller could change
/// `binary` or plant a file beside it, or `None` when nobody can. Permissions
/// that cannot be read count as a problem, never as protected.
fn location_problem(binary: &Path) -> Option<String> {
    match crate::trusted_location::untrusted_writer(binary) {
        Ok(None) => None,
        Ok(Some(writer)) => Some(writer),
        Err(e) => Some(format!(
            "cannot tell who can change {}: {e}",
            binary.display()
        )),
    }
}

/// What the install registers.
enum Placement {
    /// Register this binary.
    Register(PathBuf),
    /// The existing registration already names the protected copy, which is
    /// current now; there is nothing to register.
    AlreadyRegistered,
}

impl WindowsServiceControl {
    /// Stop for `caller`; see [`StopCaller`] for what differs.
    fn stop_as(&self, timeout: Duration, caller: StopCaller) -> Result<(), ServiceControlError> {
        // Taken first: a service already down may have a restart scheduled by
        // SCM, and only the actions decide whether it fires.
        let hold = hold_recovery().ok();
        let result = (|| {
            let manager = open_manager(ServiceManagerAccess::CONNECT)?;
            let service = manager
                .open_service(
                    WINDOWS_SERVICE_NAME,
                    ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
                )
                .map_err(map_service_error)?;

            let status = service.query_status().map_err(map_service_error)?;
            if status.current_state == ServiceState::Stopped {
                // Only a failed exit can have a restart scheduled behind it.
                let failed = !matches!(
                    status.exit_code,
                    windows_service::service::ServiceExitCode::Win32(0)
                );
                return Ok(failed);
            }

            if caller == StopCaller::Install {
                mark_upgrade_stop();
            }
            if stop_deliberately(&service).is_err() && caller == StopCaller::Install {
                let _ = take_upgrade_stop_marker();
            }
            wait_for_stopped(&service, timeout).map(|()| false)
        })();
        if stays_stopped(caller, matches!(result, Ok(true))) {
            mark_stay_stopped();
        }
        let result = result.map(drop);
        if let Some(hold) = hold {
            match recovery_after_stop(result.is_ok()) {
                RecoveryAfterStop::LeaveOff => hold.leave_off(),
                RecoveryAfterStop::PutBack => drop(hold),
            }
        }
        result
    }

    /// The binary to register for `source`: itself when only administrators
    /// can change it (or in a development build, whose binary lives in the
    /// build directory by design), else the protected copy, written or updated
    /// first. The copy is registered only once its own location checks out.
    fn place_binary(
        &self,
        manager: &ServiceManager,
        source: &Path,
    ) -> Result<Placement, ServiceControlError> {
        let problem = location_problem(source);
        if !registers_protected_copy(problem.is_none(), cfg!(debug_assertions)) {
            if let Some(problem) = problem {
                tracing::warn!(
                    target: "nrr::service-control",
                    msg_key = "win-svcctl-untrusted-binary-location",
                    problem = %problem,
                    "registering a service binary that non-administrators can change — development build only",
                );
            }
            return Ok(Placement::Register(source.to_path_buf()));
        }
        let relocation = |detail: String| ServiceControlError::Relocation { detail };
        let dir = crate::service_placement::installed_copy_dir().map_err(relocation)?;
        let target = crate::service_placement::installed_copy_binary(&dir);
        let payload = crate::service_placement::Payload::read(source).map_err(relocation)?;
        let copy = payload.state_in(&dir).map_err(relocation)?;
        let placement = match plan_copy(copy, registered_from(manager, &target)?) {
            CopyPlan::RefuseRegisteredElsewhere => {
                return Err(ServiceControlError::InvalidState {
                    detail: "the service is already registered from another folder; \
                             reinstall replaces that registration"
                        .to_string(),
                })
            }
            CopyPlan::Nothing => Placement::AlreadyRegistered,
            CopyPlan::Register => {
                crate::service_placement::prepare_copy_dir(&dir).map_err(relocation)?;
                Placement::Register(target.clone())
            }
            CopyPlan::WriteAndRegister => {
                write_protected_copy(&dir, &payload)?;
                Placement::Register(target.clone())
            }
            CopyPlan::Update { restart } => {
                self.stop_as(COPY_UPDATE_STOP_BUDGET, StopCaller::Install)
                    .map_err(|e| ServiceControlError::InvalidState {
                        detail: format!(
                            "the service did not stop, so its files were not replaced: {e}"
                        ),
                    })?;
                write_protected_copy(&dir, &payload)?;
                if restart {
                    self.start(COPY_UPDATE_START_BUDGET)?;
                }
                Placement::AlreadyRegistered
            }
        };
        if let Some(problem) = location_problem(&target) {
            return Err(relocation(format!(
                "{problem}; the copy is not out of reach of ordinary accounts"
            )));
        }
        Ok(placement)
    }
}

fn write_protected_copy(
    dir: &Path,
    payload: &crate::service_placement::Payload,
) -> Result<(), ServiceControlError> {
    let relocation = |detail: String| ServiceControlError::Relocation { detail };
    crate::service_placement::prepare_copy_dir(dir).map_err(relocation)?;
    payload.write_to(dir).map_err(relocation)
}

/// What the service manager has registered, measured against the protected
/// copy's path — a location this process computed, never one it was handed.
fn registered_from(
    manager: &ServiceManager,
    copy: &Path,
) -> Result<RegisteredFrom, ServiceControlError> {
    let service = match manager.open_service(
        WINDOWS_SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
    ) {
        Ok(service) => service,
        Err(e) => {
            return match map_service_error(e) {
                ServiceControlError::NotInstalled => Ok(RegisteredFrom::Nothing),
                other => Err(other),
            }
        }
    };
    let config = service.query_config().map_err(map_service_error)?;
    let registered = nrr_platform_api::autostart::executable_of_command_line(
        &config.executable_path.to_string_lossy(),
    );
    if !same_file_path(&registered, copy) {
        return Ok(RegisteredFrom::Elsewhere);
    }
    let status = service.query_status().map_err(map_service_error)?;
    Ok(RegisteredFrom::TheCopy {
        running: status.current_state != ServiceState::Stopped,
    })
}

/// An install over a registration that already names the current protected
/// copy: re-apply what install configures, register nothing.
fn refresh_registration(
    manager: &ServiceManager,
    spec: &ServiceInstallSpec,
) -> ServiceInstallReport {
    let recovery_configured = manager
        .open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_CONFIG | ServiceAccess::START,
        )
        .is_ok_and(|service| {
            let _ = service.set_description(WINDOWS_SERVICE_DESCRIPTION);
            service.query_config().is_ok_and(|config| {
                // SCM hands back the command line, quoted; the after-crash
                // command quotes the path itself, and a doubly quoted one
                // never runs.
                let binary = registered_binary_of(&config.executable_path);
                configure_recovery(&service, &spec.recovery, &binary).is_ok()
            })
        });
    ServiceInstallReport {
        data_dirs_created: Vec::new(),
        recovery_configured,
        acl_applied: None,
        event_source_registered: Some(crate::event_log::register_event_source().is_ok()),
    }
}

/// After the registration is gone, remove the protected copy if it was what
/// the service ran. The folder is computed here; the registered path only says
/// whether it is ours to remove. A failure leaves an inert administrators-only
/// folder the next install reuses.
fn remove_protected_copy(registered: Option<&Path>) {
    let (Some(registered), Ok(dir)) = (registered, crate::service_placement::installed_copy_dir())
    else {
        return;
    };
    if !same_file_path(
        registered,
        &crate::service_placement::installed_copy_binary(&dir),
    ) {
        return;
    }
    // A removal run from the copy itself (the registered binary's own
    // `uninstall`) cannot delete its running image: that part waits for the
    // next restart.
    if let Err(e) = crate::service_placement::remove_copy_dir(&dir) {
        tracing::warn!(
            target: "nrr::service-control",
            msg_key = "win-svcctl-protected-copy-not-removed",
            error = %e,
            "the service's protected copy could not be removed; the next install reuses it",
        );
    }
}

/// Path equality as the file system sees it: case, separators, a trailing
/// separator and the verbatim prefix do not make two paths different.
fn same_file_path(left: &Path, right: &Path) -> bool {
    fn comparable(path: &Path) -> String {
        let text = path.to_string_lossy().replace('/', "\\");
        text.strip_prefix(r"\\?\")
            .unwrap_or(&text)
            .trim_end_matches('\\')
            .to_lowercase()
    }
    comparable(left) == comparable(right)
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
        detail: winapi_detail(&err),
    }
}

/// The crate's own text for a Win32 failure is only "IO error in winapi call";
/// the OS error behind it is what tells a report apart.
fn winapi_detail(err: &windows_service::Error) -> String {
    match err {
        windows_service::Error::Winapi(io_err) => format!("{err}: {io_err}"),
        _ => err.to_string(),
    }
}

/// The SCM failure actions for `policy`, in failure order. The SCM repeats the
/// last one for every failure after it: a run command mid-list fires once, and
/// the restart after it carries the service through any later failure.
fn failure_action_plan(policy: &RecoveryPolicy) -> Vec<(ServiceActionType, Duration)> {
    let mut plan: Vec<(ServiceActionType, Duration)> = (0..policy.max_auto_restarts)
        .map(|i| {
            let ms = match i {
                0 => policy.first_restart_delay_ms,
                1 => policy.second_restart_delay_ms,
                _ => policy.later_restart_delay_ms,
            };
            (
                ServiceActionType::Restart,
                Duration::from_millis(u64::from(ms)),
            )
        })
        .collect();
    if policy.release_network_when_exhausted {
        plan.push((ServiceActionType::RunCommand, Duration::from_secs(1)));
    }
    plan.push(if policy.exhausted_restart_delay_ms > 0 {
        (
            ServiceActionType::Restart,
            Duration::from_millis(u64::from(policy.exhausted_restart_delay_ms)),
        )
    } else {
        (ServiceActionType::None, Duration::ZERO)
    });
    plan
}

/// The binary behind the command line SCM registered (`"path" args`).
fn registered_binary_of(command_line: &Path) -> PathBuf {
    nrr_platform_api::autostart::executable_of_command_line(&command_line.to_string_lossy())
}

/// The command SCM runs once the restarts are spent: the service binary's own
/// `after-crash` verb, the path quoted exactly once.
fn after_crash_command(binary: &Path) -> OsString {
    OsString::from(format!("\"{}\" after-crash", binary.display()))
}

/// Configure SCM failure actions for an already-registered service.
fn configure_recovery(
    service: &Service,
    policy: &RecoveryPolicy,
    binary: &Path,
) -> Result<(), ServiceControlError> {
    use windows_service::service::{ServiceFailureActions, ServiceFailureResetPeriod};

    let actions = failure_action_plan(policy);
    let command = policy
        .release_network_when_exhausted
        .then(|| after_crash_command(binary));
    let actions: Vec<ServiceAction> = actions
        .into_iter()
        .map(|(action_type, delay)| ServiceAction { action_type, delay })
        .collect();

    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(
                policy.reset_period_secs as u64,
            )),
            reboot_msg: None,
            command,
            actions: Some(actions),
        })
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!("set failure actions: {}", winapi_detail(&e)),
        })?;
    // A stop that reports an error — the service going down with the filtering
    // engine — gets the same recovery as a crash.
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| ServiceControlError::Mechanism {
            detail: format!(
                "set failure actions on non-crash failures: {}",
                winapi_detail(&e)
            ),
        })
}

/// Restrict the service-owned data directory to the security baseline.
///
/// SYSTEM and Administrators only — no `Users` entry anywhere under the tree.
/// The state DB carries every SID's rule set, route bindings and session list;
/// the audit directory is the tamper-evident record of who changed what; the
/// operational log names the hosts each user's traffic touched. Reads of those
/// go through the service, scoped to the caller, and a diagnostics archive is
/// handed over by `file_handoff` — nothing needs the folder itself.
///
/// The owner becomes Administrators and explicit entries below the root are
/// dropped: under `%ProgramData%` any account may create the tree first, and
/// an owner can always grant itself access back. A link anywhere in the tree
/// is refused as [`ServiceControlError::InvalidState`].
pub fn apply_data_dir_acl(root: &Path) -> Result<(), ServiceControlError> {
    // The root comes from an environment string; resetting ownership of a tree
    // someone else pointed it at is not this function's business.
    ensure_under_program_data(root)?;
    crate::trusted_location::lock_down_service_tree(root).map_err(|e| match e {
        crate::trusted_location::LockdownError::Link(_) => ServiceControlError::InvalidState {
            detail: format!("refusing the data directory: {e}"),
        },
        crate::trusted_location::LockdownError::Failed(detail) => {
            ServiceControlError::Mechanism { detail }
        }
    })
}

/// Take over a data tree that may predate this install, then lock it down.
///
/// `%ProgramData%` lets any user create the tree first: the lockdown hands its
/// permissions back, but not what was planted inside or handles held open, and
/// the service would start on that state. So a tree holding anything owned
/// outside SYSTEM/Administrators is refused, as is anything that appears while
/// it is being locked down. What this install just `created` is its own,
/// whoever the installing admin's objects default to. `Ok(false)`: adopted,
/// but the lockdown failed.
fn adopt_data_tree(root: &Path, created: &[PathBuf]) -> Result<bool, ServiceControlError> {
    use crate::trusted_location::tree_ownership;
    ensure_under_program_data(root)?;
    let census = |root: &Path| {
        tree_ownership(root).map_err(|e| ServiceControlError::InvalidState {
            detail: format!("cannot verify who owns the data directory: {e}"),
        })
    };
    let before = census(root)?;
    adoption_verdict(root, created, &before, None)?;
    let locked = match apply_data_dir_acl(root) {
        Ok(()) => true,
        Err(refused @ ServiceControlError::InvalidState { .. }) => return Err(refused),
        Err(_) => false,
    };
    adoption_verdict(root, created, &before, Some(&census(root)?))?;
    Ok(locked)
}

/// The refusal, if any, for a tree read `before` the lockdown and `after` it.
fn adoption_verdict(
    root: &Path,
    created: &[PathBuf],
    before: &crate::trusted_location::TreeOwnership,
    after: Option<&crate::trusted_location::TreeOwnership>,
) -> Result<(), ServiceControlError> {
    let refuse = |what: String| ServiceControlError::InvalidState {
        detail: format!(
            "{what}; remove {} as an administrator and install again",
            root.display()
        ),
    };
    if let Some(foreign) = before.foreign.iter().find(|path| !created.contains(path)) {
        return Err(refuse(format!(
            "{} is owned by an account other than SYSTEM or Administrators",
            foreign.display()
        )));
    }
    if let Some(stray) = after.and_then(|after| after.entries.difference(&before.entries).next()) {
        return Err(refuse(format!(
            "{} appeared while the data directory was being secured",
            stray.display()
        )));
    }
    Ok(())
}

/// What `start` does for the state the service was found in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartStep {
    AlreadyRunning,
    /// Starting already: only wait.
    Wait,
    /// Stopping: wait for the stop, then ask for the start.
    LetStopFinish,
    Request,
}

fn start_step(state: ServiceState) -> StartStep {
    match state {
        ServiceState::Running => StartStep::AlreadyRunning,
        ServiceState::StartPending => StartStep::Wait,
        ServiceState::StopPending => StartStep::LetStopFinish,
        _ => StartStep::Request,
    }
}

/// `ERROR_SERVICE_ALREADY_RUNNING`: a start that raced another one.
fn is_already_running(err: &windows_service::Error) -> bool {
    matches!(err, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(1056))
}

/// A start wait ends only past both the caller's `deadline` and what the
/// pending service promised: its wait hint, counted from its last checkpoint move.
fn start_wait_over(
    now: Instant,
    deadline: Instant,
    last_progress: Instant,
    wait_hint: Duration,
) -> bool {
    now >= deadline.max(last_progress + wait_hint.min(MAX_WAIT_HINT))
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

/// Remove what this product leaves on the machine that can lock a user out or
/// keep steering traffic: WFP filters under our provider, the Mode-B NRPT
/// redirect pointing all name resolution at a loopback listener that is about
/// to stop existing, and our routes (a stop that kept the rule routes, or a
/// killed instance, leaves them until reboot). Each sweep is scoped to our own
/// marker, provider or route signature, so an admin's or another product's
/// objects are never touched.
///
/// Returns `false` if any sweep could not run — the caller reports it rather
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
                    msg_key = "win-svcctl-sublayer-delete-failed",
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
            error = %e,
            "no autostart entry of ours to remove for this user",
        );
    }
    let dns_swept = crate::dns_redirect::sweep_orphan_dns_state(
        &crate::dns_redirect::TransactedNrptStore,
        &crate::dns_redirect::WindowsSearchList,
    )
    .is_clean();
    let routes_swept = sweep_routes(std::sync::Arc::new(
        crate::windows_api::ProductionWindowsApi,
    ));
    filters_swept && dns_swept && routes_swept
}

/// Our routes, by the signature the service writes them with; one the sweep
/// cannot remove is left to the reboot that clears it.
fn sweep_routes(api: std::sync::Arc<dyn nrr_platform_api::route_table::RouteTablePort>) -> bool {
    match nrr_platform_api::route_signature::sweep_owned_routes(api) {
        Ok(removed) => {
            if removed > 0 {
                tracing::info!(
                    target: "nrr::routes",
                    removed,
                    "removed the routes the service left behind",
                );
            }
            true
        }
        Err(e) => {
            tracing::warn!(
                target: "nrr::routes",
                error = %e,
                "could not remove every route the service left; a reboot clears them",
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The uninstall takes our host routes, overlays and network pieces, and
    /// leaves a VPN's own routes, the OS default and the user's static route.
    #[test]
    fn the_uninstall_route_sweep_takes_ours_and_nothing_else() {
        use nrr_platform_api::route_signature::{NETWORK_ROUTE_METRIC, SECONDARY_ROUTE_METRIC};
        use nrr_platform_api::route_table::RouteTablePort;
        use nrr_platform_api::{MockWindowsApi, RouteEntry, RouteTableRef};
        use std::net::{IpAddr, Ipv4Addr};

        let row = |dest: [u8; 4], prefix: u8, ifindex: u32, metric: u32| RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(dest)),
            prefix_length: prefix,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            interface_index: ifindex,
            metric,
            is_ours: false,
            table: RouteTableRef::Main,
        };
        let ours = [
            row([198, 51, 100, 4], 32, 7, SECONDARY_ROUTE_METRIC),
            row([64, 0, 0, 0], 2, 3, SECONDARY_ROUTE_METRIC),
            row([10, 20, 0, 0], 16, 7, NETWORK_ROUTE_METRIC),
        ];
        let foreign = [
            row([0, 0, 0, 0], 1, 7, 1),
            row([128, 0, 0, 0], 1, 7, 1),
            row([203, 0, 113, 7], 32, 3, 0),
            row([10, 7, 0, 0], 24, 9, 256),
            row([0, 0, 0, 0], 0, 3, 25),
            row([192, 168, 50, 0], 24, 3, 10),
        ];
        let api = std::sync::Arc::new(MockWindowsApi::new());
        api.set_route_table(ours.iter().chain(&foreign).cloned().collect());

        assert!(sweep_routes(
            std::sync::Arc::clone(&api) as std::sync::Arc<dyn RouteTablePort>
        ));
        assert_eq!(
            RouteTablePort::get_ip_forward_table(api.as_ref()).expect("table"),
            foreign
        );
    }

    /// An unreadable table is reported, never taken for a clean one.
    #[test]
    fn an_unreadable_table_is_not_a_swept_one() {
        use nrr_platform_api::route_table::RouteTablePort;
        let api = std::sync::Arc::new(nrr_platform_api::MockWindowsApi::new());
        api.set_route_table_read_error(Some("busy"));
        assert!(!sweep_routes(api as std::sync::Arc<dyn RouteTablePort>));
    }

    /// Only the stop verb asks a crashed service to stay down; an install
    /// replacing the copy over one must not eat the start that follows.
    #[test]
    fn only_the_stop_verb_asks_a_crashed_service_to_stay_down() {
        assert!(stays_stopped(StopCaller::Verb, true));
        assert!(!stays_stopped(StopCaller::Install, true));
        assert!(!stays_stopped(StopCaller::Verb, false));
        assert!(!stays_stopped(StopCaller::Install, false));
    }

    /// A reinstall reads the registered command line back from SCM, quotes
    /// and all; the after-crash command must not quote it a second time.
    #[test]
    fn a_reinstall_does_not_quote_the_registered_path_twice() {
        let registered = Path::new(r#""C:\Program Files\NetRuleRouter Service\nrr-service.exe""#);
        let command = after_crash_command(&registered_binary_of(registered));
        assert_eq!(
            command,
            OsString::from(
                r#""C:\Program Files\NetRuleRouter Service\nrr-service.exe" after-crash"#
            )
        );
        let bare = Path::new(r"C:\NRR\nrr-service.exe");
        assert_eq!(
            after_crash_command(&registered_binary_of(bare)),
            OsString::from(r#""C:\NRR\nrr-service.exe" after-crash"#)
        );
    }

    #[test]
    fn a_confirmed_stop_leaves_the_actions_off_and_a_failed_one_puts_them_back() {
        assert_eq!(recovery_after_stop(true), RecoveryAfterStop::LeaveOff);
        assert_eq!(recovery_after_stop(false), RecoveryAfterStop::PutBack);
    }

    /// The marker outlives every restart SCM may have scheduled, and no boot.
    #[test]
    fn stay_stopped_holds_through_the_longest_restart_delay_and_never_past_a_boot() {
        let boot = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let written = boot + Duration::from_secs(600);
        let after = |secs| written + Duration::from_secs(secs);
        // The slowest scheduled restart is five minutes away.
        assert!(stay_stopped_applies(written, after(5), Some(boot)));
        assert!(stay_stopped_applies(written, after(300), Some(boot)));
        assert!(!stay_stopped_applies(written, after(400), Some(boot)));
        // Written before this boot: the boot start is wanted.
        let rebooted = written + Duration::from_secs(10);
        assert!(!stay_stopped_applies(written, after(20), Some(rebooted)));
        assert!(!stay_stopped_applies(written, after(20), None));
        // A clock set back is no evidence either way: not fresh.
        assert!(!stay_stopped_applies(after(30), written, Some(boot)));
    }

    #[test]
    fn only_an_empty_action_list_counts_as_missing() {
        use windows_service::service::{ServiceFailureActions, ServiceFailureResetPeriod};
        let with = |actions| ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::ZERO),
            reboot_msg: None,
            command: None,
            actions,
        };
        assert!(recovery_missing(&with(None)));
        assert!(recovery_missing(&with(Some(Vec::new()))));
        assert!(!recovery_missing(&with(Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(5),
        }]))));
    }

    #[test]
    fn repeated_failures_keep_restarting_after_the_network_is_released() {
        let plan = failure_action_plan(&RecoveryPolicy::production());
        let kinds: Vec<_> = plan.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            kinds,
            [
                ServiceActionType::Restart,
                ServiceActionType::Restart,
                ServiceActionType::Restart,
                ServiceActionType::RunCommand,
                ServiceActionType::Restart,
            ]
        );
        let (last, delay) = plan[plan.len() - 1];
        assert_eq!(last, ServiceActionType::Restart);
        assert!(delay >= Duration::from_secs(60), "the tail is a backoff");
    }

    #[test]
    fn a_zero_tail_delay_leaves_the_service_stopped() {
        let mut policy = RecoveryPolicy::production();
        policy.exhausted_restart_delay_ms = 0;
        let plan = failure_action_plan(&policy);
        assert_eq!(plan[plan.len() - 1].0, ServiceActionType::None);
    }

    #[test]
    fn the_scripts_write_the_same_upgrade_stop_marker() {
        let lib = include_str!("../../../../scripts/lib/service-paths.ps1");
        assert!(
            lib.contains(&format!("'{UPGRADE_STOP_MARKER}'")),
            "service-paths.ps1 must name the marker file {UPGRADE_STOP_MARKER}"
        );
    }

    #[test]
    fn the_scripts_write_the_same_deliberate_stop_marker() {
        let lib = include_str!("../../../../scripts/lib/service-paths.ps1");
        assert!(
            lib.contains(&format!("'{DELIBERATE_STOP_MARKER}'")),
            "service-paths.ps1 must name the marker file {DELIBERATE_STOP_MARKER}"
        );
    }

    #[test]
    fn a_start_does_not_request_what_is_already_starting_or_running() {
        assert_eq!(start_step(ServiceState::Running), StartStep::AlreadyRunning);
        assert_eq!(start_step(ServiceState::StartPending), StartStep::Wait);
        assert_eq!(
            start_step(ServiceState::StopPending),
            StartStep::LetStopFinish
        );
        assert_eq!(start_step(ServiceState::Stopped), StartStep::Request);
    }

    #[test]
    fn a_start_slower_than_the_budget_is_waited_for_while_the_service_promised_it() {
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(15);
        let hint = Duration::from_secs(30);
        // 16 s in, the service said at 0 s that its step may take 30 s.
        assert!(!start_wait_over(
            t0 + Duration::from_secs(16),
            deadline,
            t0,
            hint
        ));
        assert!(start_wait_over(
            t0 + Duration::from_secs(30),
            deadline,
            t0,
            hint
        ));
        // A checkpoint move at 25 s renews the promise.
        let moved = t0 + Duration::from_secs(25);
        assert!(!start_wait_over(
            t0 + Duration::from_secs(40),
            deadline,
            moved,
            hint
        ));
        // No hint: the caller's budget alone decides.
        assert!(start_wait_over(
            t0 + Duration::from_secs(15),
            deadline,
            t0,
            Duration::ZERO
        ));
        // A hint of hours reads as a hang once the cap is spent.
        assert!(start_wait_over(
            t0 + MAX_WAIT_HINT,
            deadline,
            t0,
            Duration::from_secs(36_000)
        ));
    }

    fn census(entries: &[&str], foreign: &[&str]) -> crate::trusted_location::TreeOwnership {
        crate::trusted_location::TreeOwnership {
            entries: entries.iter().map(PathBuf::from).collect(),
            foreign: foreign.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn a_tree_with_a_foreign_owned_entry_is_not_adopted() {
        let root = Path::new("root");
        let before = census(
            &["root", "root/nrr_service_state.db"],
            &["root", "root/nrr_service_state.db"],
        );
        let refused = adoption_verdict(root, &[PathBuf::from("root")], &before, None);
        assert!(
            matches!(&refused, Err(ServiceControlError::InvalidState { detail }) if detail.contains("nrr_service_state.db")),
            "{refused:?}"
        );
    }

    #[test]
    fn an_entry_planted_during_the_lockdown_is_not_adopted() {
        let root = Path::new("root");
        // Created by this install under the installing admin's own SID.
        let created = [PathBuf::from("root"), PathBuf::from("root/logs")];
        let before = census(&["root", "root/logs"], &["root", "root/logs"]);
        assert!(adoption_verdict(root, &created, &before, None).is_ok());
        let after = census(&["root", "root/logs", "root/logs/planted"], &[]);
        assert!(matches!(
            adoption_verdict(root, &created, &before, Some(&after)),
            Err(ServiceControlError::InvalidState { .. })
        ));
        assert!(adoption_verdict(root, &created, &before, Some(&before)).is_ok());
    }

    #[test]
    fn a_registered_path_matches_the_copy_whatever_its_spelling() {
        let copy = Path::new(r"C:\Program Files\NetRuleRouter Service\nrr-service.exe");
        for same in [
            r"c:\program files\netrulerouter service\NRR-SERVICE.EXE",
            r"\\?\C:\Program Files\NetRuleRouter Service\nrr-service.exe",
            "C:/Program Files/NetRuleRouter Service/nrr-service.exe",
        ] {
            assert!(same_file_path(Path::new(same), copy), "{same}");
        }
        for other in [
            r"C:\Program Files\NetRuleRouter\nrr-service.exe",
            r"C:\Users\Public\NetRuleRouter Service\nrr-service.exe",
            r"C:\Program Files\NetRuleRouter Service\other.exe",
        ] {
            assert!(!same_file_path(Path::new(other), copy), "{other}");
        }
    }

    #[test]
    fn a_folder_counts_as_within_only_by_whole_components() {
        let base = PathBuf::from("Base");
        assert!(is_within(&base.join("Product"), &base));
        assert!(is_within(&PathBuf::from("base").join("Product"), &base));
        assert!(!is_within(&PathBuf::from("BaseX").join("Product"), &base));
        assert!(!is_within(&PathBuf::from("Other").join("Base"), &base));
    }

    /// `PROGRAMDATA=C:\ProgramData\..\Users\Victim` would put the purge and
    /// the lock-down on a folder outside ProgramData.
    #[test]
    fn a_path_climbing_out_with_dot_dot_is_not_within() {
        let base = PathBuf::from(r"C:\ProgramData");
        for climbing in [
            r"C:\ProgramData\..\Users\Victim\NetRuleRouter",
            r"C:\ProgramData\NetRuleRouter\..\..\Windows",
            r"C:\ProgramData\.\NetRuleRouter\..",
        ] {
            assert!(!is_within(Path::new(climbing), &base), "{climbing}");
        }
        assert!(is_within(Path::new(r"C:\ProgramData\NetRuleRouter"), &base));
        assert!(same_lexical_path(
            Path::new(r"c:\programdata\netrulerouter"),
            Path::new(r"C:\ProgramData\NetRuleRouter")
        ));
    }

    #[test]
    fn a_root_outside_program_data_is_refused_before_anything_is_touched() {
        let base = PathBuf::from(r"C:\ProgramData");
        let outside = Path::new(r"C:\ProgramData\..\Users\Victim\NetRuleRouter");
        assert!(matches!(
            ensure_under(outside, &base),
            Err(ServiceControlError::InvalidState { .. })
        ));
    }
}
