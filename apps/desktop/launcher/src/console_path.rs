//! Make the administrative console reachable by name from the user's shell.
//!
//! This is the capability behind the Settings action "add the console to my
//! PATH". It runs in the launcher — the process that runs AS the interactive
//! user — for the same reason autostart does: the store being changed belongs to
//! that user, and the background service (`LocalSystem` on Windows, root on
//! Linux) is the wrong process to be writing into it.
//!
//! ## Why nothing calls this at install time
//!
//! Registration is a human decision, not a side effect of installing. Installing
//! a product does not entitle it to change the environment every shell on the
//! machine inherits, and a `PATH` that grew on its own is a `PATH` nobody can
//! reason about later. So the capability is offered, never taken: the only
//! caller is the explicit user action, and both entry points below are safe to
//! call twice — the second call reports "already there" and writes nothing.
//!
//! ## Where the OS work happens
//!
//! Nowhere here. The decision (is it already on the list, what does the list
//! become) is `nrr_platform_api::path_registration`, and the mechanism is the
//! per-OS backend behind `PathRegistrationPort`. This module only resolves WHICH
//! directory to register and picks the implementation for the host.

use std::path::{Path, PathBuf};

use nrr_platform_api::path_registration::{
    PathRegistrationPlan, PathRegistrationPort, PathRegistrationRequest, PathRegistrationStep,
};
use nrr_shared::product_identity::BinaryRole;

/// What the UI needs to render the action and its result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolePathState {
    /// The directory holding the console executable.
    pub directory: PathBuf,
    /// Whether the directory is already reachable from a newly started shell.
    pub registered: bool,
    /// The command to paste into a shell that is ALREADY open — no OS updates a
    /// running process's environment, so this is what closes the gap between
    /// clicking the button and the console working in the terminal on screen.
    pub current_session_command: String,
    /// The file the registration writes to, where the mechanism is file-based
    /// (Unix). `None` on hosts with a real per-user environment store.
    pub target_file: Option<PathBuf>,
}

impl ConsolePathState {
    fn from_plan(plan: &PathRegistrationPlan, registered: bool) -> Self {
        let target_file = plan.steps.iter().find_map(|step| match step {
            PathRegistrationStep::AppendShellProfileLine { path, .. } => Some(path.clone()),
            _ => None,
        });
        Self {
            directory: plan.directory.clone(),
            registered,
            current_session_command: plan.current_session_command.clone(),
            target_file,
        }
    }
}

/// Report whether the console is already reachable, without changing anything.
pub fn console_path_state() -> Result<ConsolePathState, String> {
    let port = host_port()?;
    let request = PathRegistrationRequest::for_current_user(console_directory()?);
    let plan = port.plan(&request).map_err(|e| e.to_string())?;
    let registered = !plan.changes_anything();
    Ok(ConsolePathState::from_plan(&plan, registered))
}

/// Register the console's directory on the current user's `PATH`.
///
/// Idempotent: calling it when the directory is already there writes nothing and
/// still returns a state the UI can render.
pub fn register_console_on_path() -> Result<ConsolePathState, String> {
    let port = host_port()?;
    let request = PathRegistrationRequest::for_current_user(console_directory()?);
    let plan = port.plan(&request).map_err(|e| e.to_string())?;
    if plan.changes_anything() {
        port.apply(&plan).map_err(|e| e.to_string())?;
    }
    Ok(ConsolePathState::from_plan(&plan, true))
}

/// The directory to register: the one this process runs from.
///
/// It is only accepted once the console executable is confirmed to be sitting in
/// it. Registering a directory on the strength of "our binaries usually ship
/// together" would, in a partial install or an unusual layout, put a directory
/// on the user's `PATH` that never gains the program they asked for — a change
/// they then have to find and undo by hand.
fn console_directory() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate the running executable: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "the running executable has no parent directory".to_string())?;
    verify_console_present(dir)?;
    Ok(dir.to_path_buf())
}

/// Confirm the console executable lives in `dir`.
fn verify_console_present(dir: &Path) -> Result<(), String> {
    let name = BinaryRole::Console.host_file_name();
    if dir.join(name).is_file() {
        Ok(())
    } else {
        Err(format!("{name} is not present in {}", dir.display()))
    }
}

/// The host's `PATH` mechanism, when this build has one.
#[cfg(windows)]
fn host_port() -> Result<Box<dyn PathRegistrationPort>, String> {
    Ok(Box::new(
        nrr_platform_windows::path_registration::WindowsUserPathRegistration::production(),
    ))
}

/// The host's `PATH` mechanism, when this build has one.
#[cfg(all(unix, not(windows)))]
fn host_port() -> Result<Box<dyn PathRegistrationPort>, String> {
    let port = nrr_platform_linux::path_registration::UnixPathRegistration::from_environment()
        .map_err(|e| e.to_string())?;
    Ok(Box::new(port))
}

/// The host's `PATH` mechanism, when this build has one.
#[cfg(not(any(windows, unix)))]
fn host_port() -> Result<Box<dyn PathRegistrationPort>, String> {
    Err("this platform has no PATH registration mechanism".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::path_registration::{PathDecision, PathScope};

    fn plan_with(steps: Vec<PathRegistrationStep>, decision: PathDecision) -> PathRegistrationPlan {
        PathRegistrationPlan {
            directory: PathBuf::from("/opt/netrulerouter/bin"),
            scope: PathScope::CurrentUser,
            decision,
            steps,
            current_session_command: "export PATH=\"$PATH:/opt/netrulerouter/bin\"".to_string(),
        }
    }

    #[test]
    fn a_file_based_plan_surfaces_the_file_it_would_write() {
        let plan = plan_with(
            vec![PathRegistrationStep::AppendShellProfileLine {
                path: PathBuf::from("/home/u/.bashrc"),
                line: "export PATH=…".to_string(),
            }],
            PathDecision::Append {
                updated_list: "/usr/bin:/opt/netrulerouter/bin".to_string(),
            },
        );
        let state = ConsolePathState::from_plan(&plan, false);
        assert_eq!(state.target_file, Some(PathBuf::from("/home/u/.bashrc")));
        assert!(!state.registered);
        assert!(state
            .current_session_command
            .contains("/opt/netrulerouter/bin"));
    }

    #[test]
    fn an_environment_store_plan_names_no_file() {
        let plan = plan_with(
            vec![PathRegistrationStep::SetUserEnvironmentVariable {
                name: "Path".to_string(),
                value: "…".to_string(),
            }],
            PathDecision::Append {
                updated_list: "…".to_string(),
            },
        );
        assert_eq!(ConsolePathState::from_plan(&plan, false).target_file, None);
    }

    #[test]
    fn an_already_registered_state_still_carries_the_command_for_open_shells() {
        // The user may have registered it in a previous session; the terminal
        // they have open right now still predates the change.
        let plan = plan_with(Vec::new(), PathDecision::AlreadyPresent);
        let state = ConsolePathState::from_plan(&plan, true);
        assert!(state.registered);
        assert_eq!(state.target_file, None);
        assert!(!state.current_session_command.is_empty());
    }

    #[test]
    fn a_directory_without_the_console_binary_is_refused() {
        // The temp directory is real but holds no console executable.
        let dir = std::env::temp_dir();
        let err = verify_console_present(&dir).expect_err("must refuse");
        assert!(err.contains(BinaryRole::Console.host_file_name()), "{err}");
    }
}
