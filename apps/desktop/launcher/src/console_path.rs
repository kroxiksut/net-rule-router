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
//! ## Where the work happens
//!
//! Not here. The state and the two actions are `nrr_platform_api::console_path`,
//! shared with the terminal UI; the mechanism is the per-OS backend behind
//! `PathRegistrationPort`. This module only names the directory (the one this
//! process runs from) and the implementation for the host.

use std::path::PathBuf;

use nrr_platform_api::console_path;
pub use nrr_platform_api::console_path::ConsolePathState;
use nrr_platform_api::path_registration::PathRegistrationPort;

/// Report the current state, without changing anything.
pub fn console_path_state() -> Result<ConsolePathState, String> {
    console_path::state(host_port()?.as_ref(), &console_directory()?)
}

/// Register the console's directory on the current user's `PATH`; idempotent.
pub fn register_console_on_path() -> Result<ConsolePathState, String> {
    console_path::register(host_port()?.as_ref(), &console_directory()?)
}

/// Take our entry back off the current user's `PATH`; idempotent, and only
/// OUR entry goes.
pub fn unregister_console_from_path() -> Result<ConsolePathState, String> {
    console_path::unregister(host_port()?.as_ref(), &console_directory()?)
}

/// The directory to register: the one this process runs from, once the
/// console is confirmed to be in it.
fn console_directory() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate the running executable: {e}"))?;
    console_path::console_directory_beside(&exe)
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
