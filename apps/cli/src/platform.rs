//! The one place this crate knows which operating system it is on.
//!
//! Everything else codes against the port. When a platform has no
//! implementation yet, the console says so and exits with the "unsupported"
//! code — it never degrades into a different behaviour.

use nrr_platform_api::elevation::PrivilegedRelaunchPort;
use nrr_platform_api::service_control::ServiceControlPort;

/// The host's service manager, when this build has one.
#[cfg(windows)]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    Some(Box::new(
        nrr_platform_windows::service_control::WindowsServiceControl::new(),
    ))
}

/// The host's service manager, when this build has one.
#[cfg(target_os = "linux")]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    Some(Box::new(
        nrr_platform_linux::service_control::LinuxServiceControl::new(),
    ))
}

/// The host's service manager, when this build has one.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    None
}

/// The service binary's own verb that tears down leftover network state, when
/// this platform has one.
///
/// The console does not undo enforcement itself: the binary that applied the
/// state is the only thing that knows how to remove it, and running that code
/// twice — once properly, once re-implemented here — is how the two copies
/// drift. So this names the verb and the console just runs it.
///
/// `None` where the platform has nothing to undo. On Linux enforcement is still
/// a stub, so there is no leftover state and no verb to run; saying that plainly
/// beats pretending the command worked.
#[cfg(windows)]
pub fn offline_reset_verb() -> Option<&'static str> {
    Some("cleanup")
}

/// The service binary's own network-reset verb, when this platform has one.
#[cfg(not(windows))]
pub fn offline_reset_verb() -> Option<&'static str> {
    None
}

/// The host's way of re-running one command with administrator rights, when
/// this build has one.
#[cfg(windows)]
pub fn privileged_relaunch() -> Option<Box<dyn PrivilegedRelaunchPort>> {
    Some(Box::new(nrr_platform_windows::elevation::UacRelaunch::new()))
}

/// The host's way of re-running one command with administrator rights, when
/// this build has one.
#[cfg(target_os = "linux")]
pub fn privileged_relaunch() -> Option<Box<dyn PrivilegedRelaunchPort>> {
    Some(Box::new(
        nrr_platform_linux::elevation::PkexecRelaunch::new(),
    ))
}

/// The host's way of re-running one command with administrator rights, when
/// this build has one.
///
/// macOS has no platform crate yet, so there is nothing to select and the
/// console degrades to what it did before elevation existed: say what is needed
/// and exit. The mechanism is not in doubt when that crate arrives — a console
/// on macOS elevates through `sudo`, which (like `pkexec`, unlike UAC) keeps the
/// caller's terminal, so it needs the port and none of the relay machinery.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn privileged_relaunch() -> Option<Box<dyn PrivilegedRelaunchPort>> {
    None
}
