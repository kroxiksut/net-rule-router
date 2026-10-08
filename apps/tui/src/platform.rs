//! The one place this crate knows which operating system it is on. It only
//! picks implementations of platform ports; every decision codes against them.

use nrr_platform_api::service_control::ServiceControlPort;
use nrr_platform_api::system_locale::SystemLocalePort;

/// Keeps a DLL planted in the current directory or on `PATH` out of this
/// process. Called first in `main`.
#[cfg(windows)]
pub fn restrict_dll_search() {
    // Best effort: the interface still works with the default search order.
    let _ = nrr_platform_windows::dll_search::restrict_dll_search();
}

/// Elsewhere the loader's search is fixed before `main` runs.
#[cfg(not(windows))]
pub fn restrict_dll_search() {}

/// The host's service manager, asked only "installed? running?".
#[cfg(windows)]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    Some(Box::new(
        nrr_platform_windows::service_control::WindowsServiceControl::new(),
    ))
}

/// The host's service manager, asked only "installed? running?".
#[cfg(target_os = "linux")]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    Some(Box::new(
        nrr_platform_linux::service_control::LinuxServiceControl::new(),
    ))
}

/// No service manager this build can ask.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    None
}

/// Under `sudo` the Rules screen edits the administrator's baseline, as "Set
/// as baseline" does in the window: rules of root's own would reach no user.
#[cfg(target_os = "linux")]
pub fn edits_baseline() -> bool {
    nrr_platform_linux::elevation::running_as_root()
}

/// Elsewhere the screen edits the caller's own rules.
#[cfg(not(target_os = "linux"))]
pub fn edits_baseline() -> bool {
    false
}

/// The host's display-language probe.
#[cfg(windows)]
pub fn system_locale() -> Option<Box<dyn SystemLocalePort>> {
    Some(Box::new(
        nrr_platform_windows::system_locale::WindowsSystemLocale,
    ))
}

/// The host's display-language probe.
#[cfg(target_os = "linux")]
pub fn system_locale() -> Option<Box<dyn SystemLocalePort>> {
    Some(Box::new(
        nrr_platform_linux::system_locale::LinuxSystemLocale,
    ))
}

/// No probe: the language falls back to English.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn system_locale() -> Option<Box<dyn SystemLocalePort>> {
    None
}
