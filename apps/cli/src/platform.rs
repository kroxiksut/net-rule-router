//! The one place this crate knows which operating system it is on.
//!
//! Everything else codes against the port. When a platform has no
//! implementation yet, the console says so and exits with the "unsupported"
//! code — it never degrades into a different behaviour.

use nrr_platform_api::elevation::PrivilegedRelaunchPort;
use nrr_platform_api::service_control::ServiceControlPort;

/// Keeps a DLL planted in the current directory or on `PATH` out of this
/// process — the elevated relay included. Called first in `main`.
#[cfg(windows)]
pub fn restrict_dll_search() {
    if let Err(err) = nrr_platform_windows::dll_search::restrict_dll_search() {
        eprintln!("{err}");
    }
}

/// Elsewhere the loader's search is fixed before `main` runs.
#[cfg(not(windows))]
pub fn restrict_dll_search() {}

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
/// `None` where the platform has no service binary with such a verb.
#[cfg(windows)]
pub fn offline_reset_verb() -> Option<&'static str> {
    Some("cleanup")
}

/// The service binary's own network-reset verb, when this platform has one.
#[cfg(target_os = "linux")]
pub fn offline_reset_verb() -> Option<&'static str> {
    Some(nrr_platform_linux::systemd::DAEMON_CLEANUP_VERB)
}

/// The service binary's own network-reset verb, when this platform has one.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn offline_reset_verb() -> Option<&'static str> {
    None
}

/// Whether starting a program failed because the OS demands elevation first,
/// as opposed to anything being wrong with the program.
///
/// Windows refuses to start an image whose manifest requires administrator
/// rights with `ERROR_ELEVATION_REQUIRED`, which std files under no kind of its
/// own — `PermissionDenied` is a different refusal (the file cannot be run).
#[cfg(windows)]
pub fn is_elevation_refusal(err: &std::io::Error) -> bool {
    const ERROR_ELEVATION_REQUIRED: i32 = 740;
    err.raw_os_error() == Some(ERROR_ELEVATION_REQUIRED)
}

/// Elsewhere starting a program is never refused for want of elevation: the
/// program starts and says so itself.
#[cfg(not(windows))]
pub fn is_elevation_refusal(_err: &std::io::Error) -> bool {
    false
}

/// Creates the elevated relay's report: a new file, refused when a link could
/// redirect the elevated write somewhere else.
#[cfg(windows)]
pub fn create_relay_report(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    nrr_platform_windows::elevation::create_relay_report(path)
}

/// Creates the elevated relay's report. Only UAC needs the relay; elsewhere
/// the terminal is kept, so an exclusive create with no link in the way does.
#[cfg(not(windows))]
pub fn create_relay_report(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("report directory is a link: {}", dir.display()),
            ));
        }
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
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
