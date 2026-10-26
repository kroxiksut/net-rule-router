//! The one place this crate knows which operating system it is on. It only
//! picks implementations of platform ports; every decision codes against them.

use nrr_platform_api::authorization::TerminalPromptAgent;
use nrr_platform_api::path_registration::PathRegistrationPort;
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

/// The host's service manager. A person sits at this terminal, so a start or
/// stop may have the session's polkit agent ask them for a password.
#[cfg(target_os = "linux")]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    use nrr_platform_linux::service_control::{LinuxServiceControl, PasswordPrompt};
    Some(Box::new(LinuxServiceControl::new(
        PasswordPrompt::SessionAgent,
    )))
}

/// No service manager this build can ask.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn service_control() -> Option<Box<dyn ServiceControlPort>> {
    None
}

/// The host's `PATH` mechanism, and this terminal's own folder once the
/// console is confirmed to sit in it.
pub fn console_path_port() -> Result<(Box<dyn PathRegistrationPort>, std::path::PathBuf), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate the running executable: {e}"))?;
    let directory = nrr_platform_api::console_path::console_directory_beside(&exe)?;
    Ok((path_registration()?, directory))
}

#[cfg(windows)]
fn path_registration() -> Result<Box<dyn PathRegistrationPort>, String> {
    Ok(Box::new(
        nrr_platform_windows::path_registration::WindowsUserPathRegistration::production(),
    ))
}

#[cfg(target_os = "linux")]
fn path_registration() -> Result<Box<dyn PathRegistrationPort>, String> {
    let port = nrr_platform_linux::path_registration::UnixPathRegistration::from_environment()
        .map_err(|e| e.to_string())?;
    Ok(Box::new(port))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn path_registration() -> Result<Box<dyn PathRegistrationPort>, String> {
    Err("this platform has no PATH registration mechanism".to_string())
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

/// Whether the terminal runs with administrator rights: the service lets
/// such a caller through the administrator's rule-edit lock.
#[cfg(target_os = "linux")]
pub fn runs_elevated() -> bool {
    nrr_platform_linux::elevation::running_as_root()
}

/// Whether the terminal runs with administrator rights.
#[cfg(windows)]
pub fn runs_elevated() -> bool {
    nrr_platform_windows::win32_ffi::console_session::current_process_elevated()
}

/// Whether the terminal runs with administrator rights.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn runs_elevated() -> bool {
    false
}

/// polkit's text agent, so a password the service could not ask for anywhere
/// else is typed here.
#[cfg(target_os = "linux")]
pub fn terminal_prompt_agent() -> Option<Box<dyn TerminalPromptAgent>> {
    Some(Box::new(nrr_platform_linux::polkit::PkttyAgent))
}

/// Elsewhere the terminal is started elevated instead.
#[cfg(not(target_os = "linux"))]
pub fn terminal_prompt_agent() -> Option<Box<dyn TerminalPromptAgent>> {
    None
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

/// This OS's answer to "did an administrator place this file", for the
/// installer's answer sheet under the machine state root.
pub fn machine_files() -> &'static dyn nrr_platform_api::admin_authored::AdminAuthoredFiles {
    #[cfg(windows)]
    {
        &nrr_platform_windows::trusted_location::WindowsAdminAuthoredFiles
    }
    #[cfg(target_os = "linux")]
    {
        &nrr_platform_linux::trusted_location::LinuxAdminAuthoredFiles
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        &nrr_platform_api::admin_authored::TrustNothing
    }
}

/// What the Application routes screen scans for: programs of known groups on
/// this machine, run as the user who reads them.
#[cfg(windows)]
pub fn app_group_discovery() -> Box<dyn nrr_platform_api::AppGroupDiscoveryPort> {
    Box::new(nrr_platform_windows::WindowsAppGroupDiscovery::new())
}

/// What the Application routes screen scans for.
#[cfg(target_os = "linux")]
pub fn app_group_discovery() -> Box<dyn nrr_platform_api::AppGroupDiscoveryPort> {
    Box::new(nrr_platform_linux::app_group_discovery::LinuxAppGroupDiscovery::new())
}

/// This OS has nothing to scan with: the screen lists nothing.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn app_group_discovery() -> Box<dyn nrr_platform_api::AppGroupDiscoveryPort> {
    Box::new(nrr_platform_api::NoopAppGroupDiscovery)
}

/// Windows routes only users signed in to Windows; a shell reached over SSH
/// alone is not one of them.
#[cfg(windows)]
pub fn rules_need_a_windows_sign_in() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some()
}

/// Every signed-in user is routed, over SSH too.
#[cfg(not(windows))]
pub fn rules_need_a_windows_sign_in() -> bool {
    false
}

/// What the "Your VPN client" rows scan for: likely VPN programs on this
/// machine, run as the user who reads them.
#[cfg(windows)]
pub fn vpn_discovery() -> Box<dyn nrr_platform_api::VpnDiscoveryPort> {
    Box::new(nrr_platform_windows::WindowsVpnDiscovery::new())
}

/// What the "Your VPN client" rows scan for.
#[cfg(target_os = "linux")]
pub fn vpn_discovery() -> Box<dyn nrr_platform_api::VpnDiscoveryPort> {
    Box::new(nrr_platform_linux::vpn_discovery::LinuxVpnDiscovery::new())
}

/// This OS has nothing to scan with: the rows list nothing.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn vpn_discovery() -> Box<dyn nrr_platform_api::VpnDiscoveryPort> {
    Box::new(nrr_platform_api::NoopVpnDiscovery)
}

/// The hypervisors and their machines, read from the user's own files.
#[cfg(windows)]
pub fn vm_inventory() -> Box<dyn nrr_platform_api::VmInventoryPort> {
    Box::new(nrr_platform_windows::WindowsVmInventory::new())
}

/// The hypervisors and their machines, read from the user's own files.
#[cfg(target_os = "linux")]
pub fn vm_inventory() -> Box<dyn nrr_platform_api::VmInventoryPort> {
    Box::new(nrr_platform_linux::vm_inventory::LinuxVmInventory::new())
}

/// No hypervisor this build can read.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn vm_inventory() -> Box<dyn nrr_platform_api::VmInventoryPort> {
    Box::new(nrr_platform_api::NoopVmInventory)
}
