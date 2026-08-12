//! The daemon's own `install` / `uninstall` verbs.
//!
//! These are thin: both the decision (the systemd plan) and its execution live
//! behind `nrr_platform_linux::service_control::LinuxServiceControl`, which is
//! the same port the administrative console drives. One implementation, two
//! callers — the daemon installing itself and `nrr-cli` installing the daemon
//! cannot register the service differently.
//!
//! Anything printed here is operator-facing text, not a contract.

#![cfg(target_os = "linux")]

use std::process::ExitCode;

use nrr_platform_api::service_control::{
    ServiceControlPort, ServiceInstallSpec, ServiceUninstallSpec,
};
use nrr_platform_linux::service_control::LinuxServiceControl;
use nrr_platform_linux::systemd::SYSTEMD_UNIT_NAME;

/// `install` verb: register THIS binary as the service. `ExecStart` points at
/// the running executable, so a daemon installed from any path re-invokes the
/// exact binary that installed it.
pub fn install_service() -> ExitCode {
    let binary_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("install failed: cannot resolve current executable: {e}");
            return ExitCode::from(1);
        }
    };
    match LinuxServiceControl::new().install(&ServiceInstallSpec::production_defaults(binary_path))
    {
        Ok(_) => {
            println!("Installed and enabled '{SYSTEMD_UNIT_NAME}'.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("install failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// `uninstall` verb: disable, stop and remove the service, leaving its data in
/// place. Deleting service-owned data is the application-removal path, and the
/// daemon never takes that decision on its own.
pub fn uninstall_service() -> ExitCode {
    match LinuxServiceControl::new().uninstall(&ServiceUninstallSpec::keep_data()) {
        Ok(_) => {
            println!("Uninstalled '{SYSTEMD_UNIT_NAME}'.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("uninstall failed: {e}");
            ExitCode::from(1)
        }
    }
}
