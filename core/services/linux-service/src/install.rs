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

use std::path::Path;
use std::process::ExitCode;

use nrr_platform_api::service_control::{
    ServiceControlPort, ServiceInstallSpec, ServiceUninstallSpec,
};
use nrr_platform_linux::service_control::{LinuxServiceControl, PasswordPrompt};
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
    // Already root under `pkexec` or a package script: nobody to ask.
    match LinuxServiceControl::new(PasswordPrompt::Never)
        .install(&ServiceInstallSpec::production_defaults(binary_path))
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
    match LinuxServiceControl::new(PasswordPrompt::Never)
        .uninstall(&ServiceUninstallSpec::keep_data())
    {
        Ok(_) => {
            // Stopping the unit ran its stop hook; a daemon already dead
            // without one would leave the machine's DNS on a gone listener.
            if let Some(data_dir) = nrr_platform_api::paths::production_data_root() {
                if let Err(reason) = crate::dns_stack::clear_dns_redirect(&data_dir) {
                    eprintln!("could not give the machine's DNS back: {reason}");
                }
            }
            // The port swept the nft table; the per-user routing selectors and
            // our routes live outside it and nothing else removes them.
            sweep_routing_leftovers();
            println!("Uninstalled '{SYSTEMD_UNIT_NAME}'.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("uninstall failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// Remove the `ip rule` selectors and the routes a dead or stopped daemon
/// left; a failure is reported, never fatal to the removal.
fn sweep_routing_leftovers() {
    use crate::cleanup::CleanupHost;
    let host = crate::cleanup::SystemHost {
        data_dir: nrr_platform_api::paths::production_data_root(),
        revoke_overrides: false,
    };
    if let Err(reason) = host.sweep_rules() {
        eprintln!("could not remove the per-user routing rules: {reason}");
    }
    if let Err(reason) = host.sweep_routes() {
        eprintln!("could not remove the leftover routes: {reason}");
    }
}

/// `package-files <DIR>`: write the unit, its companion files and the alias
/// link a distribution package ships, rooted at DIR. Run by the packaging
/// script, so the package carries exactly what `install` would write.
pub fn write_package_files(root: Option<&str>) -> ExitCode {
    let Some(root) = root
        .map(Path::new)
        .filter(|root| !root.as_os_str().is_empty())
    else {
        eprintln!("package-files: name the directory to write into");
        return ExitCode::from(2);
    };
    // Into `/` this would be a hand install that looks like a package one.
    if root.parent().is_none() {
        eprintln!("package-files: refusing to write into {}", root.display());
        return ExitCode::from(2);
    }
    match nrr_platform_linux::service_control::stage_package_files(root) {
        Ok(written) => {
            for path in written {
                println!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("package-files failed: {e}");
            ExitCode::from(1)
        }
    }
}
