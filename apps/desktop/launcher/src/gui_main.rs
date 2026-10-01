//! Entry point for `NetRuleRouter.exe`, the main GUI launcher. The elevated
//! broker is this same binary started with `--nrr-elevated-broker`.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    if let Err(err) = nrr_platform_windows::dll_search::restrict_dll_search() {
        eprintln!("{err}");
    }
    nrr_launcher::run(nrr_launcher::LauncherConfig::main_gui())
}
