//! Entry point for `NetRuleRouter.exe` (the main GUI launcher).
//!
//! Currently produced under the preview name `nrr-launcher-gui.exe` while
//! `apps/desktop/gui` legacy crate still owns `NetRuleRouter.exe`; renamed
//! in 13.R-GUI.4.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    nrr_launcher::run(nrr_launcher::LauncherConfig::main_gui())
}
