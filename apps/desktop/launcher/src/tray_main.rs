//! Entry point for `NetRuleRouterTray.exe` (the tray launcher).
//!
//! Currently produced under the preview name `nrr-launcher-tray.exe` while
//! `apps/desktop/tray` legacy crate still owns `NetRuleRouterTray.exe`;
//! renamed in 13.R-GUI.4.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    nrr_launcher::run(nrr_launcher::LauncherConfig::tray())
}
