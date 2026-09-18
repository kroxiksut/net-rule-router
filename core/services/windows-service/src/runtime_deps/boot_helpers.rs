//! Small standalone helpers used once each by the boot-deps builder: tray
//! binary path resolution and the recompute-cost slow-pass logger.

use super::*;

/// Resolves the absolute path to `NetRuleRouterTray.exe`. Used for the
/// autostart helper's `set_enabled` and `get_state` calls. In production
/// the tray binary lives next to the service binary in
/// `%ProgramFiles%\NetRuleRouter\`; in dev runs it sits next to the
/// service in `target/debug/`. We use the `current_exe()` parent directory
/// joined with `NetRuleRouterTray.exe`. If the file does not exist, autostart
/// `set_enabled` will reject with `InvalidPath` at call time — better
/// than silently writing a dangling registry value.
pub(super) fn resolve_tray_binary_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let parent = exe
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    parent.join("NetRuleRouterTray.exe")
}

/// Log what one enforcement recompute cost, phase by phase, when it was slow
/// enough to matter.
///
/// The threshold exists because this hook fires every 30 s plus on every
/// adapter change: a healthy sub-second pass logging its breakdown would bury
/// the log in noise and teach everyone to filter the target out. A slow pass is
/// the one worth a line, because it is the one that queues DNS answers and the
/// GUI's own requests behind it.
pub(super) fn report_recompute_cost(timings: &nrr_service_runtime::phase_timings::PhaseTimings) {
    const SLOW_PASS: std::time::Duration = std::time::Duration::from_secs(1);
    nrr_service_runtime::phase_timings::report_if_slow(timings, "recompute", SLOW_PASS);
}
