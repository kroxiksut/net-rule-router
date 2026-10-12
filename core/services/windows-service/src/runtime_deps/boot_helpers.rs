//! Small standalone helpers used once each by the boot-deps builder: tray
//! binary path resolution and the recompute-cost slow-pass logger.

use super::*;

/// `NetRuleRouterTray.exe` beside the service binary, for the autostart
/// helper. A service copied out of a portable folder has no tray beside it;
/// `set_enabled` then refuses with `InvalidPath` rather than write a dangling
/// registry value. The launcher answers autostart requests itself.
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
/// `moved` names the inputs that made this pass run.
pub(super) fn report_recompute_cost(
    timings: &nrr_service_runtime::phase_timings::PhaseTimings,
    moved: &str,
) {
    const SLOW_PASS: std::time::Duration = std::time::Duration::from_secs(1);
    nrr_service_runtime::phase_timings::report_if_slow(
        timings,
        &format!("recompute[{moved}]"),
        SLOW_PASS,
    );
}
