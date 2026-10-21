//! Service-owned settings whose pushes fire on change only (rules pause, apply
//! failure policy, revision retention) are learned from every snapshot. Read
//! only after a push gap, they showed the defaults in every freshly started
//! window: retention saved as 31 days came back as 30 after a restart. The
//! retention panel's draft follows the service while the user is not editing,
//! and the pause panel shows when the pause began in local time.

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The text of `function <name>(` up to the next function at the same depth.
fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("function {name} is gone"));
    let rest = &source[start..];
    let end = rest[1..]
        .find("\n    function ")
        .map_or(rest.len(), |at| at + 1);
    &rest[..end]
}

#[test]
fn every_snapshot_read_applies_the_service_settings() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    let refresh = function_body(&main, "refreshUnenforcedAppRules");
    assert!(
        refresh.contains("_applyPushedSettingsFromSnapshot(p)"),
        "the snapshot read every start and reconnect goes through must apply \
         the service-owned settings, not only the read after a push gap"
    );
    let applied = function_body(&main, "_applyPushedSettingsFromSnapshot");
    for key in [
        "\"routing-paused\"",
        "\"apply-failure-policy\"",
        "\"retention-settings\"",
    ] {
        assert!(
            applied.contains(key),
            "{key} is no longer read from the snapshot"
        );
    }
}

#[test]
fn a_push_gap_makes_the_settings_panels_read_the_service_again() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(
        function_body(&main, "_rereadAfterPushGap").contains("pushGapReread()"),
        "a quick service restart reaches the window only as a push gap; the \
         panels must re-read then (a forced trace stayed hidden until restart)"
    );
    for panel in [
        "apps/desktop/qml/sections/settings/DiagnosticsLogsSettings.qml",
        "apps/desktop/qml/sections/settings/RoutingSettings.qml",
    ] {
        assert!(
            repo_file(panel).contains("function onPushGapReread()"),
            "{panel} does not re-read the service after a push gap"
        );
    }
}

#[test]
fn the_pause_time_is_shown_as_local_time() {
    let panel = repo_file("apps/desktop/qml/sections/settings/RoutingSettings.qml");
    let at = panel
        .find("settings.routing.pause.paused-since")
        .unwrap_or_else(|| panic!("the paused-since label is gone"));
    let label = &panel[at..at + 300.min(panel.len() - at)];
    assert!(
        label.contains("Pure.formatTimestamp(Date.parse(pauseGroup.pausedAt))"),
        "the pause time is an ISO string in UTC; shown raw it read \
         \"2026-10-21T14:11:43.800Z\" instead of the local time"
    );
}

#[test]
fn an_untouched_retention_draft_follows_the_service() {
    let panel = repo_file("apps/desktop/qml/sections/settings/RetentionSettings.qml");
    let follows = panel
        .lines()
        .any(|line| line.trim() == "onCurrentChanged: if (!draftDirty) reloadFromCurrent()");
    assert!(
        follows,
        "the draft is copied once on creation; without following `current` it \
         keeps the defaults the window held before the service answered"
    );
}
