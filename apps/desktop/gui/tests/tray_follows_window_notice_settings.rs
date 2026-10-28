//! The tray read the notification settings ("show notifications", "hide
//! addresses", the per-kind mutes, the opacity) once at start, so a tray that
//! lived for days kept naming blocked sites after the user chose to hide them.
//! The window now publishes its committed choice in the presence file and the
//! tray follows it. What the tray makes of a rewritten presence file is run on
//! the real `pure.js` in `core/client-logic/tests/tray_notices.rs`.

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
fn the_window_publishes_its_committed_notice_settings() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(
        main.contains("notices: window._committedNoticePrefs()"),
        "the presence snapshot no longer carries the notification settings"
    );
    let committed = function_body(&main, "_committedNoticePrefs");
    for key in [
        "\"showNotifications\"",
        "\"notifySuggestionChanges\"",
        "\"notifyBlockNotices\"",
        "\"notifyRuleDuplicates\"",
        "\"hideBlockNoticeAddresses\"",
        "\"trayNoticeOpacityPercent\"",
    ] {
        assert!(
            committed.contains(key),
            "{key} is not published to the tray"
        );
    }
    assert!(
        committed.contains("prefsSnapshot !== null && _bufferedPrefKeys[key]"),
        "an edit still waiting for Apply would reach the tray"
    );
    assert!(
        main.contains("onPrefsSnapshotChanged: {"),
        "Apply commits without reassigning prefs, so it must publish on its own"
    );
    let presence = repo_file("apps/desktop/qml/components/GuiPresence.qml");
    assert_eq!(
        presence.matches("payload[\"notices\"] = notices").count(),
        2,
        "both the live and the closing snapshot carry the settings"
    );
    assert!(presence.contains("notices: _noticesOf(parsed.notices)"));
}

#[test]
fn the_tray_follows_a_change_made_after_it_started() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    assert!(
        tray.contains("onTriggered: tray._followWindowNoticePrefs()"),
        "nothing re-reads the window's settings while the tray runs"
    );
    let take = function_body(&tray, "_takeNoticePrefs");
    assert!(
        take.contains("presence.at <= _startedAtMs"),
        "a snapshot older than the tray would override the launch context"
    );
    for field in [
        "showNotifications = n.showNotifications",
        "notifySuggestionChanges = n.notifySuggestionChanges",
        "notifyBlockNotices = n.notifyBlockNotices",
        "notifyRuleDuplicates = n.notifyRuleDuplicates",
        "hideBlockNoticeAddresses = n.hideBlockNoticeAddresses",
        "noticeOpacityPercent = n.trayNoticeOpacityPercent",
    ] {
        assert!(take.contains(field), "the tray no longer follows `{field}`");
    }
}

/// The tray's windows stayed at the default text size and font whatever the
/// user chose: its theme never heard of either.
#[test]
fn the_tray_follows_the_windows_text_size_and_font() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    assert!(tray.contains("fontScalePercent: tray.fontScalePercent"));
    assert!(tray.contains("systemFont: tray.systemFont"));
    assert!(function_body(&tray, "loadContext")
        .contains("_takeAppearance(Pure.trayAppearanceOf(context))"));
    assert!(
        function_body(&tray, "_takeNoticePrefs").contains("_takeAppearance(presence.appearance)")
    );
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(main.contains("fontScalePercent: window.prefs.fontScalePercent"));
    let presence = repo_file("apps/desktop/qml/components/GuiPresence.qml");
    assert!(function_body(&presence, "publish").contains("Pure.trayAppearanceOf(snap.appearance)"));
    assert!(function_body(&presence, "read").contains("Pure.trayAppearanceOf(parsed.appearance)"));
}

#[test]
fn the_presence_reader_uses_the_shared_parser() {
    let presence = repo_file("apps/desktop/qml/components/GuiPresence.qml");
    assert!(
        function_body(&presence, "_noticesOf").contains("Pure.trayNoticePrefsOf(raw)"),
        "the presence reader parses the notice settings on its own"
    );
}
