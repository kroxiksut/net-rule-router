//! The user's settings file (rule-set folder, bound rules files, picked set,
//! the user's choices on service settings) is also written by the terminal
//! client. A window that read it only at launch kept the old bound files: it
//! showed them, and after the terminal bound another set and applied it, the
//! window (or, with the window closed, the tray) wrote those rules into the
//! old set's files. The window and the tray now follow the file while they
//! run; what they take of an answer is run on the real `pure.js` in
//! `core/client-logic/tests/user_settings_follow.rs`, the launcher's answer in
//! its `prefs_persistence` tests.

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
fn the_launcher_answers_in_line_with_the_window_preferences() {
    let launcher = repo_file("apps/desktop/launcher/src/launcher/mod.rs");
    assert!(
        launcher.contains("prefs_writer.answer_in_loop(request)"),
        "a worker thread answering would race the window's own snapshots"
    );
    let header = repo_file("apps/desktop/qt-host/native/src/native_bridge.h");
    assert!(
        header.contains("Q_INVOKABLE QString rpcUserSettingsFollow(const QVariantMap &payload);")
    );
    let bridge = repo_file("apps/desktop/qt-host/native/src/native_bridge_files.cpp");
    assert!(bridge.contains("\"local.user-settings.follow\""));
}

#[test]
fn the_window_follows_the_file_while_it_runs() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    let follower_block = main
        .split("UserSettingsFollower {")
        .nth(1)
        .expect("the window follows the user's settings file");
    let follower_block = &follower_block[..follower_block.find("\n    }").expect("block end")];
    assert!(follower_block.contains("adopt: true"));
    assert!(follower_block.contains("window.adoptSharedPrefs(preferences)"));

    let adopt = function_body(&main, "adoptSharedPrefs");
    assert!(
        adopt.contains("Pure.userSettingsAdoption(prefs, prefsSnapshot, _bufferedPrefKeys,"),
        "a choice waiting for Apply would be replaced"
    );
    assert!(
        !adopt.contains("updatePrefs("),
        "a change made elsewhere would light Apply/Cancel here"
    );
    let active = main
        .split("onActiveChanged: {")
        .nth(1)
        .expect("onActiveChanged");
    let active = &active[..active.find("\n    }").expect("handler end")];
    assert!(
        active.contains("userSettingsFollower.follow()"),
        "coming back to the window does not look at the file"
    );

    let presence = main.split("GuiPresence {").nth(1).expect("presence");
    assert!(presence.contains("boundPrimary: String(window.prefs.lastSavedPathPrimary || \"\")"));
    assert!(
        presence.contains("boundSecondary: String(window.prefs.lastSavedPathSecondary || \"\")")
    );
}

#[test]
fn the_follower_asks_cheaply_and_never_blocks_a_write() {
    let follower = repo_file("apps/desktop/qml/flows/UserSettingsFollower.qml");
    assert!(
        follower.contains("{ \"since\": _stamp, \"adopt\": adopt }"),
        "without the stamp every poll reads and parses the file"
    );
    assert!(
        follower.contains("typeof nrrNativeBridge.rpcUserSettingsFollow === \"function\""),
        "a host built before the call would throw on every tick"
    );
    let send = function_body(&follower, "_send");
    assert!(
        send.contains("if (!available || !rpc) { _run(waiting); return }"),
        "a host that cannot ask must still let the waiting write go on"
    );
    assert!(follower.contains("onTriggered: follower.follow()"));
}

#[test]
fn a_write_the_service_caused_waits_for_the_bound_files() {
    let controller = repo_file("apps/desktop/qml/flows/BoundFilesController.qml");
    for caller in ["handleRulesAddedFromTray", "_rereadAfterServiceWrite"] {
        let body = function_body(&controller, caller);
        assert!(
            body.contains("_followServiceIntoBoundFiles()"),
            "{caller} writes before the window knows a binding made elsewhere"
        );
        assert!(!body.contains("_followServiceIntoFiles(false)"), "{caller}");
    }
    assert!(function_body(&controller, "_followServiceIntoBoundFiles").contains("follower.follow("));

    let writer = repo_file("apps/desktop/qml/flows/TrayBoundFileWriter.qml");
    assert!(
        function_body(&writer, "mirrorServiceIntoFiles").contains("follower.follow("),
        "the tray names the files before it knows a binding made elsewhere"
    );
}

#[test]
fn the_tray_follows_a_binding_made_with_the_window_closed() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    assert!(tray.contains("UserSettingsFollower {"));
    assert!(tray.contains("tray.guiPresence.sharedBound = rulesFiles"));
    assert!(tray.contains("follower: tray.userSettingsFollower"));

    let presence = repo_file("apps/desktop/qml/components/GuiPresence.qml");
    assert!(function_body(&presence, "read").contains("Pure.trayRulesPaths(snap, sharedBound)"));
    for publisher in ["publish", "publishGone"] {
        let body = function_body(&presence, publisher);
        assert!(
            body.contains("\"bound-primary\": String(snap.boundPrimary || \"\")"),
            "{publisher}"
        );
        assert!(
            body.contains("\"bound-secondary\": String(snap.boundSecondary || \"\")"),
            "{publisher}"
        );
    }
}

/// The file is damaged while the window runs: the window used to keep its
/// values without a word, so the user kept changing settings that went
/// nowhere. Every answer reaches the notice list, which raises the card once
/// per episode (`Pure.userSettingsDamageNoticeId`, run on the real `pure.js`
/// in `core/client-logic`) and takes it down when the file reads again.
#[test]
fn a_settings_file_damaged_while_the_window_runs_is_told() {
    let follower = repo_file("apps/desktop/qml/flows/UserSettingsFollower.qml");
    assert!(follower.contains("signal answered(var payload)"));
    let answered = follower
        .split("if (ok && payload) {")
        .nth(1)
        .expect("the answer branch");
    assert!(
        answered[..answered.find("\n            }").expect("branch end")]
            .contains("follower.answered(payload)"),
        "an answer that carried no change never reaches the notice list"
    );

    let main = repo_file("apps/desktop/qml/Main.qml");
    let block = main
        .split("UserSettingsFollower {")
        .nth(1)
        .expect("the window follows the file");
    let block = &block[..block.find("\n    }").expect("block end")];
    assert!(block.contains("notificationsController.noteUserSettingsAnswer(payload)"));

    let controller = repo_file("apps/desktop/qml/flows/NotificationsController.qml");
    let note = function_body(&controller, "noteUserSettingsAnswer");
    assert!(note.contains("Pure.userSettingsDamageNoticeId("));
    assert!(
        note.contains("_dropPushNotice("),
        "a repaired file leaves the card up"
    );
    assert!(note.contains("_addPushNotice("));
    for key in [
        "notifications.user-settings-damaged.title",
        "notifications.user-settings-damaged.body",
    ] {
        assert!(note.contains(&format!("\"{key}\"")), "{key}");
        let leaf = key.rsplit('.').next().expect("leaf");
        for locale in ["locales/en.json", "locales/ru.json"] {
            let text = repo_file(locale);
            let group = text
                .split("\"user-settings-damaged\": {")
                .nth(1)
                .unwrap_or_else(|| panic!("{locale} lacks the notice"));
            let group = &group[..group.find('}').expect("group end")];
            assert!(group.contains(&format!("\"{leaf}\":")), "{locale}: {key}");
        }
    }
}
