//! "Restore my settings": the user's route policy and mutes are recorded in
//! their own settings file only after a write of theirs the service confirmed,
//! a record of one part never erases another, and the card that offers the
//! restore is wired to the one write that performs it.
//!
//! A resync, a heal or a re-seed restates what the app holds; recorded as the
//! user's word, it would launder a service default into "what the user
//! wanted" and offer it back after the next reinstall.

#[path = "support/js.rs"]
mod js;

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

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

/// `pure.js` plus `body`, run; what it logged, as JSON.
fn run_pure(body: &str) -> Value {
    let pure = repo_file("apps/desktop/qml/lib/pure.js");
    let text = js::run_js(&format!("{pure}\n{body}\n"));
    serde_json::from_str(text.trim())
        .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {text}"))
}

#[test]
fn only_a_confirmed_user_write_is_recorded() {
    let controller = repo_file("apps/desktop/qml/flows/RoutePolicyController.qml");
    let drain = function_body(&controller, "_drainPolicyWrites");
    assert!(
        drain.contains(
            "if (ok2 && Pure.isUserWriteOrigin(job.origin) && root.settingsRestoreController)"
        ),
        "the record is written after the service confirmed, for a user origin only:\n{drain}"
    );
    assert!(drain.contains("recordRoutePolicy(req, changed)"));

    // The internal writers name an origin that is not the user's.
    let resync = function_body(&controller, "_resyncRouteBindingWith");
    assert!(resync.contains("}, \"binding-resync\")"), "{resync}");
    // The panel never re-sends what its preferences remember: a service that
    // lost the user's settings gets the restore card, and only its action writes.
    let routing = repo_file("apps/desktop/qml/sections/settings/RoutingSettings.qml");
    assert!(
        !routing.contains("mutateRoutePolicy(") && !routing.contains("_applyRoutePolicyKey"),
        "RoutingSettings writes the policy on its own"
    );
    // A binding push records only when its caller says it is the user's.
    let push = function_body(&controller, "pushRouteBindingToService");
    assert!(push.contains("}, origin)"), "{push}");
    let roles = repo_file("apps/desktop/qml/flows/InterfacesRolesController.qml");
    assert_eq!(roles.matches("\"user:interfaces\")").count(), 2);

    let out = run_pure(
        r#"console.log(JSON.stringify([
            isUserWriteOrigin("user:routing-settings"),
            isUserWriteOrigin("offline-pending-apply"),
            isUserWriteOrigin("binding-resync"),
            isUserWriteOrigin("reseed"),
            isUserWriteOrigin(""),
            isUserWriteOrigin(undefined)
        ]))"#,
    );
    assert_eq!(out, json!([true, true, false, false, false, false]));
}

#[test]
fn the_card_action_runs_the_restore() {
    let notifications = repo_file("apps/desktop/qml/flows/NotificationsController.qml");
    assert!(notifications.contains(
        "else if (actionKey === \"restore-settings\") root.settingsRestoreController.restore()"
    ));
    let restore = repo_file("apps/desktop/qml/flows/SettingsRestoreController.qml");
    let card = function_body(&restore, "_raiseCard");
    assert!(
        card.contains("\"actionKey\": \"restore-settings\""),
        "{card}"
    );
    assert!(
        card.contains("\"settings-lost:\" + String(Date.now())"),
        "a dismissed card asks again on the next connect only: {card}"
    );
    let run = function_body(&restore, "restore");
    assert!(run.contains("}, \"user:restore-settings\")"), "{run}");
    assert!(
        !restore.contains("rpcRoutePolicyUpdate("),
        "the restore goes through the window's one writer"
    );

    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(main.contains("SettingsRestoreController {"));
    assert!(main.contains("Qt.callLater(settingsRestoreController.checkOnConnect)"));
    let startup = repo_file("apps/desktop/qml/flows/StartupController.qml");
    assert!(startup.contains("Qt.callLater(root.settingsRestoreController.checkOnConnect)"));
}

#[test]
fn the_tray_records_its_writes_and_asks_only_when_the_window_is_closed() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    for record in [
        "\"merge\": { \"auto-rules-mode\": String(mode) } })",
        "\"merge\": { \"leak-protection\": req[\"leak-protection\"] } })",
        "tray._recordIntent({ \"namespace\": \"notice-mutes\", \"value\": tray._noticeMutes })",
    ] {
        assert!(tray.contains(record), "the tray does not record: {record}");
    }
    let check = function_body(&tray, "_checkSettingsLost");
    assert!(
        check.contains("if (presence.windowActive) return"),
        "{check}"
    );
    assert!(
        check.contains("actionId: \"settings-lost-restore\""),
        "{check}"
    );
    assert!(tray.contains("if (action === \"settings-lost-restore\") {"));
}

#[test]
fn an_answer_sheet_is_not_recorded_as_the_users_choice() {
    let startup = repo_file("apps/desktop/qml/flows/StartupController.qml");
    let provisioned = function_body(&startup, "_applyProvisionedFirstRun");
    assert!(
        provisioned.contains("\"provisioning\")"),
        "the answer sheet's protections carry the provisioning origin"
    );
    let policy = repo_file("apps/desktop/qml/flows/RoutePolicyController.qml");
    assert!(function_body(&policy, "applyFirstRunProtections").contains("o.origin = origin ||"));
}

#[test]
fn the_tray_restores_the_protection_the_window_would() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    let check = function_body(&tray, "_checkSettingsLost");
    assert!(
        check.contains("tray._restoreProtection(state,"),
        "the tray's check no longer switches lost protection back on:\n{check}"
    );
    assert!(
        check.contains("tray._settingsLostKeys(state)"),
        "the count must leave out the keys the protection restore sends:\n{check}"
    );
    let keys = function_body(&tray, "_settingsLostKeys");
    assert!(
        keys.contains("Pure.routePolicyProtectionToRestore("),
        "{keys}"
    );
    let protection = function_body(&tray, "_restoreProtection");
    assert!(
        protection.contains("Pure.routePolicyProtectionRestore("),
        "{protection}"
    );
    assert!(
        protection.contains("tray._noteProtectionRestored(keys)"),
        "the user is told what went back on:\n{protection}"
    );
    let restore = function_body(&tray, "_restoreSettings");
    assert!(
        restore.contains("tray._restoreProtection(state,"),
        "\"Restore my settings\" must send the protection too:\n{restore}"
    );
    // "Restored" is said only for a write that went.
    let note = function_body(&tray, "_noteSettingsRestored");
    assert!(
        note.contains("\"status.settings-restore-nothing\""),
        "{note}"
    );

    let out = run_pure(
        r#"var req = routePolicyProtectionRestore(
            { "leak-protection": "everything", "doh-lockdown-enabled": true },
            { "mode": "prefer-primary", "leak-protection": "off", "doh-lockdown-enabled": false });
        console.log(JSON.stringify([req["apply-only"], req["leak-protection"], req["doh-lockdown-enabled"]]))"#,
    );
    assert_eq!(
        out,
        json!([
            ["doh-lockdown-enabled", "leak-protection"],
            "everything",
            true
        ])
    );
}
