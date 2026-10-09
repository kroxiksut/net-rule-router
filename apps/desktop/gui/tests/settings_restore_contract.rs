//! "Restore my settings": the user's route policy and mutes are recorded in
//! their own settings file only after a write of theirs the service confirmed,
//! a record of one part never erases another, and the card that offers the
//! restore is wired to the one write that performs it.
//!
//! A resync, a heal or a re-seed restates what the app holds; recorded as the
//! user's word, it would launder a service default into "what the user
//! wanted" and offer it back after the next reinstall.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// `pure.js` plus `body`, run by node; `None` when node is not installed.
fn run_pure(body: &str) -> Option<Value> {
    let pure = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", "");
    let mut child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let Some(stdin) = child.stdin.as_mut() else {
        panic!("stdin was piped")
    };
    stdin
        .write_all(format!("{pure}\n{body}\n").as_bytes())
        .unwrap_or_else(|e| panic!("write the harness to node: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("node runs to completion: {e}"));
    assert!(
        out.status.success(),
        "node rejected the harness: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(
        serde_json::from_str(text.trim())
            .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {text}")),
    )
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
    let routing = repo_file("apps/desktop/qml/sections/settings/RoutingSettings.qml");
    let reseed = function_body(&routing, "_reseedTogglesFromPrefs");
    assert!(reseed.contains("}, \"reseed\")"), "{reseed}");
    // A binding push records only when its caller says it is the user's.
    let push = function_body(&controller, "pushRouteBindingToService");
    assert!(push.contains("}, origin)"), "{push}");
    let roles = repo_file("apps/desktop/qml/flows/InterfacesRolesController.qml");
    assert_eq!(roles.matches("\"user:interfaces\")").count(), 2);

    if let Some(out) = run_pure(
        r#"console.log(JSON.stringify([
            isUserWriteOrigin("user:routing-settings"),
            isUserWriteOrigin("offline-pending-apply"),
            isUserWriteOrigin("binding-resync"),
            isUserWriteOrigin("reseed"),
            isUserWriteOrigin(""),
            isUserWriteOrigin(undefined)
        ]))"#,
    ) {
        assert_eq!(out, json!([true, true, false, false, false, false]));
    } else {
        eprintln!("node not available — skipping the origin check");
    }
}

#[test]
fn the_stability_record_keeps_the_other_namespaces() {
    let controller = repo_file("apps/desktop/qml/flows/ServiceIntentController.qml");
    assert!(
        !controller.contains("JSON.stringify({ \"stability\""),
        "a record rebuilt from stability alone erases the route policy and the mutes"
    );
    let write = function_body(&controller, "_writeStabilityIntent");
    assert!(write.contains("Pure.intentWithNamespace("), "{write}");

    let body = r#"
        console.log(JSON.stringify({
            kept: intentWithNamespace(
                JSON.stringify({ "stability": { "a": 1 }, "route-policy": { "mode": "x" } }),
                "stability", { "a": 2 }),
            dropped: intentWithNamespace(JSON.stringify({ "stability": {}, "notice-mutes": [] }),
                "stability", null),
            broken: intentWithNamespace("{not json", "stability", { "a": 1 })
        }));
    "#;
    if let Some(out) = run_pure(body) {
        assert_eq!(
            out["kept"],
            json!({ "stability": { "a": 2 }, "route-policy": { "mode": "x" } })
        );
        assert_eq!(out["dropped"], json!({ "notice-mutes": [] }));
        assert_eq!(out["broken"], json!({ "stability": { "a": 1 } }));
    } else {
        eprintln!("node not available — skipping the namespace check");
    }
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
        "\"merge\": { \"kill-switch-enabled\": want === true } })",
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
