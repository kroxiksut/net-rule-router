//! A user who set protection up in the terminal and then opens the window
//! for the first time must not have it lowered by closing the first-run
//! setup. The window starts from what the service holds and writes only what
//! changed, through the decision it shares with the terminal setup
//! (`route_policy::first_run_writes`, vectors in `first_run_writes.json`).
#![allow(clippy::expect_used)]

use std::path::Path;

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("{name} is defined"));
    let rest = &source[start..];
    let end = rest[1..]
        .find("\n    function ")
        .map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

#[test]
fn the_wizard_writes_only_what_the_shared_decision_allows() {
    let wizard = qml("components/FirstRunWindow.qml");
    let write = function_body(&wizard, "_writeServiceChoices");
    let decision = write
        .find("Pure.firstRunWrites(")
        .expect("the write asks the shared decision");
    let protection = write
        .find("applyFirstRunProtections(")
        .expect("protection is written here");
    let stability = write
        .find("applyFirstRunStability(")
        .expect("the answers are written here");
    assert!(decision < protection && decision < stability);
    assert!(write.contains("if (writes.protection"));
    assert!(write.contains("if (!writes.stability) return"));

    let close = function_body(&wizard, "_applyProtectionChoices");
    assert!(
        !close.contains("applyFirstRunProtections(") && !close.contains("applyFirstRunStability("),
        "closing never writes past the decision"
    );
    assert!(
        close.contains("_serviceWritePending = true"),
        "before the service answered, the write waits for it"
    );
}

/// A user already set up who changes only the log window must not have
/// fake-IP switched on by the window's offer.
#[test]
fn fake_ip_is_written_only_when_the_shared_decision_says_so() {
    let wizard = qml("components/FirstRunWindow.qml");
    let write = function_body(&wizard, "_writeServiceChoices");
    assert!(write.contains("_stabilityTouched, _fakeIpTouched)"));
    assert!(write.contains("if (writes.fakeIp) patch[\"fake-ip-enabled\"] = wantFakeIp"));
    assert!(!write.contains("{ \"fake-ip-enabled\": wantFakeIp }"));
    let seed = function_body(&wizard, "_seedFakeIp");
    assert!(
        seed.contains("!_fakeIpTouched"),
        "a choice made here stands"
    );
}

#[test]
fn the_wizard_starts_from_what_the_service_holds() {
    let wizard = qml("components/FirstRunWindow.qml");
    let seed = function_body(&wizard, "_seedProtection");
    assert!(seed.contains("root._serviceRoutePolicy"));
    assert!(seed.contains("Pure.firstRunHeldProtection("));
    assert!(
        seed.contains("!_protectionTouched"),
        "a choice made before the read stands"
    );
    let main = qml("Main.qml");
    let note = function_body(&main, "_noteServicePolicy");
    assert!(note.contains("_serviceRoutePolicy = rpRaw || null"));
    let pure = qml("lib/pure.js");
    assert!(pure.contains("function firstRunHeldProtection("));
    assert!(pure.contains("function firstRunWrites("));
}
