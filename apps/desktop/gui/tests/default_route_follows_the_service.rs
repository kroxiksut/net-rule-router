//! The default route is shown and confirmed against what the service holds.
//! The tray changes leak protection without telling the window, so a decision
//! taken from the window's snapshot skipped the "Everything" question; and the
//! "Interfaces" screen read the launch context, which never updates.

use std::path::Path;

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn body<'a>(text: &'a str, start: &str) -> &'a str {
    let rest = text
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("`{start}` not found"));
    rest.split("\n    function ").next().unwrap_or(rest)
}

#[test]
fn the_route_question_is_asked_against_a_fresh_read() {
    let main = qml("Main.qml");
    let confirm = body(
        &main,
        "function confirmDefaultRoute(level, nextRoute, onProceed, onCancel) {",
    );
    assert!(
        confirm.contains("rpcSnapshotInitialGet()"),
        "the level in force is read from the service before deciding"
    );
    assert!(
        confirm.contains("decide(fresh)"),
        "the fresh level decides, not the caller's snapshot"
    );
    assert!(
        confirm.contains("updateRoutingState({ leakProtection: fresh })"),
        "the window's mirror follows what it just read"
    );
    assert!(
        confirm.contains("decide(level)"),
        "an unreadable service still gets the caller's level, never silence"
    );
}

#[test]
fn interfaces_show_the_services_default_route() {
    let section = qml("sections/InterfacesRoutesSection.qml");
    let after = section
        .split("readonly property string serviceRoute:")
        .nth(1)
        .unwrap_or_else(|| panic!("the combo no longer follows the service's route"));
    let (route, start_up) = after
        .split_once("Component.onCompleted")
        .unwrap_or_else(|| panic!("the combo's start-up is gone"));
    let completed = start_up
        .split("property string _shownMode")
        .next()
        .unwrap_or(start_up);
    let service = route
        .find("root._serviceDefaultRoute")
        .unwrap_or_else(|| panic!("the service's route is not read"));
    let context = route
        .find("selectedBehaviorMode")
        .unwrap_or_else(|| panic!("the launch context fallback is gone"));
    assert!(service < context, "the launch context is only the fallback");
    assert!(route.contains("onServiceRouteChanged"));
    assert!(
        completed.contains("serviceRoute, 0)"),
        "the first value shown is the service's"
    );
}
