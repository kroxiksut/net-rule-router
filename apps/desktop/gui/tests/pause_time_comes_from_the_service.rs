//! "Paused since …" names when the pause began, which the service records. A
//! window that stamped the moment it read the snapshot or got the push showed
//! 13:00 for a pause the tray started at 10:00.

use std::path::Path;

fn main_qml() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml/Main.qml");
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
fn the_snapshot_and_the_push_carry_the_services_pause_time() {
    let main = main_qml();
    let snapshot = body(&main, "function _applyPushedSettingsFromSnapshot(p) {");
    assert!(snapshot.contains("_pausedAtIso(p[\"routing-paused-at\"])"));
    assert!(
        !snapshot.contains("routingPausedAt = paused ? new Date()"),
        "the read moment is not the pause moment"
    );
    let push = main
        .split("case \"routing-pause-state-changed\":")
        .nth(1)
        .and_then(|rest| rest.split("break").next())
        .unwrap_or_else(|| panic!("no pause push case"));
    assert!(push.contains("_pausedAtIso(event[\"paused-at\"])"));
    assert!(!push.contains("new Date()"));
}
