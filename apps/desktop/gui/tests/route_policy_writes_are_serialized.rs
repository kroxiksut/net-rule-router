//! `route.policy.update` replaces the whole per-SID row, so a write built on a
//! read that another write overtook puts the other's fields back. First run
//! sent the kill switch, the DoH lockdown and both adapter bindings at once,
//! and the service kept neither protection. The window therefore owns ONE
//! writer, a queue, and the first-run protections travel as one write.

use std::path::{Path, PathBuf};

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn window_sources(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("list {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            window_sources(&path, out);
            continue;
        }
        // The tray is another process with its own bridge; it cannot share
        // this window's queue.
        let is_source = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("qml" | "js")
        );
        if is_source && path.file_name().and_then(|n| n.to_str()) != Some("Tray.qml") {
            let text = read(&path);
            out.push((path, text));
        }
    }
}

#[test]
fn the_window_has_one_route_policy_writer() {
    let mut sources = Vec::new();
    window_sources(&qml_root(), &mut sources);
    let writers: Vec<String> = sources
        .iter()
        .filter(|(_, text)| text.contains("rpcRoutePolicyUpdate("))
        .map(|(path, text)| {
            format!(
                "{} ({}x)",
                path.display(),
                text.matches("rpcRoutePolicyUpdate(").count()
            )
        })
        .collect();
    assert_eq!(
        writers.len(),
        1,
        "route.policy.update must go through RoutePolicyController.mutateRoutePolicy: {writers:?}"
    );
    let controller = read(&qml_root().join("flows/RoutePolicyController.qml"));
    assert_eq!(controller.matches("rpcRoutePolicyUpdate(").count(), 1);
    let drain = controller
        .split("function _drainPolicyWrites()")
        .nth(1)
        .expect("the queue drain");
    assert!(
        drain.contains("rpcRoutePolicyUpdate("),
        "the one writer must be the queue's drain"
    );
}

#[test]
fn first_run_protections_travel_as_one_write() {
    for file in [
        "flows/StartupController.qml",
        "components/FirstRunWindow.qml",
    ] {
        let text = read(&qml_root().join(file));
        assert!(
            text.contains("applyFirstRunProtections("),
            "{file} must send the kill switch and the DoH lockdown together"
        );
        assert!(
            !text.contains("applyKillSwitchEnabled(") && !text.contains("applyDohLockdownEnabled("),
            "{file} sends a first-run protection as a write of its own"
        );
        assert!(
            text.contains("applyFirstRunStability("),
            "{file} must route service-wide answers through the path that names a refusal"
        );
    }
}
