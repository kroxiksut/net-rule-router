//! A language change restarts the tray: the window asks it to quit and starts
//! a new one once the old is gone. "Gone" was judged by the PID this host had
//! spawned, which is zero for a tray that outlived an earlier window, so the
//! new tray started at once, found the old one's lock and exited as a
//! duplicate, and the icon vanished. The host now reads the tray launcher's
//! own lock file; its name must stay the launcher's key.

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn the_host_reads_the_lock_the_tray_launcher_holds() {
    let launcher = repo_file("apps/desktop/launcher/src/launcher/mod.rs");
    assert!(
        launcher.contains("single_instance_key: \"tray-shell-v1\""),
        "the tray's single-instance key changed; the host's lock file name must follow"
    );
    let bridge = repo_file("apps/desktop/qt-host/native/src/native_bridge.cpp");
    assert!(bridge.contains("QStringLiteral(\"tray-shell-v1.lock\")"));
    let alive = bridge
        .split("bool NrrNativeBridge::isTrayProcessAlive() {")
        .nth(1)
        .unwrap_or_else(|| panic!("isTrayProcessAlive is gone"));
    let lock_at = alive
        .find("trayLockHolderPid()")
        .unwrap_or_else(|| panic!("the liveness answer no longer reads the tray lock"));
    let pid_at = alive
        .find("trayProcessId_ <= 0")
        .unwrap_or_else(|| panic!("the spawned-PID fallback is gone"));
    assert!(
        lock_at < pid_at,
        "the spawned PID must not answer before the lock does"
    );
}
