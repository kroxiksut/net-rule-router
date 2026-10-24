//! "Add automatically" from the tray: a service too busy to answer in time
//! gets the write again, and a failure that stays reaches the user instead of
//! the console only. The executable check runs the real `pure.js` through
//! `node`; skipped when node is absent.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn run_node(program: &str) -> Option<String> {
    let mut child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!("this check runs the QML JavaScript through node; install Node.js ({e})")
        });
    let Some(stdin) = child.stdin.as_mut() else {
        panic!("stdin was piped")
    };
    stdin
        .write_all(program.as_bytes())
        .unwrap_or_else(|e| panic!("write the harness to node: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("node runs to completion: {e}"));
    assert!(
        out.status.success(),
        "node rejected the harness: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn only_a_late_answer_is_asked_again_and_not_forever() {
    let source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", "");
    let Some(out) = run_node(&format!(
        "{source}\nconsole.log(JSON.stringify([\
           busyRetryDelayMs('timeout', 0) > 0,\
           busyRetryDelayMs('rpc-timed-out', 1) > 0,\
           busyRetryDelayMs('timeout', 2),\
           busyRetryDelayMs('forbidden', 0),\
           busyRetryDelayMs('transport-disconnected', 0),\
           busyRetryDelayMs('', 0)\
         ]));\n"
    )) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(out.trim(), "[true,true,-1,-1,-1,-1]");
}

#[test]
fn the_tray_repeats_a_busy_write_and_tells_a_failure() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    let body = tray
        .split("function _setAutoRulesMode(")
        .nth(1)
        .and_then(|rest| rest.split("\n    function ").next())
        .unwrap_or_else(|| panic!("_setAutoRulesMode not found"));
    assert!(
        body.contains("Pure.busyRetryDelayMs("),
        "a busy service no longer gets the write again"
    );
    assert!(
        body.contains("_noteAutoRulesModeFailed("),
        "a failed write is no longer told to the user"
    );
    assert!(
        body.contains("\"apply-only\"] = [\"auto-rules-mode\"]"),
        "a repeated write must name only its own key"
    );
    assert!(
        tray.matches("\"auto-rules-mode-failed-dismiss\"").count() >= 2,
        "the failure notice is raised but its dismissal is not handled"
    );
}

#[test]
fn the_tray_leak_protection_pick_repeats_a_busy_write_and_tells_a_failure() {
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    let body = tray
        .split("function _setLeakProtection(")
        .nth(1)
        .and_then(|rest| rest.split("\n    property var ").next())
        .unwrap_or_else(|| panic!("_setLeakProtection not found"));
    assert!(
        body.contains("Pure.busyRetryDelayMs("),
        "a busy service does not get the leak-protection write again"
    );
    assert!(
        body.contains("_noteLeakProtectionFailed("),
        "a failed leak-protection write is not told to the user"
    );
    let write = tray
        .split("function _writeLeakProtection(")
        .nth(1)
        .and_then(|rest| rest.split("\n    function ").next())
        .unwrap_or_else(|| panic!("_writeLeakProtection not found"));
    assert!(
        write.contains("if (!ok) { failed(\"write\", code, msg); return }"),
        "the write's failure must reach the retry path:\n{write}"
    );
    assert!(
        tray.matches("\"leak-protection-failed-dismiss\"").count() >= 2,
        "the failure notice is raised but its dismissal is not handled"
    );
    // Same class: "Turn off rules" from the menu.
    assert!(tray.contains("tray._notePauseFailed(code)"));
    assert!(tray.matches("\"pause-failed-dismiss\"").count() >= 2);
}
