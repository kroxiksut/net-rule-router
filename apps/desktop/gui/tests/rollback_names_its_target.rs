//! Safe rollback asks the service what it would restore before anything is
//! confirmed, and judges the rollback by its operation record: "accepted" is
//! not "rolled back". Runs the real `pure.js` through `node`; skipped when
//! node is absent.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_menu_opens_the_dry_run_and_the_verdict_comes_from_the_operation_record() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(
        main.contains("onTriggered: boundFilesController.openSafeRollback()"),
        "the menu opens the dialog without asking what it would restore"
    );
    assert!(!main.contains("safeRollbackConfirmDialog.open()"));
    let controller = repo_file("apps/desktop/qml/flows/BoundFilesController.qml");
    let perform = controller
        .find("function _performSafeRollback()")
        .map(|at| &controller[at..])
        .expect("_performSafeRollback");
    assert!(
        perform.contains("root.rpc.readMutationOutcome("),
        "the rollback's success is read off its acceptance, not its record"
    );
}

#[test]
fn the_dry_run_answer_is_a_target_nothing_or_an_error() {
    let harness = format!(
        "{source}\n\
         function show(v) {{ return v.phase + ':' + v.token + ':' + (v.target ? v.target['revision-id'] : '') + ':' + v.code; }}\n\
         console.log([\n\
           show(rollbackDryRunVerdict(true, {{ 'confirmation-token': 't', target: {{ 'revision-id': 'rev-a' }} }}, '')),\n\
           show(rollbackDryRunVerdict(true, {{}}, '')),\n\
           show(rollbackDryRunVerdict(true, {{ error: {{ code: 'revision-integrity-rejected' }} }}, '')),\n\
           show(rollbackDryRunVerdict(false, null, 'timeout')),\n\
           show(rollbackDryRunVerdict(true, {{ 'confirmation-token': 't' }}, '')),\n\
           show(rollbackDryRunVerdict(true, {{ target: {{ 'revision-id': 'rev-a' }} }}, ''))\n\
         ].join('|'));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(
        output.trim(),
        "ready:t:rev-a:|none:::|error:::revision-integrity-rejected|error:::timeout\
         |error:::bad-response|error:::bad-response",
        "{output}"
    );
}

/// Feed a program to `node` on stdin. `None` when node is not installed.
fn run_node(program: &str) -> Option<String> {
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
