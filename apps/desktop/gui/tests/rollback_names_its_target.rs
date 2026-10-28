//! Safe rollback asks the service what it would restore before anything is
//! confirmed, and judges the rollback by its operation record: "accepted" is
//! not "rolled back". Runs the real `pure.js`.

#[path = "support/js.rs"]
mod js;

use std::path::{Path, PathBuf};

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
    let output = js::run_js(&harness);
    assert_eq!(
        output.trim(),
        "ready:t:rev-a:|none:::|error:::revision-integrity-rejected|error:::timeout\
         |error:::bad-response|error:::bad-response",
        "{output}"
    );
}
