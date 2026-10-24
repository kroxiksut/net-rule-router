//! With the service stopped and "load rules at start" off, the table opens
//! empty although a rules file is bound. "Apply" then saves to the file and
//! parks the table as the set to apply: both would replace the user's rules
//! with the few typed since. Every such write first asks whether the table
//! holds a whole set (the service's or the file's).
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The body of `function <name>(` up to the next function at the same depth.
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
fn the_check_knows_every_source_of_a_whole_table() {
    let controller = read("apps/desktop/qml/flows/BoundFilesController.qml");
    let check = function_body(&controller, "tableMissesBoundRules");
    for source in [
        "_serviceRuleCount >= 0",
        "rulesBaseRevision !== null",
        "tableFromFiles",
    ] {
        assert!(check.contains(source), "the check misses `{source}`");
    }
    assert!(
        check.contains("_boundTargets().length === 0) return false"),
        "with no file bound there is nothing to lose"
    );
    let import = read("apps/desktop/qml/flows/PresetImportController.qml");
    let offline = function_body(&import, "_applyPresetImportOffline");
    assert!(
        offline.contains("boundFilesController.tableFromFiles = true"),
        "a table loaded from the files counts as whole"
    );
}

#[test]
fn the_offline_writes_refuse_an_unloaded_table() {
    let controller = read("apps/desktop/qml/flows/BoundFilesController.qml");
    let save = function_body(&controller, "saveRulesToFiles");
    let guard = save
        .find("tableMissesBoundRules()")
        .expect("saveRulesToFiles checks the table");
    let write = save
        .find("_writeTargets(")
        .expect("saveRulesToFiles writes");
    assert!(guard < write, "the check comes before the write");

    let review = read("apps/desktop/qml/flows/ReviewFlowController.qml");
    let apply = function_body(&review, "_guardApplyRules");
    let guard = apply
        .find("tableMissesBoundRules()")
        .expect("the offline apply checks the table");
    let save = apply
        .find("saveRulesToFiles(")
        .expect("the offline apply saves");
    let park = apply
        .find("_parkPendingApply(")
        .expect("the offline apply parks");
    assert!(
        guard < save && guard < park,
        "nothing is saved or parked first"
    );

    let main = read("apps/desktop/qml/Main.qml");
    let marker = function_body(&main, "_writeOfflineRulesMarker");
    let guard = marker
        .find("tableMissesBoundRules()")
        .expect("the offline-edit marker checks the table");
    let park = marker.find("_parkPendingApply(").expect("the marker parks");
    assert!(guard < park, "an unloaded table is never parked");
}
