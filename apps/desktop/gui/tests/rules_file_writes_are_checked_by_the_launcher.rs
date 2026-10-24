//! A linked rules file the user edited by hand is never overwritten unasked.
//! The check lives in the launcher's write (`local.user-settings.rules-file-write`),
//! so it holds for every gesture — an apply, the offline save, "load from the
//! service", the tray — and not only for the paths that remembered to ask.
//! The QML writers therefore send their bytes there and never through the
//! host's unchecked `writeTextFile`.
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

#[test]
fn the_rules_file_writers_write_through_the_launcher() {
    for writer in [
        "apps/desktop/qml/flows/RulesFileWriter.qml",
        "apps/desktop/qml/flows/TrayBoundFileWriter.qml",
    ] {
        let source = read(writer);
        assert!(
            !source.contains("writeTextFile("),
            "{writer} writes a rules file past the hand-edit check"
        );
    }
    let writer = read("apps/desktop/qml/flows/RulesFileWriter.qml");
    assert!(
        writer.contains("rpcUserSettingsRulesFileWrite("),
        "RulesFileWriter sends its bytes to the launcher"
    );
    assert!(
        writer.contains("\"overwrite\": overwrite === true"),
        "only an explicit answer overwrites a hand-edited file"
    );
}

#[test]
fn the_launcher_routes_the_write_and_the_window_asks_on_its_refusal() {
    let handlers = read("apps/desktop/launcher/src/local_handlers.rs");
    assert!(handlers.contains("\"local.user-settings.rules-file-write\""));

    let controller = read("apps/desktop/qml/flows/BoundFilesController.qml");
    assert!(
        controller.contains("code === \"rules-file-hand-edited\""),
        "the window recognises the launcher's refusal"
    );
    // The dialog's "replace the file" is the one caller that may overwrite.
    let overwrite = controller
        .split("function overwriteHandEditedFiles(")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("overwriteHandEditedFiles is defined");
    assert!(
        overwrite.contains("}, true)"),
        "overwriteHandEditedFiles passes overwrite to _writeTargets"
    );
    assert_eq!(
        controller.matches("}, true)").count(),
        1,
        "no other write path overwrites a hand-edited file"
    );
    let bridge = read("apps/desktop/qt-host/native/src/native_bridge_files.cpp");
    assert!(bridge.contains("local.user-settings.rules-file-write"));
}
