//! A URL the window did not build opens only in the browser, and a folder only
//! through the bridge's directory check: no QML file hands a URL to the OS
//! opener itself. What the two doors let through is tested on the real
//! `pure.js` in `core/client-logic/tests/external_urls.rs`.

use std::path::Path;

#[test]
fn only_pure_js_hands_a_url_to_the_os() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml");
    let mut offenders = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("entry in {}: {e}", dir.display()))
                .path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let is_source = matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("qml" | "js")
            );
            if !is_source || path.ends_with("lib/pure.js") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            if text.contains("Qt.openUrlExternally") {
                offenders.push(path.display().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "open web URLs through Pure.openExternalUrl, folders through root.openOwnFolder: {offenders:?}"
    );
}
