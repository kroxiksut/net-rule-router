//! A table that sorts by clicking a column header must sort from the keyboard
//! too: someone without a mouse otherwise reads the logs, the audit trail,
//! the cache and the connection trace only in the order they came.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The columns `call` sorts by in handlers introduced by `handler`.
fn sorted_by(source: &str, handler: &str, call: &str) -> BTreeSet<String> {
    let needle = format!("{handler} section.{call}(\"");
    source
        .match_indices(&needle)
        .filter_map(|(at, _)| {
            let rest = &source[at + needle.len()..];
            rest.find('"').map(|end| rest[..end].to_owned())
        })
        .collect()
}

#[test]
fn every_sortable_column_sorts_from_the_keyboard() {
    let tables = [
        ("sections/LogsSection.qml", "onClicked:", "setLogSort"),
        ("sections/LogsSection.qml", "onClicked:", "setAuditSort"),
        ("sections/CacheSection.qml", "onTapped:", "_toggleCacheSort"),
        (
            "sections/ConnTraceSection.qml",
            "onTapped:",
            "_toggleConnSort",
        ),
    ];
    for (file, mouse, call) in tables {
        let source = qml(file);
        let by_mouse = sorted_by(&source, mouse, call);
        assert!(!by_mouse.is_empty(), "{file}: no {call} header found");
        let by_keys = sorted_by(&source, "onActivated:", call);
        let missing: Vec<_> = by_mouse.difference(&by_keys).collect();
        assert!(
            missing.is_empty(),
            "{file}: columns sorted only by mouse: {missing:?}"
        );
    }
    let header = qml("components/SortHeader.qml");
    assert!(header.contains("activeFocusOnTab: true"));
    assert!(header.contains("Keys.onSpacePressed: header.activated()"));
    assert!(header.contains("Accessible.role: Accessible.ColumnHeader"));
}
