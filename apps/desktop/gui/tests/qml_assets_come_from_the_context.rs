//! An image path relative to the QML file ties the package to the source
//! tree's depth: a package that moved the QML found every icon two levels
//! above itself. Every image goes through `assetUrl`, built on the
//! `assetsRootUrl` the launcher resolved.

use std::path::{Path, PathBuf};

fn qml_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            qml_sources(&path, out);
        } else if path
            .extension()
            .is_some_and(|e| e == "qml" || e == "js" || e == "mjs")
        {
            out.push(path);
        }
    }
}

fn names_assets_by_relative_path(line: &str) -> bool {
    line.contains("../assets/")
}

fn qml_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

#[test]
fn no_qml_reaches_assets_relative_to_itself() {
    let mut files = Vec::new();
    qml_sources(&qml_dir(), &mut files);
    assert!(
        !files.is_empty(),
        "no QML found under {}",
        qml_dir().display()
    );

    let offences: Vec<String> = files
        .iter()
        .flat_map(|path| {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            text.lines()
                .enumerate()
                .filter(|(_, line)| names_assets_by_relative_path(line))
                .map(|(n, line)| format!("{}:{}: {}", path.display(), n + 1, line.trim()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        offences.is_empty(),
        "build the path with `assetUrl(...)` instead:\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_check_sees_a_relative_asset_path() {
    assert!(names_assets_by_relative_path(
        r#"source: Qt.resolvedUrl("../../../assets/icons/ui/x.svg")"#
    ));
    assert!(names_assets_by_relative_path(
        r#"icon: "../assets/icons/app/icon-64.png""#
    ));
    assert!(!names_assets_by_relative_path(
        r#"source: assetUrl("icons/ui/x.svg")"#
    ));
}

/// Both surfaces read the root from the field the launcher writes.
#[test]
fn both_surfaces_take_the_root_from_the_context() {
    for surface in ["Main.qml", "Tray.qml"] {
        let text = std::fs::read_to_string(qml_dir().join(surface)).expect("surface QML");
        assert!(
            text.contains("context.assetsRootUrl"),
            "{surface} does not read `assetsRootUrl` from its launch context"
        );
    }
}
