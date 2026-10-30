//! A text that sends the user to another setting names that page, group and
//! setting from their own locale keys. Typed in by hand, the Russian one sent
//! the user to «Основные», a page the sidebar never had, for a checkbox under
//! another name.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn value_at<'a>(json: &'a serde_json::Value, dotted: &str) -> Option<&'a str> {
    dotted
        .split('.')
        .try_fold(json, |node, part| node.get(part))
        .and_then(|v| v.as_str())
}

const POINTERS: [(&str, &[&str]); 2] = [
    (
        "settings.service.launch-tray.description",
        &["{setting}", "{page}", "{group}"],
    ),
    ("rules.import-only-active.tooltip", &["{page}", "{group}"]),
];

#[test]
fn every_language_names_the_page_from_its_keys() {
    let dir = repo().join("locales");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.map(|e| e.path()).unwrap_or_default();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let json: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for (key, placeholders) in POINTERS {
            let Some(value) = value_at(&json, key) else {
                continue;
            };
            for placeholder in placeholders {
                assert!(
                    value.contains(placeholder),
                    "{} {key} names a page or setting by hand instead of {placeholder}: {value}",
                    path.display()
                );
            }
            checked += 1;
        }
    }
    assert!(checked >= POINTERS.len(), "no locale holds the texts");
}

#[test]
fn the_window_fills_the_page_names_in() {
    for (file, key) in [
        (
            "apps/desktop/qml/sections/settings/ServiceManagementSettings.qml",
            "settings.service.launch-tray.description",
        ),
        (
            "apps/desktop/qml/components/LoadListWindow.qml",
            "rules.import-only-active.tooltip",
        ),
    ] {
        let source = std::fs::read_to_string(repo().join(file))
            .unwrap_or_else(|e| panic!("{file}: {e}"))
            .replace("\r\n", "\n");
        let at = source
            .find(&format!("\"{key}\""))
            .unwrap_or_else(|| panic!("{file} no longer shows {key}"));
        let call = &source[at..source.len().min(at + 900)];
        for filler in [
            ".replace(\"{page}\", root.tr(\"settings.category.application\"",
            ".replace(\"{group}\", root.tr(\"settings.group.general\"",
        ] {
            assert!(call.contains(filler), "{file}: {key} lacks {filler}");
        }
    }
}
