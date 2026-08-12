use nrr_shared::load_locale_map;
use std::fs;
use std::path::{Path, PathBuf};

const REQUIRED_ACCESSIBILITY_KEYS: &[&str] = &[
    "a11y.high-contrast",
    "a11y.enhanced-focus",
    "a11y.simplified-labels",
    "settings.field.tooltips",
    "a11y.tray.status-text.preview-mode",
    "a11y.tray.status-text.no-active-policy",
    "a11y.tray.status-text.service-unavailable",
    "a11y.tray.setup-state.allowed",
    "a11y.tray.setup-state.soft-guided",
    "a11y.tray.setup-state.blocked-until-wizard-completion",
    "a11y.tray.preview-only-note",
    "a11y.tray.action-label.open-main-window",
    "a11y.tray.action-label.interfaces-routes",
    "a11y.tray.action-label.rules",
    "a11y.tray.action-label.diagnostics",
    "a11y.tray.action-label.logs",
    "a11y.tray.action-label.settings",
    "a11y.tray.action-label.open-about-window",
    "a11y.tray.action-label.open-license-window",
    "a11y.tray.action-label.open-logs-folder",
    "a11y.tray.action-label.exit-application",
    "a11y.tray.action-label.refresh-interfaces",
    "a11y.tray.action-label.check-service-status",
    "a11y.tray.action-label.safe-rollback",
    "a11y.tray.action-label.temporary-disable-product-impact",
    "a11y.tray.action-description.open-main-window",
    "a11y.tray.action-description.interfaces-routes",
    "a11y.tray.action-description.rules",
    "a11y.tray.action-description.diagnostics",
    "a11y.tray.action-description.logs",
    "a11y.tray.action-description.settings",
    "a11y.tray.action-description.open-about-window",
    "a11y.tray.action-description.open-license-window",
    "a11y.tray.action-description.open-logs-folder",
    "a11y.tray.action-description.exit-application",
    "a11y.tray.action-description.refresh-interfaces",
    "a11y.tray.action-description.check-service-status",
    "a11y.tray.action-description.safe-rollback",
    "a11y.tray.action-description.temporary-disable-product-impact",
];

#[test]
fn required_accessibility_keys_exist_in_en_and_ru() {
    for locale in ["en", "ru"] {
        let locale_map = load_locale_map(locale);
        let missing = REQUIRED_ACCESSIBILITY_KEYS
            .iter()
            .filter(|key| !locale_map.contains_key(**key))
            .copied()
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "locale '{locale}' is missing required accessibility keys: {}",
            missing.join(", ")
        );
    }
}

#[test]
fn accessibility_strings_are_wired_in_main_and_tray_surfaces() {
    // The QML shell is decomposed into section files under
    // apps/desktop/qml/sections/, so accessibility keys may live in any
    // section file rather than directly in Main.qml. Concatenate all QML
    // files under apps/desktop/qml/ and check the corpus as a whole.
    let gui_qml_corpus = collect_qml_corpus("apps/desktop/qml");
    assert!(gui_qml_corpus.contains("a11y.high-contrast"));
    assert!(gui_qml_corpus.contains("a11y.enhanced-focus"));
    assert!(gui_qml_corpus.contains("a11y.simplified-labels"));
    assert!(gui_qml_corpus.contains("settings.field.tooltips"));

    let tray_qml = read_file("apps/desktop/qml/Tray.qml");
    assert!(tray_qml.contains("statusAccessibilityText"));

    // nrr-desktop-tray is a lib-only crate; the tray surface code lives
    // in `lib.rs`.
    let tray_runtime = read_file("apps/desktop/tray/src/lib.rs");
    assert!(tray_runtime.contains("accessible_description"));
    assert!(tray_runtime.contains("a11y.tray.status-text."));
    assert!(tray_runtime.contains("a11y.tray.action-label."));
    assert!(tray_runtime.contains("a11y.tray.action-description."));
}

fn collect_qml_corpus(relative_dir: &str) -> String {
    let dir = workspace_root().join(relative_dir);
    let mut buffer = String::new();
    collect_qml_files(&dir, &mut buffer);
    buffer
}

fn collect_qml_files(dir: &Path, buffer: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_qml_files(&path, buffer);
        } else if path.extension().and_then(|s| s.to_str()) == Some("qml") {
            if let Ok(contents) = fs::read_to_string(&path) {
                buffer.push_str(&contents);
                buffer.push('\n');
            }
        }
    }
}

fn read_file(relative_path: &str) -> String {
    let path = workspace_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()))
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| {
            panic!(
                "failed to resolve workspace root from '{}': {error}",
                manifest_dir.display()
            )
        })
}
