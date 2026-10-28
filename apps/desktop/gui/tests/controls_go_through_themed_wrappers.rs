//! The native style ignores the palette for these controls: a raw one stays
//! light on a dark or high-contrast theme, white text on white. Every instance
//! goes through its `Themed*` wrapper; only a wrapper file may declare one.

use std::path::{Path, PathBuf};

const RAW: [&str; 5] = ["Button", "TextField", "SpinBox", "ComboBox", "TextArea"];

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

fn qml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            qml_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "qml") {
            out.push(path);
        }
    }
}

#[test]
fn no_raw_control_reaches_the_screen() {
    let mut files = Vec::new();
    qml_files(&qml_root(), &mut files);
    assert!(files.len() > 50, "found only {} QML files", files.len());

    let mut raw = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        let in_components = path.parent().and_then(Path::file_name) == Some("components".as_ref());
        for (at, line) in text.lines().enumerate() {
            let Some(kind) = line.trim().strip_suffix('{').map(str::trim) else {
                continue;
            };
            if !RAW.contains(&kind) {
                continue;
            }
            // An unindented object is the file's own root: a wrapper, which only
            // the components folder holds.
            if !line.starts_with(char::is_whitespace) && in_components {
                continue;
            }
            raw.push(format!(
                "{}:{} {kind}",
                path.strip_prefix(qml_root()).unwrap_or(path).display(),
                at + 1
            ));
        }
    }
    assert!(
        raw.is_empty(),
        "raw controls (use ThemedButton / ThemedTextField / ThemedSpinBox / ThemedComboBox / ThemedTextArea):\n{}",
        raw.join("\n")
    );
}
