//! `root: root` inside a component that declares its own `root` property binds
//! that property to itself: every `root.` read in the block then sees
//! `undefined`, and QML only logs a TypeError at runtime. The verbose-logging
//! combo in Settings and in the first-run wizard shipped that way, so the
//! setting silently did nothing. Pass the owner's root by id instead.

use std::path::{Path, PathBuf};

fn qml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            qml_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "qml") {
            out.push(path);
        }
    }
}

fn is_self_assignment(line: &str) -> bool {
    let Some(rest) = line.trim().strip_prefix("root:") else {
        return false;
    };
    rest.trim() == "root"
}

#[test]
fn no_component_binds_its_root_to_itself() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml");
    let mut files = Vec::new();
    qml_files(&dir, &mut files);
    assert!(!files.is_empty(), "no QML found under {}", dir.display());

    let offences: Vec<String> = files
        .iter()
        .flat_map(|path| {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            text.lines()
                .enumerate()
                .filter(|(_, line)| is_self_assignment(line))
                .map(|(n, _)| format!("{}:{}", path.display(), n + 1))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        offences.is_empty(),
        "`root: root` binds a component's root to itself:\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_check_sees_a_self_assignment() {
    assert!(is_self_assignment("    root: root"));
    assert!(is_self_assignment("root:root"));
    assert!(!is_self_assignment("    root: group.root"));
    assert!(!is_self_assignment("    root: window"));
}
