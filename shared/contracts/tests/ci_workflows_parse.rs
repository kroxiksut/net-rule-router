#![allow(clippy::expect_used)]

//! Every YAML file under `.github` parses. GitHub refuses a broken workflow
//! only after the push, and nothing else in the gate reads these files.

use std::path::{Path, PathBuf};

use yaml_rust2::YamlLoader;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).expect("readable .github directory");
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            yaml_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml" | "yaml")
        ) {
            out.push(path);
        }
    }
}

fn parse_error(text: &str) -> Option<String> {
    match YamlLoader::load_from_str(text) {
        Ok(docs) if docs.is_empty() => Some("no document".into()),
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    }
}

#[test]
fn every_github_yaml_file_parses() {
    let mut files = Vec::new();
    yaml_files(&repo_root().join(".github"), &mut files);
    assert!(!files.is_empty(), "no YAML found under .github");
    let broken: Vec<String> = files
        .iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).expect("readable YAML file");
            parse_error(&text).map(|e| format!("{}: {e}", path.display()))
        })
        .collect();
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// The break that shipped once: an escape in a `run:` block turned into a real
/// line break. The check above is worth nothing if it would not see this.
#[test]
fn a_run_block_split_by_a_raw_line_break_is_refused() {
    let broken = "jobs:\n  sign:\n    steps:\n      - run: |\n          printf '%s\n' \"$KEY\" > \"$file\"\n          rm -f \"$file\"\n";
    assert!(parse_error(broken).is_some());
    let fixed = "jobs:\n  sign:\n    steps:\n      - run: |\n          printf '%s\\n' \"$KEY\" > \"$file\"\n          rm -f \"$file\"\n";
    assert_eq!(parse_error(fixed), None);
}
