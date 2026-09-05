//! Every preference write in the QML tree must reach the disk.
//!
//! `updatePrefs()` only mutates the in-memory object; `emitPrefs()` is what
//! prints the `NRR_PREFS_JSON:` line the launcher persists. So a key has
//! exactly two legal homes, and `Main.qml` states them right above the list:
//!
//!   * in `_bufferedPrefKeys` — the patch arms the Apply/Cancel snapshot, and
//!     whichever of the two the user picks emits;
//!   * outside it — the writer emits in the same handler.
//!
//! A key in neither lived in memory only, and persisted just in case something
//! unrelated emitted afterwards. That is how a "don't show these again" toggle
//! came back on the next launch, and it is invisible in review because both
//! halves look perfectly ordinary on their own. This test walks every write
//! site instead.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("apps/desktop/qml")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn qml_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![qml_root()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "qml") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The keys `Main.qml` buffers, read from the declaration itself so this test
/// cannot drift from it.
fn buffered_keys() -> BTreeSet<String> {
    let main = read(&qml_root().join("Main.qml"));
    let start = main
        .find("_bufferedPrefKeys")
        .expect("Main.qml declares _bufferedPrefKeys");
    let block = &main[start..];
    let end = block
        .find("})")
        .expect("_bufferedPrefKeys literal is closed");
    let mut keys = BTreeSet::new();
    for line in block[..end].lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('"') else {
            continue;
        };
        let Some(name) = rest.split('"').next() else {
            continue;
        };
        if line.contains(": true") {
            keys.insert(name.to_string());
        }
    }
    assert!(
        keys.len() > 10,
        "parsed {} buffered keys — the literal's shape changed",
        keys.len()
    );
    keys
}

/// The object-literal keys of the call starting at `from`.
fn patch_keys(text: &str, from: usize) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut end = text.len();
    for (i, b) in bytes.iter().enumerate().skip(from) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let call = &text[from..end];
    let mut keys = Vec::new();
    for (i, _) in call.match_indices(':') {
        let before = call[..i].trim_end();
        let name: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            keys.push(name.chars().rev().collect());
        }
    }
    keys
}

/// `firstRunCompleted` is written on five paths that all end in the wizard's
/// `close()`, and its `onClosing` is what flushes them. The exception is only
/// sound while that emit is there — the positive control below is what keeps
/// this from becoming a blanket excuse.
const FLUSHED_BY_WIZARD_CLOSE: &str = "firstRunCompleted";

#[test]
fn the_wizards_closing_handler_flushes_what_its_paths_write() {
    let wizard = read(&qml_root().join("components/FirstRunWindow.qml"));
    let start = wizard
        .find("onClosing:")
        .expect("FirstRunWindow declares onClosing");
    let handler = &wizard[start..];
    let end = handler.find("\n    }").unwrap_or(handler.len());
    assert!(
        handler[..end].contains("root.emitPrefs()"),
        "the wizard's onClosing must emit: every option path sets \
         `{FLUSHED_BY_WIZARD_CLOSE}` and closes, and nothing else writes it. \
         Waiting for the main window's exit emit loses the flag to a force-kill \
         and greets the user with the wizard again."
    );
}

#[test]
fn every_preference_write_is_either_buffered_or_emitted() {
    let buffered = buffered_keys();
    let mut offences = Vec::new();

    for path in qml_files() {
        let text = read(&path);
        for (at, _) in text.match_indices("updatePrefs(") {
            // `commitPrefs(` also ends in `updatePrefs(`-like text only by
            // coincidence; match the call name exactly.
            let head = text[..at].chars().last().unwrap_or(' ');
            if head.is_alphanumeric() || head == '_' {
                continue; // part of `commitPrefs(` / a longer identifier
            }
            let keys = patch_keys(&text, at);
            if keys.is_empty() {
                continue;
            }
            // A patch carrying ANY buffered key arms the snapshot, so Apply or
            // Cancel emits and the whole patch lands with it.
            if keys.iter().any(|k| buffered.contains(k)) {
                continue;
            }
            if keys.iter().all(|k| k == FLUSHED_BY_WIZARD_CLOSE) {
                continue;
            }
            let line = text[..at].lines().count();
            let window: String = text[at..].lines().take(14).collect::<Vec<_>>().join("\n");
            if window.contains("emitPrefs()") {
                continue;
            }
            offences.push(format!(
                "{}:{line}: {} — neither buffered nor emitted",
                path.display(),
                keys.join(", ")
            ));
        }
    }

    assert!(
        offences.is_empty(),
        "preference writes that never reach the disk:\n{}\n\nFix by calling \
         `commitPrefs(...)` (write + persist, without arming the global \
         Apply/Cancel buffer) or by adding the key to `_bufferedPrefKeys`.",
        offences.join("\n")
    );
}
