//! A keyboard user closes what a mouse user closes, and a banner says its
//! whole sentence at any font size: a close button shows where focus is and
//! stays reachable by Tab, the two first-start windows close on Escape, and
//! no banner cuts its message off with an ellipsis.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

fn qml_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn qml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("list qml dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            qml_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("qml") {
            out.push(path);
        }
    }
}

/// The text of the object opened by the `{` on `line`, braces balanced.
fn block_from(lines: &[&str], line: usize) -> String {
    let mut depth = 0usize;
    let mut out = String::new();
    for text in &lines[line..] {
        out.push_str(text);
        out.push('\n');
        depth += text.matches('{').count();
        depth = depth.saturating_sub(text.matches('}').count());
        if depth == 0 {
            break;
        }
    }
    out
}

/// Every hand-drawn `ToolButton` that closes something with a glyph.
fn glyph_close_buttons(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "ToolButton {" {
            let block = block_from(&lines, index);
            if block.contains("text: \"✕\"") {
                found.push((index + 1, block));
            }
        }
    }
    found
}

/// Problems a keyboard user meets at a glyph close button.
fn close_button_faults(block: &str) -> Vec<&'static str> {
    let mut faults = Vec::new();
    if !block.contains(".visualFocus") {
        faults.push("draws nothing when it takes keyboard focus");
    }
    let hides_off_hover = block.lines().any(|l| {
        let l = l.trim();
        l.starts_with("visible:") && l.contains("containsMouse")
    });
    if hides_off_hover {
        faults.push("is invisible, so Tab skips it, until the mouse hovers");
    }
    faults
}

#[test]
fn every_glyph_close_button_shows_focus_and_stays_in_the_tab_order() {
    let mut files = Vec::new();
    qml_files(&qml_dir(), &mut files);
    let mut seen = 0;
    let mut faults = Vec::new();
    for file in files {
        for (line, block) in glyph_close_buttons(&read(&file)) {
            seen += 1;
            for fault in close_button_faults(&block) {
                faults.push(format!("{}:{line}: {fault}", file.display()));
            }
        }
    }
    assert!(
        seen >= 5,
        "the banner and toast close buttons were not found"
    );
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

#[test]
fn a_close_button_without_a_focus_frame_or_shown_on_hover_only_is_caught() {
    let hover_only =
        "ToolButton {\n    visible: failed || hoverArea.containsMouse\n    text: \"✕\"\n}\n";
    assert_eq!(close_button_faults(hover_only).len(), 2);
}

/// Escape is how a keyboard user says "not now" to a window that asks.
#[test]
fn the_first_start_windows_close_on_escape() {
    for name in ["AppGroupRoutingDialog.qml", "VpnOnboardingDialog.qml"] {
        let source = read(&qml_dir().join("components").join(name));
        let lines: Vec<&str> = source.lines().collect();
        let closes = lines.iter().enumerate().any(|(index, line)| {
            line.trim() == "Shortcut {" && {
                let block = block_from(&lines, index);
                block.contains("\"Esc\"") && block.contains("root.close()")
            }
        });
        assert!(closes, "{name}: Escape does not close the window");
    }
}

/// A banner cut to "…" hides the very instruction it exists for once the
/// text is long (Russian), the window narrow or the font enlarged.
#[test]
fn no_banner_cuts_its_message_off() {
    let source = read(&qml_dir().join("components/TopBannerStack.qml"));
    let cut: Vec<String> = source
        .lines()
        .enumerate()
        .filter(|(_, l)| l.trim() == "elide: Text.ElideRight")
        .map(|(i, _)| format!("TopBannerStack.qml:{}", i + 1))
        .collect();
    assert!(cut.is_empty(), "banner text elided at {cut:?}");
    let fixed: Vec<String> = source
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            let l = l.trim();
            l.starts_with("height: root.") && l.ends_with("BannerHeight")
        })
        .map(|(i, _)| format!("TopBannerStack.qml:{}", i + 1))
        .collect();
    assert!(
        fixed.is_empty(),
        "banner height does not grow with wrapped text at {fixed:?}"
    );
}
