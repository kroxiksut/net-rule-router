//! A text-bearing child of a `ColumnLayout` without `Layout.fillWidth` is laid
//! out at a FIXED width equal to its unwrapped text (Qt Quick Layouts). Inside a
//! dialog that one long radio-button caption becomes the column's minimum
//! width: every wrapping label then wraps at that width instead of the
//! dialog's, and the text runs past the dialog's right edge with the window
//! showing through (the full-reset dialog at a large text scale). Every such
//! child of a dialog's column must take the column's width and wrap inside it.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

/// Controls whose caption is text the user reads, and so can be long.
const TEXT_KINDS: [&str; 5] = [
    "Label",
    "Text",
    "CheckBox",
    "RadioButton",
    "ThemedRadioButton",
];
/// Wrappers that already wrap their caption themselves.
const SELF_WRAPPING: [&str; 1] = ["ThemedRadioButton"];

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
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

/// The type an object opens with: `Type {` or `name: Type {`.
fn opened_type(before: &str) -> Option<String> {
    let text = before.trim();
    let text = text.rsplit(':').next().unwrap_or(text).trim();
    let first = text.chars().next()?;
    (first.is_ascii_uppercase()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'))
    .then(|| text.to_string())
}

struct Node {
    kind: Option<String>,
    parent: Option<usize>,
    line: usize,
    /// The object's own text: its property lines, not its children's, with
    /// strings and comments removed.
    own: String,
}

fn parse(source: &str) -> Vec<Node> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut in_block_comment = false;
    for (index, line) in source.lines().enumerate() {
        let chars: Vec<char> = line.chars().collect();
        let mut quote: Option<char> = None;
        let mut segment_start = 0;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if in_block_comment {
                if c == '*' && next == Some('/') {
                    i += 1;
                    in_block_comment = false;
                    segment_start = i + 1;
                }
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
                i += 1;
                continue;
            }
            match c {
                '"' | '\'' | '`' => quote = Some(c),
                '/' if next == Some('/') => break,
                '/' if next == Some('*') => {
                    in_block_comment = true;
                    i += 1;
                }
                '{' => {
                    let before: String = chars[segment_start.min(i)..i].iter().collect();
                    nodes.push(Node {
                        kind: opened_type(&before),
                        parent: stack.last().copied(),
                        line: index + 1,
                        own: String::new(),
                    });
                    stack.push(nodes.len() - 1);
                    segment_start = i + 1;
                    i += 1;
                    continue;
                }
                '}' => {
                    stack.pop();
                    segment_start = i + 1;
                    i += 1;
                    continue;
                }
                ';' => segment_start = i + 1,
                _ => {}
            }
            if let Some(&top) = stack.last() {
                nodes[top].own.push(c);
            }
            i += 1;
        }
        if let Some(&top) = stack.last() {
            nodes[top].own.push('\n');
        }
    }
    nodes
}

fn kind(nodes: &[Node], at: usize) -> &str {
    nodes[at].kind.as_deref().unwrap_or("")
}

fn inside_dialog(nodes: &[Node], at: usize) -> bool {
    let mut cursor = nodes[at].parent;
    while let Some(p) = cursor {
        if kind(nodes, p) == "Dialog" {
            return true;
        }
        cursor = nodes[p].parent;
    }
    false
}

fn subtree_mentions(nodes: &[Node], at: usize, needle: &str) -> bool {
    if nodes[at].own.contains(needle) {
        return true;
    }
    (0..nodes.len())
        .any(|child| nodes[child].parent == Some(at) && subtree_mentions(nodes, child, needle))
}

/// Lines of dialog text that can push past the dialog's width.
fn overflowing_text(source: &str) -> Vec<usize> {
    let nodes = parse(source);
    let mut found = Vec::new();
    for at in 0..nodes.len() {
        let own_kind = kind(&nodes, at);
        if !TEXT_KINDS.contains(&own_kind) {
            continue;
        }
        let Some(parent) = nodes[at].parent else {
            continue;
        };
        if kind(&nodes, parent) != "ColumnLayout" || !inside_dialog(&nodes, at) {
            continue;
        }
        let own = &nodes[at].own;
        let bound = own.contains("Layout.fillWidth: true") || own.contains("Layout.maximumWidth");
        let wraps = SELF_WRAPPING.contains(&own_kind)
            || own.contains("elide")
            || subtree_mentions(&nodes, at, "wrapMode");
        if !(bound && wraps) {
            found.push(nodes[at].line);
        }
    }
    found
}

#[test]
fn dialog_text_wraps_inside_the_dialog_width() {
    let root = qml_root();
    let mut files = Vec::new();
    qml_files(&root, &mut files);
    assert!(files.len() > 20, "the QML tree was found");
    let mut offences = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .expect("read qml")
            .replace("\r\n", "\n");
        let relative = file
            .strip_prefix(&root)
            .expect("under the qml root")
            .to_string_lossy()
            .replace('\\', "/");
        let lines = overflowing_text(&text);
        if !lines.is_empty() {
            offences.push(format!(
                "{relative}: dialog text not held to the dialog width at line(s) {lines:?} \
                 (Layout.fillWidth: true and a wrapping caption)"
            ));
        }
    }
    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// Positive control: the shape of the broken full-reset dialog is caught, and
/// the fixed shape is not.
#[test]
fn the_scanner_finds_an_unbound_dialog_caption() {
    let broken = "Dialog {\n    contentItem: ColumnLayout {\n        ThemedRadioButton {\n            text: \"long\"\n        }\n        CheckBox {\n            Layout.fillWidth: true\n            text: \"long\"\n        }\n    }\n}\n";
    assert_eq!(overflowing_text(broken), vec![3, 6]);

    let fixed = "Dialog {\n    contentItem: ColumnLayout {\n        ThemedRadioButton {\n            Layout.fillWidth: true\n        }\n        CheckBox {\n            id: c\n            Layout.fillWidth: true\n            contentItem: Label {\n                wrapMode: Text.WordWrap\n            }\n        }\n        Label { Layout.fillWidth: true; wrapMode: Text.Wrap }\n    }\n}\n";
    assert!(
        overflowing_text(fixed).is_empty(),
        "{:?}",
        overflowing_text(fixed)
    );

    let not_a_dialog = "Item {\n    ColumnLayout {\n        Label {\n            text: \"x\"\n        }\n    }\n}\n";
    assert!(overflowing_text(not_a_dialog).is_empty());
}
