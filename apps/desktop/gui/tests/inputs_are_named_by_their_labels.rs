//! A screen reader on any input says which field it is on. The wrappers fall
//! back to the value ("Dark") or the placeholder, often an example ("hostname
//! or IP"), so every input names itself from the label beside it.

use std::path::{Path, PathBuf};

const WRAPPERS: [&str; 4] = [
    "ThemedComboBox",
    "ThemedSpinBox",
    "ThemedTextField",
    "ThemedTextArea",
];

/// Named by their own `text`, when they have one.
const TOGGLES: [&str; 3] = ["CheckBox", "Switch", "RadioButton"];

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

/// Braces that open (+1) or close (-1) objects on this line, outside strings
/// and comments.
fn brace_delta(line: &str) -> i32 {
    let mut delta = 0;
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == '\\' {
                    chars.next();
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' | '`' => quote = Some(c),
                '/' if chars.peek() == Some(&'/') => break,
                '{' => delta += 1,
                '}' => delta -= 1,
                _ => {}
            },
        }
    }
    delta
}

/// The object type a component file declares, when it is an input wrapper:
/// its instances are inputs too.
fn root_type(source: &str) -> Option<&str> {
    source
        .lines()
        .find(|line| line.ends_with('{') && !line.starts_with(char::is_whitespace))
        .map(|line| line.trim_end_matches('{').trim())
}

/// A name that is only the value again. A placeholder named on purpose is the
/// author's word that it describes the field, not an example.
fn names_only_the_value(expr: &str) -> bool {
    let last = expr.trim().rsplit('.').next().unwrap_or("");
    !expr.contains('(') && matches!(last, "displayText" | "value")
}

#[test]
fn every_input_is_named_by_its_label() {
    let mut files = Vec::new();
    qml_files(&qml_root(), &mut files);
    let sources: Vec<(PathBuf, String)> = files
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
                .replace("\r\n", "\n");
            (path, text)
        })
        .collect();

    let mut inputs: Vec<String> = WRAPPERS.iter().map(|s| (*s).to_owned()).collect();
    for (path, text) in &sources {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if !WRAPPERS.contains(&stem) && root_type(text).is_some_and(|t| WRAPPERS.contains(&t)) {
            inputs.push(stem.to_owned());
        }
    }
    assert!(
        inputs.len() > WRAPPERS.len(),
        "the duration picker wraps a combo box"
    );

    let mut unnamed = Vec::new();
    let mut seen = 0;
    for (path, text) in &sources {
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            // An unindented object is a component's own root: its caller names it.
            if !line.starts_with(char::is_whitespace) {
                continue;
            }
            let head = line.trim();
            let Some(kind) = head.strip_suffix('{').map(str::trim) else {
                continue;
            };
            let toggle = TOGGLES.contains(&kind);
            if !toggle && !inputs.iter().any(|i| i == kind) {
                continue;
            }
            seen += 1;
            let mut depth = brace_delta(line);
            let mut name = None;
            let props: &[&str] = if toggle {
                &["text:", "Accessible.name:"]
            } else {
                &["accessibleLabel:", "Accessible.name:"]
            };
            for body in &lines[at + 1..] {
                let trimmed = body.trim_start();
                if depth == 1 {
                    for prop in props {
                        if let Some(expr) = trimmed.strip_prefix(prop) {
                            name = Some(expr.to_owned());
                        }
                    }
                }
                depth += brace_delta(body);
                if depth <= 0 {
                    break;
                }
            }
            let place = format!(
                "{}:{} {kind}",
                path.strip_prefix(qml_root()).unwrap_or(path).display(),
                at + 1
            );
            match name {
                None => unnamed.push(format!("{place}: no name")),
                // A toggle's `text` is its label, not its value.
                Some(expr) if !toggle && names_only_the_value(&expr) => {
                    unnamed.push(format!("{place}: named by its value `{}`", expr.trim()));
                }
                Some(_) => {}
            }
        }
    }
    assert!(seen > 50, "found only {seen} inputs; the scan lost them");
    assert!(
        unnamed.is_empty(),
        "inputs a screen reader cannot tell apart (name them by the visible label):\n{}",
        unnamed.join("\n")
    );
}
