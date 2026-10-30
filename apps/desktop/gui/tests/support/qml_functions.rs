//! A QML file's `function`s as written, for a test that runs them in the
//! embedded engine against a stand-in for what they read.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

/// A file under `apps/desktop/qml`, line endings normalised.
pub fn read(relative: &str) -> String {
    let path = qml_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// `pure.js` as plain JavaScript, its functions reachable as `Pure.*`.
pub fn pure() -> String {
    let body: String = read("lib/pure.js")
        .lines()
        .filter(|line| !line.trim_start().starts_with('.'))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{body}\nvar Pure = globalThis;\n")
}

/// `function <name>(…) { … }` as written, braces matched outside strings and
/// comments.
pub fn function_source(source: &str, name: &str) -> String {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("function {name} is gone"));
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if c == b'"' || c == b'\'' {
            quote = Some(c);
        } else if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return source[start..=i].to_owned();
            }
        }
        i += 1;
    }
    panic!("function {name} never closes");
}

/// The named functions of `file`, one after another.
pub fn functions(file: &str, names: &[&str]) -> String {
    let source = read(file);
    names
        .iter()
        .map(|name| function_source(&source, name))
        .collect::<Vec<_>>()
        .join("\n")
}
