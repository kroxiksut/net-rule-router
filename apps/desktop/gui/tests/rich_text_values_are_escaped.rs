//! A name learned from DNS or reported by the service may carry `<` or `&`.
//! Placed into a StyledText notice unescaped, it styles or spoofs the text
//! around it; shown in an AutoText label, a leading tag turns the whole cell
//! into rich text. Every value bolded into a notice goes through
//! `Pure.escapeMarkup`, and the trace's name cell is plain text.
#![allow(clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
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

/// Values that are ours and cannot carry markup.
const TRUSTED_BOLD_VALUES: [&str; 1] = ["String(count)"];

/// The expression after each `"<b>" + ` that is not an escape call or a
/// trusted value, by 1-based line.
fn unescaped_bold_values(source: &str) -> Vec<(usize, String)> {
    let marker = "\"<b>\" + ";
    let mut found = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let mut rest = line;
        while let Some(at) = rest.find(marker) {
            let value = &rest[at + marker.len()..];
            let escaped = value.starts_with("_escapeMarkup(")
                || value.starts_with("Pure.escapeMarkup(")
                || value.starts_with("tray._escapeMarkup(");
            let trusted = TRUSTED_BOLD_VALUES.iter().any(|t| value.starts_with(t));
            if !escaped && !trusted {
                let end = value.find(" + \"</b>\"").unwrap_or(value.len());
                found.push((index + 1, value[..end].to_string()));
            }
            rest = value;
        }
    }
    found
}

#[test]
fn every_value_bolded_into_a_notice_is_escaped() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml");
    let mut files = Vec::new();
    qml_files(&root, &mut files);
    assert!(files.len() > 20, "the QML tree was found");
    let mut offences = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read qml");
        for (line, value) in unescaped_bold_values(&text) {
            offences.push(format!("{}:{line}: unescaped `{value}`", file.display()));
        }
    }
    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// Positive control: the shape that shipped is caught; escaped and trusted
/// values are not.
#[test]
fn the_scanner_finds_an_unescaped_value_and_only_that() {
    let broken = ".replace(\"{host}\", \"<b>\" + host + \"</b>\")\n";
    assert_eq!(unescaped_bold_values(broken), vec![(1, "host".to_string())]);
    let fine = "{ host: \"<b>\" + Pure.escapeMarkup(host) + \"</b>\" }\n\
                .replace(\"{count}\", \"<b>\" + String(count) + \"</b>\")\n";
    assert!(unescaped_bold_values(fine).is_empty());
}

#[test]
fn the_trace_name_cell_is_plain_text() {
    let qml = repo_file("apps/desktop/qml/sections/ConnTraceSection.qml");
    let at = qml
        .find("id: connRemoteCell")
        .expect("the name cell exists");
    let cell = &qml[at..at + qml[at..].find("ToolTip.text").expect("cell has a tooltip")];
    assert!(
        cell.contains("textFormat: Text.PlainText"),
        "the trace's name cell must not interpret markup from a DNS answer"
    );
}

fn run_pure(expr: &str) -> Option<String> {
    let program = format!(
        "{source}\nconsole.log(JSON.stringify({expr}));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let mut child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let Some(stdin) = child.stdin.as_mut() else {
        panic!("stdin was piped")
    };
    stdin
        .write_all(program.as_bytes())
        .unwrap_or_else(|e| panic!("write the harness to node: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("node runs to completion: {e}"));
    assert!(
        out.status.success(),
        "node rejected the harness: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(serde_json::from_str::<String>(text.trim()).unwrap_or_else(|e| panic!("{e}: {text}")))
}

#[test]
fn escaping_round_trips_through_the_spoken_text() {
    let Some(escaped) = run_pure("escapeMarkup('<font size=7>a&b</font>')") else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(escaped, "&lt;font size=7&gt;a&amp;b&lt;/font&gt;");
    let spoken = run_pure("markupToPlain('<b>' + escapeMarkup('x<y>&amp;') + '</b>')")
        .expect("node was available a moment ago");
    assert_eq!(spoken, "x<y>&amp;");
}
