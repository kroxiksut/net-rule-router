#![allow(clippy::expect_used)]

//! Every regular expression the Windows packaging script hands to `-match`
//! uses only escapes .NET knows. A `\Q` in one of them (a `\\` that lost a
//! backslash) is a parse error that stops the packaging, and the gate never
//! runs the packaging: only a release build would have found it.

use std::path::Path;

/// A single-quoted PowerShell literal that follows `-match` or `-notmatch`,
/// with `''` unescaped.
fn match_literals(script: &str) -> Vec<String> {
    let mut found = Vec::new();
    for op in ["-match '", "-notmatch '"] {
        let mut rest = script;
        while let Some(at) = rest.find(op) {
            let body = &rest[at + op.len()..];
            let mut literal = String::new();
            let mut chars = body.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                        literal.push('\'');
                        continue;
                    }
                    break;
                }
                literal.push(c);
            }
            found.push(literal);
            rest = body;
        }
    }
    found
}

/// Escapes .NET regular expressions accept: metacharacters, the character
/// classes the scripts use, and anchors.
fn escape_is_known(c: char) -> bool {
    r#"\.^$|()[]{}*+?-/:,'" "#.contains(c) || "dDwWsSbBAzZnrt".contains(c)
}

fn bad_escapes(pattern: &str) -> Vec<String> {
    let mut bad = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            continue;
        }
        match chars.next() {
            Some(next) if escape_is_known(next) => {}
            Some(next) => bad.push(format!("\\{next}")),
            None => bad.push("\\ at the end".to_owned()),
        }
    }
    bad
}

#[test]
fn every_match_pattern_in_the_windows_packaging_script_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/package-windows.ps1");
    let script = std::fs::read_to_string(&path).expect("the packaging script");
    let literals = match_literals(&script);
    assert!(
        literals.len() >= 2,
        "the Qt root and the Qt version patterns were expected"
    );
    let broken: Vec<String> = literals
        .iter()
        .filter_map(|pattern| {
            let bad = bad_escapes(pattern);
            (!bad.is_empty()).then(|| format!("'{pattern}': {}", bad.join(", ")))
        })
        .collect();
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

#[test]
fn a_backslash_that_lost_its_twin_is_refused() {
    assert_eq!(
        bad_escapes(r"^(?<root>.*\Qt)\(?<version>\d+\.\d+\.\d+)\"),
        vec!["\\Q".to_owned(), "\\ at the end".to_owned()]
    );
    assert!(bad_escapes(r"^(?<root>.*\\Qt)\\(?<version>\d+\.\d+\.\d+)\\").is_empty());
}

#[test]
fn a_literal_keeps_its_doubled_quotes() {
    assert_eq!(
        match_literals("if ($x -match 'it''s\\d') { }"),
        vec!["it's\\d".to_owned()]
    );
}
