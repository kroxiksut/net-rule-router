//! The rule dialog reads its host through `root.<name>`, and two windows host
//! it: the main window and the tray's add-rule window. A name the tray window
//! does not declare is `undefined` there, which QML reports only as a runtime
//! TypeError while the form quietly stops working. This test reads every
//! `root.` name the dialog uses and holds the tray window to declaring it.

use std::collections::BTreeSet;
use std::path::Path;

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `source` with comments removed and string literals blanked, so neither a
/// commented-out `root.x` nor one inside a text counts.
fn code_only(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            out.push(c);
            i += 1;
            while i < chars.len() && chars[i] != c {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push(c);
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn ident_at(chars: &[char], start: usize) -> String {
    chars[start..]
        .iter()
        .take_while(|c| is_ident_char(**c))
        .collect()
}

/// Every `<name>` in `root.<name>`, where `root` is a whole identifier and not
/// a member of something else (`group.root.x` is another object's root).
fn root_names(source: &str) -> BTreeSet<String> {
    let chars: Vec<char> = code_only(source).chars().collect();
    let mut names = BTreeSet::new();
    let needle = ['r', 'o', 'o', 't', '.'];
    for (i, window) in chars.windows(needle.len()).enumerate() {
        if window != needle.as_slice() {
            continue;
        }
        if i > 0 && (is_ident_char(chars[i - 1]) || chars[i - 1] == '.') {
            continue;
        }
        let name = ident_at(&chars, i + needle.len());
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names
}

/// The word after `keyword` wherever `keyword` stands alone.
fn words_after(chars: &[char], keyword: &str) -> Vec<String> {
    let key: Vec<char> = keyword.chars().collect();
    let mut out = Vec::new();
    for (i, window) in chars.windows(key.len()).enumerate() {
        if window != key.as_slice() || (i > 0 && is_ident_char(chars[i - 1])) {
            continue;
        }
        let mut j = i + key.len();
        if chars.get(j).is_some_and(|c| is_ident_char(*c)) {
            continue;
        }
        while chars.get(j).is_some_and(|c| c.is_whitespace()) {
            j += 1;
        }
        let word = ident_at(chars, j);
        if !word.is_empty() {
            out.push(word);
        }
    }
    out
}

/// Names a QML file declares: properties (any type, aliases included),
/// functions, signals and ids.
fn declared_names(source: &str) -> BTreeSet<String> {
    let chars: Vec<char> = code_only(source).chars().collect();
    let mut names = BTreeSet::new();
    // `property <type> <name>`: skip the type, keep the name.
    let key: Vec<char> = "property".chars().collect();
    for (i, window) in chars.windows(key.len()).enumerate() {
        if window != key.as_slice() || (i > 0 && is_ident_char(chars[i - 1])) {
            continue;
        }
        let mut j = i + key.len();
        if !chars.get(j).is_some_and(|c| c.is_whitespace()) {
            continue;
        }
        while chars.get(j).is_some_and(|c| c.is_whitespace()) {
            j += 1;
        }
        while chars
            .get(j)
            .is_some_and(|c| is_ident_char(*c) || matches!(*c, '.' | '<' | '>'))
        {
            j += 1;
        }
        while chars.get(j).is_some_and(|c| c.is_whitespace()) {
            j += 1;
        }
        let name = ident_at(&chars, j);
        if !name.is_empty() {
            names.insert(name);
        }
    }
    for keyword in ["function", "signal"] {
        names.extend(words_after(&chars, keyword));
    }
    let id_key: Vec<char> = "id:".chars().collect();
    for (i, window) in chars.windows(id_key.len()).enumerate() {
        if window != id_key.as_slice() || (i > 0 && is_ident_char(chars[i - 1])) {
            continue;
        }
        let mut j = i + id_key.len();
        while chars.get(j).is_some_and(|c| c.is_whitespace()) {
            j += 1;
        }
        let name = ident_at(&chars, j);
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names
}

/// What every QML `Window` already has.
const WINDOW_BUILT_INS: [&str; 9] = [
    "width", "height", "x", "y", "palette", "font", "title", "color", "visible",
];

#[test]
fn the_tray_window_declares_every_name_the_rule_dialog_reads() {
    let wanted = root_names(&qml("components/RuleEditDialog.qml"));
    assert!(
        wanted.contains("saveRule") && wanted.contains("uiTheme"),
        "the scan no longer sees the dialog's `root.` names: {wanted:?}"
    );
    let declared = declared_names(&qml("components/TrayRuleWindow.qml"));
    let missing: Vec<&str> = wanted
        .iter()
        .map(String::as_str)
        .filter(|name| !declared.contains(*name) && !WINDOW_BUILT_INS.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "components/TrayRuleWindow.qml hosts RuleEditDialog but does not declare: {}",
        missing.join(", ")
    );
}

#[test]
fn the_scan_skips_comments_strings_and_other_roots() {
    let source = "// root.commented\n/* root.blocked */\nx: root.used + \"root.quoted\"\ny: group.root.other\nz: myroot.notRoot\n";
    let names = root_names(source);
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        vec!["used".to_string()]
    );
}

#[test]
fn the_scan_sees_each_kind_of_declaration() {
    let source = "Window {\n    id: host\n    property var a: null\n    readonly property int b: 0\n    required property var c\n    property alias d: inner.d\n    function e(x) {}\n    signal f()\n    // property var commented\n}\n";
    let declared = declared_names(source);
    for name in ["host", "a", "b", "c", "d", "e", "f"] {
        assert!(declared.contains(name), "`{name}` not seen in {declared:?}");
    }
    assert!(!declared.contains("commented"));
}
