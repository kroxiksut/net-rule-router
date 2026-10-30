//! A child window declared in `Main.qml` exists from start-up even when it is
//! never shown, and its items and laid-out texts (the licence and the agreement
//! are whole documents) stay in memory for the whole session. The windows most
//! sessions never open build their content on the first show instead: the
//! window object, its id and every function callers use stay where they were,
//! only what it draws waits for a Loader.

use std::path::Path;

const LAZY_WINDOWS: &[(&str, &str, &str)] = &[
    ("components/AboutWindow.qml", "AboutWindow", "aboutWindow"),
    (
        "components/LicenseWindow.qml",
        "LicenseWindow",
        "licenseWindow",
    ),
    (
        "components/EulaAgreementWindow.qml",
        "EulaAgreementWindow",
        "eulaAgreementWindow",
    ),
];

/// Children the window may hold before its first show: none of them draws.
const ALLOWED_DIRECT_CHILDREN: &[&str] = &["Loader", "Component", "Connections"];

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// Brace depth at the start of every line, ignoring braces inside comments
/// and string literals.
fn depth_at_line_starts(text: &str) -> Vec<i32> {
    let mut depths = Vec::new();
    let mut depth = 0;
    let mut chars = text.chars().peekable();
    let mut at_line_start = true;
    let mut quote: Option<char> = None;
    let mut block_comment = false;
    while let Some(c) = chars.next() {
        if at_line_start {
            depths.push(depth);
            at_line_start = false;
        }
        if c == '\n' {
            at_line_start = true;
            continue;
        }
        if block_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                block_comment = false;
            }
            continue;
        }
        if let Some(q) = quote {
            if c == '\\' {
                chars.next();
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '/' if chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|&n| n != '\n') {
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                block_comment = true;
            }
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
    }
    depths
}

/// Type names of the objects declared directly inside the file's root object.
fn direct_children(text: &str) -> Vec<String> {
    let depths = depth_at_line_starts(text);
    text.lines()
        .zip(depths)
        .filter(|(_, depth)| *depth == 1)
        .filter_map(|(line, _)| {
            let trimmed = line.trim();
            let name: String = trimmed
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                .collect();
            let rest = trimmed[name.len()..].trim_start();
            (name.starts_with(|c: char| c.is_ascii_uppercase()) && rest.starts_with('{'))
                .then_some(name)
        })
        .collect()
}

#[test]
fn rarely_opened_windows_draw_nothing_before_their_first_show() {
    for (file, _, _) in LAZY_WINDOWS {
        let text = qml(file);
        let children = direct_children(&text);
        assert!(
            children.iter().any(|c| c == "Loader"),
            "{file}: the content is not behind a Loader (direct children: {children:?})"
        );
        let drawn: Vec<&String> = children
            .iter()
            .filter(|c| !ALLOWED_DIRECT_CHILDREN.contains(&c.as_str()))
            .collect();
        assert!(
            drawn.is_empty(),
            "{file}: built at start-up although the window is hidden: {drawn:?}"
        );
        assert!(
            text.contains("active:") && text.contains(".contentBuilt"),
            "{file}: the Loader does not wait for the first show"
        );
        assert!(
            text.contains("contentBuilt = true"),
            "{file}: nothing builds the content when the window is shown"
        );
    }
}

#[test]
fn callers_still_reach_each_window_by_its_id() {
    let main = qml("Main.qml");
    for (_, type_name, id) in LAZY_WINDOWS {
        let declared = main
            .match_indices(&format!("{type_name} {{"))
            .any(|(at, _)| {
                main[at..]
                    .lines()
                    .take(3)
                    .any(|l| l.contains(&format!("id: {id}")))
            });
        assert!(
            declared,
            "Main.qml no longer declares {type_name} as `{id}`"
        );
        assert!(
            main.contains(&format!("property alias {id}: {id}")),
            "Main.qml lost the `{id}` alias other files call through"
        );
    }
}

/// The acknowledgement tick lives on the window now, so `open()` can clear a
/// tick left from an earlier show even when the content was already built.
#[test]
fn agreement_accept_waits_for_a_fresh_tick() {
    let text = qml("components/EulaAgreementWindow.qml");
    let open = text
        .split("function open()")
        .nth(1)
        .and_then(|rest| rest.split('\n').next())
        .expect("EulaAgreementWindow has no open()");
    assert!(
        open.contains("acknowledged = false"),
        "open() does not clear the tick: {open}"
    );
    assert!(text.contains("checked: root.acknowledged"));
    assert!(text.contains("enabled: root.acknowledged"));
}

#[test]
fn the_scan_sees_a_drawn_child_and_skips_strings_and_comments() {
    let window = "Window {\n    id: w\n    // ColumnLayout {\n    property string s: \"{\"\n    ColumnLayout {\n        Label { text: \"}\" }\n    }\n    Loader {\n    }\n}\n";
    assert_eq!(direct_children(window), vec!["ColumnLayout", "Loader"]);
}
