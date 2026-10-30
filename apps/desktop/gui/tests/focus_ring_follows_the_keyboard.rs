#![allow(clippy::expect_used)]

//! A click on a sidebar entry left a focus ring around it until something else
//! took focus, so the screen showed two selected entries. The ring is for the
//! keyboard: it shows when focus arrives by Tab or a shortcut, and after a
//! click only for a user who asked for focus to show always.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

const SIDEBAR: [&str; 3] = [
    "components/SidebarSubNavButton.qml",
    "components/SidebarGlyphButton.qml",
    "components/NavigationSidebar.qml",
];

/// The `focusShown` expression of `source`, as written.
fn focus_shown(source: &str) -> String {
    let start = source
        .find("readonly property bool focusShown:")
        .expect("the entry says when its ring shows")
        + "readonly property bool focusShown:".len();
    let mut expr = String::new();
    for (i, line) in source[start..].lines().enumerate() {
        let line = line.trim();
        if i > 0 && !line.starts_with("||") && !line.starts_with("&&") {
            break;
        }
        expr.push(' ');
        expr.push_str(line);
    }
    expr
}

#[test]
fn a_click_draws_no_ring_and_the_keyboard_does() {
    for file in SIDEBAR {
        let expr = focus_shown(&qml_functions::read(file));
        let output = js::run_js(&format!(
            "function shown(visualFocus, activeFocus, enhanced) {{\n\
                 var shell = {{ prefs: {{ enhancedFocus: enhanced }} }}, root = shell;\n\
                 return {expr};\n\
             }}\n\
             console.log(shown(false, true, false), shown(true, true, false), shown(false, true, true));"
        ));
        assert_eq!(
            output, "false true true\n",
            "{file}: click / Tab / click with focus always shown"
        );
    }
}

#[test]
fn the_ring_is_drawn_from_that_rule() {
    for file in SIDEBAR {
        let source = qml_functions::read(file);
        let mut ringed = 0;
        for (at, _) in source.match_indices("background: PanelSurface {") {
            // The background object, braces balanced.
            let mut depth = 0usize;
            let mut end = at;
            for (i, c) in source[at..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = at + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let background = &source[at..end];
            assert!(
                !background.contains("activeFocus"),
                "{file}: the ring still follows any focus, a click's included"
            );
            if background.contains("focusShown") {
                ringed += 1;
            }
        }
        assert!(ringed > 0, "{file}: no background draws the ring");
    }
}
