#![allow(clippy::expect_used)]

//! The review of a Russian user's change listed `chrome.exe (app)` and would
//! list `(primary → secondary)`: the service spells its markers in English, and
//! the window showed them as they came. Runs `pure.js` with the Russian words.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

fn russian_tr() -> String {
    let ru = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../locales/ru.json"),
    )
    .expect("ru.json");
    format!(
        "var __ru = {ru};\n\
         function tr(key, fallback) {{\n\
             var at = __ru;\n\
             var parts = key.split('.');\n\
             for (var i = 0; i < parts.length && at !== undefined; i += 1) at = at[parts[i]];\n\
             return typeof at === 'string' ? at : fallback\n\
         }}\n\
         function routeLabel(slug) {{ return tr('label.' + slug, slug) }}\n"
    )
}

#[test]
fn a_review_row_says_the_service_markers_in_the_window_language() {
    let output = js::run_js(&format!(
        "{}\n{}\n\
         console.log(reviewEntryText('chrome.exe (app) (primary → secondary)', tr, routeLabel));\n\
         console.log(reviewEntryText('(no match — invalid rule)', tr, routeLabel));\n\
         console.log(reviewEntryText('example.com', tr, routeLabel));",
        qml_functions::pure(),
        russian_tr()
    ));
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].starts_with("chrome.exe"), "{output}");
    for english in ["(app)", "primary", "secondary"] {
        assert!(
            !lines[0].contains(english),
            "{english} left in English:\n{output}"
        );
    }
    assert!(!lines[1].contains("invalid rule"), "{output}");
    assert_eq!(lines[2], "example.com");
}

#[test]
fn the_review_columns_show_rows_through_it() {
    let column = qml_functions::read("components/ReviewDiffColumn.qml");
    assert!(
        column.contains("Pure.reviewEntryText(display, root.ownerRoot.tr"),
        "the review column shows the service's display as it came"
    );
}
