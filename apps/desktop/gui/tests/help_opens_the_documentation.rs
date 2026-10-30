//! Help > Documentation opens the page the launcher found: the key the context
//! writes is the one the menu reads, and the menu goes through the door that
//! lets the own offline page through. A key renamed on one side leaves a menu
//! item that opens nothing.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_help_menu_opens_the_page_the_context_names() {
    let surface = read("src/ui_surface.rs");
    assert!(
        surface.contains("\"docsUrls\": docs_urls("),
        "the context names the documentation pages"
    );
    let main = read("../qml/Main.qml");
    let help = &main[main.find("tr(\"menu.help\"").expect("the Help menu")..];
    let item = help
        .lines()
        .find(|line| line.contains("action.open-documentation") && line.contains("onTriggered"))
        .expect("a Documentation item in the Help menu");
    assert!(
        item.contains("Pure.docsPageUrl((context.about || {}).docsUrls")
            && item.contains("resolveLanguageId(currentLanguage)")
            && item.contains(", true)"),
        "{item}"
    );
    for locale in ["../../../locales/en.json", "../../../locales/ru.json"] {
        assert!(read(locale).contains("\"open-documentation\""), "{locale}");
    }
}
