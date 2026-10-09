//! A folder the user makes their own becomes the home of the rules on screen:
//! picking it in Settings or accepting the "keep your sets here?" offer saves
//! the set there. Pointing at the sets shipped with the app does not — that
//! folder is replaced by the next update. The save never overwrites a set of
//! the same name and leaves the previously linked files alone.
#![allow(clippy::expect_used)]

use std::path::Path;

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let head = format!("function {name}(");
    let at = source
        .find(&head)
        .unwrap_or_else(|| panic!("no function {name}"));
    let rest = &source[at + head.len()..];
    let end = rest.find("\n    function ").unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn a_chosen_or_accepted_folder_takes_the_set_on_screen() {
    let settings = qml("sections/settings/PresetSettings.qml");
    assert!(settings.contains("root.boundFilesController.adoptRulesFolder(folder)"));
    let main = qml("Main.qml");
    assert!(function_body(&main, "acceptRulesFolderSuggestion")
        .contains("boundFilesController.adoptRulesFolder(folder)"));
}

#[test]
fn the_shipped_sets_folder_is_not_adopted() {
    let settings = qml("sections/settings/PresetSettings.qml");
    assert!(!function_body(&settings, "_useBundledPresetsPath").contains("adoptRulesFolder"));
}

#[test]
fn the_adopting_save_keeps_what_is_there() {
    let controller = qml("flows/BoundFilesController.qml");
    let adopt = function_body(&controller, "adoptRulesFolder");
    assert!(
        adopt.contains("Pure.rulesLiveInFolder(root.prefs, dir)) return"),
        "a set already in the folder stays where it is"
    );
    assert!(
        adopt.contains("Pure.numberedSetName(")
            && adopt.contains("_ruleSetDirHasFiles(dir + \"/\" + candidate)"),
        "a taken name gets a number instead of being overwritten"
    );
    assert!(
        !adopt.contains("guardExistingSetDir"),
        "adopting never asks: it picks a free name"
    );
}
