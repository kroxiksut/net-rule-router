#![allow(clippy::expect_used)]

//! File → "Export settings…" (Ctrl+Alt+S) only opened the Settings screen and
//! exported nothing; the user had to find the export button there. The menu
//! item and its shortcut ask where to save and write the export, through the
//! same funnel as the Settings button.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

#[test]
fn the_menu_item_and_its_shortcut_export() {
    let main = qml_functions::read("Main.qml");
    let item = main
        .lines()
        .find(|l| l.contains("labelText: tr(\"action.export-settings\""))
        .expect("the File menu item");
    assert!(
        item.contains("onTriggered: settingsExportController.chooseAndExport()"),
        "the menu item does not export: {item}"
    );
    assert!(
        main.contains(
            "Shortcut { sequence: \"Ctrl+Alt+S\"; context: Qt.ApplicationShortcut; onActivated: settingsExportController.chooseAndExport() }"
        ),
        "Ctrl+Alt+S is shown in the menu and does nothing"
    );
    let settings = qml_functions::read("sections/settings/PresetSettings.qml");
    assert!(
        settings.contains("root.settingsExportController.chooseAndExport()"),
        "the Settings button exports some other way than the menu"
    );
}

#[test]
fn a_chosen_file_receives_the_export() {
    let output = js::run_js(&format!(
        "var root = {{\n\
             tr: function(key, fallback) {{ return fallback }},\n\
             statusLine: '',\n\
             prefs: {{ lastSavedPathPrimary: 'C:/r/rules_primary.txt' }},\n\
             boundFilesController: {{ writer: {{ readPassthroughSections: function(route, done) {{ done({{}}) }} }} }},\n\
             rpc: {{ registerRpcCallback: function(corr, done) {{ done(true, {{ 'yaml-bytes-b64': 'eWFtbA==' }}) }} }}\n\
         }};\n\
         var nrrNativeBridge = {{\n\
             rpcSettingsExportFull: function(p, s) {{ console.log('export asked, primary file ' + p); return 'c' }},\n\
             writeFileBytes: function(path, b64) {{ console.log('wrote ' + b64 + ' to ' + path); return true }}\n\
         }};\n\
         {}\n\
         exportTo('C:/backup/nrr.yaml');\n\
         console.log(root.statusLine);",
        qml_functions::functions("flows/SettingsExportController.qml", &["exportTo", "_request"])
    ));
    assert_eq!(
        output,
        "export asked, primary file C:/r/rules_primary.txt\nwrote eWFtbA== to C:/backup/nrr.yaml\nFull settings exported.\n"
    );
}
