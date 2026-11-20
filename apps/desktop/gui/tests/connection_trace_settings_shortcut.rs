use std::path::PathBuf;

fn repo_file(relative: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root");
    std::fs::read_to_string(root.join(relative)).expect("read QML source")
}

#[test]
fn disabled_connection_trace_offers_the_logs_and_diagnostics_settings() {
    for file in [
        "apps/desktop/qml/sections/ConnTraceSection.qml",
        "apps/desktop/qml/sections/OutageBlocksSection.qml",
    ] {
        let qml = repo_file(file);
        assert!(
            qml.contains("action.open-logs-diagnostics-settings"),
            "{file} must offer a visible route out of the disabled trace state"
        );
        assert!(
            qml.contains("root.openSettingsCategory(\"diagnostics\")"),
            "{file} must take that action to the Logs and diagnostics settings"
        );
    }
}

#[test]
fn resetting_diagnostics_restores_the_default_connection_trace_visibility() {
    let qml = repo_file("apps/desktop/qml/sections/settings/DiagnosticsLogsSettings.qml");
    let reset = qml
        .split("function _resetStabilityToDefaults()")
        .nth(1)
        .and_then(|after| after.split("function _stabilitySaveErrorText()").next())
        .expect("diagnostics reset function");
    assert!(
        reset.contains("_stabilityDraftConnTraceGui = true"),
        "Reset must restore the contract default instead of hiding the connection trace"
    );
}

#[test]
fn connection_trace_copy_uses_the_actual_settings_section_name() {
    for file in [
        "apps/desktop/qml/sections/ConnTraceSection.qml",
        "apps/desktop/qml/sections/OutageBlocksSection.qml",
        "apps/tui/src/screens/inspect/keys.rs",
    ] {
        let source = repo_file(file);
        assert!(
            !source.contains("Settings → Diagnostics and logs"),
            "{file} must name the Logs and diagnostics section exactly"
        );
    }
}
