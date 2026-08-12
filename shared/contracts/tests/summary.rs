use nrr_shared::{
    format_about_summary, format_accessibility_baseline_summary, format_first_run_summary,
    format_interfaces_routes_summary, format_main_window_shell_summary, format_rules_summary,
    format_settings_summary, format_tooltip_policy_summary, format_ui_surface_contract_summary,
    gui_shell_v1,
};

#[test]
fn settings_and_about_summaries_include_expected_markers() {
    let shell = gui_shell_v1();
    let settings_summary = format_settings_summary(&shell);
    let about_summary = format_about_summary(&shell);
    let tooltip_summary = format_tooltip_policy_summary(&shell);
    let accessibility_summary = format_accessibility_baseline_summary(&shell);
    let surfaces_summary = format_ui_surface_contract_summary(&shell);
    let interfaces_summary = format_interfaces_routes_summary(&shell);
    let rules_summary = format_rules_summary(&shell);
    let first_run_summary = format_first_run_summary(&shell);
    let main_window_summary = format_main_window_shell_summary(&shell);
    assert!(settings_summary.contains("Storage:"));
    assert!(settings_summary.contains("General"));
    assert!(about_summary.contains("NetRuleRouter"));
    assert!(about_summary.contains("License"));
    assert!(tooltip_summary.contains("supplemental_only=true"));
    assert!(accessibility_summary.contains("Keyboard-first navigation"));
    assert!(surfaces_summary.contains("Main window"));
    assert!(interfaces_summary.contains("preview_only=true"));
    assert!(rules_summary.contains("review_before_replace=true"));
    assert!(first_run_summary.contains("default_scenario=Quick start"));
    assert!(
        first_run_summary.contains("quick_start=[Interfaces and routes -> Rules -> Diagnostics]")
    );
    assert!(main_window_summary.contains("title=NetRuleRouter"));
    assert!(main_window_summary.contains("review_dialogs="));
}
