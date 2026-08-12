use nrr_shared::{
    format_about_summary, format_accessibility_baseline_summary, format_first_run_summary,
    format_interfaces_routes_summary, format_main_window_shell_summary, format_rules_summary,
    format_security_visibility_summary, format_settings_summary, format_shell_summary,
    format_tooltip_policy_summary, format_ui_surface_contract_summary, AppShellModel,
};
use nrr_ui_support::ui_preferences::{
    UiPreferences, UiPreferencesStore, MANAGED_STORAGE_POLICY_NOTE,
};

pub fn print_shell_summaries(
    shell: &AppShellModel,
    preferences: UiPreferences,
    store: Option<&UiPreferencesStore>,
) {
    println!("GUI shell v1 initialized.");
    println!("{}", format_shell_summary(shell));
    println!("{}", format_first_run_summary(shell));
    println!("{}", format_settings_summary(shell));
    println!("{}", format_about_summary(shell));
    println!("{}", format_security_visibility_summary(shell));
    println!("{}", format_tooltip_policy_summary(shell));
    println!("{}", format_accessibility_baseline_summary(shell));
    println!("{}", format_ui_surface_contract_summary(shell));
    println!("{}", format_interfaces_routes_summary(shell));
    println!("{}", format_rules_summary(shell));
    println!("{}", format_main_window_shell_summary(shell));
    println!("{}", MANAGED_STORAGE_POLICY_NOTE);
    println!(
        "UI preferences: theme={}, language={}, reopen_last_section={}, first_run_completed={}, a11y_high_contrast={}, a11y_font_scale={}%, a11y_font={}, focus_indicator={}, simplified_labels={}, tooltips_enabled={}",
        preferences.theme_mode,
        preferences.language,
        preferences.reopen_last_section_on_startup,
        preferences.first_run_completed,
        preferences.accessibility_high_contrast,
        preferences.accessibility_ui_font_scale_percent,
        preferences.accessibility_system_font,
        preferences.accessibility_enhanced_focus_indicator,
        preferences.accessibility_simplified_labels,
        preferences.tooltips_enabled
    );

    if let Some(store_ref) = store {
        println!("UI preferences store: {}", store_ref.path().display());
        if !store_ref.is_profile_persistent() {
            println!("UI preferences persistence tier: temporary fallback (profile storage unavailable).");
        } else {
            println!("UI preferences persistence tier: profile-managed (update-safe).");
        }
    } else {
        println!("UI preferences store: unavailable (using runtime defaults)");
    }
}
