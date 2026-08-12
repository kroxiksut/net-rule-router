use nrr_shared::{AppShellModel, SettingAvailability};
use nrr_ui_support::ui_preferences::{UiPreferences, UiPreferencesStore};

pub fn render_settings_screen(shell: &AppShellModel, preferences: UiPreferences) {
    println!("Settings screen (standalone shell view):");
    for section in shell.settings.sections {
        println!("Section: {}", section.id.title());
        for field in section.fields {
            let status = match field.availability {
                SettingAvailability::Enabled => "enabled",
                SettingAvailability::Preview => "preview",
                SettingAvailability::Disabled => "disabled",
            };
            println!("- {} [{}]", field.id.label(), status);
        }
    }
    println!(
        "Current UI values: theme={}, language={}, last_opened_section={}, a11y_high_contrast={}, a11y_font_scale={}%, a11y_font={}, focus_indicator={}, simplified_labels={}, tooltips_enabled={}",
        preferences.theme_mode,
        preferences.language,
        preferences.last_opened_section,
        preferences.accessibility_high_contrast,
        preferences.accessibility_ui_font_scale_percent,
        preferences.accessibility_system_font,
        preferences.accessibility_enhanced_focus_indicator,
        preferences.accessibility_simplified_labels,
        preferences.tooltips_enabled
    );
}

pub fn load_preferences_with_fallback() -> (Option<UiPreferencesStore>, UiPreferences) {
    match UiPreferencesStore::managed_local() {
        Ok(store) => match store.load() {
            Ok(preferences) => (Some(store), preferences),
            Err(error) => {
                eprintln!(
                    "Failed to load UI preferences from managed storage ({}): {}",
                    store.path().display(),
                    error
                );
                (Some(store), UiPreferences::default())
            }
        },
        Err(error) => {
            eprintln!(
                "Failed to initialize managed UI preferences storage, using defaults: {}",
                error
            );
            (None, UiPreferences::default())
        }
    }
}

pub fn persist_preferences(store: Option<&UiPreferencesStore>, preferences: &UiPreferences) {
    if let Some(store_ref) = store {
        if let Err(error) = store_ref.save(preferences) {
            eprintln!(
                "Failed to persist UI preferences to {}: {}",
                store_ref.path().display(),
                error
            );
        }
    }
}
