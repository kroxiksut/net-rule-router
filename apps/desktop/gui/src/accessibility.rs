use nrr_shared::ThemeMode;
use nrr_ui_support::ui_preferences::UiPreferences;

pub fn normalize_accessibility_preferences(preferences: &mut UiPreferences) {
    if matches!(preferences.theme_mode, ThemeMode::HighContrast) {
        preferences.accessibility_high_contrast = true;
    }
}
