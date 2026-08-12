use nrr_shared::ThemeMode;
use std::env;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemThemeMode {
    Light,
    Dark,
}

impl SystemThemeMode {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThemeResolution {
    pub selected_mode: ThemeMode,
    pub effective_mode: ThemeMode,
    pub system_mode: SystemThemeMode,
    pub system_mode_detected: bool,
}

pub fn resolve_theme(selected_mode: ThemeMode) -> ThemeResolution {
    let (system_mode, system_mode_detected) = detect_system_theme_mode();
    let effective_mode = match selected_mode {
        ThemeMode::Light => ThemeMode::Light,
        ThemeMode::Dark => ThemeMode::Dark,
        ThemeMode::System => match system_mode {
            SystemThemeMode::Light => ThemeMode::Light,
            SystemThemeMode::Dark => ThemeMode::Dark,
        },
        ThemeMode::HighContrast => ThemeMode::HighContrast,
    };

    ThemeResolution {
        selected_mode,
        effective_mode,
        system_mode,
        system_mode_detected,
    }
}

fn detect_system_theme_mode() -> (SystemThemeMode, bool) {
    if let Some(from_env) = parse_system_theme_hint(env::var("NRR_SYSTEM_THEME").ok().as_deref()) {
        return (from_env, true);
    }

    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize' -Name AppsUseLightTheme -ErrorAction Stop).AppsUseLightTheme",
            ])
            // Console-subsystem child of a GUI-subsystem launcher would otherwise
            // briefly show a PowerShell-blue console window.
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            if output.status.success() {
                let value = String::from_utf8_lossy(&output.stdout);
                let normalized = value.trim();
                if normalized == "0" {
                    return (SystemThemeMode::Dark, true);
                }
                if normalized == "1" {
                    return (SystemThemeMode::Light, true);
                }
            }
        }
    }

    // Fail-safe fallback for unknown platform or detection failure.
    (SystemThemeMode::Light, false)
}

fn parse_system_theme_hint(value: Option<&str>) -> Option<SystemThemeMode> {
    match value.map(|item| item.trim().to_ascii_lowercase()) {
        Some(value) if value == "dark" => Some(SystemThemeMode::Dark),
        Some(value) if value == "light" => Some(SystemThemeMode::Light),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_theme, SystemThemeMode};
    use nrr_shared::ThemeMode;

    #[test]
    fn high_contrast_is_a_distinct_supported_theme_mode() {
        let resolved = resolve_theme(ThemeMode::HighContrast);
        assert_eq!(resolved.effective_mode, ThemeMode::HighContrast);
    }

    #[test]
    fn non_system_selected_mode_is_stable() {
        let resolved = resolve_theme(ThemeMode::Dark);
        assert_eq!(resolved.selected_mode, ThemeMode::Dark);
        assert_eq!(resolved.effective_mode, ThemeMode::Dark);
    }

    #[test]
    fn system_mode_resolves_to_light_or_dark() {
        let resolved = resolve_theme(ThemeMode::System);
        assert!(matches!(
            resolved.system_mode,
            SystemThemeMode::Light | SystemThemeMode::Dark
        ));
        assert!(matches!(
            resolved.effective_mode,
            ThemeMode::Light | ThemeMode::Dark
        ));
    }
}
