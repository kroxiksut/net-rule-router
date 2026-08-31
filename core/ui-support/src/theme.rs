use nrr_platform_api::system_theme::{SystemAppearance, SystemThemePort};
use nrr_shared::ThemeMode;
use std::env;

/// The probe this process should use, if it has one wired.
///
/// A UI crate cannot name an OS implementation without dragging that OS into
/// every build, so the surfaces install theirs at startup through
/// [`install_system_theme_port`]. Nothing installed = the question cannot be
/// answered, which is reported as such.
static SYSTEM_THEME_PORT: std::sync::OnceLock<Box<dyn SystemThemePort>> =
    std::sync::OnceLock::new();

/// Installs the process-wide system-theme probe. The first call wins; later
/// ones are ignored, so a test that sets its own is not overwritten by a
/// surface initialising afterwards.
pub fn install_system_theme_port(port: Box<dyn SystemThemePort>) {
    let _ = SYSTEM_THEME_PORT.set(port);
}

fn system_theme_port() -> Option<&'static dyn SystemThemePort> {
    SYSTEM_THEME_PORT.get().map(|port| &**port)
}

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
    resolve_theme_with(selected_mode, system_theme_port())
}

/// Same resolution against an explicit probe. The probe is OS mechanism and
/// lives behind [`SystemThemePort`]; this crate stays neutral and only decides
/// what the answer MEANS.
pub fn resolve_theme_with(
    selected_mode: ThemeMode,
    port: Option<&dyn SystemThemePort>,
) -> ThemeResolution {
    let (system_mode, system_mode_detected) = detect_system_theme_mode(port);
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

fn detect_system_theme_mode(port: Option<&dyn SystemThemePort>) -> (SystemThemeMode, bool) {
    if let Some(from_env) = parse_system_theme_hint(env::var("NRR_SYSTEM_THEME").ok().as_deref()) {
        return (from_env, true);
    }
    match port.and_then(SystemThemePort::detect) {
        Some(SystemAppearance::Dark) => (SystemThemeMode::Dark, true),
        Some(SystemAppearance::Light) => (SystemThemeMode::Light, true),
        // Fail-safe fallback, and `system_mode_detected = false` is how the
        // caller is told it IS a fallback rather than an observation.
        None => (SystemThemeMode::Light, false),
    }
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

    #[test]
    fn an_undetectable_system_is_told_apart_from_a_light_one() {
        use nrr_platform_api::system_theme::{
            SystemAppearance, SystemThemePort, UnknownSystemTheme,
        };

        struct AlwaysDark;
        impl SystemThemePort for AlwaysDark {
            fn detect(&self) -> Option<SystemAppearance> {
                Some(SystemAppearance::Dark)
            }
        }

        // The env hint short-circuits the probe, so it must be absent here.
        std::env::remove_var("NRR_SYSTEM_THEME");

        let unknown = super::resolve_theme_with(ThemeMode::System, Some(&UnknownSystemTheme));
        assert_eq!(unknown.effective_mode, ThemeMode::Light);
        assert!(
            !unknown.system_mode_detected,
            "a fail-safe guess must not be reported as an observation"
        );

        let dark = super::resolve_theme_with(ThemeMode::System, Some(&AlwaysDark));
        assert_eq!(dark.effective_mode, ThemeMode::Dark);
        assert!(dark.system_mode_detected);
    }

    #[test]
    fn with_no_port_installed_nothing_is_claimed() {
        std::env::remove_var("NRR_SYSTEM_THEME");
        let resolved = super::resolve_theme_with(ThemeMode::System, None);
        assert!(!resolved.system_mode_detected);
    }
}
