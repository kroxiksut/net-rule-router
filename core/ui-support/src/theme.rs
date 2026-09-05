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
    /// The OS is in an accessibility high-contrast mode. It outranks the
    /// light/dark preference rather than sitting beside it: a user who turned
    /// it on needs the high-contrast palette whichever appearance the same
    /// system also states.
    HighContrast,
}

impl SystemThemeMode {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::HighContrast => "high-contrast",
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
            SystemThemeMode::HighContrast => ThemeMode::HighContrast,
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
    // Asked first, because it is the answer that matters most and the one the
    // light/dark question cannot express. `Some(false)` and `None` both fall
    // through; only a stated "on" short-circuits.
    if port.and_then(SystemThemePort::high_contrast) == Some(true) {
        return (SystemThemeMode::HighContrast, true);
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
        Some(value) if value == "high-contrast" => Some(SystemThemeMode::HighContrast),
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
            fn high_contrast(&self) -> Option<bool> {
                Some(false)
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

    /// The OS switch was never read: `SPI_GETHIGHCONTRAST` appears nowhere in
    /// the repository, and `SystemThemeMode` had only light and dark — so a
    /// user with high contrast on and the theme set to "system" stayed in the
    /// ordinary palette, while the accessibility requirement was recorded as
    /// met.
    #[test]
    fn a_high_contrast_system_is_not_answered_with_light_or_dark() {
        use nrr_platform_api::system_theme::{SystemAppearance, SystemThemePort};

        /// The shape that used to be invisible: high contrast ON while the
        /// same system also states a light appearance.
        struct HighContrastAndLight;
        impl SystemThemePort for HighContrastAndLight {
            fn detect(&self) -> Option<SystemAppearance> {
                Some(SystemAppearance::Light)
            }
            fn high_contrast(&self) -> Option<bool> {
                Some(true)
            }
        }

        /// A host that cannot answer the question must not be read as "off".
        struct CannotTell;
        impl SystemThemePort for CannotTell {
            fn detect(&self) -> Option<SystemAppearance> {
                Some(SystemAppearance::Dark)
            }
            fn high_contrast(&self) -> Option<bool> {
                None
            }
        }

        std::env::remove_var("NRR_SYSTEM_THEME");

        let hc = super::resolve_theme_with(ThemeMode::System, Some(&HighContrastAndLight));
        assert_eq!(hc.effective_mode, ThemeMode::HighContrast);
        assert_eq!(hc.system_mode, SystemThemeMode::HighContrast);
        assert!(hc.system_mode_detected);

        // An explicit choice still wins over what the system says.
        let chosen = super::resolve_theme_with(ThemeMode::Dark, Some(&HighContrastAndLight));
        assert_eq!(chosen.effective_mode, ThemeMode::Dark);

        // "Cannot tell" falls through to the appearance question, unchanged.
        let unknown = super::resolve_theme_with(ThemeMode::System, Some(&CannotTell));
        assert_eq!(unknown.effective_mode, ThemeMode::Dark);
    }

    #[test]
    fn with_no_port_installed_nothing_is_claimed() {
        std::env::remove_var("NRR_SYSTEM_THEME");
        let resolved = super::resolve_theme_with(ThemeMode::System, None);
        assert!(!resolved.system_mode_detected);
    }
}
