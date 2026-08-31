//! Linux implementation of [`SystemThemePort`].

use nrr_platform_api::system_theme::{SystemAppearance, SystemThemePort};

/// Reads the desktop's colour-scheme preference.
///
/// `gsettings` is the portable-enough answer across GNOME and the many shells
/// that mirror its schema; a desktop that has neither answers `None`, which the
/// caller renders as "undetected" rather than as "light".
pub struct LinuxSystemTheme;

impl SystemThemePort for LinuxSystemTheme {
    fn detect(&self) -> Option<SystemAppearance> {
        let out = crate::command::output_with_timeout(
            "gsettings",
            &["get", "org.gnome.desktop.interface", "color-scheme"],
            crate::command::DEFAULT_COMMAND_TIMEOUT,
        )
        .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_color_scheme(&String::from_utf8_lossy(&out.stdout))
    }
}

/// `'prefer-dark'` / `'prefer-light'` / `'default'`, quotes included.
///
/// `default` means the desktop states no preference — that is not "light", so
/// it answers `None` like any other unknown.
fn parse_color_scheme(value: &str) -> Option<SystemAppearance> {
    let trimmed = value.trim().trim_matches('\'');
    match trimmed {
        "prefer-dark" => Some(SystemAppearance::Dark),
        "prefer-light" => Some(SystemAppearance::Light),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_desktops_answers_map_to_an_appearance() {
        assert_eq!(
            parse_color_scheme("'prefer-dark'\n"),
            Some(SystemAppearance::Dark)
        );
        assert_eq!(
            parse_color_scheme("'prefer-light'\n"),
            Some(SystemAppearance::Light)
        );
    }

    #[test]
    fn no_stated_preference_is_not_light() {
        assert_eq!(parse_color_scheme("'default'\n"), None);
        assert_eq!(parse_color_scheme(""), None);
    }
}
