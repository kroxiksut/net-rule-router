//! Linux implementation of [`SystemLocalePort`].

use nrr_platform_api::system_locale::SystemLocalePort;

/// Reads the POSIX locale environment the session was started with.
pub struct LinuxSystemLocale;

impl SystemLocalePort for LinuxSystemLocale {
    fn ui_language_candidates(&self) -> Vec<String> {
        language_candidates_from(|key| std::env::var(key).ok())
    }
}

/// `LANGUAGE` is gettext's colon-separated priority list and outranks the
/// single-value locale variables for message-catalog selection; its entries
/// are returned in order so the caller can walk to the first one it has a
/// translation for. `LC_ALL`, `LC_MESSAGES`, `LANG` follow, each a single
/// candidate, in glibc's own precedence order.
fn language_candidates_from(lookup: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(list) = lookup("LANGUAGE") {
        candidates.extend(
            list.split(':')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string),
        );
    }
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(value) = lookup(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_string())
        }
    }

    #[test]
    fn language_outranks_the_single_value_variables() {
        assert_eq!(
            language_candidates_from(env_of(&[
                ("LANG", "en_US.UTF-8"),
                ("LC_ALL", "fr_FR.UTF-8"),
                ("LANGUAGE", "de:ru:en"),
            ])),
            vec!["de", "ru", "en", "fr_FR.UTF-8", "en_US.UTF-8"]
        );
    }

    #[test]
    fn without_language_the_single_value_variables_keep_their_order() {
        assert_eq!(
            language_candidates_from(env_of(&[
                ("LANG", "en_US.UTF-8"),
                ("LC_ALL", "ru_RU.UTF-8")
            ])),
            vec!["ru_RU.UTF-8", "en_US.UTF-8"]
        );
        assert_eq!(
            language_candidates_from(env_of(&[("LANG", "de_DE.UTF-8")])),
            vec!["de_DE.UTF-8"]
        );
    }

    #[test]
    fn an_empty_variable_does_not_produce_a_candidate() {
        assert_eq!(
            language_candidates_from(env_of(&[("LC_ALL", ""), ("LANG", "ru_RU.UTF-8")])),
            vec!["ru_RU.UTF-8"]
        );
        assert!(language_candidates_from(env_of(&[])).is_empty());
        assert!(language_candidates_from(env_of(&[("LANGUAGE", ""), ("LANG", "")])).is_empty());
    }
}
