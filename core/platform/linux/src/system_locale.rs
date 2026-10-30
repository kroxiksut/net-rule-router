//! Linux implementation of [`SystemLocalePort`].

use nrr_platform_api::system_locale::SystemLocalePort;

/// Reads the POSIX locale environment the session was started with.
pub struct LinuxSystemLocale;

impl SystemLocalePort for LinuxSystemLocale {
    fn ui_language_candidates(&self) -> Vec<String> {
        language_candidates_from(|key| std::env::var(key).ok())
    }

    fn region(&self) -> Option<String> {
        region_from(|key| std::env::var(key).ok())
    }
}

/// The first locale that names a territory, in glibc's precedence for the
/// categories a country decides (address, telephone, money, time); the
/// message language (`LANGUAGE`, `LC_MESSAGES`) says nothing about it.
fn region_from(lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    [
        "LC_ALL",
        "LC_ADDRESS",
        "LC_TELEPHONE",
        "LC_MONETARY",
        "LC_TIME",
        "LANG",
    ]
    .into_iter()
    .filter_map(lookup)
    .map(|value| value.trim().to_string())
    .find(|value| {
        value
            .split(['.', '@'])
            .next()
            .is_some_and(|tag| tag.contains(['_', '-']))
    })
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
    fn the_region_follows_the_country_categories_not_the_message_language() {
        assert_eq!(
            region_from(env_of(&[
                ("LANGUAGE", "en_US:en"),
                ("LC_MESSAGES", "en_US.UTF-8"),
                ("LC_TIME", "ru_RU.UTF-8"),
                ("LANG", "en_US.UTF-8"),
            ])),
            Some("ru_RU.UTF-8".to_string())
        );
        // A bare language names no country; the next locale that does wins.
        assert_eq!(
            region_from(env_of(&[("LC_ALL", "C"), ("LANG", "kk_KZ.UTF-8")])),
            Some("kk_KZ.UTF-8".to_string())
        );
        assert_eq!(region_from(env_of(&[("LANG", "C.UTF-8")])), None);
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
