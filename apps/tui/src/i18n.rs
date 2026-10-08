//! Locale text for the terminal: the same `locales/*.json` the GUI reads, through
//! the shared loader, and the language choice `--lang` → system → English.

use std::collections::BTreeMap;

use nrr_shared::localization::{load_locale_state, translate_or};

/// A locale key with its English text, used when no locale file is found (a
/// binary run outside its package). The locale files stay the source of truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub id: &'static str,
    pub en: &'static str,
}

/// Shorthand for the key tables.
pub const fn key(id: &'static str, en: &'static str) -> Key {
    Key { id, en }
}

/// The resolved strings of one language.
#[derive(Clone, Debug)]
pub struct Texts {
    map: BTreeMap<String, String>,
    language: String,
}

/// A language the locale files offer: its id and its name in itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Language {
    pub id: String,
    pub name: String,
}

/// Every language a locale file was found for; the list is never written in
/// code, a dropped-in file adds to it.
pub fn available_languages() -> Vec<Language> {
    load_locale_state()
        .descriptors
        .into_iter()
        .map(|d| Language {
            name: if d.native_label.is_empty() {
                d.label
            } else {
                d.native_label
            },
            id: d.id,
        })
        .collect()
}

impl Texts {
    /// Loads the locale files once and picks the language: the explicit choice,
    /// else the first system candidate this build translates, else English.
    pub fn load(explicit: Option<&str>, system_candidates: &[String]) -> Self {
        let state = load_locale_state();
        let available: Vec<String> = state.descriptors.iter().map(|d| d.id.clone()).collect();
        let language = choose_language(explicit, system_candidates, &available);
        let map = state
            .catalog
            .get(&language)
            .or_else(|| state.catalog.get("en"))
            .cloned()
            .unwrap_or_default();
        Self { map, language }
    }

    /// The id of the language the texts are in.
    pub fn language(&self) -> &str {
        &self.language
    }

    pub fn get(&self, key: Key) -> String {
        translate_or(&self.map, key.id, key.en)
    }

    /// A key built from a service slug (`diag.conn-trace.egress.<slug>`), the
    /// GUI's own family; `fallback` where no locale has the text.
    pub fn dynamic(&self, id: &str, fallback: &str) -> String {
        translate_or(&self.map, id, fallback)
    }

    /// The text with each `{name}` filled.
    pub fn fill<V: AsRef<str>>(&self, key: Key, values: &[(&str, V)]) -> String {
        nrr_client_logic::placeholders::fill_placeholders(
            &self.get(key),
            values.iter().map(|(name, value)| (*name, value.as_ref())),
        )
    }
}

/// The language to run in. A candidate is tried as written, then by its base
/// language (`ru-RU` → `ru`); one this build does not translate is skipped, so
/// the walk goes on to the next candidate rather than widening it.
pub fn choose_language(
    explicit: Option<&str>,
    system_candidates: &[String],
    available: &[String],
) -> String {
    explicit
        .into_iter()
        .chain(system_candidates.iter().map(String::as_str))
        .find_map(|candidate| translated(candidate, available))
        .unwrap_or_else(|| "en".to_string())
}

fn translated(candidate: &str, available: &[String]) -> Option<String> {
    // `en_US.UTF-8@euro` → `en-us`.
    let tag = candidate
        .split(['.', '@'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-");
    if tag.is_empty() || tag == "c" || tag == "posix" {
        return None;
    }
    let base = tag.split('-').next().unwrap_or_default();
    let found = [tag.as_str(), base]
        .into_iter()
        .find(|id| available.iter().any(|a| a == id))
        .map(str::to_string);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn langs() -> Vec<String> {
        vec!["en".to_string(), "ru".to_string()]
    }

    #[test]
    fn the_flag_outranks_the_system() {
        assert_eq!(
            choose_language(Some("ru"), &["en-US".into()], &langs()),
            "ru"
        );
    }

    #[test]
    fn a_system_tag_maps_to_its_base_language() {
        assert_eq!(
            choose_language(None, &["ru_RU.UTF-8".into()], &langs()),
            "ru"
        );
        assert_eq!(choose_language(None, &["ru-RU".into()], &langs()), "ru");
    }

    #[test]
    fn an_untranslated_candidate_is_skipped_not_widened() {
        assert_eq!(
            choose_language(Some("de"), &["fr_FR.UTF-8".into(), "ru".into()], &langs()),
            "ru"
        );
    }

    #[test]
    fn nothing_translated_means_english() {
        assert_eq!(
            choose_language(None, &["C".into(), "de".into()], &langs()),
            "en"
        );
        assert_eq!(choose_language(None, &[], &langs()), "en");
    }
}
