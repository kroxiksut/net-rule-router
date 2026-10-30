// Locale catalogue: loading, validating and merging the locale files the UI
// translates through.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const LOCALE_SCHEMA_VERSION: &str = "1.0";
const RESERVED_ROOT_NAMESPACES: &[&str] = &["_system", "_service", "_internal"];
const ALLOWED_METADATA_FIELDS: &[&str] =
    &["language", "label", "nativeLabel", "version", "fallbacks"];
const MAX_RECOMMENDED_LOCALE_VALUE_LEN: usize = 2000;
// Bounds on a locale file, which may come from a folder its user writes. The
// largest shipped one is about 0.6 MiB with 4k keys of at most 74 bytes, so
// these leave years of growth; past them a file is no translation, and every
// client that loads it would pay memory for whatever was planted there.
const MAX_LOCALE_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOCALE_KEYS: usize = 50_000;
const MAX_LOCALE_KEY_BYTES: usize = 512;
const MAX_LOCALE_FALLBACKS: usize = 16;
const MAX_LOCALE_FILES_PER_DIR: usize = 256;
/// Past this, one line says the rest of a file's warnings went unlisted.
const MAX_LOCALE_WARNINGS: usize = 64;
const MANAGED_SUBFOLDER: &str = "managed";
const USER_LOCALES_SUBFOLDER: &str = "locales";
/// Beside the main files: `tray/<id>.json` holds the words only the tray shows.
const TRAY_SUBFOLDER: &str = "tray";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocaleDescriptor {
    pub id: String,
    pub label: String,
    pub native_label: String,
    pub fallbacks: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocaleLoadStatus {
    Accepted,
    AcceptedWithWarnings,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocaleLoadReport {
    pub id: String,
    pub file_name: String,
    pub source: LocaleSource,
    pub status: LocaleLoadStatus,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocaleSource {
    Bundled,
    User,
}

impl LocaleSource {
    fn slug(self) -> &'static str {
        match self {
            Self::Bundled => "bundled",
            Self::User => "user",
        }
    }
}

pub fn load_locale_catalog() -> BTreeMap<String, BTreeMap<String, String>> {
    load_locale_state().catalog
}

pub fn load_locale_descriptors() -> Vec<LocaleDescriptor> {
    load_locale_state().descriptors
}

pub fn load_locale_reports() -> Vec<LocaleLoadReport> {
    load_locale_state().reports
}

pub fn load_locale_map(language_id: &str) -> BTreeMap<String, String> {
    let catalog = load_locale_catalog();
    let normalized = normalize_locale_id(language_id);
    if let Some(language_map) = catalog.get(&normalized) {
        return language_map.clone();
    }

    let base = normalized
        .split('-')
        .next()
        .filter(|item| !item.is_empty())
        .unwrap_or("en");
    if let Some(language_map) = catalog.get(base) {
        return language_map.clone();
    }

    catalog.get("en").cloned().unwrap_or_default()
}

pub fn translate_or(translations: &BTreeMap<String, String>, key: &str, fallback: &str) -> String {
    translations
        .get(key)
        .cloned()
        .unwrap_or_else(|| fallback.to_string())
}

pub fn resolve_catalog_text(
    catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language_id: &str,
    key: &str,
    fallback: &str,
) -> String {
    let normalized = normalize_locale_id(language_id);

    if let Some(value) = catalog
        .get(&normalized)
        .and_then(|language_map| language_map.get(key))
    {
        return value.clone();
    }

    let base = normalized
        .split('-')
        .next()
        .filter(|item| !item.is_empty())
        .unwrap_or("en");
    if let Some(value) = catalog
        .get(base)
        .and_then(|language_map| language_map.get(key))
    {
        return value.clone();
    }

    if let Some(value) = catalog
        .get("en")
        .and_then(|english_map| english_map.get(key))
    {
        return value.clone();
    }

    report_missing_key(language_id, key);
    fallback.to_string()
}

/// Everything one pass over the locale files yields.
///
/// Public because a caller that needs more than one of these — the QML context
/// emitter needs all three — would otherwise pay for the whole load once per
/// field: reading, parsing and validating both locale files three times to
/// build a single JSON document.
#[derive(Clone, Debug)]
pub struct LocaleLoadState {
    /// Every language's words, its tray file's included.
    pub catalog: BTreeMap<String, BTreeMap<String, String>>,
    pub descriptors: Vec<LocaleDescriptor>,
    /// One row per main locale file.
    pub reports: Vec<LocaleLoadReport>,
    /// One row per tray file; a tray file never adds a language.
    pub tray_reports: Vec<LocaleLoadReport>,
}

#[derive(Clone, Debug)]
struct LocaleCandidate {
    id: String,
    file_name: String,
    source: LocaleSource,
    descriptor: LocaleDescriptor,
    entries: BTreeMap<String, String>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

#[derive(Clone, Debug)]
struct EffectiveLocaleBundle {
    id: String,
    descriptor: LocaleDescriptor,
    entries: BTreeMap<String, String>,
}

impl LocaleCandidate {
    fn status(&self) -> LocaleLoadStatus {
        if !self.errors.is_empty() {
            LocaleLoadStatus::Rejected
        } else if self.warnings.is_empty() {
            LocaleLoadStatus::Accepted
        } else {
            LocaleLoadStatus::AcceptedWithWarnings
        }
    }
}

static REPORTED_MISSING_KEYS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static REPORTED_LOCALE_ISSUES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Load the locale files once and return all three views of them.
///
/// Deliberately not cached: the bundled and user locale directories come from
/// the environment, and a process that changes them expects the next load to
/// see the change.
pub fn load_locale_state() -> LocaleLoadState {
    let (candidates, tray_candidates) = load_validated_candidates();
    let reports = reports_of(&candidates);
    let tray_reports = reports_of(&tray_candidates);

    let tray_bundles = build_effective_locale_bundles(&tray_candidates);
    let mut active_bundles = build_effective_locale_bundles(&candidates);
    for bundle in &mut active_bundles {
        if let Some(tray) = tray_bundles.iter().find(|tray| tray.id == bundle.id) {
            merge_missing_entries(&mut bundle.entries, &tray.entries);
        }
    }
    let descriptor_by_id = active_bundles
        .iter()
        .map(|bundle| (bundle.id.clone(), bundle.descriptor.clone()))
        .collect::<HashMap<_, _>>();

    let raw_catalog = active_bundles
        .iter()
        .map(|bundle| (bundle.id.clone(), bundle.entries.clone()))
        .collect::<BTreeMap<_, _>>();
    let english_fallback = raw_catalog.get("en").cloned().unwrap_or_default();

    let mut catalog = BTreeMap::new();
    for bundle in active_bundles {
        let mut merged = bundle.entries;
        let mut fallback_order = bundle.descriptor.fallbacks.clone();
        if bundle.id != "en" && !fallback_order.iter().any(|item| item == "en") {
            fallback_order.push("en".to_string());
        }

        for fallback_id in fallback_order {
            if let Some(fallback_map) = raw_catalog.get(&fallback_id) {
                merge_missing_entries(&mut merged, fallback_map);
            } else if fallback_id == "en" {
                merge_missing_entries(&mut merged, &english_fallback);
            }
        }

        catalog.insert(bundle.id, merged);
    }

    if !catalog.contains_key("en") {
        catalog.insert("en".to_string(), english_fallback);
    }

    let mut descriptors = reports
        .iter()
        .filter(|report| report.status != LocaleLoadStatus::Rejected)
        .map(|report| {
            descriptor_by_id
                .get(&report.id)
                .cloned()
                .unwrap_or_else(|| LocaleDescriptor {
                    id: report.id.clone(),
                    label: default_locale_label(&report.id),
                    native_label: default_locale_native_label(&report.id),
                    fallbacks: if report.id == "en" {
                        Vec::new()
                    } else {
                        vec!["en".to_string()]
                    },
                })
        })
        .collect::<Vec<_>>();

    if !descriptors.iter().any(|descriptor| descriptor.id == "en") {
        descriptors.push(LocaleDescriptor {
            id: "en".to_string(),
            label: "English".to_string(),
            native_label: "English".to_string(),
            fallbacks: Vec::new(),
        });
    }

    let descriptors = sorted_unique_descriptors(descriptors);

    LocaleLoadState {
        catalog,
        descriptors,
        reports,
        tray_reports,
    }
}

/// The tray's catalogue: its own language and English, each the tray file's
/// words plus the main file's words under `window_words` (a key, or a family
/// when it ends in `.`). The tray never switches language, so the others
/// would only cost it memory.
pub fn load_tray_locale_catalog(
    language_id: &str,
    window_words: &[&str],
) -> BTreeMap<String, BTreeMap<String, String>> {
    let (candidates, tray_candidates) = load_validated_candidates();
    reports_of(&candidates);
    reports_of(&tray_candidates);
    tray_catalog_from(&candidates, &tray_candidates, language_id, window_words)
}

/// Both sets of files read, validated and reported once.
fn load_validated_candidates() -> (Vec<LocaleCandidate>, Vec<LocaleCandidate>) {
    let mut candidates = load_locale_candidates();
    validate_cross_locale_rules(&mut candidates);
    add_missing_baseline_coverage_warnings(&mut candidates);
    let mut tray_candidates = load_tray_locale_candidates();
    validate_tray_candidates(&mut tray_candidates, &candidates);
    (candidates, tray_candidates)
}

fn reports_of(candidates: &[LocaleCandidate]) -> Vec<LocaleLoadReport> {
    let reports = candidates
        .iter()
        .map(|candidate| LocaleLoadReport {
            id: candidate.id.clone(),
            file_name: candidate.file_name.clone(),
            source: candidate.source,
            status: candidate.status(),
            warnings: candidate.warnings.clone(),
            errors: candidate.errors.clone(),
        })
        .collect::<Vec<_>>();
    emit_locale_reports(&reports);
    reports
}

fn tray_catalog_from(
    candidates: &[LocaleCandidate],
    tray_candidates: &[LocaleCandidate],
    language_id: &str,
    window_words: &[&str],
) -> BTreeMap<String, BTreeMap<String, String>> {
    let main = build_effective_locale_bundles(candidates);
    let tray = build_effective_locale_bundles(tray_candidates);
    let shown_by_tray = |key: &str| {
        window_words.iter().any(|word| {
            if word.ends_with('.') {
                key.starts_with(word)
            } else {
                key == *word
            }
        })
    };
    // The main file's text wins a key both files hold, as in the window.
    let words_of = |id: &str| -> BTreeMap<String, String> {
        let mut words = main
            .iter()
            .find(|bundle| bundle.id == id)
            .map(|bundle| {
                bundle
                    .entries
                    .iter()
                    .filter(|(key, _)| shown_by_tray(key))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        if let Some(own) = tray.iter().find(|bundle| bundle.id == id) {
            merge_missing_entries(&mut words, &own.entries);
        }
        words
    };

    // The id the tray's `tr()` finds first: the language, else its base.
    let normalized = normalize_locale_id(language_id);
    let base = normalized.split('-').next().unwrap_or_default().to_string();
    let chosen = [normalized, base]
        .into_iter()
        .find(|id| main.iter().any(|bundle| &bundle.id == id))
        .unwrap_or_else(|| "en".to_string());

    let mut catalog = BTreeMap::new();
    if chosen != "en" {
        let mut words = words_of(&chosen);
        let fallbacks = main
            .iter()
            .find(|bundle| bundle.id == chosen)
            .map(|bundle| bundle.descriptor.fallbacks.clone())
            .unwrap_or_default();
        // English rides separately; `tr()` falls back to it per key.
        for fallback in fallbacks.iter().filter(|id| id.as_str() != "en") {
            merge_missing_entries(&mut words, &words_of(fallback));
        }
        catalog.insert(chosen, words);
    }
    catalog.insert("en".to_string(), words_of("en"));
    catalog
}

/// One entry per LANGUAGE, ordered by id.
///
/// The list is built from `reports`, which holds a row per FILE — and a user
/// override is a second file for a language the bundle already ships. This
/// module creates the `managed/locales` directory on every run, so the moment
/// anyone put a file there the language dropdown grew a second, byte-identical
/// "Русский". Both rows resolve to the same descriptor (precedence is settled
/// in `build_effective_locale_bundles`), so collapsing them loses nothing.
/// One locale file's bytes through the loader as `<id>.json` in the user's
/// folder beside an English baseline: the size bound, the parse, validation
/// and the merge. Returns how many keys the merged languages hold.
#[cfg(feature = "fuzzing")]
#[must_use]
pub fn fuzz_user_locale_file(id: &str, bytes: &[u8]) -> usize {
    let mut user = new_candidate(id, format!("{id}.json"), LocaleSource::User);
    fill_candidate(&mut user, bytes.to_vec());
    let mut english = new_candidate("en", "en.json".to_string(), LocaleSource::Bundled);
    english
        .entries
        .insert("menu.file".to_string(), "File".to_string());
    let mut candidates = vec![english, user];
    validate_cross_locale_rules(&mut candidates);
    add_missing_baseline_coverage_warnings(&mut candidates);
    build_effective_locale_bundles(&candidates)
        .iter()
        .map(|bundle| bundle.entries.len())
        .sum()
}

mod bundles;
mod candidates;
mod validation;

use bundles::*;
use candidates::*;
use validation::*;

#[cfg(test)]
mod tests;
