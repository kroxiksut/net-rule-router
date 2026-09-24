// Locale catalogue: loading, validating and merging the locale files the UI
// translates through.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const LOCALE_SCHEMA_VERSION: &str = "1.0";
pub const LOCALE_SCHEMA_PATH: &str = "configs/localization/locale.schema.v1.json";
const RESERVED_ROOT_NAMESPACES: &[&str] = &["_system", "_service", "_internal"];
const ALLOWED_METADATA_FIELDS: &[&str] =
    &["language", "label", "nativeLabel", "version", "fallbacks"];
const MAX_RECOMMENDED_LOCALE_VALUE_LEN: usize = 2000;
const MANAGED_SUBFOLDER: &str = "managed";
const USER_LOCALES_SUBFOLDER: &str = "locales";

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
    pub catalog: BTreeMap<String, BTreeMap<String, String>>,
    pub descriptors: Vec<LocaleDescriptor>,
    pub reports: Vec<LocaleLoadReport>,
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
    let mut candidates = load_locale_candidates();
    validate_cross_locale_rules(&mut candidates);
    add_missing_baseline_coverage_warnings(&mut candidates);
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

    let active_bundles = build_effective_locale_bundles(&candidates);
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
    }
}

/// One entry per LANGUAGE, ordered by id.
///
/// The list is built from `reports`, which holds a row per FILE — and a user
/// override is a second file for a language the bundle already ships. This
/// module creates the `managed/locales` directory on every run, so the moment
/// anyone put a file there the language dropdown grew a second, byte-identical
/// "Русский". Both rows resolve to the same descriptor (precedence is settled
/// in `build_effective_locale_bundles`), so collapsing them loses nothing.
mod bundles;
mod candidates;
mod validation;

use bundles::*;
use candidates::*;
use validation::*;

#[cfg(test)]
mod tests;
