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
const MANAGED_ROOT_FOLDER: &str = "NetRuleRouter";
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

#[derive(Clone, Debug)]
struct LocaleLoadState {
    catalog: BTreeMap<String, BTreeMap<String, String>>,
    descriptors: Vec<LocaleDescriptor>,
    reports: Vec<LocaleLoadReport>,
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

fn load_locale_state() -> LocaleLoadState {
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

    descriptors.sort_by(|left, right| left.id.cmp(&right.id));

    LocaleLoadState {
        catalog,
        descriptors,
        reports,
    }
}

fn load_locale_candidates() -> Vec<LocaleCandidate> {
    let bundled_dir = resolve_bundled_locales_dir();
    let user_dir = resolve_user_locales_dir();
    let user_dir_matches_bundled = match (&bundled_dir, &user_dir) {
        (Some(bundled), Some(user)) => canonical_eq(bundled, user),
        _ => false,
    };

    let mut bundles = Vec::new();
    if let Some(path) = bundled_dir {
        bundles.extend(load_locale_candidates_from_dir(path, LocaleSource::Bundled));
    }
    if let Some(path) = user_dir {
        if user_dir_matches_bundled {
            eprintln!(
                "User locale directory resolves to bundled locale directory; user source layer is skipped."
            );
        } else {
            bundles.extend(load_locale_candidates_from_dir(path, LocaleSource::User));
        }
    }
    bundles.sort_by(|left, right| left.id.cmp(&right.id));
    bundles
}

fn load_locale_candidates_from_dir(path: PathBuf, source: LocaleSource) -> Vec<LocaleCandidate> {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| read_locale_candidate(&entry.path(), source))
        .collect::<Vec<_>>()
}

fn read_locale_candidate(path: &Path, source: LocaleSource) -> Option<LocaleCandidate> {
    if !path.extension()?.to_str()?.eq_ignore_ascii_case("json") {
        return None;
    }

    let id = normalize_locale_id(path.file_stem()?.to_str()?);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();

    let mut candidate = LocaleCandidate {
        id: id.clone(),
        file_name,
        source,
        descriptor: LocaleDescriptor {
            id: id.clone(),
            label: default_locale_label(&id),
            native_label: default_locale_native_label(&id),
            fallbacks: vec!["en".to_string()],
        },
        entries: BTreeMap::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
    };

    let raw_bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            candidate
                .errors
                .push(format!("failed to read locale file: {error}"));
            return Some(candidate);
        }
    };

    let bom_present = raw_bytes.starts_with(&[0xEF, 0xBB, 0xBF]);
    let raw = match String::from_utf8(raw_bytes) {
        Ok(text) => text,
        Err(error) => {
            candidate
                .errors
                .push(format!("invalid UTF-8 in locale file: {error}"));
            return Some(candidate);
        }
    };

    if bom_present {
        candidate
            .warnings
            .push("UTF-8 BOM was detected and ignored".to_string());
    }

    let parsed = match serde_json::from_str::<serde_json::Value>(strip_utf8_bom(&raw)) {
        Ok(value) => value,
        Err(error) => {
            candidate.errors.push(format!("invalid JSON: {error}"));
            return Some(candidate);
        }
    };

    validate_candidate_root(&parsed, &mut candidate);
    Some(candidate)
}

fn validate_candidate_root(value: &serde_json::Value, candidate: &mut LocaleCandidate) {
    let Some(object) = value.as_object() else {
        candidate
            .errors
            .push("root locale value must be a JSON object".to_string());
        return;
    };

    let Some(metadata) = object.get("metadata") else {
        candidate
            .errors
            .push("required metadata object is missing".to_string());
        return;
    };
    let Some(metadata_object) = metadata.as_object() else {
        candidate
            .errors
            .push("metadata must be a JSON object".to_string());
        return;
    };

    validate_metadata(metadata_object, candidate);
    let mut entries = BTreeMap::new();
    flatten_locale_object_validated("", value, true, &mut entries, candidate);
    candidate.entries = entries;
}

fn validate_metadata(
    metadata: &serde_json::Map<String, serde_json::Value>,
    candidate: &mut LocaleCandidate,
) {
    for key in metadata.keys() {
        if !ALLOWED_METADATA_FIELDS
            .iter()
            .any(|allowed| allowed == &key.as_str())
        {
            candidate.warnings.push(format!(
                "unknown metadata field '{key}' is ignored for schema {}",
                LOCALE_SCHEMA_VERSION
            ));
        }
    }

    let language_raw = require_metadata_string(metadata, "language", candidate);
    let label = require_metadata_string(metadata, "label", candidate)
        .unwrap_or_else(|| default_locale_label(&candidate.id));
    let native_label = require_metadata_string(metadata, "nativeLabel", candidate)
        .unwrap_or_else(|| default_locale_native_label(&candidate.id));
    let version = require_metadata_string(metadata, "version", candidate);
    let fallbacks = require_metadata_string_array(metadata, "fallbacks", candidate);

    if let Some(language_raw) = language_raw {
        let normalized_language = normalize_locale_id(&language_raw);
        if normalized_language != candidate.id {
            candidate.errors.push(format!(
                "metadata.language '{}' does not match file locale id '{}'",
                normalized_language, candidate.id
            ));
        }
    }

    if let Some(version) = version {
        if version != LOCALE_SCHEMA_VERSION {
            candidate.errors.push(format!(
                "unsupported locale schema version '{}'; expected '{}'",
                version, LOCALE_SCHEMA_VERSION
            ));
        }
    }

    let mut normalized_fallbacks = Vec::new();
    if let Some(fallbacks) = fallbacks {
        for item in fallbacks {
            let normalized = normalize_locale_id(&item);
            if normalized == candidate.id {
                if candidate.id == "en" {
                    candidate.warnings.push(
                        "self-reference 'en' in fallback chain is ignored for baseline locale"
                            .to_string(),
                    );
                } else {
                    candidate.errors.push(format!(
                        "fallback chain contains self-reference '{}'",
                        candidate.id
                    ));
                }
                continue;
            }
            if !normalized_fallbacks
                .iter()
                .any(|existing| existing == &normalized)
            {
                normalized_fallbacks.push(normalized);
            }
        }
    }

    candidate.descriptor = LocaleDescriptor {
        id: candidate.id.clone(),
        label,
        native_label,
        fallbacks: normalized_fallbacks,
    };
}

fn require_metadata_string(
    metadata: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    candidate: &mut LocaleCandidate,
) -> Option<String> {
    let Some(value) = metadata.get(field) else {
        candidate
            .errors
            .push(format!("required metadata field '{field}' is missing"));
        return None;
    };
    let Some(value) = value.as_str() else {
        candidate.errors.push(format!(
            "metadata field '{field}' must be a non-empty string"
        ));
        return None;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        candidate.errors.push(format!(
            "metadata field '{field}' must be a non-empty string"
        ));
        return None;
    }
    Some(trimmed.to_string())
}

fn require_metadata_string_array(
    metadata: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    candidate: &mut LocaleCandidate,
) -> Option<Vec<String>> {
    let Some(value) = metadata.get(field) else {
        candidate
            .errors
            .push(format!("required metadata field '{field}' is missing"));
        return None;
    };
    let Some(values) = value.as_array() else {
        candidate.errors.push(format!(
            "metadata field '{field}' must be an array of locale ids"
        ));
        return None;
    };
    if values.is_empty() {
        candidate
            .errors
            .push(format!("metadata field '{field}' must not be empty"));
        return None;
    }

    let mut parsed = Vec::new();
    for item in values {
        let Some(raw) = item.as_str() else {
            candidate.errors.push(format!(
                "metadata field '{field}' must contain only locale id strings"
            ));
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            candidate.errors.push(format!(
                "metadata field '{field}' must contain only non-empty locale id strings"
            ));
            continue;
        }
        parsed.push(trimmed.to_string());
    }
    Some(parsed)
}

fn flatten_locale_object_validated(
    prefix: &str,
    value: &serde_json::Value,
    is_root: bool,
    output: &mut BTreeMap<String, String>,
    candidate: &mut LocaleCandidate,
) {
    let Some(object) = value.as_object() else {
        if !is_root {
            candidate
                .errors
                .push(format!("namespace '{prefix}' must be an object"));
        }
        return;
    };

    for (key, nested) in object {
        if is_root && key == "metadata" {
            continue;
        }

        if is_root
            && RESERVED_ROOT_NAMESPACES
                .iter()
                .any(|reserved| reserved == &key.as_str())
        {
            candidate.errors.push(format!(
                "reserved namespace '{key}' is not allowed in locale translation payload"
            ));
            continue;
        }

        if !is_valid_key_segment(key) {
            candidate.errors.push(format!(
                "invalid key segment '{key}' in namespace '{}'",
                if prefix.is_empty() { "<root>" } else { prefix }
            ));
        }

        let merged_key = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };

        if is_root && !nested.is_object() {
            candidate.errors.push(format!(
                "root translation key '{key}' must be a namespace object"
            ));
            continue;
        }

        if let Some(text) = nested.as_str() {
            if text.trim().is_empty() {
                candidate.warnings.push(format!(
                    "translation key '{merged_key}' contains an empty string"
                ));
            }
            if text.chars().count() > MAX_RECOMMENDED_LOCALE_VALUE_LEN {
                candidate.warnings.push(format!(
                    "translation key '{merged_key}' exceeds recommended length (>{MAX_RECOMMENDED_LOCALE_VALUE_LEN})"
                ));
            }
            if text
                .chars()
                .any(|ch| ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t')
            {
                candidate.warnings.push(format!(
                    "translation key '{merged_key}' contains control characters"
                ));
            }

            output.insert(merged_key, text.to_string());
            continue;
        }

        if nested.is_object() {
            flatten_locale_object_validated(&merged_key, nested, false, output, candidate);
            continue;
        }

        candidate.errors.push(format!(
            "translation key '{merged_key}' has invalid value type; only string/object are allowed"
        ));
    }
}

fn validate_cross_locale_rules(candidates: &mut [LocaleCandidate]) {
    mark_duplicate_locale_ids(candidates);
    sanitize_fallback_targets(candidates);
    reject_fallback_cycles(candidates);
}

fn mark_duplicate_locale_ids(candidates: &mut [LocaleCandidate]) {
    let mut groups = HashMap::<(String, LocaleSource), Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        groups
            .entry((candidate.id.clone(), candidate.source))
            .or_default()
            .push(index);
    }

    for ((id, source), indices) in groups {
        if indices.len() <= 1 {
            continue;
        }
        for index in indices {
            candidates[index].errors.push(format!(
                "duplicate locale id '{id}' in '{}' source (multiple files resolve to the same locale id)",
                source.slug()
            ));
        }
    }
}

fn sanitize_fallback_targets(candidates: &mut [LocaleCandidate]) {
    let available = candidates
        .iter()
        .filter(|candidate| candidate.errors.is_empty())
        .map(|candidate| candidate.id.clone())
        .collect::<HashSet<_>>();

    for candidate in candidates.iter_mut().filter(|item| item.errors.is_empty()) {
        let mut sanitized = Vec::<String>::new();
        for fallback in &candidate.descriptor.fallbacks {
            if !available.contains(fallback) {
                candidate.warnings.push(format!(
                    "fallback locale '{}' is not available and will be ignored",
                    fallback
                ));
                continue;
            }
            if !sanitized.iter().any(|item| item == fallback) {
                sanitized.push(fallback.clone());
            }
        }
        candidate.descriptor.fallbacks = sanitized;
    }
}

fn reject_fallback_cycles(candidates: &mut [LocaleCandidate]) {
    let id_to_index = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.errors.is_empty())
        .map(|(index, candidate)| (candidate.id.clone(), index))
        .collect::<HashMap<_, _>>();

    let mut graph = HashMap::<String, Vec<String>>::new();
    for candidate in candidates.iter().filter(|item| item.errors.is_empty()) {
        let edges = candidate
            .descriptor
            .fallbacks
            .iter()
            .filter(|item| id_to_index.contains_key(*item))
            .cloned()
            .collect::<Vec<_>>();
        graph.insert(candidate.id.clone(), edges);
    }

    let mut visit_state = HashMap::<String, u8>::new();
    let mut stack = Vec::<String>::new();
    let mut cycle_nodes = HashSet::<String>::new();

    let ids = graph.keys().cloned().collect::<Vec<_>>();
    for id in ids {
        if visit_state.get(&id).copied().unwrap_or(0) == 0 {
            dfs_collect_cycles(&id, &graph, &mut visit_state, &mut stack, &mut cycle_nodes);
        }
    }

    for locale_id in cycle_nodes {
        if let Some(index) = id_to_index.get(&locale_id).copied() {
            candidates[index]
                .errors
                .push("fallback chain contains a cycle".to_string());
        }
    }
}

fn dfs_collect_cycles(
    id: &str,
    graph: &HashMap<String, Vec<String>>,
    visit_state: &mut HashMap<String, u8>,
    stack: &mut Vec<String>,
    cycle_nodes: &mut HashSet<String>,
) {
    visit_state.insert(id.to_string(), 1);
    stack.push(id.to_string());

    if let Some(next_ids) = graph.get(id) {
        for next_id in next_ids {
            match visit_state.get(next_id).copied().unwrap_or(0) {
                0 => dfs_collect_cycles(next_id, graph, visit_state, stack, cycle_nodes),
                1 => {
                    if let Some(position) = stack.iter().position(|item| item == next_id) {
                        for node in &stack[position..] {
                            cycle_nodes.insert(node.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let _ = stack.pop();
    visit_state.insert(id.to_string(), 2);
}

fn add_missing_baseline_coverage_warnings(candidates: &mut [LocaleCandidate]) {
    let english_entries = build_effective_locale_bundles(candidates)
        .into_iter()
        .find(|bundle| bundle.id == "en")
        .map(|bundle| bundle.entries)
        .unwrap_or_default();

    if english_entries.is_empty() {
        return;
    }

    for candidate in candidates
        .iter_mut()
        .filter(|candidate| candidate.id != "en" && candidate.errors.is_empty())
    {
        let missing_count = english_entries
            .keys()
            .filter(|key| !candidate.entries.contains_key(*key))
            .count();
        if missing_count > 0 {
            candidate.warnings.push(format!(
                "locale is missing {missing_count} key(s) relative to English baseline and will use fallback values"
            ));
        }
    }
}

fn build_effective_locale_bundles(candidates: &[LocaleCandidate]) -> Vec<EffectiveLocaleBundle> {
    let mut bundled_by_id = HashMap::<String, &LocaleCandidate>::new();
    let mut user_by_id = HashMap::<String, &LocaleCandidate>::new();
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.errors.is_empty())
    {
        match candidate.source {
            LocaleSource::Bundled => {
                bundled_by_id
                    .entry(candidate.id.clone())
                    .or_insert(candidate);
            }
            LocaleSource::User => {
                user_by_id.entry(candidate.id.clone()).or_insert(candidate);
            }
        }
    }

    let ids = bundled_by_id
        .keys()
        .chain(user_by_id.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut bundles = Vec::new();
    for id in ids {
        let bundled = bundled_by_id.get(&id).copied();
        let user = user_by_id.get(&id).copied();
        let mut entries = bundled
            .map(|candidate| candidate.entries.clone())
            .unwrap_or_default();
        if let Some(user_candidate) = user {
            for (key, value) in &user_candidate.entries {
                entries.insert(key.clone(), value.clone());
            }
        }

        let descriptor = if let Some(user_candidate) = user {
            user_candidate.descriptor.clone()
        } else if let Some(bundled_candidate) = bundled {
            bundled_candidate.descriptor.clone()
        } else {
            continue;
        };

        bundles.push(EffectiveLocaleBundle {
            id,
            descriptor,
            entries,
        });
    }

    bundles
}

fn resolve_bundled_locales_dir() -> Option<PathBuf> {
    if let Ok(explicit_dir) = env::var("NRR_BUNDLED_LOCALES_DIR") {
        let path = PathBuf::from(explicit_dir);
        if path.exists() {
            return Some(path);
        }
    }

    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../locales");
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }

    if let Ok(current_executable) = env::current_exe() {
        if let Some(mut directory) = current_executable.parent().map(PathBuf::from) {
            loop {
                let candidate = directory.join("locales");
                if candidate.exists() {
                    return Some(candidate);
                }
                if !directory.pop() {
                    break;
                }
            }
        }
    }

    let mut directory = env::current_dir().ok()?;
    loop {
        let candidate = directory.join("locales");
        if candidate.exists() {
            return Some(candidate);
        }
        if !directory.pop() {
            break;
        }
    }

    None
}

fn resolve_user_locales_dir() -> Option<PathBuf> {
    if let Ok(explicit_dir) = env::var("NRR_USER_LOCALES_DIR") {
        let path = PathBuf::from(explicit_dir);
        if path.exists() {
            return Some(path);
        }
    }
    // Backward compatibility with the pre-3.6 external-locale override variable.
    if let Ok(legacy_dir) = env::var("NRR_LOCALES_DIR") {
        let path = PathBuf::from(legacy_dir);
        if path.exists() {
            return Some(path);
        }
    }

    resolve_managed_locales_dir()
}

fn resolve_managed_locales_dir() -> Option<PathBuf> {
    let mut candidates = Vec::<PathBuf>::new();
    if let Some(app_data) = env::var_os("APPDATA") {
        candidates.push(PathBuf::from(app_data));
    }
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        candidates.push(PathBuf::from(local_app_data));
    }
    candidates.push(env::temp_dir());

    for base in candidates {
        let candidate = base
            .join(MANAGED_ROOT_FOLDER)
            .join(MANAGED_SUBFOLDER)
            .join(USER_LOCALES_SUBFOLDER);
        if fs::create_dir_all(&candidate).is_ok() {
            return Some(candidate);
        }
    }

    None
}

fn canonical_eq(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left_canonical), Ok(right_canonical)) => left_canonical == right_canonical,
        _ => left == right,
    }
}

fn merge_missing_entries(
    target: &mut BTreeMap<String, String>,
    fallback: &BTreeMap<String, String>,
) {
    for (key, value) in fallback {
        target.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

fn normalize_locale_id(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    let without_charset = normalized
        .split('.')
        .next()
        .unwrap_or_default()
        .split('@')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if without_charset.is_empty() {
        "en".to_string()
    } else {
        without_charset
    }
}

fn strip_utf8_bom(value: &str) -> &str {
    value.strip_prefix('\u{feff}').unwrap_or(value)
}

fn is_valid_key_segment(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn default_locale_label(id: &str) -> String {
    match id {
        "en" => "English".to_string(),
        "ru" => "Russian".to_string(),
        _ => id.to_ascii_uppercase(),
    }
}

fn default_locale_native_label(id: &str) -> String {
    match id {
        "en" => "English".to_string(),
        "ru" => "Русский".to_string(),
        _ => id.to_string(),
    }
}

fn report_missing_key(language_id: &str, key: &str) {
    let registry = REPORTED_MISSING_KEYS.get_or_init(|| Mutex::new(HashSet::new()));
    if let Ok(mut seen) = registry.lock() {
        let fingerprint = format!("{}|{}", normalize_locale_id(language_id), key);
        if seen.insert(fingerprint) {
            eprintln!(
                "Localization coverage defect: missing key '{}' for locale '{}'; fallback text was used.",
                key, language_id
            );
        }
    }
}

fn emit_locale_reports(reports: &[LocaleLoadReport]) {
    let registry = REPORTED_LOCALE_ISSUES.get_or_init(|| Mutex::new(HashSet::new()));
    let Ok(mut seen) = registry.lock() else {
        return;
    };

    for report in reports {
        match report.status {
            LocaleLoadStatus::Accepted => {}
            LocaleLoadStatus::AcceptedWithWarnings => {
                let fingerprint = format!(
                    "warning|{}|{}|{}",
                    report.source.slug(),
                    report.id,
                    report.warnings.join("|")
                );
                if seen.insert(fingerprint) {
                    eprintln!(
                        "Locale '{}' ({}) loaded with warnings ({}): {}",
                        report.file_name,
                        report.source.slug(),
                        report.warnings.len(),
                        report.warnings.join("; ")
                    );
                }
            }
            LocaleLoadStatus::Rejected => {
                let fingerprint = format!(
                    "rejected|{}|{}|{}",
                    report.source.slug(),
                    report.id,
                    report.errors.join("|")
                );
                if seen.insert(fingerprint) {
                    eprintln!(
                        "Locale '{}' ({}) was rejected ({}): {}",
                        report.file_name,
                        report.source.slug(),
                        report.errors.len(),
                        report.errors.join("; ")
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        add_missing_baseline_coverage_warnings, build_effective_locale_bundles,
        normalize_locale_id, read_locale_candidate, reject_fallback_cycles,
        require_metadata_string, resolve_catalog_text, strip_utf8_bom, validate_cross_locale_rules,
        LocaleCandidate, LocaleDescriptor, LocaleLoadStatus, LocaleSource,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn candidate(id: &str, fallbacks: &[&str], entries: &[(&str, &str)]) -> LocaleCandidate {
        candidate_with_source(id, LocaleSource::Bundled, fallbacks, entries)
    }

    fn candidate_with_source(
        id: &str,
        source: LocaleSource,
        fallbacks: &[&str],
        entries: &[(&str, &str)],
    ) -> LocaleCandidate {
        LocaleCandidate {
            id: id.to_string(),
            file_name: format!("{id}.json"),
            source,
            descriptor: LocaleDescriptor {
                id: id.to_string(),
                label: id.to_string(),
                native_label: id.to_string(),
                fallbacks: fallbacks.iter().map(|item| item.to_string()).collect(),
            },
            entries: entries
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Write a locale fixture into a fresh `TempDir`. Callers MUST keep the
    /// `TempDir` binding alive for the duration of the assertion — dropping
    /// it removes the directory recursively, so a `let (_dir, path) = ...`
    /// or `let (dir, path) = ...; ...drop(dir);` pattern is required.
    /// Previously these helpers used `std::env::temp_dir().join("nrr-locale-test-…")`
    /// with no cleanup, leaking one directory per test run.
    fn write_temp_locale_named(
        file_name: &str,
        content: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("nrr-locale-test-")
            .tempdir()
            .unwrap_or_else(|error| panic!("failed to create temp locale directory: {error}"));
        let path = dir.path().join(file_name);
        std::fs::write(&path, content)
            .unwrap_or_else(|error| panic!("failed to write temp locale file: {error}"));
        (dir, path)
    }

    fn write_temp_locale(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        write_temp_locale_named("ru.json", content)
    }

    #[test]
    fn metadata_required_string_rejects_empty_values() {
        let metadata = json!({
            "language": " ",
            "label": "English",
            "nativeLabel": "English",
            "version": "1.0",
            "fallbacks": ["en"]
        });
        let mut candidate = candidate("en", &["en"], &[("menu.file", "File")]);
        let object = metadata
            .as_object()
            .unwrap_or_else(|| panic!("metadata object expected"));
        assert!(require_metadata_string(object, "language", &mut candidate).is_none());
        assert!(!candidate.errors.is_empty());
    }

    #[test]
    fn locale_id_normalization_drops_charset_and_uses_hyphen() {
        assert_eq!(normalize_locale_id("pt_BR.UTF-8"), "pt-br");
        assert_eq!(normalize_locale_id("ru_RU"), "ru-ru");
    }

    #[test]
    fn utf8_bom_is_ignored_before_json_parse() {
        let raw = "\u{feff}{\"menu\":{\"file\":\"File\"}}";
        let parsed = serde_json::from_str::<serde_json::Value>(strip_utf8_bom(raw))
            .unwrap_or_else(|error| panic!("BOM-stripped JSON should parse: {error}"));
        assert_eq!(
            parsed
                .get("menu")
                .and_then(|value| value.get("file"))
                .and_then(|value| value.as_str()),
            Some("File")
        );
    }

    #[test]
    fn resolve_catalog_text_uses_language_base_and_english_fallback_chain() {
        let mut en = BTreeMap::new();
        en.insert("status.ready".to_string(), "Ready".to_string());

        let mut ru = BTreeMap::new();
        ru.insert("status.ready".to_string(), "Готово".to_string());

        let mut catalog = BTreeMap::new();
        catalog.insert("en".to_string(), en);
        catalog.insert("ru".to_string(), ru);

        assert_eq!(
            resolve_catalog_text(&catalog, "ru-RU", "status.ready", "fallback"),
            "Готово"
        );
        assert_eq!(
            resolve_catalog_text(&catalog, "de-DE", "status.ready", "fallback"),
            "Ready"
        );
    }

    #[test]
    fn resolve_catalog_text_returns_explicit_fallback_when_key_is_missing_everywhere() {
        let catalog = BTreeMap::new();
        assert_eq!(
            resolve_catalog_text(&catalog, "ru", "status.missing", "fallback-text"),
            "fallback-text"
        );
    }

    #[test]
    fn fallback_cycle_is_rejected() {
        let mut candidates = vec![
            candidate("ru", &["de"], &[("menu.file", "Файл")]),
            candidate("de", &["ru"], &[("menu.file", "Datei")]),
        ];
        reject_fallback_cycles(&mut candidates);
        assert!(candidates.iter().all(|item| !item.errors.is_empty()));
    }

    #[test]
    fn partial_locale_is_marked_with_warning_against_english_baseline() {
        let mut candidates = vec![
            candidate(
                "en",
                &["en"],
                &[
                    ("menu.file", "File"),
                    ("menu.help", "Help"),
                    ("status.ok", "OK"),
                ],
            ),
            candidate("ru", &["en"], &[("menu.file", "Файл")]),
        ];
        add_missing_baseline_coverage_warnings(&mut candidates);
        let ru = candidates
            .iter()
            .find(|item| item.id == "ru")
            .unwrap_or_else(|| panic!("ru candidate must exist"));
        assert_eq!(ru.status(), LocaleLoadStatus::AcceptedWithWarnings);
    }

    #[test]
    fn invalid_json_candidate_is_rejected() {
        let (_dir, path) = write_temp_locale("{invalid");
        let candidate = read_locale_candidate(&path, LocaleSource::Bundled)
            .unwrap_or_else(|| panic!("candidate expected"));
        assert_eq!(candidate.status(), LocaleLoadStatus::Rejected);
    }

    #[test]
    fn invalid_metadata_type_is_rejected() {
        let (_dir, path) = write_temp_locale(
            r#"{
                "metadata": [],
                "menu": { "file": "File" }
            }"#,
        );
        let candidate = read_locale_candidate(&path, LocaleSource::Bundled)
            .unwrap_or_else(|| panic!("candidate expected"));
        assert_eq!(candidate.status(), LocaleLoadStatus::Rejected);
    }

    #[test]
    fn unknown_metadata_fields_produce_warning_status() {
        let (_dir, path) = write_temp_locale_named(
            "fr.json",
            r#"{
                "metadata": {
                    "language": "fr",
                    "label": "French",
                    "nativeLabel": "Français",
                    "version": "1.0",
                    "fallbacks": ["en"],
                    "unknownField": "value"
                },
                "menu": { "file": "Fichier" }
            }"#,
        );
        let candidate = read_locale_candidate(&path, LocaleSource::Bundled)
            .unwrap_or_else(|| panic!("candidate expected"));
        assert_eq!(candidate.status(), LocaleLoadStatus::AcceptedWithWarnings);
    }

    #[test]
    fn validate_cross_locale_rules_marks_unknown_fallback_as_warning() {
        let mut candidates = vec![candidate("ru", &["de"], &[("menu.file", "Файл")])];
        validate_cross_locale_rules(&mut candidates);
        assert_eq!(
            candidates[0].status(),
            LocaleLoadStatus::AcceptedWithWarnings
        );
    }

    #[test]
    fn effective_locale_prefers_user_values_over_bundled() {
        let candidates = vec![
            candidate_with_source(
                "ru",
                LocaleSource::Bundled,
                &["en"],
                &[("menu.file", "Файл"), ("menu.help", "Справка")],
            ),
            candidate_with_source(
                "ru",
                LocaleSource::User,
                &["en"],
                &[("menu.file", "Файл (пользовательский)")],
            ),
        ];

        let bundles = build_effective_locale_bundles(&candidates);
        let ru = bundles
            .iter()
            .find(|bundle| bundle.id == "ru")
            .unwrap_or_else(|| panic!("ru effective bundle must exist"));
        assert_eq!(
            ru.entries.get("menu.file"),
            Some(&"Файл (пользовательский)".to_string())
        );
        assert_eq!(ru.entries.get("menu.help"), Some(&"Справка".to_string()));
    }

    #[test]
    fn duplicate_locale_ids_are_rejected_only_within_same_source() {
        let mut candidates = vec![
            candidate_with_source(
                "fr",
                LocaleSource::Bundled,
                &["en"],
                &[("menu.file", "File")],
            ),
            candidate_with_source(
                "fr",
                LocaleSource::Bundled,
                &["en"],
                &[("menu.file", "File")],
            ),
            candidate_with_source(
                "fr",
                LocaleSource::User,
                &["en"],
                &[("menu.file", "Fichier utilisateur")],
            ),
        ];

        validate_cross_locale_rules(&mut candidates);
        assert_eq!(candidates[0].status(), LocaleLoadStatus::Rejected);
        assert_eq!(candidates[1].status(), LocaleLoadStatus::Rejected);
        assert_ne!(candidates[2].status(), LocaleLoadStatus::Rejected);
    }
}
